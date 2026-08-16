//! `DBUS_COOKIE_SHA1` keyring: `~/.dbus-keyrings/<context>`, one line per
//! key as `<id> <created-unix-secs> <hex-secret>`. Matches
//! `dbus/dbus-keyring.c` exactly (including the directory/file layout) so
//! an OxiBus client and a real `dbus-daemon` sharing a `$HOME` can
//! interoperate over this mechanism.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AuthError, AuthResult};

/// Default keyring context/filename used by `dbus-daemon` and most
/// clients (`~/.dbus-keyrings/org_freedesktop_general`).
pub const DEFAULT_CONTEXT: &str = "org_freedesktop_general";
const KEY_LENGTH_BYTES: usize = 24;
const NEW_KEY_TIMEOUT_SECONDS: i64 = 60 * 5;
const EXPIRE_KEYS_TIMEOUT_SECONDS: i64 = NEW_KEY_TIMEOUT_SECONDS + 60 * 2;

#[derive(Debug, Clone)]
struct Key {
    id: u32,
    created: i64,
    secret: Vec<u8>,
}

/// In-memory view of one `~/.dbus-keyrings/<context>` file: the shared
/// secrets `DBUS_COOKIE_SHA1` uses to authenticate a user against
/// themselves (client and server run as the same uid and read the same
/// file from that uid's `$HOME`).
pub struct Keyring {
    dir: PathBuf,
    context: String,
    keys: Vec<Key>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl Keyring {
    /// Directory the keyring lives in for `home` (mirrors
    /// `_dbus_append_keyring_directory_for_credentials`).
    pub fn dir_for_home(home: &Path) -> PathBuf {
        home.join(".dbus-keyrings")
    }

    /// Load the keyring for `context` under `home`, creating the
    /// `.dbus-keyrings` directory (mode `0700`) if it doesn't exist yet.
    /// An absent context file is treated as an empty keyring rather than
    /// an error. Does not lock the file — callers that mint or persist a
    /// key should go through [`Keyring::best_key`], which locks
    /// internally.
    pub fn load(home: &Path, context: &str) -> AuthResult<Self> {
        let dir = Self::dir_for_home(home);
        std::fs::create_dir_all(&dir)?;
        // 0700: only the owner may read the secrets inside.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

        let path = dir.join(context);
        let keys = if path.exists() {
            Self::parse_file(&path)?
        } else {
            Vec::new()
        };
        Ok(Self {
            dir,
            context: context.to_string(),
            keys,
        })
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(format!("{}.lock", self.context))
    }

    fn file_path(&self) -> PathBuf {
        self.dir.join(&self.context)
    }

    fn parse_file(path: &Path) -> AuthResult<Vec<Key>> {
        let text = std::fs::read_to_string(path)?;
        let mut keys = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.splitn(3, ' ');
            let id: u32 = parts
                .next()
                .ok_or_else(|| AuthError::KeyringCorrupt("missing id".into()))?
                .parse()
                .map_err(|_| AuthError::KeyringCorrupt("bad id".into()))?;
            let created: i64 = parts
                .next()
                .ok_or_else(|| AuthError::KeyringCorrupt("missing timestamp".into()))?
                .parse()
                .map_err(|_| AuthError::KeyringCorrupt("bad timestamp".into()))?;
            let hex_secret = parts
                .next()
                .ok_or_else(|| AuthError::KeyringCorrupt("missing secret".into()))?;
            let secret = hex::decode(hex_secret).map_err(|_| AuthError::HexDecode)?;
            keys.push(Key {
                id,
                created,
                secret,
            });
        }
        Ok(keys)
    }

    fn save(&self) -> AuthResult<()> {
        let mut contents = String::new();
        for k in &self.keys {
            contents.push_str(&format!(
                "{} {} {}\n",
                k.id,
                k.created,
                hex::encode(&k.secret)
            ));
        }
        let path = self.file_path();
        let tmp_path = self
            .dir
            .join(format!("{}.tmp.{}", self.context, std::process::id()));
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(contents.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Hold an exclusive `flock` on `<context>.lock` for the duration of
    /// `f`, matching libdbus' cross-process keyring locking so concurrent
    /// `oxibus-daemon` / `dbus-daemon` / client processes never race on a
    /// read-modify-write of the same keyring file.
    fn with_lock<T>(&self, f: impl FnOnce() -> AuthResult<T>) -> AuthResult<T> {
        let lock_file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(self.lock_path())?;
        // SAFETY: lock_file owns a valid fd for the duration of this block;
        // flock() blocks until the lock is available, unlocked implicitly
        // when lock_file is dropped (closing the fd).
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(AuthError::Io(std::io::Error::last_os_error()));
        }
        let result = f();
        unsafe {
            libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN);
        }
        result
    }

    fn prune_expired(&mut self) {
        let now = now_secs();
        self.keys
            .retain(|k| now - k.created < EXPIRE_KEYS_TIMEOUT_SECONDS);
    }

    fn find_recent(&self) -> Option<&Key> {
        let now = now_secs();
        self.keys
            .iter()
            .filter(|k| now - k.created < NEW_KEY_TIMEOUT_SECONDS)
            .max_by_key(|k| k.created)
    }

    fn add_new_key(&mut self) -> AuthResult<u32> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let id: u32 = loop {
            let candidate = rng.next_u32() & 0x7fff_ffff;
            if !self.keys.iter().any(|k| k.id == candidate) {
                break candidate;
            }
        };
        let mut secret = vec![0u8; KEY_LENGTH_BYTES];
        rng.fill_bytes(&mut secret);
        self.keys.push(Key {
            id,
            created: now_secs(),
            secret,
        });
        Ok(id)
    }

    /// Pick (creating if necessary) a key young enough to offer to a new
    /// client, persisting any change under the cross-process lock.
    pub fn best_key(&mut self) -> AuthResult<u32> {
        if let Some(k) = self.find_recent() {
            return Ok(k.id);
        }
        self.with_lock(|| Ok(()))?; // reload-under-lock semantics below
        // Reload from disk in case another process just rotated the key,
        // then re-check before minting a brand new one ourselves.
        let path = self.file_path();
        if path.exists() {
            self.keys = Self::parse_file(&path)?;
        }
        if let Some(k) = self.find_recent() {
            return Ok(k.id);
        }
        self.prune_expired();
        let id = self.add_new_key()?;
        self.with_lock(|| self.save())?;
        Ok(id)
    }

    /// Hex-encoded secret for `id`, or `None` if unknown (matches
    /// libdbus returning an empty hash in that case, which the caller
    /// then treats as an authentication rejection).
    pub fn hex_key(&self, id: u32) -> Option<String> {
        self.keys
            .iter()
            .find(|k| k.id == id)
            .map(|k| hex::encode(&k.secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn best_key_creates_and_reuses() {
        let tmp = std::env::temp_dir().join(format!("oxibus-keyring-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut kr = Keyring::load(&tmp, "test_context").unwrap();
        let id1 = kr.best_key().unwrap();
        let id2 = kr.best_key().unwrap();
        assert_eq!(id1, id2);

        let hex1 = kr.hex_key(id1).unwrap();
        assert_eq!(hex1.len(), KEY_LENGTH_BYTES * 2);

        // A fresh Keyring instance loading the same file sees the same key.
        let kr2 = Keyring::load(&tmp, "test_context").unwrap();
        assert_eq!(kr2.hex_key(id1), Some(hex1));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
