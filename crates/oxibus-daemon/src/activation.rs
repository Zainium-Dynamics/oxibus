//! Traditional (on-demand, non-systemd) bus activation: TOML service files
//! instead of D-Bus's classic `.service` ini files, same idea — a bus name
//! maps to a command line to run when nothing currently owns that name
//! (matches `bus/activation.c` + `-Dtraditional_activation=true`).
//!
//! ```toml
//! [service]
//! name = "org.freedesktop.Notifications"
//! exec = "/overlayer/syshub/bin/notification-daemon"
//! args = []
//! user = "notifications"
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

use serde::Deserialize;
use tokio::process::Command;

#[derive(Debug, Clone, Deserialize)]
struct ServiceFile {
    service: ServiceDef,
}

/// One `[service]` TOML file's worth of activation config for a single bus
/// name.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServiceDef {
    /// The bus name this file activates; must match the key it's stored
    /// under in [`ActivationRegistry`] (see [`crate::launch_helper::find_service`]'s
    /// consistency check).
    pub name: String,
    /// Path to the executable to run. Never shell-interpreted — passed
    /// straight to `exec`/`Command::new`.
    pub exec: String,
    /// Argument vector passed to `exec` as-is (no shell word-splitting).
    #[serde(default)]
    pub args: Vec<String>,
    /// The user to run the service as. Required for system-bus activation
    /// via the setuid launch helper; optional (and, if set, must match the
    /// daemon's own uid) for direct session-bus spawning.
    #[serde(default)]
    pub user: Option<String>,
    /// Extra environment variables to set on the spawned process. Only
    /// applied in [`SpawnStrategy::Direct`] mode — see [`ActivationRegistry::spawn`].
    #[serde(default)]
    pub environment: HashMap<String, String>,
}

/// How a service gets spawned — mirrors real dbus's `<servicehelper>`
/// split in `bus/activation.c`: the session bus has no privilege boundary
/// to cross and spawns directly; the system bus never execs a service
/// command itself, only the setuid `oxibus-daemon-launch-helper`, passing
/// nothing but the validated bus name (see `crates/oxibus-daemon/src/bin/
/// oxibus-daemon-launch-helper.rs` for why: the helper re-derives the
/// actual command/user from trusted on-disk config rather than trusting
/// anything the — possibly already-compromised — daemon process hands it).
pub enum SpawnStrategy<'a> {
    /// Fork/exec the service's own `exec`/`args`/`environment` directly —
    /// only ever used for the session bus.
    Direct,
    /// Exec the setuid `oxibus-daemon-launch-helper` at this path instead,
    /// passing only the bus name — used for the system bus.
    ViaLaunchHelper(&'a Path),
}

/// Errors from looking up or spawning an activatable service.
#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    /// No `[service]` file registers this bus name.
    #[error("service unknown: {0}")]
    ServiceUnknown(String),
    /// The service process could not be spawned, or spawning it was refused
    /// (e.g. a system-bus service with no configured user).
    #[error("exec failed: {0}")]
    ExecFailed(String),
    /// The service was spawned but never claimed its name before
    /// [`ActivationRegistry::DEFAULT_POLL_INTERVAL`]-spaced polling hit the
    /// configured activation timeout.
    #[error("activation timed out waiting for '{0}' to appear on the bus")]
    TimedOut(String),
}

/// In-memory table of activatable service definitions, loaded once at
/// startup from every `*.toml` file under the configured service
/// directories (later duplicates by name overwrite earlier ones).
pub struct ActivationRegistry {
    services: RwLock<HashMap<String, ServiceDef>>,
}

impl ActivationRegistry {
    /// Parse every `*.toml` file in `dirs` into a [`ServiceDef`], keyed by
    /// its `name`. Malformed files are logged and skipped rather than
    /// failing startup.
    pub fn load(dirs: &[PathBuf]) -> Self {
        let mut services = HashMap::new();
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str());
                if ext == Some("toml") {
                    match std::fs::read_to_string(&path).and_then(|t| {
                        toml::from_str::<ServiceFile>(&t)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                    }) {
                        Ok(f) => {
                            services.insert(f.service.name.clone(), f.service);
                        }
                        Err(e) => {
                            tracing::warn!("skipping malformed service file {}: {e}", path.display());
                        }
                    }
                } else if ext == Some("service") {
                    match std::fs::read_to_string(&path) {
                        Ok(text) => {
                            if let Some(def) = parse_ini_service(&text) {
                                services.insert(def.name.clone(), def);
                            } else {
                                tracing::warn!("skipping malformed legacy service file {}", path.display());
                            }
                        }
                        Err(e) => {
                            tracing::warn!("failed to read legacy service file {}: {e}", path.display());
                        }
                    }
                }
            }
        }
        Self {
            services: RwLock::new(services),
        }
    }

    /// Is there a `[service]` file registering `name`?
    pub fn is_activatable(&self, name: &str) -> bool {
        self.services.read().unwrap().contains_key(name)
    }

    /// All registered bus names, in arbitrary order (backs
    /// `ListActivatableNames`).
    pub fn list_activatable_names(&self) -> Vec<String> {
        self.services.read().unwrap().keys().cloned().collect()
    }

    /// Look up a service definition by its bus name — used both by
    /// `spawn()`'s direct-mode path and by `oxibus-daemon-launch-helper`,
    /// which builds its own independent `ActivationRegistry` from the
    /// trusted on-disk service dirs and calls this itself (never receiving
    /// a `ServiceDef` from the daemon process).
    pub fn lookup(&self, name: &str) -> Option<ServiceDef> {
        self.services.read().unwrap().get(name).cloned()
    }

    /// Spawn the process registered for `name`. Returns once the process
    /// has been forked/exec'd (or immediately fails to start) — it does
    /// NOT wait for the service to actually claim the name; callers poll
    /// the bus registry for that (see `Bus::start_service_by_name`).
    ///
    /// `extra_env` is whatever `UpdateActivationEnvironment` has
    /// accumulated on the bus. It is only ever applied in [`SpawnStrategy::Direct`]
    /// mode (the session bus) — real dbus rejects
    /// `UpdateActivationEnvironment` outright once a servicehelper is
    /// configured (`bus/driver.c`), precisely so an unprivileged caller can
    /// never smuggle environment into a setuid-launched system service.
    pub fn spawn(
        &self,
        name: &str,
        extra_env: &std::collections::HashMap<String, String>,
        strategy: SpawnStrategy<'_>,
    ) -> Result<(), ActivationError> {
        let def = self
            .lookup(name)
            .ok_or_else(|| ActivationError::ServiceUnknown(name.to_string()))?;

        if let SpawnStrategy::ViaLaunchHelper(helper_path) = strategy {
            // Belt-and-suspenders check mirroring activation.c: the daemon
            // itself also refuses to invoke the helper for a service with
            // no configured user, rather than relying solely on the
            // helper's own (also present) check.
            if def.user.is_none() {
                return Err(ActivationError::ExecFailed(format!(
                    "service '{name}' has no `user =` set — required for system-bus activation"
                )));
            }
            // Deliberately nothing else: no extra_env, no def.environment,
            // no def.exec/def.args. The setuid helper re-derives all of
            // that itself from trusted on-disk config; passing it here
            // would just be an untrusted process asserting things a
            // privileged one must not believe.
            Command::new(helper_path)
                .arg(name)
                .stdin(std::process::Stdio::null())
                .spawn()
                .map_err(|e| ActivationError::ExecFailed(e.to_string()))?;
            return Ok(());
        }

        let mut cmd = Command::new(&def.exec);
        cmd.args(&def.args);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        for (k, v) in &def.environment {
            cmd.env(k, v);
        }
        cmd.stdin(std::process::Stdio::null());

        // Direct mode never crosses a privilege boundary in practice (it's
        // only used for the session bus, which is never root) — but if a
        // service file still asks for a specific user, fail closed unless
        // we already happen to be that exact user, rather than silently
        // running as whoever the daemon currently is.
        if let Some(user) = &def.user {
            let target_uid = resolve_uid(user)
                .ok_or_else(|| ActivationError::ExecFailed(format!("unknown user '{user}'")))?;
            // SAFETY: getuid() has no preconditions.
            let current_uid = unsafe { libc::getuid() };
            if target_uid != current_uid {
                return Err(ActivationError::ExecFailed(format!(
                    "cannot activate '{name}' as user '{user}': not running as that user and \
                     no launch helper configured for this bus"
                )));
            }
        }

        cmd.spawn()
            .map_err(|e| ActivationError::ExecFailed(e.to_string()))?;
        Ok(())
    }

    /// Interval between registry polls while waiting for an activated
    /// service to claim its name (see [`crate::driver::activate_and_wait`]).
    pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);
}

fn resolve_uid(user: &str) -> Option<u32> {
    if let Ok(uid) = user.parse::<u32>() {
        return Some(uid);
    }
    // SAFETY: getpwnam is not thread-safe re: its static return buffer, but
    // we copy out only the uid field before any other libc call.
    unsafe {
        let cname = std::ffi::CString::new(user).ok()?;
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some((*pw).pw_uid)
        }
    }
}

fn parse_ini_service(content: &str) -> Option<ServiceDef> {
    let mut name = None;
    let mut exec = None;
    let mut user = None;
    let mut in_section = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            if section.eq_ignore_ascii_case("D-BUS Service") {
                in_section = true;
            } else {
                in_section = false;
            }
            continue;
        }

        if in_section {
            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim();
                let val = line[pos + 1..].trim();
                
                if key.eq_ignore_ascii_case("Name") {
                    name = Some(val.to_string());
                } else if key.eq_ignore_ascii_case("Exec") {
                    exec = Some(val.to_string());
                } else if key.eq_ignore_ascii_case("User") {
                    user = Some(val.to_string());
                }
            }
        }
    }

    let (name_str, exec_str) = (name?, exec?);

    // Split exec to get binary path and args
    let mut parts = Vec::new();
    let mut chars = exec_str.chars().peekable();
    let mut current = String::new();
    let mut in_quotes = false;

    while let Some(c) = chars.next() {
        if c == '"' {
            in_quotes = !in_quotes;
        } else if c.is_whitespace() && !in_quotes {
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }

    if parts.is_empty() {
        return None;
    }

    let exec_bin = parts.remove(0);

    Some(ServiceDef {
        name: name_str,
        exec: exec_bin,
        args: parts,
        user,
        environment: HashMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_and_looks_up_service_files() {
        let dir = std::env::temp_dir().join(format!("oxibus-activation-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("com.example.Foo.toml"),
            r#"
[service]
name = "com.example.Foo"
exec = "/bin/true"
"#,
        )
        .unwrap();

        std::fs::write(
            dir.join("org.example.Bar.service"),
            r#"
[D-BUS Service]
Name=org.example.Bar
Exec=/bin/false --arg1 "arg 2"
User=nobody
"#,
        )
        .unwrap();

        let reg = ActivationRegistry::load(&[dir.clone()]);
        assert!(reg.is_activatable("com.example.Foo"));
        assert!(reg.is_activatable("org.example.Bar"));
        assert!(!reg.is_activatable("com.example.Baz"));
        
        let bar = reg.lookup("org.example.Bar").unwrap();
        assert_eq!(bar.name, "org.example.Bar");
        assert_eq!(bar.exec, "/bin/false");
        assert_eq!(bar.args, vec!["--arg1".to_string(), "arg 2".to_string()]);
        assert_eq!(bar.user.as_deref(), Some("nobody"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_parse_ini_service() {
        let content = r#"
        # comment line
        [D-BUS Service]
        Name = org.freedesktop.Notifications
        Exec = /overlayer/syshub/bin/notification-daemon --some-flag
        User = notifications
        "#;
        let def = parse_ini_service(content).unwrap();
        assert_eq!(def.name, "org.freedesktop.Notifications");
        assert_eq!(def.exec, "/overlayer/syshub/bin/notification-daemon");
        assert_eq!(def.args, vec!["--some-flag".to_string()]);
        assert_eq!(def.user.as_deref(), Some("notifications"));
    }
}
