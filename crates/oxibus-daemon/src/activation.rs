// On-demand service activation handling.

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

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ServiceDef {
    pub name: String,
    pub exec: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub environment: HashMap<String, String>,
}

pub enum SpawnStrategy<'a> {
    Direct,
    ViaLaunchHelper(&'a Path),
}

#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    #[error("service unknown: {0}")]
    ServiceUnknown(String),
    #[error("exec failed: {0}")]
    ExecFailed(String),
    #[error("activation timed out waiting for '{0}' to appear on the bus")]
    TimedOut(String),
}

pub struct ActivationRegistry {
    services: RwLock<HashMap<String, ServiceDef>>,
}

impl ActivationRegistry {
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
                            tracing::warn!(
                                "skipping malformed service file {}: {e}",
                                path.display()
                            );
                        }
                    }
                } else if ext == Some("service") {
                    match std::fs::read_to_string(&path) {
                        Ok(text) => {
                            if let Some(def) = parse_ini_service(&text) {
                                services.insert(def.name.clone(), def);
                            } else {
                                tracing::warn!(
                                    "skipping malformed legacy service file {}",
                                    path.display()
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "failed to read legacy service file {}: {e}",
                                path.display()
                            );
                        }
                    }
                }
            }
        }
        Self {
            services: RwLock::new(services),
        }
    }

    pub fn is_activatable(&self, name: &str) -> bool {
        self.services.read().unwrap().contains_key(name)
    }

    pub fn list_activatable_names(&self) -> Vec<String> {
        self.services.read().unwrap().keys().cloned().collect()
    }

    pub fn lookup(&self, name: &str) -> Option<ServiceDef> {
        self.services.read().unwrap().get(name).cloned()
    }

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
            if def.user.is_none() {
                return Err(ActivationError::ExecFailed(format!(
                    "service '{name}' has no `user =` set — required for system-bus activation"
                )));
            }
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

        if let Some(user) = &def.user {
            let target_uid = resolve_uid(user)
                .ok_or_else(|| ActivationError::ExecFailed(format!("unknown user '{user}'")))?;
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

    pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);
}

fn resolve_uid(user: &str) -> Option<u32> {
    if let Ok(uid) = user.parse::<u32>() {
        return Some(uid);
    }
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
            in_section = section.eq_ignore_ascii_case("D-BUS Service");
            continue;
        }

        if in_section && let Some(pos) = line.find('=') {
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

    let (name_str, exec_str) = (name?, exec?);

    let mut parts = Vec::new();
    let chars = exec_str.chars().peekable();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in chars {
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
        let dir =
            std::env::temp_dir().join(format!("oxibus-activation-test-{}", std::process::id()));
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

        let reg = ActivationRegistry::load(std::slice::from_ref(&dir));
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
