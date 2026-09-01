#![allow(rustdoc::broken_intra_doc_links)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: Box<toml::de::Error>,
    },
}

pub type ConfigResult<T> = Result<T, ConfigError>;

// Project configuration table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(default = "default_project_name")]
    pub name: String,
    #[serde(default = "default_project_version")]
    pub version: String,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: default_project_name(),
            version: default_project_version(),
        }
    }
}

fn default_project_name() -> String {
    "oxibus".into()
}
fn default_project_version() -> String {
    "0.1.0".into()
}

// Subsystem feature toggles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesConfig {
    #[serde(default = "default_true")]
    pub message_bus: bool,
    #[serde(default = "default_true")]
    pub tools: bool,
    #[serde(default = "default_true")]
    pub traditional_activation: bool,
    #[serde(default = "default_true")]
    pub stats: bool,
    #[serde(default = "default_true")]
    pub cookie_sha1: bool,
    #[serde(default = "default_true")]
    pub unix_fd_passing: bool,
    #[serde(default)]
    pub systemd: bool,
    #[serde(default)]
    pub selinux: bool,
    #[serde(default)]
    pub apparmor: bool,
    #[serde(default)]
    pub libaudit: bool,
    #[serde(default)]
    pub launchd: bool,
    #[serde(default)]
    pub x11_autolaunch: bool,
}

impl Default for FeaturesConfig {
    fn default() -> Self {
        Self {
            message_bus: true,
            tools: true,
            traditional_activation: true,
            stats: true,
            cookie_sha1: true,
            unix_fd_passing: true,
            systemd: false,
            selinux: false,
            apparmor: false,
            libaudit: false,
            launchd: false,
            x11_autolaunch: false,
        }
    }
}

fn default_true() -> bool {
    true
}

// Filesystem layout paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default = "default_bindir")]
    pub bindir: String,
    #[serde(default = "default_sbindir")]
    pub sbindir: String,
    #[serde(default = "default_libdir")]
    pub libdir: String,
    #[serde(default = "default_includedir")]
    pub includedir: String,
    #[serde(default = "default_conf_dir")]
    pub conf_dir: String,
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
    #[serde(default = "default_services_dir")]
    pub services_dir: String,
    #[serde(default = "default_vendor_services_dir")]
    pub vendor_services_dir: String,
    #[serde(default = "default_share_dir")]
    pub share_dir: String,
    #[serde(default = "default_runtime_dir")]
    pub runtime_dir: String,
    #[serde(default = "default_system_socket")]
    pub system_socket: String,
    #[serde(default = "default_system_pid_file")]
    pub system_pid_file: String,
    #[serde(default = "default_session_socket_dir")]
    pub session_socket_dir: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    #[serde(default = "default_machine_id_file")]
    pub machine_id_file: String,
    #[serde(default = "default_launch_helper")]
    pub launch_helper: String,
    #[serde(default = "default_legacy_system_socket")]
    pub legacy_system_socket: String,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            prefix: default_prefix(),
            bindir: default_bindir(),
            sbindir: default_sbindir(),
            libdir: default_libdir(),
            includedir: default_includedir(),
            conf_dir: default_conf_dir(),
            policy_dir: default_policy_dir(),
            services_dir: default_services_dir(),
            vendor_services_dir: default_vendor_services_dir(),
            share_dir: default_share_dir(),
            runtime_dir: default_runtime_dir(),
            system_socket: default_system_socket(),
            system_pid_file: default_system_pid_file(),
            session_socket_dir: default_session_socket_dir(),
            state_dir: default_state_dir(),
            machine_id_file: default_machine_id_file(),
            launch_helper: default_launch_helper(),
            legacy_system_socket: default_legacy_system_socket(),
        }
    }
}

fn default_prefix() -> String {
    "/overlayer/syshub".into()
}
fn default_bindir() -> String {
    "/bin".into()
}
fn default_sbindir() -> String {
    "/sbin".into()
}
fn default_libdir() -> String {
    "/lib".into()
}
fn default_includedir() -> String {
    "/include".into()
}
fn default_conf_dir() -> String {
    "/etc/oxibus".into()
}
fn default_policy_dir() -> String {
    "/etc/oxibus/policy.d".into()
}
fn default_services_dir() -> String {
    "/etc/oxibus/services".into()
}
fn default_vendor_services_dir() -> String {
    "/lib/oxibus/services".into()
}
fn default_share_dir() -> String {
    "/share/oxibus".into()
}
fn default_runtime_dir() -> String {
    "/run".into()
}
fn default_system_socket() -> String {
    "/run/oxibus/system_bus_socket".into()
}
fn default_system_pid_file() -> String {
    "/run/oxibus/pid".into()
}
fn default_session_socket_dir() -> String {
    "/tmp".into()
}
fn default_state_dir() -> String {
    "/var/lib/oxibus".into()
}
fn default_machine_id_file() -> String {
    "/var/lib/oxibus/machine-id".into()
}
fn default_launch_helper() -> String {
    "/libexec/dbus-daemon-launch-helper".into()
}
fn default_legacy_system_socket() -> String {
    "/run/dbus/system_bus_socket".into()
}

impl PathsConfig {
    pub fn as_path(field: &str) -> PathBuf {
        PathBuf::from(field)
    }

    pub fn bin_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.bindir)
    }
    pub fn sbin_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.sbindir)
    }
    pub fn lib_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.libdir)
    }
    pub fn include_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.includedir)
    }
    pub fn share_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.share_dir)
    }
    pub fn launch_helper_path(&self) -> PathBuf {
        joined(&self.prefix, &self.launch_helper)
    }
    pub fn conf_dir(&self) -> PathBuf {
        Self::as_path(&self.conf_dir)
    }
    pub fn policy_dir(&self) -> PathBuf {
        Self::as_path(&self.policy_dir)
    }
    pub fn services_dir(&self) -> PathBuf {
        Self::as_path(&self.services_dir)
    }
    pub fn vendor_services_dir(&self) -> PathBuf {
        Self::as_path(&self.vendor_services_dir)
    }
    pub fn state_dir(&self) -> PathBuf {
        Self::as_path(&self.state_dir)
    }
    pub fn machine_id_file(&self) -> PathBuf {
        Self::as_path(&self.machine_id_file)
    }
    pub fn system_socket(&self) -> PathBuf {
        Self::as_path(&self.system_socket)
    }
    pub fn legacy_system_socket(&self) -> PathBuf {
        Self::as_path(&self.legacy_system_socket)
    }
    pub fn system_pid_file(&self) -> PathBuf {
        Self::as_path(&self.system_pid_file)
    }

    pub fn rooted(&self, destroot: &Path) -> PathBuf {
        destroot.to_path_buf()
    }
}

fn joined(prefix: &str, sub: &str) -> PathBuf {
    let mut p = PathBuf::from(prefix);
    p.push(sub.trim_start_matches('/'));
    p
}

// System bus daemon settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusSystemConfig {
    #[serde(default = "default_bus_user")]
    pub user: String,
    #[serde(default = "default_system_listen")]
    pub listen: String,
    #[serde(default = "default_system_pid_file")]
    pub pidfile: String,
    #[serde(default = "default_auth_mechanisms")]
    pub auth_mechanisms: Vec<String>,
    #[serde(default)]
    pub allow_anonymous: bool,
}

impl Default for BusSystemConfig {
    fn default() -> Self {
        Self {
            user: default_bus_user(),
            listen: default_system_listen(),
            pidfile: default_system_pid_file(),
            auth_mechanisms: default_auth_mechanisms(),
            allow_anonymous: false,
        }
    }
}

fn default_bus_user() -> String {
    "messagebus".into()
}
fn default_system_listen() -> String {
    "unix:path=/run/oxibus/system_bus_socket".into()
}
fn default_auth_mechanisms() -> Vec<String> {
    vec![
        "EXTERNAL".into(),
        "DBUS_COOKIE_SHA1".into(),
        "ANONYMOUS".into(),
    ]
}

// Session bus settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusSessionConfig {
    #[serde(default = "default_session_listen")]
    pub listen: String,
    #[serde(default = "default_session_auth_mechanisms")]
    pub auth_mechanisms: Vec<String>,
    #[serde(default)]
    pub allow_anonymous: bool,
}

impl Default for BusSessionConfig {
    fn default() -> Self {
        Self {
            listen: default_session_listen(),
            auth_mechanisms: default_session_auth_mechanisms(),
            allow_anonymous: false,
        }
    }
}

fn default_session_listen() -> String {
    "unix:tmpdir=/tmp".into()
}
fn default_session_auth_mechanisms() -> Vec<String> {
    vec!["EXTERNAL".into(), "DBUS_COOKIE_SHA1".into()]
}

// Bus configuration wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BusConfig {
    #[serde(default)]
    pub system: BusSystemConfig,
    #[serde(default)]
    pub session: BusSessionConfig,
}

// Limits configuration table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_incoming_bytes")]
    pub max_incoming_bytes: u64,
    #[serde(default = "default_max_outgoing_bytes")]
    pub max_outgoing_bytes: u64,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: u32,
    #[serde(default = "default_max_message_unix_fds")]
    pub max_message_unix_fds: u32,
    #[serde(default = "default_max_completed_connections")]
    pub max_completed_connections: u32,
    #[serde(default = "default_max_incomplete_connections")]
    pub max_incomplete_connections: u32,
    #[serde(default = "default_max_connections_per_user")]
    pub max_connections_per_user: u32,
    #[serde(default = "default_max_pending_service_starts")]
    pub max_pending_service_starts: u32,
    #[serde(default = "default_max_names_per_connection")]
    pub max_names_per_connection: u32,
    #[serde(default = "default_max_match_rules_per_connection")]
    pub max_match_rules_per_connection: u32,
    #[serde(default = "default_activation_timeout_ms")]
    pub activation_timeout_ms: u64,
    #[serde(default = "default_auth_timeout_ms")]
    pub auth_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_incoming_bytes: default_max_incoming_bytes(),
            max_outgoing_bytes: default_max_outgoing_bytes(),
            max_message_size: default_max_message_size(),
            max_message_unix_fds: default_max_message_unix_fds(),
            max_completed_connections: default_max_completed_connections(),
            max_incomplete_connections: default_max_incomplete_connections(),
            max_connections_per_user: default_max_connections_per_user(),
            max_pending_service_starts: default_max_pending_service_starts(),
            max_names_per_connection: default_max_names_per_connection(),
            max_match_rules_per_connection: default_max_match_rules_per_connection(),
            activation_timeout_ms: default_activation_timeout_ms(),
            auth_timeout_ms: default_auth_timeout_ms(),
        }
    }
}

fn default_max_incoming_bytes() -> u64 {
    1_000_000_000
}
fn default_max_outgoing_bytes() -> u64 {
    1_000_000_000
}
fn default_max_message_size() -> u32 {
    134_217_728
}
fn default_max_message_unix_fds() -> u32 {
    1024
}
fn default_max_completed_connections() -> u32 {
    100_000
}
fn default_max_incomplete_connections() -> u32 {
    64
}
fn default_max_connections_per_user() -> u32 {
    512
}
fn default_max_pending_service_starts() -> u32 {
    512
}
fn default_max_names_per_connection() -> u32 {
    50_000
}
fn default_max_match_rules_per_connection() -> u32 {
    50_000
}
fn default_activation_timeout_ms() -> u64 {
    25_000
}
fn default_auth_timeout_ms() -> u64 {
    30_000
}

// Logging settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_ident")]
    pub ident: String,
    #[serde(default = "default_log_target")]
    pub target: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            ident: default_log_ident(),
            target: default_log_target(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}
fn default_log_ident() -> String {
    "dbus-daemon".into()
}
fn default_log_target() -> String {
    "stderr".into()
}

// Global oxibus.toml structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    #[serde(default)]
    pub project: ProjectConfig,
    #[serde(default)]
    pub features: FeaturesConfig,
    #[serde(default)]
    pub paths: PathsConfig,
    #[serde(default)]
    pub bus: BusConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl GlobalConfig {
    pub fn parse(text: &str) -> ConfigResult<Self> {
        toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: "<inline>".into(),
            source: Box::new(e),
        })
    }

    pub fn load_path(path: impl AsRef<Path>) -> ConfigResult<Self> {
        let path_ref = path.as_ref();
        let text = std::fs::read_to_string(path_ref).map_err(|e| ConfigError::Io {
            path: path_ref.display().to_string(),
            source: e,
        })?;
        toml::from_str(&text).map_err(|e| ConfigError::Parse {
            path: path_ref.display().to_string(),
            source: Box::new(e),
        })
    }

    pub fn load_default() -> Self {
        if let Ok(explicit) = std::env::var("OXIBUS_CONFIG")
            && let Ok(cfg) = Self::load_path(&explicit)
        {
            return cfg;
        }
        let candidates = ["/etc/oxibus/oxibus.toml", "/etc/oxibus.toml", "oxibus.toml"];
        for c in candidates {
            if let Ok(cfg) = Self::load_path(c) {
                return cfg;
            }
        }
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_zainium_layout() {
        let cfg = GlobalConfig::default();
        assert_eq!(cfg.paths.prefix, "/overlayer/syshub");
        assert_eq!(cfg.paths.bin_dir(), PathBuf::from("/overlayer/syshub/bin"));
        assert_eq!(
            cfg.paths.system_socket(),
            PathBuf::from("/run/oxibus/system_bus_socket")
        );
        assert!(!cfg.features.systemd);
        assert!(!cfg.features.selinux);
        assert!(cfg.features.message_bus);
    }

    #[test]
    fn parses_full_oxibus_toml() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../oxibus.toml"))
                .expect("root oxibus.toml must exist");
        let cfg = GlobalConfig::parse(&text).expect("root oxibus.toml must parse");
        assert_eq!(cfg.bus.system.user, "messagebus");
        assert_eq!(cfg.limits.max_message_size, 134_217_728);
    }
}
