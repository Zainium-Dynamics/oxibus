#![allow(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
//! TOML-only configuration for the OxiBus workspace.
//!
//! Every OxiBus binary (daemon, tools, client examples) loads the same
//! `oxibus.toml` shape through [`GlobalConfig`]. All filesystem paths in the
//! rest of the codebase are derived from [`PathsConfig`] — nothing hardcodes
//! `/overlayer/syshub` or `/run/oxibus` outside of this file's `default_*`
//! functions, which exist only as the fallback when no `oxibus.toml` is
//! found at all.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Everything that can go wrong loading an `oxibus.toml`.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file at `path` could not be read from disk (missing, permissions, etc).
    #[error("read {path}: {source}")]
    Io {
        /// Path that was passed to [`GlobalConfig::load_path`].
        path: String,
        #[source]
        /// Underlying I/O failure.
        source: std::io::Error,
    },
    /// The file at `path` was read but is not valid `oxibus.toml` TOML.
    #[error("parse {path}: {source}")]
    Parse {
        /// Path the invalid TOML was read from (`"<inline>"` for [`GlobalConfig::parse`]).
        path: String,
        #[source]
        /// Underlying TOML deserialization failure.
        source: Box<toml::de::Error>,
    },
}

/// Result alias used throughout this crate's loading API.
pub type ConfigResult<T> = Result<T, ConfigError>;

// ── [project] ───────────────────────────────────────────────────────────────

/// The `[project]` table — metadata only, never consulted for behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    /// Project name, defaults to `"oxibus"`.
    #[serde(default = "default_project_name")]
    pub name: String,
    /// Project version string, defaults to `"0.1.0"`.
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

// ── [features] ──────────────────────────────────────────────────────────────

/// The `[features]` table. Toggles that gate optional subsystems at
/// runtime — most default to `true` (core bus behavior); the
/// platform-integration flags below default to `false` since Zainium
/// doesn't ship systemd/SELinux/AppArmor/launchd by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeaturesConfig {
    /// Enables the message bus (`org.freedesktop.DBus`) itself. Default `true`.
    #[serde(default = "default_true")]
    pub message_bus: bool,
    /// Enables the CLI tooling surface (introspection/debug helpers). Default `true`.
    #[serde(default = "default_true")]
    pub tools: bool,
    /// Enables classic `.service`-file activation (as opposed to Quantra-managed
    /// activation). Default `true`.
    #[serde(default = "default_true")]
    pub traditional_activation: bool,
    /// Enables `org.freedesktop.DBus.Debug.Stats`. Default `true`.
    #[serde(default = "default_true")]
    pub stats: bool,
    /// Enables the `DBUS_COOKIE_SHA1` SASL mechanism. Default `true`.
    #[serde(default = "default_true")]
    pub cookie_sha1: bool,
    /// Enables passing Unix file descriptors over the bus. Default `true`.
    #[serde(default = "default_true")]
    pub unix_fd_passing: bool,
    /// Enables systemd socket-activation integration. Default `false` (Zainium has no systemd).
    #[serde(default)]
    pub systemd: bool,
    /// Enables SELinux access-vector-cache mediation. Default `false`.
    #[serde(default)]
    pub selinux: bool,
    /// Enables AppArmor mediation. Default `false`.
    #[serde(default)]
    pub apparmor: bool,
    /// Enables libaudit event logging. Default `false`.
    #[serde(default)]
    pub libaudit: bool,
    /// Enables launchd socket-activation integration (macOS-style). Default `false`.
    #[serde(default)]
    pub launchd: bool,
    /// Enables X11 autolaunch (`DISPLAY`-keyed session bus discovery). Default `false`.
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

// ── [paths] ─────────────────────────────────────────────────────────────────

/// Filesystem layout. `prefix` is the RUNTIME path baked into binaries
/// (`/overlayer/syshub` on Zainium); every other field is either relative to
/// `prefix` (joined by [`PathsConfig::resolve`]) or already absolute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathsConfig {
    /// Runtime prefix baked into binaries at resolve time (default
    /// `/overlayer/syshub` on Zainium). Never a build-host path — this is
    /// the root the *installed* tree lives under.
    #[serde(default = "default_prefix")]
    pub prefix: String,
    /// Binary directory, joined with `prefix` by [`PathsConfig::bin_dir`]. Default `/bin`.
    #[serde(default = "default_bindir")]
    pub bindir: String,
    /// System-binary directory, joined with `prefix` by [`PathsConfig::sbin_dir`]. Default `/sbin`.
    #[serde(default = "default_sbindir")]
    pub sbindir: String,
    /// Library directory, joined with `prefix` by [`PathsConfig::lib_dir`]. Default `/lib`.
    #[serde(default = "default_libdir")]
    pub libdir: String,
    /// Header/include directory, joined with `prefix` by [`PathsConfig::include_dir`]. Default `/include`.
    #[serde(default = "default_includedir")]
    pub includedir: String,
    /// Configuration directory. Stored and resolved as an absolute path
    /// (NOT joined with `prefix` — see [`PathsConfig::conf_dir`]), because
    /// `/etc` is the live, writable system root, not part of the overlay
    /// tree. Default `/etc/oxibus`.
    #[serde(default = "default_conf_dir")]
    pub conf_dir: String,
    /// Directory of `[[rule]]` policy TOML files, absolute (not prefix-joined). Default `/etc/oxibus/policy.d`.
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
    /// Directory of user-installed activation service files, absolute (not prefix-joined). Default `/etc/oxibus/services`.
    #[serde(default = "default_services_dir")]
    pub services_dir: String,
    /// Directory of vendor-shipped activation service files, resolved as
    /// an absolute path by [`PathsConfig::vendor_services_dir`] despite
    /// its default (`/lib/oxibus/services`) looking prefix-relative.
    #[serde(default = "default_vendor_services_dir")]
    pub vendor_services_dir: String,
    /// Shared data directory, joined with `prefix` by [`PathsConfig::share_dir`]. Default `/share/oxibus`.
    #[serde(default = "default_share_dir")]
    pub share_dir: String,
    /// Runtime (`/run`-style) directory root. Default `/run`; no dedicated
    /// resolver method exists for this field, unlike the others.
    #[serde(default = "default_runtime_dir")]
    pub runtime_dir: String,
    /// System bus listen socket path, absolute (not prefix-joined). Default `/run/oxibus/system_bus_socket`.
    #[serde(default = "default_system_socket")]
    pub system_socket: String,
    /// System bus daemon PID file, absolute (not prefix-joined). Default `/run/oxibus/pid`.
    #[serde(default = "default_system_pid_file")]
    pub system_pid_file: String,
    /// Directory session-bus sockets are created under (`unix:tmpdir=`).
    /// Default `/tmp`; no dedicated resolver method exists for this field.
    #[serde(default = "default_session_socket_dir")]
    pub session_socket_dir: String,
    /// Persistent daemon state directory, absolute (not prefix-joined). Default `/var/lib/oxibus`.
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    /// Path to the persisted D-Bus machine ID, absolute (not prefix-joined). Default `/var/lib/oxibus/machine-id`.
    #[serde(default = "default_machine_id_file")]
    pub machine_id_file: String,
    /// Path to the setuid activation launch helper binary, joined with
    /// `prefix` by [`PathsConfig::launch_helper_path`]. Default
    /// `/libexec/oxibus-daemon-launch-helper`.
    #[serde(default = "default_launch_helper")]
    pub launch_helper: String,
    /// Legacy `dbus-daemon`-compatible system socket path, absolute (not
    /// prefix-joined), kept for clients that still hardcode it. Default
    /// `/run/dbus/system_bus_socket`.
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
    "/libexec/oxibus-daemon-launch-helper".into()
}
fn default_legacy_system_socket() -> String {
    "/run/dbus/system_bus_socket".into()
}

impl PathsConfig {
    /// Join `prefix` with a path that is conf/state/runtime-style (already
    /// absolute in `oxibus.toml`, e.g. `/etc/oxibus`) — these are NOT
    /// prefix-relative on Zainium (etc/run/var sit next to, not under,
    /// `prefix`), matching `build-zainium-dbus.sh`'s DESTDIR merge layout.
    pub fn as_path(field: &str) -> PathBuf {
        PathBuf::from(field)
    }

    /// Resolved binary directory (`prefix` + `bindir`).
    pub fn bin_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.bindir)
    }
    /// Resolved system-binary directory (`prefix` + `sbindir`).
    pub fn sbin_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.sbindir)
    }
    /// Resolved library directory (`prefix` + `libdir`).
    pub fn lib_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.libdir)
    }
    /// Resolved include directory (`prefix` + `includedir`).
    pub fn include_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.includedir)
    }
    /// Resolved shared-data directory (`prefix` + `share_dir`).
    pub fn share_dir(&self) -> PathBuf {
        joined(&self.prefix, &self.share_dir)
    }
    /// Resolved path to the setuid activation launch helper (`prefix` + `launch_helper`).
    pub fn launch_helper_path(&self) -> PathBuf {
        joined(&self.prefix, &self.launch_helper)
    }
    /// Configuration directory, taken as-is (not joined with `prefix`).
    pub fn conf_dir(&self) -> PathBuf {
        Self::as_path(&self.conf_dir)
    }
    /// Policy rule directory, taken as-is (not joined with `prefix`).
    pub fn policy_dir(&self) -> PathBuf {
        Self::as_path(&self.policy_dir)
    }
    /// User-installed service directory, taken as-is (not joined with `prefix`).
    pub fn services_dir(&self) -> PathBuf {
        Self::as_path(&self.services_dir)
    }
    /// Vendor-shipped service directory, taken as-is (not joined with `prefix`).
    pub fn vendor_services_dir(&self) -> PathBuf {
        Self::as_path(&self.vendor_services_dir)
    }
    /// Persistent state directory, taken as-is (not joined with `prefix`).
    pub fn state_dir(&self) -> PathBuf {
        Self::as_path(&self.state_dir)
    }
    /// Machine ID file path, taken as-is (not joined with `prefix`).
    pub fn machine_id_file(&self) -> PathBuf {
        Self::as_path(&self.machine_id_file)
    }
    /// System bus socket path, taken as-is (not joined with `prefix`).
    pub fn system_socket(&self) -> PathBuf {
        Self::as_path(&self.system_socket)
    }
    /// Legacy `dbus-daemon`-compatible socket path, taken as-is (not joined with `prefix`).
    pub fn legacy_system_socket(&self) -> PathBuf {
        Self::as_path(&self.legacy_system_socket)
    }
    /// System bus daemon PID file path, taken as-is (not joined with `prefix`).
    pub fn system_pid_file(&self) -> PathBuf {
        Self::as_path(&self.system_pid_file)
    }

    /// Re-root every path under `destroot` (used only by installers, e.g.
    /// `DESTROOT=.../zairoot/overlayer/syshub scripts/install.sh`). The
    /// RUNTIME value baked into the built binary is always the un-rooted
    /// one — this method never touches the compiled defaults.
    pub fn rooted(&self, destroot: &Path) -> PathBuf {
        destroot.to_path_buf()
    }
}

fn joined(prefix: &str, sub: &str) -> PathBuf {
    let mut p = PathBuf::from(prefix);
    // sub is stored with a leading '/', strip it so PathBuf::join doesn't
    // treat it as a second absolute root.
    p.push(sub.trim_start_matches('/'));
    p
}

// ── [bus.system] / [bus.session] ───────────────────────────────────────────

/// The `[bus.system]` table — settings for the privileged system bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusSystemConfig {
    /// Unix user the daemon drops privileges to after binding its socket. Default `"messagebus"`.
    #[serde(default = "default_bus_user")]
    pub user: String,
    /// D-Bus address to listen on. Default `unix:path=/run/oxibus/system_bus_socket`.
    #[serde(default = "default_system_listen")]
    pub listen: String,
    /// PID file written by the running daemon. Default `/run/oxibus/pid`.
    #[serde(default = "default_system_pid_file")]
    pub pidfile: String,
    /// SASL mechanisms offered to connecting clients, in order. Default
    /// `["EXTERNAL", "DBUS_COOKIE_SHA1", "ANONYMOUS"]`.
    #[serde(default = "default_auth_mechanisms")]
    pub auth_mechanisms: Vec<String>,
    /// Whether the `ANONYMOUS` mechanism is allowed to authenticate without
    /// further credential checks. Default `false`.
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

/// The `[bus.session]` table — settings for the per-user session bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusSessionConfig {
    /// D-Bus address to listen on. Default `unix:tmpdir=/tmp` (an
    /// abstract/anonymous socket created fresh under that directory, unlike
    /// the system bus's fixed `unix:path=`).
    #[serde(default = "default_session_listen")]
    pub listen: String,
    /// SASL mechanisms offered to connecting clients, in order. Default
    /// `["EXTERNAL", "DBUS_COOKIE_SHA1"]` — no `ANONYMOUS`, since the
    /// session bus is already scoped to one user.
    #[serde(default = "default_session_auth_mechanisms")]
    pub auth_mechanisms: Vec<String>,
    /// Whether the `ANONYMOUS` mechanism is allowed to authenticate without
    /// further credential checks. Default `false`.
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

/// The `[bus]` table — groups the system-bus and session-bus settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BusConfig {
    /// System bus (`[bus.system]`) settings.
    #[serde(default)]
    pub system: BusSystemConfig,
    /// Session bus (`[bus.session]`) settings.
    #[serde(default)]
    pub session: BusSessionConfig,
}

// ── [limits] ────────────────────────────────────────────────────────────────

/// The `[limits]` table — resource ceilings mirroring classic
/// `dbus-daemon`'s `<limit>` directives. Not every field is enforced yet;
/// see individual field docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Total bytes of unread incoming data buffered per connection before
    /// it's disconnected. Default 1,000,000,000. Not currently enforced by
    /// the daemon (kept for `dbus-daemon` schema parity).
    #[serde(default = "default_max_incoming_bytes")]
    pub max_incoming_bytes: u64,
    /// Total bytes of unsent outgoing data buffered per connection before
    /// it's disconnected. Default 1,000,000,000. Not currently enforced by
    /// the daemon (kept for `dbus-daemon` schema parity).
    #[serde(default = "default_max_outgoing_bytes")]
    pub max_outgoing_bytes: u64,
    /// Largest single message the transport will accept, in bytes. Default
    /// 134,217,728 (128 MiB). Enforced per-connection via
    /// `Transport::set_max_message_size`.
    #[serde(default = "default_max_message_size")]
    pub max_message_size: u32,
    /// Largest number of Unix file descriptors accepted in one message.
    /// Default 1024.
    #[serde(default = "default_max_message_unix_fds")]
    pub max_message_unix_fds: u32,
    /// Cap on connections that have completed the SASL handshake. Default
    /// 100,000. Not currently enforced by the daemon (kept for
    /// `dbus-daemon` schema parity).
    #[serde(default = "default_max_completed_connections")]
    pub max_completed_connections: u32,
    /// Cap on sockets accepted but not yet past the SASL handshake — bounds
    /// the half-open-connection DoS surface during auth. Default 64.
    #[serde(default = "default_max_incomplete_connections")]
    pub max_incomplete_connections: u32,
    /// Cap on completed connections held by a single uid. Default 512.
    #[serde(default = "default_max_connections_per_user")]
    pub max_connections_per_user: u32,
    /// Cap on service-activation requests awaiting the activated process to
    /// claim its name. Default 512. Not currently enforced by the daemon
    /// (kept for `dbus-daemon` schema parity).
    #[serde(default = "default_max_pending_service_starts")]
    pub max_pending_service_starts: u32,
    /// Cap on well-known bus names a single connection may own or queue
    /// for. Default 50,000.
    #[serde(default = "default_max_names_per_connection")]
    pub max_names_per_connection: u32,
    /// Cap on match rules (`AddMatch`) a single connection may register.
    /// Default 50,000.
    #[serde(default = "default_max_match_rules_per_connection")]
    pub max_match_rules_per_connection: u32,
    /// How long the daemon waits for on-demand activation to complete
    /// before replying `ServiceUnknown`, in milliseconds. Default 25,000.
    #[serde(default = "default_activation_timeout_ms")]
    pub activation_timeout_ms: u64,
    /// How long a connection has to complete the SASL handshake before
    /// being dropped, in milliseconds. Default 30,000.
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

// ── [logging] ───────────────────────────────────────────────────────────────

/// The `[logging]` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Minimum log level, e.g. `"info"`, `"debug"`, `"trace"`. Default `"info"`.
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Identifier tag attached to log lines (process/facility name). Default `"oxibus-daemon"`.
    #[serde(default = "default_log_ident")]
    pub ident: String,
    /// Where log output is written, e.g. `"stderr"`. Default `"stderr"`.
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
    "oxibus-daemon".into()
}
fn default_log_target() -> String {
    "stderr".into()
}

// ── top level ───────────────────────────────────────────────────────────────

/// The root `oxibus.toml` schema. Every OxiBus binary loads exactly this
/// shape; any field absent from the file falls back to its `default_*`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    /// `[project]` — name/version metadata.
    #[serde(default)]
    pub project: ProjectConfig,
    /// `[features]` — subsystem toggles.
    #[serde(default)]
    pub features: FeaturesConfig,
    /// `[paths]` — filesystem layout.
    #[serde(default)]
    pub paths: PathsConfig,
    /// `[bus]` — system/session bus settings.
    #[serde(default)]
    pub bus: BusConfig,
    /// `[limits]` — resource ceilings.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// `[logging]` — log level/target settings.
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl GlobalConfig {
    /// Parse `oxibus.toml` contents already held in memory (used for
    /// embedded/test configs where there's no file on disk to attribute
    /// errors to — failures report their path as `"<inline>"`).
    pub fn parse(text: &str) -> ConfigResult<Self> {
        toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: "<inline>".into(),
            source: Box::new(e),
        })
    }

    /// Read and parse `oxibus.toml` from `path`, reporting `path` in any
    /// resulting [`ConfigError`].
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

    /// Load from the first candidate that exists, else compiled-in defaults.
    /// Search order matches elevate's convention: `/etc` first (production),
    /// then CWD (dev tree checkout), then embedded defaults.
    pub fn load_default() -> Self {
        if let Ok(explicit) = std::env::var("OXIBUS_CONFIG") {
            if let Ok(cfg) = Self::load_path(&explicit) {
                return cfg;
            }
        }
        let candidates = [
            "/etc/oxibus/oxibus.toml",
            "/etc/oxibus.toml",
            "oxibus.toml",
        ];
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
        let text = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../oxibus.toml"),
        )
        .expect("root oxibus.toml must exist");
        let cfg = GlobalConfig::parse(&text).expect("root oxibus.toml must parse");
        assert_eq!(cfg.bus.system.user, "messagebus");
        assert_eq!(cfg.limits.max_message_size, 134_217_728);
    }
}
