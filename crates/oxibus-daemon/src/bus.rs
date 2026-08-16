//! The shared bus state every connection handler and driver method reads
//! and mutates through — one `Arc<Bus>` per running `oxibus-daemon`
//! process (a system bus and a session bus are two separate processes,
//! same as real D-Bus).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use oxibus_config::GlobalConfig;

use crate::activation::ActivationRegistry;
use crate::policy::Policy;
use crate::registry::Registry;
use crate::stats::Stats;

/// Which of the two well-known D-Bus buses this process is serving. Each
/// `oxibus-daemon` process handles exactly one; the system bus additionally
/// enforces a privilege boundary (setuid launch helper, mandatory policy)
/// that the session bus does not need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusKind {
    /// The system bus — one per host, typically running as `messagebus`,
    /// shared by all users and system services.
    System,
    /// The session bus — one per logged-in user session.
    Session,
}

/// All shared, mutable state for one running bus process. Held behind a
/// single `Arc<Bus>` and passed to every connection handler and driver
/// call; individual fields carry their own interior mutability
/// (`RwLock`/atomics) rather than the whole struct being locked.
pub struct Bus {
    /// System or session — determines activation strategy and default
    /// policy strictness.
    pub kind: BusKind,
    /// Effective on-disk configuration this bus was started with.
    pub config: GlobalConfig,
    /// Connection table and bus-name ownership state.
    pub registry: Registry,
    /// Security policy, reloadable at runtime via [`Bus::reload_policy`]
    /// (e.g. on SIGHUP).
    pub policy: RwLock<Policy>,
    /// Table of on-demand-activatable service definitions.
    pub activation: ActivationRegistry,
    /// `org.freedesktop.DBus.Debug.Stats` counters.
    pub stats: Stats,
    /// This bus instance's GUID, hex-encoded, as returned by `GetId` and
    /// used during the SASL handshake.
    pub guid_hex: RwLock<String>,
    /// Environment variables accumulated via `UpdateActivationEnvironment`,
    /// applied to services spawned in [`crate::activation::SpawnStrategy::Direct`]
    /// mode only.
    pub activation_environment: RwLock<HashMap<String, String>>,
}

impl Bus {
    /// Build a fresh bus: loads policy from `config`'s policy directory
    /// (falling back to an empty, permissive [`Policy`] if that fails) and
    /// the activation registry from its service directories, then
    /// generates a new GUID.
    pub fn new(kind: BusKind, config: GlobalConfig) -> Self {
        let p_dirs = policy_dirs(kind, &config);
        let policy = Policy::load_dirs(&p_dirs).unwrap_or_else(|e| {
            tracing::warn!("failed to load policy dirs: {e}");
            Policy::default()
        });

        let s_dirs = service_dirs(kind, &config);
        let activation = ActivationRegistry::load(&s_dirs);

        Self {
            kind,
            registry: Registry::new(),
            policy: RwLock::new(policy),
            activation,
            stats: Stats::default(),
            guid_hex: RwLock::new(oxibus_auth::generate_guid_hex()),
            activation_environment: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// The bus's current GUID, hex-encoded (as sent in the SASL `OK`
    /// response and returned by `GetId`).
    pub fn guid(&self) -> String {
        self.guid_hex.read().unwrap().clone()
    }

    /// Overwrite the bus's GUID.
    pub fn set_guid(&self, guid: String) {
        *self.guid_hex.write().unwrap() = guid;
    }

    /// Whether unauthenticated (`ANONYMOUS` mechanism) connections are
    /// accepted, per this bus kind's config section.
    pub fn allow_anonymous(&self) -> bool {
        match self.kind {
            BusKind::System => self.config.bus.system.allow_anonymous,
            BusKind::Session => self.config.bus.session.allow_anonymous,
        }
    }

    /// SASL mechanisms enabled for this bus kind, parsed from config.
    /// Unrecognized names are silently dropped rather than failing startup.
    pub fn auth_mechanisms(&self) -> Vec<oxibus_auth::Mechanism> {
        let names: &[String] = match self.kind {
            BusKind::System => &self.config.bus.system.auth_mechanisms,
            BusKind::Session => &self.config.bus.session.auth_mechanisms,
        };
        names
            .iter()
            .filter_map(|n| oxibus_auth::Mechanism::parse(n))
            .collect()
    }

    /// Re-read the policy directory and swap in the result, replacing the
    /// current policy wholesale. On a read/parse error, the existing policy
    /// is left in place (a bad reload never leaves the bus with no policy
    /// at all).
    pub fn reload_policy(&self) {
        let p_dirs = policy_dirs(self.kind, &self.config);
        match Policy::load_dirs(&p_dirs) {
            Ok(p) => *self.policy.write().unwrap() = p,
            Err(e) => tracing::warn!("policy reload failed: {e}"),
        }
    }
}

fn policy_dirs(kind: BusKind, config: &GlobalConfig) -> Vec<PathBuf> {
    let mut dirs = vec![config.paths.policy_dir()];
    if kind == BusKind::System {
        let prefix = std::path::Path::new(&config.paths.prefix);
        // Zainium syshub overlays first
        dirs.push(prefix.join("share/dbus-1/system.d"));
        dirs.push(prefix.join("etc/dbus-1/system.d"));
        
        // Traditional Linux fallbacks
        dirs.push(PathBuf::from("/etc/dbus-1/system.d"));
        dirs.push(PathBuf::from("/usr/share/dbus-1/system.d"));
    }
    dirs
}

fn service_dirs(kind: BusKind, config: &GlobalConfig) -> Vec<PathBuf> {
    let mut dirs = vec![
        config.paths.services_dir(),
        config.paths.vendor_services_dir(),
    ];
    let prefix = std::path::Path::new(&config.paths.prefix);

    match kind {
        BusKind::System => {
            // Zainium syshub overlays first
            dirs.push(prefix.join("share/dbus-1/system-services"));
            dirs.push(prefix.join("etc/dbus-1/system-services"));
            dirs.push(prefix.join("lib/dbus-1/system-services"));

            // Traditional Linux fallbacks
            dirs.push(PathBuf::from("/etc/dbus-1/system-services"));
            dirs.push(PathBuf::from("/usr/share/dbus-1/system-services"));
            dirs.push(PathBuf::from("/usr/lib/dbus-1/system-services"));
        }
        BusKind::Session => {
            // Zainium syshub overlays first
            dirs.push(prefix.join("share/dbus-1/services"));
            dirs.push(prefix.join("etc/dbus-1/services"));
            dirs.push(prefix.join("lib/dbus-1/services"));

            // Traditional Linux fallbacks
            dirs.push(PathBuf::from("/etc/dbus-1/services"));
            dirs.push(PathBuf::from("/usr/share/dbus-1/services"));
            dirs.push(PathBuf::from("/usr/lib/dbus-1/services"));
        }
    }
    dirs
}
