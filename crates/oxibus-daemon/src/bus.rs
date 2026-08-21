// Shared bus state: connections, registry, policy, activation, and stats.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use oxibus_config::GlobalConfig;

use crate::activation::ActivationRegistry;
use crate::policy::Policy;
use crate::registry::Registry;
use crate::stats::Stats;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusKind {
    System,
    Session,
}

pub struct Bus {
    pub kind: BusKind,
    pub config: GlobalConfig,
    pub registry: Registry,
    pub policy: RwLock<Policy>,
    pub activation: ActivationRegistry,
    pub stats: Stats,
    pub guid_hex: RwLock<String>,
    pub activation_environment: RwLock<HashMap<String, String>>,
}

impl Bus {
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

    pub fn guid(&self) -> String {
        self.guid_hex.read().unwrap().clone()
    }

    pub fn set_guid(&self, guid: String) {
        *self.guid_hex.write().unwrap() = guid;
    }

    pub fn allow_anonymous(&self) -> bool {
        match self.kind {
            BusKind::System => self.config.bus.system.allow_anonymous,
            BusKind::Session => self.config.bus.session.allow_anonymous,
        }
    }

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
        dirs.push(prefix.join("share/dbus-1/system.d"));
        dirs.push(prefix.join("etc/dbus-1/system.d"));
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
            dirs.push(prefix.join("share/dbus-1/system-services"));
            dirs.push(prefix.join("etc/dbus-1/system-services"));
            dirs.push(prefix.join("lib/dbus-1/system-services"));
            dirs.push(PathBuf::from("/etc/dbus-1/system-services"));
            dirs.push(PathBuf::from("/usr/share/dbus-1/system-services"));
            dirs.push(PathBuf::from("/usr/lib/dbus-1/system-services"));
        }
        BusKind::Session => {
            dirs.push(prefix.join("share/dbus-1/services"));
            dirs.push(prefix.join("etc/dbus-1/services"));
            dirs.push(prefix.join("lib/dbus-1/services"));
            dirs.push(PathBuf::from("/etc/dbus-1/services"));
            dirs.push(PathBuf::from("/usr/share/dbus-1/services"));
            dirs.push(PathBuf::from("/usr/lib/dbus-1/services"));
        }
    }
    dirs
}
