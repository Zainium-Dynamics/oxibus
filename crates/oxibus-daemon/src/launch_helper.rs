//! Pure, unit-testable logic for `oxibus-daemon-launch-helper` — the
//! setuid-root service-activation helper for the SYSTEM bus.
//!
//! Security model (mirrors `bus/activation-helper.c` / `bus/activation-
//! helper-bin.c` in the D-Bus source exactly): the helper trusts **nothing**
//! the calling process (the unprivileged `oxibus-daemon`, running as
//! `messagebus`) tells it except the bus name to activate, and even that is
//! only used as a lookup key. Everything else — which config file governs
//! the system bus, which service files exist, what command to run, which
//! user to run it as — is re-derived by the helper itself from a single
//! hardcoded, absolute, root-owned path. If the calling `oxibus-daemon`
//! process were somehow compromised, it still could not make this helper
//! execute anything other than a real, pre-registered system service as
//! that service's own configured user.
//!
//! The actual privileged side effects (clearing the environment, dropping
//! to the target user, `execve`) live only in the `oxibus-daemon-launch-
//! helper` binary itself, not here — this module is everything about that
//! process that can be exercised by a normal, unprivileged `cargo test`.

use std::path::{Path, PathBuf};

use crate::activation::{ActivationRegistry, ServiceDef};

/// Every way `oxibus-daemon-launch-helper` can fail to activate a service,
/// each mapped to a distinct process exit code by [`HelperError::exit_code`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HelperError {
    /// Argv was not exactly one bus name (or was a help flag).
    #[error("usage: oxibus-daemon-launch-helper SERVICE.NAME.TO.ACTIVATE")]
    InvalidArgs,
    /// The supplied bus name failed [`oxibus_core::is_valid_bus_name`].
    #[error("bus name '{0}' is not a valid bus name")]
    InvalidBusName(String),
    /// The trusted config at [`TRUSTED_CONFIG_PATH`] could not be read or
    /// parsed.
    #[error("could not load trusted config at {0}: {1}")]
    ConfigInvalid(String, String),
    /// [`check_permissions`] rejected the caller: wrong real uid, or the
    /// setuid bit did not actually take effect.
    #[error("{0}")]
    PermissionsInvalid(String),
    /// No service file registers this bus name.
    #[error("the name {0} was not provided by any service files")]
    ServiceNotFound(String),
    /// The service file exists but has no `user =`, which is mandatory for
    /// system-bus activation.
    #[error("service '{0}' has no `user =` set — required for system-bus activation")]
    NoUserConfigured(String),
    /// The service's configured `user =` does not resolve to a real uid.
    #[error("cannot find user '{0}'")]
    UnknownUser(String),
    /// The privilege-drop sequence (`initgroups`/`setgid`/`setuid`) failed.
    #[error("{0}")]
    SetupFailed(String),
    /// `execve` of the service's `exec` failed.
    #[error("{0}")]
    ExecFailed(String),
}

impl HelperError {
    /// Distinct process exit codes so a supervisor/log can tell failure
    /// modes apart without parsing stderr (loosely mirrors `bus/
    /// activation-exit-codes.h`; nothing on the daemon side parses these
    /// today since the daemon only polls the bus registry for success).
    pub fn exit_code(&self) -> i32 {
        match self {
            HelperError::InvalidArgs => 2,
            HelperError::InvalidBusName(_) => 3,
            HelperError::ConfigInvalid(_, _) => 4,
            HelperError::PermissionsInvalid(_) => 5,
            HelperError::ServiceNotFound(_) => 6,
            HelperError::NoUserConfigured(_) => 7,
            HelperError::UnknownUser(_) => 8,
            HelperError::SetupFailed(_) => 9,
            HelperError::ExecFailed(_) => 10,
        }
    }
}

/// The single hardcoded, absolute path this helper will ever read its
/// trust anchor from. Deliberately NOT
/// `oxibus_config::GlobalConfig::load_default()` — that loader checks
/// `$OXIBUS_CONFIG` and falls back to a `./oxibus.toml` in the current
/// directory, either of which a malicious caller could steer before
/// exec'ing us (env is cleared before we'd read it, but CWD is not
/// something we control at all).
pub const TRUSTED_CONFIG_PATH: &str = "/etc/oxibus/oxibus.toml";

/// Parse argv (already stripped of argv[0]). Exactly one non-flag argument
/// — the bus name — or a help flag.
pub fn parse_args(args: &[String]) -> Result<&str, HelperError> {
    match args {
        [name] if name != "--help" && name != "-h" && name != "-?" => Ok(name.as_str()),
        _ => Err(HelperError::InvalidArgs),
    }
}

/// Does `real_uid` (our caller's uid, preserved across a setuid-root
/// `execve`) belong to `dbus_user`, and is `effective_uid` actually 0? Both
/// must hold: the first proves we were invoked by the genuine bus daemon
/// process (not some other local user who merely knows our path), the
/// second proves our setuid bit is actually in effect (catches a botched
/// install where the mode/owner bits got lost).
pub fn check_permissions(
    dbus_user: &str,
    real_uid: u32,
    effective_uid: u32,
    resolve_uid: impl Fn(&str) -> Option<u32>,
) -> Result<(), HelperError> {
    let expected_uid = resolve_uid(dbus_user)
        .ok_or_else(|| HelperError::PermissionsInvalid(format!("cannot find user '{dbus_user}'")))?;
    if real_uid != expected_uid {
        return Err(HelperError::PermissionsInvalid(format!(
            "not invoked from user '{dbus_user}'"
        )));
    }
    if effective_uid != 0 {
        return Err(HelperError::PermissionsInvalid("not setuid root".into()));
    }
    Ok(())
}

/// Re-derive the service definition from the trusted service dirs (never
/// from anything the caller supplied) and confirm it actually requires a
/// specific user — mandatory for system-bus activation, exactly as real
/// dbus requires `User=` in system `.service` files.
pub fn find_service(registry: &ActivationRegistry, bus_name: &str) -> Result<ServiceDef, HelperError> {
    let def = registry
        .lookup(bus_name)
        .ok_or_else(|| HelperError::ServiceNotFound(bus_name.to_string()))?;
    if def.name != bus_name {
        // Cannot actually happen given ActivationRegistry keys services by
        // this same field, but kept as an explicit invariant check —
        // mirrors check_service_name() in the real helper, which guards
        // against a renamed-but-stale service file.
        return Err(HelperError::ServiceNotFound(bus_name.to_string()));
    }
    if def.user.is_none() {
        return Err(HelperError::NoUserConfigured(bus_name.to_string()));
    }
    Ok(def)
}

/// The service directories the helper searches, in the trusted config's own
/// terms — kept as a tiny function (rather than inlining at the call site)
/// so tests can exercise the exact same list the real `main()` builds.
pub fn service_dirs(services_dir: &Path, vendor_services_dir: &Path, prefix: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![services_dir.to_path_buf(), vendor_services_dir.to_path_buf()];
    
    // Zainium syshub overlays first
    dirs.push(prefix.join("share/dbus-1/system-services"));
    dirs.push(prefix.join("etc/dbus-1/system-services"));
    dirs.push(prefix.join("lib/dbus-1/system-services"));

    // Traditional Linux fallbacks
    dirs.push(PathBuf::from("/etc/dbus-1/system-services"));
    dirs.push(PathBuf::from("/usr/share/dbus-1/system-services"));
    dirs.push(PathBuf::from("/usr/lib/dbus-1/system-services"));
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_requires_exactly_one_name() {
        assert_eq!(parse_args(&[]), Err(HelperError::InvalidArgs));
        assert_eq!(
            parse_args(&["a".into(), "b".into()]),
            Err(HelperError::InvalidArgs)
        );
        assert_eq!(
            parse_args(&["--help".into()]),
            Err(HelperError::InvalidArgs)
        );
        assert_eq!(parse_args(&["com.example.Foo".into()]), Ok("com.example.Foo"));
    }

    #[test]
    fn check_permissions_rejects_wrong_real_uid() {
        let result = check_permissions("messagebus", 1000, 0, |_| Some(81));
        assert_eq!(
            result,
            Err(HelperError::PermissionsInvalid(
                "not invoked from user 'messagebus'".into()
            ))
        );
    }

    #[test]
    fn check_permissions_rejects_non_root_effective_uid() {
        let result = check_permissions("messagebus", 81, 81, |_| Some(81));
        assert_eq!(
            result,
            Err(HelperError::PermissionsInvalid("not setuid root".into()))
        );
    }

    #[test]
    fn check_permissions_accepts_correct_caller() {
        assert!(check_permissions("messagebus", 81, 0, |_| Some(81)).is_ok());
    }

    #[test]
    fn check_permissions_rejects_unknown_dbus_user() {
        let result = check_permissions("nosuchuser", 81, 0, |_| None);
        assert!(matches!(result, Err(HelperError::PermissionsInvalid(_))));
    }

    #[test]
    fn find_service_requires_configured_user() {
        let dir = std::env::temp_dir().join(format!("oxibus-launch-helper-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("com.example.NoUser.toml"),
            "[service]\nname = \"com.example.NoUser\"\nexec = \"/bin/true\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("com.example.WithUser.toml"),
            "[service]\nname = \"com.example.WithUser\"\nexec = \"/bin/true\"\nuser = \"nobody\"\n",
        )
        .unwrap();

        let registry = ActivationRegistry::load(&[dir.clone()]);

        assert_eq!(
            find_service(&registry, "com.example.NoUser"),
            Err(HelperError::NoUserConfigured("com.example.NoUser".into()))
        );
        assert_eq!(
            find_service(&registry, "com.example.Missing"),
            Err(HelperError::ServiceNotFound("com.example.Missing".into()))
        );
        let found = find_service(&registry, "com.example.WithUser").unwrap();
        assert_eq!(found.user.as_deref(), Some("nobody"));

        std::fs::remove_dir_all(&dir).ok();
    }
}
