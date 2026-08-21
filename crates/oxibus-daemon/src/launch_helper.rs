// Activation helper logic for system-bus setuid execution.

use std::path::{Path, PathBuf};

use crate::activation::{ActivationRegistry, ServiceDef};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HelperError {
    #[error("usage: oxibus-daemon-launch-helper SERVICE.NAME.TO.ACTIVATE")]
    InvalidArgs,
    #[error("bus name '{0}' is not a valid bus name")]
    InvalidBusName(String),
    #[error("could not load trusted config at {0}: {1}")]
    ConfigInvalid(String, String),
    #[error("{0}")]
    PermissionsInvalid(String),
    #[error("the name {0} was not provided by any service files")]
    ServiceNotFound(String),
    #[error("service '{0}' has no `user =` set — required for system-bus activation")]
    NoUserConfigured(String),
    #[error("cannot find user '{0}'")]
    UnknownUser(String),
    #[error("{0}")]
    SetupFailed(String),
    #[error("{0}")]
    ExecFailed(String),
}

impl HelperError {
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

pub const TRUSTED_CONFIG_PATH: &str = "/etc/oxibus/oxibus.toml";

pub fn parse_args(args: &[String]) -> Result<&str, HelperError> {
    match args {
        [name] if name != "--help" && name != "-h" && name != "-?" => Ok(name.as_str()),
        _ => Err(HelperError::InvalidArgs),
    }
}

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

pub fn find_service(registry: &ActivationRegistry, bus_name: &str) -> Result<ServiceDef, HelperError> {
    let def = registry
        .lookup(bus_name)
        .ok_or_else(|| HelperError::ServiceNotFound(bus_name.to_string()))?;
    if def.name != bus_name {
        return Err(HelperError::ServiceNotFound(bus_name.to_string()));
    }
    if def.user.is_none() {
        return Err(HelperError::NoUserConfigured(bus_name.to_string()));
    }
    Ok(def)
}

pub fn service_dirs(services_dir: &Path, vendor_services_dir: &Path, prefix: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![services_dir.to_path_buf(), vendor_services_dir.to_path_buf()];
    dirs.push(prefix.join("share/dbus-1/system-services"));
    dirs.push(prefix.join("etc/dbus-1/system-services"));
    dirs.push(prefix.join("lib/dbus-1/system-services"));
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
