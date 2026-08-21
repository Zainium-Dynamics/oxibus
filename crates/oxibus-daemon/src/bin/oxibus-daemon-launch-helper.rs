// Setuid-root launch helper binary.

use std::ffi::CString;
use std::os::unix::process::CommandExt;

use oxibus_daemon::activation::ActivationRegistry;
use oxibus_daemon::launch_helper::{
    check_permissions, find_service, parse_args, service_dirs, HelperError, TRUSTED_CONFIG_PATH,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let name = match parse_args(&args) {
        Ok(n) => n.to_string(),
        Err(_) => {
            eprintln!("oxibus-daemon-launch-helper: usage: oxibus-daemon-launch-helper SERVICE.NAME.TO.ACTIVATE");
            std::process::exit(if args.iter().any(|a| a == "--help" || a == "-h" || a == "-?") {
                0
            } else {
                HelperError::InvalidArgs.exit_code()
            });
        }
    };

    if let Err(e) = run(&name) {
        eprintln!("oxibus-daemon-launch-helper: {e}");
        std::process::exit(e.exit_code());
    }
}

fn run(bus_name: &str) -> Result<(), HelperError> {
    clear_environment();

    if !oxibus_core::is_valid_bus_name(bus_name) {
        return Err(HelperError::InvalidBusName(bus_name.to_string()));
    }

    let paths_to_try = [
        "/overlayer/syshub/etc/oxibus/oxibus.toml",
        TRUSTED_CONFIG_PATH,
    ];
    let mut loaded_config = None;
    let mut last_err = None;
    for path in &paths_to_try {
        if std::path::Path::new(path).exists() {
            match oxibus_config::GlobalConfig::load_path(path) {
                Ok(c) => {
                    loaded_config = Some(c);
                    break;
                }
                Err(e) => {
                    last_err = Some(HelperError::ConfigInvalid((*path).to_string(), e.to_string()));
                }
            }
        }
    }
    let config = match loaded_config {
        Some(c) => c,
        None => return Err(last_err.unwrap_or_else(|| {
            HelperError::ConfigInvalid(TRUSTED_CONFIG_PATH.to_string(), "Config file not found".to_string())
        })),
    };

    let (real_uid, effective_uid) = unsafe { (libc::getuid(), libc::geteuid()) };
    check_permissions(&config.bus.system.user, real_uid, effective_uid, resolve_uid)?;

    let prefix = std::path::Path::new(&config.paths.prefix);
    let dirs = service_dirs(&config.paths.services_dir(), &config.paths.vendor_services_dir(), prefix);
    let registry = ActivationRegistry::load(&dirs);
    let def = find_service(&registry, bus_name)?;
    let user = def.user.as_deref().expect("find_service guarantees Some");

    switch_user(user)?;

    let err = std::process::Command::new(&def.exec).args(&def.args).exec();
    Err(HelperError::ExecFailed(format!("failed to exec '{}': {err}", def.exec)))
}

fn clear_environment() {
    let keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    unsafe {
        for k in keys {
            std::env::remove_var(k);
        }
        std::env::set_var("DBUS_STARTER_BUS_TYPE", "system");
        std::env::set_var("OXIBUS_STARTER_BUS_TYPE", "system");
        std::env::set_var("PATH", "/overlayer/syshub/bin:/overlayer/syshub/sbin:/usr/bin:/usr/sbin:/bin:/sbin");
        std::env::set_var("LD_LIBRARY_PATH", "/overlayer/syshub/lib:/usr/lib:/lib");
    }
}

fn switch_user(user: &str) -> Result<(), HelperError> {
    let cname = CString::new(user).map_err(|_| HelperError::UnknownUser(user.to_string()))?;
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            return Err(HelperError::UnknownUser(user.to_string()));
        }
        let gid = (*pw).pw_gid;
        let uid = (*pw).pw_uid;
        if libc::initgroups(cname.as_ptr(), gid) != 0 {
            return Err(HelperError::SetupFailed("could not initialize groups".into()));
        }
        if libc::setgid(gid) != 0 {
            return Err(HelperError::SetupFailed(format!("cannot setgid to {gid}")));
        }
        if libc::setuid(uid) != 0 {
            return Err(HelperError::SetupFailed(format!("cannot setuid to {uid}")));
        }
    }
    Ok(())
}

fn resolve_uid(user: &str) -> Option<u32> {
    unsafe {
        let cname = CString::new(user).ok()?;
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some((*pw).pw_uid)
        }
    }
}
