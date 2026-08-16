//! `oxibus-daemon-launch-helper` — setuid-root helper that lets the
//! unprivileged system `oxibus-daemon` (running as `messagebus`) activate
//! services that must run as a *different* user.
//!
//! THIS FILE IS SECURITY SENSITIVE. It must be installed:
//!   owner root, group messagebus, mode 4750 (setuid, group-executable
//!   only by the bus daemon's own group) — see `scripts/install.sh`.
//!
//! Trust model: see `crates/oxibus-daemon/src/launch_helper.rs` module
//! docs. In short — this process believes nothing its caller says except
//! the bus name, used only as a lookup key into service files it re-reads
//! itself from a hardcoded trusted path.

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
    // run() only returns on error — success replaces this process via execve.
}

fn run(bus_name: &str) -> Result<(), HelperError> {
    // Step 1: wipe our environment before doing ANYTHING else that might
    // consult it, and before the target process ever sees a trace of
    // whatever the calling (unprivileged) daemon's environment contained.
    clear_environment();

    if !oxibus_core::is_valid_bus_name(bus_name) {
        return Err(HelperError::InvalidBusName(bus_name.to_string()));
    }

    // Step 2: load the ONE trusted config path — prioritize Zainium overlay,
    // fallback to traditional /etc/oxibus path. Never env- or cwd-derived.
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

    // Step 3: prove we were invoked by the real bus daemon process, and
    // that our setuid bit genuinely took effect.
    // SAFETY: getuid()/geteuid() have no preconditions.
    let (real_uid, effective_uid) = unsafe { (libc::getuid(), libc::geteuid()) };
    check_permissions(&config.bus.system.user, real_uid, effective_uid, resolve_uid)?;

    // Step 4: re-derive the service definition ourselves from the trusted
    // service directories — never from anything the caller supplied.
    let prefix = std::path::Path::new(&config.paths.prefix);
    let dirs = service_dirs(&config.paths.services_dir(), &config.paths.vendor_services_dir(), prefix);
    let registry = ActivationRegistry::load(&dirs);
    let def = find_service(&registry, bus_name)?;
    let user = def.user.as_deref().expect("find_service guarantees Some");

    // Step 5: drop from root to the service's configured user.
    switch_user(user)?;

    // Step 6: replace this process image directly (no shell — `args` is
    // already a real argv array from TOML, not a string requiring
    // shell-word-splitting the way D-Bus's classic `Exec=` line needs).
    let err = std::process::Command::new(&def.exec).args(&def.args).exec();
    Err(HelperError::ExecFailed(format!("failed to exec '{}': {err}", def.exec)))
}

/// Clears every inherited environment variable, then sets only the
/// well-known bus-discovery variables a freshly-activated service is
/// entitled to — matches `clear_environment()` in `bus/activation-
/// helper.c`, extended with an `OXIBUS_*` alias for native tooling,
/// and adds standard environment PATH and LD_LIBRARY_PATH with Zainium and
/// traditional Linux system directories.
fn clear_environment() {
    let keys: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    // SAFETY: this process is single-threaded (no tokio runtime, no
    // spawned threads) at this point, which is the actual hazard
    // env::remove_var/set_var guard against.
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
    // SAFETY: cname is a valid NUL-terminated C string for the duration of
    // these calls; initgroups/setgid/setuid are the standard privilege-
    // drop syscall sequence, in the correct order (groups+gid before uid).
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
    // SAFETY: getpwnam's returned pointer is copied out immediately; no
    // other passwd-db call happens while it's still borrowed.
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
