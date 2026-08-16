//! `oxibus-daemon` — the OxiBus message bus. Drop-in successor to
//! `dbus-daemon` for Zainium OS: same wire protocol and socket paths (see
//! `oxibus.toml`'s `[paths]`), TOML policy/activation instead of XML.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use oxibus_config::GlobalConfig;
use oxibus_core::Address;
use oxibus_daemon::{Bus, BusKind};
use tokio::net::UnixListener;

#[derive(Parser, Debug)]
#[command(name = "oxibus-daemon", about = "OxiBus message bus daemon")]
struct Args {
    /// Run as the system bus (listens on paths.system_socket +
    /// paths.legacy_system_socket for libdbus-1.so compatibility).
    #[arg(long, conflicts_with = "session")]
    system: bool,

    /// Run as a session bus (listens on an ephemeral unix:tmpdir= socket).
    #[arg(long, conflicts_with = "system")]
    session: bool,

    /// Explicit oxibus.toml path (defaults to the candidates in
    /// oxibus-config: /etc/oxibus/oxibus.toml, /etc/oxibus.toml, ./oxibus.toml).
    #[arg(long)]
    config: Option<PathBuf>,

    /// Print the address(es) this daemon ends up listening on to stdout
    /// once ready (one per line), then continue running.
    #[arg(long)]
    print_address: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if !args.system && !args.session {
        anyhow::bail!("must pass --system or --session");
    }
    let kind = if args.system { BusKind::System } else { BusKind::Session };

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = match &args.config {
        Some(path) => GlobalConfig::load_path(path)?,
        None => GlobalConfig::load_default(),
    };

    let bus = Bus::new(kind, config);

    if kind == BusKind::System {
        load_or_create_machine_id(&bus);
    }

    let bus = Arc::new(bus);
    let mut listen_addresses: Vec<Address> = Vec::new();

    match kind {
        BusKind::System => {
            let primary = Address::UnixPath(bus.config.paths.system_socket().display().to_string());
            let legacy = Address::UnixPath(bus.config.paths.legacy_system_socket().display().to_string());
            listen_addresses.push(primary);
            if legacy_differs(&bus) {
                listen_addresses.push(legacy);
            }
            write_pid_file(&bus);
        }
        BusKind::Session => {
            listen_addresses.push(Address::parse_one(&bus.config.bus.session.listen)?);
        }
    }

    let mut join_handles = Vec::new();
    let mut bound_socket_paths: Vec<PathBuf> = Vec::new();
    for addr in &listen_addresses {
        let bound = oxibus_transport::bind(addr).await?;
        let printed = bound.effective_address.to_address_string();
        if args.print_address {
            println!("{printed}");
        }
        tracing::info!("listening on {printed}");
        if let oxibus_core::Address::UnixPath(p) = &bound.effective_address {
            // Access control is enforced by SASL identity + bus policy, not
            // filesystem bits — matches real dbus-daemon's world-writable
            // socket file.
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o666));
            bound_socket_paths.push(PathBuf::from(p));
        }
        join_handles.push(spawn_accept_loop(bus.clone(), bound.listener));
    }

    if kind == BusKind::System {
        if let Err(e) = drop_privileges(&bus.config.bus.system.user) {
            tracing::warn!(
                "could not drop privileges to '{}': {e} — continuing as current uid",
                bus.config.bus.system.user
            );
        }
    }

    spawn_signal_handlers(bus.clone(), bound_socket_paths, kind);

    for h in join_handles {
        let _ = h.await;
    }
    Ok(())
}

/// Drop from root to `user` (setgroups/initgroups → setgid → setuid), the
/// same shape as real `dbus-daemon`'s `<user>` config directive. No-op
/// (with a debug log) if we're not currently root — e.g. under a
/// supervisor that already starts us unprivileged, or the session bus,
/// which never calls this at all.
fn drop_privileges(user: &str) -> std::io::Result<()> {
    // SAFETY: getuid() has no preconditions.
    if unsafe { libc::getuid() } != 0 {
        tracing::debug!("not running as root — skipping privilege drop");
        return Ok(());
    }

    let cname = std::ffi::CString::new(user)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "user name has embedded NUL"))?;
    // SAFETY: getpwnam's returned pointer is copied out immediately; no
    // other libc passwd/group call happens while `pw` is still borrowed.
    let (uid, gid) = unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no such user '{user}'"),
            ));
        }
        ((*pw).pw_uid, (*pw).pw_gid)
    };

    // SAFETY: cname is a valid NUL-terminated C string for this call;
    // initgroups/setgid/setuid are standard privilege-drop syscalls, done
    // in the correct order (groups and gid before uid, since dropping uid
    // first would remove the capability to change them).
    unsafe {
        if libc::initgroups(cname.as_ptr(), gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setgid(gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setuid(uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Verify the drop actually took (setuid silently no-ops in some
        // exotic sandboxed environments) — fail loudly rather than run on
        // as root while believing we dropped privileges.
        if libc::getuid() != uid || libc::geteuid() != uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "setuid() did not take effect",
            ));
        }
    }
    tracing::info!("dropped privileges to '{user}' (uid={uid}, gid={gid})");
    Ok(())
}

fn legacy_differs(bus: &Bus) -> bool {
    bus.config.paths.system_socket() != bus.config.paths.legacy_system_socket()
}

fn spawn_accept_loop(bus: Arc<Bus>, listener: UnixListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let bus = bus.clone();
                    tokio::spawn(async move {
                        oxibus_daemon::connection_handler::handle_connection(bus, stream).await;
                    });
                }
                Err(e) => {
                    tracing::warn!("accept() failed: {e}");
                }
            }
        }
    })
}

fn spawn_signal_handlers(bus: Arc<Bus>, socket_paths: Vec<PathBuf>, kind: BusKind) {
    let sighup_bus = bus.clone();
    tokio::spawn(async move {
        let bus = sighup_bus;
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("cannot install SIGHUP handler: {e}");
                return;
            }
        };
        loop {
            sighup.recv().await;
            tracing::info!("SIGHUP received — reloading policy");
            bus.reload_policy();
        }
    });

    tokio::spawn(async move {
        let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("cannot install SIGTERM handler: {e}");
                return;
            }
        };
        let mut sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("cannot install SIGINT handler: {e}");
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received — shutting down"),
            _ = sigint.recv() => tracing::info!("SIGINT received — shutting down"),
        }
        for path in &socket_paths {
            let _ = std::fs::remove_file(path);
        }
        if kind == BusKind::System {
            let _ = std::fs::remove_file(bus.config.paths.system_pid_file());
        }
        std::process::exit(0);
    });
}

fn load_or_create_machine_id(bus: &Bus) {
    let path = bus.config.paths.machine_id_file();
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            bus.set_guid(trimmed.to_string());
            return;
        }
    }
    let generated = oxibus_auth::generate_guid_hex();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&path, &generated) {
        tracing::warn!("could not persist machine-id at {}: {e}", path.display());
    }
    bus.set_guid(generated);
}

fn write_pid_file(bus: &Bus) {
    let path = bus.config.paths.system_pid_file();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // SAFETY: getpid() has no preconditions.
    let pid = unsafe { libc::getpid() };
    if let Err(e) = std::fs::write(&path, pid.to_string()) {
        tracing::warn!("could not write pid file {}: {e}", path.display());
    }
}
