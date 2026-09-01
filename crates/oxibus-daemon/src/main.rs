// dbus-daemon main entry point.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use oxibus_config::GlobalConfig;
use oxibus_core::Address;
use oxibus_daemon::{Bus, BusKind};
use tokio::net::UnixListener;

#[derive(Parser, Debug)]
#[command(name = "dbus-daemon", about = "OxiBus message bus daemon", version)]
struct Args {
    #[arg(long, conflicts_with = "session")]
    system: bool,

    #[arg(long, conflicts_with = "system")]
    session: bool,

    #[arg(long)]
    config: Option<PathBuf>,

    /// Listen address, overriding the configured one. Accepts `systemd:` to
    /// take over an already-bound socket via systemd socket activation
    /// (LISTEN_FDS/LISTEN_PID) instead of binding one ourselves.
    #[arg(long)]
    address: Option<String>,

    #[arg(long)]
    print_address: bool,

    #[arg(long)]
    print_pid: bool,

    /// Detach from the controlling terminal and background the daemon.
    /// Binding and any --print-address/--print-pid output happen first, so
    /// `addr=$(dbus-daemon --fork --print-address --session)` still works.
    #[arg(long)]
    fork: bool,

    /// Accepted for compatibility — this is already the default; we only
    /// background ourselves when --fork is given.
    #[arg(long)]
    nofork: bool,

    /// Don't write the system-bus pid file.
    #[arg(long)]
    nopidfile: bool,

    /// Log to syslog in addition to stderr.
    #[arg(long)]
    syslog: bool,

    /// Log to syslog only, no stderr — what a systemd `Type=notify` unit
    /// typically wants (journald reads the syslog socket anyway).
    #[arg(long = "syslog-only")]
    syslog_only: bool,

    /// Accepted for compatibility — this is already the default.
    #[arg(long)]
    nosyslog: bool,

    /// Accept systemd-style unit activation as an additional activation
    /// source alongside our existing traditional `.service`-file activation.
    ///
    /// NOTE: this currently only makes us accept the flag (and the CLI/unit
    /// combination systemd's own dbus.service uses) without erroring out —
    /// starting a systemd *unit* by name via the systemd manager D-Bus API
    /// is not implemented yet. Traditional activation is unaffected.
    #[arg(long = "systemd-activation")]
    systemd_activation: bool,

    /// Print the built-in org.freedesktop.DBus introspection XML and exit.
    #[arg(long)]
    introspect: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.introspect {
        println!("{}", oxibus_daemon::dispatch::driver_introspection_xml());
        return Ok(());
    }
    if !args.system && !args.session {
        anyhow::bail!("must pass --system or --session");
    }

    // A single-threaded runtime keeps `--fork`'s fork()-after-bind safe (no
    // other OS threads to leave in an inconsistent state) and matches the
    // reference daemon's own single-threaded event-loop model.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main(args))
}

async fn async_main(args: Args) -> anyhow::Result<()> {
    let kind = if args.system {
        BusKind::System
    } else {
        BusKind::Session
    };

    init_logging(&args);

    if args.systemd_activation {
        tracing::info!(
            "--systemd-activation: accepted; traditional .service-file activation stays active \
             (starting systemd units by name is not implemented yet)"
        );
    }

    oxibus_daemon::audit::init();

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
    let mut write_pid = false;

    if let Some(addr_str) = &args.address {
        listen_addresses.push(Address::parse_one(addr_str)?);
        write_pid = kind == BusKind::System;
    } else {
        match kind {
            BusKind::System => {
                let primary =
                    Address::UnixPath(bus.config.paths.system_socket().display().to_string());
                let legacy = Address::UnixPath(
                    bus.config
                        .paths
                        .legacy_system_socket()
                        .display()
                        .to_string(),
                );
                listen_addresses.push(primary);
                if legacy_differs(&bus) {
                    listen_addresses.push(legacy);
                }
                write_pid = true;
            }
            BusKind::Session => {
                listen_addresses.push(Address::parse_one(&bus.config.bus.session.listen)?);
            }
        }
    }
    if write_pid && !args.nopidfile {
        write_pid_file(&bus);
    }

    let pid = unsafe { libc::getpid() };
    if args.print_pid {
        println!("{pid}");
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
            let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o666));
            bound_socket_paths.push(PathBuf::from(p));
        }
        join_handles.push(spawn_accept_loop(bus.clone(), bound.listener));
    }

    if args.fork {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        if let Err(e) = daemonize() {
            tracing::warn!("--fork: could not daemonize: {e} — continuing in foreground");
        }
    }

    if kind == BusKind::System
        && let Err(e) = drop_privileges(&bus.config.bus.system.user)
    {
        tracing::warn!(
            "could not drop privileges to '{}': {e} — continuing as current uid",
            bus.config.bus.system.user
        );
    }

    spawn_signal_handlers(bus.clone(), bound_socket_paths, kind);

    // Tell systemd (Type=notify units, e.g. the reference dbus.service) that
    // we're up and accepting connections. A silent no-op when NOTIFY_SOCKET
    // isn't set, i.e. whenever we're not running under systemd at all.
    oxibus_daemon::sd_notify::notify_ready();

    for h in join_handles {
        let _ = h.await;
    }
    Ok(())
}

/// Classic double-fork daemonization. Runs *after* sockets are bound and any
/// --print-address/--print-pid output is flushed, so scripts that do
/// `addr=$(dbus-daemon --fork --print-address ...)` still capture the
/// address before we sever our stdio from that pipe.
fn daemonize() -> std::io::Result<()> {
    unsafe {
        match libc::fork() {
            -1 => return Err(std::io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }
        if libc::setsid() < 0 {
            return Err(std::io::Error::last_os_error());
        }
        match libc::fork() {
            -1 => return Err(std::io::Error::last_os_error()),
            0 => {}
            _ => std::process::exit(0),
        }
    }
    let _ = std::env::set_current_dir("/");
    redirect_stdio_to_devnull();
    Ok(())
}

fn redirect_stdio_to_devnull() {
    if let Ok(devnull) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        let fd = devnull.as_raw_fd();
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }
}

/// A writer that forwards each formatted log line to syslog via libc's
/// `syslog(3)`, so `--syslog`/`--syslog-only` work without linking a
/// separate syslog crate.
#[derive(Clone, Copy)]
struct SyslogWriter;

impl std::io::Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let line = String::from_utf8_lossy(buf);
        let line = line.trim_end_matches('\n');
        if !line.is_empty() {
            let sanitized = line.replace('\0', "");
            if let Ok(cstr) = std::ffi::CString::new(sanitized) {
                unsafe {
                    libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), cstr.as_ptr());
                }
            }
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logging(args: &Args) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let want_syslog = args.syslog || args.syslog_only;
    if want_syslog {
        let ident = c"dbus-daemon";
        unsafe {
            libc::openlog(ident.as_ptr(), libc::LOG_PID, libc::LOG_DAEMON);
        }
    }

    let filter = tracing_subscriber::EnvFilter::from_default_env();
    let stderr_layer =
        (!args.syslog_only).then(|| tracing_subscriber::fmt::layer().with_target(false));
    let syslog_layer = want_syslog.then(|| {
        tracing_subscriber::fmt::layer()
            .with_writer(|| SyslogWriter)
            .with_ansi(false)
            .without_time()
            .with_target(false)
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(syslog_layer)
        .init();
}

fn drop_privileges(user: &str) -> std::io::Result<()> {
    if unsafe { libc::getuid() } != 0 {
        tracing::debug!("not running as root — skipping privilege drop");
        return Ok(());
    }

    let cname = std::ffi::CString::new(user).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "user name has embedded NUL",
        )
    })?;
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
        if libc::getuid() != uid || libc::geteuid() != uid {
            return Err(std::io::Error::other("setuid() did not take effect"));
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
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
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
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("cannot install SIGTERM handler: {e}");
                    return;
                }
            };
        let mut sigint =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
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
        oxibus_daemon::audit::shutdown();
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
    let pid = unsafe { libc::getpid() };
    if let Err(e) = std::fs::write(&path, pid.to_string()) {
        tracing::warn!("could not write pid file {}: {e}", path.display());
    }
}
