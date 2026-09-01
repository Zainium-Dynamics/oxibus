// AF_UNIX listener and connection binding.

use std::io;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};

use oxibus_core::Address;
use rand::Rng;
use tokio::net::{UnixListener, UnixStream};

pub struct BoundListener {
    pub listener: UnixListener,
    pub effective_address: Address,
}

pub async fn bind(addr: &Address) -> io::Result<BoundListener> {
    match addr {
        Address::UnixPath(path) => {
            let path = PathBuf::from(path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if path.exists() {
                std::fs::remove_file(&path).ok();
            }
            let listener = UnixListener::bind(&path)?;
            Ok(BoundListener {
                listener,
                effective_address: Address::UnixPath(path.display().to_string()),
            })
        }
        Address::UnixAbstract(name) => {
            let listener = bind_abstract(name.as_bytes())?;
            Ok(BoundListener {
                listener,
                effective_address: Address::UnixAbstract(name.clone()),
            })
        }
        Address::UnixTmpdir(dir) => {
            let name = format!("oxibus-{}", random_hex(16));
            let path = Path::new(dir).join(name);
            let listener = UnixListener::bind(&path)?;
            Ok(BoundListener {
                listener,
                effective_address: Address::UnixPath(path.display().to_string()),
            })
        }
        Address::Tcp { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tcp: transport intentionally unsupported (Zainium is unix-socket-only, matches -Dx11_autolaunch=disabled / no remote bus)",
        )),
        Address::Systemd => bind_systemd_activated(),
    }
}

pub async fn connect(addr: &Address) -> io::Result<UnixStream> {
    match addr {
        Address::UnixPath(path) => UnixStream::connect(path).await,
        Address::UnixAbstract(name) => connect_abstract(name.as_bytes()),
        Address::UnixTmpdir(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unix:tmpdir= is a listen-only address form (server picks the path)",
        )),
        Address::Tcp { .. } => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "tcp: transport intentionally unsupported",
        )),
        Address::Systemd => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "systemd: is a listen-only address form (clients connect to the real socket path)",
        )),
    }
}

/// Take over the socket systemd already bound for us, per the sd_listen_fds(3)
/// protocol: it hands us the fd(s) starting at fd 3 and tells us so via
/// LISTEN_PID/LISTEN_FDS. No libsystemd link needed — it's just env vars plus
/// an inherited fd.
fn bind_systemd_activated() -> io::Result<BoundListener> {
    let pid_var = std::env::var("LISTEN_PID").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "systemd: address given but LISTEN_PID is not set — not socket-activated",
        )
    })?;
    let fds_var = std::env::var("LISTEN_FDS").map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "systemd: address given but LISTEN_FDS is not set — not socket-activated",
        )
    })?;
    let expected_pid: i32 = pid_var
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "LISTEN_PID is not a pid"))?;
    if expected_pid != std::process::id() as i32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "LISTEN_PID does not match our pid — these fds were meant for a different process",
        ));
    }
    let count: u32 = fds_var
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "LISTEN_FDS is not a count"))?;
    if count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "LISTEN_FDS=0 — systemd passed no sockets",
        ));
    }

    const SD_LISTEN_FDS_START: i32 = 3;
    let fd = SD_LISTEN_FDS_START;
    unsafe {
        // Own it going forward, and make sure services we later exec() via
        // activation don't inherit it by accident.
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;

    // Per sd_listen_fds(3): only the first consumer in a process should see
    // these — clear them so anything we fork/exec later doesn't misread them
    // as its own activation sockets.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }

    Ok(BoundListener {
        listener,
        effective_address: Address::Systemd,
    })
}

fn build_abstract_sockaddr(name: &[u8]) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let max_len = addr.sun_path.len() - 1;
    if name.len() > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "abstract socket name too long",
        ));
    }
    for (i, b) in name.iter().enumerate() {
        addr.sun_path[i + 1] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
    Ok((addr, len))
}

fn bind_abstract(name: &[u8]) -> io::Result<UnixListener> {
    let (sockaddr, len) = build_abstract_sockaddr(name)?;
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::bind(fd, &sockaddr as *const _ as *const libc::sockaddr, len) != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        if libc::listen(fd, 128) != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let std_listener = std::os::unix::net::UnixListener::from_raw_fd(fd);
        UnixListener::from_std(std_listener)
    }
}

fn connect_abstract(name: &[u8]) -> io::Result<UnixStream> {
    let (sockaddr, len) = build_abstract_sockaddr(name)?;
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::connect(fd, &sockaddr as *const _ as *const libc::sockaddr, len) != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        let std_stream = std::os::unix::net::UnixStream::from_raw_fd(fd);
        UnixStream::from_std(std_stream)
    }
}

fn random_hex(bytes: usize) -> String {
    let mut rng = rand::thread_rng();
    let raw: Vec<u8> = (0..bytes).map(|_| rng.r#gen()).collect();
    hex::encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_and_connect_unix_path() {
        let dir = std::env::temp_dir().join(format!("oxibus-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("test.sock");
        let addr = Address::UnixPath(sock_path.display().to_string());

        let bound = bind(&addr).await.unwrap();
        let accept_task = tokio::spawn(async move { bound.listener.accept().await });

        let _client = connect(&addr).await.unwrap();
        let (_, _) = accept_task.await.unwrap().unwrap();

        std::fs::remove_file(&sock_path).ok();
    }

    #[tokio::test]
    async fn tmpdir_bind_picks_random_name() {
        let addr = Address::UnixTmpdir(std::env::temp_dir().display().to_string());
        let bound = bind(&addr).await.unwrap();
        match &bound.effective_address {
            Address::UnixPath(p) => assert!(p.contains("oxibus-")),
            _ => panic!("expected UnixPath effective address"),
        }
    }

    #[tokio::test]
    async fn bind_and_connect_abstract_socket() {
        let name = format!("oxibus-test-abstract-{}", std::process::id());
        let addr = Address::UnixAbstract(name);
        let bound = bind(&addr).await.unwrap();
        let accept_task = tokio::spawn(async move { bound.listener.accept().await });
        let _client = connect(&addr).await.unwrap();
        accept_task.await.unwrap().unwrap();
    }
}
