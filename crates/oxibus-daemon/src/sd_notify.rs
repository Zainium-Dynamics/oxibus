// Minimal sd_notify(3)-compatible client.
//
// Lets us tell systemd "I'm ready" (for `Type=notify` units, which is what
// the reference dbus.service ships) without linking libsystemd — it's just
// an env var (`NOTIFY_SOCKET`) plus a datagram sendto(). No-ops silently
// when the var is unset, which is the correct behaviour when we're not
// running under systemd at all.

use std::os::unix::io::RawFd;

/// Send a state update (e.g. `"READY=1"`, or multiple `KEY=VALUE` lines
/// joined with `\n`) to systemd's notification socket. Never fails loudly —
/// a missing/unreachable NOTIFY_SOCKET just means we're not being supervised
/// this way, which is a normal, expected case.
pub fn notify(state: &str) {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    if path.is_empty() {
        return;
    }

    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            tracing::debug!("sd_notify: socket() failed: {}", std::io::Error::last_os_error());
            return;
        }
        let ok = send_to(fd, &path, state.as_bytes());
        libc::close(fd);
        if !ok {
            tracing::debug!("sd_notify: could not reach NOTIFY_SOCKET={path}");
        }
    }
}

/// Convenience: notify readiness, including our pid so `NotifyAccess=main`
/// units are happy even though we never fork away from it.
pub fn notify_ready() {
    let pid = std::process::id();
    notify(&format!("READY=1\nMAINPID={pid}"));
}

unsafe fn send_to(fd: RawFd, path: &str, payload: &[u8]) -> bool {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

    let bytes = path.as_bytes();
    // A leading '@' denotes the Linux abstract namespace, i.e. a leading NUL
    // byte on the wire — same convention libsystemd itself uses.
    let (dest, offset) = if bytes.first() == Some(&b'@') {
        (&bytes[1..], 1usize)
    } else {
        (bytes, 0usize)
    };
    let max_len = addr.sun_path.len() - offset - 1;
    if dest.len() > max_len {
        return false;
    }
    for (i, b) in dest.iter().enumerate() {
        addr.sun_path[i + offset] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + offset + dest.len()) as libc::socklen_t;

    let ret = unsafe {
        libc::sendto(
            fd,
            payload.as_ptr() as *const libc::c_void,
            payload.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            len,
        )
    };
    ret >= 0
}
