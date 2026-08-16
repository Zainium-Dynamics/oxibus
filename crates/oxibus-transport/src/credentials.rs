//! Peer credentials for a connected `AF_UNIX` socket, via `SO_PEERCRED`
//! (Linux — matches `_dbus_read_credentials_socket` in
//! `dbus/dbus-sysdeps-unix.c`, minus the BSD/`SCM_CREDS` fallback paths
//! Zainium doesn't need since it only targets Linux).

use std::io;
use std::os::unix::io::RawFd;

/// Identity of the process on the other end of a connected `AF_UNIX`
/// socket, as reported by the kernel via `SO_PEERCRED`. This is the trust
/// anchor for the `EXTERNAL` SASL mechanism and for authorization decisions
/// elsewhere in the daemon — it cannot be spoofed by the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Effective user ID of the peer process at connect time.
    pub uid: u32,
    /// Effective group ID of the peer process at connect time.
    pub gid: u32,
    /// Process ID of the peer, or 0 if the kernel could not determine it
    /// (e.g. the peer's namespace is not visible to us).
    pub pid: i32,
}

/// Read `SO_PEERCRED` off a connected unix-domain socket fd.
pub fn peer_credentials(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: fd is a valid, open socket fd owned by the caller for the
    // duration of this call; ucred/len are correctly sized out-params.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(PeerCredentials {
        uid: ucred.uid,
        gid: ucred.gid,
        pid: ucred.pid,
    })
}

/// Look up a process' Linux Security Module label (used by the EXTERNAL
/// mechanism to carry `DBUS_CREDENTIAL_LINUX_SECURITY_LABEL`; matches
/// `_dbus_read_local_process_label`). Best-effort: returns `None` if the
/// LSM proc file isn't present/readable (no SELinux/AppArmor in this
/// build, matching `oxibus.toml`'s `selinux=false, apparmor=false`).
pub fn security_label(pid: i32) -> Option<Vec<u8>> {
    std::fs::read(format!("/proc/{pid}/attr/current")).ok()
}

/// The uid this process runs as — used for `EXTERNAL`'s implicit "auth as
/// myself" identity and for the DBUS_COOKIE_SHA1 same-user check.
pub fn current_uid() -> u32 {
    // SAFETY: getuid() has no preconditions.
    unsafe { libc::getuid() }
}

/// The process ID of this process — used alongside [`current_uid`] for the
/// `EXTERNAL` mechanism's implicit "auth as myself" identity.
pub fn current_pid() -> i32 {
    // SAFETY: getpid() has no preconditions.
    unsafe { libc::getpid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credentials_on_socketpair() {
        let mut fds = [0i32; 2];
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        let creds = peer_credentials(fds[0]).unwrap();
        assert_eq!(creds.uid, current_uid());
        assert_eq!(creds.pid, current_pid());
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
