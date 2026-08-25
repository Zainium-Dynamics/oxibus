// Peer credentials for a connected AF_UNIX socket via SO_PEERCRED.

use std::io;
use std::os::unix::io::RawFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

pub fn peer_credentials(fd: RawFd) -> io::Result<PeerCredentials> {
    let mut ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

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

pub fn peer_security_label(fd: RawFd) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 1024];
    let mut len = buf.len() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            buf.as_mut_ptr() as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        buf.truncate(len as usize);
        if let Some(pos) = buf.iter().position(|&x| x == 0) {
            buf.truncate(pos);
        }
        if !buf.is_empty() {
            return Some(buf);
        }
    }
    None
}

pub fn security_label(pid: i32) -> Option<Vec<u8>> {
    std::fs::read(format!("/proc/{pid}/attr/current")).ok()
}

pub fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

pub fn current_pid() -> i32 {
    unsafe { libc::getpid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credentials_on_socketpair() {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
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
