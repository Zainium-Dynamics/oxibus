// SCM_RIGHTS file descriptor passing.

use std::io;
use std::os::unix::io::RawFd;

pub const MAX_FDS_PER_CALL: usize = 1024;

fn cmsg_space(n_fds: usize) -> usize {
    let payload = n_fds * std::mem::size_of::<RawFd>();
    let align = std::mem::size_of::<usize>();
    let hdr = unsafe { libc::CMSG_SPACE(payload as u32) as usize };
    let _ = align;
    hdr
}

pub fn send_with_fds(fd: RawFd, buf: &[u8], out_fds: &[RawFd]) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut cmsg_buf: Vec<u8>;
    let (cmsg_ptr, cmsg_len) = if out_fds.is_empty() {
        (std::ptr::null_mut(), 0usize)
    } else {
        let space = cmsg_space(out_fds.len());
        cmsg_buf = vec![0u8; space];
        unsafe {
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = space as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN((out_fds.len() * std::mem::size_of::<RawFd>()) as u32) as _;
            let data_ptr = libc::CMSG_DATA(cmsg) as *mut RawFd;
            std::ptr::copy_nonoverlapping(out_fds.as_ptr(), data_ptr, out_fds.len());
        }
        (cmsg_buf.as_mut_ptr() as *mut libc::c_void, space)
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_ptr;
    msg.msg_controllen = cmsg_len as _;

    let n = unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

pub fn recv_with_fds(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, Vec<RawFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let space = cmsg_space(MAX_FDS_PER_CALL);
    let mut cmsg_buf = vec![0u8; space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut received_fds = Vec::new();
    if msg.msg_controllen > 0 {
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS
                {
                    let data_len =
                        (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                    let count = data_len / std::mem::size_of::<RawFd>();
                    let data_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                    for i in 0..count {
                        received_fds.push(*data_ptr.add(i));
                    }
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }
    }

    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        for f in &received_fds {
            unsafe {
                libc::close(*f);
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SCM_RIGHTS ancillary data truncated (too many fds in one message)",
        ));
    }

    Ok((n as usize, received_fds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn send_and_recv_fd_over_socketpair() {
        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            0
        );
        let (a, b) = (fds[0], fds[1]);

        let dummy = std::io::stdin().as_raw_fd();
        let sent = send_with_fds(a, b"hi", &[dummy]).unwrap();
        assert_eq!(sent, 2);

        let mut buf = [0u8; 16];
        let (n, recv_fds) = recv_with_fds(b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(recv_fds.len(), 1);

        unsafe {
            libc::close(a);
            libc::close(b);
            libc::close(recv_fds[0]);
        }
    }
}
