use std::ffi::CString;
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// User space AVC message type ID.
pub const AUDIT_USER_AVC: i32 = 1107;

struct AuditLib {
    audit_open: unsafe extern "C" fn() -> libc::c_int,
    audit_log_user_avc_message: unsafe extern "C" fn(
        audit_fd: libc::c_int,
        type_: libc::c_int,
        message: *const libc::c_char,
        hostname: *const libc::c_char,
        addr: *const libc::c_char,
        tty: *const libc::c_char,
        uid: libc::uid_t,
    ) -> libc::c_int,
    audit_close: unsafe extern "C" fn(audit_fd: libc::c_int),
}

static AUDIT_LIB: OnceLock<Option<AuditLib>> = OnceLock::new();
static AUDIT_FD: OnceLock<libc::c_int> = OnceLock::new();

fn get_audit_lib() -> Option<&'static AuditLib> {
    AUDIT_LIB.get_or_init(|| {
        unsafe {
            let handle = libc::dlopen(b"libaudit.so.1\0".as_ptr() as *const _, libc::RTLD_LAZY);
            let handle = if handle.is_null() {
                libc::dlopen(b"libaudit.so\0".as_ptr() as *const _, libc::RTLD_LAZY)
            } else {
                handle
            };
            if handle.is_null() {
                debug!("Audit library not found, audit logging disabled");
                return None;
            }

            let audit_open_ptr = libc::dlsym(handle, b"audit_open\0".as_ptr() as *const _);
            let audit_log_user_avc_message_ptr = libc::dlsym(handle, b"audit_log_user_avc_message\0".as_ptr() as *const _);
            let audit_close_ptr = libc::dlsym(handle, b"audit_close\0".as_ptr() as *const _);

            if audit_open_ptr.is_null() || audit_log_user_avc_message_ptr.is_null() || audit_close_ptr.is_null() {
                warn!("Audit library symbols missing, audit logging disabled");
                libc::dlclose(handle);
                return None;
            }

            debug!("Audit library loaded successfully");
            Some(AuditLib {
                audit_open: std::mem::transmute(audit_open_ptr),
                audit_log_user_avc_message: std::mem::transmute(audit_log_user_avc_message_ptr),
                audit_close: std::mem::transmute(audit_close_ptr),
            })
        }
    }).as_ref()
}

/// Initialize the Audit subsystem.
pub fn init() {
    if let Some(lib) = get_audit_lib() {
        let fd = unsafe { (lib.audit_open)() };
        if fd >= 0 {
            debug!("Audit connection opened successfully (fd={})", fd);
            let _ = AUDIT_FD.set(fd);
        } else {
            warn!("Failed to open audit socket: {}", std::io::Error::last_os_error());
        }
    }
}

/// Log an AVC message.
pub fn log_avc(uid: u32, msg: &str) {
    if let Some(lib) = get_audit_lib() {
        if let Some(&fd) = AUDIT_FD.get() {
            if fd >= 0 {
                if let Ok(c_msg) = CString::new(msg) {
                    unsafe {
                        (lib.audit_log_user_avc_message)(
                            fd,
                            AUDIT_USER_AVC,
                            c_msg.as_ptr(),
                            std::ptr::null(),
                            std::ptr::null(),
                            std::ptr::null(),
                            uid as libc::uid_t,
                        );
                    }
                    return;
                }
            }
        }
    }
    info!("AVC log (fallback): uid={} msg={}", uid, msg);
}

/// Shutdown the Audit subsystem.
pub fn shutdown() {
    if let Some(lib) = get_audit_lib() {
        if let Some(&fd) = AUDIT_FD.get() {
            if fd >= 0 {
                unsafe {
                    (lib.audit_close)(fd);
                }
            }
        }
    }
}
