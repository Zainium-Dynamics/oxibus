// AppArmor dynamic mediation.

use std::sync::OnceLock;
use tracing::{debug, warn};

pub const AA_CLASS_DBUS: u8 = 32;
pub const AA_DBUS_SEND: u32 = 1 << 1;
pub const AA_DBUS_RECEIVE: u32 = 1 << 2;
pub const AA_DBUS_BIND: u32 = 1 << 6;

struct AppArmorLib {
    _aa_is_enabled: unsafe extern "C" fn() -> libc::c_int,
    aa_query_label: unsafe extern "C" fn(
        mask: u32,
        query: *mut libc::c_char,
        size: libc::size_t,
        allowed: *mut libc::c_int,
        audited: *mut libc::c_int,
    ) -> libc::c_int,
}

static APPARMOR_LIB: OnceLock<Option<AppArmorLib>> = OnceLock::new();

fn get_apparmor_lib() -> Option<&'static AppArmorLib> {
    APPARMOR_LIB
        .get_or_init(|| unsafe {
            let handle = libc::dlopen(c"libapparmor.so.1".as_ptr(), libc::RTLD_LAZY);
            let handle = if handle.is_null() {
                libc::dlopen(c"libapparmor.so".as_ptr(), libc::RTLD_LAZY)
            } else {
                handle
            };
            if handle.is_null() {
                debug!("AppArmor library not found, mediation disabled");
                return None;
            }

            let aa_is_enabled_ptr = libc::dlsym(handle, c"aa_is_enabled".as_ptr());
            let aa_query_label_ptr = libc::dlsym(handle, c"aa_query_label".as_ptr());

            if aa_is_enabled_ptr.is_null() || aa_query_label_ptr.is_null() {
                warn!("AppArmor library symbols missing, mediation disabled");
                libc::dlclose(handle);
                return None;
            }

            let aa_is_enabled: unsafe extern "C" fn() -> libc::c_int =
                std::mem::transmute(aa_is_enabled_ptr);
            let aa_query_label: unsafe extern "C" fn(
                mask: u32,
                query: *mut libc::c_char,
                size: libc::size_t,
                allowed: *mut libc::c_int,
                audited: *mut libc::c_int,
            ) -> libc::c_int = std::mem::transmute(aa_query_label_ptr);

            if aa_is_enabled() == 0 {
                debug!("AppArmor is disabled in the kernel");
                libc::dlclose(handle);
                return None;
            }

            debug!("AppArmor library loaded successfully");
            Some(AppArmorLib {
                _aa_is_enabled: aa_is_enabled,
                aa_query_label,
            })
        })
        .as_ref()
}

pub fn is_enabled() -> bool {
    get_apparmor_lib().is_some()
}

pub fn query_label(mask: u32, query_data: &[u8]) -> Result<(bool, bool), std::io::Error> {
    let Some(lib) = get_apparmor_lib() else {
        return Ok((true, false));
    };

    let mut query = query_data.to_vec();
    let mut allowed: libc::c_int = 0;
    let mut audited: libc::c_int = 0;

    let rc = unsafe {
        (lib.aa_query_label)(
            mask,
            query.as_mut_ptr() as *mut libc::c_char,
            query.len(),
            &mut allowed,
            &mut audited,
        )
    };

    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok((allowed != 0, audited != 0))
}

pub fn get_self_label() -> String {
    std::fs::read_to_string("/proc/self/attr/current")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unconfined".to_string())
}

pub fn build_query(
    con: &str,
    bustype: &str,
    name: Option<&str>,
    dst_con: Option<&str>,
    path: Option<&str>,
    interface: Option<&str>,
    member: Option<&str>,
) -> Vec<u8> {
    let mut query = vec![0u8; 6];
    query.extend_from_slice(con.as_bytes());
    query.push(0);
    query.push(AA_CLASS_DBUS);
    query.extend_from_slice(bustype.as_bytes());

    let parts = [name, dst_con, path, interface, member];
    let end_idx = parts
        .iter()
        .rposition(|p| p.is_some())
        .map(|i| i + 1)
        .unwrap_or(0);

    for part in parts.iter().take(end_idx) {
        query.push(0);
        if let Some(val) = part {
            query.extend_from_slice(val.as_bytes());
        }
    }

    query
}

#[allow(clippy::too_many_arguments)] // mirrors the AppArmor D-Bus query shape 1:1
pub fn check_permission(
    mask: u32,
    con: Option<&str>,
    dst_con: Option<&str>,
    bustype: &str,
    name: Option<&str>,
    path: Option<&str>,
    interface: Option<&str>,
    member: Option<&str>,
    uid: u32,
) -> bool {
    if !is_enabled() {
        return true;
    }

    let con = con.unwrap_or("unconfined");
    if con == "unconfined" {
        return true;
    }

    let query = build_query(con, bustype, name, dst_con, path, interface, member);
    match query_label(mask, &query) {
        Ok((allowed, _audited)) => {
            if !allowed {
                let op = if mask == AA_DBUS_BIND {
                    "dbus_bind"
                } else {
                    "dbus_method_call"
                };
                let info = if mask == AA_DBUS_BIND {
                    "bind"
                } else if mask == AA_DBUS_SEND {
                    "send"
                } else {
                    "receive"
                };

                let mut avc_msg = format!(
                    "apparmor=\"DENIED\" operation=\"{}\" info=\"{}\" bus=\"{}\"",
                    op, info, bustype
                );
                if let Some(n) = name {
                    avc_msg.push_str(&format!(" name=\"{}\"", n));
                }
                if let Some(p) = path {
                    avc_msg.push_str(&format!(" path=\"{}\"", p));
                }
                if let Some(i) = interface {
                    avc_msg.push_str(&format!(" interface=\"{}\"", i));
                }
                if let Some(m) = member {
                    avc_msg.push_str(&format!(" member=\"{}\"", m));
                }
                if let Some(dc) = dst_con {
                    avc_msg.push_str(&format!(" peer_label=\"{}\"", dc));
                }

                crate::audit::log_avc(uid, &avc_msg);
                return false;
            }
            true
        }
        Err(e) => {
            warn!("AppArmor query failed: {e}");
            true
        }
    }
}
