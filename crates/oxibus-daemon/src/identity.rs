//! uid → username / group-name resolution for policy evaluation
//! (`/etc/passwd`, `/etc/group` via libc, matching how real `dbus-daemon`
//! resolves `<policy user=".."/>`/`<policy group=".."/>`).

use std::ffi::CStr;

/// A resolved uid, together with the passwd/group-db names policy rules are
/// written against. Owned counterpart of [`crate::policy::Identity`]'s
/// borrowed fields.
pub struct Identity {
    /// The uid this was resolved from — always present even if the
    /// remaining fields could not be resolved.
    pub uid: u32,
    /// The `/etc/passwd` username for `uid`, or `None` if there is no such
    /// user (policy `user =` rules referencing this identity then only
    /// match by numeric uid).
    pub user_name: Option<String>,
    /// Every group `uid` belongs to (primary and supplementary), or empty
    /// if `user_name` could not be resolved.
    pub group_names: Vec<String>,
}

/// Look up `uid`'s username and full group membership via `libc`'s
/// passwd/group database, for evaluating `<policy user=".."/>` /
/// `<policy group=".."/>`-equivalent rules. Never fails outright — an
/// unresolvable uid just yields empty `user_name`/`group_names`.
pub fn resolve(uid: u32) -> Identity {
    // SAFETY: getpwuid returns a pointer into a static buffer that is only
    // valid until the next passwd-db call on this thread; we copy the
    // fields we need out of it immediately and don't call any other
    // getpw*/getgr* function while `pw` is still borrowed.
    let (user_name, primary_gid) = unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            (None, None)
        } else {
            let name = CStr::from_ptr((*pw).pw_name).to_string_lossy().into_owned();
            (Some(name), Some((*pw).pw_gid))
        }
    };

    let mut group_names = Vec::new();
    if let Some(name) = &user_name {
        if let Ok(cname) = std::ffi::CString::new(name.as_str()) {
            // First call to discover how many groups; if it fits, libc
            // fills `gids`, otherwise it tells us the real count via
            // `ngroups` and we retry once with a correctly sized buffer.
            let mut ngroups: libc::c_int = 32;
            let mut gids = vec![0 as libc::gid_t; ngroups as usize];
            let base_gid = primary_gid.unwrap_or(0);
            // SAFETY: cname is a valid NUL-terminated C string for the
            // duration of this call; gids is sized to ngroups and getgrouplist
            // writes at most ngroups entries (or returns -1 and updates
            // ngroups with the required size on Linux).
            let rc = unsafe {
                libc::getgrouplist(
                    cname.as_ptr(),
                    base_gid,
                    gids.as_mut_ptr(),
                    &mut ngroups,
                )
            };
            if rc < 0 {
                gids.resize(ngroups as usize, 0);
                // SAFETY: same as above, buffer now sized to the kernel's
                // reported requirement.
                unsafe {
                    libc::getgrouplist(cname.as_ptr(), base_gid, gids.as_mut_ptr(), &mut ngroups);
                }
            } else {
                gids.truncate(ngroups as usize);
            }
            for gid in gids {
                // SAFETY: getgrgid's returned pointer is copied out
                // immediately, same caveat as getpwuid above.
                unsafe {
                    let gr = libc::getgrgid(gid);
                    if !gr.is_null() {
                        group_names.push(CStr::from_ptr((*gr).gr_name).to_string_lossy().into_owned());
                    }
                }
            }
        }
    }

    Identity {
        uid,
        user_name,
        group_names,
    }
}
