// Identity resolution for uid, username, and group membership.

use std::ffi::CStr;

pub struct Identity {
    pub uid: u32,
    pub user_name: Option<String>,
    pub group_names: Vec<String>,
}

pub fn resolve(uid: u32) -> Identity {
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
            let mut ngroups: libc::c_int = 32;
            let mut gids = vec![0 as libc::gid_t; ngroups as usize];
            let base_gid = primary_gid.unwrap_or(0);
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
                unsafe {
                    libc::getgrouplist(cname.as_ptr(), base_gid, gids.as_mut_ptr(), &mut ngroups);
                }
            } else {
                gids.truncate(ngroups as usize);
            }
            for gid in gids {
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
