//! `DBusError` and the `dbus_error_*`/`dbus_set_error*` entry points.

use std::ffi::{CString, c_char, c_void};

/// Field layout fixed by the external ABI: `name`/`message` are the two
/// documented-public fields real callers read directly
/// (`fprintf(stderr, "%s: %s", err.name, err.message)` is extremely
/// common); the rest is opaque bookkeeping every caller is told never to
/// touch, so we only need to match its *size*, not its meaning.
#[repr(C)]
pub struct DBusError {
    pub name: *const c_char,
    pub message: *const c_char,
    flags: u32,
    _reserved: u32,
    padding1: *mut c_void,
}

impl DBusError {
    fn clear(&mut self) {
        drop_owned(self.name);
        drop_owned(self.message);
        self.name = std::ptr::null();
        self.message = std::ptr::null();
        self.flags = 0;
        self._reserved = 0;
        self.padding1 = std::ptr::null_mut();
    }

    pub(crate) fn set(&mut self, name: &str, message: &str) {
        self.clear();
        self.name = leak_cstring(name);
        self.message = leak_cstring(message);
    }
}

fn leak_cstring(s: &str) -> *const c_char {
    CString::new(s.replace('\0', ""))
        .map(|c| c.into_raw() as *const c_char)
        .unwrap_or(std::ptr::null())
}

fn drop_owned(ptr: *const c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr as *mut c_char));
        }
    }
}

/// # Safety
/// `error` must point to a valid, writable `DBusError`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_error_init(error: *mut DBusError) {
    if error.is_null() {
        return;
    }
    unsafe {
        (*error).name = std::ptr::null();
        (*error).message = std::ptr::null();
        (*error).flags = 0;
        (*error)._reserved = 0;
        (*error).padding1 = std::ptr::null_mut();
    }
}

/// # Safety
/// `error` must point to a valid `DBusError` previously passed to
/// `dbus_error_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_error_free(error: *mut DBusError) {
    if error.is_null() {
        return;
    }
    unsafe { (*error).clear() };
}

/// # Safety
/// `error` must point to a valid `DBusError` (or be null).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_error_is_set(error: *const DBusError) -> libc::c_int {
    if error.is_null() {
        return 0;
    }
    unsafe { !(*error).name.is_null() as libc::c_int }
}

/// # Safety
/// `error` must point to a valid `DBusError`; `name` must be a valid C
/// string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_error_has_name(
    error: *const DBusError,
    name: *const c_char,
) -> libc::c_int {
    if error.is_null() || unsafe { (*error).name.is_null() } {
        return 0;
    }
    let Some(want) = (unsafe { crate::cstr(name) }) else {
        return 0;
    };
    let have = unsafe { std::ffi::CStr::from_ptr((*error).name) }.to_string_lossy();
    (have == want) as libc::c_int
}

/// # Safety
/// `error` must point to a valid, writable `DBusError`; `name` and
/// `message` must be valid C strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_set_error_const(
    error: *mut DBusError,
    name: *const c_char,
    message: *const c_char,
) {
    if error.is_null() {
        return;
    }
    let name = unsafe { crate::cstr(name) }.unwrap_or_default();
    let message = unsafe { crate::cstr(message) }.unwrap_or_default();
    unsafe { (*error).set(&name, &message) };
}

/// # Safety
/// `dest` must point to a valid, writable `DBusError`; `src` must point to
/// a valid `DBusError`. `src` is left cleared, matching upstream
/// `dbus_move_error`'s documented ownership-transfer semantics.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_move_error(src: *mut DBusError, dest: *mut DBusError) {
    if src.is_null() || dest.is_null() || std::ptr::eq(src, dest) {
        return;
    }
    unsafe {
        (*dest).clear();
        (*dest).name = (*src).name;
        (*dest).message = (*src).message;
        (*src).name = std::ptr::null();
        (*src).message = std::ptr::null();
        (*src).flags = 0;
        (*src)._reserved = 0;
        (*src).padding1 = std::ptr::null_mut();
    }
}
