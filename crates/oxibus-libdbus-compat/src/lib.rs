//! `libdbus-1.so.3` compatibility shim.
//!
//! This is a C ABI shared library — built with `crate-type = ["cdylib"]`
//! and an explicit `[lib] name = "dbus-1"` in Cargo.toml so the artifact
//! is `libdbus-1.so` — that lets unmodified programs which dynamically
//! link the reference `libdbus-1.so.3` talk to OxiBus instead, without
//! recompiling. It's a thin bridge on top of `oxibus-client`'s async API:
//! every exported `dbus_*` function is original code written for this
//! crate, not derived from any existing libdbus implementation. Only the
//! public function names, the `DBusError`/`DBusMessageIter` struct
//! layouts, and the D-Bus wire-protocol type codes are fixed by the
//! external ABI/spec we're interoperating with.
//!
//! Scope (MVP): covers the common "open a connection, build a method
//! call, send it and block for the reply, read the reply back" path plus
//! signals and basic error handling. Not covered yet (calls into these
//! link fine but return a clear failure rather than working): async
//! pending-call tracking / `dbus_connection_send` for method calls,
//! `dbus_connection_pop_message`/filters, containers (array/struct/dict/
//! variant) in the iterator API, and anything Windows- or X11-specific.
//!
//! One real gap worth calling out: the printf-style, C-variadic
//! `dbus_set_error(error, name, format, ...)` isn't exported — stable
//! Rust can't define a variadic `extern "C"` function, and getting a tiny
//! C shim's symbol to survive rustc's cdylib export-list trimming turned
//! out to need proper version-script plumbing rather than a quick flag.
//! `dbus_set_error_const` (no varargs) is fully implemented and exported;
//! callers that only ever pass a literal message (i.e. no `%` specifiers)
//! would work fine even against the real `dbus_set_error` and are
//! unaffected by this gap.

mod connection;
mod error;
mod message;

use std::sync::OnceLock;
use tokio::runtime::Runtime;

/// One background Tokio runtime shared by every connection this process
/// opens through the shim — C callers have no async context of their own,
/// so blocking entry points (`dbus_connection_send_with_reply_and_block`,
/// `dbus_bus_get`, ...) drive it with `block_on`.
pub(crate) fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("oxibus-libdbus-compat: failed to start Tokio runtime")
    })
}

/// Reads a NUL-terminated C string. `None` for a null pointer or invalid
/// UTF-8 (real libdbus requires valid UTF-8 for bus/interface/member names
/// and strings too, so this matches the documented contract rather than
/// silently mangling data).
pub(crate) unsafe fn cstr(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}
