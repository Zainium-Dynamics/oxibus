//! `DBusConnection` and the `dbus_connection_*`/`dbus_bus_*` entry points.

use std::ffi::{CString, c_char, c_int};
use std::sync::Arc;
use std::time::Duration;

use oxibus_client::Connection;
use oxibus_core::Address;

use crate::error::DBusError;
use crate::message::{self, DBusMessage, Kind};

pub struct DBusConnection {
    conn: Connection,
}

fn handle(ptr: *mut DBusConnection) -> Option<Arc<DBusConnection>> {
    if ptr.is_null() {
        return None;
    }
    let arc = unsafe { Arc::from_raw(ptr as *const DBusConnection) };
    let borrowed = arc.clone();
    std::mem::forget(arc);
    Some(borrowed)
}

fn resolve_bus_address(bus_type: c_int) -> Result<Address, String> {
    match bus_type {
        // DBUS_BUS_SESSION / DBUS_BUS_STARTER
        0 | 2 => std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .or_else(|_| std::env::var("OXIBUS_SESSION_BUS_ADDRESS"))
            .map_err(|_| "DBUS_SESSION_BUS_ADDRESS is not set".to_string())
            .and_then(|s| Address::parse_one(&s).map_err(|e| e.to_string())),
        // DBUS_BUS_SYSTEM
        1 => {
            if let Ok(s) = std::env::var("DBUS_SYSTEM_BUS_ADDRESS") {
                return Address::parse_one(&s).map_err(|e| e.to_string());
            }
            let cfg = oxibus_config::GlobalConfig::load_default();
            Ok(Address::UnixPath(cfg.paths.system_socket().display().to_string()))
        }
        other => Err(format!("unknown DBusBusType {other}")),
    }
}

fn connect_and_hello(addr: &Address, error: *mut DBusError) -> *mut DBusConnection {
    let result = crate::rt().block_on(async {
        let conn = Connection::connect(addr).await?;
        conn.bus_hello().await?;
        Ok::<Connection, oxibus_client::ClientError>(conn)
    });
    match result {
        Ok(conn) => {
            let arc = Arc::new(DBusConnection { conn });
            Arc::into_raw(arc) as *mut DBusConnection
        }
        Err(e) => {
            if !error.is_null() {
                unsafe {
                    crate::error::dbus_set_error_const(
                        error,
                        c"org.freedesktop.DBus.Error.Failed".as_ptr(),
                        CString::new(e.to_string()).unwrap_or_default().as_ptr(),
                    );
                }
            }
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `error` must be a valid, writable `DBusError*` or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_bus_get(bus_type: c_int, error: *mut DBusError) -> *mut DBusConnection {
    match resolve_bus_address(bus_type) {
        Ok(addr) => connect_and_hello(&addr, error),
        Err(msg) => {
            if !error.is_null() {
                unsafe {
                    crate::error::dbus_set_error_const(
                        error,
                        c"org.freedesktop.DBus.Error.Failed".as_ptr(),
                        CString::new(msg).unwrap_or_default().as_ptr(),
                    );
                }
            }
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `error` must be a valid, writable `DBusError*` or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_bus_get_private(
    bus_type: c_int,
    error: *mut DBusError,
) -> *mut DBusConnection {
    unsafe { dbus_bus_get(bus_type, error) }
}

/// # Safety
/// `address` must be a valid C string; `error` a valid `DBusError*` or
/// null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_open(
    address: *const c_char,
    error: *mut DBusError,
) -> *mut DBusConnection {
    let Some(addr_str) = (unsafe { crate::cstr(address) }) else {
        return std::ptr::null_mut();
    };
    match Address::parse_one(&addr_str) {
        Ok(addr) => connect_and_hello(&addr, error),
        Err(e) => {
            if !error.is_null() {
                unsafe {
                    crate::error::dbus_set_error_const(
                        error,
                        c"org.freedesktop.DBus.Error.Failed".as_ptr(),
                        CString::new(e.to_string()).unwrap_or_default().as_ptr(),
                    );
                }
            }
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `address` must be a valid C string; `error` a valid `DBusError*` or
/// null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_open_private(
    address: *const c_char,
    error: *mut DBusError,
) -> *mut DBusConnection {
    unsafe { dbus_connection_open(address, error) }
}

/// # Safety
/// `connection` must be a valid `DBusConnection*` obtained from this
/// library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_ref(connection: *mut DBusConnection) -> *mut DBusConnection {
    if connection.is_null() {
        return connection;
    }
    unsafe { Arc::increment_strong_count(connection as *const DBusConnection) };
    connection
}

/// # Safety
/// `connection` must be a valid `DBusConnection*` obtained from this
/// library, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_unref(connection: *mut DBusConnection) {
    if connection.is_null() {
        return;
    }
    drop(unsafe { Arc::from_raw(connection as *const DBusConnection) });
}

/// No-op: this MVP doesn't track a separate "closed but not yet dropped"
/// state — the connection tears down when the last reference is unref'd.
/// # Safety
/// `connection` must be a valid `DBusConnection*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_close(_connection: *mut DBusConnection) {}

/// # Safety
/// `connection` must be a valid `DBusConnection*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_get_is_connected(connection: *mut DBusConnection) -> c_int {
    handle(connection).is_some() as c_int
}

/// Always reports true post-handshake in this MVP (we don't yet do
/// external SASL mechanisms where this would meaningfully be false).
/// # Safety
/// `connection` must be a valid `DBusConnection*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_get_is_authenticated(connection: *mut DBusConnection) -> c_int {
    handle(connection).is_some() as c_int
}

/// No-op: every send in this MVP already awaits the underlying socket
/// write before returning.
/// # Safety
/// `connection` must be a valid `DBusConnection*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_flush(_connection: *mut DBusConnection) {}

/// # Safety
/// `connection` must be a valid `DBusConnection*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_bus_get_unique_name(connection: *mut DBusConnection) -> *const c_char {
    let Some(h) = handle(connection) else { return std::ptr::null() };
    match h.conn.unique_name() {
        Some(n) => CString::new(n).map(|c| c.into_raw() as *const c_char).unwrap_or(std::ptr::null()),
        None => std::ptr::null(),
    }
}

/// # Safety
/// `connection` must be a valid `DBusConnection*`; `name` a valid C
/// string; `error` a valid `DBusError*` or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_bus_request_name(
    connection: *mut DBusConnection,
    name: *const c_char,
    flags: u32,
    error: *mut DBusError,
) -> c_int {
    let (Some(h), Some(name)) = (handle(connection), unsafe { crate::cstr(name) }) else {
        return -1;
    };
    match crate::rt().block_on(h.conn.request_name(&name, flags)) {
        Ok(result) => result as c_int,
        Err(e) => {
            if !error.is_null() {
                unsafe {
                    crate::error::dbus_set_error_const(
                        error,
                        c"org.freedesktop.DBus.Error.Failed".as_ptr(),
                        CString::new(e.to_string()).unwrap_or_default().as_ptr(),
                    );
                }
            }
            -1
        }
    }
}

/// # Safety
/// `connection` must be a valid `DBusConnection*`; `rule` a valid C
/// string; `error` a valid `DBusError*` or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_bus_add_match(
    connection: *mut DBusConnection,
    rule: *const c_char,
    error: *mut DBusError,
) {
    let (Some(h), Some(rule)) = (handle(connection), unsafe { crate::cstr(rule) }) else {
        return;
    };
    if let Err(e) = crate::rt().block_on(h.conn.add_match(&rule))
        && !error.is_null()
    {
        unsafe {
            crate::error::dbus_set_error_const(
                error,
                c"org.freedesktop.DBus.Error.Failed".as_ptr(),
                CString::new(e.to_string()).unwrap_or_default().as_ptr(),
            );
        }
    }
}

/// The core MVP path: build a method call or signal with
/// `dbus_message_new_*` + `dbus_message_iter_append_basic`, then send it
/// here and block for the reply (method calls) or fire-and-forget
/// (signals). `dbus_connection_send` (non-blocking, dispatch-later) isn't
/// implemented for method calls yet — use this function instead.
///
/// # Safety
/// `connection` and `message` must be valid pointers obtained from this
/// library; `error` a valid `DBusError*` or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_send_with_reply_and_block(
    connection: *mut DBusConnection,
    dbus_message: *mut DBusMessage,
    timeout_milliseconds: c_int,
    error: *mut DBusError,
) -> *mut DBusMessage {
    let Some(h) = handle(connection) else { return std::ptr::null_mut() };
    let Some(out) = message::take_outgoing(dbus_message) else {
        if !error.is_null() {
            unsafe {
                crate::error::dbus_set_error_const(
                    error,
                    c"org.freedesktop.DBus.Error.Failed".as_ptr(),
                    c"message is not a call under construction, or has already been sent".as_ptr(),
                );
            }
        }
        return std::ptr::null_mut();
    };
    if out.kind != Kind::MethodCall {
        if !error.is_null() {
            unsafe {
                crate::error::dbus_set_error_const(
                    error,
                    c"org.freedesktop.DBus.Error.Failed".as_ptr(),
                    c"only method-call messages can be sent with a blocking reply".as_ptr(),
                );
            }
        }
        return std::ptr::null_mut();
    }
    let Some(path) = out.path else { return std::ptr::null_mut() };
    let Some(member) = out.member else { return std::ptr::null_mut() };

    let call = h.conn.call_method(
        out.destination.as_deref(),
        path,
        out.interface.as_deref(),
        &member,
        out.args,
    );
    let timeout = if timeout_milliseconds > 0 {
        Some(Duration::from_millis(timeout_milliseconds as u64))
    } else {
        None // -1 means "use a sane default" upstream; we just wait indefinitely for the MVP
    };
    let result = crate::rt().block_on(async move {
        match timeout {
            Some(d) => tokio::time::timeout(d, call)
                .await
                .map_err(|_| "no reply within the requested timeout".to_string())
                .and_then(|r| r.map_err(|e| e.to_string())),
            None => call.await.map_err(|e| e.to_string()),
        }
    });
    match result {
        Ok(reply_args) => {
            let msg = oxibus_core::MessageBuilder::method_return(0).args(reply_args).build(0);
            message::wrap_incoming(msg)
        }
        Err(e) => {
            if !error.is_null() {
                unsafe {
                    crate::error::dbus_set_error_const(
                        error,
                        c"org.freedesktop.DBus.Error.Failed".as_ptr(),
                        CString::new(e).unwrap_or_default().as_ptr(),
                    );
                }
            }
            std::ptr::null_mut()
        }
    }
}

/// Sends a signal (fire-and-forget). Method-call messages should go
/// through `dbus_connection_send_with_reply_and_block` instead in this
/// MVP — see that function's docs.
///
/// # Safety
/// `connection` and `message` must be valid pointers obtained from this
/// library; `serial` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_connection_send(
    connection: *mut DBusConnection,
    dbus_message: *mut DBusMessage,
    serial: *mut u32,
) -> c_int {
    let (Some(h), Some(out)) = (handle(connection), message::take_outgoing(dbus_message)) else {
        return 0;
    };
    if out.kind != Kind::Signal {
        return 0; // method calls / returns / errors: not implemented via this entry point yet
    }
    let (Some(path), Some(interface), Some(member)) = (out.path, out.interface, out.member) else {
        return 0;
    };
    let ok = crate::rt()
        .block_on(h.conn.emit_signal(path, &interface, &member, out.args))
        .is_ok();
    if ok && !serial.is_null() {
        unsafe { *serial = 0 }; // signal serials aren't surfaced by oxibus-client today
    }
    ok as c_int
}
