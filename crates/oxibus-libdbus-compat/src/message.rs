//! `DBusMessage` + `DBusMessageIter` and the `dbus_message_*` entry points.
//!
//! A `DBusMessage` on the C side is either a message we're still building
//! (created by `dbus_message_new_*`, args appended via the iterator API,
//! then handed to a `dbus_connection_send*` function) or one we received
//! (a reply, wrapped up for the caller to read back out with the same
//! iterator API). Refcounted with a plain `Arc`, matching
//! `dbus_message_ref`/`dbus_message_unref`.

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::{Arc, Mutex};

use oxibus_core::{Message, ObjectPath, Type, Value};

// Wire-protocol type codes — fixed by the D-Bus Specification, not by any
// particular implementation.
const TYPE_INVALID: c_int = 0;
const TYPE_BYTE: c_int = b'y' as c_int;
const TYPE_BOOLEAN: c_int = b'b' as c_int;
const TYPE_INT16: c_int = b'n' as c_int;
const TYPE_UINT16: c_int = b'q' as c_int;
const TYPE_INT32: c_int = b'i' as c_int;
const TYPE_UINT32: c_int = b'u' as c_int;
const TYPE_INT64: c_int = b'x' as c_int;
const TYPE_UINT64: c_int = b't' as c_int;
const TYPE_DOUBLE: c_int = b'd' as c_int;
const TYPE_STRING: c_int = b's' as c_int;
const TYPE_OBJECT_PATH: c_int = b'o' as c_int;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    MethodCall,
    MethodReturn,
    Signal,
    Error,
}

pub(crate) struct Outgoing {
    pub kind: Kind,
    pub path: Option<ObjectPath>,
    pub interface: Option<String>,
    /// Method/signal name for calls and signals; error name for errors.
    pub member: Option<String>,
    pub destination: Option<String>,
    pub reply_serial: Option<u32>,
    pub args: Vec<Value>,
}

pub(crate) enum Inner {
    Out(Outgoing),
    In(Message),
}

pub struct DBusMessage {
    pub(crate) inner: Mutex<Inner>,
}

fn handle(ptr: *mut DBusMessage) -> Option<Arc<DBusMessage>> {
    if ptr.is_null() {
        return None;
    }
    // Borrow without touching the refcount: dbus_message_unref is the only
    // function allowed to actually drop a reference.
    let arc = unsafe { Arc::from_raw(ptr as *const DBusMessage) };
    let borrowed = arc.clone();
    std::mem::forget(arc);
    Some(borrowed)
}

pub(crate) fn wrap_incoming(msg: Message) -> *mut DBusMessage {
    let arc = Arc::new(DBusMessage {
        inner: Mutex::new(Inner::In(msg)),
    });
    Arc::into_raw(arc) as *mut DBusMessage
}

fn new_outgoing(kind: Kind) -> *mut DBusMessage {
    let arc = Arc::new(DBusMessage {
        inner: Mutex::new(Inner::Out(Outgoing {
            kind,
            path: None,
            interface: None,
            member: None,
            destination: None,
            reply_serial: None,
            args: Vec::new(),
        })),
    });
    Arc::into_raw(arc) as *mut DBusMessage
}

#[unsafe(no_mangle)]
pub extern "C" fn dbus_message_new_method_call(
    destination: *const c_char,
    path: *const c_char,
    interface: *const c_char,
    method: *const c_char,
) -> *mut DBusMessage {
    let Some(path) = (unsafe { crate::cstr(path) }).and_then(|p| ObjectPath::new(p).ok()) else {
        return std::ptr::null_mut();
    };
    let Some(method) = (unsafe { crate::cstr(method) }) else {
        return std::ptr::null_mut();
    };
    let ptr = new_outgoing(Kind::MethodCall);
    if let Some(h) = handle(ptr)
        && let Inner::Out(o) = &mut *h.inner.lock().unwrap()
    {
        o.path = Some(path);
        o.member = Some(method);
        o.interface = unsafe { crate::cstr(interface) };
        o.destination = unsafe { crate::cstr(destination) };
    }
    ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn dbus_message_new_signal(
    path: *const c_char,
    interface: *const c_char,
    name: *const c_char,
) -> *mut DBusMessage {
    let (Some(path), Some(interface), Some(name)) = (
        (unsafe { crate::cstr(path) }).and_then(|p| ObjectPath::new(p).ok()),
        unsafe { crate::cstr(interface) },
        unsafe { crate::cstr(name) },
    ) else {
        return std::ptr::null_mut();
    };
    let ptr = new_outgoing(Kind::Signal);
    if let Some(h) = handle(ptr)
        && let Inner::Out(o) = &mut *h.inner.lock().unwrap()
    {
        o.path = Some(path);
        o.interface = Some(interface);
        o.member = Some(name);
    }
    ptr
}

/// # Safety
/// `method_call` must be a valid `DBusMessage*` received from this
/// library (e.g. one passed to a method handler — not implemented as a
/// server-side entry point yet, but the constructor itself works for any
/// received message).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_new_method_return(
    method_call: *mut DBusMessage,
) -> *mut DBusMessage {
    let Some(h) = handle(method_call) else { return std::ptr::null_mut() };
    let (reply_serial, destination) = match &*h.inner.lock().unwrap() {
        Inner::In(m) => (Some(m.serial()), m.sender().map(str::to_owned)),
        Inner::Out(_) => return std::ptr::null_mut(),
    };
    let ptr = new_outgoing(Kind::MethodReturn);
    if let Some(h) = handle(ptr)
        && let Inner::Out(o) = &mut *h.inner.lock().unwrap()
    {
        o.reply_serial = reply_serial;
        o.destination = destination;
    }
    ptr
}

/// # Safety
/// `reply_to` must be a valid `DBusMessage*` received from this library;
/// `error_name` and `error_message` must be valid C strings, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_new_error(
    reply_to: *mut DBusMessage,
    error_name: *const c_char,
    error_message: *const c_char,
) -> *mut DBusMessage {
    let Some(name) = (unsafe { crate::cstr(error_name) }) else { return std::ptr::null_mut() };
    let Some(h) = handle(reply_to) else { return std::ptr::null_mut() };
    let (reply_serial, destination) = match &*h.inner.lock().unwrap() {
        Inner::In(m) => (Some(m.serial()), m.sender().map(str::to_owned)),
        Inner::Out(_) => return std::ptr::null_mut(),
    };
    let ptr = new_outgoing(Kind::Error);
    if let Some(h) = handle(ptr)
        && let Inner::Out(o) = &mut *h.inner.lock().unwrap()
    {
        o.reply_serial = reply_serial;
        o.destination = destination;
        o.member = Some(name);
        if let Some(msg) = unsafe { crate::cstr(error_message) } {
            o.args.push(Value::String(msg));
        }
    }
    ptr
}

/// # Safety
/// `message` must be a valid, non-null `DBusMessage*` obtained from this
/// library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_ref(message: *mut DBusMessage) -> *mut DBusMessage {
    if message.is_null() {
        return message;
    }
    unsafe { Arc::increment_strong_count(message as *const DBusMessage) };
    message
}

/// # Safety
/// `message` must be a valid `DBusMessage*` obtained from this library, or
/// null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_unref(message: *mut DBusMessage) {
    if message.is_null() {
        return;
    }
    drop(unsafe { Arc::from_raw(message as *const DBusMessage) });
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_type(message: *mut DBusMessage) -> c_int {
    let Some(h) = handle(message) else { return TYPE_INVALID };
    match &*h.inner.lock().unwrap() {
        Inner::Out(o) => match o.kind {
            Kind::MethodCall => 1,
            Kind::MethodReturn => 2,
            Kind::Error => 3,
            Kind::Signal => 4,
        },
        Inner::In(m) => match m.message_type() {
            oxibus_core::header::MessageType::MethodCall => 1,
            oxibus_core::header::MessageType::MethodReturn => 2,
            oxibus_core::header::MessageType::Error => 3,
            oxibus_core::header::MessageType::Signal => 4,
        },
    }
}

fn leak_opt(s: Option<String>) -> *const c_char {
    match s {
        Some(s) => CString::new(s).map(|c| c.into_raw() as *const c_char).unwrap_or(std::ptr::null()),
        None => std::ptr::null(),
    }
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_interface(message: *mut DBusMessage) -> *const c_char {
    let Some(h) = handle(message) else { return std::ptr::null() };
    let s = match &*h.inner.lock().unwrap() {
        Inner::Out(o) => o.interface.clone(),
        Inner::In(m) => m.interface().map(str::to_owned),
    };
    leak_opt(s)
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_member(message: *mut DBusMessage) -> *const c_char {
    let Some(h) = handle(message) else { return std::ptr::null() };
    let s = match &*h.inner.lock().unwrap() {
        Inner::Out(o) => o.member.clone(),
        Inner::In(m) => m.member().map(str::to_owned),
    };
    leak_opt(s)
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_destination(message: *mut DBusMessage) -> *const c_char {
    let Some(h) = handle(message) else { return std::ptr::null() };
    let s = match &*h.inner.lock().unwrap() {
        Inner::Out(o) => o.destination.clone(),
        Inner::In(m) => m.destination().map(str::to_owned),
    };
    leak_opt(s)
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_sender(message: *mut DBusMessage) -> *const c_char {
    let Some(h) = handle(message) else { return std::ptr::null() };
    let s = match &*h.inner.lock().unwrap() {
        Inner::Out(_) => None, // no sender until the daemon stamps one on delivery
        Inner::In(m) => m.sender().map(str::to_owned),
    };
    leak_opt(s)
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_error_name(message: *mut DBusMessage) -> *const c_char {
    let Some(h) = handle(message) else { return std::ptr::null() };
    let s = match &*h.inner.lock().unwrap() {
        Inner::Out(o) if o.kind == Kind::Error => o.member.clone(),
        Inner::Out(_) => None,
        Inner::In(m) => m.header.error_name().map(str::to_owned),
    };
    leak_opt(s)
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_path(message: *mut DBusMessage) -> *const c_char {
    let Some(h) = handle(message) else { return std::ptr::null() };
    let s = match &*h.inner.lock().unwrap() {
        Inner::Out(o) => o.path.as_ref().map(|p| p.as_str().to_owned()),
        Inner::In(m) => m.path().map(|p| p.as_str().to_owned()),
    };
    match s {
        Some(s) => CString::new(s).map(|c| c.into_raw() as *const c_char).unwrap_or(std::ptr::null()),
        None => std::ptr::null(),
    }
}

/// # Safety
/// `message` must be a valid, writable `DBusMessage*` still under
/// construction (i.e. not yet sent).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_set_destination(
    message: *mut DBusMessage,
    destination: *const c_char,
) -> c_int {
    let Some(h) = handle(message) else { return 0 };
    if let Inner::Out(o) = &mut *h.inner.lock().unwrap() {
        o.destination = unsafe { crate::cstr(destination) };
        1
    } else {
        0
    }
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_serial(message: *mut DBusMessage) -> u32 {
    let Some(h) = handle(message) else { return 0 };
    match &*h.inner.lock().unwrap() {
        Inner::Out(_) => 0,
        Inner::In(m) => m.serial(),
    }
}

/// # Safety
/// `message` must be a valid `DBusMessage*`, or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_get_reply_serial(message: *mut DBusMessage) -> u32 {
    let Some(h) = handle(message) else { return 0 };
    match &*h.inner.lock().unwrap() {
        Inner::Out(_) => 0,
        Inner::In(m) => m.reply_serial().unwrap_or(0),
    }
}

// --- DBusMessageIter --------------------------------------------------
//
// Every field is private per upstream's own "don't use this" contract, so
// only the total size/alignment of the real struct matters for ABI safety
// (callers embed it on the stack and pass `&mut DBusMessageIter` around,
// but never read a field directly). 72 bytes / 8-byte alignment matches
// the real struct on LP64 (x86_64/aarch64) targets.
#[repr(C, align(8))]
pub struct DBusMessageIter {
    _opaque: [u8; 72],
    // Fields below aren't part of the ABI-visible region above; we stash
    // our own state past byte 72, which is safe because callers never
    // read/write this struct's bytes themselves — only pass its address
    // to our own iterator functions.
    msg: *mut DBusMessage,
    appending: bool,
    read_pos: usize,
}

impl Default for DBusMessageIter {
    fn default() -> Self {
        DBusMessageIter {
            _opaque: [0; 72],
            msg: std::ptr::null_mut(),
            appending: false,
            read_pos: 0,
        }
    }
}

/// # Safety
/// `message` must be a valid, writable `DBusMessage*` still under
/// construction; `iter` must point to valid, writable memory at least the
/// size of `DBusMessageIter`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_iter_init_append(
    message: *mut DBusMessage,
    iter: *mut DBusMessageIter,
) {
    if iter.is_null() {
        return;
    }
    unsafe {
        *iter = DBusMessageIter {
            msg: message,
            appending: true,
            ..Default::default()
        };
    }
}

/// # Safety
/// `message` must be a valid `DBusMessage*`; `iter` must point to valid,
/// writable memory at least the size of `DBusMessageIter`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_iter_init(
    message: *mut DBusMessage,
    iter: *mut DBusMessageIter,
) -> c_int {
    if iter.is_null() {
        return 0;
    }
    let has_args = handle(message)
        .map(|h| match &*h.inner.lock().unwrap() {
            Inner::Out(o) => !o.args.is_empty(),
            Inner::In(m) => !m.body.is_empty(),
        })
        .unwrap_or(false);
    unsafe {
        *iter = DBusMessageIter {
            msg: message,
            appending: false,
            ..Default::default()
        };
    }
    has_args as c_int
}

fn value_type_code(v: &Value) -> c_int {
    match v {
        Value::Byte(_) => TYPE_BYTE,
        Value::Boolean(_) => TYPE_BOOLEAN,
        Value::Int16(_) => TYPE_INT16,
        Value::UInt16(_) => TYPE_UINT16,
        Value::Int32(_) => TYPE_INT32,
        Value::UInt32(_) => TYPE_UINT32,
        Value::Int64(_) => TYPE_INT64,
        Value::UInt64(_) => TYPE_UINT64,
        Value::Double(_) => TYPE_DOUBLE,
        Value::String(_) => TYPE_STRING,
        Value::ObjectPath(_) => TYPE_OBJECT_PATH,
        _ => TYPE_INVALID, // containers/variant/signature/fd: not in MVP scope
    }
}

/// # Safety
/// `iter` must have been initialized by `dbus_message_iter_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_iter_get_arg_type(iter: *mut DBusMessageIter) -> c_int {
    if iter.is_null() {
        return TYPE_INVALID;
    }
    let it = unsafe { &*iter };
    let Some(h) = handle(it.msg) else { return TYPE_INVALID };
    let body_len = match &*h.inner.lock().unwrap() {
        Inner::Out(o) => o.args.len(),
        Inner::In(m) => m.body.len(),
    };
    if it.read_pos >= body_len {
        return TYPE_INVALID;
    }
    match &*h.inner.lock().unwrap() {
        Inner::Out(o) => value_type_code(&o.args[it.read_pos]),
        Inner::In(m) => value_type_code(&m.body[it.read_pos]),
    }
}

/// # Safety
/// `iter` must have been initialized by `dbus_message_iter_init`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_iter_next(iter: *mut DBusMessageIter) -> c_int {
    if iter.is_null() {
        return 0;
    }
    let it = unsafe { &mut *iter };
    it.read_pos += 1;
    (unsafe { dbus_message_iter_get_arg_type(iter) } != TYPE_INVALID) as c_int
}

/// # Safety
/// `iter` must have been initialized by `dbus_message_iter_init`; `value`
/// must point to storage big enough for the current arg's basic type
/// (matching upstream's own documented contract for this function).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_iter_get_basic(iter: *mut DBusMessageIter, value: *mut c_void) {
    if iter.is_null() || value.is_null() {
        return;
    }
    let it = unsafe { &*iter };
    let Some(h) = handle(it.msg) else { return };
    let guard = h.inner.lock().unwrap();
    let v = match &*guard {
        Inner::Out(o) => o.args.get(it.read_pos),
        Inner::In(m) => m.body.get(it.read_pos),
    };
    let Some(v) = v else { return };
    unsafe {
        match v {
            Value::Byte(b) => *(value as *mut u8) = *b,
            Value::Boolean(b) => *(value as *mut c_int) = *b as c_int,
            Value::Int16(n) => *(value as *mut i16) = *n,
            Value::UInt16(n) => *(value as *mut u16) = *n,
            Value::Int32(n) => *(value as *mut i32) = *n,
            Value::UInt32(n) => *(value as *mut u32) = *n,
            Value::Int64(n) => *(value as *mut i64) = *n,
            Value::UInt64(n) => *(value as *mut u64) = *n,
            Value::Double(d) => *(value as *mut f64) = *d,
            Value::String(s) => {
                // Points into a string we leak for the lifetime of the
                // message, same ownership contract as real libdbus (the
                // pointer is valid until the message is freed).
                let leaked = CString::new(s.clone()).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut());
                *(value as *mut *const c_char) = leaked;
            }
            Value::ObjectPath(p) => {
                let leaked = CString::new(p.as_str()).map(|c| c.into_raw()).unwrap_or(std::ptr::null_mut());
                *(value as *mut *const c_char) = leaked;
            }
            _ => {}
        }
    }
}

/// # Safety
/// `iter` must have been initialized by `dbus_message_iter_init_append`;
/// `value` must point to a valid value of the type named by `dbus_type`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dbus_message_iter_append_basic(
    iter: *mut DBusMessageIter,
    dbus_type: c_int,
    value: *const c_void,
) -> c_int {
    if iter.is_null() || value.is_null() {
        return 0;
    }
    let it = unsafe { &*iter };
    if !it.appending {
        return 0;
    }
    let v = unsafe {
        match dbus_type {
            TYPE_BYTE => Value::Byte(*(value as *const u8)),
            TYPE_BOOLEAN => Value::Boolean(*(value as *const c_int) != 0),
            TYPE_INT16 => Value::Int16(*(value as *const i16)),
            TYPE_UINT16 => Value::UInt16(*(value as *const u16)),
            TYPE_INT32 => Value::Int32(*(value as *const i32)),
            TYPE_UINT32 => Value::UInt32(*(value as *const u32)),
            TYPE_INT64 => Value::Int64(*(value as *const i64)),
            TYPE_UINT64 => Value::UInt64(*(value as *const u64)),
            TYPE_DOUBLE => Value::Double(*(value as *const f64)),
            TYPE_STRING => {
                let Some(s) = crate::cstr(*(value as *const *const c_char)) else {
                    return 0;
                };
                Value::String(s)
            }
            TYPE_OBJECT_PATH => {
                let Some(s) = crate::cstr(*(value as *const *const c_char)) else {
                    return 0;
                };
                let Ok(p) = ObjectPath::new(s) else { return 0 };
                Value::ObjectPath(p)
            }
            _ => return 0, // container/variant/signature/fd: not in MVP scope
        }
    };
    let Some(h) = handle(it.msg) else { return 0 };
    if let Inner::Out(o) = &mut *h.inner.lock().unwrap() {
        o.args.push(v);
        1
    } else {
        0
    }
}

pub(crate) fn take_outgoing(msg: *mut DBusMessage) -> Option<Outgoing> {
    let h = handle(msg)?;
    let mut guard = h.inner.lock().unwrap();
    match &mut *guard {
        Inner::Out(o) => Some(Outgoing {
            kind: o.kind,
            path: o.path.take(),
            interface: o.interface.take(),
            member: o.member.take(),
            destination: o.destination.take(),
            reply_serial: o.reply_serial.take(),
            args: std::mem::take(&mut o.args),
        }),
        Inner::In(_) => None,
    }
}

/// Placeholder D-Bus type import so `Type` stays a used symbol if this
/// module grows richer container support later.
#[allow(dead_code)]
fn _keep_type_import(_t: Type) {}
