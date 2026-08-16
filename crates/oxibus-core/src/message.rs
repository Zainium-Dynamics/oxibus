//! A complete D-Bus message: header + body, plus out-of-band unix fds.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{CoreError, CoreResult};
use crate::header::{flags, HeaderField, MessageHeader, MessageType};
use crate::marshal::Marshaler;
use crate::types::{ObjectPath, Signature, Value};

/// Per-connection monotonic serial allocator. D-Bus serials are non-zero
/// u32s; 0 is reserved to mean "no reply expected / not yet sent".
#[derive(Debug)]
pub struct SerialGenerator(AtomicU32);

impl SerialGenerator {
    /// Create a generator whose first call to [`next`](Self::next) returns 1.
    pub fn new() -> Self {
        Self(AtomicU32::new(1))
    }

    /// Atomically allocate the next serial number, wrapping past 0 (which is
    /// reserved) back to 1.
    pub fn next(&self) -> u32 {
        loop {
            let v = self.0.fetch_add(1, Ordering::Relaxed);
            if v != 0 {
                return v;
            }
            // wrapped through 0 — skip it, try again
        }
    }
}

impl Default for SerialGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// A complete D-Bus message: decoded header, decoded body values, and any
/// file descriptors that travel alongside it out-of-band.
#[derive(Debug, Clone)]
pub struct Message {
    /// The message's header (type, flags, serial, path/interface/member/etc fields).
    pub header: MessageHeader,
    /// The decoded body arguments, one `Value` per top-level type in the body signature.
    pub body: Vec<Value>,
    /// File descriptors referenced by `UnixFd` values in the body, transferred via SCM_RIGHTS.
    pub fds: Vec<RawFd>,
}

impl Message {
    /// The kind of message (method call, method return, error, or signal).
    pub fn message_type(&self) -> MessageType {
        self.header.message_type
    }
    /// The message's serial number, unique per sending connection.
    pub fn serial(&self) -> u32 {
        self.header.serial
    }
    /// The object path this message targets or was sent from, if present.
    pub fn path(&self) -> Option<&ObjectPath> {
        self.header.path()
    }
    /// The interface the member belongs to, if present.
    pub fn interface(&self) -> Option<&str> {
        self.header.interface()
    }
    /// The method or signal name, if present.
    pub fn member(&self) -> Option<&str> {
        self.header.member()
    }
    /// The unique or well-known name of the intended recipient, if present.
    pub fn destination(&self) -> Option<&str> {
        self.header.destination()
    }
    /// The unique name of the sending connection, if present (set by the bus).
    pub fn sender(&self) -> Option<&str> {
        self.header.sender()
    }
    /// The serial of the message this one replies to, if present.
    pub fn reply_serial(&self) -> Option<u32> {
        self.header.reply_serial()
    }
    /// Whether the `NO_REPLY_EXPECTED` flag is set.
    pub fn no_reply_expected(&self) -> bool {
        self.header.flags & flags::NO_REPLY_EXPECTED != 0
    }
    /// Whether the `NO_AUTO_START` flag is set.
    pub fn no_auto_start(&self) -> bool {
        self.header.flags & flags::NO_AUTO_START != 0
    }

    /// Set (or replace) the `SENDER` header field.
    pub fn set_sender(&mut self, sender: impl Into<String>) {
        self.header.set_sender(sender.into());
    }

    /// Serialize to wire bytes. `fds.len()` is written into the UNIX_FDS
    /// header field automatically if non-empty.
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        let (body_bytes, sig) = crate::marshal::marshal_body(&self.body, self.header.big_endian)?;

        let mut header = self.header.clone();
        header.body_length = body_bytes.len() as u32;
        header
            .fields
            .retain(|f| !matches!(f, HeaderField::Signature(_) | HeaderField::UnixFds(_)));
        if !sig.is_empty() {
            header.fields.push(HeaderField::Signature(Signature::new(sig)?));
        }
        if !self.fds.is_empty() {
            header.fields.push(HeaderField::UnixFds(self.fds.len() as u32));
        }
        header.validate()?;

        let mut m = Marshaler::new(header.big_endian);
        header.write(&mut m)?;
        m.buf.extend_from_slice(&body_bytes);
        Ok(m.into_bytes())
    }

    /// Given a complete frame (as sized by [`MessageHeader::peek_frame_len`]),
    /// parse header + body. `fds` are the unix fds that arrived out-of-band
    /// alongside this frame (via SCM_RIGHTS), supplied by the transport.
    pub fn from_bytes(buf: &[u8], fds: Vec<RawFd>) -> CoreResult<Message> {
        let (header, body_offset) = MessageHeader::read(buf)?;
        let body_buf = &buf[body_offset..body_offset + header.body_length as usize];
        let sig = header.signature().to_string();
        let body = if sig.is_empty() {
            Vec::new()
        } else {
            crate::unmarshal::unmarshal_body(body_buf, &sig, header.big_endian)?
        };

        let declared_fds = header.unix_fds() as usize;
        if fds.len() < declared_fds {
            return Err(CoreError::FdIndexOutOfRange(declared_fds as u32, fds.len()));
        }

        Ok(Message { header, body, fds })
    }
}

/// Builder for constructing outgoing messages. Endianness defaults to the
/// host's native order (little-endian on every Zainium target).
pub struct MessageBuilder {
    message_type: MessageType,
    flags: u8,
    fields: Vec<HeaderField>,
    body: Vec<Value>,
    fds: Vec<RawFd>,
    big_endian: bool,
}

impl MessageBuilder {
    fn new(message_type: MessageType) -> Self {
        Self {
            message_type,
            flags: 0,
            fields: Vec::new(),
            body: Vec::new(),
            fds: Vec::new(),
            big_endian: cfg!(target_endian = "big"),
        }
    }

    /// Start building a `METHOD_CALL` to the given object path and member name.
    pub fn method_call(path: ObjectPath, member: impl Into<String>) -> Self {
        let mut b = Self::new(MessageType::MethodCall);
        b.fields.push(HeaderField::Path(path));
        b.fields.push(HeaderField::Member(member.into()));
        b
    }

    /// Start building a `SIGNAL` with the given path, interface and member name.
    pub fn signal(path: ObjectPath, interface: impl Into<String>, member: impl Into<String>) -> Self {
        let mut b = Self::new(MessageType::Signal);
        b.fields.push(HeaderField::Path(path));
        b.fields.push(HeaderField::Interface(interface.into()));
        b.fields.push(HeaderField::Member(member.into()));
        b
    }

    /// Start building a `METHOD_RETURN` replying to the call with serial `reply_to_serial`.
    pub fn method_return(reply_to_serial: u32) -> Self {
        let mut b = Self::new(MessageType::MethodReturn);
        b.fields.push(HeaderField::ReplySerial(reply_to_serial));
        b
    }

    /// Start building an `ERROR` reply to the call with serial `reply_to_serial`,
    /// carrying the given D-Bus error name (e.g. `org.freedesktop.DBus.Error.Failed`).
    pub fn error(
        reply_to_serial: u32,
        error_name: impl Into<String>,
    ) -> Self {
        let mut b = Self::new(MessageType::Error);
        b.fields.push(HeaderField::ReplySerial(reply_to_serial));
        b.fields.push(HeaderField::ErrorName(error_name.into()));
        b
    }

    /// Set the `INTERFACE` header field.
    pub fn interface(mut self, iface: impl Into<String>) -> Self {
        self.fields.push(HeaderField::Interface(iface.into()));
        self
    }
    /// Set the `DESTINATION` header field.
    pub fn destination(mut self, dest: impl Into<String>) -> Self {
        self.fields.push(HeaderField::Destination(dest.into()));
        self
    }
    /// Set the `SENDER` header field.
    pub fn sender(mut self, sender: impl Into<String>) -> Self {
        self.fields.push(HeaderField::Sender(sender.into()));
        self
    }
    /// Set the `NO_REPLY_EXPECTED` flag.
    pub fn no_reply_expected(mut self) -> Self {
        self.flags |= flags::NO_REPLY_EXPECTED;
        self
    }
    /// Set the `NO_AUTO_START` flag.
    pub fn no_auto_start(mut self) -> Self {
        self.flags |= flags::NO_AUTO_START;
        self
    }
    /// Set the `ALLOW_INTERACTIVE_AUTHORIZATION` flag.
    pub fn allow_interactive_authorization(mut self) -> Self {
        self.flags |= flags::ALLOW_INTERACTIVE_AUTHORIZATION;
        self
    }
    /// Append a single argument to the message body.
    pub fn arg(mut self, v: Value) -> Self {
        self.body.push(v);
        self
    }
    /// Append multiple arguments to the message body.
    pub fn args(mut self, vs: Vec<Value>) -> Self {
        self.body.extend(vs);
        self
    }
    /// Append a file descriptor to be sent out-of-band alongside the message.
    pub fn fd(mut self, fd: RawFd) -> Self {
        self.fds.push(fd);
        self
    }

    /// Finish building, assigning `serial` as the message's serial number.
    /// The header's `body_length` is left at 0 here and filled in later by
    /// [`Message::to_bytes`] once the body is actually marshaled.
    pub fn build(self, serial: u32) -> Message {
        let header = MessageHeader {
            big_endian: self.big_endian,
            message_type: self.message_type,
            flags: self.flags,
            protocol_version: crate::header::PROTOCOL_VERSION,
            body_length: 0, // filled in by to_bytes()
            serial,
            fields: self.fields,
        };
        Message {
            header,
            body: self.body,
            fds: self.fds,
        }
    }
}

/// Build a `METHOD_RETURN`/`ERROR` in reply to an incoming call, copying the
/// DESTINATION from the caller's SENDER as required by the spec.
pub fn reply_to(call: &Message, error_name: Option<&str>) -> MessageBuilder {
    let mut b = match error_name {
        None => MessageBuilder::method_return(call.serial()),
        Some(name) => MessageBuilder::error(call.serial(), name.to_string()),
    };
    if let Some(sender) = call.sender() {
        b = b.destination(sender.to_string());
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_call_roundtrip_through_bytes() {
        let serial = SerialGenerator::new();
        let msg = MessageBuilder::method_call(
            ObjectPath::new("/org/freedesktop/DBus").unwrap(),
            "Hello",
        )
        .interface("org.freedesktop.DBus")
        .destination("org.freedesktop.DBus")
        .build(serial.next());

        let bytes = msg.to_bytes().unwrap();
        let frame_len = MessageHeader::peek_frame_len(&bytes).unwrap().unwrap();
        assert_eq!(frame_len, bytes.len());

        let parsed = Message::from_bytes(&bytes, Vec::new()).unwrap();
        assert_eq!(parsed.member(), Some("Hello"));
        assert_eq!(parsed.destination(), Some("org.freedesktop.DBus"));
    }

    #[test]
    fn method_call_with_body_roundtrips() {
        let serial = SerialGenerator::new();
        let msg = MessageBuilder::method_call(
            ObjectPath::new("/org/freedesktop/DBus").unwrap(),
            "RequestName",
        )
        .interface("org.freedesktop.DBus")
        .arg(Value::string("com.example.Foo"))
        .arg(Value::UInt32(4))
        .build(serial.next());

        let bytes = msg.to_bytes().unwrap();
        let parsed = Message::from_bytes(&bytes, Vec::new()).unwrap();
        assert_eq!(parsed.body.len(), 2);
        assert_eq!(parsed.body[0], Value::String("com.example.Foo".into()));
        assert_eq!(parsed.body[1], Value::UInt32(4));
    }

    #[test]
    fn serial_generator_skips_zero_and_increments() {
        let g = SerialGenerator::new();
        assert_eq!(g.next(), 1);
        assert_eq!(g.next(), 2);
    }

    #[test]
    fn reply_to_sets_destination_from_sender() {
        let serial = SerialGenerator::new();
        let mut call = MessageBuilder::method_call(
            ObjectPath::new("/").unwrap(),
            "Ping",
        )
        .build(serial.next());
        call.set_sender(":1.5");

        let reply = reply_to(&call, None).build(serial.next());
        assert_eq!(reply.destination(), Some(":1.5"));
        assert_eq!(reply.reply_serial(), Some(call.serial()));
    }
}
