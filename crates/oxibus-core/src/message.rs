// Message construction, serialization, and deserialization.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{CoreError, CoreResult};
use crate::header::{flags, HeaderField, MessageHeader, MessageType};
use crate::marshal::Marshaler;
use crate::types::{ObjectPath, Signature, Value};

#[derive(Debug)]
pub struct SerialGenerator(AtomicU32);

impl SerialGenerator {
    pub fn new() -> Self {
        Self(AtomicU32::new(1))
    }

    pub fn next(&self) -> u32 {
        loop {
            let v = self.0.fetch_add(1, Ordering::Relaxed);
            if v != 0 {
                return v;
            }
        }
    }
}

impl Default for SerialGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub header: MessageHeader,
    pub body: Vec<Value>,
    pub fds: Vec<RawFd>,
}

impl Message {
    pub fn message_type(&self) -> MessageType {
        self.header.message_type
    }
    pub fn serial(&self) -> u32 {
        self.header.serial
    }
    pub fn path(&self) -> Option<&ObjectPath> {
        self.header.path()
    }
    pub fn interface(&self) -> Option<&str> {
        self.header.interface()
    }
    pub fn member(&self) -> Option<&str> {
        self.header.member()
    }
    pub fn destination(&self) -> Option<&str> {
        self.header.destination()
    }
    pub fn sender(&self) -> Option<&str> {
        self.header.sender()
    }
    pub fn reply_serial(&self) -> Option<u32> {
        self.header.reply_serial()
    }
    pub fn no_reply_expected(&self) -> bool {
        self.header.flags & flags::NO_REPLY_EXPECTED != 0
    }
    pub fn no_auto_start(&self) -> bool {
        self.header.flags & flags::NO_AUTO_START != 0
    }

    pub fn set_sender(&mut self, sender: impl Into<String>) {
        self.header.set_sender(sender.into());
    }

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

    pub fn method_call(path: ObjectPath, member: impl Into<String>) -> Self {
        let mut b = Self::new(MessageType::MethodCall);
        b.fields.push(HeaderField::Path(path));
        b.fields.push(HeaderField::Member(member.into()));
        b
    }

    pub fn signal(path: ObjectPath, interface: impl Into<String>, member: impl Into<String>) -> Self {
        let mut b = Self::new(MessageType::Signal);
        b.fields.push(HeaderField::Path(path));
        b.fields.push(HeaderField::Interface(interface.into()));
        b.fields.push(HeaderField::Member(member.into()));
        b
    }

    pub fn method_return(reply_to_serial: u32) -> Self {
        let mut b = Self::new(MessageType::MethodReturn);
        b.fields.push(HeaderField::ReplySerial(reply_to_serial));
        b
    }

    pub fn error(
        reply_to_serial: u32,
        error_name: impl Into<String>,
    ) -> Self {
        let mut b = Self::new(MessageType::Error);
        b.fields.push(HeaderField::ReplySerial(reply_to_serial));
        b.fields.push(HeaderField::ErrorName(error_name.into()));
        b
    }

    pub fn interface(mut self, iface: impl Into<String>) -> Self {
        self.fields.push(HeaderField::Interface(iface.into()));
        self
    }

    pub fn destination(mut self, dest: impl Into<String>) -> Self {
        self.fields.push(HeaderField::Destination(dest.into()));
        self
    }

    pub fn sender(mut self, sender: impl Into<String>) -> Self {
        self.fields.push(HeaderField::Sender(sender.into()));
        self
    }

    pub fn no_reply_expected(mut self) -> Self {
        self.flags |= flags::NO_REPLY_EXPECTED;
        self
    }

    pub fn no_auto_start(mut self) -> Self {
        self.flags |= flags::NO_AUTO_START;
        self
    }

    pub fn allow_interactive_authorization(mut self) -> Self {
        self.flags |= flags::ALLOW_INTERACTIVE_AUTHORIZATION;
        self
    }

    pub fn arg(mut self, v: Value) -> Self {
        self.body.push(v);
        self
    }

    pub fn args(mut self, vs: Vec<Value>) -> Self {
        self.body.extend(vs);
        self
    }

    pub fn fd(mut self, fd: RawFd) -> Self {
        self.fds.push(fd);
        self
    }

    pub fn build(self, serial: u32) -> Message {
        let header = MessageHeader {
            big_endian: self.big_endian,
            message_type: self.message_type,
            flags: self.flags,
            protocol_version: crate::header::PROTOCOL_VERSION,
            body_length: 0,
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
