// D-Bus message header encoding and decoding.

use crate::error::{CoreError, CoreResult};
use crate::marshal::Marshaler;
use crate::types::{ArrayValue, ObjectPath, Signature, Type, Value};
use crate::unmarshal::Unmarshaler;

pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    MethodCall = 1,
    MethodReturn = 2,
    Error = 3,
    Signal = 4,
}

impl MessageType {
    pub fn from_u8(v: u8) -> CoreResult<Self> {
        Ok(match v {
            1 => MessageType::MethodCall,
            2 => MessageType::MethodReturn,
            3 => MessageType::Error,
            4 => MessageType::Signal,
            other => {
                return Err(CoreError::InvalidSignature(
                    other.to_string(),
                    "unknown message type",
                ));
            }
        })
    }
}

pub mod flags {
    pub const NO_REPLY_EXPECTED: u8 = 0x1;
    pub const NO_AUTO_START: u8 = 0x2;
    pub const ALLOW_INTERACTIVE_AUTHORIZATION: u8 = 0x4;
}

#[derive(Debug, Clone, PartialEq)]
pub enum HeaderField {
    Path(ObjectPath),
    Interface(String),
    Member(String),
    ErrorName(String),
    ReplySerial(u32),
    Destination(String),
    Sender(String),
    Signature(Signature),
    UnixFds(u32),
}

impl HeaderField {
    fn code(&self) -> u8 {
        match self {
            HeaderField::Path(_) => 1,
            HeaderField::Interface(_) => 2,
            HeaderField::Member(_) => 3,
            HeaderField::ErrorName(_) => 4,
            HeaderField::ReplySerial(_) => 5,
            HeaderField::Destination(_) => 6,
            HeaderField::Sender(_) => 7,
            HeaderField::Signature(_) => 8,
            HeaderField::UnixFds(_) => 9,
        }
    }

    fn to_value(&self) -> Value {
        match self {
            HeaderField::Path(p) => Value::ObjectPath(p.clone()),
            HeaderField::Interface(s) | HeaderField::Member(s) | HeaderField::ErrorName(s) => {
                Value::String(s.clone())
            }
            HeaderField::ReplySerial(v) | HeaderField::UnixFds(v) => Value::UInt32(*v),
            HeaderField::Destination(s) | HeaderField::Sender(s) => Value::String(s.clone()),
            HeaderField::Signature(sig) => Value::Signature(sig.clone()),
        }
    }

    fn from_code_and_value(code: u8, value: Value) -> CoreResult<Option<HeaderField>> {
        let field = match code {
            1 => HeaderField::Path(match value {
                Value::ObjectPath(p) => p,
                _ => return Err(bad_field("PATH")),
            }),
            2 => HeaderField::Interface(expect_string(value, "INTERFACE")?),
            3 => HeaderField::Member(expect_string(value, "MEMBER")?),
            4 => HeaderField::ErrorName(expect_string(value, "ERROR_NAME")?),
            5 => HeaderField::ReplySerial(match value {
                Value::UInt32(v) => v,
                _ => return Err(bad_field("REPLY_SERIAL")),
            }),
            6 => HeaderField::Destination(expect_string(value, "DESTINATION")?),
            7 => HeaderField::Sender(expect_string(value, "SENDER")?),
            8 => HeaderField::Signature(match value {
                Value::Signature(s) => s,
                _ => return Err(bad_field("SIGNATURE")),
            }),
            9 => HeaderField::UnixFds(match value {
                Value::UInt32(v) => v,
                _ => return Err(bad_field("UNIX_FDS")),
            }),
            _ => return Ok(None),
        };
        Ok(Some(field))
    }
}

fn expect_string(v: Value, field: &'static str) -> CoreResult<String> {
    match v {
        Value::String(s) => Ok(s),
        Value::ObjectPath(p) => Ok(p.into_string()),
        _ => Err(bad_field(field)),
    }
}

fn bad_field(name: &'static str) -> CoreError {
    CoreError::TypeMismatch {
        expected: format!("header field {name} has wrong variant type"),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageHeader {
    pub big_endian: bool,
    pub message_type: MessageType,
    pub flags: u8,
    pub protocol_version: u8,
    pub body_length: u32,
    pub serial: u32,
    pub fields: Vec<HeaderField>,
}

impl MessageHeader {
    pub fn field(&self, code: u8) -> Option<&HeaderField> {
        self.fields.iter().find(|f| f.code() == code)
    }

    pub fn path(&self) -> Option<&ObjectPath> {
        self.fields.iter().find_map(|f| match f {
            HeaderField::Path(p) => Some(p),
            _ => None,
        })
    }
    pub fn interface(&self) -> Option<&str> {
        self.fields.iter().find_map(|f| match f {
            HeaderField::Interface(s) => Some(s.as_str()),
            _ => None,
        })
    }
    pub fn member(&self) -> Option<&str> {
        self.fields.iter().find_map(|f| match f {
            HeaderField::Member(s) => Some(s.as_str()),
            _ => None,
        })
    }
    pub fn error_name(&self) -> Option<&str> {
        self.fields.iter().find_map(|f| match f {
            HeaderField::ErrorName(s) => Some(s.as_str()),
            _ => None,
        })
    }
    pub fn reply_serial(&self) -> Option<u32> {
        self.fields.iter().find_map(|f| match f {
            HeaderField::ReplySerial(v) => Some(*v),
            _ => None,
        })
    }
    pub fn destination(&self) -> Option<&str> {
        self.fields.iter().find_map(|f| match f {
            HeaderField::Destination(s) => Some(s.as_str()),
            _ => None,
        })
    }
    pub fn sender(&self) -> Option<&str> {
        self.fields.iter().find_map(|f| match f {
            HeaderField::Sender(s) => Some(s.as_str()),
            _ => None,
        })
    }
    pub fn signature(&self) -> &str {
        self.fields
            .iter()
            .find_map(|f| match f {
                HeaderField::Signature(s) => Some(s.as_str()),
                _ => None,
            })
            .unwrap_or("")
    }
    pub fn unix_fds(&self) -> u32 {
        self.fields
            .iter()
            .find_map(|f| match f {
                HeaderField::UnixFds(v) => Some(*v),
                _ => None,
            })
            .unwrap_or(0)
    }

    pub fn set_sender(&mut self, sender: String) {
        self.fields.retain(|f| !matches!(f, HeaderField::Sender(_)));
        self.fields.push(HeaderField::Sender(sender));
    }

    pub fn validate(&self) -> CoreResult<()> {
        match self.message_type {
            MessageType::MethodCall => {
                if self.path().is_none() {
                    return Err(CoreError::MissingHeaderField("PATH"));
                }
                if self.member().is_none() {
                    return Err(CoreError::MissingHeaderField("MEMBER"));
                }
            }
            MessageType::Signal => {
                if self.path().is_none() {
                    return Err(CoreError::MissingHeaderField("PATH"));
                }
                if self.interface().is_none() {
                    return Err(CoreError::MissingHeaderField("INTERFACE"));
                }
                if self.member().is_none() {
                    return Err(CoreError::MissingHeaderField("MEMBER"));
                }
            }
            MessageType::Error => {
                if self.error_name().is_none() {
                    return Err(CoreError::MissingHeaderField("ERROR_NAME"));
                }
                if self.reply_serial().is_none() {
                    return Err(CoreError::MissingHeaderField("REPLY_SERIAL"));
                }
            }
            MessageType::MethodReturn => {
                if self.reply_serial().is_none() {
                    return Err(CoreError::MissingHeaderField("REPLY_SERIAL"));
                }
            }
        }
        Ok(())
    }

    pub fn write(&self, m: &mut Marshaler) -> CoreResult<()> {
        m.write_u8(if self.big_endian { b'B' } else { b'l' });
        m.write_u8(self.message_type as u8);
        m.write_u8(self.flags);
        m.write_u8(self.protocol_version);
        m.write_u32(self.body_length);
        m.write_u32(self.serial);

        let elements: Vec<Value> = self
            .fields
            .iter()
            .map(|f| {
                Value::Struct(vec![
                    Value::Byte(f.code()),
                    Value::Variant(Box::new(f.to_value())),
                ])
            })
            .collect();
        let arr = ArrayValue::new(Type::Struct(vec![Type::Byte, Type::Variant]), elements);
        m.write_value(&Value::Array(arr))?;
        m.align(8);
        Ok(())
    }

    fn read_prefix(buf: &[u8]) -> CoreResult<(bool, MessageType, u8, u8, u32, u32, u32)> {
        if buf.len() < 16 {
            return Err(CoreError::UnexpectedEof {
                needed: 16,
                have: buf.len(),
            });
        }
        let big_endian = match buf[0] {
            b'l' => false,
            b'B' => true,
            other => return Err(CoreError::BadByteOrder(other)),
        };
        let message_type = MessageType::from_u8(buf[1])?;
        let msg_flags = buf[2];
        let protocol_version = buf[3];
        if protocol_version != PROTOCOL_VERSION {
            return Err(CoreError::BadProtocolVersion(protocol_version));
        }
        let mut u = Unmarshaler::new(&buf[4..], big_endian);
        let body_length = u.read_u32()?;
        let serial = u.read_u32()?;
        let fields_array_len = u.read_u32()?;
        Ok((
            big_endian,
            message_type,
            msg_flags,
            protocol_version,
            body_length,
            serial,
            fields_array_len,
        ))
    }

    pub fn peek_frame_len(buf: &[u8]) -> CoreResult<Option<usize>> {
        if buf.len() < 16 {
            return Ok(None);
        }
        let (_, _, _, _, body_length, _, fields_array_len) = Self::read_prefix(buf)?;
        let header_len_before_pad = 16 + fields_array_len as usize;
        let header_len = header_len_before_pad.div_ceil(8) * 8;
        Ok(Some(header_len + body_length as usize))
    }

    pub fn read(buf: &[u8]) -> CoreResult<(MessageHeader, usize)> {
        let (big_endian, message_type, msg_flags, protocol_version, body_length, serial, _) =
            Self::read_prefix(buf)?;

        let mut u = Unmarshaler::new(buf, big_endian);
        u.pos = 4;
        let _body_length_dup = u.read_u32()?;
        let _serial_dup = u.read_u32()?;
        let fields_array_ty = Type::Array(Box::new(Type::Struct(vec![Type::Byte, Type::Variant])));
        let fields_value = u.read_value(&fields_array_ty)?;

        let mut fields = Vec::new();
        if let Value::Array(arr) = fields_value {
            for el in arr.elements {
                if let Value::Struct(mut pair) = el {
                    if pair.len() != 2 {
                        continue;
                    }
                    let variant = pair.pop().unwrap();
                    let code_val = pair.pop().unwrap();
                    let code = match code_val {
                        Value::Byte(b) => b,
                        _ => continue,
                    };
                    let inner = match variant {
                        Value::Variant(v) => *v,
                        other => other,
                    };
                    if let Some(hf) = HeaderField::from_code_and_value(code, inner)? {
                        fields.push(hf);
                    }
                }
            }
        }
        u.align(8)?;

        let header = MessageHeader {
            big_endian,
            message_type,
            flags: msg_flags,
            protocol_version,
            body_length,
            serial,
            fields,
        };
        Ok((header, u.pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let header = MessageHeader {
            big_endian: false,
            message_type: MessageType::MethodCall,
            flags: 0,
            protocol_version: PROTOCOL_VERSION,
            body_length: 0,
            serial: 5,
            fields: vec![
                HeaderField::Path(ObjectPath::new("/org/freedesktop/DBus").unwrap()),
                HeaderField::Interface("org.freedesktop.DBus".into()),
                HeaderField::Member("Hello".into()),
                HeaderField::Destination("org.freedesktop.DBus".into()),
            ],
        };
        let mut m = Marshaler::new(false);
        header.write(&mut m).unwrap();
        let bytes = m.into_bytes();
        assert_eq!(bytes.len() % 8, 0);

        let (parsed, body_offset) = MessageHeader::read(&bytes).unwrap();
        assert_eq!(body_offset, bytes.len());
        assert_eq!(parsed.serial, 5);
        assert_eq!(parsed.member(), Some("Hello"));
        assert_eq!(parsed.path().unwrap().as_str(), "/org/freedesktop/DBus");
        parsed.validate().unwrap();
    }

    #[test]
    fn peek_frame_len_needs_16_bytes() {
        assert_eq!(MessageHeader::peek_frame_len(&[1, 2, 3]).unwrap(), None);
    }
}
