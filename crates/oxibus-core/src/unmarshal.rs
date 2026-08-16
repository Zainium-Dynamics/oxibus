//! Decoding [`Value`]s from the D-Bus wire format.

use crate::error::{CoreError, CoreResult};
use crate::types::{is_valid_object_path, ArrayValue, ObjectPath, Signature, Type, Value, MAX_ARRAY_LEN};

/// Decoder for D-Bus wire-marshaled values.
pub struct Unmarshaler<'a> {
    /// The buffer of marshaled bytes to read from.
    pub buf: &'a [u8],
    /// The current byte offset/position inside the buffer.
    pub pos: usize,
    /// Whether the wire representation is big-endian (true) or little-endian (false).
    pub big_endian: bool,
}

impl<'a> Unmarshaler<'a> {
    /// Creates a new `Unmarshaler` for the given buffer and endianness.
    pub fn new(buf: &'a [u8], big_endian: bool) -> Self {
        Self {
            buf,
            pos: 0,
            big_endian,
        }
    }

    fn need(&self, n: usize) -> CoreResult<()> {
        if self.pos + n > self.buf.len() {
            Err(CoreError::UnexpectedEof {
                needed: n,
                have: self.buf.len().saturating_sub(self.pos),
            })
        } else {
            Ok(())
        }
    }

    /// Aligns the current buffer position to a multiple of `n` bytes.
    pub fn align(&mut self, n: usize) -> CoreResult<()> {
        let rem = self.pos % n;
        if rem != 0 {
            let pad = n - rem;
            self.need(pad)?;
            // Padding bytes must be zero per spec; we don't hard-fail on
            // violations (some peers are sloppy) but we do skip them.
            self.pos += pad;
        }
        Ok(())
    }

    /// Reads a single byte from the buffer.
    pub fn read_u8(&mut self) -> CoreResult<u8> {
        self.need(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Reads an aligned unsigned 16-bit integer.
    pub fn read_u16(&mut self) -> CoreResult<u16> {
        self.align(2)?;
        self.need(2)?;
        let bytes = [self.buf[self.pos], self.buf[self.pos + 1]];
        self.pos += 2;
        Ok(if self.big_endian {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        })
    }

    /// Reads an aligned signed 16-bit integer.
    pub fn read_i16(&mut self) -> CoreResult<i16> {
        Ok(self.read_u16()? as i16)
    }

    /// Reads an aligned unsigned 32-bit integer.
    pub fn read_u32(&mut self) -> CoreResult<u32> {
        self.align(4)?;
        self.need(4)?;
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(if self.big_endian {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    /// Reads an aligned signed 32-bit integer.
    pub fn read_i32(&mut self) -> CoreResult<i32> {
        Ok(self.read_u32()? as i32)
    }

    /// Reads an aligned unsigned 64-bit integer.
    pub fn read_u64(&mut self) -> CoreResult<u64> {
        self.align(8)?;
        self.need(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(if self.big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }

    /// Reads an aligned signed 64-bit integer.
    pub fn read_i64(&mut self) -> CoreResult<i64> {
        Ok(self.read_u64()? as i64)
    }

    /// Reads an aligned double-precision floating-point number.
    pub fn read_f64(&mut self) -> CoreResult<f64> {
        Ok(f64::from_bits(self.read_u64()?))
    }

    fn read_raw_string(&mut self) -> CoreResult<String> {
        let len = self.read_u32()? as usize;
        self.need(len + 1)?;
        let bytes = &self.buf[self.pos..self.pos + len];
        let s = std::str::from_utf8(bytes)
            .map_err(|_| CoreError::InvalidUtf8)?
            .to_string();
        if self.buf[self.pos + len] != 0 {
            return Err(CoreError::InvalidSignature(s, "string not NUL-terminated"));
        }
        self.pos += len + 1;
        Ok(s)
    }

    fn read_signature_str(&mut self) -> CoreResult<String> {
        let len = self.read_u8()? as usize;
        self.need(len + 1)?;
        let bytes = &self.buf[self.pos..self.pos + len];
        let s = std::str::from_utf8(bytes)
            .map_err(|_| CoreError::InvalidUtf8)?
            .to_string();
        if self.buf[self.pos + len] != 0 {
            return Err(CoreError::InvalidSignature(
                s,
                "signature not NUL-terminated",
            ));
        }
        self.pos += len + 1;
        Ok(s)
    }

    /// Reads a single complete `Value` of the specified `Type` from the buffer.
    pub fn read_value(&mut self, ty: &Type) -> CoreResult<Value> {
        Ok(match ty {
            Type::Byte => Value::Byte(self.read_u8()?),
            Type::Boolean => {
                let raw = self.read_u32()?;
                match raw {
                    0 => Value::Boolean(false),
                    1 => Value::Boolean(true),
                    other => return Err(CoreError::InvalidBoolean(other)),
                }
            }
            Type::Int16 => Value::Int16(self.read_i16()?),
            Type::UInt16 => Value::UInt16(self.read_u16()?),
            Type::Int32 => Value::Int32(self.read_i32()?),
            Type::UInt32 => Value::UInt32(self.read_u32()?),
            Type::Int64 => Value::Int64(self.read_i64()?),
            Type::UInt64 => Value::UInt64(self.read_u64()?),
            Type::Double => Value::Double(self.read_f64()?),
            Type::String => Value::String(self.read_raw_string()?),
            Type::ObjectPath => {
                let s = self.read_raw_string()?;
                if !is_valid_object_path(&s) {
                    return Err(CoreError::InvalidObjectPath(s));
                }
                Value::ObjectPath(ObjectPath::new_unchecked(s))
            }
            Type::Signature => {
                let s = self.read_signature_str()?;
                let sig = Signature::new(s)?;
                Value::Signature(sig)
            }
            Type::UnixFd => Value::UnixFd(self.read_u32()?),
            Type::Array(elem_ty) => {
                let byte_len = self.read_u32()? as usize;
                if byte_len > MAX_ARRAY_LEN {
                    return Err(CoreError::ArrayTooLong(byte_len));
                }
                self.align(elem_ty.alignment())?;
                self.need(byte_len)?;
                let start = self.pos;
                let end = start + byte_len;
                let mut elements = Vec::new();
                while self.pos < end {
                    elements.push(self.read_value(elem_ty)?);
                }
                if self.pos != end {
                    return Err(CoreError::InvalidSignature(
                        String::new(),
                        "array element did not end on declared boundary",
                    ));
                }
                Value::Array(ArrayValue::new(elem_ty.as_ref().clone(), elements))
            }
            Type::Struct(field_types) => {
                self.align(8)?;
                let mut fields = Vec::with_capacity(field_types.len());
                for ft in field_types {
                    fields.push(self.read_value(ft)?);
                }
                Value::Struct(fields)
            }
            Type::DictEntry(k_ty, v_ty) => {
                self.align(8)?;
                let k = self.read_value(k_ty)?;
                let v = self.read_value(v_ty)?;
                Value::DictEntry(Box::new(k), Box::new(v))
            }
            Type::Variant => {
                let sig_str = self.read_signature_str()?;
                let inner_ty = crate::signature::parse_single_complete_type(&sig_str)?;
                let inner = self.read_value(&inner_ty)?;
                Value::Variant(Box::new(inner))
            }
        })
    }

    /// Reads a list of values matching the specified slice of types.
    pub fn read_values(&mut self, types: &[Type]) -> CoreResult<Vec<Value>> {
        types.iter().map(|t| self.read_value(t)).collect()
    }

    /// Returns the number of bytes remaining in the buffer.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
}

/// Convenience: unmarshal a full body given its signature string.
pub fn unmarshal_body(buf: &[u8], signature: &str, big_endian: bool) -> CoreResult<Vec<Value>> {
    let types = crate::signature::parse_signature(signature)?;
    let mut u = Unmarshaler::new(buf, big_endian);
    u.read_values(&types)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::Marshaler;

    fn roundtrip(v: &Value) -> Value {
        let mut m = Marshaler::new(false);
        m.write_value(v).unwrap();
        let bytes = m.into_bytes();
        let mut u = Unmarshaler::new(&bytes, false);
        u.read_value(&v.value_type()).unwrap()
    }

    #[test]
    fn roundtrip_scalars() {
        assert_eq!(roundtrip(&Value::Byte(42)), Value::Byte(42));
        assert_eq!(roundtrip(&Value::Boolean(true)), Value::Boolean(true));
        assert_eq!(roundtrip(&Value::Int64(-1)), Value::Int64(-1));
        assert_eq!(roundtrip(&Value::Double(3.5)), Value::Double(3.5));
        assert_eq!(
            roundtrip(&Value::String("hello".into())),
            Value::String("hello".into())
        );
    }

    #[test]
    fn roundtrip_variant() {
        let v = Value::Variant(Box::new(Value::UInt32(99)));
        assert_eq!(roundtrip(&v), v);
    }

    #[test]
    fn roundtrip_dict() {
        use crate::types::ArrayValue;
        let dict = Value::Array(ArrayValue::new(
            Type::DictEntry(Box::new(Type::String), Box::new(Type::Variant)),
            vec![Value::DictEntry(
                Box::new(Value::String("k".into())),
                Box::new(Value::Variant(Box::new(Value::Int32(1)))),
            )],
        ));
        assert_eq!(roundtrip(&dict), dict);
    }

    #[test]
    fn invalid_boolean_rejected() {
        let mut m = Marshaler::new(false);
        m.write_u32(5);
        let bytes = m.into_bytes();
        let mut u = Unmarshaler::new(&bytes, false);
        assert!(u.read_value(&Type::Boolean).is_err());
    }

    #[test]
    fn truncated_buffer_errs_not_panics() {
        let mut u = Unmarshaler::new(&[1, 2], false);
        assert!(u.read_u32().is_err());
    }
}
