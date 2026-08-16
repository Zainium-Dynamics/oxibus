//! Encoding [`Value`]s to the D-Bus wire format.

use crate::error::{CoreError, CoreResult};
use crate::types::{Value, MAX_ARRAY_LEN};

/// Accumulates a byte buffer while encoding [`Value`]s in D-Bus wire format,
/// tracking alignment as it goes.
pub struct Marshaler {
    /// The bytes written so far.
    pub buf: Vec<u8>,
    /// Byte order to encode multi-byte values in (`true` = big-endian).
    pub big_endian: bool,
}

impl Marshaler {
    /// Create an empty marshaler that encodes in the given byte order.
    pub fn new(big_endian: bool) -> Self {
        Self {
            buf: Vec::new(),
            big_endian,
        }
    }

    /// Create an empty marshaler with `cap` bytes of pre-allocated buffer capacity.
    pub fn with_capacity(big_endian: bool, cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            big_endian,
        }
    }

    /// Current write position, i.e. the number of bytes written so far.
    pub fn pos(&self) -> usize {
        self.buf.len()
    }

    /// Pad with zero bytes until `pos()` is a multiple of `n`.
    pub fn align(&mut self, n: usize) {
        let rem = self.buf.len() % n;
        if rem != 0 {
            self.buf.resize(self.buf.len() + (n - rem), 0);
        }
    }

    /// Write a single byte with no alignment padding (bytes are already 1-aligned).
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Align to 2 bytes, then write `v` in the marshaler's byte order.
    pub fn write_u16(&mut self, v: u16) {
        self.align(2);
        if self.big_endian {
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Align to 2 bytes, then write `v` in the marshaler's byte order (same wire format as `write_u16`).
    pub fn write_i16(&mut self, v: i16) {
        self.write_u16(v as u16);
    }

    /// Align to 4 bytes, then write `v` in the marshaler's byte order.
    pub fn write_u32(&mut self, v: u32) {
        self.align(4);
        if self.big_endian {
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Align to 4 bytes, then write `v` in the marshaler's byte order (same wire format as `write_u32`).
    pub fn write_i32(&mut self, v: i32) {
        self.write_u32(v as u32);
    }

    /// Align to 8 bytes, then write `v` in the marshaler's byte order.
    pub fn write_u64(&mut self, v: u64) {
        self.align(8);
        if self.big_endian {
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Align to 8 bytes, then write `v` in the marshaler's byte order (same wire format as `write_u64`).
    pub fn write_i64(&mut self, v: i64) {
        self.write_u64(v as u64);
    }

    /// Align to 8 bytes, then write `v`'s IEEE-754 bit pattern as a u64.
    pub fn write_f64(&mut self, v: f64) {
        self.write_u64(v.to_bits());
    }

    /// Patch a previously-written 4-byte-aligned u32 in place (used for
    /// array/body length fields whose value isn't known until after the
    /// payload is written).
    pub fn patch_u32(&mut self, at: usize, v: u32) {
        let bytes = if self.big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        self.buf[at..at + 4].copy_from_slice(&bytes);
    }

    fn write_raw_string(&mut self, s: &str) -> CoreResult<()> {
        if s.as_bytes().contains(&0) {
            return Err(CoreError::EmbeddedNul);
        }
        self.write_u32(s.len() as u32);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    fn write_signature_str(&mut self, s: &str) -> CoreResult<()> {
        if s.len() > crate::types::MAX_SIGNATURE_LEN {
            return Err(CoreError::SignatureTooLong(s.len()));
        }
        self.buf.push(s.len() as u8);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
    }

    /// Marshal a single [`Value`] of any type, including nested containers
    /// (arrays, structs, dict entries, variants), applying the correct
    /// per-type alignment as it recurses. Fails if a string contains an
    /// embedded NUL, a signature is too long, or an array body exceeds the
    /// spec's max length.
    pub fn write_value(&mut self, value: &Value) -> CoreResult<()> {
        match value {
            Value::Byte(v) => self.write_u8(*v),
            Value::Boolean(v) => self.write_u32(if *v { 1 } else { 0 }),
            Value::Int16(v) => self.write_i16(*v),
            Value::UInt16(v) => self.write_u16(*v),
            Value::Int32(v) => self.write_i32(*v),
            Value::UInt32(v) => self.write_u32(*v),
            Value::Int64(v) => self.write_i64(*v),
            Value::UInt64(v) => self.write_u64(*v),
            Value::Double(v) => self.write_f64(*v),
            Value::String(s) => self.write_raw_string(s)?,
            Value::ObjectPath(p) => self.write_raw_string(p.as_str())?,
            Value::Signature(sig) => self.write_signature_str(sig.as_str())?,
            Value::UnixFd(idx) => self.write_u32(*idx),
            Value::Array(arr) => {
                self.align(4);
                let len_pos = self.pos();
                self.write_u32(0); // placeholder
                self.align(arr.element_type.alignment());
                let start = self.pos();
                for el in &arr.elements {
                    self.write_value(el)?;
                }
                let byte_len = self.pos() - start;
                if byte_len > MAX_ARRAY_LEN {
                    return Err(CoreError::ArrayTooLong(byte_len));
                }
                self.patch_u32(len_pos, byte_len as u32);
            }
            Value::Struct(fields) => {
                self.align(8);
                for f in fields {
                    self.write_value(f)?;
                }
            }
            Value::DictEntry(k, v) => {
                self.align(8);
                self.write_value(k)?;
                self.write_value(v)?;
            }
            Value::Variant(inner) => {
                let sig = inner.value_type().to_signature_string();
                self.write_signature_str(&sig)?;
                self.write_value(inner)?;
            }
        }
        Ok(())
    }

    /// Marshal a top-level sequence of values (e.g. a message body), each
    /// value being one complete type in the overall signature.
    pub fn write_values(&mut self, values: &[Value]) -> CoreResult<()> {
        for v in values {
            self.write_value(v)?;
        }
        Ok(())
    }

    /// Consume the marshaler and return the accumulated bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// Convenience: marshal a slice of values into fresh bytes and return the
/// concatenated signature string alongside.
pub fn marshal_body(values: &[Value], big_endian: bool) -> CoreResult<(Vec<u8>, String)> {
    let mut m = Marshaler::new(big_endian);
    m.write_values(values)?;
    let sig: String = values
        .iter()
        .map(|v| v.value_type().to_signature_string())
        .collect();
    Ok((m.into_bytes(), sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ArrayValue, Type};

    #[test]
    fn align_pads_correctly() {
        let mut m = Marshaler::new(false);
        m.write_u8(1);
        assert_eq!(m.pos(), 1);
        m.align(4);
        assert_eq!(m.pos(), 4);
    }

    #[test]
    fn string_marshals_with_length_prefix_and_nul() {
        let mut m = Marshaler::new(false);
        m.write_value(&Value::String("hi".into())).unwrap();
        // u32 len(2) + "hi" + NUL = 4 + 2 + 1 = 7
        assert_eq!(m.pos(), 7);
        assert_eq!(&m.buf[0..4], &2u32.to_le_bytes());
        assert_eq!(&m.buf[4..6], b"hi");
        assert_eq!(m.buf[6], 0);
    }

    #[test]
    fn array_of_bytes_length_is_element_count() {
        let mut m = Marshaler::new(false);
        let arr = ArrayValue::new(
            Type::Byte,
            vec![Value::Byte(1), Value::Byte(2), Value::Byte(3)],
        );
        m.write_value(&Value::Array(arr)).unwrap();
        assert_eq!(&m.buf[0..4], &3u32.to_le_bytes());
        assert_eq!(&m.buf[4..7], &[1, 2, 3]);
    }

    #[test]
    fn struct_aligns_to_8() {
        let mut m = Marshaler::new(false);
        m.write_u8(1);
        m.write_value(&Value::Struct(vec![Value::Int32(7)])).unwrap();
        // after 1 byte + align(8) => struct starts at 8, then i32 at 8..12
        assert_eq!(&m.buf[8..12], &7i32.to_le_bytes());
    }

    #[test]
    fn embedded_nul_rejected() {
        let mut m = Marshaler::new(false);
        assert!(m.write_value(&Value::String("a\0b".into())).is_err());
    }
}
