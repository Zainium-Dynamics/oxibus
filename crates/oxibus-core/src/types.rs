// D-Bus type system: Type, Value, ObjectPath, and Signature.

use std::fmt;

use crate::error::{CoreError, CoreResult};

pub const MAX_ARRAY_DEPTH: u32 = 32;
pub const MAX_STRUCT_DEPTH: u32 = 32;
pub const MAX_SIGNATURE_LEN: usize = 255;
pub const MAX_ARRAY_LEN: usize = 67_108_864;
pub const DEFAULT_MAX_MESSAGE_LEN: u32 = 134_217_728;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    Byte,
    Boolean,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Double,
    String,
    ObjectPath,
    Signature,
    UnixFd,
    Array(Box<Type>),
    Struct(Vec<Type>),
    DictEntry(Box<Type>, Box<Type>),
    Variant,
}

impl Type {
    pub fn code(&self) -> char {
        match self {
            Type::Byte => 'y',
            Type::Boolean => 'b',
            Type::Int16 => 'n',
            Type::UInt16 => 'q',
            Type::Int32 => 'i',
            Type::UInt32 => 'u',
            Type::Int64 => 'x',
            Type::UInt64 => 't',
            Type::Double => 'd',
            Type::String => 's',
            Type::ObjectPath => 'o',
            Type::Signature => 'g',
            Type::UnixFd => 'h',
            Type::Array(_) => 'a',
            Type::Struct(_) => '(',
            Type::DictEntry(_, _) => '{',
            Type::Variant => 'v',
        }
    }

    pub fn alignment(&self) -> usize {
        match self {
            Type::Byte | Type::Signature | Type::Variant => 1,
            Type::Int16 | Type::UInt16 => 2,
            Type::Boolean
            | Type::Int32
            | Type::UInt32
            | Type::UnixFd
            | Type::String
            | Type::ObjectPath
            | Type::Array(_) => 4,
            Type::Int64 | Type::UInt64 | Type::Double | Type::Struct(_) | Type::DictEntry(_, _) => {
                8
            }
        }
    }

    pub fn is_basic(&self) -> bool {
        matches!(
            self,
            Type::Byte
                | Type::Boolean
                | Type::Int16
                | Type::UInt16
                | Type::Int32
                | Type::UInt32
                | Type::Int64
                | Type::UInt64
                | Type::Double
                | Type::String
                | Type::ObjectPath
                | Type::Signature
                | Type::UnixFd
        )
    }

    pub fn is_container(&self) -> bool {
        !self.is_basic()
    }

    pub fn to_signature_string(&self) -> String {
        let mut s = String::new();
        self.write_signature(&mut s);
        s
    }

    fn write_signature(&self, out: &mut String) {
        match self {
            Type::Array(elem) => {
                out.push('a');
                elem.write_signature(out);
            }
            Type::Struct(fields) => {
                out.push('(');
                for f in fields {
                    f.write_signature(out);
                }
                out.push(')');
            }
            Type::DictEntry(k, v) => {
                out.push('{');
                k.write_signature(out);
                v.write_signature(out);
                out.push('}');
            }
            other => out.push(other.code()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectPath(String);

impl ObjectPath {
    pub fn new(s: impl Into<String>) -> CoreResult<Self> {
        let s = s.into();
        if !is_valid_object_path(&s) {
            return Err(CoreError::InvalidObjectPath(s));
        }
        Ok(ObjectPath(s))
    }

    pub const fn new_unchecked(s: String) -> Self {
        ObjectPath(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn is_within_namespace(&self, prefix: &str) -> bool {
        if prefix == "/" {
            return true;
        }
        self.0 == prefix || self.0.starts_with(&format!("{prefix}/"))
    }
}

impl fmt::Display for ObjectPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for ObjectPath {
    type Err = CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ObjectPath::new(s)
    }
}

pub fn is_valid_object_path(s: &str) -> bool {
    if !s.starts_with('/') {
        return false;
    }
    if s == "/" {
        return true;
    }
    if s.ends_with('/') {
        return false;
    }
    for segment in s[1..].split('/') {
        if segment.is_empty() {
            return false;
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Signature(String);

impl Signature {
    pub fn new(s: impl Into<String>) -> CoreResult<Self> {
        let s = s.into();
        if s.len() > MAX_SIGNATURE_LEN {
            return Err(CoreError::SignatureTooLong(s.len()));
        }
        let _ = crate::signature::parse_signature(&s)?;
        Ok(Signature(s))
    }

    pub const fn empty() -> Self {
        Signature(String::new())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn types(&self) -> CoreResult<Vec<Type>> {
        crate::signature::parse_signature(&self.0)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Byte(u8),
    Boolean(bool),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Double(f64),
    String(String),
    ObjectPath(ObjectPath),
    Signature(Signature),
    UnixFd(u32),
    Array(ArrayValue),
    Struct(Vec<Value>),
    DictEntry(Box<Value>, Box<Value>),
    Variant(Box<Value>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArrayValue {
    pub element_type: Type,
    pub elements: Vec<Value>,
}

impl ArrayValue {
    pub fn new(element_type: Type, elements: Vec<Value>) -> Self {
        Self {
            element_type,
            elements,
        }
    }

    pub fn empty(element_type: Type) -> Self {
        Self {
            element_type,
            elements: Vec::new(),
        }
    }
}

impl Value {
    pub fn value_type(&self) -> Type {
        match self {
            Value::Byte(_) => Type::Byte,
            Value::Boolean(_) => Type::Boolean,
            Value::Int16(_) => Type::Int16,
            Value::UInt16(_) => Type::UInt16,
            Value::Int32(_) => Type::Int32,
            Value::UInt32(_) => Type::UInt32,
            Value::Int64(_) => Type::Int64,
            Value::UInt64(_) => Type::UInt64,
            Value::Double(_) => Type::Double,
            Value::String(_) => Type::String,
            Value::ObjectPath(_) => Type::ObjectPath,
            Value::Signature(_) => Type::Signature,
            Value::UnixFd(_) => Type::UnixFd,
            Value::Array(a) => Type::Array(Box::new(a.element_type.clone())),
            Value::Struct(fields) => Type::Struct(fields.iter().map(Value::value_type).collect()),
            Value::DictEntry(k, v) => {
                Type::DictEntry(Box::new(k.value_type()), Box::new(v.value_type()))
            }
            Value::Variant(_) => Type::Variant,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            Value::ObjectPath(p) => Some(p.as_str()),
            Value::Signature(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::UInt32(v) => Some(*v),
            Value::UnixFd(v) => Some(*v),
            _ => None,
        }
    }

    pub fn unwrap_variant(&self) -> &Value {
        match self {
            Value::Variant(inner) => inner.unwrap_variant(),
            other => other,
        }
    }

    pub fn string(s: impl Into<String>) -> Value {
        Value::String(s.into())
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}
impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::UInt32(v)
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Boolean(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_path_validation() {
        assert!(is_valid_object_path("/"));
        assert!(is_valid_object_path("/org/freedesktop/DBus"));
        assert!(is_valid_object_path("/a_1/b_2"));
        assert!(!is_valid_object_path(""));
        assert!(!is_valid_object_path("no-leading-slash"));
        assert!(!is_valid_object_path("/trailing/"));
        assert!(!is_valid_object_path("/double//slash"));
        assert!(!is_valid_object_path("/bad-dash"));
    }

    #[test]
    fn path_namespace_matching() {
        let p = ObjectPath::new("/org/freedesktop/DBus").unwrap();
        assert!(p.is_within_namespace("/org/freedesktop"));
        assert!(p.is_within_namespace("/org/freedesktop/DBus"));
        assert!(!p.is_within_namespace("/org/freedesktop/DBusX"));
        assert!(p.is_within_namespace("/"));
    }

    #[test]
    fn alignment_table() {
        assert_eq!(Type::Byte.alignment(), 1);
        assert_eq!(Type::Int64.alignment(), 8);
        assert_eq!(Type::Struct(vec![]).alignment(), 8);
        assert_eq!(Type::Array(Box::new(Type::Byte)).alignment(), 4);
    }
}
