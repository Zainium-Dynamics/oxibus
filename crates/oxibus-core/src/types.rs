//! The D-Bus type system: [`Type`] (a parsed signature node) and [`Value`]
//! (a concrete value tagged with its type), plus the two string newtypes
//! the spec treats specially: [`ObjectPath`] and [`Signature`].

use std::fmt;

use crate::error::{CoreError, CoreResult};

/// Maximum nesting depth for arrays-of-arrays (D-Bus spec: 32).
pub const MAX_ARRAY_DEPTH: u32 = 32;
/// Maximum nesting depth for struct-in-struct / dict-entry-in-struct (D-Bus spec: 32).
pub const MAX_STRUCT_DEPTH: u32 = 32;
/// Maximum length in bytes of a single SIGNATURE value (D-Bus spec: 255).
pub const MAX_SIGNATURE_LEN: usize = 255;
/// Maximum length in bytes of a marshaled array body (D-Bus spec: 64 MiB).
pub const MAX_ARRAY_LEN: usize = 67_108_864;
/// Default maximum total message length (matches libdbus' default).
pub const DEFAULT_MAX_MESSAGE_LEN: u32 = 134_217_728;

/// A parsed node of a D-Bus type signature (one "complete type").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    /// Signature code `y`: an unsigned 8-bit integer.
    Byte,
    /// Signature code `b`: a boolean, marshaled as a `u32` that must be 0 or 1.
    Boolean,
    /// Signature code `n`: a signed 16-bit integer.
    Int16,
    /// Signature code `q`: an unsigned 16-bit integer.
    UInt16,
    /// Signature code `i`: a signed 32-bit integer.
    Int32,
    /// Signature code `u`: an unsigned 32-bit integer.
    UInt32,
    /// Signature code `x`: a signed 64-bit integer.
    Int64,
    /// Signature code `t`: an unsigned 64-bit integer.
    UInt64,
    /// Signature code `d`: an IEEE-754 double-precision float.
    Double,
    /// Signature code `s`: a UTF-8 string with no embedded NUL.
    String,
    /// Signature code `o`: a validated D-Bus object path.
    ObjectPath,
    /// Signature code `g`: a validated D-Bus type signature string.
    Signature,
    /// Signature code `h`: an index into the message's out-of-band file descriptor array.
    UnixFd,
    /// Signature code `a` followed by the element type: a homogeneous array.
    Array(Box<Type>),
    /// A parenthesized `(...)` sequence of field types.
    Struct(Vec<Type>),
    /// A `{key value}` pair as found inside an array-of-dict-entries (i.e. a map).
    DictEntry(Box<Type>, Box<Type>),
    /// Signature code `v`: a variant, whose concrete type is carried alongside the value on the wire.
    Variant,
}

impl Type {
    /// The single-character signature code for this type (`(` for `Struct`, `{` for `DictEntry`).
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

    /// Wire alignment in bytes for this type.
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
            Type::Int64 | Type::UInt64 | Type::Double | Type::Struct(_) | Type::DictEntry(_, _) => 8,
        }
    }

    /// True for the fixed and string-like scalar types (everything except arrays, structs,
    /// dict entries and variants) — the types that are valid dict-entry keys.
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

    /// True for array, struct, dict-entry and variant types (the inverse of [`is_basic`](Self::is_basic)).
    pub fn is_container(&self) -> bool {
        !self.is_basic()
    }

    /// Render back to a signature string.
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

/// A D-Bus object path, e.g. `/org/freedesktop/DBus`. Validated on
/// construction per the D-Bus spec grammar.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectPath(String);

impl ObjectPath {
    /// Validate and wrap `s` as an object path, failing with
    /// [`CoreError::InvalidObjectPath`] if it does not match the spec grammar.
    pub fn new(s: impl Into<String>) -> CoreResult<Self> {
        let s = s.into();
        if !is_valid_object_path(&s) {
            return Err(CoreError::InvalidObjectPath(s));
        }
        Ok(ObjectPath(s))
    }

    /// Construct without validation. Only for compiled-in constants that
    /// are known-valid (e.g. `/org/freedesktop/DBus`).
    pub const fn new_unchecked(s: String) -> Self {
        ObjectPath(s)
    }

    /// Borrow the path as a plain string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the `ObjectPath` and return the underlying `String`.
    pub fn into_string(self) -> String {
        self.0
    }

    /// True if `self` is `prefix` or a descendant of it (used for
    /// `path_namespace=` match rules).
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

/// Check whether `s` matches the D-Bus object path grammar: starts with `/`,
/// is either exactly `/` or has no trailing slash, and every `/`-separated
/// segment is non-empty and consists only of `[A-Za-z0-9_]`.
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

/// A validated D-Bus type signature string (may describe zero or more
/// complete types concatenated, e.g. header body signatures).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Signature(String);

impl Signature {
    /// Validate and wrap `s` as a signature: checks the 255-byte length limit
    /// and parses it to confirm well-formedness and nesting-depth limits.
    pub fn new(s: impl Into<String>) -> CoreResult<Self> {
        let s = s.into();
        if s.len() > MAX_SIGNATURE_LEN {
            return Err(CoreError::SignatureTooLong(s.len()));
        }
        // Validates via the parser (also enforces nesting limits).
        let _ = crate::signature::parse_signature(&s)?;
        Ok(Signature(s))
    }

    /// The empty signature, describing zero complete types (e.g. a message with no body).
    pub const fn empty() -> Self {
        Signature(String::new())
    }

    /// Borrow the signature as a plain string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse the signature into its sequence of complete [`Type`]s.
    pub fn types(&self) -> CoreResult<Vec<Type>> {
        crate::signature::parse_signature(&self.0)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A concrete D-Bus value. Containers carry their element/field types so a
/// `Value` alone is always self-describing (needed to re-derive a signature
/// for e.g. VARIANT bodies without a side channel).
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// An unsigned 8-bit integer (`y`).
    Byte(u8),
    /// A boolean (`b`).
    Boolean(bool),
    /// A signed 16-bit integer (`n`).
    Int16(i16),
    /// An unsigned 16-bit integer (`q`).
    UInt16(u16),
    /// A signed 32-bit integer (`i`).
    Int32(i32),
    /// An unsigned 32-bit integer (`u`).
    UInt32(u32),
    /// A signed 64-bit integer (`x`).
    Int64(i64),
    /// An unsigned 64-bit integer (`t`).
    UInt64(u64),
    /// An IEEE-754 double-precision float (`d`).
    Double(f64),
    /// A UTF-8 string (`s`).
    String(String),
    /// A validated object path (`o`).
    ObjectPath(ObjectPath),
    /// A validated type signature (`g`).
    Signature(Signature),
    /// An index into the message's out-of-band file descriptor array (`h`).
    UnixFd(u32),
    /// A homogeneous array of values (`a...`), self-describing via its element type.
    Array(ArrayValue),
    /// A heterogeneous sequence of field values (`(...)`).
    Struct(Vec<Value>),
    /// A key/value pair, only meaningful as an element of an array typed as a dict (`{..}`).
    DictEntry(Box<Value>, Box<Value>),
    /// A value wrapped with its own type tag, allowing heterogeneous containers (`v`).
    Variant(Box<Value>),
}

/// The contents of an [`Value::Array`]: the element type shared by every
/// entry, plus the entries themselves. Kept together so an empty array still
/// carries enough information to be re-marshaled with the correct signature.
#[derive(Debug, Clone, PartialEq)]
pub struct ArrayValue {
    /// The type every element in `elements` must have.
    pub element_type: Type,
    /// The array's elements, in wire order.
    pub elements: Vec<Value>,
}

impl ArrayValue {
    /// Construct an array value from an explicit element type and elements.
    /// The caller is responsible for ensuring every element actually has `element_type`.
    pub fn new(element_type: Type, elements: Vec<Value>) -> Self {
        Self {
            element_type,
            elements,
        }
    }

    /// Construct an empty array of the given element type.
    pub fn empty(element_type: Type) -> Self {
        Self {
            element_type,
            elements: Vec::new(),
        }
    }
}

impl Value {
    /// Derive the [`Type`] describing this value.
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

    /// If this value is a string, object path, or signature, borrows it as a string slice.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            Value::ObjectPath(p) => Some(p.as_str()),
            Value::Signature(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// If this value is a `UInt32` or `UnixFd`, returns its value as a `u32`.
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::UInt32(v) => Some(*v),
            Value::UnixFd(v) => Some(*v),
            _ => None,
        }
    }

    /// Recursively unwraps variant wrappers to return the underlying concrete `Value`.
    pub fn unwrap_variant(&self) -> &Value {
        match self {
            Value::Variant(inner) => inner.unwrap_variant(),
            other => other,
        }
    }

    /// Helper to construct a `Value::String` from any type that converts into a `String`.
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
