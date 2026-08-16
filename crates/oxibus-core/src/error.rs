use thiserror::Error;

/// Errors that can arise while parsing, marshaling, or unmarshaling D-Bus
/// wire data, or while working with addresses and names.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A type signature string is not well-formed; the `&'static str` names the specific rule violated.
    #[error("invalid signature '{0}': {1}")]
    InvalidSignature(String, &'static str),
    /// A signature string exceeds the 255-byte spec limit.
    #[error("signature too long: {0} bytes (max 255)")]
    SignatureTooLong(usize),
    /// A signature or value nests arrays/structs deeper than the spec-mandated limits.
    #[error("container nesting too deep (max array depth {max_array}, max struct depth {max_struct})")]
    NestingTooDeep {
        /// Maximum allowed array nesting depth (spec limit: 32).
        max_array: u32,
        /// Maximum allowed struct nesting depth (spec limit: 32).
        max_struct: u32,
    },
    /// An object path does not match the spec grammar (must start with `/`, elements separated by `/`, no trailing `/` except the root).
    #[error("invalid object path '{0}'")]
    InvalidObjectPath(String),
    /// A string value contains bytes that are not valid UTF-8.
    #[error("invalid UTF-8 in string")]
    InvalidUtf8,
    /// A string value contains an embedded NUL byte, which D-Bus strings must not.
    #[error("string contains embedded NUL byte")]
    EmbeddedNul,
    /// The input buffer ended before all expected bytes could be read.
    #[error("unexpected end of buffer (need {needed} more bytes, have {have})")]
    UnexpectedEof {
        /// Number of additional bytes that were required to continue reading.
        needed: usize,
        /// Number of bytes actually remaining in the buffer.
        have: usize,
    },
    /// A marshaled boolean was neither 0 nor 1.
    #[error("boolean value must be 0 or 1, got {0}")]
    InvalidBoolean(u32),
    /// An array's marshaled byte length exceeds the spec's 64 MiB (67108864-byte) limit.
    #[error("array body exceeds max length: {0} bytes (max 67108864)")]
    ArrayTooLong(usize),
    /// A message's total length exceeds the configured or spec maximum (128 MiB by default).
    #[error("message exceeds max length: {0} bytes (max {1})")]
    MessageTooLong(usize, u32),
    /// The header's byte-order marker was neither `l` (little-endian) nor `B` (big-endian).
    #[error("unknown byte order marker '{0}' (expected 'l' or 'B')")]
    BadByteOrder(u8),
    /// The header declares a protocol version other than the one this crate implements (1).
    #[error("unsupported protocol version {0} (expected 1)")]
    BadProtocolVersion(u8),
    /// A header field required for this message type (e.g. `PATH` for a method call) was absent.
    #[error("required header field missing: {0}")]
    MissingHeaderField(&'static str),
    /// A `Value` did not match the `Type` expected at this position.
    #[error("type mismatch: expected {expected}, found value of a different type")]
    TypeMismatch {
        /// Human-readable description of the type that was expected.
        expected: String,
    },
    /// A UNIX_FD value referenced an index past the end of the message's fd array.
    #[error("unix fd index {0} out of range ({1} fds available)")]
    FdIndexOutOfRange(u32, usize),
    /// A message carries more file descriptors than the configured maximum.
    #[error("too many unix fds in message: {0} (max {1})")]
    TooManyFds(usize, u32),
    /// A D-Bus server address string could not be parsed.
    #[error("invalid D-Bus address: {0}")]
    InvalidAddress(String),
    /// An I/O error occurred on the underlying transport; the message is the formatted source error.
    #[error("io error: {0}")]
    Io(String),
}

/// Convenience alias for results whose error type is [`CoreError`].
pub type CoreResult<T> = Result<T, CoreError>;
