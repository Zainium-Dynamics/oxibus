use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid signature '{0}': {1}")]
    InvalidSignature(String, &'static str),
    #[error("signature too long: {0} bytes (max 255)")]
    SignatureTooLong(usize),
    #[error("container nesting too deep (max array depth {max_array}, max struct depth {max_struct})")]
    NestingTooDeep {
        max_array: u32,
        max_struct: u32,
    },
    #[error("invalid object path '{0}'")]
    InvalidObjectPath(String),
    #[error("invalid UTF-8 in string")]
    InvalidUtf8,
    #[error("string contains embedded NUL byte")]
    EmbeddedNul,
    #[error("unexpected end of buffer (need {needed} more bytes, have {have})")]
    UnexpectedEof {
        needed: usize,
        have: usize,
    },
    #[error("boolean value must be 0 or 1, got {0}")]
    InvalidBoolean(u32),
    #[error("array body exceeds max length: {0} bytes (max 67108864)")]
    ArrayTooLong(usize),
    #[error("message exceeds max length: {0} bytes (max {1})")]
    MessageTooLong(usize, u32),
    #[error("unknown byte order marker '{0}' (expected 'l' or 'B')")]
    BadByteOrder(u8),
    #[error("unsupported protocol version {0} (expected 1)")]
    BadProtocolVersion(u8),
    #[error("required header field missing: {0}")]
    MissingHeaderField(&'static str),
    #[error("type mismatch: expected {expected}, found value of a different type")]
    TypeMismatch {
        expected: String,
    },
    #[error("unix fd index {0} out of range ({1} fds available)")]
    FdIndexOutOfRange(u32, usize),
    #[error("too many unix fds in message: {0} (max {1})")]
    TooManyFds(usize, u32),
    #[error("invalid D-Bus address: {0}")]
    InvalidAddress(String),
    #[error("io error: {0}")]
    Io(String),
}

pub type CoreResult<T> = Result<T, CoreError>;
