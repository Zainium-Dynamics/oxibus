// Errors produced by SASL authentication and keyring access.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no home directory for current user (needed for DBUS_COOKIE_SHA1 keyring)")]
    NoHomeDir,
    #[error("keyring file corrupt: {0}")]
    KeyringCorrupt(String),
    #[error("no usable key in keyring")]
    NoUsableKey,
    #[error("hex decode error")]
    HexDecode,
    #[error("protocol error: {0}")]
    Protocol(String),
}

pub type AuthResult<T> = Result<T, AuthError>;
