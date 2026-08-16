//! Errors produced by SASL authentication (client and server) and by
//! `DBUS_COOKIE_SHA1` keyring access.

use thiserror::Error;

/// Errors from SASL authentication or keyring handling.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Underlying I/O failure — keyring file access, or a socket error
    /// surfaced through this crate.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// `DBUS_COOKIE_SHA1` needs a `$HOME` to locate `~/.dbus-keyrings`,
    /// but the current process has none set.
    #[error("no home directory for current user (needed for DBUS_COOKIE_SHA1 keyring)")]
    NoHomeDir,
    /// A keyring file exists but its contents don't parse as
    /// `<id> <created> <hex-secret>` lines.
    #[error("keyring file corrupt: {0}")]
    KeyringCorrupt(String),
    /// The keyring holds no key young enough to offer to a client, and a
    /// new one could not be created.
    #[error("no usable key in keyring")]
    NoUsableKey,
    /// A hex-encoded field (secret, challenge, or response) failed to
    /// decode.
    #[error("hex decode error")]
    HexDecode,
    /// The peer violated the SASL protocol (unexpected command, bad
    /// framing, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Result alias for fallible SASL/keyring operations.
pub type AuthResult<T> = Result<T, AuthError>;
