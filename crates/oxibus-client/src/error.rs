use thiserror::Error;

/// Errors returned by [`crate::Connection`] and [`crate::Proxy`] operations.
#[derive(Debug, Error)]
pub enum ClientError {
    /// A read or write on the underlying transport failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The peer sent something that violates the D-Bus wire protocol
    /// (unexpected reply type, missing required field, etc.).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The SASL handshake did not complete: every configured mechanism was
    /// rejected, or the server sent an unparseable auth response.
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    /// A method call returned an `Error` reply from the peer.
    #[error("{name}: {message}")]
    CallError {
        /// The D-Bus error name, e.g. `org.freedesktop.DBus.Error.ServiceUnknown`.
        name: String,
        /// The human-readable error message from the reply body, if any.
        message: String,
    },
    /// The connection's reader task exited (peer disconnected) while a
    /// call was still awaiting its reply.
    #[error("connection closed")]
    Closed,
    /// An error propagated up from `oxibus-core` (message building,
    /// address parsing, etc.).
    #[error("core error: {0}")]
    Core(#[from] oxibus_core::CoreError),
}

/// Result alias used throughout this crate's public API.
pub type ClientResult<T> = Result<T, ClientError>;

impl ClientError {
    /// True if this is a `CallError` whose name is
    /// `org.freedesktop.DBus.Error.ServiceUnknown` — the peer service
    /// isn't running or isn't bus-activatable.
    pub fn is_service_unknown(&self) -> bool {
        matches!(self, ClientError::CallError { name, .. } if name == oxibus_core::errors::SERVICE_UNKNOWN)
    }
}
