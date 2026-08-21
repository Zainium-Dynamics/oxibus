use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("{name}: {message}")]
    CallError {
        name: String,
        message: String,
    },
    #[error("connection closed")]
    Closed,
    #[error("core error: {0}")]
    Core(#[from] oxibus_core::CoreError),
}

pub type ClientResult<T> = Result<T, ClientError>;

impl ClientError {
    pub fn is_service_unknown(&self) -> bool {
        matches!(self, ClientError::CallError { name, .. } if name == oxibus_core::errors::SERVICE_UNKNOWN)
    }
}
