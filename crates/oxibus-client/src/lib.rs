#![allow(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
//! `oxibus-client` — the OxiBus connection library (what `libdbus`/GDBus
//! were to real D-Bus): connect, call methods, emit/subscribe to signals,
//! and optionally serve objects of your own on the same connection.

pub mod connection;
/// Error type returned by client operations.
pub mod error;
pub mod object_server;
pub mod proxy;

pub use connection::{default_mechanisms, Connection};
pub use error::{ClientError, ClientResult};
pub use object_server::{BoxFuture, Interface, MethodError, MethodResult, ObjectServer};
pub use proxy::Proxy;

pub use oxibus_auth::Mechanism;
pub use oxibus_core::{Address, Message, ObjectPath, Value};
