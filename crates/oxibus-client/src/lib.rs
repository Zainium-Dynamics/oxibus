// oxibus-client: D-Bus connection library.

pub mod connection;
pub mod error;
pub mod object_server;
pub mod proxy;

pub use connection::{default_mechanisms, Connection};
pub use error::{ClientError, ClientResult};
pub use object_server::{BoxFuture, Interface, MethodError, MethodResult, ObjectServer};
pub use proxy::Proxy;

pub use oxibus_auth::Mechanism;
pub use oxibus_core::{Address, Message, ObjectPath, Value};
