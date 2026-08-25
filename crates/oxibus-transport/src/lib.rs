// oxibus-transport: AF_UNIX transport, credentials, fd passing, and framing.

pub mod credentials;
pub mod fds;
pub mod listener;
pub mod stream;

pub use credentials::{PeerCredentials, current_pid, current_uid, security_label};
pub use listener::{BoundListener, bind, connect};
pub use stream::{Transport, Writer};
