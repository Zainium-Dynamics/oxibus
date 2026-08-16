#![allow(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
//! `oxibus-transport` — `AF_UNIX` transport for OxiBus: peer credentials,
//! `SCM_RIGHTS` fd passing, and SASL-line / framed-message I/O.

pub mod credentials;
pub mod fds;
pub mod listener;
pub mod stream;

pub use credentials::{current_pid, current_uid, security_label, PeerCredentials};
pub use listener::{bind, connect, BoundListener};
pub use stream::{Transport, Writer};
