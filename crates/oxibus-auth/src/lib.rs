#![allow(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
//! `oxibus-auth` — SASL authentication for the D-Bus wire protocol:
//! `EXTERNAL` (peer-credential based), `ANONYMOUS`, and `DBUS_COOKIE_SHA1`
//! (keyring-based, file-compatible with `~/.dbus-keyrings`).

pub mod client;
pub mod error;
pub mod keyring;
pub mod mechanism;
pub mod server;

pub use client::{ClientAction, ClientAuth};
pub use error::{AuthError, AuthResult};
pub use mechanism::Mechanism;
pub use server::{ServerAction, ServerAuth};

/// Generate a random 128-bit hex GUID, used both as a D-Bus server GUID
/// (sent in the SASL `OK` line) and as the bus id returned by
/// `org.freedesktop.DBus.GetId`.
pub fn generate_guid_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
