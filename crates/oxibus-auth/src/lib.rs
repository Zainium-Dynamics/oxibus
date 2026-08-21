// oxibus-auth: SASL authentication for D-Bus wire protocol (EXTERNAL, ANONYMOUS, DBUS_COOKIE_SHA1).

pub mod client;
pub mod error;
pub mod keyring;
pub mod mechanism;
pub mod server;

pub use client::{ClientAction, ClientAuth};
pub use error::{AuthError, AuthResult};
pub use mechanism::Mechanism;
pub use server::{ServerAction, ServerAuth};

// Generate a random 128-bit hex GUID.
pub fn generate_guid_hex() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
