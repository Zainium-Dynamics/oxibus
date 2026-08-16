//! SASL mechanism identifiers used in the D-Bus auth handshake.

/// A SASL authentication mechanism understood by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mechanism {
    /// `EXTERNAL`: authenticate using the peer credentials supplied by
    /// the underlying socket (`SO_PEERCRED`), not any shared secret.
    External,
    /// `DBUS_COOKIE_SHA1`: challenge/response over a secret ("cookie")
    /// shared via a file under `~/.dbus-keyrings`, readable only by the
    /// owning user.
    DbusCookieSha1,
    /// `ANONYMOUS`: no credentials are checked; any peer is accepted.
    Anonymous,
}

impl Mechanism {
    /// The SASL mechanism name as sent on the wire (e.g. `EXTERNAL`).
    pub fn name(self) -> &'static str {
        match self {
            Mechanism::External => "EXTERNAL",
            Mechanism::DbusCookieSha1 => "DBUS_COOKIE_SHA1",
            Mechanism::Anonymous => "ANONYMOUS",
        }
    }

    /// Parse a SASL mechanism name as sent on the wire, or `None` if it
    /// isn't one of the mechanisms this crate implements.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "EXTERNAL" => Some(Mechanism::External),
            "DBUS_COOKIE_SHA1" => Some(Mechanism::DbusCookieSha1),
            "ANONYMOUS" => Some(Mechanism::Anonymous),
            _ => None,
        }
    }
}

/// Space-separated list of mechanism names, as sent in a `REJECTED` line.
pub fn mechanism_list_string(mechs: &[Mechanism]) -> String {
    mechs.iter().map(|m| m.name()).collect::<Vec<_>>().join(" ")
}
