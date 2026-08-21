// SASL mechanism identifiers.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mechanism {
    External,
    DbusCookieSha1,
    Anonymous,
}

impl Mechanism {
    pub fn name(self) -> &'static str {
        match self {
            Mechanism::External => "EXTERNAL",
            Mechanism::DbusCookieSha1 => "DBUS_COOKIE_SHA1",
            Mechanism::Anonymous => "ANONYMOUS",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "EXTERNAL" => Some(Mechanism::External),
            "DBUS_COOKIE_SHA1" => Some(Mechanism::DbusCookieSha1),
            "ANONYMOUS" => Some(Mechanism::Anonymous),
            _ => None,
        }
    }
}

pub fn mechanism_list_string(mechs: &[Mechanism]) -> String {
    mechs.iter().map(|m| m.name()).collect::<Vec<_>>().join(" ")
}
