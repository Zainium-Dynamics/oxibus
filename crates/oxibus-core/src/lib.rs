#![allow(rustdoc::broken_intra_doc_links)]

pub mod addr;
pub mod error;
pub mod header;
pub mod marshal;
pub mod message;
pub mod signature;
pub mod types;
pub mod unmarshal;

pub use addr::Address;
pub use error::{CoreError, CoreResult};
pub use header::{HeaderField, MessageHeader, MessageType, PROTOCOL_VERSION, flags};
pub use message::{Message, MessageBuilder, SerialGenerator, reply_to};
pub use types::{ArrayValue, ObjectPath, Signature, Type, Value};

// Well-known bus names, interfaces and object paths.
pub mod well_known {
    pub const BUS_NAME: &str = "org.freedesktop.DBus";
    pub const BUS_PATH: &str = "/org/freedesktop/DBus";
    pub const BUS_INTERFACE: &str = "org.freedesktop.DBus";
    pub const MONITORING_INTERFACE: &str = "org.freedesktop.DBus.Monitoring";
    pub const STATS_INTERFACE: &str = "org.freedesktop.DBus.Debug.Stats";
    pub const INTROSPECTABLE_INTERFACE: &str = "org.freedesktop.DBus.Introspectable";
    pub const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
    pub const OBJECT_MANAGER_INTERFACE: &str = "org.freedesktop.DBus.ObjectManager";
    pub const PEER_INTERFACE: &str = "org.freedesktop.DBus.Peer";

    pub const NAME_ACQUIRED: &str = "NameAcquired";
    pub const NAME_LOST: &str = "NameLost";
    pub const NAME_OWNER_CHANGED: &str = "NameOwnerChanged";
}

// Standard D-Bus error names.
pub mod errors {
    pub const FAILED: &str = "org.freedesktop.DBus.Error.Failed";
    pub const NO_MEMORY: &str = "org.freedesktop.DBus.Error.NoMemory";
    pub const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
    pub const NAME_HAS_NO_OWNER: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
    pub const NO_REPLY: &str = "org.freedesktop.DBus.Error.NoReply";
    pub const IO_ERROR: &str = "org.freedesktop.DBus.Error.IOError";
    pub const BAD_ADDRESS: &str = "org.freedesktop.DBus.Error.BadAddress";
    pub const NOT_SUPPORTED: &str = "org.freedesktop.DBus.Error.NotSupported";
    pub const LIMITS_EXCEEDED: &str = "org.freedesktop.DBus.Error.LimitsExceeded";
    pub const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
    pub const AUTH_FAILED: &str = "org.freedesktop.DBus.Error.AuthFailed";
    pub const NO_SERVER: &str = "org.freedesktop.DBus.Error.NoServer";
    pub const TIMEOUT: &str = "org.freedesktop.DBus.Error.Timeout";
    pub const NO_NETWORK: &str = "org.freedesktop.DBus.Error.NoNetwork";
    pub const ADDRESS_IN_USE: &str = "org.freedesktop.DBus.Error.AddressInUse";
    pub const DISCONNECTED: &str = "org.freedesktop.DBus.Error.Disconnected";
    pub const INVALID_ARGS: &str = "org.freedesktop.DBus.Error.InvalidArgs";
    pub const FILE_NOT_FOUND: &str = "org.freedesktop.DBus.Error.FileNotFound";
    pub const FILE_EXISTS: &str = "org.freedesktop.DBus.Error.FileExists";
    pub const UNKNOWN_METHOD: &str = "org.freedesktop.DBus.Error.UnknownMethod";
    pub const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";
    pub const UNKNOWN_INTERFACE: &str = "org.freedesktop.DBus.Error.UnknownInterface";
    pub const UNKNOWN_PROPERTY: &str = "org.freedesktop.DBus.Error.UnknownProperty";
    pub const PROPERTY_READ_ONLY: &str = "org.freedesktop.DBus.Error.PropertyReadOnly";
    pub const TIMED_OUT: &str = "org.freedesktop.DBus.Error.TimedOut";
    pub const MATCH_RULE_NOT_FOUND: &str = "org.freedesktop.DBus.Error.MatchRuleNotFound";
    pub const MATCH_RULE_INVALID: &str = "org.freedesktop.DBus.Error.MatchRuleInvalid";
    pub const SPAWN_SERVICE_NOT_FOUND: &str = "org.freedesktop.DBus.Error.Spawn.ServiceNotFound";
    pub const SPAWN_EXEC_FAILED: &str = "org.freedesktop.DBus.Error.Spawn.ExecFailed";
    pub const SPAWN_PERMISSIONS_INVALID: &str =
        "org.freedesktop.DBus.Error.Spawn.PermissionsInvalid";
    pub const SPAWN_SERVICE_LINK_NOT_FOUND: &str =
        "org.freedesktop.DBus.Error.Spawn.ServiceLinkNotFound";
    pub const SPAWN_CONFIG_INVALID: &str = "org.freedesktop.DBus.Error.Spawn.ConfigInvalid";
    pub const SPAWN_NO_MEMORY: &str = "org.freedesktop.DBus.Error.Spawn.NoMemory";
    pub const OBJECT_PATH_IN_USE: &str = "org.freedesktop.DBus.Error.ObjectPathInUse";
    pub const INTERACTIVE_AUTHORIZATION_REQUIRED: &str =
        "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired";
}

// Validate dotted bus/interface/error name.
pub fn is_valid_dotted_name(s: &str, allow_leading_digit_after_hyphen: bool) -> bool {
    let _ = allow_leading_digit_after_hyphen;
    if s.is_empty() || s.len() > 255 || !s.contains('.') {
        return false;
    }
    for element in s.split('.') {
        if element.is_empty() {
            return false;
        }
        let mut chars = element.chars();
        let first = chars.next().unwrap();
        if !(first.is_ascii_alphabetic() || first == '_') {
            return false;
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    true
}

// Validate bus name.
pub fn is_valid_bus_name(s: &str) -> bool {
    if let Some(rest) = s.strip_prefix(':') {
        if rest.is_empty() || s.len() > 255 {
            return false;
        }
        return rest.split('.').all(|el| {
            !el.is_empty()
                && el
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        });
    }
    is_valid_dotted_name(s, false)
}

// Validate member name.
pub fn is_valid_member_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_name_validation() {
        assert!(is_valid_bus_name("org.freedesktop.DBus"));
        assert!(is_valid_bus_name(":1.42"));
        assert!(!is_valid_bus_name("nodots"));
        assert!(!is_valid_bus_name(".leadingdot"));
    }

    #[test]
    fn member_name_validation() {
        assert!(is_valid_member_name("Hello"));
        assert!(is_valid_member_name("_leading_underscore"));
        assert!(!is_valid_member_name("1leadingdigit"));
        assert!(!is_valid_member_name("has.dot"));
    }
}
