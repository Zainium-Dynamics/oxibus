#![allow(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
//! `oxibus-core` — the D-Bus wire protocol, implemented from the
//! Specification (not transliterated from libdbus' C). This is the shared
//! foundation for `oxibus-daemon`, `oxibus-client`, and `oxibus-tools`.

/// Bus address parsing (`unix:path=...`, `tcp:host=...`, etc.).
pub mod addr;
/// Error type shared across parsing, marshaling and address handling.
pub mod error;
/// Message header fields, flags and the fixed header layout.
pub mod header;
/// Marshaling of values into the D-Bus wire format.
pub mod marshal;
/// The `Message` type and builders for constructing method calls, returns, errors and signals.
pub mod message;
/// Type signature strings: parsing and validation.
pub mod signature;
/// D-Bus type system: `Type`, `Value`, `ObjectPath`, `Signature`.
pub mod types;
/// Unmarshaling of values out of the D-Bus wire format.
pub mod unmarshal;

pub use addr::Address;
pub use error::{CoreError, CoreResult};
pub use header::{flags, HeaderField, MessageHeader, MessageType, PROTOCOL_VERSION};
pub use message::{reply_to, Message, MessageBuilder, SerialGenerator};
pub use types::{ArrayValue, ObjectPath, Signature, Type, Value};

/// Well-known bus names, interfaces and object paths every implementation
/// must recognize (D-Bus spec §Message Bus Specifications).
pub mod well_known {
    /// Well-known name of the bus daemon itself.
    pub const BUS_NAME: &str = "org.freedesktop.DBus";
    /// Object path exposed by the bus daemon for bus-management calls.
    pub const BUS_PATH: &str = "/org/freedesktop/DBus";
    /// Interface for core bus-management methods (`Hello`, `RequestName`, ...).
    pub const BUS_INTERFACE: &str = "org.freedesktop.DBus";
    /// Interface for the message-monitoring API (`BecomeMonitor`).
    pub const MONITORING_INTERFACE: &str = "org.freedesktop.DBus.Monitoring";
    /// Interface for bus debug/statistics queries.
    pub const STATS_INTERFACE: &str = "org.freedesktop.DBus.Debug.Stats";
    /// Interface for the `Introspect` method.
    pub const INTROSPECTABLE_INTERFACE: &str = "org.freedesktop.DBus.Introspectable";
    /// Interface for `Get`/`Set`/`GetAll` property access.
    pub const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
    /// Interface for the `GetManagedObjects` object-manager pattern.
    pub const OBJECT_MANAGER_INTERFACE: &str = "org.freedesktop.DBus.ObjectManager";
    /// Interface for peer-to-peer methods (`Ping`, `GetMachineId`).
    pub const PEER_INTERFACE: &str = "org.freedesktop.DBus.Peer";

    /// Signal emitted to a connection when it gains ownership of a bus name.
    pub const NAME_ACQUIRED: &str = "NameAcquired";
    /// Signal emitted to a connection when it loses ownership of a bus name.
    pub const NAME_LOST: &str = "NameLost";
    /// Signal broadcast on the bus whenever a name's owner changes.
    pub const NAME_OWNER_CHANGED: &str = "NameOwnerChanged";
}

/// Standard D-Bus error names (spec §Error Names + libdbus conventions).
pub mod errors {
    /// Generic catch-all failure with no more specific error name.
    pub const FAILED: &str = "org.freedesktop.DBus.Error.Failed";
    /// Allocation failed on the bus/service side.
    pub const NO_MEMORY: &str = "org.freedesktop.DBus.Error.NoMemory";
    /// The name in a message's `DESTINATION` field has no owner and cannot be auto-started.
    pub const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
    /// The requested well-known name currently has no owner.
    pub const NAME_HAS_NO_OWNER: &str = "org.freedesktop.DBus.Error.NameHasNoOwner";
    /// A method call did not receive a reply before the connection closed.
    pub const NO_REPLY: &str = "org.freedesktop.DBus.Error.NoReply";
    /// An I/O error occurred on the underlying transport.
    pub const IO_ERROR: &str = "org.freedesktop.DBus.Error.IOError";
    /// A bus address could not be parsed or connected to.
    pub const BAD_ADDRESS: &str = "org.freedesktop.DBus.Error.BadAddress";
    /// The requested operation is not supported by this implementation.
    pub const NOT_SUPPORTED: &str = "org.freedesktop.DBus.Error.NotSupported";
    /// A configured resource limit (message size, fds, etc.) was exceeded.
    pub const LIMITS_EXCEEDED: &str = "org.freedesktop.DBus.Error.LimitsExceeded";
    /// The caller is not authorized (by policy) to perform this operation.
    pub const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
    /// SASL authentication with the bus failed.
    pub const AUTH_FAILED: &str = "org.freedesktop.DBus.Error.AuthFailed";
    /// No bus daemon is running at the given address.
    pub const NO_SERVER: &str = "org.freedesktop.DBus.Error.NoServer";
    /// The operation timed out.
    pub const TIMEOUT: &str = "org.freedesktop.DBus.Error.Timeout";
    /// No network access is available to reach the bus.
    pub const NO_NETWORK: &str = "org.freedesktop.DBus.Error.NoNetwork";
    /// The requested transport address is already in use.
    pub const ADDRESS_IN_USE: &str = "org.freedesktop.DBus.Error.AddressInUse";
    /// The connection was disconnected from the bus.
    pub const DISCONNECTED: &str = "org.freedesktop.DBus.Error.Disconnected";
    /// A method call's arguments did not match the expected signature.
    pub const INVALID_ARGS: &str = "org.freedesktop.DBus.Error.InvalidArgs";
    /// A referenced file does not exist.
    pub const FILE_NOT_FOUND: &str = "org.freedesktop.DBus.Error.FileNotFound";
    /// A file that was expected not to exist already exists.
    pub const FILE_EXISTS: &str = "org.freedesktop.DBus.Error.FileExists";
    /// The requested method does not exist on the target object/interface.
    pub const UNKNOWN_METHOD: &str = "org.freedesktop.DBus.Error.UnknownMethod";
    /// The message's object path does not exist on the destination.
    pub const UNKNOWN_OBJECT: &str = "org.freedesktop.DBus.Error.UnknownObject";
    /// The requested interface is not implemented by the target object.
    pub const UNKNOWN_INTERFACE: &str = "org.freedesktop.DBus.Error.UnknownInterface";
    /// The requested property does not exist on the interface.
    pub const UNKNOWN_PROPERTY: &str = "org.freedesktop.DBus.Error.UnknownProperty";
    /// An attempt was made to set a read-only property.
    pub const PROPERTY_READ_ONLY: &str = "org.freedesktop.DBus.Error.PropertyReadOnly";
    /// The operation timed out (used in place of `TIMEOUT` in some contexts).
    pub const TIMED_OUT: &str = "org.freedesktop.DBus.Error.TimedOut";
    /// No signal match rule matching the given parameters was found.
    pub const MATCH_RULE_NOT_FOUND: &str = "org.freedesktop.DBus.Error.MatchRuleNotFound";
    /// The given match rule is malformed or otherwise invalid.
    pub const MATCH_RULE_INVALID: &str = "org.freedesktop.DBus.Error.MatchRuleInvalid";
    /// Auto-starting a service failed because no matching service file was found.
    pub const SPAWN_SERVICE_NOT_FOUND: &str = "org.freedesktop.DBus.Error.Spawn.ServiceNotFound";
    /// Auto-starting a service failed because `exec()` of its binary failed.
    pub const SPAWN_EXEC_FAILED: &str = "org.freedesktop.DBus.Error.Spawn.ExecFailed";
    /// Auto-starting a service failed due to invalid permissions on its service file.
    pub const SPAWN_PERMISSIONS_INVALID: &str =
        "org.freedesktop.DBus.Error.Spawn.PermissionsInvalid";
    /// Auto-starting a service failed because a required symlink was missing or broken.
    pub const SPAWN_SERVICE_LINK_NOT_FOUND: &str =
        "org.freedesktop.DBus.Error.Spawn.ServiceLinkNotFound";
    /// Auto-starting a service failed due to invalid bus configuration.
    pub const SPAWN_CONFIG_INVALID: &str = "org.freedesktop.DBus.Error.Spawn.ConfigInvalid";
    /// Auto-starting a service failed due to an allocation failure.
    pub const SPAWN_NO_MEMORY: &str = "org.freedesktop.DBus.Error.Spawn.NoMemory";
    /// The object path is already registered by another object.
    pub const OBJECT_PATH_IN_USE: &str = "org.freedesktop.DBus.Error.ObjectPathInUse";
    /// The operation requires interactive authorization that was not granted.
    pub const INTERACTIVE_AUTHORIZATION_REQUIRED: &str =
        "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired";
}

/// Validate a bus/interface/error name against the D-Bus spec grammar
/// (dot-separated elements, each `[A-Za-z_][A-Za-z0-9_]*`, at least two
/// elements, total length <= 255). Used for INTERFACE, ERROR_NAME and the
/// well-known-name form of BUS names (not the `:x.y` unique form).
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

/// Validate a bus name, which is either `:` + unique-connection-name-body or
/// a well-known dotted name (dotted elements may start with a digit only in
/// the unique-name form, per spec).
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

/// Validate a member name (method, signal or property name): non-empty,
/// at most 255 bytes, `[A-Za-z_][A-Za-z0-9_]*` with no dots.
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
