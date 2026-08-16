//! Server-side object tree for a [`crate::Connection`] that wants to expose
//! methods/signals/properties of its own (used by activated services, and
//! by `oxibus-daemon` itself for the `org.freedesktop.DBus` driver object).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use oxibus_core::{ObjectPath, Value};

/// A boxed, `Send` future — the return type of [`Interface::call`], needed
/// since traits can't have `async fn` in an object-safe way.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// The result of dispatching a method call: the reply body's argument
/// values, or the [`MethodError`] to send back as a D-Bus `Error` reply.
pub type MethodResult = Result<Vec<Value>, MethodError>;

/// A D-Bus error reply: an error name plus a human-readable message, sent
/// back to the caller when a method call fails.
#[derive(Debug, Clone)]
pub struct MethodError {
    /// The D-Bus error name, e.g. `org.freedesktop.DBus.Error.Failed`.
    pub name: String,
    /// The human-readable message included in the error reply.
    pub message: String,
}

impl MethodError {
    /// Builds an error with an arbitrary D-Bus error name and message.
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            message: message.into(),
        }
    }

    /// `org.freedesktop.DBus.Error.UnknownMethod` — no method named
    /// `member` exists on `interface`.
    pub fn unknown_method(member: &str, interface: &str) -> Self {
        Self::new(
            oxibus_core::errors::UNKNOWN_METHOD,
            format!("No such method \"{member}\" on interface \"{interface}\""),
        )
    }

    /// `org.freedesktop.DBus.Error.UnknownInterface` — no such interface
    /// is registered at the target object path.
    pub fn unknown_interface(interface: &str) -> Self {
        Self::new(
            oxibus_core::errors::UNKNOWN_INTERFACE,
            format!("No such interface \"{interface}\""),
        )
    }

    /// `org.freedesktop.DBus.Error.UnknownObject` — no interface is
    /// registered at `path` at all.
    pub fn unknown_object(path: &str) -> Self {
        Self::new(
            oxibus_core::errors::UNKNOWN_OBJECT,
            format!("No such object path \"{path}\""),
        )
    }

    /// `org.freedesktop.DBus.Error.InvalidArgs` — the call's arguments
    /// were malformed or ambiguous.
    pub fn invalid_args(msg: impl Into<String>) -> Self {
        Self::new(oxibus_core::errors::INVALID_ARGS, msg.into())
    }
}

/// One D-Bus interface implementation attached to an object path.
pub trait Interface: Send + Sync {
    /// The interface name, e.g. `com.example.Echo`.
    fn name(&self) -> &str;

    /// Full `<interface>...</interface>` introspection XML fragment for
    /// this interface (methods, signals, properties).
    fn introspection_xml(&self) -> String;

    /// Invokes method `member` with the given argument values, returning
    /// the reply body or a [`MethodError`]. Implementations should return
    /// [`MethodError::unknown_method`] for an unrecognized `member`.
    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult>;

    /// Reads a property value, or `None` if `_name` isn't a known
    /// property. The default implementation reports no properties.
    fn get_property(&self, _name: &str) -> Option<Value> {
        None
    }

    /// Writes a property value. The default implementation rejects every
    /// property with `org.freedesktop.DBus.Error.UnknownProperty`.
    fn set_property(&self, name: &str, _value: Value) -> Result<(), MethodError> {
        Err(MethodError::new(
            oxibus_core::errors::UNKNOWN_PROPERTY,
            format!("No such property \"{name}\""),
        ))
    }

    /// All property name/value pairs, used to answer
    /// `org.freedesktop.DBus.Properties.GetAll`. The default implementation
    /// reports no properties.
    fn list_properties(&self) -> Vec<(String, Value)> {
        Vec::new()
    }
}

/// A registry of objects (path -> interface implementations) that a
/// [`crate::Connection`] dispatches incoming method calls into.
#[derive(Default)]
pub struct ObjectServer {
    // path -> (interface name -> handler)
    objects: RwLock<HashMap<String, HashMap<String, Arc<dyn Interface>>>>,
}

impl ObjectServer {
    /// Creates an empty object server with no registered paths.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `iface` at `path`, keyed by [`Interface::name`]. Replaces
    /// any interface previously registered under the same name at the same
    /// path.
    pub fn register(&self, path: &ObjectPath, iface: Arc<dyn Interface>) {
        let mut objects = self.objects.write().unwrap();
        objects
            .entry(path.as_str().to_string())
            .or_default()
            .insert(iface.name().to_string(), iface);
    }

    /// Removes the interface named `interface` from `path`. Removes the
    /// path entirely once it has no interfaces left. No-op if `path` or
    /// `interface` isn't registered.
    pub fn unregister(&self, path: &str, interface: &str) {
        let mut objects = self.objects.write().unwrap();
        if let Some(ifaces) = objects.get_mut(path) {
            ifaces.remove(interface);
            if ifaces.is_empty() {
                objects.remove(path);
            }
        }
    }

    /// True if any interface is registered at `path`.
    pub fn has_path(&self, path: &str) -> bool {
        self.objects.read().unwrap().contains_key(path)
    }

    /// Returns the registered interface named `interface` at `path`, if any.
    pub fn get_interface(&self, path: &str, interface: &str) -> Option<Arc<dyn Interface>> {
        let objects = self.objects.read().unwrap();
        objects.get(path)?.get(interface).cloned()
    }

    /// Dispatch an incoming method call. `interface` is `None` when the
    /// caller omitted the INTERFACE header field (allowed by the spec —
    /// the method name is then resolved against whichever interface at
    /// this path defines it, erroring on ambiguity).
    pub async fn dispatch(
        &self,
        path: &str,
        interface: Option<&str>,
        member: &str,
        args: &[Value],
    ) -> MethodResult {
        let ifaces = {
            let objects = self.objects.read().unwrap();
            objects.get(path).cloned()
        };
        let Some(ifaces) = ifaces else {
            return Err(MethodError::unknown_object(path));
        };

        let target: Arc<dyn Interface> = match interface {
            Some(name) => ifaces
                .get(name)
                .cloned()
                .ok_or_else(|| MethodError::unknown_interface(name))?,
            None => {
                let mut candidates = ifaces.values();
                let first = candidates.next().ok_or_else(|| {
                    MethodError::unknown_method(member, "<no interface>")
                })?;
                if candidates.next().is_some() {
                    return Err(MethodError::invalid_args(
                        "ambiguous method call: multiple interfaces implement this member, specify INTERFACE",
                    ));
                }
                first.clone()
            }
        };

        target.call(member, args).await
    }

    /// Build introspection XML for `path`: this node's registered
    /// interfaces plus `<node>` children inferred from deeper registered
    /// paths (matches `org.freedesktop.DBus.Introspectable` semantics).
    pub fn introspect(&self, path: &str) -> String {
        let objects = self.objects.read().unwrap();
        let mut xml = String::new();
        xml.push_str("<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n");
        xml.push_str(" \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n");
        xml.push_str("<node>\n");

        if let Some(ifaces) = objects.get(path) {
            for iface in ifaces.values() {
                xml.push_str(&iface.introspection_xml());
                xml.push('\n');
            }
        }

        let prefix = if path == "/" {
            "/".to_string()
        } else {
            format!("{path}/")
        };
        let mut children: Vec<String> = Vec::new();
        for candidate in objects.keys() {
            if candidate == path {
                continue;
            }
            if let Some(rest) = candidate.strip_prefix(&prefix) {
                let child = rest.split('/').next().unwrap_or(rest);
                if !child.is_empty() && !children.contains(&child.to_string()) {
                    children.push(child.to_string());
                }
            }
        }
        for child in children {
            xml.push_str(&format!("  <node name=\"{child}\"/>\n"));
        }

        xml.push_str("</node>\n");
        xml
    }
}
