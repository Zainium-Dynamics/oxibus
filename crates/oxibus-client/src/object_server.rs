// Server-side object tree for Connection dispatching.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use oxibus_core::{ObjectPath, Value};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type MethodResult = Result<Vec<Value>, MethodError>;

#[derive(Debug, Clone)]
pub struct MethodError {
    pub name: String,
    pub message: String,
}

impl MethodError {
    pub fn new(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            message: message.into(),
        }
    }

    pub fn unknown_method(member: &str, interface: &str) -> Self {
        Self::new(
            oxibus_core::errors::UNKNOWN_METHOD,
            format!("No such method \"{member}\" on interface \"{interface}\""),
        )
    }

    pub fn unknown_interface(interface: &str) -> Self {
        Self::new(
            oxibus_core::errors::UNKNOWN_INTERFACE,
            format!("No such interface \"{interface}\""),
        )
    }

    pub fn unknown_object(path: &str) -> Self {
        Self::new(
            oxibus_core::errors::UNKNOWN_OBJECT,
            format!("No such object path \"{path}\""),
        )
    }

    pub fn invalid_args(msg: impl Into<String>) -> Self {
        Self::new(oxibus_core::errors::INVALID_ARGS, msg.into())
    }
}

pub trait Interface: Send + Sync {
    fn name(&self) -> &str;
    fn introspection_xml(&self) -> String;
    fn call<'a>(&'a self, member: &'a str, args: &'a [Value]) -> BoxFuture<'a, MethodResult>;

    fn get_property(&self, _name: &str) -> Option<Value> {
        None
    }

    fn set_property(&self, name: &str, _value: Value) -> Result<(), MethodError> {
        Err(MethodError::new(
            oxibus_core::errors::UNKNOWN_PROPERTY,
            format!("No such property \"{name}\""),
        ))
    }

    fn list_properties(&self) -> Vec<(String, Value)> {
        Vec::new()
    }

    /// `<property>` tags for everything `list_properties()` reports,
    /// with the type signature inferred from each `Value` itself. Access
    /// is always `readwrite` — `list_properties()` alone can't say which
    /// properties `set_property` actually accepts, and claiming
    /// read-only for a writable one is the worse of the two wrong
    /// guesses. Splice this into `introspection_xml()`'s own
    /// `<interface>` block, or just don't write any `<property>` tags
    /// there yourself and let [`ObjectServer::introspect`] append this
    /// automatically (see its doc).
    fn properties_xml(&self) -> String {
        let mut xml = String::new();
        for (name, value) in self.list_properties() {
            let sig = value.value_type().to_signature_string();
            xml.push_str(&format!(
                "<property name=\"{name}\" type=\"{sig}\" access=\"readwrite\"/>"
            ));
        }
        xml
    }
}

/// Inserts `properties_xml` right before `iface_xml`'s closing
/// `</interface>`. No-op if `iface_xml` already has its own
/// `<property` tags (manual wins over automatic) or if there's nothing
/// to add.
fn splice_properties(iface_xml: &str, properties_xml: &str) -> String {
    if properties_xml.is_empty() || iface_xml.contains("<property") {
        return iface_xml.to_string();
    }
    match iface_xml.rfind("</interface>") {
        Some(idx) => format!(
            "{}{}{}",
            &iface_xml[..idx],
            properties_xml,
            &iface_xml[idx..]
        ),
        None => iface_xml.to_string(),
    }
}

// path -> (interface name -> handler)
type ObjectMap = HashMap<String, HashMap<String, Arc<dyn Interface>>>;

#[derive(Default)]
pub struct ObjectServer {
    objects: RwLock<ObjectMap>,
}

impl ObjectServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, path: &ObjectPath, iface: Arc<dyn Interface>) {
        let mut objects = self.objects.write().unwrap();
        objects
            .entry(path.as_str().to_string())
            .or_default()
            .insert(iface.name().to_string(), iface);
    }

    pub fn unregister(&self, path: &str, interface: &str) {
        let mut objects = self.objects.write().unwrap();
        if let Some(ifaces) = objects.get_mut(path) {
            ifaces.remove(interface);
            if ifaces.is_empty() {
                objects.remove(path);
            }
        }
    }

    pub fn has_path(&self, path: &str) -> bool {
        self.objects.read().unwrap().contains_key(path)
    }

    pub fn get_interface(&self, path: &str, interface: &str) -> Option<Arc<dyn Interface>> {
        let objects = self.objects.read().unwrap();
        objects.get(path)?.get(interface).cloned()
    }

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
                let first = candidates
                    .next()
                    .ok_or_else(|| MethodError::unknown_method(member, "<no interface>"))?;
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

    /// Full introspection XML for `path`: each registered interface's
    /// `introspection_xml()`, with `<property>` tags auto-appended from
    /// `list_properties()` if the interface didn't already write its
    /// own, plus `<node>` entries for child paths.
    pub fn introspect(&self, path: &str) -> String {
        let objects = self.objects.read().unwrap();
        let mut xml = String::new();
        xml.push_str(
            "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n",
        );
        xml.push_str(" \"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n");
        xml.push_str("<node>\n");

        if let Some(ifaces) = objects.get(path) {
            for iface in ifaces.values() {
                xml.push_str(&splice_properties(
                    &iface.introspection_xml(),
                    &iface.properties_xml(),
                ));
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

#[cfg(test)]
mod tests {
    use super::*;

    struct WithProperties;
    impl Interface for WithProperties {
        fn name(&self) -> &str {
            "com.example.Battery"
        }
        fn introspection_xml(&self) -> String {
            "<interface name=\"com.example.Battery\"><method name=\"Refresh\"/></interface>".into()
        }
        fn call<'a>(&'a self, member: &'a str, _args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
            Box::pin(async move { Err(MethodError::unknown_method(member, self.name())) })
        }
        fn list_properties(&self) -> Vec<(String, Value)> {
            vec![("Percentage".to_string(), Value::Double(42.0))]
        }
    }

    struct ManualProperties;
    impl Interface for ManualProperties {
        fn name(&self) -> &str {
            "com.example.Manual"
        }
        fn introspection_xml(&self) -> String {
            "<interface name=\"com.example.Manual\"><property name=\"Hand\" type=\"s\" access=\"read\"/></interface>".into()
        }
        fn call<'a>(&'a self, member: &'a str, _args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
            Box::pin(async move { Err(MethodError::unknown_method(member, self.name())) })
        }
        fn list_properties(&self) -> Vec<(String, Value)> {
            vec![("ShouldNotAppear".to_string(), Value::Boolean(true))]
        }
    }

    #[test]
    fn introspect_auto_appends_properties_when_none_written() {
        let os = ObjectServer::new();
        os.register(
            &ObjectPath::new("/battery").unwrap(),
            Arc::new(WithProperties),
        );
        let xml = os.introspect("/battery");
        assert!(xml.contains("<method name=\"Refresh\"/>"));
        assert!(xml.contains("<property name=\"Percentage\" type=\"d\" access=\"readwrite\"/>"));
        // spliced before the interface's own closing tag, not appended after it
        assert!(xml.find("<property").unwrap() < xml.find("</interface>").unwrap());
    }

    #[test]
    fn introspect_leaves_manual_properties_alone() {
        let os = ObjectServer::new();
        os.register(
            &ObjectPath::new("/manual").unwrap(),
            Arc::new(ManualProperties),
        );
        let xml = os.introspect("/manual");
        assert!(xml.contains("<property name=\"Hand\" type=\"s\" access=\"read\"/>"));
        assert!(!xml.contains("ShouldNotAppear"));
    }
}
