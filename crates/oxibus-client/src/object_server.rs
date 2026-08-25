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
