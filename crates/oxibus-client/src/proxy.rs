//! A thin, repeatable handle onto one remote object — the common case of
//! "call methods / read properties on this one service+path+interface".

use oxibus_core::{well_known, ObjectPath, Value};

use crate::connection::Connection;
use crate::error::ClientResult;

/// A handle bound to one destination service, object path, and (optionally)
/// interface, for making repeated calls without repeating those arguments.
pub struct Proxy {
    connection: Connection,
    destination: String,
    path: ObjectPath,
    interface: Option<String>,
}

impl Proxy {
    /// Creates a proxy for `path` on `destination`, using `connection`.
    /// When `interface` is `Some`, it's sent as the INTERFACE header field
    /// on every call made through [`Proxy::call`]; when `None`, the callee
    /// resolves the method name against whichever interface at `path`
    /// defines it.
    pub fn new(
        connection: &Connection,
        destination: impl Into<String>,
        path: ObjectPath,
        interface: Option<String>,
    ) -> Self {
        Self {
            connection: connection.clone(),
            destination: destination.into(),
            path,
            interface,
        }
    }

    /// Calls method `member` on this proxy's interface with `args`,
    /// awaiting the reply. See [`Connection::call_method`] for the error
    /// conditions.
    pub async fn call(&self, member: &str, args: Vec<Value>) -> ClientResult<Vec<Value>> {
        self.connection
            .call_method(
                Some(&self.destination),
                self.path.clone(),
                self.interface.as_deref(),
                member,
                args,
            )
            .await
    }

    /// `org.freedesktop.DBus.Properties.Get` — reads property `name` on
    /// `interface`. Returns [`Value::String("")`](Value::String) if the
    /// reply's variant is somehow absent, rather than erroring.
    pub async fn get_property(&self, interface: &str, name: &str) -> ClientResult<Value> {
        let reply = self
            .connection
            .call_method(
                Some(&self.destination),
                self.path.clone(),
                Some(well_known::PROPERTIES_INTERFACE),
                "Get",
                vec![Value::string(interface), Value::string(name)],
            )
            .await?;
        Ok(reply
            .into_iter()
            .next()
            .map(|v| v.unwrap_variant().clone())
            .unwrap_or(Value::String(String::new())))
    }

    /// `org.freedesktop.DBus.Properties.Set` — writes property `name` on
    /// `interface` to `value`. Fails with [`ClientError::CallError`] if the
    /// property doesn't exist or is read-only.
    pub async fn set_property(&self, interface: &str, name: &str, value: Value) -> ClientResult<()> {
        self.connection
            .call_method(
                Some(&self.destination),
                self.path.clone(),
                Some(well_known::PROPERTIES_INTERFACE),
                "Set",
                vec![
                    Value::string(interface),
                    Value::string(name),
                    Value::Variant(Box::new(value)),
                ],
            )
            .await?;
        Ok(())
    }

    /// `org.freedesktop.DBus.Properties.GetAll` — reads every property on
    /// `interface`. Returns an empty vec (rather than erroring) if the
    /// reply body isn't the expected `a{sv}` array.
    pub async fn get_all_properties(&self, interface: &str) -> ClientResult<Vec<(String, Value)>> {
        let reply = self
            .connection
            .call_method(
                Some(&self.destination),
                self.path.clone(),
                Some(well_known::PROPERTIES_INTERFACE),
                "GetAll",
                vec![Value::string(interface)],
            )
            .await?;
        let mut out = Vec::new();
        if let Some(Value::Array(arr)) = reply.into_iter().next() {
            for el in arr.elements {
                if let Value::DictEntry(k, v) = el {
                    if let Some(key) = k.as_str() {
                        out.push((key.to_string(), v.unwrap_variant().clone()));
                    }
                }
            }
        }
        Ok(out)
    }

    /// `org.freedesktop.DBus.Introspectable.Introspect` — fetches the
    /// introspection XML for this proxy's object path. Returns an empty
    /// string if the reply body doesn't contain a string, rather than
    /// erroring.
    pub async fn introspect(&self) -> ClientResult<String> {
        let reply = self
            .connection
            .call_method(
                Some(&self.destination),
                self.path.clone(),
                Some(well_known::INTROSPECTABLE_INTERFACE),
                "Introspect",
                vec![],
            )
            .await?;
        Ok(reply
            .into_iter()
            .next()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default())
    }
}
