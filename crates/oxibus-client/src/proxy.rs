// Proxy handle for remote object calls.

use oxibus_core::{ObjectPath, Value, well_known};

use crate::connection::Connection;
use crate::error::ClientResult;

pub struct Proxy {
    connection: Connection,
    destination: String,
    path: ObjectPath,
    interface: Option<String>,
}

impl Proxy {
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

    pub async fn set_property(
        &self,
        interface: &str,
        name: &str,
        value: Value,
    ) -> ClientResult<()> {
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
                if let Value::DictEntry(k, v) = el
                    && let Some(key) = k.as_str()
                {
                    out.push((key.to_string(), v.unwrap_variant().clone()));
                }
            }
        }
        Ok(out)
    }

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
