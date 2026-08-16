#![allow(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
//! Shared helpers for the `oxibus-tools` binaries: bus-address discovery
//! and simple `type:value` argument parsing (the `dbus-send` grammar).

use oxibus_core::{ArrayValue, Type, Value};

/// Which well-known bus a tool should connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusChoice {
    /// The system bus.
    System,
    /// The per-user session bus.
    Session,
}

/// Resolve which address to connect to, mirroring libdbus' discovery order:
/// an explicit `--address=`, then the well-known env var, then (system
/// bus only) the configured default socket path.
pub fn resolve_address(choice: BusChoice, explicit: Option<&str>) -> anyhow::Result<oxibus_core::Address> {
    if let Some(a) = explicit {
        return Ok(oxibus_core::Address::parse_one(a)?);
    }
    match choice {
        BusChoice::Session => {
            let env = std::env::var("OXIBUS_SESSION_BUS_ADDRESS")
                .or_else(|_| std::env::var("DBUS_SESSION_BUS_ADDRESS"))
                .map_err(|_| {
                    anyhow::anyhow!(
                        "OXIBUS_SESSION_BUS_ADDRESS (or DBUS_SESSION_BUS_ADDRESS) is not set"
                    )
                })?;
            Ok(oxibus_core::Address::parse_one(&env)?)
        }
        BusChoice::System => {
            if let Ok(env) = std::env::var("OXIBUS_SYSTEM_BUS_ADDRESS") {
                return Ok(oxibus_core::Address::parse_one(&env)?);
            }
            let cfg = oxibus_config::GlobalConfig::load_default();
            Ok(oxibus_core::Address::UnixPath(
                cfg.paths.system_socket().display().to_string(),
            ))
        }
    }
}

/// Parse one `type:value` CLI argument (dbus-send's scalar grammar; arrays
/// and containers aren't supported from the command line — build those
/// programmatically against `oxibus-client` instead).
pub fn parse_typed_arg(spec: &str) -> anyhow::Result<Value> {
    let (ty, val) = spec
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("argument '{spec}' is not in type:value form"))?;
    Ok(match ty {
        "string" => Value::String(val.to_string()),
        "objpath" => Value::ObjectPath(oxibus_core::ObjectPath::new(val)?),
        "boolean" => Value::Boolean(match val {
            "true" | "1" => true,
            "false" | "0" => false,
            other => anyhow::bail!("invalid boolean '{other}'"),
        }),
        "byte" => Value::Byte(val.parse()?),
        "int16" => Value::Int16(val.parse()?),
        "uint16" => Value::UInt16(val.parse()?),
        "int32" => Value::Int32(val.parse()?),
        "uint32" => Value::UInt32(val.parse()?),
        "int64" => Value::Int64(val.parse()?),
        "uint64" => Value::UInt64(val.parse()?),
        "double" => Value::Double(val.parse()?),
        "array" => {
            // array:string:a,b,c — element type + comma-separated values.
            let (elem_ty, list) = val
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("array needs an element type, e.g. array:string:a,b"))?;
            let elements: Vec<Value> = if list.is_empty() {
                Vec::new()
            } else {
                list.split(',')
                    .map(|v| parse_typed_arg(&format!("{elem_ty}:{v}")))
                    .collect::<Result<_, _>>()?
            };
            let element_type = match elem_ty {
                "string" => Type::String,
                "int32" => Type::Int32,
                "uint32" => Type::UInt32,
                "double" => Type::Double,
                other => anyhow::bail!("unsupported array element type '{other}'"),
            };
            Value::Array(ArrayValue::new(element_type, elements))
        }
        other => anyhow::bail!("unsupported type '{other}'"),
    })
}

/// Render a `Value` as `dbus-send`/`dbus-monitor`-style human-readable text,
/// e.g. `int32 42` or `array [string "a", string "b"]`.
pub fn format_value(v: &Value) -> String {
    match v {
        Value::Byte(b) => format!("byte {b}"),
        Value::Boolean(b) => format!("boolean {b}"),
        Value::Int16(i) => format!("int16 {i}"),
        Value::UInt16(i) => format!("uint16 {i}"),
        Value::Int32(i) => format!("int32 {i}"),
        Value::UInt32(i) => format!("uint32 {i}"),
        Value::Int64(i) => format!("int64 {i}"),
        Value::UInt64(i) => format!("uint64 {i}"),
        Value::Double(d) => format!("double {d}"),
        Value::String(s) => format!("string \"{s}\""),
        Value::ObjectPath(p) => format!("object path \"{}\"", p.as_str()),
        Value::Signature(s) => format!("signature \"{}\"", s.as_str()),
        Value::UnixFd(fd) => format!("unix fd {fd}"),
        Value::Array(arr) => {
            let items: Vec<String> = arr.elements.iter().map(format_value).collect();
            format!("array [{}]", items.join(", "))
        }
        Value::Struct(fields) => {
            let items: Vec<String> = fields.iter().map(format_value).collect();
            format!("struct {{{}}}", items.join(", "))
        }
        Value::DictEntry(k, v) => format!("dict entry({} {})", format_value(k), format_value(v)),
        Value::Variant(inner) => format!("variant {}", format_value(inner)),
    }
}
