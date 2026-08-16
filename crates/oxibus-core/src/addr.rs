//! D-Bus server address strings, e.g.
//! `unix:path=/run/oxibus/system_bus_socket` or `unix:tmpdir=/tmp`.
//! A full address is a `;`-separated list of these (tried in order).

use crate::error::{CoreError, CoreResult};

/// A single parsed D-Bus server address (one entry of a `;`-separated address list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// `unix:path=...` — connect to a Unix domain socket bound to a filesystem path.
    UnixPath(String),
    /// `unix:abstract=...` — connect to a Unix domain socket in the Linux abstract namespace.
    UnixAbstract(String),
    /// `unix:tmpdir=...` — a directory in which the server creates a socket with a random name.
    UnixTmpdir(String),
    /// `tcp:host=...,port=...` — connect over TCP (unencrypted, for testing/non-Unix use).
    Tcp {
        /// Hostname or IP address to connect to; defaults to `localhost` if unspecified.
        host: String,
        /// TCP port to connect to.
        port: u16,
    },
}

impl Address {
    /// Parse a full `;`-separated address string into an ordered list of candidates,
    /// skipping empty entries. Per spec, clients try each entry in order until one connects.
    pub fn parse_list(s: &str) -> CoreResult<Vec<Address>> {
        s.split(';')
            .filter(|part| !part.is_empty())
            .map(Address::parse_one)
            .collect()
    }

    /// Parse a single `transport:key=value,...` address entry.
    pub fn parse_one(s: &str) -> CoreResult<Address> {
        let (transport, rest) = s
            .split_once(':')
            .ok_or_else(|| CoreError::InvalidAddress(s.to_string()))?;
        let kv = parse_kv(rest)?;
        match transport {
            "unix" => {
                if let Some(path) = kv.get("path") {
                    Ok(Address::UnixPath(unescape(path)))
                } else if let Some(abs) = kv.get("abstract") {
                    Ok(Address::UnixAbstract(unescape(abs)))
                } else if let Some(dir) = kv.get("tmpdir") {
                    Ok(Address::UnixTmpdir(unescape(dir)))
                } else {
                    Err(CoreError::InvalidAddress(s.to_string()))
                }
            }
            "tcp" => {
                let host = kv.get("host").cloned().unwrap_or_else(|| "localhost".into());
                let port: u16 = kv
                    .get("port")
                    .ok_or_else(|| CoreError::InvalidAddress(s.to_string()))?
                    .parse()
                    .map_err(|_| CoreError::InvalidAddress(s.to_string()))?;
                Ok(Address::Tcp { host, port })
            }
            other => Err(CoreError::InvalidAddress(format!(
                "unsupported transport '{other}' in '{s}'"
            ))),
        }
    }

    /// Render back to the wire address-string form, percent-escaping unsafe bytes
    /// in path/name components so the result round-trips through `parse_one`.
    pub fn to_address_string(&self) -> String {
        match self {
            Address::UnixPath(p) => format!("unix:path={}", escape(p)),
            Address::UnixAbstract(a) => format!("unix:abstract={}", escape(a)),
            Address::UnixTmpdir(d) => format!("unix:tmpdir={}", escape(d)),
            Address::Tcp { host, port } => format!("tcp:host={host},port={port}"),
        }
    }
}

fn parse_kv(rest: &str) -> CoreResult<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    for pair in rest.split(',') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| CoreError::InvalidAddress(rest.to_string()))?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
}

/// Percent-decode per the D-Bus address escaping rules.
fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let is_safe = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'/' | b'.' | b'\\');
        if is_safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unix_path() {
        let a = Address::parse_one("unix:path=/run/oxibus/system_bus_socket").unwrap();
        assert_eq!(a, Address::UnixPath("/run/oxibus/system_bus_socket".into()));
    }

    #[test]
    fn parse_unix_tmpdir() {
        let a = Address::parse_one("unix:tmpdir=/tmp").unwrap();
        assert_eq!(a, Address::UnixTmpdir("/tmp".into()));
    }

    #[test]
    fn parse_list_of_addresses() {
        let list = Address::parse_list(
            "unix:path=/run/oxibus/system_bus_socket;unix:abstract=/oxibus/fallback",
        )
        .unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn roundtrip_escaping() {
        let a = Address::UnixPath("/run/needs space".into());
        let s = a.to_address_string();
        let parsed = Address::parse_one(&s).unwrap();
        assert_eq!(parsed, a);
    }
}
