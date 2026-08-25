// Match rule parsing and message filtering.

use oxibus_core::header::MessageType;
use oxibus_core::{Message, errors};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchRule {
    pub message_type: Option<MessageType>,
    pub sender: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub path: Option<String>,
    pub path_namespace: Option<String>,
    pub destination: Option<String>,
    pub args: Vec<(usize, String)>,
    pub arg_paths: Vec<(usize, String)>,
    pub arg0namespace: Option<String>,
    pub eavesdrop: bool,
    pub raw: String,
}

pub fn parse_match_rule(s: &str) -> Result<MatchRule, String> {
    let mut rule = MatchRule {
        raw: s.to_string(),
        ..Default::default()
    };

    for (key, value) in tokenize(s)? {
        match key.as_str() {
            "type" => {
                rule.message_type = Some(match value.as_str() {
                    "signal" => MessageType::Signal,
                    "method_call" => MessageType::MethodCall,
                    "method_return" => MessageType::MethodReturn,
                    "error" => MessageType::Error,
                    other => return Err(format!("invalid match rule type '{other}'")),
                });
            }
            "sender" => rule.sender = Some(value),
            "interface" => rule.interface = Some(value),
            "member" => rule.member = Some(value),
            "path" => rule.path = Some(value),
            "path_namespace" => rule.path_namespace = Some(value),
            "destination" => rule.destination = Some(value),
            "eavesdrop" => rule.eavesdrop = value == "true",
            "arg0namespace" => rule.arg0namespace = Some(value),
            other if other.starts_with("arg") => {
                if other.ends_with("path") {
                    let idx_str = other.trim_start_matches("arg").trim_end_matches("path");
                    let idx: usize = idx_str
                        .parse()
                        .map_err(|_| format!("invalid match rule key '{other}'"))?;
                    if idx > 63 {
                        return Err("arg index must be 0..63".into());
                    }
                    rule.arg_paths.push((idx, value));
                } else {
                    let idx_str = other.trim_start_matches("arg");
                    let idx: usize = idx_str
                        .parse()
                        .map_err(|_| format!("invalid match rule key '{other}'"))?;
                    if idx > 63 {
                        return Err("arg index must be 0..63".into());
                    }
                    rule.args.push((idx, value));
                }
            }
            other => return Err(format!("unknown match rule key '{other}'")),
        }
    }

    Ok(rule)
}

fn tokenize(s: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            return Err("match rule missing '=' after key".into());
        }
        let key = s[key_start..i].to_string();
        i += 1;
        if i >= bytes.len() || bytes[i] != b'\'' {
            return Err("match rule value must be single-quoted".into());
        }
        i += 1;
        let mut value = String::new();
        loop {
            if i >= bytes.len() {
                return Err("unterminated quoted value in match rule".into());
            }
            if bytes[i] == b'\'' {
                i += 1;
                if i + 1 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'\'' {
                    value.push('\'');
                    i += 2;
                    if i < bytes.len() && bytes[i] == b'\'' {
                        i += 1;
                        continue;
                    } else {
                        return Err("malformed escaped quote in match rule".into());
                    }
                }
                break;
            }
            value.push(bytes[i] as char);
            i += 1;
        }
        out.push((key, value));
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
        }
    }
    Ok(out)
}

impl MatchRule {
    pub fn matches(&self, msg: &Message, resolve_owner: impl Fn(&str) -> Option<String>) -> bool {
        if let Some(t) = self.message_type
            && msg.message_type() != t
        {
            return false;
        }
        if let Some(sender) = &self.sender {
            let actual = msg.sender().unwrap_or("");
            let matches_directly = actual == sender;
            let matches_via_owner = if sender.starts_with(':') {
                false
            } else {
                resolve_owner(sender).as_deref() == Some(actual)
            };
            if !matches_directly && !matches_via_owner {
                return false;
            }
        }
        if let Some(iface) = &self.interface
            && msg.interface() != Some(iface.as_str())
        {
            return false;
        }
        if let Some(member) = &self.member
            && msg.member() != Some(member.as_str())
        {
            return false;
        }
        if let Some(path) = &self.path
            && msg.path().map(|p| p.as_str()) != Some(path.as_str())
        {
            return false;
        }
        if let Some(ns) = &self.path_namespace {
            match msg.path() {
                Some(p) if p.is_within_namespace(ns) => {}
                _ => return false,
            }
        }
        if let Some(dest) = &self.destination
            && msg.destination() != Some(dest.as_str())
        {
            return false;
        }
        for (idx, expected) in &self.args {
            if value_as_str(msg, *idx) != Some(expected.as_str()) {
                return false;
            }
        }
        for (idx, expected) in &self.arg_paths {
            let Some(val) = value_as_str(msg, *idx) else {
                return false;
            };
            if !is_path_parent_or_child(val, expected) {
                return false;
            }
        }
        if let Some(ns) = &self.arg0namespace {
            let Some(val) = value_as_str(msg, 0) else {
                return false;
            };
            if val != ns && !val.starts_with(&format!("{}.", ns)) {
                return false;
            }
        }
        true
    }
}

fn is_path_parent_or_child(p1: &str, p2: &str) -> bool {
    p1 == p2
        || p1 == "/"
        || p2 == "/"
        || p1.starts_with(&format!("{}/", p2))
        || p2.starts_with(&format!("{}/", p1))
}

fn value_as_str(msg: &Message, idx: usize) -> Option<&str> {
    msg.body.get(idx).and_then(|v| v.unwrap_variant().as_str())
}

pub fn validate_rule_string(s: &str) -> Result<(), &'static str> {
    if s.len() > 4096 {
        return Err(errors::MATCH_RULE_INVALID);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_owner_changed_rule() {
        let rule = parse_match_rule(
            "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'",
        )
        .unwrap();
        assert_eq!(rule.message_type, Some(MessageType::Signal));
        assert_eq!(rule.sender.as_deref(), Some("org.freedesktop.DBus"));
        assert_eq!(rule.member.as_deref(), Some("NameOwnerChanged"));
    }

    #[test]
    fn parses_escaped_quote() {
        let rule = parse_match_rule("member='don'\\''t'").unwrap();
        assert_eq!(rule.member.as_deref(), Some("don't"));
    }

    #[test]
    fn rejects_missing_quotes() {
        assert!(parse_match_rule("member=foo").is_err());
    }

    #[test]
    fn rejects_unknown_key() {
        assert!(parse_match_rule("bogus='x'").is_err());
    }

    #[test]
    fn parses_arg0namespace_and_arg_paths() {
        let rule = parse_match_rule("arg0namespace='com.example',arg3path='/a/b'").unwrap();
        assert_eq!(rule.arg0namespace.as_deref(), Some("com.example"));
        assert_eq!(rule.arg_paths, vec![(3, "/a/b".to_string())]);
    }

    #[test]
    fn matches_arg_path_hierarchy() {
        assert!(is_path_parent_or_child("/a/b/c", "/a/b"));
        assert!(is_path_parent_or_child("/a/b", "/a/b/c"));
        assert!(is_path_parent_or_child("/a/b", "/"));
        assert!(!is_path_parent_or_child("/a/b", "/a/bc"));
    }
}
