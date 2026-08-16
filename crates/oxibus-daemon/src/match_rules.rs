//! `AddMatch`/`RemoveMatch` rule parsing and matching (spec §Match Rules).

use oxibus_core::header::MessageType;
use oxibus_core::{errors, Message};

/// A parsed `AddMatch` rule. Every field is an optional filter; a `None`/
/// empty field imposes no constraint, so the default rule (all fields
/// unset) matches everything.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchRule {
    /// Restrict to this message type, if set.
    pub message_type: Option<MessageType>,
    /// Restrict to this sender, matched either against the message's
    /// unique-name sender directly or, if this is a well-known name,
    /// against whoever currently owns it (see [`MatchRule::matches`]).
    pub sender: Option<String>,
    /// Restrict to this interface.
    pub interface: Option<String>,
    /// Restrict to this member (method/signal name).
    pub member: Option<String>,
    /// Restrict to this exact object path.
    pub path: Option<String>,
    /// Restrict to object paths within this namespace (spec's
    /// `path_namespace=` prefix matching, mutually meaningful alongside but
    /// distinct from `path`).
    pub path_namespace: Option<String>,
    /// Restrict to this destination.
    pub destination: Option<String>,
    /// `(argN index, expected string value)` pairs; every listed index must
    /// match the message body's corresponding string argument. Index range
    /// 0..=63 per the spec.
    pub args: Vec<(usize, String)>,
    /// `(argN index, expected path value)` pairs for path prefix/subpath matching.
    pub arg_paths: Vec<(usize, String)>,
    /// Expected namespace for the 0th argument (arg0namespace).
    pub arg0namespace: Option<String>,
    /// Whether this rule opts the connection into eavesdropping (currently
    /// parsed but not separately enforced beyond ordinary match delivery).
    pub eavesdrop: bool,
    /// The raw rule string, used as the identity for `RemoveMatch` (spec:
    /// removal matches the exact rule text previously added).
    pub raw: String,
}

/// Parse an `AddMatch`-style rule string (`key='value',key2='value2'`) into
/// a [`MatchRule`]. Rejects unknown keys, malformed quoting, an out-of-range
/// `argN` index, or an unrecognized `type=` value; the raw string is
/// preserved on the returned rule for later `RemoveMatch` comparison.
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

/// Split `key='value',key2='value2'` honoring the spec's quoting rule: a
/// literal `'` inside a value is written as closing the quote, `\'`, then
/// reopening (`'don'\''t'`).
fn tokenize(s: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // key
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            return Err("match rule missing '=' after key".into());
        }
        let key = s[key_start..i].to_string();
        i += 1; // skip '='
        if i >= bytes.len() || bytes[i] != b'\'' {
            return Err("match rule value must be single-quoted".into());
        }
        i += 1; // skip opening quote
        let mut value = String::new();
        loop {
            if i >= bytes.len() {
                return Err("unterminated quoted value in match rule".into());
            }
            if bytes[i] == b'\'' {
                i += 1;
                // Escaped literal quote: '\'' -> check for that pattern.
                if i + 1 < bytes.len() && bytes[i] == b'\\' && bytes[i + 1] == b'\'' {
                    value.push('\'');
                    i += 2;
                    // Expect a fresh opening quote to continue the value.
                    if i < bytes.len() && bytes[i] == b'\'' {
                        i += 1;
                        continue;
                    } else {
                        return Err("malformed escaped quote in match rule".into());
                    }
                }
                break; // end of value
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
    /// Does `msg` (with its now-authoritative bus-stamped `sender`) satisfy
    /// this rule? `resolve_owner` looks up the current unique-name owner of
    /// a well-known bus name, for matching a `sender=` rule expressed as a
    /// well-known name against the connection's real unique name.
    pub fn matches(&self, msg: &Message, resolve_owner: impl Fn(&str) -> Option<String>) -> bool {
        if let Some(t) = self.message_type {
            if msg.message_type() != t {
                return false;
            }
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
        if let Some(iface) = &self.interface {
            if msg.interface() != Some(iface.as_str()) {
                return false;
            }
        }
        if let Some(member) = &self.member {
            if msg.member() != Some(member.as_str()) {
                return false;
            }
        }
        if let Some(path) = &self.path {
            if msg.path().map(|p| p.as_str()) != Some(path.as_str()) {
                return false;
            }
        }
        if let Some(ns) = &self.path_namespace {
            match msg.path() {
                Some(p) if p.is_within_namespace(ns) => {}
                _ => return false,
            }
        }
        if let Some(dest) = &self.destination {
            if msg.destination() != Some(dest.as_str()) {
                return false;
            }
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
    p1 == p2 || p1 == "/" || p2 == "/" || p1.starts_with(&format!("{}/", p2)) || p2.starts_with(&format!("{}/", p1))
}

fn value_as_str(msg: &Message, idx: usize) -> Option<&str> {
    msg.body.get(idx).and_then(|v| v.unwrap_variant().as_str())
}

/// Cheap size check for a raw match-rule string, independent of full
/// parsing: rejects anything over 4096 bytes with
/// [`oxibus_core::errors::MATCH_RULE_INVALID`].
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
