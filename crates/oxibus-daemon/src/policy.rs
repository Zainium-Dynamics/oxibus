//! TOML security policy — the Zainium replacement for D-Bus's XML
//! `<policy>` blocks in `system.conf`/`session.conf`. Same last-match-wins
//! evaluation model (spec §Message Bus Security, `bus/policy.c`), applied
//! per connection identity (uid / primary+supplementary gids), just
//! expressed as `[[rule]]` tables instead of XML.
//!
//! ```toml
//! [[rule]]
//! context = "default"
//! allow_own = ["*"]
//! allow_send = ["*"]
//! allow_receive = ["*"]
//!
//! [[rule]]
//! context = "user"
//! user = "messagebus"
//! allow_own = ["org.freedesktop.DBus"]
//! ```

use std::path::{Path, PathBuf};

use oxibus_core::header::MessageType;
use oxibus_core::Message;
use serde::Deserialize;

/// Which identities a [`PolicyRule`] applies to — evaluated in this order
/// (default, then user, then group, then mandatory) regardless of file or
/// declaration order, matching `bus/policy.c`'s context precedence.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Context {
    /// Applies to every connection; evaluated first, so any later context
    /// can override it.
    Default,
    /// Applies only when `user` matches the connection's resolved username
    /// or numeric uid.
    User,
    /// Applies only when `group` matches one of the connection's resolved
    /// group names.
    Group,
    /// Applies to every connection and is evaluated last, so it always has
    /// the final say for the fields it sets (mirrors `<policy
    /// context="mandatory">` in real dbus config).
    Mandatory,
}

/// One `[[rule]]` entry from a policy TOML file — a context selector plus
/// allow/deny glob lists for owning names and sending/receiving messages.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    /// Which identities this rule applies to.
    pub context: Context,
    /// Required when `context = "user"`: matched against the resolved
    /// username, or the uid as a decimal string.
    #[serde(default)]
    pub user: Option<String>,
    /// Required when `context = "group"`: matched against any of the
    /// connection's resolved group names.
    #[serde(default)]
    pub group: Option<String>,
    /// Bus-name glob patterns this rule permits owning.
    #[serde(default)]
    pub allow_own: Vec<String>,
    /// Bus-name glob patterns this rule forbids owning.
    #[serde(default)]
    pub deny_own: Vec<String>,
    /// Patterns this rule permits sending messages to.
    #[serde(default)]
    pub allow_send: Vec<SendReceivePattern>,
    /// Patterns this rule forbids sending messages to.
    #[serde(default)]
    pub deny_send: Vec<SendReceivePattern>,
    /// Patterns this rule permits receiving messages from.
    #[serde(default)]
    pub allow_receive: Vec<SendReceivePattern>,
    /// Patterns this rule forbids receiving messages from.
    #[serde(default)]
    pub deny_receive: Vec<SendReceivePattern>,
}

/// A send/receive filter. Bare strings (`"*"`, `"org.freedesktop.DBus"`) are
/// shorthand for `{ destination = "..." }`; the table form allows filtering
/// by interface/member/path too.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum SendReceivePattern {
    /// Shorthand form: a bare glob string, equivalent to `Full` with only
    /// `destination` set.
    Destination(String),
    /// Table form allowing the filter to also constrain interface, member,
    /// path, and/or message type; every field present must match for the
    /// pattern to apply.
    Full {
        /// Destination glob, matched against the other party's bus name
        /// (unset matches any destination).
        #[serde(default)]
        destination: Option<String>,
        /// Required interface, if set.
        #[serde(default)]
        interface: Option<String>,
        /// Required member (method/signal name), if set.
        #[serde(default)]
        member: Option<String>,
        /// Required exact object path, if set.
        #[serde(default)]
        path: Option<String>,
        /// Required message type as a string (`"method_call"`,
        /// `"method_return"`, `"signal"`, or `"error"`); an unrecognized
        /// value matches everything rather than rejecting the rule.
        #[serde(default)]
        r#type: Option<String>,
    },
}

impl SendReceivePattern {
    fn matches(&self, msg: &Message, other_party: Option<&str>) -> bool {
        match self {
            SendReceivePattern::Destination(pat) => {
                glob_match(pat, other_party.unwrap_or(""))
            }
            SendReceivePattern::Full {
                destination,
                interface,
                member,
                path,
                r#type,
            } => {
                if let Some(d) = destination {
                    if !glob_match(d, other_party.unwrap_or("")) {
                        return false;
                    }
                }
                if let Some(i) = interface {
                    if msg.interface() != Some(i.as_str()) {
                        return false;
                    }
                }
                if let Some(m) = member {
                    if msg.member() != Some(m.as_str()) {
                        return false;
                    }
                }
                if let Some(p) = path {
                    if msg.path().map(|x| x.as_str()) != Some(p.as_str()) {
                        return false;
                    }
                }
                if let Some(t) = r#type {
                    let matches_type = match t.as_str() {
                        "method_call" => msg.message_type() == MessageType::MethodCall,
                        "method_return" => msg.message_type() == MessageType::MethodReturn,
                        "signal" => msg.message_type() == MessageType::Signal,
                        "error" => msg.message_type() == MessageType::Error,
                        _ => true,
                    };
                    if !matches_type {
                        return false;
                    }
                }
                true
            }
        }
    }
}

/// Minimal glob: `*` matches any run of characters, everything else is
/// literal (sufficient for bus-name / interface patterns; no `?`/`[]`).
fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return text.starts_with(prefix);
    }
    pattern == text
}

#[derive(Debug, Clone, Deserialize, Default)]
struct PolicyFile {
    #[serde(default, rename = "rule")]
    rules: Vec<PolicyRule>,
}

/// Borrowed view of a connection's resolved identity, as evaluated against
/// policy rules. Mirrors [`crate::identity::Identity`]'s fields without
/// owning them, since callers typically already have an owned copy alive
/// for the duration of the policy check.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    /// The connection's uid.
    pub uid: u32,
    /// The connection's resolved username, if any.
    pub user_name: Option<&'a str>,
    /// The connection's resolved group names (primary and supplementary).
    pub group_names: &'a [String],
}

/// The full set of policy rules loaded for a bus, in file order. An empty
/// `Policy` (no `[[rule]]` entries loaded at all) is a distinguished
/// permissive state — see [`Policy::is_empty`] and the `can_*` methods.
#[derive(Default)]
pub struct Policy {
    rules: Vec<PolicyRule>,
}

impl Policy {
    /// Load and concatenate every `*.toml` and `*.conf` (XML) in `dir`, in filename order.
    pub fn load_dir(dir: &Path) -> std::io::Result<Self> {
        Self::load_dirs(&[dir.to_path_buf()])
    }

    /// Load and concatenate every `*.toml` and `*.conf` (XML) in the specified list of directories.
    pub fn load_dirs(dirs: &[PathBuf]) -> std::io::Result<Self> {
        let mut rules = Vec::new();
        for dir in dirs {
            if !dir.is_dir() {
                continue;
            }
            let mut paths: Vec<PathBuf> = Vec::new();
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str());
                if ext == Some("toml") || ext == Some("conf") {
                    paths.push(path);
                }
            }
            paths.sort();

            for path in paths {
                let text = std::fs::read_to_string(&path)?;
                let ext = path.extension().and_then(|e| e.to_str());
                if ext == Some("toml") {
                    match toml::from_str::<PolicyFile>(&text) {
                        Ok(f) => rules.extend(f.rules),
                        Err(e) => {
                            tracing::warn!("skipping malformed policy file {}: {e}", path.display());
                        }
                    }
                } else if ext == Some("conf") {
                    let parsed = parse_xml_policy(&text);
                    rules.extend(parsed);
                }
            }
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    fn applicable<'a>(&'a self, identity: &Identity) -> Vec<&'a PolicyRule> {
        let mut default_rules = Vec::new();
        let mut user_rules = Vec::new();
        let mut group_rules = Vec::new();
        let mut mandatory_rules = Vec::new();

        for rule in &self.rules {
            match rule.context {
                Context::Default => default_rules.push(rule),
                Context::User => {
                    if rule.user.as_deref() == identity.user_name
                        || rule.user.as_deref() == Some(&identity.uid.to_string())
                    {
                        user_rules.push(rule);
                    }
                }
                Context::Group => {
                    if let Some(g) = &rule.group {
                        if identity.group_names.iter().any(|gn| gn == g) {
                            group_rules.push(rule);
                        }
                    }
                }
                Context::Mandatory => mandatory_rules.push(rule),
            }
        }

        default_rules
            .into_iter()
            .chain(user_rules)
            .chain(group_rules)
            .chain(mandatory_rules)
            .collect()
    }

    /// Last-match-wins over `allow_own`/`deny_own` glob patterns. If no
    /// policy is configured at all, every name is ownable (permissive dev
    /// default — the session bus and a from-scratch system bus both ship
    /// with an empty `policy.d/` until the administrator opts in).
    pub fn can_own(&self, identity: &Identity, name: &str) -> bool {
        if self.is_empty() {
            return true;
        }
        let mut verdict = false;
        for rule in self.applicable(identity) {
            if rule.allow_own.iter().any(|p| glob_match(p, name)) {
                verdict = true;
            }
            if rule.deny_own.iter().any(|p| glob_match(p, name)) {
                verdict = false;
            }
        }
        verdict
    }

    pub fn can_send(&self, identity: &Identity, msg: &Message, destination: Option<&str>) -> bool {
        if self.is_empty() {
            return true;
        }
        let mut verdict = false;
        for rule in self.applicable(identity) {
            if rule.allow_send.iter().any(|p| p.matches(msg, destination)) {
                verdict = true;
            }
            if rule.deny_send.iter().any(|p| p.matches(msg, destination)) {
                verdict = false;
            }
        }
        verdict
    }

    pub fn can_receive(&self, identity: &Identity, msg: &Message, sender: Option<&str>) -> bool {
        if self.is_empty() {
            return true;
        }
        let mut verdict = false;
        for rule in self.applicable(identity) {
            if rule.allow_receive.iter().any(|p| p.matches(msg, sender)) {
                verdict = true;
            }
            if rule.deny_receive.iter().any(|p| p.matches(msg, sender)) {
                verdict = false;
            }
        }
        verdict
    }
}

#[derive(Debug, Clone)]
enum XmlToken {
    StartTag { name: String, attrs: std::collections::HashMap<String, String> },
    EndTag { name: String },
    SelfClosingTag { name: String, attrs: std::collections::HashMap<String, String> },
}

fn tokenize_xml(xml: &str) -> Vec<XmlToken> {
    let mut tokens = Vec::new();
    let mut chars = xml.char_indices().peekable();

    while let Some(&(_i, c)) = chars.peek() {
        if c == '<' {
            chars.next(); // consume '<'
            
            // Check for comment
            if let Some(&(_, '!')) = chars.peek() {
                chars.next(); // consume '!'
                if let Some(&(_, '-')) = chars.peek() {
                    chars.next(); // consume '-'
                    if let Some(&(_, '-')) = chars.peek() {
                        chars.next(); // consume '-'
                        // Skip until '-->'
                        while let Some(&(idx, ch)) = chars.peek() {
                            if ch == '-' && xml[idx..].starts_with("-->") {
                                chars.next(); // '-'
                                chars.next(); // '-'
                                chars.next(); // '>'
                                break;
                            }
                            chars.next();
                        }
                        continue;
                    }
                } else if let Some(&(_, '[')) = chars.peek() {
                    // Check CDATA or doctype
                    // Just skip until '>'
                    while let Some((_, ch)) = chars.next() {
                        if ch == '>' { break; }
                    }
                    continue;
                } else {
                    // Other <! like DOCTYPE, just skip until '>'
                    while let Some((_, ch)) = chars.next() {
                        if ch == '>' { break; }
                    }
                    continue;
                }
            }

            // It's a tag
            let mut is_end = false;
            if let Some(&(_, '/')) = chars.peek() {
                is_end = true;
                chars.next();
            }

            // Read tag name
            let mut tag_name = String::new();
            while let Some(&(_idx, ch)) = chars.peek() {
                if ch.is_whitespace() || ch == '>' || ch == '/' {
                    break;
                }
                tag_name.push(ch);
                chars.next();
            }

            let mut attrs = std::collections::HashMap::new();
            // Read attributes if not end tag
            if !is_end {
                loop {
                    // Skip whitespace
                    while let Some(&(_, ch)) = chars.peek() {
                        if ch.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    if let Some(&(_, ch)) = chars.peek() {
                        if ch == '>' || ch == '/' {
                            break;
                        }
                    } else {
                        break;
                    }

                    // Read attribute name
                    let mut attr_name = String::new();
                    while let Some(&(_idx, ch)) = chars.peek() {
                        if ch == '=' || ch.is_whitespace() || ch == '>' || ch == '/' {
                            break;
                        }
                        attr_name.push(ch);
                        chars.next();
                    }

                    // Skip whitespace and look for '='
                    while let Some(&(_, ch)) = chars.peek() {
                        if ch.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    if let Some(&(_, '=')) = chars.peek() {
                        chars.next(); // consume '='
                    } else {
                        continue; // invalid attribute, skip
                    }

                    // Skip whitespace and look for quote
                    while let Some(&(_, ch)) = chars.peek() {
                        if ch.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    let quote_char = if let Some(&(_, q)) = chars.peek() {
                        if q == '"' || q == '\'' {
                            chars.next();
                            q
                        } else {
                            '"' // default fallback
                        }
                    } else {
                        '"'
                    };

                    // Read attribute value
                    let mut attr_val = String::new();
                    while let Some((_, ch)) = chars.next() {
                        if ch == quote_char {
                            break;
                        }
                        attr_val.push(ch);
                    }

                    if !attr_name.is_empty() {
                        attrs.insert(attr_name, attr_val);
                    }
                }
            }

            // Read end of tag
            let mut is_self_closing = false;
            if let Some(&(_, '/')) = chars.peek() {
                is_self_closing = true;
                chars.next();
            }

            if let Some(&(_, '>')) = chars.peek() {
                chars.next();
            }

            if is_end {
                tokens.push(XmlToken::EndTag { name: tag_name });
            } else if is_self_closing {
                tokens.push(XmlToken::SelfClosingTag { name: tag_name, attrs });
            } else {
                tokens.push(XmlToken::StartTag { name: tag_name, attrs });
            }
        } else {
            // Text or other, just skip
            chars.next();
        }
    }

    tokens
}

fn parse_xml_policy(xml_content: &str) -> Vec<PolicyRule> {
    let tokens = tokenize_xml(xml_content);
    let mut rules = Vec::new();
    let mut current_policy_context: Option<(Context, Option<String>, Option<String>)> = None;

    for token in tokens {
        match token {
            XmlToken::StartTag { name, attrs } => {
                if name == "policy" {
                    let mut context = Context::Default;
                    let mut user = None;
                    let mut group = None;

                    if let Some(c) = attrs.get("context") {
                        context = match c.as_str() {
                            "default" => Context::Default,
                            "mandatory" => Context::Mandatory,
                            _ => Context::Default,
                        };
                    } else if let Some(u) = attrs.get("user") {
                        context = Context::User;
                        user = Some(u.clone());
                    } else if let Some(g) = attrs.get("group") {
                        context = Context::Group;
                        group = Some(g.clone());
                    }

                    current_policy_context = Some((context, user, group));
                } else if name == "allow" || name == "deny" {
                    if let Some((ref ctx, ref usr, ref grp)) = current_policy_context {
                        let is_allow = name == "allow";
                        let mut rule = PolicyRule {
                            context: ctx.clone(),
                            user: usr.clone(),
                            group: grp.clone(),
                            allow_own: Vec::new(),
                            deny_own: Vec::new(),
                            allow_send: Vec::new(),
                            deny_send: Vec::new(),
                            allow_receive: Vec::new(),
                            deny_receive: Vec::new(),
                        };

                        let mut has_applied = false;

                        // Ownership
                        if let Some(own) = attrs.get("own") {
                            if is_allow {
                                rule.allow_own.push(own.clone());
                            } else {
                                rule.deny_own.push(own.clone());
                            }
                            has_applied = true;
                        } else if let Some(own_prefix) = attrs.get("own_prefix") {
                            let pat = format!("{}*", own_prefix);
                            if is_allow {
                                rule.allow_own.push(pat);
                            } else {
                                rule.deny_own.push(pat);
                            }
                            has_applied = true;
                        }

                        // Send rules
                        let send_destination = attrs.get("send_destination");
                        let send_destination_prefix = attrs.get("send_destination_prefix");
                        let send_interface = attrs.get("send_interface");
                        let send_member = attrs.get("send_member");
                        let send_path = attrs.get("send_path");
                        let send_type = attrs.get("send_type");

                        if send_destination.is_some() || send_destination_prefix.is_some() || send_interface.is_some() || send_member.is_some() || send_path.is_some() || send_type.is_some() {
                            let dest = send_destination.cloned().or_else(|| {
                                send_destination_prefix.map(|p| format!("{}*", p))
                            });
                            
                            let pattern = SendReceivePattern::Full {
                                destination: dest,
                                interface: send_interface.cloned(),
                                member: send_member.cloned(),
                                path: send_path.cloned(),
                                r#type: send_type.cloned(),
                            };

                            if is_allow {
                                rule.allow_send.push(pattern);
                            } else {
                                rule.deny_send.push(pattern);
                            }
                            has_applied = true;
                        }

                        // Receive rules
                        let recv_sender = attrs.get("recv_sender");
                        let recv_sender_prefix = attrs.get("recv_sender_prefix");
                        let recv_interface = attrs.get("recv_interface");
                        let recv_member = attrs.get("recv_member");
                        let recv_path = attrs.get("recv_path");
                        let recv_type = attrs.get("recv_type");

                        if recv_sender.is_some() || recv_sender_prefix.is_some() || recv_interface.is_some() || recv_member.is_some() || recv_path.is_some() || recv_type.is_some() {
                            let sender = recv_sender.cloned().or_else(|| {
                                recv_sender_prefix.map(|p| format!("{}*", p))
                            });

                            let pattern = SendReceivePattern::Full {
                                destination: sender,
                                interface: recv_interface.cloned(),
                                member: recv_member.cloned(),
                                path: recv_path.cloned(),
                                r#type: recv_type.cloned(),
                            };

                            if is_allow {
                                rule.allow_receive.push(pattern);
                            } else {
                                rule.deny_receive.push(pattern);
                            }
                            has_applied = true;
                        }

                        if has_applied {
                            rules.push(rule);
                        }
                    }
                }
            }
            XmlToken::EndTag { name } => {
                if name == "policy" {
                    current_policy_context = None;
                }
            }
            XmlToken::SelfClosingTag { name, attrs } => {
                if (name == "allow" || name == "deny") && current_policy_context.is_some() {
                    let start_tok = XmlToken::StartTag { name, attrs };
                    match start_tok {
                        XmlToken::StartTag { name, attrs } => {
                            if let Some((ref ctx, ref usr, ref grp)) = current_policy_context {
                                let is_allow = name == "allow";
                                let mut rule = PolicyRule {
                                    context: ctx.clone(),
                                    user: usr.clone(),
                                    group: grp.clone(),
                                    allow_own: Vec::new(),
                                    deny_own: Vec::new(),
                                    allow_send: Vec::new(),
                                    deny_send: Vec::new(),
                                    allow_receive: Vec::new(),
                                    deny_receive: Vec::new(),
                                };

                                let mut has_applied = false;

                                // Ownership
                                if let Some(own) = attrs.get("own") {
                                    if is_allow {
                                        rule.allow_own.push(own.clone());
                                    } else {
                                        rule.deny_own.push(own.clone());
                                    }
                                    has_applied = true;
                                } else if let Some(own_prefix) = attrs.get("own_prefix") {
                                    let pat = format!("{}*", own_prefix);
                                    if is_allow {
                                        rule.allow_own.push(pat);
                                    } else {
                                        rule.deny_own.push(pat);
                                    }
                                    has_applied = true;
                                }

                                // Send rules
                                let send_destination = attrs.get("send_destination");
                                let send_destination_prefix = attrs.get("send_destination_prefix");
                                let send_interface = attrs.get("send_interface");
                                let send_member = attrs.get("send_member");
                                let send_path = attrs.get("send_path");
                                let send_type = attrs.get("send_type");

                                if send_destination.is_some() || send_destination_prefix.is_some() || send_interface.is_some() || send_member.is_some() || send_path.is_some() || send_type.is_some() {
                                    let dest = send_destination.cloned().or_else(|| {
                                        send_destination_prefix.map(|p| format!("{}*", p))
                                    });
                                    
                                    let pattern = SendReceivePattern::Full {
                                        destination: dest,
                                        interface: send_interface.cloned(),
                                        member: send_member.cloned(),
                                        path: send_path.cloned(),
                                        r#type: send_type.cloned(),
                                    };

                                    if is_allow {
                                        rule.allow_send.push(pattern);
                                    } else {
                                        rule.deny_send.push(pattern);
                                    }
                                    has_applied = true;
                                }

                                // Receive rules
                                let recv_sender = attrs.get("recv_sender");
                                let recv_sender_prefix = attrs.get("recv_sender_prefix");
                                let recv_interface = attrs.get("recv_interface");
                                let recv_member = attrs.get("recv_member");
                                let recv_path = attrs.get("recv_path");
                                let recv_type = attrs.get("recv_type");

                                if recv_sender.is_some() || recv_sender_prefix.is_some() || recv_interface.is_some() || recv_member.is_some() || recv_path.is_some() || recv_type.is_some() {
                                    let sender = recv_sender.cloned().or_else(|| {
                                        recv_sender_prefix.map(|p| format!("{}*", p))
                                    });

                                    let pattern = SendReceivePattern::Full {
                                        destination: sender,
                                        interface: recv_interface.cloned(),
                                        member: recv_member.cloned(),
                                        path: recv_path.cloned(),
                                        r#type: recv_type.cloned(),
                                    };

                                    if is_allow {
                                        rule.allow_receive.push(pattern);
                                    } else {
                                        rule.deny_receive.push(pattern);
                                    }
                                    has_applied = true;
                                }

                                if has_applied {
                                    rules.push(rule);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_policy(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn empty_policy_allows_everything() {
        let dir = std::env::temp_dir().join(format!("oxibus-policy-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy = Policy::load_dir(&dir).unwrap();
        let id = Identity {
            uid: 1000,
            user_name: Some("alice"),
            group_names: &[],
        };
        assert!(policy.can_own(&id, "com.example.Anything"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn user_rule_overrides_default_deny() {
        let dir = std::env::temp_dir().join(format!("oxibus-policy-user-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_policy(
            &dir,
            "00-default.toml",
            r#"
[[rule]]
context = "default"
deny_own = ["*"]
"#,
        );
        write_policy(
            &dir,
            "10-messagebus.toml",
            r#"
[[rule]]
context = "user"
user = "messagebus"
allow_own = ["org.freedesktop.DBus"]
"#,
        );
        let policy = Policy::load_dir(&dir).unwrap();

        let bus_user = Identity {
            uid: 81,
            user_name: Some("messagebus"),
            group_names: &[],
        };
        assert!(policy.can_own(&bus_user, "org.freedesktop.DBus"));
        assert!(!policy.can_own(&bus_user, "com.example.Other"));

        let other_user = Identity {
            uid: 1000,
            user_name: Some("alice"),
            group_names: &[],
        };
        assert!(!policy.can_own(&other_user, "org.freedesktop.DBus"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_parse_xml_policy() {
        let xml = r#"
        <!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
         "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
        <busconfig>
          <!-- Comment test -->
          <policy context="default">
            <allow own="org.freedesktop.DBus"/>
            <deny send_destination="*"/>
            <allow recv_sender="*"/>
          </policy>
          <policy user="root">
            <allow own_prefix="org.freedesktop.Notifications"/>
            <allow send_destination="org.freedesktop.Notifications" send_interface="org.freedesktop.Notifications.Introspectable"/>
          </policy>
        </busconfig>
        "#;
        let rules = parse_xml_policy(xml);
        assert_eq!(rules.len(), 5);

        // Rule 0: allow own="org.freedesktop.DBus"
        assert_eq!(rules[0].context, Context::Default);
        assert_eq!(rules[0].allow_own, vec!["org.freedesktop.DBus".to_string()]);

        // Rule 1: deny send_destination="*"
        assert_eq!(rules[1].context, Context::Default);
        assert_eq!(rules[1].deny_send.len(), 1);
        if let SendReceivePattern::Full { destination, .. } = &rules[1].deny_send[0] {
            assert_eq!(destination.as_deref(), Some("*"));
        } else {
            panic!("Expected Full pattern");
        }

        // Rule 3: allow own_prefix="org.freedesktop.Notifications"
        assert_eq!(rules[3].context, Context::User);
        assert_eq!(rules[3].user.as_deref(), Some("root"));
        assert_eq!(rules[3].allow_own, vec!["org.freedesktop.Notifications*".to_string()]);
    }
}
