// TOML security policy evaluation (context precedence: default, user, group, mandatory).

use std::path::{Path, PathBuf};

use oxibus_core::Message;
use oxibus_core::header::MessageType;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Context {
    Default,
    User,
    Group,
    Mandatory,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub context: Context,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub allow_own: Vec<String>,
    #[serde(default)]
    pub deny_own: Vec<String>,
    #[serde(default)]
    pub allow_send: Vec<SendReceivePattern>,
    #[serde(default)]
    pub deny_send: Vec<SendReceivePattern>,
    #[serde(default)]
    pub allow_receive: Vec<SendReceivePattern>,
    #[serde(default)]
    pub deny_receive: Vec<SendReceivePattern>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum SendReceivePattern {
    Destination(String),
    Full {
        #[serde(default)]
        destination: Option<String>,
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        member: Option<String>,
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        r#type: Option<String>,
    },
}

impl SendReceivePattern {
    fn matches(&self, msg: &Message, other_party: Option<&str>) -> bool {
        match self {
            SendReceivePattern::Destination(pat) => glob_match(pat, other_party.unwrap_or("")),
            SendReceivePattern::Full {
                destination,
                interface,
                member,
                path,
                r#type,
            } => {
                if let Some(d) = destination
                    && !glob_match(d, other_party.unwrap_or(""))
                {
                    return false;
                }
                if let Some(i) = interface
                    && msg.interface() != Some(i.as_str())
                {
                    return false;
                }
                if let Some(m) = member
                    && msg.member() != Some(m.as_str())
                {
                    return false;
                }
                if let Some(p) = path
                    && msg.path().map(|x| x.as_str()) != Some(p.as_str())
                {
                    return false;
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

#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    pub uid: u32,
    pub user_name: Option<&'a str>,
    pub group_names: &'a [String],
}

#[derive(Default)]
pub struct Policy {
    rules: Vec<PolicyRule>,
}

impl Policy {
    pub fn load_dir(dir: &Path) -> std::io::Result<Self> {
        Self::load_dirs(&[dir.to_path_buf()])
    }

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
                            tracing::warn!(
                                "skipping malformed policy file {}: {e}",
                                path.display()
                            );
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
                    if let Some(g) = &rule.group
                        && identity.group_names.iter().any(|gn| gn == g)
                    {
                        group_rules.push(rule);
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
#[allow(clippy::enum_variant_names)] // "...Tag" reads clearer than dropping the suffix here
enum XmlToken {
    StartTag {
        name: String,
        attrs: std::collections::HashMap<String, String>,
    },
    EndTag {
        name: String,
    },
    SelfClosingTag {
        name: String,
        attrs: std::collections::HashMap<String, String>,
    },
}

fn tokenize_xml(xml: &str) -> Vec<XmlToken> {
    let mut tokens = Vec::new();
    let mut chars = xml.char_indices().peekable();

    while let Some(&(_i, c)) = chars.peek() {
        if c == '<' {
            chars.next();

            if let Some(&(_, '!')) = chars.peek() {
                chars.next();
                if let Some(&(_, '-')) = chars.peek() {
                    chars.next();
                    if let Some(&(_, '-')) = chars.peek() {
                        chars.next();
                        while let Some(&(idx, ch)) = chars.peek() {
                            if ch == '-' && xml[idx..].starts_with("-->") {
                                chars.next();
                                chars.next();
                                chars.next();
                                break;
                            }
                            chars.next();
                        }
                        continue;
                    }
                } else if let Some(&(_, '[')) = chars.peek() {
                    for (_, ch) in chars.by_ref() {
                        if ch == '>' {
                            break;
                        }
                    }
                    continue;
                } else {
                    for (_, ch) in chars.by_ref() {
                        if ch == '>' {
                            break;
                        }
                    }
                    continue;
                }
            }

            let mut is_end = false;
            if let Some(&(_, '/')) = chars.peek() {
                is_end = true;
                chars.next();
            }

            let mut tag_name = String::new();
            while let Some(&(_idx, ch)) = chars.peek() {
                if ch.is_whitespace() || ch == '>' || ch == '/' {
                    break;
                }
                tag_name.push(ch);
                chars.next();
            }

            let mut attrs = std::collections::HashMap::new();
            if !is_end {
                loop {
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

                    let mut attr_name = String::new();
                    while let Some(&(_idx, ch)) = chars.peek() {
                        if ch == '=' || ch.is_whitespace() || ch == '>' || ch == '/' {
                            break;
                        }
                        attr_name.push(ch);
                        chars.next();
                    }

                    while let Some(&(_, ch)) = chars.peek() {
                        if ch.is_whitespace() {
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    if let Some(&(_, '=')) = chars.peek() {
                        chars.next();
                    } else {
                        continue;
                    }

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
                            '"'
                        }
                    } else {
                        '"'
                    };

                    let mut attr_val = String::new();
                    for (_, ch) in chars.by_ref() {
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
                tokens.push(XmlToken::SelfClosingTag {
                    name: tag_name,
                    attrs,
                });
            } else {
                tokens.push(XmlToken::StartTag {
                    name: tag_name,
                    attrs,
                });
            }
        } else {
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
                } else if (name == "allow" || name == "deny")
                    && let Some((ref ctx, ref usr, ref grp)) = current_policy_context
                {
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

                    let send_destination = attrs.get("send_destination");
                    let send_destination_prefix = attrs.get("send_destination_prefix");
                    let send_interface = attrs.get("send_interface");
                    let send_member = attrs.get("send_member");
                    let send_path = attrs.get("send_path");
                    let send_type = attrs.get("send_type");

                    if send_destination.is_some()
                        || send_destination_prefix.is_some()
                        || send_interface.is_some()
                        || send_member.is_some()
                        || send_path.is_some()
                        || send_type.is_some()
                    {
                        let dest = send_destination
                            .cloned()
                            .or_else(|| send_destination_prefix.map(|p| format!("{}*", p)));

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

                    let recv_sender = attrs.get("recv_sender");
                    let recv_sender_prefix = attrs.get("recv_sender_prefix");
                    let recv_interface = attrs.get("recv_interface");
                    let recv_member = attrs.get("recv_member");
                    let recv_path = attrs.get("recv_path");
                    let recv_type = attrs.get("recv_type");

                    if recv_sender.is_some()
                        || recv_sender_prefix.is_some()
                        || recv_interface.is_some()
                        || recv_member.is_some()
                        || recv_path.is_some()
                        || recv_type.is_some()
                    {
                        let sender = recv_sender
                            .cloned()
                            .or_else(|| recv_sender_prefix.map(|p| format!("{}*", p)));

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
            XmlToken::EndTag { name } => {
                if name == "policy" {
                    current_policy_context = None;
                }
            }
            XmlToken::SelfClosingTag { name, attrs } => {
                if (name == "allow" || name == "deny") && current_policy_context.is_some() {
                    let start_tok = XmlToken::StartTag { name, attrs };
                    if let XmlToken::StartTag { name, attrs } = start_tok
                        && let Some((ref ctx, ref usr, ref grp)) = current_policy_context
                    {
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

                        let send_destination = attrs.get("send_destination");
                        let send_destination_prefix = attrs.get("send_destination_prefix");
                        let send_interface = attrs.get("send_interface");
                        let send_member = attrs.get("send_member");
                        let send_path = attrs.get("send_path");
                        let send_type = attrs.get("send_type");

                        if send_destination.is_some()
                            || send_destination_prefix.is_some()
                            || send_interface.is_some()
                            || send_member.is_some()
                            || send_path.is_some()
                            || send_type.is_some()
                        {
                            let dest = send_destination
                                .cloned()
                                .or_else(|| send_destination_prefix.map(|p| format!("{}*", p)));

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

                        let recv_sender = attrs.get("recv_sender");
                        let recv_sender_prefix = attrs.get("recv_sender_prefix");
                        let recv_interface = attrs.get("recv_interface");
                        let recv_member = attrs.get("recv_member");
                        let recv_path = attrs.get("recv_path");
                        let recv_type = attrs.get("recv_type");

                        if recv_sender.is_some()
                            || recv_sender_prefix.is_some()
                            || recv_interface.is_some()
                            || recv_member.is_some()
                            || recv_path.is_some()
                            || recv_type.is_some()
                        {
                            let sender = recv_sender
                                .cloned()
                                .or_else(|| recv_sender_prefix.map(|p| format!("{}*", p)));

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

        assert_eq!(rules[0].context, Context::Default);
        assert_eq!(rules[0].allow_own, vec!["org.freedesktop.DBus".to_string()]);

        assert_eq!(rules[1].context, Context::Default);
        assert_eq!(rules[1].deny_send.len(), 1);
        if let SendReceivePattern::Full { destination, .. } = &rules[1].deny_send[0] {
            assert_eq!(destination.as_deref(), Some("*"));
        } else {
            panic!("Expected Full pattern");
        }

        assert_eq!(rules[3].context, Context::User);
        assert_eq!(rules[3].user.as_deref(), Some("root"));
        assert_eq!(
            rules[3].allow_own,
            vec!["org.freedesktop.Notifications*".to_string()]
        );
    }
}
