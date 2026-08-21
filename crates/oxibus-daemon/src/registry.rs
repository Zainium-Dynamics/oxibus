// Registry tracking connection entries and name ownership tables.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use oxibus_core::header::flags as msg_flags;
use oxibus_transport::{PeerCredentials, Writer};

use crate::match_rules::MatchRule;

pub const FLAG_ALLOW_REPLACEMENT: u32 = 0x1;
pub const FLAG_REPLACE_EXISTING: u32 = 0x2;
pub const FLAG_DO_NOT_QUEUE: u32 = 0x4;

pub const REQUEST_REPLY_PRIMARY_OWNER: u32 = 1;
pub const REQUEST_REPLY_IN_QUEUE: u32 = 2;
pub const REQUEST_REPLY_EXISTS: u32 = 3;
pub const REQUEST_REPLY_ALREADY_OWNER: u32 = 4;

pub const RELEASE_REPLY_RELEASED: u32 = 1;
pub const RELEASE_REPLY_NON_EXISTENT: u32 = 2;
pub const RELEASE_REPLY_NOT_OWNER: u32 = 3;

pub struct ConnectionEntry {
    pub unique_name: String,
    pub writer: Writer,
    pub credentials: PeerCredentials,
    pub security_label: Option<String>,
    pub match_rules: RwLock<Vec<MatchRule>>,
    pub is_monitor: AtomicBool,
    pub is_registered: AtomicBool,
}

#[derive(Clone)]
struct QueueEntry {
    unique_name: String,
    allow_replacement: bool,
    do_not_queue: bool,
}

#[derive(Default)]
struct NameOwnership {
    queue: Vec<QueueEntry>,
}

pub struct NameOwnerChange {
    pub name: String,
    pub old_owner: Option<String>,
    pub new_owner: Option<String>,
}

#[derive(Default)]
pub struct Registry {
    connections: RwLock<HashMap<String, Arc<ConnectionEntry>>>,
    names: RwLock<HashMap<String, NameOwnership>>,
    next_id: AtomicU64,
    incomplete: std::sync::atomic::AtomicU32,
}

impl Registry {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            names: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            incomplete: std::sync::atomic::AtomicU32::new(0),
        }
    }

    pub fn try_begin_incomplete(&self, max: u32) -> bool {
        loop {
            let current = self.incomplete.load(Ordering::Relaxed);
            if current >= max {
                return false;
            }
            if self
                .incomplete
                .compare_exchange(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    pub fn end_incomplete(&self) {
        self.incomplete.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn allocate_unique_name(&self) -> String {
        format!(":1.{}", self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    pub fn add_connection(&self, entry: Arc<ConnectionEntry>) {
        self.connections
            .write()
            .unwrap()
            .insert(entry.unique_name.clone(), entry);
    }

    pub fn get(&self, unique_name: &str) -> Option<Arc<ConnectionEntry>> {
        self.connections.read().unwrap().get(unique_name).cloned()
    }

    pub fn all_connections(&self) -> Vec<Arc<ConnectionEntry>> {
        self.connections.read().unwrap().values().cloned().collect()
    }

    pub fn connection_count(&self) -> usize {
        self.connections.read().unwrap().len()
    }

    pub fn connection_count_for_uid(&self, uid: u32) -> usize {
        self.connections
            .read()
            .unwrap()
            .values()
            .filter(|c| c.credentials.uid == uid)
            .count()
    }

    pub fn remove_connection(&self, unique_name: &str) -> Vec<NameOwnerChange> {
        self.connections.write().unwrap().remove(unique_name);

        let mut events = Vec::new();
        let names_snapshot: Vec<String> = self.names.read().unwrap().keys().cloned().collect();
        for name in names_snapshot {
            if let Some(ev) = self.release_name_internal(unique_name, &name) {
                events.push(ev);
            }
        }
        events.push(NameOwnerChange {
            name: unique_name.to_string(),
            old_owner: Some(unique_name.to_string()),
            new_owner: None,
        });
        events
    }

    pub fn list_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self.connections.read().unwrap().keys().cloned().collect();
        out.extend(
            self.names
                .read()
                .unwrap()
                .iter()
                .filter(|(_, o)| !o.queue.is_empty())
                .map(|(n, _)| n.clone()),
        );
        out
    }

    pub fn name_has_owner(&self, name: &str) -> bool {
        self.get_name_owner(name).is_some()
    }

    pub fn get_name_owner(&self, name: &str) -> Option<String> {
        if name.starts_with(':') {
            return self
                .connections
                .read()
                .unwrap()
                .contains_key(name)
                .then(|| name.to_string());
        }
        self.names
            .read()
            .unwrap()
            .get(name)
            .and_then(|o| o.queue.first())
            .map(|e| e.unique_name.clone())
    }

    pub fn names_held_by(&self, unique_name: &str) -> usize {
        self.names
            .read()
            .unwrap()
            .values()
            .filter(|o| o.queue.iter().any(|e| e.unique_name == unique_name))
            .count()
    }

    pub fn list_queued_owners(&self, name: &str) -> Vec<String> {
        self.names
            .read()
            .unwrap()
            .get(name)
            .map(|o| o.queue.iter().map(|e| e.unique_name.clone()).collect())
            .unwrap_or_default()
    }

    pub fn request_name(
        &self,
        unique_name: &str,
        name: &str,
        request_flags: u32,
    ) -> (u32, Vec<NameOwnerChange>) {
        let mut names = self.names.write().unwrap();
        let entry = names.entry(name.to_string()).or_default();

        if let Some(primary) = entry.queue.first() {
            if primary.unique_name == unique_name {
                return (REQUEST_REPLY_ALREADY_OWNER, Vec::new());
            }

            let can_replace =
                request_flags & FLAG_REPLACE_EXISTING != 0 && primary.allow_replacement;

            if can_replace {
                let old_owner = primary.unique_name.clone();
                let old_do_not_queue = primary.do_not_queue;
                entry.queue.retain(|e| e.unique_name != unique_name);
                let displaced = entry.queue.remove(0);
                entry.queue.insert(
                    0,
                    QueueEntry {
                        unique_name: unique_name.to_string(),
                        allow_replacement: request_flags & FLAG_ALLOW_REPLACEMENT != 0,
                        do_not_queue: request_flags & FLAG_DO_NOT_QUEUE != 0,
                    },
                );
                if !old_do_not_queue {
                    entry.queue.push(displaced);
                }
                return (
                    REQUEST_REPLY_PRIMARY_OWNER,
                    vec![NameOwnerChange {
                        name: name.to_string(),
                        old_owner: Some(old_owner),
                        new_owner: Some(unique_name.to_string()),
                    }],
                );
            }

            if request_flags & FLAG_DO_NOT_QUEUE != 0 {
                return (REQUEST_REPLY_EXISTS, Vec::new());
            }

            if !entry.queue.iter().any(|e| e.unique_name == unique_name) {
                entry.queue.push(QueueEntry {
                    unique_name: unique_name.to_string(),
                    allow_replacement: request_flags & FLAG_ALLOW_REPLACEMENT != 0,
                    do_not_queue: false,
                });
            }
            return (REQUEST_REPLY_IN_QUEUE, Vec::new());
        }

        entry.queue.push(QueueEntry {
            unique_name: unique_name.to_string(),
            allow_replacement: request_flags & FLAG_ALLOW_REPLACEMENT != 0,
            do_not_queue: request_flags & FLAG_DO_NOT_QUEUE != 0,
        });
        (
            REQUEST_REPLY_PRIMARY_OWNER,
            vec![NameOwnerChange {
                name: name.to_string(),
                old_owner: None,
                new_owner: Some(unique_name.to_string()),
            }],
        )
    }

    pub fn release_name(&self, unique_name: &str, name: &str) -> (u32, Vec<NameOwnerChange>) {
        let exists = self.names.read().unwrap().contains_key(name);
        if !exists {
            return (RELEASE_REPLY_NON_EXISTENT, Vec::new());
        }
        let owns_or_queued = self
            .names
            .read()
            .unwrap()
            .get(name)
            .map(|o| o.queue.iter().any(|e| e.unique_name == unique_name))
            .unwrap_or(false);
        if !owns_or_queued {
            return (RELEASE_REPLY_NOT_OWNER, Vec::new());
        }
        let events = self
            .release_name_internal(unique_name, name)
            .into_iter()
            .collect();
        (RELEASE_REPLY_RELEASED, events)
    }

    fn release_name_internal(&self, unique_name: &str, name: &str) -> Option<NameOwnerChange> {
        let mut names = self.names.write().unwrap();
        let entry = names.get_mut(name)?;
        let was_primary = entry.queue.first().map(|e| e.unique_name.as_str()) == Some(unique_name);
        let had_entry = entry.queue.iter().any(|e| e.unique_name == unique_name);
        if !had_entry {
            return None;
        }
        entry.queue.retain(|e| e.unique_name != unique_name);

        if !was_primary {
            if entry.queue.is_empty() {
                names.remove(name);
            }
            return None;
        }

        let new_owner = entry.queue.first().map(|e| e.unique_name.clone());
        if entry.queue.is_empty() {
            names.remove(name);
        }
        Some(NameOwnerChange {
            name: name.to_string(),
            old_owner: Some(unique_name.to_string()),
            new_owner,
        })
    }
}

pub fn no_reply_expected(msg: &oxibus_core::Message) -> bool {
    msg.header.flags & msg_flags::NO_REPLY_EXPECTED != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_requester_becomes_primary_owner() {
        let reg = Registry::new();
        let (code, events) = reg.request_name(":1.1", "com.example.Foo", 0);
        assert_eq!(code, REQUEST_REPLY_PRIMARY_OWNER);
        assert_eq!(events.len(), 1);
        assert_eq!(reg.get_name_owner("com.example.Foo").as_deref(), Some(":1.1"));
    }

    #[test]
    fn second_requester_without_queueing_flag_gets_exists() {
        let reg = Registry::new();
        reg.request_name(":1.1", "com.example.Foo", 0);
        let (code, events) = reg.request_name(":1.2", "com.example.Foo", FLAG_DO_NOT_QUEUE);
        assert_eq!(code, REQUEST_REPLY_EXISTS);
        assert!(events.is_empty());
    }

    #[test]
    fn second_requester_queues_by_default() {
        let reg = Registry::new();
        reg.request_name(":1.1", "com.example.Foo", 0);
        let (code, _) = reg.request_name(":1.2", "com.example.Foo", 0);
        assert_eq!(code, REQUEST_REPLY_IN_QUEUE);
        assert_eq!(
            reg.list_queued_owners("com.example.Foo"),
            vec![":1.1".to_string(), ":1.2".to_string()]
        );
    }

    #[test]
    fn replace_existing_requires_allow_replacement() {
        let reg = Registry::new();
        reg.request_name(":1.1", "com.example.Foo", 0);
        let (code, events) =
            reg.request_name(":1.2", "com.example.Foo", FLAG_REPLACE_EXISTING);
        assert_eq!(code, REQUEST_REPLY_IN_QUEUE);
        assert!(events.is_empty());
    }

    #[test]
    fn replace_existing_succeeds_when_allowed() {
        let reg = Registry::new();
        reg.request_name(":1.1", "com.example.Foo", FLAG_ALLOW_REPLACEMENT);
        let (code, events) =
            reg.request_name(":1.2", "com.example.Foo", FLAG_REPLACE_EXISTING);
        assert_eq!(code, REQUEST_REPLY_PRIMARY_OWNER);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].old_owner.as_deref(), Some(":1.1"));
        assert_eq!(events[0].new_owner.as_deref(), Some(":1.2"));
        assert_eq!(
            reg.list_queued_owners("com.example.Foo"),
            vec![":1.2".to_string(), ":1.1".to_string()]
        );
    }

    #[test]
    fn release_promotes_next_in_queue() {
        let reg = Registry::new();
        reg.request_name(":1.1", "com.example.Foo", 0);
        reg.request_name(":1.2", "com.example.Foo", 0);
        let (code, events) = reg.release_name(":1.1", "com.example.Foo");
        assert_eq!(code, RELEASE_REPLY_RELEASED);
        assert_eq!(events[0].new_owner.as_deref(), Some(":1.2"));
        assert_eq!(reg.get_name_owner("com.example.Foo").as_deref(), Some(":1.2"));
    }

    #[test]
    fn remove_connection_releases_all_its_names() {
        let reg = Registry::new();
        reg.request_name(":1.1", "com.example.Foo", 0);
        reg.request_name(":1.1", "com.example.Bar", 0);
        let events = reg.remove_connection(":1.1");
        assert!(events.iter().any(|e| e.name == "com.example.Foo"));
        assert!(events.iter().any(|e| e.name == "com.example.Bar"));
        assert!(!reg.name_has_owner("com.example.Foo"));
    }

    #[test]
    fn names_held_by_counts_owned_and_queued() {
        let reg = Registry::new();
        reg.request_name(":1.1", "com.example.Foo", 0);
        reg.request_name(":1.1", "com.example.Bar", 0);
        reg.request_name(":1.2", "com.example.Bar", 0);
        assert_eq!(reg.names_held_by(":1.1"), 2);
        assert_eq!(reg.names_held_by(":1.2"), 1);
        assert_eq!(reg.names_held_by(":1.3"), 0);
    }
}
