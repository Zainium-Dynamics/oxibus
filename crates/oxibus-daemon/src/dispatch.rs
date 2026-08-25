// Message routing, driver call handling, and policy enforcement.

use std::sync::Arc;

use oxibus_core::header::MessageType;
use oxibus_core::message::reply_to;
use oxibus_core::{Message, MessageBuilder, ObjectPath, Value, errors, well_known};

use crate::bus::Bus;
use crate::driver;
use crate::identity;
use crate::policy::Identity as PolicyIdentity;
use crate::registry::{ConnectionEntry, NameOwnerChange};

pub async fn dispatch_incoming(bus: &Arc<Bus>, sender: &Arc<ConnectionEntry>, mut msg: Message) {
    msg.set_sender(sender.unique_name.clone());
    let msg = msg;

    deliver_to_monitors(bus, &msg);

    if !sender
        .is_registered
        .load(std::sync::atomic::Ordering::SeqCst)
        && !is_hello_call(&msg)
    {
        reply_error(
            bus,
            sender,
            &msg,
            errors::ACCESS_DENIED,
            "Client tried to send a message other than Hello without being registered",
        )
        .await;
        return;
    }

    match msg.message_type() {
        MessageType::Signal => dispatch_signal(bus, sender, msg).await,
        MessageType::MethodCall => dispatch_method_call(bus, sender, msg).await,
        MessageType::MethodReturn | MessageType::Error => dispatch_reply(bus, msg).await,
    }
}

fn is_hello_call(msg: &Message) -> bool {
    msg.message_type() == MessageType::MethodCall
        && msg.destination() == Some(well_known::BUS_NAME)
        && matches!(msg.interface(), None | Some(well_known::BUS_INTERFACE))
        && msg.member() == Some("Hello")
}

fn deliver_to_monitors(bus: &Arc<Bus>, msg: &Message) {
    for conn in bus.registry.all_connections() {
        if conn.is_monitor.load(std::sync::atomic::Ordering::Relaxed) {
            let writer = conn.writer.clone();
            let msg = msg.clone();
            tokio::spawn(async move {
                let _ = writer.write_message(&msg).await;
            });
        }
    }
}

async fn dispatch_signal(bus: &Arc<Bus>, sender: &Arc<ConnectionEntry>, msg: Message) {
    let sender_identity_owned = identity::resolve(sender.credentials.uid);
    let sender_identity = PolicyIdentity {
        uid: sender_identity_owned.uid,
        user_name: sender_identity_owned.user_name.as_deref(),
        group_names: &sender_identity_owned.group_names,
    };
    if !bus
        .policy
        .read()
        .unwrap()
        .can_send(&sender_identity, &msg, msg.destination())
    {
        bus.stats.record_denial();
        return;
    }

    let bustype = match bus.kind {
        crate::BusKind::System => "system",
        crate::BusKind::Session => "session",
    };
    if !crate::apparmor::check_permission(
        crate::apparmor::AA_DBUS_SEND,
        sender.security_label.as_deref(),
        None,
        bustype,
        msg.destination(),
        msg.path().map(|p| p.as_str()),
        msg.interface(),
        msg.member(),
        sender.credentials.uid,
    ) {
        bus.stats.record_denial();
        return;
    }

    if let Some(dest) = msg.destination() {
        if let Some(owner) = bus.registry.get_name_owner(dest)
            && let Some(conn) = bus.registry.get(&owner)
        {
            let _ = conn.writer.write_message(&msg).await;
            bus.stats.record_signal();
        }
        return;
    }

    broadcast_signal(bus, &msg, true).await;
}

async fn broadcast_signal(bus: &Arc<Bus>, msg: &Message, enforce_policy: bool) {
    for conn in bus.registry.all_connections() {
        if conn.is_monitor.load(std::sync::atomic::Ordering::Relaxed) {
            continue;
        }
        let rules = conn.match_rules.read().unwrap().clone();
        if rules.is_empty() {
            continue;
        }
        let owner_lookup = |n: &str| bus.registry.get_name_owner(n);
        let matched = rules.iter().any(|r| r.matches(msg, owner_lookup));
        if !matched {
            continue;
        }
        if enforce_policy {
            let identity = identity::resolve(conn.credentials.uid);
            let policy_identity = PolicyIdentity {
                uid: identity.uid,
                user_name: identity.user_name.as_deref(),
                group_names: &identity.group_names,
            };
            if !bus
                .policy
                .read()
                .unwrap()
                .can_receive(&policy_identity, msg, msg.sender())
            {
                continue;
            }

            let bustype = match bus.kind {
                crate::BusKind::System => "system",
                crate::BusKind::Session => "session",
            };
            let sender_conn = msg.sender().and_then(|s| bus.registry.get(s));
            if !crate::apparmor::check_permission(
                crate::apparmor::AA_DBUS_RECEIVE,
                conn.security_label.as_deref(),
                sender_conn
                    .as_ref()
                    .and_then(|c| c.security_label.as_deref()),
                bustype,
                msg.destination(),
                msg.path().map(|p| p.as_str()),
                msg.interface(),
                msg.member(),
                conn.credentials.uid,
            ) {
                continue;
            }
        }
        let _ = conn.writer.write_message(msg).await;
        bus.stats.record_signal();
    }
}

async fn dispatch_reply(bus: &Arc<Bus>, msg: Message) {
    let Some(dest) = msg.destination() else {
        return;
    };
    if let Some(owner) = bus.registry.get_name_owner(dest)
        && let Some(conn) = bus.registry.get(&owner)
    {
        let _ = conn.writer.write_message(&msg).await;
        bus.stats
            .record_routed(msg.to_bytes().map(|b| b.len() as u64).unwrap_or(0));
    }
}

async fn dispatch_method_call(bus: &Arc<Bus>, sender: &Arc<ConnectionEntry>, msg: Message) {
    let Some(dest) = msg.destination() else {
        reply_error(
            bus,
            sender,
            &msg,
            errors::BAD_ADDRESS,
            "Method call missing DESTINATION",
        )
        .await;
        return;
    };

    if dest == well_known::BUS_NAME {
        handle_driver_call(bus, sender, msg).await;
        return;
    }

    let sender_identity_owned = identity::resolve(sender.credentials.uid);
    let sender_identity = PolicyIdentity {
        uid: sender_identity_owned.uid,
        user_name: sender_identity_owned.user_name.as_deref(),
        group_names: &sender_identity_owned.group_names,
    };
    if !bus
        .policy
        .read()
        .unwrap()
        .can_send(&sender_identity, &msg, Some(dest))
    {
        bus.stats.record_denial();
        reply_error(
            bus,
            sender,
            &msg,
            errors::ACCESS_DENIED,
            format!("Connection is not allowed to send to \"{dest}\""),
        )
        .await;
        return;
    }

    let bustype = match bus.kind {
        crate::BusKind::System => "system",
        crate::BusKind::Session => "session",
    };
    let dst_conn = bus
        .registry
        .get_name_owner(dest)
        .and_then(|o| bus.registry.get(&o));
    if !crate::apparmor::check_permission(
        crate::apparmor::AA_DBUS_SEND,
        sender.security_label.as_deref(),
        dst_conn.as_ref().and_then(|c| c.security_label.as_deref()),
        bustype,
        Some(dest),
        msg.path().map(|p| p.as_str()),
        msg.interface(),
        msg.member(),
        sender.credentials.uid,
    ) {
        bus.stats.record_denial();
        reply_error(
            bus,
            sender,
            &msg,
            errors::ACCESS_DENIED,
            format!("AppArmor mediation denied sending to \"{dest}\""),
        )
        .await;
        return;
    }

    match bus.registry.get_name_owner(dest) {
        Some(owner) => deliver_to_owner(bus, sender, &msg, &owner).await,
        None => {
            if msg.no_auto_start() || !bus.activation.is_activatable(dest) {
                reply_error(
                    bus,
                    sender,
                    &msg,
                    errors::SERVICE_UNKNOWN,
                    format!("The name {dest} was not provided by any .service files or activatable connections"),
                )
                .await;
                return;
            }
            match driver::activate_and_wait(bus, dest).await {
                Ok(()) => match bus.registry.get_name_owner(dest) {
                    Some(owner) => deliver_to_owner(bus, sender, &msg, &owner).await,
                    None => {
                        reply_error(
                            bus,
                            sender,
                            &msg,
                            errors::SERVICE_UNKNOWN,
                            "activation raced with removal",
                        )
                        .await
                    }
                },
                Err(e) => {
                    reply_error(bus, sender, &msg, errors::SPAWN_EXEC_FAILED, e.to_string()).await
                }
            }
        }
    }
}

async fn deliver_to_owner(
    bus: &Arc<Bus>,
    sender: &Arc<ConnectionEntry>,
    msg: &Message,
    owner: &str,
) {
    let Some(conn) = bus.registry.get(owner) else {
        reply_error(bus, sender, msg, errors::SERVICE_UNKNOWN, "owner vanished").await;
        return;
    };
    let dest_identity_raw = identity::resolve(conn.credentials.uid);
    let dest_identity = PolicyIdentity {
        uid: dest_identity_raw.uid,
        user_name: dest_identity_raw.user_name.as_deref(),
        group_names: &dest_identity_raw.group_names,
    };
    if !bus
        .policy
        .read()
        .unwrap()
        .can_receive(&dest_identity, msg, msg.sender())
    {
        bus.stats.record_denial();
        reply_error(
            bus,
            sender,
            msg,
            errors::ACCESS_DENIED,
            "Destination is not allowed to receive this message",
        )
        .await;
        return;
    }

    let bustype = match bus.kind {
        crate::BusKind::System => "system",
        crate::BusKind::Session => "session",
    };
    if !crate::apparmor::check_permission(
        crate::apparmor::AA_DBUS_RECEIVE,
        conn.security_label.as_deref(),
        sender.security_label.as_deref(),
        bustype,
        msg.destination(),
        msg.path().map(|p| p.as_str()),
        msg.interface(),
        msg.member(),
        conn.credentials.uid,
    ) {
        bus.stats.record_denial();
        reply_error(
            bus,
            sender,
            msg,
            errors::ACCESS_DENIED,
            "AppArmor mediation denied recipient from receiving this message",
        )
        .await;
        return;
    }
    match conn.writer.write_message(msg).await {
        Ok(()) => bus
            .stats
            .record_routed(msg.to_bytes().map(|b| b.len() as u64).unwrap_or(0)),
        Err(_) => {
            reply_error(
                bus,
                sender,
                msg,
                errors::NO_REPLY,
                "destination connection is gone",
            )
            .await
        }
    }
}

async fn handle_driver_call(bus: &Arc<Bus>, sender: &Arc<ConnectionEntry>, msg: Message) {
    let member = msg.member().unwrap_or("").to_string();

    if let Some(outcome) = handle_side_interface(bus, sender, msg.interface(), &member, &msg.body) {
        finish_driver_reply(bus, sender, &msg, outcome).await;
        return;
    }

    let outcome = driver::handle(bus, sender, &member, &msg.body).await;
    finish_driver_reply(bus, sender, &msg, outcome).await;
}

fn handle_side_interface(
    bus: &Arc<Bus>,
    sender: &Arc<ConnectionEntry>,
    interface: Option<&str>,
    member: &str,
    args: &[Value],
) -> Option<driver::DriverOutcome> {
    match interface {
        Some(well_known::PEER_INTERFACE) => Some(match member {
            "Ping" => driver_ok(vec![]),
            "GetMachineId" => driver_ok(vec![Value::string(bus.guid())]),
            other => driver_err(
                errors::UNKNOWN_METHOD,
                format!("Peer has no method \"{other}\""),
            ),
        }),
        Some(well_known::INTROSPECTABLE_INTERFACE) => Some(match member {
            "Introspect" => driver_ok(vec![Value::string(driver_introspection_xml())]),
            other => driver_err(
                errors::UNKNOWN_METHOD,
                format!("Introspectable has no method \"{other}\""),
            ),
        }),
        Some(well_known::STATS_INTERFACE) => Some(match member {
            "GetStats" => driver_ok(vec![stats_dict(bus)]),
            "GetConnectionStats" => match args.first().and_then(|v| v.as_str()) {
                Some(name) => match bus
                    .registry
                    .get_name_owner(name)
                    .and_then(|o| bus.registry.get(&o))
                {
                    Some(conn) => driver_ok(vec![connection_stats_dict(&conn)]),
                    None => driver_err(
                        errors::NAME_HAS_NO_OWNER,
                        format!("Could not get stats for '{name}': no such name"),
                    ),
                },
                None => driver_err(
                    errors::INVALID_ARGS,
                    "GetConnectionStats needs a connection name",
                ),
            },
            other => driver_err(
                errors::UNKNOWN_METHOD,
                format!("Debug.Stats has no method \"{other}\""),
            ),
        }),
        Some(well_known::MONITORING_INTERFACE) => Some(match member {
            "BecomeMonitor" => {
                let rules: Vec<String> = match args.first().map(|v| v.unwrap_variant()) {
                    Some(Value::Array(arr)) => arr
                        .elements
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect(),
                    _ => Vec::new(),
                };
                let parsed: Vec<_> = rules
                    .iter()
                    .filter_map(|r| crate::match_rules::parse_match_rule(r).ok())
                    .collect();
                *sender.match_rules.write().unwrap() = if parsed.is_empty() {
                    vec![crate::match_rules::parse_match_rule("").unwrap_or_default()]
                } else {
                    parsed
                };
                sender
                    .is_monitor
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                driver_ok(vec![])
            }
            other => driver_err(
                errors::UNKNOWN_METHOD,
                format!("Monitoring has no method \"{other}\""),
            ),
        }),
        _ => None,
    }
}

fn stats_dict(bus: &Arc<Bus>) -> Value {
    dict_of_u32(vec![
        ("BusNames", bus.registry.list_names().len() as u32),
        ("ActiveConnections", bus.registry.connection_count() as u32),
        (
            "MessagesRouted",
            bus.stats
                .messages_routed
                .load(std::sync::atomic::Ordering::Relaxed) as u32,
        ),
        (
            "BytesRouted",
            bus.stats
                .bytes_routed
                .load(std::sync::atomic::Ordering::Relaxed) as u32,
        ),
        (
            "SignalsDelivered",
            bus.stats
                .signals_delivered
                .load(std::sync::atomic::Ordering::Relaxed) as u32,
        ),
        (
            "ActivationsStarted",
            bus.stats
                .activations_started
                .load(std::sync::atomic::Ordering::Relaxed) as u32,
        ),
        (
            "PolicyDenials",
            bus.stats
                .policy_denials
                .load(std::sync::atomic::Ordering::Relaxed) as u32,
        ),
        ("UptimeSeconds", bus.stats.uptime_secs() as u32),
    ])
}

fn connection_stats_dict(conn: &ConnectionEntry) -> Value {
    dict_of_u32(vec![
        ("UnixUserID", conn.credentials.uid),
        ("ProcessID", conn.credentials.pid.max(0) as u32),
        ("MatchRules", conn.match_rules.read().unwrap().len() as u32),
    ])
}

fn dict_of_u32(entries: Vec<(&str, u32)>) -> Value {
    use oxibus_core::types::ArrayValue;
    Value::Array(ArrayValue::new(
        oxibus_core::Type::DictEntry(
            Box::new(oxibus_core::Type::String),
            Box::new(oxibus_core::Type::Variant),
        ),
        entries
            .into_iter()
            .map(|(k, v)| {
                Value::DictEntry(
                    Box::new(Value::string(k)),
                    Box::new(Value::Variant(Box::new(Value::UInt32(v)))),
                )
            })
            .collect(),
    ))
}

fn driver_ok(values: Vec<Value>) -> driver::DriverOutcome {
    driver::DriverOutcome {
        result: Ok(values),
        name_owner_changes: Vec::new(),
    }
}

fn driver_err(name: &str, message: impl Into<String>) -> driver::DriverOutcome {
    driver::DriverOutcome {
        result: Err(driver::DriverError {
            name: name.to_string(),
            message: message.into(),
        }),
        name_owner_changes: Vec::new(),
    }
}

fn driver_introspection_xml() -> String {
    format!(
        r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
  <interface name="{bus}">
    <method name="Hello"><arg direction="out" type="s"/></method>
    <method name="RequestName"><arg direction="in" type="s"/><arg direction="in" type="u"/><arg direction="out" type="u"/></method>
    <method name="ReleaseName"><arg direction="in" type="s"/><arg direction="out" type="u"/></method>
    <method name="ListNames"><arg direction="out" type="as"/></method>
    <method name="ListActivatableNames"><arg direction="out" type="as"/></method>
    <method name="NameHasOwner"><arg direction="in" type="s"/><arg direction="out" type="b"/></method>
    <method name="GetNameOwner"><arg direction="in" type="s"/><arg direction="out" type="s"/></method>
    <method name="ListQueuedOwners"><arg direction="in" type="s"/><arg direction="out" type="as"/></method>
    <method name="StartServiceByName"><arg direction="in" type="s"/><arg direction="in" type="u"/><arg direction="out" type="u"/></method>
    <method name="AddMatch"><arg direction="in" type="s"/></method>
    <method name="RemoveMatch"><arg direction="in" type="s"/></method>
    <method name="GetConnectionUnixUser"><arg direction="in" type="s"/><arg direction="out" type="u"/></method>
    <method name="GetConnectionUnixProcessID"><arg direction="in" type="s"/><arg direction="out" type="u"/></method>
    <method name="GetConnectionCredentials"><arg direction="in" type="s"/><arg direction="out" type="a{{sv}}"/></method>
    <method name="GetId"><arg direction="out" type="s"/></method>
    <method name="UpdateActivationEnvironment"><arg direction="in" type="a{{ss}}"/></method>
    <signal name="NameOwnerChanged"><arg type="s"/><arg type="s"/><arg type="s"/></signal>
    <signal name="NameLost"><arg type="s"/></signal>
    <signal name="NameAcquired"><arg type="s"/></signal>
  </interface>
  <interface name="{peer}">
    <method name="Ping"/>
    <method name="GetMachineId"><arg direction="out" type="s"/></method>
  </interface>
  <interface name="{introspectable}">
    <method name="Introspect"><arg direction="out" type="s"/></method>
  </interface>
  <interface name="{monitoring}">
    <method name="BecomeMonitor"><arg direction="in" type="as"/><arg direction="in" type="u"/></method>
  </interface>
  <interface name="{stats}">
    <method name="GetStats"><arg direction="out" type="a{{sv}}"/></method>
    <method name="GetConnectionStats"><arg direction="in" type="s"/><arg direction="out" type="a{{sv}}"/></method>
  </interface>
</node>
"#,
        bus = well_known::BUS_INTERFACE,
        peer = well_known::PEER_INTERFACE,
        introspectable = well_known::INTROSPECTABLE_INTERFACE,
        monitoring = well_known::MONITORING_INTERFACE,
        stats = well_known::STATS_INTERFACE,
    )
}

async fn finish_driver_reply(
    bus: &Arc<Bus>,
    sender: &Arc<ConnectionEntry>,
    msg: &Message,
    outcome: driver::DriverOutcome,
) {
    if !outcome.name_owner_changes.is_empty() {
        broadcast_name_owner_changes(bus, outcome.name_owner_changes).await;
    }

    if msg.no_reply_expected() {
        return;
    }

    let reply = match outcome.result {
        Ok(values) => reply_to(msg, None)
            .sender(well_known::BUS_NAME)
            .args(values),
        Err(e) => reply_to(msg, Some(&e.name))
            .sender(well_known::BUS_NAME)
            .arg(Value::string(e.message)),
    };
    let out = reply.build(driver_serial());
    let _ = sender.writer.write_message(&out).await;
}

pub async fn broadcast_name_owner_changes(bus: &Arc<Bus>, changes: Vec<NameOwnerChange>) {
    for change in changes {
        let signal = MessageBuilder::signal(
            ObjectPath::new(well_known::BUS_PATH).unwrap(),
            well_known::BUS_INTERFACE.to_string(),
            well_known::NAME_OWNER_CHANGED.to_string(),
        )
        .sender(well_known::BUS_NAME)
        .arg(Value::string(change.name.clone()))
        .arg(Value::string(change.old_owner.clone().unwrap_or_default()))
        .arg(Value::string(change.new_owner.clone().unwrap_or_default()))
        .build(driver_serial());
        broadcast_signal(bus, &signal, false).await;

        if let Some(new_owner) = &change.new_owner {
            send_unicast_driver_signal(bus, new_owner, well_known::NAME_ACQUIRED, &change.name)
                .await;
        }
        if let Some(old_owner) = &change.old_owner {
            send_unicast_driver_signal(bus, old_owner, well_known::NAME_LOST, &change.name).await;
        }
    }
}

async fn send_unicast_driver_signal(
    bus: &Arc<Bus>,
    to_unique_name: &str,
    member: &'static str,
    name: &str,
) {
    let Some(conn) = bus.registry.get(to_unique_name) else {
        return;
    };
    let signal = MessageBuilder::signal(
        ObjectPath::new(well_known::BUS_PATH).unwrap(),
        well_known::BUS_INTERFACE.to_string(),
        member.to_string(),
    )
    .sender(well_known::BUS_NAME)
    .destination(to_unique_name.to_string())
    .arg(Value::string(name))
    .build(driver_serial());
    let _ = conn.writer.write_message(&signal).await;
}

async fn reply_error(
    bus: &Arc<Bus>,
    sender: &Arc<ConnectionEntry>,
    call: &Message,
    error_name: &str,
    message: impl Into<String>,
) {
    if call.no_reply_expected() {
        return;
    }
    let out = reply_to(call, Some(error_name))
        .sender(well_known::BUS_NAME)
        .arg(Value::string(message.into()))
        .build(driver_serial());
    let _ = sender.writer.write_message(&out).await;
    let _ = bus;
}

fn driver_serial() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    loop {
        let v = COUNTER.fetch_add(1, Ordering::Relaxed);
        if v != 0 {
            return v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{Bus, BusKind};
    use oxibus_config::GlobalConfig;
    use oxibus_core::{MessageBuilder, ObjectPath, SerialGenerator};

    #[tokio::test]
    async fn monitor_receives_exactly_one_copy_of_signal() {
        let bus = Arc::new(Bus::new(BusKind::Session, GlobalConfig::default()));

        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let transport = oxibus_transport::Transport::new(a).unwrap();
        let mut transport_recv = oxibus_transport::Transport::new(b).unwrap();
        let unique_name = bus.registry.allocate_unique_name();

        let conn = Arc::new(crate::registry::ConnectionEntry {
            unique_name: unique_name.clone(),
            writer: transport.writer(),
            credentials: transport.credentials(),
            security_label: None,
            match_rules: std::sync::RwLock::new(Vec::new()),
            is_monitor: std::sync::atomic::AtomicBool::new(true),
            is_registered: std::sync::atomic::AtomicBool::new(true),
        });

        bus.registry.add_connection(conn.clone());

        let serial = SerialGenerator::new();
        let msg = MessageBuilder::signal(
            ObjectPath::new("/org/example/Test").unwrap(),
            "org.example.Test".to_string(),
            "FooSignal".to_string(),
        )
        .sender(unique_name.clone())
        .build(serial.next());

        dispatch_incoming(&bus, &conn, msg).await;

        let received = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            transport_recv.read_message(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(received.member(), Some("FooSignal"));

        let second = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            transport_recv.read_message(),
        )
        .await;

        assert!(second.is_err(), "Monitor received a duplicate message!");
    }
}
