// Implementation of org.freedesktop.DBus driver methods.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use oxibus_core::types::ArrayValue;
use oxibus_core::{errors, Type, Value};

use crate::bus::Bus;
use crate::registry::{ConnectionEntry, NameOwnerChange};

pub struct DriverError {
    pub name: String,
    pub message: String,
}

impl DriverError {
    fn new(name: &str, message: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            message: message.into(),
        }
    }
    fn invalid_args(msg: impl Into<String>) -> Self {
        Self::new(errors::INVALID_ARGS, msg.into())
    }
}

pub type DriverResult = Result<Vec<Value>, DriverError>;

pub struct DriverOutcome {
    pub result: DriverResult,
    pub name_owner_changes: Vec<NameOwnerChange>,
}

fn ok(values: Vec<Value>, changes: Vec<NameOwnerChange>) -> DriverOutcome {
    DriverOutcome {
        result: Ok(values),
        name_owner_changes: changes,
    }
}
fn err(e: DriverError) -> DriverOutcome {
    DriverOutcome {
        result: Err(e),
        name_owner_changes: Vec::new(),
    }
}

fn arg_str(args: &[Value], idx: usize) -> Result<String, DriverError> {
    args.get(idx)
        .and_then(|v| v.unwrap_variant().as_str())
        .map(str::to_string)
        .ok_or_else(|| DriverError::invalid_args(format!("expected string argument {idx}")))
}

fn arg_u32(args: &[Value], idx: usize) -> Result<u32, DriverError> {
    match args.get(idx).map(|v| v.unwrap_variant()) {
        Some(Value::UInt32(v)) => Ok(*v),
        _ => Err(DriverError::invalid_args(format!(
            "expected uint32 argument {idx}"
        ))),
    }
}

fn validate_bus_name(name: &str, allow_unique: bool) -> Result<(), DriverError> {
    let valid = if name.starts_with(':') {
        allow_unique && oxibus_core::is_valid_bus_name(name)
    } else {
        oxibus_core::is_valid_bus_name(name)
    };
    if valid {
        Ok(())
    } else {
        Err(DriverError::invalid_args(format!("invalid bus name '{name}'")))
    }
}

pub async fn handle(bus: &Arc<Bus>, caller: &Arc<ConnectionEntry>, member: &str, args: &[Value]) -> DriverOutcome {
    match member {
        "Hello" => handle_hello(caller),
        "RequestName" => handle_request_name(bus, caller, args),
        "ReleaseName" => handle_release_name(bus, caller, args),
        "ListNames" => ok(vec![string_array(bus.registry.list_names())], vec![]),
        "ListActivatableNames" => ok(
            vec![string_array(bus.activation.list_activatable_names())],
            vec![],
        ),
        "NameHasOwner" => match args.first().and_then(|v| v.as_str()) {
            Some(name) => ok(vec![Value::Boolean(bus.registry.name_has_owner(name))], vec![]),
            None => err(DriverError::invalid_args("NameHasOwner needs a name")),
        },
        "GetNameOwner" => handle_get_name_owner(bus, args),
        "ListQueuedOwners" => match arg_str(args, 0) {
            Ok(name) => ok(vec![string_array(bus.registry.list_queued_owners(&name))], vec![]),
            Err(e) => err(e),
        },
        "StartServiceByName" => handle_start_service(bus, args).await,
        "AddMatch" => handle_add_match(bus, caller, args),
        "RemoveMatch" => handle_remove_match(caller, args),
        "GetConnectionUnixUser" => handle_get_conn_uid(bus, args),
        "GetConnectionUnixProcessID" => handle_get_conn_pid(bus, args),
        "GetConnectionCredentials" => handle_get_conn_credentials(bus, args),
        "GetId" => ok(vec![Value::string(bus.guid())], vec![]),
        "UpdateActivationEnvironment" => handle_update_activation_env(bus, args),
        "ReloadConfig" => ok(vec![], vec![]),
        other => err(DriverError::new(
            errors::UNKNOWN_METHOD,
            format!("org.freedesktop.DBus has no method \"{other}\""),
        )),
    }
}

fn string_array(items: Vec<String>) -> Value {
    Value::Array(ArrayValue::new(
        Type::String,
        items.into_iter().map(Value::String).collect(),
    ))
}

fn handle_hello(caller: &Arc<ConnectionEntry>) -> DriverOutcome {
    if caller.is_registered.swap(true, Ordering::SeqCst) {
        return err(DriverError::new(
            errors::FAILED,
            "Already handled an Hello message",
        ));
    }
    let change = NameOwnerChange {
        name: caller.unique_name.clone(),
        old_owner: None,
        new_owner: Some(caller.unique_name.clone()),
    };
    ok(vec![Value::string(caller.unique_name.clone())], vec![change])
}

fn handle_request_name(bus: &Arc<Bus>, caller: &Arc<ConnectionEntry>, args: &[Value]) -> DriverOutcome {
    let name = match arg_str(args, 0) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    if let Err(e) = validate_bus_name(&name, false) {
        return err(e);
    }
    let flags = match arg_u32(args, 1) {
        Ok(f) => f,
        Err(e) => return err(e),
    };

    let identity = crate::identity::resolve(caller.credentials.uid);
    let policy_identity = crate::policy::Identity {
        uid: identity.uid,
        user_name: identity.user_name.as_deref(),
        group_names: &identity.group_names,
    };
    if !bus.policy.read().unwrap().can_own(&policy_identity, &name) {
        bus.stats.record_denial();
        return err(DriverError::new(
            errors::ACCESS_DENIED,
            format!("Connection is not allowed to own the name \"{name}\""),
        ));
    }

    let bustype = match bus.kind {
        crate::bus::BusKind::System => "system",
        crate::bus::BusKind::Session => "session",
    };
    if !crate::apparmor::check_permission(
        crate::apparmor::AA_DBUS_BIND,
        caller.security_label.as_deref(),
        None,
        bustype,
        Some(&name),
        None,
        None,
        None,
        caller.credentials.uid,
    ) {
        bus.stats.record_denial();
        return err(DriverError::new(
            errors::ACCESS_DENIED,
            format!("AppArmor mediation denied owning the name \"{name}\""),
        ));
    }

    let max_names = bus.config.limits.max_names_per_connection as usize;
    if bus.registry.names_held_by(&caller.unique_name) >= max_names {
        return err(DriverError::new(
            errors::LIMITS_EXCEEDED,
            format!("Connection has reached the maximum of {max_names} owned/queued names"),
        ));
    }

    let (code, changes) = bus.registry.request_name(&caller.unique_name, &name, flags);
    ok(vec![Value::UInt32(code)], changes)
}

fn handle_release_name(bus: &Arc<Bus>, caller: &Arc<ConnectionEntry>, args: &[Value]) -> DriverOutcome {
    let name = match arg_str(args, 0) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    let (code, changes) = bus.registry.release_name(&caller.unique_name, &name);
    ok(vec![Value::UInt32(code)], changes)
}

fn handle_get_name_owner(bus: &Arc<Bus>, args: &[Value]) -> DriverOutcome {
    let name = match arg_str(args, 0) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    match bus.registry.get_name_owner(&name) {
        Some(owner) => ok(vec![Value::string(owner)], vec![]),
        None => err(DriverError::new(
            errors::NAME_HAS_NO_OWNER,
            format!("Could not get owner of name '{name}': no such name"),
        )),
    }
}

async fn handle_start_service(bus: &Arc<Bus>, args: &[Value]) -> DriverOutcome {
    let name = match arg_str(args, 0) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    const START_REPLY_SUCCESS: u32 = 1;
    const START_REPLY_ALREADY_RUNNING: u32 = 2;

    if bus.registry.name_has_owner(&name) {
        return ok(vec![Value::UInt32(START_REPLY_ALREADY_RUNNING)], vec![]);
    }
    if !bus.activation.is_activatable(&name) {
        return err(DriverError::new(
            errors::SERVICE_UNKNOWN,
            format!("The name {name} was not provided by any .service files"),
        ));
    }
    match activate_and_wait(bus, &name).await {
        Ok(()) => ok(vec![Value::UInt32(START_REPLY_SUCCESS)], vec![]),
        Err(e) => err(DriverError::new(errors::SPAWN_EXEC_FAILED, e.to_string())),
    }
}

pub(crate) async fn activate_and_wait(bus: &Arc<Bus>, name: &str) -> Result<(), crate::activation::ActivationError> {
    use crate::activation::SpawnStrategy;
    use crate::bus::BusKind;

    let helper_path = bus.config.paths.launch_helper_path();
    let strategy = if bus.kind == BusKind::System && helper_path.exists() {
        SpawnStrategy::ViaLaunchHelper(&helper_path)
    } else {
        SpawnStrategy::Direct
    };
    bus.activation
        .spawn(name, &bus.activation_environment.read().unwrap(), strategy)?;
    bus.stats.record_activation();

    let timeout = Duration::from_millis(bus.config.limits.activation_timeout_ms);
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if bus.registry.name_has_owner(name) {
            return Ok(());
        }
        tokio::time::sleep(crate::activation::ActivationRegistry::DEFAULT_POLL_INTERVAL).await;
    }
    Err(crate::activation::ActivationError::TimedOut(name.to_string()))
}

fn handle_add_match(bus: &Arc<Bus>, caller: &Arc<ConnectionEntry>, args: &[Value]) -> DriverOutcome {
    let rule_str = match arg_str(args, 0) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let max_rules = bus.config.limits.max_match_rules_per_connection as usize;
    if caller.match_rules.read().unwrap().len() >= max_rules {
        return err(DriverError::new(
            errors::LIMITS_EXCEEDED,
            format!("Connection has reached the maximum of {max_rules} match rules"),
        ));
    }
    match crate::match_rules::parse_match_rule(&rule_str) {
        Ok(rule) => {
            caller.match_rules.write().unwrap().push(rule);
            ok(vec![], vec![])
        }
        Err(msg) => err(DriverError::new(errors::MATCH_RULE_INVALID, msg)),
    }
}

fn handle_remove_match(caller: &Arc<ConnectionEntry>, args: &[Value]) -> DriverOutcome {
    let rule_str = match arg_str(args, 0) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let mut rules = caller.match_rules.write().unwrap();
    let before = rules.len();
    rules.retain(|r| r.raw != rule_str);
    if rules.len() == before {
        return err(DriverError::new(
            errors::MATCH_RULE_NOT_FOUND,
            "The given match rule wasn't found and can't be removed",
        ));
    }
    ok(vec![], vec![])
}

fn handle_get_conn_uid(bus: &Arc<Bus>, args: &[Value]) -> DriverOutcome {
    let name = match arg_str(args, 0) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    match resolve_connection(bus, &name) {
        Some(c) => ok(vec![Value::UInt32(c.credentials.uid)], vec![]),
        None => name_has_no_owner(&name),
    }
}

fn handle_get_conn_pid(bus: &Arc<Bus>, args: &[Value]) -> DriverOutcome {
    let name = match arg_str(args, 0) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    match resolve_connection(bus, &name) {
        Some(c) => ok(vec![Value::UInt32(c.credentials.pid.max(0) as u32)], vec![]),
        None => name_has_no_owner(&name),
    }
}

fn handle_get_conn_credentials(bus: &Arc<Bus>, args: &[Value]) -> DriverOutcome {
    let name = match arg_str(args, 0) {
        Ok(n) => n,
        Err(e) => return err(e),
    };
    let Some(c) = resolve_connection(bus, &name) else {
        return name_has_no_owner(&name);
    };
    let dict = Value::Array(ArrayValue::new(
        Type::DictEntry(Box::new(Type::String), Box::new(Type::Variant)),
        vec![
            Value::DictEntry(
                Box::new(Value::string("UnixUserID")),
                Box::new(Value::Variant(Box::new(Value::UInt32(c.credentials.uid)))),
            ),
            Value::DictEntry(
                Box::new(Value::string("ProcessID")),
                Box::new(Value::Variant(Box::new(Value::UInt32(
                    c.credentials.pid.max(0) as u32,
                )))),
            ),
        ],
    ));
    ok(vec![dict], vec![])
}

fn handle_update_activation_env(bus: &Arc<Bus>, args: &[Value]) -> DriverOutcome {
    if bus.kind == crate::bus::BusKind::System {
        return err(DriverError::new(
            errors::ACCESS_DENIED,
            "Cannot change activation environment on a system bus.",
        ));
    }
    let Some(Value::Array(arr)) = args.first().map(|v| v.unwrap_variant()) else {
        return err(DriverError::invalid_args("expected a{ss} environment map"));
    };
    let mut env = bus.activation_environment.write().unwrap();
    for el in &arr.elements {
        if let Value::DictEntry(k, v) = el {
            if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                env.insert(key.to_string(), val.to_string());
            }
        }
    }
    ok(vec![], vec![])
}

fn resolve_connection(bus: &Arc<Bus>, name: &str) -> Option<Arc<ConnectionEntry>> {
    let owner = bus.registry.get_name_owner(name)?;
    bus.registry.get(&owner)
}

fn name_has_no_owner(name: &str) -> DriverOutcome {
    err(DriverError::new(
        errors::NAME_HAS_NO_OWNER,
        format!("Could not get UID of name '{name}': no such name"),
    ))
}
