// Live D-Bus connection implementation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

use oxibus_auth::{ClientAction, ClientAuth, Mechanism};
use oxibus_core::header::MessageType;
use oxibus_core::message::reply_to;
use oxibus_core::{
    Address, ArrayValue, Message, MessageBuilder, ObjectPath, SerialGenerator, Type, Value,
    well_known,
};
use oxibus_transport::{Transport, Writer};

use crate::error::{ClientError, ClientResult};
use crate::object_server::ObjectServer;

pub fn default_mechanisms() -> Vec<Mechanism> {
    vec![Mechanism::External, Mechanism::DbusCookieSha1]
}

struct Inner {
    writer: Writer,
    pending: Arc<StdMutex<HashMap<u32, oneshot::Sender<Message>>>>,
    signal_tx: broadcast::Sender<Message>,
    raw_tx: broadcast::Sender<Message>,
    serials: SerialGenerator,
    unique_name: Arc<StdMutex<Option<String>>>,
    object_server: Arc<ObjectServer>,
    _reader_task: JoinHandle<()>,
}

#[derive(Clone)]
pub struct Connection {
    inner: Arc<Inner>,
}

impl Connection {
    pub async fn connect(address: &Address) -> ClientResult<Self> {
        Self::connect_with(
            address,
            default_mechanisms(),
            true,
            Arc::new(ObjectServer::new()),
        )
        .await
    }

    pub async fn connect_with(
        address: &Address,
        mechanisms: Vec<Mechanism>,
        want_unix_fd: bool,
        object_server: Arc<ObjectServer>,
    ) -> ClientResult<Self> {
        let stream = oxibus_transport::connect(address).await?;
        let mut transport = Transport::new(stream)?;
        handshake(&mut transport, mechanisms, want_unix_fd).await?;

        let writer = transport.writer();
        let pending: Arc<StdMutex<HashMap<u32, oneshot::Sender<Message>>>> =
            Arc::new(StdMutex::new(HashMap::new()));
        let (signal_tx, _) = broadcast::channel(4096);
        let (raw_tx, _) = broadcast::channel(4096);
        let unique_name: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));

        let task_pending = pending.clone();
        let task_signal_tx = signal_tx.clone();
        let task_raw_tx = raw_tx.clone();
        let task_object_server = object_server.clone();
        let task_writer = writer.clone();
        let task_unique_name = unique_name.clone();

        let reader_task = tokio::spawn(async move {
            while let Ok(msg) = transport.read_message().await {
                let _ = task_raw_tx.send(msg.clone());
                handle_incoming(
                    msg,
                    &task_pending,
                    &task_signal_tx,
                    &task_object_server,
                    &task_writer,
                    &task_unique_name,
                )
                .await;
            }
            task_pending.lock().unwrap().clear();
        });

        Ok(Connection {
            inner: Arc::new(Inner {
                writer,
                pending,
                signal_tx,
                raw_tx,
                serials: SerialGenerator::new(),
                unique_name,
                object_server,
                _reader_task: reader_task,
            }),
        })
    }

    pub fn object_server(&self) -> &Arc<ObjectServer> {
        &self.inner.object_server
    }

    pub fn unique_name(&self) -> Option<String> {
        self.inner.unique_name.lock().unwrap().clone()
    }

    pub fn subscribe_signals(&self) -> broadcast::Receiver<Message> {
        self.inner.signal_tx.subscribe()
    }

    pub fn subscribe_all_messages(&self) -> broadcast::Receiver<Message> {
        self.inner.raw_tx.subscribe()
    }

    pub async fn call_method(
        &self,
        destination: Option<&str>,
        path: ObjectPath,
        interface: Option<&str>,
        member: &str,
        args: Vec<Value>,
    ) -> ClientResult<Vec<Value>> {
        let serial = self.inner.serials.next();
        let mut builder = MessageBuilder::method_call(path, member.to_string());
        if let Some(i) = interface {
            builder = builder.interface(i.to_string());
        }
        if let Some(d) = destination {
            builder = builder.destination(d.to_string());
        }
        let mut args = args;
        let mut fds = Vec::new();
        extract_fds(&mut args, &mut fds);
        for fd in fds {
            builder = builder.fd(fd);
        }
        let msg = builder.args(args).build(serial);

        let (tx, rx) = oneshot::channel();
        self.inner.pending.lock().unwrap().insert(serial, tx);

        if let Err(e) = self.inner.writer.write_message(&msg).await {
            self.inner.pending.lock().unwrap().remove(&serial);
            return Err(ClientError::Io(e));
        }

        let reply = rx.await.map_err(|_| ClientError::Closed)?;
        match reply.message_type() {
            MessageType::MethodReturn => Ok(reply.body),
            MessageType::Error => Err(ClientError::CallError {
                name: reply.header.error_name().unwrap_or("").to_string(),
                message: reply
                    .body
                    .first()
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            }),
            _ => Err(ClientError::Protocol(
                "unexpected reply message type".into(),
            )),
        }
    }

    pub async fn emit_signal(
        &self,
        path: ObjectPath,
        interface: &str,
        member: &str,
        args: Vec<Value>,
    ) -> ClientResult<()> {
        let serial = self.inner.serials.next();
        let msg = MessageBuilder::signal(path, interface.to_string(), member.to_string())
            .args(args)
            .build(serial);
        self.inner.writer.write_message(&msg).await?;
        Ok(())
    }

    /// Emits `org.freedesktop.DBus.Properties.PropertiesChanged` for
    /// `interface` at `path` — the signal every reactive desktop status
    /// UI (battery, network, volume, media player, ...) polls for
    /// instead of re-querying. Was possible before via `emit_signal`
    /// with a hand-built `a{sv}`/`as` pair; this just saves doing that
    /// by hand every time.
    pub async fn properties_changed(
        &self,
        path: ObjectPath,
        interface: &str,
        changed: Vec<(String, Value)>,
        invalidated: Vec<String>,
    ) -> ClientResult<()> {
        let changed_dict = Value::Array(ArrayValue::new(
            Type::DictEntry(Box::new(Type::String), Box::new(Type::Variant)),
            changed
                .into_iter()
                .map(|(name, value)| {
                    Value::DictEntry(
                        Box::new(Value::string(name)),
                        Box::new(Value::Variant(Box::new(value))),
                    )
                })
                .collect(),
        ));
        let invalidated_arr = Value::Array(ArrayValue::new(
            Type::String,
            invalidated.into_iter().map(Value::string).collect(),
        ));
        self.emit_signal(
            path,
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            vec![Value::string(interface), changed_dict, invalidated_arr],
        )
        .await
    }

    pub async fn send_no_reply(&self, msg_builder: MessageBuilder) -> ClientResult<()> {
        let serial = self.inner.serials.next();
        let msg = msg_builder.no_reply_expected().build(serial);
        self.inner.writer.write_message(&msg).await?;
        Ok(())
    }

    pub async fn bus_hello(&self) -> ClientResult<String> {
        let reply = self
            .call_method(
                Some(well_known::BUS_NAME),
                ObjectPath::new(well_known::BUS_PATH).unwrap(),
                Some(well_known::BUS_INTERFACE),
                "Hello",
                vec![],
            )
            .await?;
        let name = reply
            .first()
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| ClientError::Protocol("Hello did not return a name".into()))?;
        *self.inner.unique_name.lock().unwrap() = Some(name.clone());
        Ok(name)
    }

    pub async fn request_name(&self, name: &str, flags: u32) -> ClientResult<u32> {
        let reply = self
            .call_method(
                Some(well_known::BUS_NAME),
                ObjectPath::new(well_known::BUS_PATH).unwrap(),
                Some(well_known::BUS_INTERFACE),
                "RequestName",
                vec![Value::string(name), Value::UInt32(flags)],
            )
            .await?;
        reply
            .first()
            .and_then(|v| v.as_u32())
            .ok_or_else(|| ClientError::Protocol("RequestName returned no result".into()))
    }

    pub async fn add_match(&self, rule: &str) -> ClientResult<()> {
        self.call_method(
            Some(well_known::BUS_NAME),
            ObjectPath::new(well_known::BUS_PATH).unwrap(),
            Some(well_known::BUS_INTERFACE),
            "AddMatch",
            vec![Value::string(rule)],
        )
        .await?;
        Ok(())
    }
}

async fn handshake(
    transport: &mut Transport,
    mechanisms: Vec<Mechanism>,
    want_unix_fd: bool,
) -> ClientResult<()> {
    transport.send_initial_nul().await?;

    let mut auth = ClientAuth::new(mechanisms, want_unix_fd);
    let mut line = auth.start();
    loop {
        transport.write_line(&line).await?;
        let resp = transport.read_line().await?;
        match auth.feed_line(&resp) {
            ClientAction::Authenticated => break,
            ClientAction::Send(l) => line = l,
            ClientAction::MechanismRejected { .. } => match auth.try_next_mechanism() {
                Some(next) => line = next,
                None => {
                    return Err(ClientError::AuthFailed(
                        "server rejected every configured SASL mechanism".into(),
                    ));
                }
            },
            ClientAction::ProtocolError(e) => return Err(ClientError::AuthFailed(e)),
        }
    }

    let (lines, expect_reply) = auth.finish_lines();
    for l in &lines {
        transport.write_line(l).await?;
    }
    if expect_reply {
        transport.read_line().await?;
    }
    Ok(())
}

async fn handle_incoming(
    msg: Message,
    pending: &StdMutex<HashMap<u32, oneshot::Sender<Message>>>,
    signal_tx: &broadcast::Sender<Message>,
    object_server: &Arc<ObjectServer>,
    writer: &Writer,
    unique_name: &StdMutex<Option<String>>,
) {
    match msg.message_type() {
        MessageType::MethodReturn | MessageType::Error => {
            if let Some(reply_serial) = msg.reply_serial()
                && let Some(tx) = pending.lock().unwrap().remove(&reply_serial)
            {
                let _ = tx.send(msg);
            }
        }
        MessageType::Signal => {
            let _ = signal_tx.send(msg);
        }
        MessageType::MethodCall => {
            let is_for_us = match msg.destination() {
                None => true,
                Some(dest) => unique_name.lock().unwrap().as_deref() == Some(dest),
            };
            if !is_for_us {
                return;
            }

            let no_reply = msg.no_reply_expected();
            let path = msg.path().map(|p| p.as_str().to_string());
            let interface = msg.interface().map(str::to_string);
            let member = msg.member().map(str::to_string);

            let Some(path) = path else { return };
            let Some(member) = member else { return };

            let result = object_server
                .dispatch(&path, interface.as_deref(), &member, &msg.body)
                .await;

            if no_reply {
                return;
            }
            let reply = match result {
                Ok(mut values) => {
                    let mut builder = reply_to(&msg, None);
                    let mut fds = Vec::new();
                    extract_fds(&mut values, &mut fds);
                    for fd in fds {
                        builder = builder.fd(fd);
                    }
                    builder.args(values)
                }
                Err(e) => reply_to(&msg, Some(&e.name)).arg(Value::string(e.message)),
            };
            let out = reply.build(next_reply_serial());
            let _ = writer.write_message(&out).await;
        }
    }
}

fn extract_fds(values: &mut [Value], fds: &mut Vec<std::os::fd::RawFd>) {
    fn walk(val: &mut Value, fds: &mut Vec<std::os::fd::RawFd>) {
        match val {
            Value::UnixFd(fd_ref) => {
                let raw_fd = *fd_ref as std::os::fd::RawFd;
                let idx = fds.len() as u32;
                fds.push(raw_fd);
                *fd_ref = idx;
            }
            Value::Array(arr) => {
                for el in &mut arr.elements {
                    walk(el, fds);
                }
            }
            Value::Struct(fields) => {
                for f in fields {
                    walk(f, fds);
                }
            }
            Value::DictEntry(k, v) => {
                walk(k, fds);
                walk(v, fds);
            }
            Value::Variant(inner) => {
                walk(inner, fds);
            }
            _ => {}
        }
    }
    for val in values {
        walk(val, fds);
    }
}

fn next_reply_serial() -> u32 {
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
    use crate::object_server::{BoxFuture, Interface, MethodError, MethodResult};

    struct Echo;
    impl Interface for Echo {
        fn name(&self) -> &str {
            "com.example.Echo"
        }
        fn introspection_xml(&self) -> String {
            "<interface name=\"com.example.Echo\"><method name=\"Ping\"/></interface>".into()
        }
        fn call<'a>(&'a self, member: &'a str, _args: &'a [Value]) -> BoxFuture<'a, MethodResult> {
            Box::pin(async move {
                if member == "Ping" {
                    Ok(vec![Value::string("pong")])
                } else {
                    Err(MethodError::unknown_method(member, self.name()))
                }
            })
        }
    }

    #[tokio::test]
    async fn peer_to_peer_call_and_reply() {
        let dir = std::env::temp_dir().join(format!("oxibus-client-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("p2p.sock");
        let addr = Address::UnixPath(sock.display().to_string());

        let bound = oxibus_transport::bind(&addr).await.unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _peer) = bound.listener.accept().await.unwrap();
            let object_server = Arc::new(ObjectServer::new());
            object_server.register(&ObjectPath::new("/echo").unwrap(), Arc::new(Echo));

            let mut transport = Transport::new(stream).unwrap();
            transport.read_initial_nul().await.unwrap();
            loop {
                let line = transport.read_line().await.unwrap();
                if let Some(rest) = line.strip_prefix("AUTH EXTERNAL ") {
                    let _ = rest;
                    transport.write_line("OK 0000").await.unwrap();
                    break;
                }
            }
            let mut line = transport.read_line().await.unwrap();
            if line == "NEGOTIATE_UNIX_FD" {
                transport.write_line("AGREE_UNIX_FD").await.unwrap();
                line = transport.read_line().await.unwrap();
            }
            assert_eq!(line, "BEGIN");

            let writer = transport.writer();
            loop {
                let msg = match transport.read_message().await {
                    Ok(m) => m,
                    Err(_) => break,
                };
                handle_incoming(
                    msg,
                    &StdMutex::new(HashMap::new()),
                    &broadcast::channel(1).0,
                    &object_server,
                    &writer,
                    &StdMutex::new(None),
                )
                .await;
            }
        });

        let client = Connection::connect(&addr).await.unwrap();
        let reply = client
            .call_method(
                None,
                ObjectPath::new("/echo").unwrap(),
                None,
                "Ping",
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(reply, vec![Value::string("pong")]);

        drop(client);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), server_task).await;
        std::fs::remove_file(&sock).ok();
    }

    #[tokio::test]
    async fn properties_changed_round_trips_correctly() {
        let dir = std::env::temp_dir().join(format!("oxibus-propchg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("propchg.sock");
        let addr = Address::UnixPath(sock.display().to_string());

        let bound = oxibus_transport::bind(&addr).await.unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _peer) = bound.listener.accept().await.unwrap();
            let mut transport = Transport::new(stream).unwrap();
            transport.read_initial_nul().await.unwrap();
            loop {
                let line = transport.read_line().await.unwrap();
                if line.strip_prefix("AUTH EXTERNAL ").is_some() {
                    transport.write_line("OK 0000").await.unwrap();
                    break;
                }
            }
            let mut line = transport.read_line().await.unwrap();
            if line == "NEGOTIATE_UNIX_FD" {
                transport.write_line("AGREE_UNIX_FD").await.unwrap();
                line = transport.read_line().await.unwrap();
            }
            assert_eq!(line, "BEGIN");

            // the actual signal, nothing else - grab it directly rather
            // than going through the full driver/dispatch machinery.
            transport.read_message().await.unwrap()
        });

        let client = Connection::connect(&addr).await.unwrap();
        client
            .properties_changed(
                ObjectPath::new("/org/example/Battery").unwrap(),
                "org.freedesktop.UPower.Device",
                vec![("Percentage".to_string(), Value::Double(42.0))],
                vec!["IconName".to_string()],
            )
            .await
            .unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            msg.header.interface().unwrap(),
            "org.freedesktop.DBus.Properties"
        );
        assert_eq!(msg.header.member().unwrap(), "PropertiesChanged");
        assert_eq!(msg.body[0], Value::string("org.freedesktop.UPower.Device"));
        let Value::Array(changed) = &msg.body[1] else {
            panic!("expected a{{sv}}, got {:?}", msg.body[1]);
        };
        assert_eq!(changed.elements.len(), 1);
        let Value::DictEntry(k, v) = &changed.elements[0] else {
            panic!("expected dict entry");
        };
        assert_eq!(**k, Value::string("Percentage"));
        assert_eq!(**v, Value::Variant(Box::new(Value::Double(42.0))));
        let Value::Array(invalidated) = &msg.body[2] else {
            panic!("expected as, got {:?}", msg.body[2]);
        };
        assert_eq!(invalidated.elements, vec![Value::string("IconName")]);

        std::fs::remove_file(&sock).ok();
    }
}
