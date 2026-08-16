//! Per-connection lifecycle: SASL server handshake, registration into the
//! bus registry, the read loop that feeds [`crate::dispatch`], and cleanup
//! on disconnect.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use oxibus_auth::{ServerAction, ServerAuth};
use oxibus_transport::Transport;
use tokio::net::UnixStream;

use crate::bus::Bus;
use crate::dispatch;
use crate::registry::ConnectionEntry;

/// Releases the `Registry`'s incomplete-connection slot on every exit path
/// (auth failure, timeout, or successful handshake) without repeating the
/// bookkeeping call at each `return`.
struct IncompleteGuard<'a>(&'a Bus);
impl Drop for IncompleteGuard<'_> {
    fn drop(&mut self) {
        self.0.registry.end_incomplete();
    }
}

/// Owns one accepted connection end-to-end: enforces the incomplete- and
/// per-uid connection limits, runs the SASL handshake, registers a
/// [`ConnectionEntry`], then loops reading and dispatching messages until
/// the peer disconnects or a read fails — at which point it releases the
/// connection's names and broadcasts the resulting `NameOwnerChanged`/
/// `NameLost` signals.
pub async fn handle_connection(bus: Arc<Bus>, stream: UnixStream) {
    let max_incomplete = bus.config.limits.max_incomplete_connections;
    if !bus.registry.try_begin_incomplete(max_incomplete) {
        tracing::warn!("rejecting connection: {max_incomplete} incomplete connections already in flight");
        return;
    }
    let _guard = IncompleteGuard(&bus);

    let mut transport = match Transport::new(stream) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("failed to wrap accepted socket: {e}");
            return;
        }
    };
    transport.set_max_message_size(bus.config.limits.max_message_size);

    let max_per_user = bus.config.limits.max_connections_per_user;
    if bus.registry.connection_count_for_uid(transport.credentials().uid) >= max_per_user as usize {
        tracing::warn!(
            "rejecting connection from uid {}: already at max_connections_per_user ({max_per_user})",
            transport.credentials().uid
        );
        return;
    }

    let auth_timeout = Duration::from_millis(bus.config.limits.auth_timeout_ms);
    let handshake_result = tokio::time::timeout(auth_timeout, run_sasl_handshake(&bus, &mut transport)).await;
    match handshake_result {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => {
            tracing::debug!("SASL handshake failed: {reason}");
            return;
        }
        Err(_) => {
            tracing::debug!("SASL handshake timed out after {auth_timeout:?}");
            return;
        }
    }

    let security_label = oxibus_transport::credentials::peer_security_label(transport.raw_fd())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .or_else(|| {
            oxibus_transport::credentials::security_label(transport.credentials().pid)
                .and_then(|bytes| String::from_utf8(bytes).ok())
        });

    let unique_name = bus.registry.allocate_unique_name();
    let entry = Arc::new(ConnectionEntry {
        unique_name: unique_name.clone(),
        writer: transport.writer(),
        credentials: transport.credentials(),
        security_label,
        match_rules: RwLock::new(Vec::new()),
        is_monitor: AtomicBool::new(false),
        is_registered: AtomicBool::new(false),
    });
    bus.registry.add_connection(entry.clone());
    tracing::info!(
        "connection {unique_name} accepted (uid={}, pid={})",
        entry.credentials.uid,
        entry.credentials.pid
    );

    loop {
        let msg = match transport.read_message().await {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("connection {unique_name} read error: {e}");
                break;
            }
        };
        dispatch::dispatch_incoming(&bus, &entry, msg).await;
    }

    let events = bus.registry.remove_connection(&unique_name);
    dispatch::broadcast_name_owner_changes(&bus, events).await;
    tracing::info!("connection {unique_name} disconnected");
}

/// Runs the leading-NUL + SASL command loop up through `BEGIN`. Returns
/// `Err(reason)` on protocol violations or explicit rejection past the
/// configured failure limit; the caller (or the surrounding
/// `tokio::time::timeout`) is responsible for closing the socket either way
/// by simply dropping `transport`.
async fn run_sasl_handshake(bus: &Arc<Bus>, transport: &mut Transport) -> Result<(), String> {
    transport
        .read_initial_nul()
        .await
        .map_err(|e| format!("no leading NUL byte: {e}"))?;

    let mut auth = ServerAuth::new(
        transport.credentials(),
        bus.auth_mechanisms(),
        bus.allow_anonymous(),
        bus.guid(),
    );

    loop {
        let line = transport
            .read_line()
            .await
            .map_err(|e| format!("SASL read error: {e}"))?;
        match auth.feed_line(&line) {
            ServerAction::Send(lines) => {
                for l in lines {
                    transport
                        .write_line(&l)
                        .await
                        .map_err(|e| format!("SASL write error: {e}"))?;
                }
            }
            ServerAction::Begin { .. } => return Ok(()),
            ServerAction::Disconnect(reason) => return Err(reason),
        }
    }
}
