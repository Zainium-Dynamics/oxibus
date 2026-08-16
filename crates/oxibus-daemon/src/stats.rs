//! `org.freedesktop.DBus.Debug.Stats` — real counters, not placeholders
//! (matches `bus/stats.c`, gated by `-Dstats=true` / `oxibus.toml`'s
//! `features.stats`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub struct Stats {
    pub started_at: Instant,
    pub messages_routed: AtomicU64,
    pub bytes_routed: AtomicU64,
    pub signals_delivered: AtomicU64,
    pub activations_started: AtomicU64,
    pub policy_denials: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
            messages_routed: AtomicU64::new(0),
            bytes_routed: AtomicU64::new(0),
            signals_delivered: AtomicU64::new(0),
            activations_started: AtomicU64::new(0),
            policy_denials: AtomicU64::new(0),
        }
    }
}

impl Stats {
    pub fn record_routed(&self, bytes: u64) {
        self.messages_routed.fetch_add(1, Ordering::Relaxed);
        self.bytes_routed.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn record_signal(&self) {
        self.signals_delivered.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_activation(&self) {
        self.activations_started.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_denial(&self) {
        self.policy_denials.fetch_add(1, Ordering::Relaxed);
    }
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
