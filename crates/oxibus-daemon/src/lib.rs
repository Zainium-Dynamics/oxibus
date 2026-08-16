#![allow(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]
//! `oxibus-daemon` library surface — split out from `main.rs` so the bus
//! logic is unit-testable and reusable (e.g. by an in-process test harness
//! for `oxibus-tools`).

pub mod activation;
pub mod bus;
pub mod connection_handler;
pub mod dispatch;
pub mod driver;
pub mod identity;
pub mod launch_helper;
pub mod match_rules;
pub mod policy;
pub mod registry;
pub mod stats;

pub use bus::{Bus, BusKind};
