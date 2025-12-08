//! Database layer for router-hosts server
//!
//! This module provides persistent storage using DuckDB with CQRS Event Sourcing:
//! - Host entries managed via event log
//! - Version snapshots for /etc/hosts backup/rollback
//!
//! ## Architecture: CQRS with Event Sourcing
//!
//! - `schema.rs` - Event store and materialized views
//! - `events.rs` - Domain events (HostCreated, IpAddressChanged, etc.)
//! - `event_store.rs` - Append-only event log with optimistic concurrency
//! - `projections.rs` - Read models built from events (Query side)
//!
//! The architecture eliminates soft-delete complexity by using immutable
//! events as the source of truth, with DuckDB views for efficient queries.

// Database layer is not yet used by gRPC handlers (will be used in future PR)
#![allow(dead_code)]
#![allow(unused_imports)]

// Event-sourced CQRS modules
mod event_store;
mod events;
mod projections;
mod schema;

// Public exports
pub use event_store::EventStore;
pub use events::{EventData, EventEnvelope, EventMetadata, HostEvent};
pub use projections::{HostEntry, HostProjections};
pub use schema::{Database, DatabaseError, DatabaseResult};

/// Snapshot of hosts file at a point in time
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub snapshot_id: String,
    pub created_at: i64, // Unix timestamp in microseconds
    pub hosts_content: String,
    pub entry_count: i32,
    pub trigger: String,
    pub name: Option<String>,
    pub event_log_position: Option<i64>,
}
