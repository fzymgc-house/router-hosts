//! Database layer for router-hosts server
//!
//! This module provides persistent storage using DuckDB for:
//! - Host entries (CRUD operations)
//! - Version snapshots (backup and rollback)
//! - Edit session management (draft changes)
//!
//! ## Architecture: CQRS with Event Sourcing
//!
//! This module implements Command Query Responsibility Segregation (CQRS) pattern:
//!
//! ### V1 (Legacy - Soft Delete Pattern):
//! - `schema.rs` - Traditional CRUD schema with soft deletes
//! - `hosts.rs` - Repository with optimistic locking (ULID version tags)
//! - `snapshots.rs` - Snapshot management for /etc/hosts versioning
//!
//! ### V2 (Event Sourced - Current):
//! - `schema_v2.rs` - Event store and materialized views
//! - `events.rs` - Domain events (HostCreated, IpAddressChanged, etc.)
//! - `event_store.rs` - Append-only event log with optimistic concurrency
//! - `projections.rs` - Read models built from events (Query side)
//!
//! The V2 architecture eliminates soft-delete complexity by using immutable
//! events as the source of truth, with DuckDB views for efficient queries.

// Database layer is not yet used by gRPC handlers (will be used in future PR)
#![allow(dead_code)]
#![allow(unused_imports)]

// V1 modules (legacy soft-delete pattern)
mod hosts;
mod schema;
mod snapshots;

// V2 modules (event-sourced CQRS)
mod event_store;
mod events;
mod projections;
mod schema_v2;

// V1 exports
pub use hosts::HostsRepository;
pub use schema::{Database, DatabaseError, DatabaseResult};
pub use snapshots::SnapshotsRepository;

// V2 exports
pub use event_store::EventStore;
pub use events::{EventEnvelope, EventMetadata, HostEvent};
pub use projections::{HostEntry as HostEntryV2, HostProjections};
pub use schema_v2::{
    Database as DatabaseV2, DatabaseError as DatabaseErrorV2, DatabaseResult as DatabaseResultV2,
};

use chrono::{DateTime, Utc};
use ulid::Ulid;
use uuid::Uuid;

/// Represents a host entry in the database
#[derive(Debug, Clone, PartialEq)]
pub struct HostEntry {
    pub id: Uuid,
    pub ip_address: String,
    pub hostname: String,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub active: bool,
    pub version_tag: Ulid,
}

/// Represents a version snapshot
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub snapshot_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub hosts_content: String,
    pub entry_count: i32,
    pub trigger: SnapshotTrigger,
    pub name: Option<String>,
}

/// Snapshot trigger type
#[derive(Debug, Clone, PartialEq)]
pub enum SnapshotTrigger {
    Manual,
    AutoBeforeChange,
    Scheduled,
}

impl std::fmt::Display for SnapshotTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotTrigger::Manual => write!(f, "manual"),
            SnapshotTrigger::AutoBeforeChange => write!(f, "auto_before_change"),
            SnapshotTrigger::Scheduled => write!(f, "scheduled"),
        }
    }
}
