//! Database layer for router-hosts server
//!
//! This module provides persistent storage using DuckDB for:
//! - Host entries (CRUD operations)
//! - Version snapshots (backup and rollback)
//! - Edit session management (draft changes)

// Database layer is not yet used by gRPC handlers (will be used in future PR)
#![allow(dead_code)]
#![allow(unused_imports)]

mod hosts;
mod schema;
mod snapshots;

pub use hosts::HostsRepository;
pub use schema::{Database, DatabaseError, DatabaseResult};
pub use snapshots::SnapshotsRepository;

use chrono::{DateTime, Utc};
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
