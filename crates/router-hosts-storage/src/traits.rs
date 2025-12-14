//! Storage trait definitions
//!
//! This module defines the trait interfaces for the storage abstraction layer.
//! The design follows CQRS pattern:
//! - EventStore: Event sourcing write side
//! - HostProjection: CQRS read side
//! - SnapshotStore: /etc/hosts versioning
//! - Storage: Combined interface with lifecycle management

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ulid::Ulid;

use crate::error::StorageError;
use crate::types::{EventEnvelope, HostEntry, HostFilter, Snapshot, SnapshotMetadata};

/// Event sourcing write side
///
/// Stores immutable events with optimistic concurrency control.
/// Events are append-only and never updated or deleted.
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Append a single event with optimistic concurrency check
    ///
    /// # Arguments
    /// * `aggregate_id` - The aggregate root identifier
    /// * `event` - The event envelope to append
    /// * `expected_version` - Expected current version (for optimistic locking)
    ///
    /// # Errors
    /// * `StorageError::ConcurrentWriteConflict` - Version mismatch
    /// * `StorageError::Query` - Database error
    async fn append_event(
        &self,
        aggregate_id: Ulid,
        event: EventEnvelope,
        expected_version: Option<String>,
    ) -> Result<(), StorageError>;

    /// Append multiple events atomically
    ///
    /// All events must belong to the same aggregate and will be written
    /// in a single transaction. If any event fails, all are rolled back.
    ///
    /// # Arguments
    /// * `aggregate_id` - The aggregate root identifier
    /// * `events` - The event envelopes to append
    /// * `expected_version` - Expected current version before appending
    ///
    /// # Errors
    /// * `StorageError::ConcurrentWriteConflict` - Version mismatch
    /// * `StorageError::Query` - Database error
    async fn append_events(
        &self,
        aggregate_id: Ulid,
        events: Vec<EventEnvelope>,
        expected_version: Option<String>,
    ) -> Result<(), StorageError>;

    /// Load all events for an aggregate in order
    ///
    /// Returns events sorted by event_version ascending.
    ///
    /// # Arguments
    /// * `aggregate_id` - The aggregate root identifier
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn load_events(&self, aggregate_id: Ulid) -> Result<Vec<EventEnvelope>, StorageError>;

    /// Get the current version for an aggregate
    ///
    /// Returns the latest event_version, or None if no events exist.
    ///
    /// # Arguments
    /// * `aggregate_id` - The aggregate root identifier
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn get_current_version(&self, aggregate_id: Ulid)
        -> Result<Option<String>, StorageError>;

    /// Count events for an aggregate
    ///
    /// # Arguments
    /// * `aggregate_id` - The aggregate root identifier
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn count_events(&self, aggregate_id: Ulid) -> Result<i64, StorageError>;
}

/// Snapshot storage for /etc/hosts versioning
///
/// Stores point-in-time snapshots of the hosts file with metadata.
/// Supports retention policies and time-travel queries.
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    /// Save a new snapshot
    ///
    /// # Arguments
    /// * `snapshot` - The snapshot to save
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn save_snapshot(&self, snapshot: Snapshot) -> Result<(), StorageError>;

    /// Get a snapshot by ID
    ///
    /// # Arguments
    /// * `snapshot_id` - The snapshot identifier
    ///
    /// # Errors
    /// * `StorageError::NotFound` - Snapshot doesn't exist
    /// * `StorageError::Query` - Database error
    async fn get_snapshot(&self, snapshot_id: &str) -> Result<Snapshot, StorageError>;

    /// List all snapshots (metadata only, no content)
    ///
    /// Returns snapshots sorted by created_at descending (newest first).
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn list_snapshots(&self) -> Result<Vec<SnapshotMetadata>, StorageError>;

    /// Delete a snapshot by ID
    ///
    /// # Arguments
    /// * `snapshot_id` - The snapshot identifier
    ///
    /// # Errors
    /// * `StorageError::NotFound` - Snapshot doesn't exist
    /// * `StorageError::Query` - Database error
    async fn delete_snapshot(&self, snapshot_id: &str) -> Result<(), StorageError>;

    /// Apply retention policy (delete old snapshots)
    ///
    /// Removes snapshots exceeding retention limits.
    ///
    /// # Arguments
    /// * `max_count` - Maximum number of snapshots to keep (None = unlimited)
    /// * `max_age_days` - Maximum age in days (None = unlimited)
    ///
    /// # Returns
    /// Number of snapshots deleted
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn apply_retention_policy(
        &self,
        max_count: Option<i32>,
        max_age_days: Option<i32>,
    ) -> Result<i32, StorageError>;
}

/// CQRS read side projection
///
/// Provides optimized queries over the current state of host entries.
/// This is the materialized view rebuilt from events.
#[async_trait]
pub trait HostProjection: Send + Sync {
    /// List all host entries
    ///
    /// Returns entries sorted by IP address, then hostname.
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn list_all(&self) -> Result<Vec<HostEntry>, StorageError>;

    /// Get a host entry by ID
    ///
    /// # Arguments
    /// * `id` - The host entry identifier
    ///
    /// # Errors
    /// * `StorageError::NotFound` - Entry doesn't exist
    /// * `StorageError::Query` - Database error
    async fn get_by_id(&self, id: Ulid) -> Result<HostEntry, StorageError>;

    /// Find entry by IP and hostname (duplicate detection)
    ///
    /// # Arguments
    /// * `ip_address` - The IP address to search for
    /// * `hostname` - The hostname to search for
    ///
    /// # Returns
    /// Some(entry) if found, None if not exists
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn find_by_ip_and_hostname(
        &self,
        ip_address: &str,
        hostname: &str,
    ) -> Result<Option<HostEntry>, StorageError>;

    /// Search entries with filters
    ///
    /// Applies filters for IP pattern, hostname pattern, and tags.
    /// Empty filter returns all entries.
    ///
    /// # Arguments
    /// * `filter` - Search filter criteria
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn search(&self, filter: HostFilter) -> Result<Vec<HostEntry>, StorageError>;

    /// Get entries as they existed at a specific time (time travel query)
    ///
    /// Reconstructs state by replaying events up to the given timestamp.
    ///
    /// # Arguments
    /// * `at_time` - The point in time to query
    ///
    /// # Errors
    /// * `StorageError::Query` - Database error
    async fn get_at_time(&self, at_time: DateTime<Utc>) -> Result<Vec<HostEntry>, StorageError>;
}

/// Combined storage interface with lifecycle management
///
/// This is the main trait that consumers interact with. It composes
/// EventStore, SnapshotStore, and HostProjection along with lifecycle
/// methods for initialization, health checks, and cleanup.
#[async_trait]
pub trait Storage: EventStore + SnapshotStore + HostProjection {
    /// Initialize storage (schema setup, migrations)
    ///
    /// Must be called before any other operations. Idempotent - safe to
    /// call multiple times.
    ///
    /// # Errors
    /// * `StorageError::Migration` - Schema setup failed
    /// * `StorageError::Connection` - Connection failed
    async fn initialize(&self) -> Result<(), StorageError>;

    /// Check storage health and connectivity
    ///
    /// Performs a lightweight check to verify the storage backend is
    /// accessible and responsive.
    ///
    /// # Errors
    /// * `StorageError::Connection` - Backend unreachable
    /// * `StorageError::Query` - Health check query failed
    async fn health_check(&self) -> Result<(), StorageError>;

    /// Close storage connections and clean up resources
    ///
    /// Should be called during graceful shutdown. After calling close,
    /// no other operations should be performed.
    async fn close(&self) -> Result<(), StorageError>;
}
