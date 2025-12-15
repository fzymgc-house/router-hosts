//! SQLite storage backend implementation
//!
//! This module provides event-sourced storage using SQLite as the backing store.
//! SQLite is a lightweight, file-based database that's widely available and
//! works well in resource-constrained environments.
//!
//! # Architecture
//!
//! - **schema**: Table definitions and migrations
//! - **event_store**: Event sourcing write side (append-only events)
//! - **snapshot_store**: /etc/hosts versioning and snapshots
//! - **projection**: CQRS read side (materialized view of current state)
//!
//! # Connection Management
//!
//! SQLite connections are not Send/Sync, so we wrap them in Arc<Mutex<Connection>>
//! and use tokio::task::spawn_blocking for all database operations.
//!
//! # Differences from DuckDB
//!
//! SQLite doesn't support `IGNORE NULLS` in window functions, so the projection
//! uses a different approach (subqueries or application-level merging).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::sync::Arc;
use ulid::Ulid;

use crate::error::StorageError;
use crate::traits::{EventStore, HostProjection, SnapshotStore, Storage};
use crate::types::{EventEnvelope, HostEntry, HostFilter, Snapshot, SnapshotId, SnapshotMetadata};

mod event_store;
mod projection;
mod schema;
mod snapshot_store;

pub use schema::initialize_schema;

/// SQLite storage backend
///
/// Provides event-sourced storage using an embedded SQLite database.
/// All operations are executed asynchronously using spawn_blocking to
/// avoid blocking the async runtime.
///
/// # Examples
///
/// ```no_run
/// use router_hosts_storage::backends::sqlite::SqliteStorage;
/// use router_hosts_storage::Storage;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // In-memory database for testing
/// let storage = SqliteStorage::new(":memory:").await?;
/// storage.initialize().await?;
///
/// // File-based database for production
/// let storage = SqliteStorage::new("/var/lib/router-hosts/events.sqlite").await?;
/// storage.initialize().await?;
/// # Ok(())
/// # }
/// ```
pub struct SqliteStorage {
    /// SQLite connection wrapped in Arc<Mutex> for thread-safe access
    /// across spawn_blocking boundaries
    conn: Arc<Mutex<rusqlite::Connection>>,
}

impl SqliteStorage {
    /// Create a new SQLite storage backend
    ///
    /// # Arguments
    ///
    /// * `path` - Database path or `:memory:` for in-memory database
    ///   - `:memory:` - In-memory database (for testing)
    ///   - `/path/to/file.sqlite` - File-based database (absolute path)
    ///   - `./relative/path.sqlite` - File-based database (relative path)
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Connection` if the database connection fails.
    pub async fn new(path: &str) -> Result<Self, StorageError> {
        let path = path.to_string();

        // Open connection in spawn_blocking since it may do I/O
        let conn = tokio::task::spawn_blocking(move || {
            if path == ":memory:" {
                rusqlite::Connection::open_in_memory()
            } else {
                rusqlite::Connection::open(&path)
            }
        })
        .await
        .map_err(|e| StorageError::connection("failed to spawn blocking task", e))?
        .map_err(|e| StorageError::connection("failed to open SQLite connection", e))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Get a reference to the connection for internal use
    fn conn(&self) -> Arc<Mutex<rusqlite::Connection>> {
        Arc::clone(&self.conn)
    }
}

#[async_trait]
impl EventStore for SqliteStorage {
    async fn append_event(
        &self,
        aggregate_id: Ulid,
        event: EventEnvelope,
        expected_version: Option<String>,
    ) -> Result<(), StorageError> {
        self.append_event_impl(aggregate_id, event, expected_version)
            .await
    }

    async fn append_events(
        &self,
        aggregate_id: Ulid,
        events: Vec<EventEnvelope>,
        expected_version: Option<String>,
    ) -> Result<(), StorageError> {
        self.append_events_impl(aggregate_id, events, expected_version)
            .await
    }

    async fn load_events(&self, aggregate_id: Ulid) -> Result<Vec<EventEnvelope>, StorageError> {
        self.load_events_impl(aggregate_id).await
    }

    async fn get_current_version(
        &self,
        aggregate_id: Ulid,
    ) -> Result<Option<String>, StorageError> {
        self.get_current_version_impl(aggregate_id).await
    }

    async fn count_events(&self, aggregate_id: Ulid) -> Result<i64, StorageError> {
        self.count_events_impl(aggregate_id).await
    }
}

#[async_trait]
impl SnapshotStore for SqliteStorage {
    async fn save_snapshot(&self, snapshot: Snapshot) -> Result<(), StorageError> {
        self.save_snapshot_impl(snapshot).await
    }

    async fn get_snapshot(&self, snapshot_id: &SnapshotId) -> Result<Snapshot, StorageError> {
        self.get_snapshot_impl(snapshot_id).await
    }

    async fn list_snapshots(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<SnapshotMetadata>, StorageError> {
        self.list_snapshots_impl(limit, offset).await
    }

    async fn delete_snapshot(&self, snapshot_id: &SnapshotId) -> Result<(), StorageError> {
        self.delete_snapshot_impl(snapshot_id).await
    }

    async fn apply_retention_policy(
        &self,
        max_count: Option<usize>,
        max_age_days: Option<u32>,
    ) -> Result<usize, StorageError> {
        self.apply_retention_policy_impl(max_count, max_age_days)
            .await
    }
}

#[async_trait]
impl HostProjection for SqliteStorage {
    async fn list_all(&self) -> Result<Vec<HostEntry>, StorageError> {
        self.list_all_impl().await
    }

    async fn get_by_id(&self, id: Ulid) -> Result<HostEntry, StorageError> {
        self.get_by_id_impl(id).await
    }

    async fn find_by_ip_and_hostname(
        &self,
        ip_address: &str,
        hostname: &str,
    ) -> Result<Option<HostEntry>, StorageError> {
        self.find_by_ip_and_hostname_impl(ip_address, hostname)
            .await
    }

    async fn search(&self, filter: HostFilter) -> Result<Vec<HostEntry>, StorageError> {
        self.search_impl(filter).await
    }

    async fn get_at_time(&self, at_time: DateTime<Utc>) -> Result<Vec<HostEntry>, StorageError> {
        self.get_at_time_impl(at_time).await
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn initialize(&self) -> Result<(), StorageError> {
        schema::initialize_schema(self).await
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();

            // Simple health check: verify we can execute a query
            conn.query_row("SELECT 1", [], |row| row.get::<_, i32>(0))
                .map_err(|e| StorageError::connection("health check query failed", e))?;

            Ok(())
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during health check", e))?
    }

    async fn close(&self) -> Result<(), StorageError> {
        // SQLite connections don't need explicit close in Rust
        // The Drop impl handles cleanup
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_memory_database() {
        let storage = SqliteStorage::new(":memory:").await;
        assert!(storage.is_ok());
    }

    #[tokio::test]
    async fn test_new_file_database() {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let db_path = temp_dir.path().join("test.sqlite");
        let db_path_str = db_path.to_string_lossy().to_string();

        let storage = SqliteStorage::new(&db_path_str).await;
        assert!(storage.is_ok());

        // Verify file was created
        assert!(db_path.exists());
    }
}
