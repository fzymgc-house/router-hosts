//! DuckDB storage backend implementation
//!
//! This module provides event-sourced storage using DuckDB as the backing store.
//! DuckDB is an embedded analytical database that's ideal for the event sourcing
//! pattern and works well in resource-constrained environments like routers.
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
//! DuckDB connections are not Send/Sync, so we wrap them in Arc<Mutex<Connection>>
//! and use tokio::task::spawn_blocking for all database operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::sync::Arc;
use ulid::Ulid;
use url::Url;

use crate::error::StorageError;
use crate::traits::{EventStore, HostProjection, SnapshotStore, Storage};
use crate::types::{EventEnvelope, HostEntry, HostFilter, Snapshot, SnapshotId, SnapshotMetadata};

mod event_store;
mod projection;
mod schema;
mod snapshot_store;

/// DuckDB storage backend
///
/// Provides event-sourced storage using an embedded DuckDB database.
/// All operations are executed asynchronously using spawn_blocking to
/// avoid blocking the async runtime.
///
/// # Examples
///
/// ```no_run
/// use router_hosts_storage::backends::duckdb::DuckDbStorage;
/// use router_hosts_storage::Storage;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // In-memory database for testing
/// let storage = DuckDbStorage::new("duckdb://:memory:").await?;
/// storage.initialize().await?;
///
/// // File-based database for production
/// let storage = DuckDbStorage::new("duckdb:///var/lib/router-hosts/events.duckdb").await?;
/// storage.initialize().await?;
/// # Ok(())
/// # }
/// ```
pub struct DuckDbStorage {
    /// DuckDB connection wrapped in Arc<Mutex> for thread-safe access
    /// across spawn_blocking boundaries
    conn: Arc<Mutex<duckdb::Connection>>,
}

impl DuckDbStorage {
    /// Create a new DuckDB storage backend
    ///
    /// # Arguments
    ///
    /// * `connection_string` - DuckDB connection URL
    ///   - `duckdb://:memory:` - In-memory database (for testing)
    ///   - `duckdb:///path/to/file.duckdb` - File-based database
    ///
    /// # Errors
    ///
    /// Returns `StorageError::InvalidConnectionString` if the URL is malformed
    /// or doesn't use the `duckdb://` scheme.
    ///
    /// Returns `StorageError::Connection` if the database connection fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use router_hosts_storage::backends::duckdb::DuckDbStorage;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let storage = DuckDbStorage::new("duckdb://:memory:").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(connection_string: &str) -> Result<Self, StorageError> {
        let path = Self::parse_connection_string(connection_string)?;

        // Open connection in spawn_blocking since it may do I/O
        let conn = tokio::task::spawn_blocking(move || {
            if path == ":memory:" {
                duckdb::Connection::open_in_memory()
            } else {
                duckdb::Connection::open(&path)
            }
        })
        .await
        .map_err(|e| StorageError::connection("failed to spawn blocking task", e))?
        .map_err(|e| StorageError::connection("failed to open DuckDB connection", e))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Parse DuckDB connection string
    ///
    /// Supports:
    /// - `duckdb://:memory:` - In-memory database
    /// - `duckdb:///absolute/path` - File-based database (absolute path)
    /// - `duckdb://./relative/path` - File-based database (relative path)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - URL scheme is not "duckdb"
    /// - URL cannot be parsed
    fn parse_connection_string(connection_string: &str) -> Result<String, StorageError> {
        // Special case: handle :memory: directly before URL parsing
        // URL parser doesn't handle this format well
        if connection_string == "duckdb://:memory:" {
            return Ok(":memory:".to_string());
        }

        let url = Url::parse(connection_string)
            .map_err(|e| StorageError::InvalidConnectionString(format!("invalid URL: {}", e)))?;

        if url.scheme() != "duckdb" {
            return Err(StorageError::InvalidConnectionString(format!(
                "expected scheme 'duckdb', got '{}'",
                url.scheme()
            )));
        }

        // For relative paths like duckdb://./path, the URL parser converts host to "."
        // and path to "/path". We need to reconstruct the original "./path"
        if let Some(host) = url.host_str() {
            if host == "." {
                // Relative path: reconstruct as ./path
                let path = url.path();
                if path.is_empty() || path == "/" {
                    return Err(StorageError::InvalidConnectionString(
                        "missing database path (use duckdb:///path/to/db.duckdb or duckdb://:memory:)"
                            .to_string(),
                    ));
                }
                return Ok(format!(".{}", path));
            }
        }

        // Extract path from URL (absolute paths)
        let path = url.path();
        if path.is_empty() || path == "/" {
            return Err(StorageError::InvalidConnectionString(
                "missing database path (use duckdb:///path/to/db.duckdb or duckdb://:memory:)"
                    .to_string(),
            ));
        }

        Ok(path.to_string())
    }

    /// Get a reference to the connection for internal use
    ///
    /// This is used by the sub-modules (event_store, snapshot_store, etc.)
    /// to access the connection within spawn_blocking closures.
    fn conn(&self) -> Arc<Mutex<duckdb::Connection>> {
        Arc::clone(&self.conn)
    }
}

#[async_trait]
impl EventStore for DuckDbStorage {
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
impl SnapshotStore for DuckDbStorage {
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
impl HostProjection for DuckDbStorage {
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
impl Storage for DuckDbStorage {
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
        // DuckDB connections don't need explicit close in Rust
        // The Drop impl handles cleanup
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connection_string_memory() {
        let result = DuckDbStorage::parse_connection_string("duckdb://:memory:");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ":memory:");
    }

    #[test]
    fn test_parse_connection_string_file() {
        let result =
            DuckDbStorage::parse_connection_string("duckdb:///var/lib/router-hosts/events.duckdb");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/var/lib/router-hosts/events.duckdb");
    }

    #[test]
    fn test_parse_connection_string_relative() {
        let result = DuckDbStorage::parse_connection_string("duckdb://./data/events.duckdb");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "./data/events.duckdb");
    }

    #[test]
    fn test_parse_connection_string_invalid_scheme() {
        let result = DuckDbStorage::parse_connection_string("sqlite:///path/to/db");
        assert!(result.is_err());
        match result {
            Err(StorageError::InvalidConnectionString(msg)) => {
                assert!(msg.contains("expected scheme 'duckdb'"));
            }
            _ => panic!("expected InvalidConnectionString error"),
        }
    }

    #[test]
    fn test_parse_connection_string_missing_path() {
        let result = DuckDbStorage::parse_connection_string("duckdb://");
        assert!(result.is_err());
        match result {
            Err(StorageError::InvalidConnectionString(msg)) => {
                assert!(msg.contains("missing database path"));
            }
            _ => panic!("expected InvalidConnectionString error"),
        }
    }

    #[tokio::test]
    async fn test_new_memory_database() {
        let storage = DuckDbStorage::new("duckdb://:memory:").await;
        assert!(storage.is_ok());
    }
}
