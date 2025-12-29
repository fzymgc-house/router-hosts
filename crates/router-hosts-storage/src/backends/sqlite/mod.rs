//! SQLite storage backend implementation using sqlx
//!
//! This module provides event-sourced storage using SQLite as the backing store.
//! SQLite is a lightweight, file-based database that's widely available and
//! works well in resource-constrained environments.
//!
//! # Architecture
//!
//! - **migrations**: SQL schema in `migrations/sqlite/` (applied via sqlx)
//! - **event_store**: Event sourcing write side (append-only events)
//! - **snapshot_store**: /etc/hosts versioning and snapshots
//! - **projection**: CQRS read side (materialized view of current state)
//!
//! # Connection Management
//!
//! Uses sqlx's SqlitePool for true async database operations without blocking
//! the Tokio runtime.
//!
//! # Differences from DuckDB
//!
//! SQLite doesn't support `IGNORE NULLS` in window functions, so the projection
//! uses a different approach (subqueries or application-level merging).
//!
//! # Performance Characteristics
//!
//! The `host_entries_current` view uses 7 correlated subqueries to reconstruct
//! the current state of each host from the event log. This scales as O(n × m × 7)
//! where n = number of hosts and m = average events per host.
//!
//! Additionally, duplicate entry detection (see `event_store.rs:append_event_impl`)
//! queries the `host_entries_current` view which is not indexable, resulting in a
//! full table scan. This is acceptable for small datasets but may become noticeable
//! with many hosts.
//!
//! **Ballpark estimates:**
//! - < 100 hosts: < 10ms (instant)
//! - ~1,000 hosts: ~100ms (acceptable)
//! - ~10,000 hosts: 1-2 seconds (consider DuckDB)
//!
//! This backend is optimized for router/small server deployments with < 1,000 hosts.
//! For larger deployments, consider using the DuckDB backend which uses window
//! functions instead of correlated subqueries.
//!
//! # Security
//!
//! All queries use sqlx's prepared statement bindings (`bind()`) to prevent
//! SQL injection. User-provided data is never interpolated into query strings.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;
use std::time::Duration;
use ulid::Ulid;

use crate::error::StorageError;
use crate::traits::{EventStore, HostProjection, SnapshotStore, Storage};
use crate::types::{EventEnvelope, HostEntry, HostFilter, Snapshot, SnapshotId, SnapshotMetadata};

mod event_store;
mod projection;
mod snapshot_store;

/// Embedded SQLite migrations
///
/// These migrations are compiled into the binary and applied at runtime.
/// Migration files are in `migrations/sqlite/` directory.
static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("migrations/sqlite");

/// SQLite storage backend
///
/// Provides event-sourced storage using an embedded SQLite database with sqlx.
/// All operations are truly async using sqlx's native async driver.
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
#[derive(Debug)]
pub struct SqliteStorage {
    pool: SqlitePool,
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
    /// # Pool Configuration
    ///
    /// Default pool settings with rationale:
    /// - min_connections: 1 - keeps one connection warm to avoid cold-start latency
    /// - max_connections: 5 - SQLite uses single-writer/multiple-reader model; more
    ///   connections add overhead without write throughput benefit
    /// - acquire_timeout: 30s - allows time for long transactions to complete
    /// - idle_timeout: 10min - balances resource usage with connection reuse
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Connection` if the database connection fails.
    pub async fn new(path: &str) -> Result<Self, StorageError> {
        // Build connection options with pragmas
        // Pragmas are set on each connection via SqliteConnectOptions
        let options = if path == ":memory:" {
            SqliteConnectOptions::from_str("sqlite::memory:")
                .map_err(|e| StorageError::connection("invalid SQLite URL", e))?
        } else {
            SqliteConnectOptions::from_str(&format!("sqlite://{}?mode=rwc", path))
                .map_err(|e| StorageError::connection("invalid SQLite URL", e))?
        }
        // Performance and durability pragmas applied to each connection
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .foreign_keys(true)
        // WAL auto-checkpoint after 1000 pages (~4MB with default page size)
        .pragma("wal_autocheckpoint", "1000");

        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(5) // SQLite is single-writer
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .connect_with(options)
            .await
            .map_err(|e| StorageError::connection("failed to create SQLite pool", e))?;

        Ok(Self { pool })
    }

    /// Get a reference to the connection pool for internal use
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
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
    fn backend_name(&self) -> &'static str {
        "sqlite"
    }

    async fn initialize(&self) -> Result<(), StorageError> {
        MIGRATIONS
            .run(self.pool())
            .await
            .map_err(|e| StorageError::migration("failed to run SQLite migrations", e))
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        // First check basic connectivity
        sqlx::query("SELECT 1")
            .execute(self.pool())
            .await
            .map_err(|e| StorageError::connection("health check: database connection failed", e))?;

        // Verify schema exists by checking for our tables
        let table_exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'host_events'
            )
            "#,
        )
        .fetch_one(self.pool())
        .await
        .map_err(|e| StorageError::connection("health check: failed to verify schema", e))?;

        if !table_exists {
            return Err(StorageError::connection(
                "health check: schema not initialized (host_events table missing)",
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "schema not initialized - call initialize() first",
                ),
            ));
        }

        Ok(())
    }

    async fn close(&self) -> Result<(), StorageError> {
        self.pool.close().await;
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

    #[tokio::test]
    async fn test_pool_exhaustion_returns_error() {
        // Create a pool with only 1 connection to make exhaustion testable
        let url = "sqlite::memory:";
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(100)) // Short timeout for test
            .connect(url)
            .await
            .expect("failed to create pool");

        // Hold the only connection
        let _held_conn = pool.acquire().await.expect("failed to acquire connection");

        // Try to acquire another - should timeout with an error
        let result = pool.acquire().await;
        assert!(
            result.is_err(),
            "Should fail when pool is exhausted and timeout expires"
        );

        // Verify the error is a timeout/pool exhaustion error
        let err = result.unwrap_err();
        let err_string = err.to_string().to_lowercase();
        assert!(
            err_string.contains("timed out") || err_string.contains("timeout"),
            "Error should indicate timeout: {}",
            err_string
        );
    }

    #[tokio::test]
    async fn test_pool_releases_connection_after_drop() {
        let url = "sqlite::memory:";
        let pool = SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(500))
            .connect(url)
            .await
            .expect("failed to create pool");

        // Acquire and release a connection
        {
            let _conn = pool.acquire().await.expect("failed to acquire connection");
            // Connection is dropped here
        }

        // Should be able to acquire again
        let result = pool.acquire().await;
        assert!(
            result.is_ok(),
            "Should be able to acquire after previous connection is dropped"
        );
    }

    #[tokio::test]
    async fn test_migrations_create_schema() {
        let storage = SqliteStorage::new(":memory:")
            .await
            .expect("failed to create in-memory storage");

        // Run migrations
        storage
            .initialize()
            .await
            .expect("migrations should succeed");

        // Verify tables exist by querying them
        let event_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM host_events")
            .fetch_one(storage.pool())
            .await
            .expect("host_events table should exist");
        assert_eq!(event_count.0, 0);

        let view_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM host_entries_current")
            .fetch_one(storage.pool())
            .await
            .expect("host_entries_current view should exist");
        assert_eq!(view_count.0, 0);

        let history_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM host_entries_history")
            .fetch_one(storage.pool())
            .await
            .expect("host_entries_history view should exist");
        assert_eq!(history_count.0, 0);

        let snapshot_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM snapshots")
            .fetch_one(storage.pool())
            .await
            .expect("snapshots table should exist");
        assert_eq!(snapshot_count.0, 0);

        // Verify migrations table was created by sqlx
        let migrations_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(storage.pool())
            .await
            .expect("_sqlx_migrations table should exist");
        assert!(
            migrations_count.0 >= 1,
            "at least one migration should be recorded"
        );
    }

    #[tokio::test]
    async fn test_migrations_are_idempotent() {
        let storage = SqliteStorage::new(":memory:")
            .await
            .expect("failed to create in-memory storage");

        // Run migrations twice - should not fail
        storage
            .initialize()
            .await
            .expect("first migration run should succeed");
        storage
            .initialize()
            .await
            .expect("second migration run should succeed (idempotent)");

        // Verify only one migration recorded (not duplicated)
        let migrations_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(storage.pool())
            .await
            .expect("_sqlx_migrations table should exist");
        assert_eq!(
            migrations_count.0, 1,
            "migration should only be recorded once"
        );
    }

    #[tokio::test]
    async fn test_migrations_create_indexes() {
        let storage = SqliteStorage::new(":memory:")
            .await
            .expect("failed to create in-memory storage");

        storage
            .initialize()
            .await
            .expect("migrations should succeed");

        // Query sqlite_master for all indexes on host_events table
        let indexes: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT name FROM sqlite_master
            WHERE type = 'index'
              AND tbl_name = 'host_events'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            "#,
        )
        .fetch_all(storage.pool())
        .await
        .expect("should be able to query indexes");

        let index_names: Vec<&str> = indexes.iter().map(|(name,)| name.as_str()).collect();

        // Verify all expected indexes exist
        assert!(
            index_names.contains(&"idx_events_aggregate"),
            "idx_events_aggregate index should exist, found: {:?}",
            index_names
        );
        assert!(
            index_names.contains(&"idx_events_time"),
            "idx_events_time index should exist, found: {:?}",
            index_names
        );
        assert!(
            index_names.contains(&"idx_events_ip_hostname"),
            "idx_events_ip_hostname index should exist, found: {:?}",
            index_names
        );

        // Also verify snapshots index
        let snapshot_indexes: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT name FROM sqlite_master
            WHERE type = 'index'
              AND tbl_name = 'snapshots'
              AND name NOT LIKE 'sqlite_%'
            "#,
        )
        .fetch_all(storage.pool())
        .await
        .expect("should be able to query snapshot indexes");

        let snapshot_index_names: Vec<&str> = snapshot_indexes
            .iter()
            .map(|(name,)| name.as_str())
            .collect();
        assert!(
            snapshot_index_names.contains(&"idx_snapshots_created"),
            "idx_snapshots_created index should exist, found: {:?}",
            snapshot_index_names
        );
    }
}
