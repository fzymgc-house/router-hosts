//! PostgreSQL storage backend implementation
//!
//! This module provides event-sourced storage using PostgreSQL with sqlx.
//! PostgreSQL is ideal for multi-instance and cloud deployments where
//! horizontal scaling and high availability are required.
//!
//! # Compatibility
//!
//! Requires PostgreSQL 12+ (tested with PostgreSQL 17). The schema uses
//! `DISTINCT ON` for "last non-null value" patterns because PostgreSQL
//! does not currently support `IGNORE NULLS` in window functions.
//!
//! # Architecture
//!
//! - **migrations**: SQL schema in `migrations/postgres/` (applied via sqlx)
//! - **event_store**: Event sourcing write side (append-only events)
//! - **snapshot_store**: /etc/hosts versioning and snapshots
//! - **projection**: CQRS read side (DISTINCT ON with CTEs)
//!
//! # Connection Pooling
//!
//! Uses sqlx's PgPool for connection management with these defaults:
//! - min_connections: 1 (keep warm)
//! - max_connections: 10 (prevent overwhelming)
//! - acquire_timeout: 30s (match gRPC timeout)
//! - idle_timeout: 10min (release unused)
//!
//! ## Overriding Pool Settings
//!
//! Pool settings can be customized via connection string query parameters:
//!
//! ```text
//! postgres://host/db?options=-c%20statement_timeout=30000
//! postgres://host/db?sslmode=require
//! ```
//!
//! For fine-grained control, use environment variables or configure at
//! the PostgreSQL server level in `postgresql.conf`.
//!
//! # Differences from SQLite/DuckDB
//!
//! - True async (no spawn_blocking wrappers)
//! - Uses DISTINCT ON CTEs instead of IGNORE NULLS window functions
//! - Connection pooling for concurrent access
//! - Standard PostgreSQL SSL via sslmode parameter
//! - Better concurrent write handling than SQLite
//!
//! # Performance Characteristics
//!
//! The `host_entries_current` view uses 7 `DISTINCT ON` CTEs (one per field)
//! joined together. Unlike SQLite's correlated subqueries, PostgreSQL's query
//! planner can leverage indexes on `(aggregate_id, event_version)` for each CTE.
//!
//! Duplicate entry detection queries the `host_entries_current` view, which
//! materializes the CTEs and applies filters. This scales better than SQLite
//! for larger datasets but still requires scanning all active aggregates.
//!
//! **Ballpark estimates (single-instance):**
//! - < 1,000 hosts: < 10ms (instant)
//! - ~10,000 hosts: ~50ms (acceptable)
//! - ~100,000 hosts: ~500ms (consider caching or read replicas)
//!
//! PostgreSQL is suitable for deployments with 10,000+ hosts or requiring
//! concurrent multi-instance access. For single-instance small deployments
//! (< 1,000 hosts), SQLite or DuckDB offer simpler operational overhead.
//!
//! # Security
//!
//! All queries use sqlx's prepared statement bindings to prevent SQL injection.
//! Connection SSL is controlled via the `sslmode` URL parameter.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use ulid::Ulid;

use crate::error::StorageError;
use crate::traits::{EventStore, HostProjection, SnapshotStore, Storage};
use crate::types::{EventEnvelope, HostEntry, HostFilter, Snapshot, SnapshotId, SnapshotMetadata};

mod event_store;
mod projection;
mod snapshot_store;

/// Embedded PostgreSQL migrations
///
/// These migrations are compiled into the binary and applied at runtime.
/// Migration files are in `migrations/postgres/` directory.
static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("migrations/postgres");

/// PostgreSQL storage backend
///
/// Provides event-sourced storage using PostgreSQL with connection pooling.
/// All operations are truly async using sqlx.
///
/// # Examples
///
/// ```no_run
/// use router_hosts_storage::backends::postgres::PostgresStorage;
/// use router_hosts_storage::Storage;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let storage = PostgresStorage::new("postgres://user:pass@localhost/db").await?;
/// storage.initialize().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Create a new PostgreSQL storage backend
    ///
    /// # Arguments
    ///
    /// * `url` - PostgreSQL connection URL
    ///   - `postgres://user:pass@host:5432/dbname`
    ///   - `postgres://host/db?sslmode=require`
    ///   - `postgres://host/db?max_connections=20`
    ///
    /// # Pool Configuration
    ///
    /// Default pool settings (overridable via URL query params):
    /// - min_connections: 1
    /// - max_connections: 10
    /// - acquire_timeout: 30s
    /// - idle_timeout: 10min
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Connection` if:
    /// - URL is not a valid PostgreSQL connection string
    /// - Connection to database fails
    /// - Authentication fails
    pub async fn new(url: &str) -> Result<Self, StorageError> {
        // Validate URL format before attempting connection
        if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
            return Err(StorageError::InvalidData(format!(
                "invalid PostgreSQL URL: must start with postgres:// or postgresql://, got: {}",
                if url.len() > 50 {
                    format!("{}...", &url[..50])
                } else {
                    url.to_string()
                }
            )));
        }

        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .connect(url)
            .await
            .map_err(|e| StorageError::connection("failed to create PostgreSQL pool", e))?;

        Ok(Self { pool })
    }

    /// Get a reference to the connection pool
    ///
    /// This is primarily for internal use and testing. Direct pool access
    /// bypasses the storage abstraction layer.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl EventStore for PostgresStorage {
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
impl SnapshotStore for PostgresStorage {
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
impl HostProjection for PostgresStorage {
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
impl Storage for PostgresStorage {
    async fn initialize(&self) -> Result<(), StorageError> {
        MIGRATIONS
            .run(self.pool())
            .await
            .map_err(|e| StorageError::migration("failed to run PostgreSQL migrations", e))
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
                SELECT FROM information_schema.tables
                WHERE table_name = 'host_events'
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
