//! PostgreSQL storage backend implementation
//!
//! This module provides event-sourced storage using PostgreSQL with sqlx.
//! PostgreSQL is ideal for multi-instance and cloud deployments where
//! horizontal scaling and high availability are required.
//!
//! # Architecture
//!
//! - **schema**: Table definitions (CREATE TABLE IF NOT EXISTS)
//! - **event_store**: Event sourcing write side (append-only events)
//! - **snapshot_store**: /etc/hosts versioning and snapshots
//! - **projection**: CQRS read side (window functions with IGNORE NULLS)
//!
//! # Connection Pooling
//!
//! Uses sqlx's PgPool for connection management:
//! - min_connections: 1 (keep warm)
//! - max_connections: 10 (prevent overwhelming)
//! - acquire_timeout: 30s (match gRPC timeout)
//! - idle_timeout: 10min (release unused)
//!
//! Pool settings can be overridden via connection string query params.
//!
//! # Differences from SQLite/DuckDB
//!
//! - True async (no spawn_blocking wrappers)
//! - Supports IGNORE NULLS in window functions (like DuckDB)
//! - Connection pooling for concurrent access
//! - Standard PostgreSQL SSL via sslmode parameter

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
mod schema;
mod snapshot_store;

pub use schema::initialize_schema;

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
    /// Returns `StorageError::Connection` if pool creation fails.
    pub async fn new(url: &str) -> Result<Self, StorageError> {
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

    /// Get a reference to the connection pool for internal use
    fn pool(&self) -> &PgPool {
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
        schema::initialize_schema(self).await
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1")
            .execute(self.pool())
            .await
            .map_err(|e| StorageError::connection("health check failed", e))?;
        Ok(())
    }

    async fn close(&self) -> Result<(), StorageError> {
        self.pool.close().await;
        Ok(())
    }
}
