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
