//! Storage abstraction layer for router-hosts
//!
//! Provides backend-agnostic traits for event sourcing storage with CQRS pattern.
//!
//! # Supported Backends
//!
//! - **DuckDB** (feature: `duckdb`, default) - High-performance embedded analytics database
//! - **SQLite** (feature: `sqlite`) - Lightweight, widely-available embedded database
//! - **PostgreSQL** (feature: `postgres`) - Scalable networked database for multi-instance deployments
//!
//! # Architecture
//!
//! All backends implement the same traits:
//! - [`EventStore`] - Append-only event log (write side)
//! - [`SnapshotStore`] - Versioned /etc/hosts snapshots
//! - [`HostProjection`] - Current state queries (read side)
//! - [`Storage`] - Lifecycle management (initialize, health check, close)
//!
//! # Examples
//!
//! ## DuckDB (default)
//!
//! ```no_run
//! use router_hosts_storage::{create_storage, StorageConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = StorageConfig::from_url("duckdb://:memory:")?;
//! let storage = create_storage(&config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## SQLite
//!
//! ```no_run
//! use router_hosts_storage::{create_storage, StorageConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // In-memory for testing
//! let config = StorageConfig::from_url("sqlite://:memory:")?;
//! let storage = create_storage(&config).await?;
//!
//! // File-based for production
//! let config = StorageConfig::from_url("sqlite:///var/lib/router-hosts/events.db")?;
//! let storage = create_storage(&config).await?;
//! # Ok(())
//! # }
//! ```

mod config;
mod error;
mod traits;
mod types;

pub mod backends;

// Re-exports
pub use config::{BackendType, ConfigError, StorageConfig};
pub use error::StorageError;
pub use traits::{EventStore, HostProjection, SnapshotStore, Storage};
pub use types::{
    EventEnvelope, HostEntry, HostEvent, HostFilter, Snapshot, SnapshotId, SnapshotMetadata,
};

/// Create storage from configuration
///
/// This is the primary entry point for creating a storage backend.
/// It parses the configuration, creates the appropriate backend,
/// and initializes the schema.
///
/// # Errors
///
/// Returns `StorageError::InvalidConnectionString` if the backend type
/// is not compiled in (missing feature flag) or not yet implemented.
pub async fn create_storage(
    config: &StorageConfig,
) -> Result<std::sync::Arc<dyn Storage>, StorageError> {
    let storage: std::sync::Arc<dyn Storage> = match config.backend {
        #[cfg(feature = "duckdb")]
        BackendType::DuckDb => std::sync::Arc::new(
            backends::duckdb::DuckDbStorage::new(&config.connection_string).await?,
        ),
        #[cfg(not(feature = "duckdb"))]
        BackendType::DuckDb => {
            return Err(StorageError::InvalidConnectionString(
                "DuckDB backend not compiled in (enable 'duckdb' feature)".into(),
            ))
        }
        #[cfg(feature = "sqlite")]
        BackendType::Sqlite => std::sync::Arc::new(
            backends::sqlite::SqliteStorage::new(&config.connection_string).await?,
        ),
        #[cfg(not(feature = "sqlite"))]
        BackendType::Sqlite => {
            return Err(StorageError::InvalidConnectionString(
                "SQLite backend not compiled in (enable 'sqlite' feature)".into(),
            ))
        }
        #[cfg(feature = "postgres")]
        BackendType::Postgres => std::sync::Arc::new(
            backends::postgres::PostgresStorage::new(&config.connection_string).await?,
        ),
        #[cfg(not(feature = "postgres"))]
        BackendType::Postgres => {
            return Err(StorageError::InvalidConnectionString(
                "PostgreSQL backend not compiled in (enable 'postgres' feature)".into(),
            ))
        }
    };

    storage.initialize().await?;
    Ok(storage)
}
