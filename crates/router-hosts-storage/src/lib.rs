//! Storage abstraction layer for router-hosts
//!
//! Provides backend-agnostic traits for event sourcing storage with CQRS pattern.
//!
//! # Supported Backends
//!
//! - **SQLite** (feature: `sqlite`, default) - Lightweight, widely-available embedded database
//! - **PostgreSQL** (feature: `postgres`) - Scalable networked database for multi-instance deployments
//! - **DuckDB** (feature: `duckdb`) - High-performance embedded analytics database
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
//! ## SQLite (default)
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
//!
//! ## DuckDB
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

/// Returns a list of storage backends available in this build.
///
/// This is determined at compile time based on enabled features.
/// Use this to display available backends in `--version` output.
///
/// # Example
///
/// ```
/// let backends = router_hosts_storage::available_backends();
/// println!("Supported backends: {}", backends.join(", "));
/// ```
pub fn available_backends() -> &'static [&'static str] {
    &[
        #[cfg(feature = "sqlite")]
        "sqlite",
        #[cfg(feature = "postgres")]
        "postgres",
        #[cfg(feature = "duckdb")]
        "duckdb",
    ]
}

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
                "DuckDB backend not available in this build.\n\n\
                 To use DuckDB, install the router-hosts-duckdb variant:\n  \
                 macOS:  brew install fzymgc-house/tap/router-hosts-duckdb\n  \
                 Other:  https://github.com/fzymgc-house/router-hosts/releases\n\n\
                 Or switch to a supported backend:\n  \
                 sqlite:///path/to/hosts.db\n  \
                 postgres://user:pass@host/db"
                    .into(),
            ))
        }
        #[cfg(feature = "sqlite")]
        BackendType::Sqlite => std::sync::Arc::new(
            backends::sqlite::SqliteStorage::new(&config.connection_string).await?,
        ),
        #[cfg(not(feature = "sqlite"))]
        BackendType::Sqlite => {
            return Err(StorageError::InvalidConnectionString(
                "SQLite backend not available in this build.\n\n\
                 This is unexpected - SQLite is the default backend.\n\
                 Please report this issue at:\n  \
                 https://github.com/fzymgc-house/router-hosts/issues"
                    .into(),
            ))
        }
        #[cfg(feature = "postgres")]
        BackendType::Postgres => std::sync::Arc::new(
            backends::postgres::PostgresStorage::new(&config.connection_string).await?,
        ),
        #[cfg(not(feature = "postgres"))]
        BackendType::Postgres => {
            return Err(StorageError::InvalidConnectionString(
                "PostgreSQL backend not available in this build.\n\n\
                 PostgreSQL support requires the 'postgres' feature.\n\
                 The standard router-hosts binary includes PostgreSQL support.\n\n\
                 Or switch to the default SQLite backend:\n  \
                 sqlite:///path/to/hosts.db"
                    .into(),
            ))
        }
    };

    storage.initialize().await?;
    Ok(storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[cfg(feature = "duckdb")]
    async fn test_create_storage_duckdb_memory() {
        let config = StorageConfig::from_url("duckdb://:memory:").unwrap();
        let storage = create_storage(&config).await.unwrap();
        assert!(storage.health_check().await.is_ok());
    }

    #[tokio::test]
    #[cfg(feature = "sqlite")]
    async fn test_create_storage_sqlite_memory() {
        let config = StorageConfig::from_url("sqlite://:memory:").unwrap();
        let storage = create_storage(&config).await.unwrap();
        assert!(storage.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_create_storage_invalid_backend() {
        // Test that parsing fails for unknown backend
        let result = StorageConfig::from_url("unknown://test");
        assert!(result.is_err());
    }
}
