//! Storage abstraction layer for router-hosts
//!
//! Provides backend-agnostic traits for event sourcing storage.
//! Supports DuckDB (default), with SQLite and PostgreSQL planned.
//!
//! # Example
//!
//! ```ignore
//! use router_hosts_storage::{create_storage, StorageConfig};
//!
//! let config = StorageConfig::from_url("duckdb://:memory:")?;
//! let storage = create_storage(&config).await?;
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
pub use types::{EventEnvelope, HostEntry, HostEvent, HostFilter, Snapshot, SnapshotMetadata};

/// Create storage from configuration
///
/// This is the primary entry point for creating a storage backend.
/// It parses the configuration, creates the appropriate backend,
/// and initializes the schema.
///
/// # Errors
///
/// Returns `StorageError::InvalidConnectionString` if the backend type
/// is not yet implemented (SQLite, PostgreSQL).
pub async fn create_storage(
    config: &StorageConfig,
) -> Result<std::sync::Arc<dyn Storage>, StorageError> {
    use backends::duckdb::DuckDbStorage;

    let storage: std::sync::Arc<dyn Storage> = match config.backend {
        BackendType::DuckDb => {
            std::sync::Arc::new(DuckDbStorage::new(&config.connection_string).await?)
        }
        BackendType::Sqlite => {
            return Err(StorageError::InvalidConnectionString(
                "SQLite not yet implemented".into(),
            ))
        }
        BackendType::Postgres => {
            return Err(StorageError::InvalidConnectionString(
                "PostgreSQL not yet implemented".into(),
            ))
        }
    };

    storage.initialize().await?;
    Ok(storage)
}
