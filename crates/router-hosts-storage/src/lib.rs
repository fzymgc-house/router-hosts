//! Storage abstraction layer for router-hosts
//!
//! Provides backend-agnostic traits for event sourcing storage.
//! Supports DuckDB (default), with SQLite and PostgreSQL planned.

mod config;
mod error;
mod traits;
mod types;

pub mod backends;

// Re-exports
pub use error::StorageError;
pub use traits::{EventStore, HostProjection, SnapshotStore, Storage};
pub use types::{EventEnvelope, HostEntry, HostEvent, Snapshot, SnapshotMetadata};

// Config and create_storage (commented out until full implementation)
// pub use config::{StorageConfig, BackendType};

// Create storage from configuration (commented out until traits are implemented)
// pub async fn create_storage(config: &StorageConfig) -> Result<std::sync::Arc<dyn Storage>, StorageError> {
//     use backends::duckdb::DuckDbStorage;
//
//     let storage: std::sync::Arc<dyn Storage> = match config.backend {
//         BackendType::DuckDb => std::sync::Arc::new(DuckDbStorage::new(&config.connection_string).await?),
//         BackendType::Sqlite => return Err(StorageError::InvalidConnectionString("SQLite not yet implemented".into())),
//         BackendType::Postgres => return Err(StorageError::InvalidConnectionString("PostgreSQL not yet implemented".into())),
//     };
//
//     storage.initialize().await?;
//     Ok(storage)
// }
