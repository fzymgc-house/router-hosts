//! Storage error types

use std::error::Error as StdError;
use thiserror::Error;

/// Boxed error for wrapping backend-specific errors
pub type BoxedError = Box<dyn StdError + Send + Sync>;

/// Storage layer errors
#[derive(Debug, Error)]
pub enum StorageError {
    /// Optimistic concurrency conflict
    #[error("concurrent write conflict on aggregate {aggregate_id}")]
    ConcurrentWriteConflict { aggregate_id: String },

    /// Duplicate IP+hostname entry
    #[error("duplicate entry: {ip} {hostname} already exists")]
    DuplicateEntry { ip: String, hostname: String },

    /// Entity not found
    #[error("not found: {entity_type} with id {id}")]
    NotFound {
        entity_type: &'static str,
        id: String,
    },

    /// Connection failure
    #[error("connection failed: {message}")]
    Connection {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    /// Query execution failure
    #[error("query failed: {message}")]
    Query {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    /// Schema migration failure
    #[error("schema migration failed: {message}")]
    Migration {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    /// Invalid connection string
    #[error("invalid connection string: {0}")]
    InvalidConnectionString(String),

    /// Invalid data (corruption or format error)
    #[error("invalid data: {0}")]
    InvalidData(String),
}

impl StorageError {
    /// Create a connection error with source
    pub fn connection(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Connection {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a query error with source
    pub fn query(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Query {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a migration error with source
    pub fn migration(
        message: impl Into<String>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self::Migration {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}
