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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_connection_error_helper() {
        let source = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let err = StorageError::connection("failed to connect", source);

        match err {
            StorageError::Connection { message, source } => {
                assert_eq!(message, "failed to connect");
                assert!(source.is_some());
            }
            _ => panic!("Expected Connection variant"),
        }
    }

    #[test]
    fn test_query_error_helper() {
        let source = io::Error::new(io::ErrorKind::Other, "query failed");
        let err = StorageError::query("select failed", source);

        match err {
            StorageError::Query { message, source } => {
                assert_eq!(message, "select failed");
                assert!(source.is_some());
            }
            _ => panic!("Expected Query variant"),
        }
    }

    #[test]
    fn test_migration_error_helper() {
        let source = io::Error::new(io::ErrorKind::Other, "schema error");
        let err = StorageError::migration("migration v2 failed", source);

        match err {
            StorageError::Migration { message, source } => {
                assert_eq!(message, "migration v2 failed");
                assert!(source.is_some());
            }
            _ => panic!("Expected Migration variant"),
        }
    }

    #[test]
    fn test_error_display() {
        let err = StorageError::ConcurrentWriteConflict {
            aggregate_id: "host-123".into(),
        };
        assert!(err.to_string().contains("host-123"));

        let err = StorageError::DuplicateEntry {
            ip: "192.168.1.1".into(),
            hostname: "test.local".into(),
        };
        assert!(err.to_string().contains("192.168.1.1"));
        assert!(err.to_string().contains("test.local"));

        let err = StorageError::NotFound {
            entity_type: "host",
            id: "abc".into(),
        };
        assert!(err.to_string().contains("host"));
        assert!(err.to_string().contains("abc"));

        let err = StorageError::InvalidConnectionString("bad://url".into());
        assert!(err.to_string().contains("bad://url"));

        let err = StorageError::InvalidData("corrupted".into());
        assert!(err.to_string().contains("corrupted"));
    }
}
