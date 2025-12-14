//! Storage configuration

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur when parsing storage configuration
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Invalid URL format
    #[error("Invalid URL format: {0}")]
    InvalidUrl(#[from] url::ParseError),

    /// Unsupported URL scheme
    #[error("Unsupported URL scheme: {0}. Supported schemes: duckdb, sqlite, postgres")]
    UnsupportedScheme(String),

    /// Invalid pool size
    #[error("Invalid pool size: {0}")]
    InvalidPoolSize(String),
}

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    /// DuckDB backend
    DuckDb,
    /// SQLite backend
    Sqlite,
    /// PostgreSQL backend
    Postgres,
}

/// Storage configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend type
    pub backend: BackendType,

    /// Connection string (file path or connection URL)
    pub connection_string: String,

    /// Connection pool size (PostgreSQL only)
    pub pool_size: Option<usize>,
}

impl StorageConfig {
    /// Parse connection URL into storage configuration
    ///
    /// Supported URL formats:
    /// - `duckdb://:memory:` - In-memory DuckDB
    /// - `duckdb:///path/to/db.duckdb` - File-based DuckDB
    /// - `sqlite://:memory:` - In-memory SQLite
    /// - `sqlite:///path/to/db.sqlite` - File-based SQLite
    /// - `postgres://user:pass@host:port/db` - PostgreSQL
    /// - `postgres://user:pass@host:port/db?pool_size=10` - PostgreSQL with pool size
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::InvalidUrl` if the URL cannot be parsed.
    /// Returns `ConfigError::UnsupportedScheme` if the URL scheme is not supported.
    /// Returns `ConfigError::InvalidPoolSize` if the pool_size parameter is invalid.
    pub fn from_url(url: &str) -> Result<Self, ConfigError> {
        // Handle special case for :memory: URLs which are not valid URLs
        // Replace ://:memory: with :///memory: for parsing, then fix it back
        let normalized_url = if url.contains("://:memory:") {
            url.replace("://:memory:", ":///memory:")
        } else {
            url.to_string()
        };

        let parsed = url::Url::parse(&normalized_url)?;

        let backend = match parsed.scheme() {
            "duckdb" => BackendType::DuckDb,
            "sqlite" => BackendType::Sqlite,
            "postgres" | "postgresql" => BackendType::Postgres,
            scheme => return Err(ConfigError::UnsupportedScheme(scheme.to_string())),
        };

        let connection_string = match backend {
            BackendType::DuckDb | BackendType::Sqlite => {
                let path = parsed.path();
                if path == "/memory:" || path == "/:memory:" {
                    ":memory:".to_string()
                } else if path.starts_with('/') && !path[1..].is_empty() {
                    // Remove leading slash from path for file-based databases
                    path[1..].to_string()
                } else {
                    path.to_string()
                }
            }
            BackendType::Postgres => {
                // Reconstruct URL without query parameters for connection string
                let mut conn_url = parsed.clone();
                conn_url.set_query(None);
                conn_url.to_string()
            }
        };

        // Parse pool_size from query parameters (PostgreSQL only)
        let pool_size = if backend == BackendType::Postgres {
            parsed
                .query_pairs()
                .find(|(key, _)| key == "pool_size")
                .map(|(_, value)| {
                    value
                        .parse::<usize>()
                        .map_err(|_| ConfigError::InvalidPoolSize(value.to_string()))
                })
                .transpose()?
        } else {
            None
        };

        Ok(Self {
            backend,
            connection_string,
            pool_size,
        })
    }

    /// Create in-memory DuckDB configuration for testing
    #[must_use]
    pub fn duckdb_memory() -> Self {
        Self {
            backend: BackendType::DuckDb,
            connection_string: ":memory:".to_string(),
            pool_size: None,
        }
    }

    /// Create file-based DuckDB configuration
    #[must_use]
    pub fn duckdb_file(path: &str) -> Self {
        Self {
            backend: BackendType::DuckDb,
            connection_string: path.to_string(),
            pool_size: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::duckdb_memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duckdb_memory() {
        let config = StorageConfig::from_url("duckdb://:memory:").unwrap();
        assert_eq!(config.backend, BackendType::DuckDb);
        assert_eq!(config.connection_string, ":memory:");
        assert_eq!(config.pool_size, None);
    }

    #[test]
    fn test_parse_duckdb_file() {
        let config = StorageConfig::from_url("duckdb:///var/lib/router-hosts/db.duckdb").unwrap();
        assert_eq!(config.backend, BackendType::DuckDb);
        assert_eq!(config.connection_string, "var/lib/router-hosts/db.duckdb");
        assert_eq!(config.pool_size, None);
    }

    #[test]
    fn test_parse_sqlite_memory() {
        let config = StorageConfig::from_url("sqlite://:memory:").unwrap();
        assert_eq!(config.backend, BackendType::Sqlite);
        assert_eq!(config.connection_string, ":memory:");
        assert_eq!(config.pool_size, None);
    }

    #[test]
    fn test_parse_sqlite_file() {
        let config = StorageConfig::from_url("sqlite:///path/to/db.sqlite").unwrap();
        assert_eq!(config.backend, BackendType::Sqlite);
        assert_eq!(config.connection_string, "path/to/db.sqlite");
        assert_eq!(config.pool_size, None);
    }

    #[test]
    fn test_parse_postgres() {
        let config = StorageConfig::from_url("postgres://user:pass@localhost:5432/dbname").unwrap();
        assert_eq!(config.backend, BackendType::Postgres);
        assert_eq!(
            config.connection_string,
            "postgres://user:pass@localhost:5432/dbname"
        );
        assert_eq!(config.pool_size, None);
    }

    #[test]
    fn test_parse_postgres_with_pool() {
        let config =
            StorageConfig::from_url("postgres://user:pass@localhost:5432/dbname?pool_size=10")
                .unwrap();
        assert_eq!(config.backend, BackendType::Postgres);
        assert_eq!(
            config.connection_string,
            "postgres://user:pass@localhost:5432/dbname"
        );
        assert_eq!(config.pool_size, Some(10));
    }

    #[test]
    fn test_parse_postgresql_scheme() {
        let config =
            StorageConfig::from_url("postgresql://user:pass@localhost:5432/dbname").unwrap();
        assert_eq!(config.backend, BackendType::Postgres);
        assert_eq!(
            config.connection_string,
            "postgresql://user:pass@localhost:5432/dbname"
        );
    }

    #[test]
    fn test_parse_invalid_scheme() {
        let result = StorageConfig::from_url("mysql://localhost/db");
        assert!(result.is_err());
        match result {
            Err(ConfigError::UnsupportedScheme(scheme)) => {
                assert_eq!(scheme, "mysql");
            }
            _ => panic!("Expected UnsupportedScheme error"),
        }
    }

    #[test]
    fn test_parse_invalid_url() {
        let result = StorageConfig::from_url("not a url");
        assert!(result.is_err());
        assert!(matches!(result, Err(ConfigError::InvalidUrl(_))));
    }

    #[test]
    fn test_parse_invalid_pool_size() {
        let result = StorageConfig::from_url("postgres://localhost/db?pool_size=not_a_number");
        assert!(result.is_err());
        match result {
            Err(ConfigError::InvalidPoolSize(val)) => {
                assert_eq!(val, "not_a_number");
            }
            _ => panic!("Expected InvalidPoolSize error"),
        }
    }

    #[test]
    fn test_duckdb_memory_constructor() {
        let config = StorageConfig::duckdb_memory();
        assert_eq!(config.backend, BackendType::DuckDb);
        assert_eq!(config.connection_string, ":memory:");
        assert_eq!(config.pool_size, None);
    }

    #[test]
    fn test_duckdb_file_constructor() {
        let config = StorageConfig::duckdb_file("/path/to/db.duckdb");
        assert_eq!(config.backend, BackendType::DuckDb);
        assert_eq!(config.connection_string, "/path/to/db.duckdb");
        assert_eq!(config.pool_size, None);
    }

    #[test]
    fn test_default() {
        let config = StorageConfig::default();
        assert_eq!(config.backend, BackendType::DuckDb);
        assert_eq!(config.connection_string, ":memory:");
        assert_eq!(config.pool_size, None);
    }
}
