//! DuckDB variant of router-hosts.
//!
//! This binary provides the same functionality as `router-hosts` but includes
//! the DuckDB storage backend in addition to SQLite and PostgreSQL.
//!
//! Use this variant if you need DuckDB's analytics capabilities or are
//! migrating from an existing DuckDB-based installation.

use anyhow::Result;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    router_hosts::run().await
}

#[cfg(test)]
mod tests {
    use router_hosts_storage::{create_storage, StorageConfig};

    /// Verify that DuckDB storage backend is available in this binary.
    ///
    /// This test ensures the router-hosts-duckdb variant actually includes
    /// DuckDB support, which is the primary differentiator from the standard binary.
    #[tokio::test]
    async fn test_duckdb_backend_available() {
        let config = StorageConfig::from_url("duckdb://:memory:").expect("DuckDB URL should parse");
        let storage = create_storage(&config)
            .await
            .expect("DuckDB storage should be creatable");
        assert!(
            storage.health_check().await.is_ok(),
            "DuckDB storage should pass health check"
        );
    }

    /// Verify that SQLite backend is also available (for migration scenarios).
    #[tokio::test]
    async fn test_sqlite_backend_available() {
        let config = StorageConfig::from_url("sqlite://:memory:").expect("SQLite URL should parse");
        let storage = create_storage(&config)
            .await
            .expect("SQLite storage should be creatable");
        assert!(
            storage.health_check().await.is_ok(),
            "SQLite storage should pass health check"
        );
    }
}
