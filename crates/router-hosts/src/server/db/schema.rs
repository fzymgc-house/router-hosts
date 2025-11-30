use duckdb::Connection;
use std::path::Path;
use thiserror::Error;

#[cfg(test)]
use duckdb::Result as DuckDbResult;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Database connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Schema initialization failed: {0}")]
    SchemaInitFailed(String),

    #[error("Query execution failed: {0}")]
    QueryFailed(String),

    #[error("Host entry not found: {0}")]
    HostNotFound(String),

    #[error("Snapshot not found: {0}")]
    SnapshotNotFound(String),

    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Concurrent modification detected: {0}")]
    ConcurrentModification(String),
}

pub type DatabaseResult<T> = Result<T, DatabaseError>;

/// Database connection and management
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Create a new database connection from a file path
    pub fn new(path: &Path) -> DatabaseResult<Self> {
        let conn = Connection::open(path).map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to open database at {:?}: {}", path, e))
        })?;

        let mut db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> DatabaseResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to open in-memory database: {}", e))
        })?;

        let mut db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Initialize database schema
    fn initialize_schema(&mut self) -> DatabaseResult<()> {
        // Create host_entries table
        //
        // UNIQUE CONSTRAINT EXPLANATION:
        // The UNIQUE(ip_address, hostname) constraint prevents duplicate (ip, hostname) pairs
        // across BOTH active and inactive entries. This is intentional and works with the
        // soft-delete pattern as follows:
        //
        // 1. When adding an entry, if an inactive entry with the same (ip, hostname) exists,
        //    the HostsRepository::add() method reactivates it instead of inserting a new row.
        // 2. This ensures exactly ONE record per (ip, hostname) pair in the database at all times.
        // 3. The active flag determines visibility, not uniqueness.
        // 4. This design prevents accumulation of duplicate historical records.
        //
        // Alternative approach (not used): UNIQUE(ip_address, hostname, active) would allow
        // multiple inactive duplicates, which is not desirable for data integrity.
        self.conn
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS host_entries (
                    id VARCHAR PRIMARY KEY,
                    ip_address VARCHAR NOT NULL,
                    hostname VARCHAR NOT NULL,
                    comment VARCHAR,
                    tags VARCHAR,
                    created_at VARCHAR NOT NULL,
                    updated_at VARCHAR NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT true,
                    version_tag VARCHAR NOT NULL,
                    UNIQUE(ip_address, hostname)
                )
                "#,
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!(
                    "Failed to create host_entries table: {}",
                    e
                ))
            })?;

        // Create snapshots table
        self.conn
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS snapshots (
                    snapshot_id VARCHAR PRIMARY KEY,
                    created_at VARCHAR NOT NULL,
                    hosts_content TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    trigger VARCHAR NOT NULL,
                    name VARCHAR
                )
                "#,
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create snapshots table: {}", e))
            })?;

        // Create index on active host entries for fast querying
        // Note: DuckDB doesn't support partial indexes, so we index the entire column
        self.conn
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_active_hosts ON host_entries(active)",
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create index: {}", e))
            })?;

        Ok(())
    }

    /// Get a reference to the underlying connection
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_in_memory_creation() {
        let db = Database::in_memory();
        assert!(db.is_ok(), "Should create in-memory database");
    }

    #[test]
    fn test_database_file_creation() {
        // Create a temp directory and use a non-existent file path within it
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let db = Database::new(&db_path);
        assert!(
            db.is_ok(),
            "Should create file-based database: {:?}",
            db.err()
        );
    }

    #[test]
    fn test_schema_initialization() {
        let db = Database::in_memory().unwrap();

        // Verify host_entries table exists
        let result: DuckDbResult<i32> = db.conn.query_row(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'host_entries'",
            [],
            |row| row.get(0),
        );
        assert_eq!(result.unwrap(), 1, "host_entries table should exist");

        // Verify snapshots table exists
        let result: DuckDbResult<i32> = db.conn.query_row(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'snapshots'",
            [],
            |row| row.get(0),
        );
        assert_eq!(result.unwrap(), 1, "snapshots table should exist");
    }

    #[test]
    fn test_host_entries_schema() {
        let db = Database::in_memory().unwrap();

        // Verify columns exist
        let column_count: i32 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'host_entries'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(column_count, 9, "host_entries should have 9 columns");
    }
}
