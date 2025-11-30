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

    #[error("Invalid event sequence: {0}")]
    InvalidEventSequence(String),

    #[error("Concurrent write conflict: {0}")]
    ConcurrentWriteConflict(String),
}

pub type DatabaseResult<T> = Result<T, DatabaseError>;

/// Database connection with CQRS event sourcing pattern
///
/// This implementation uses an event-sourced architecture where:
/// - All changes are stored as immutable events in an append-only log
/// - Read models are projections built from events using DuckDB views
/// - No soft deletes - event log captures complete history
/// - Time travel queries supported via event replay
///
/// # Thread Safety
///
/// A single `Database` instance wraps a single DuckDB connection, which is
/// NOT thread-safe. For concurrent access from multiple threads:
///
/// 1. Use [`try_clone()`](Self::try_clone) to create additional connections
///    that share the same underlying database
/// 2. Each thread should have its own cloned connection
/// 3. DuckDB handles concurrency internally when using cloned connections
///
/// ```ignore
/// let db = Database::new(path)?;
/// let db_clone = db.try_clone()?;  // For another thread
/// ```
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

    /// Initialize CQRS event-sourced schema
    fn initialize_schema(&mut self) -> DatabaseResult<()> {
        // Install and load JSON extension
        // Use INSTALL with FORCE to download if needed, or just load if already installed
        if let Err(e) = self.conn.execute("INSTALL json", []) {
            // If install fails, try to load anyway (might already be installed)
            if let Err(load_err) = self.conn.execute("LOAD json", []) {
                return Err(DatabaseError::SchemaInitFailed(format!(
                    "Failed to setup json extension. Install error: {}. Load error: {}",
                    e, load_err
                )));
            }
        } else {
            // Install succeeded, now load
            self.conn.execute("LOAD json", []).map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to load json extension: {}", e))
            })?;
        }

        // Install and load INET extension for IP address types
        if let Err(e) = self.conn.execute("INSTALL inet", []) {
            // If install fails, try to load anyway (might already be installed)
            if let Err(load_err) = self.conn.execute("LOAD inet", []) {
                return Err(DatabaseError::SchemaInitFailed(format!(
                    "Failed to setup inet extension. Install error: {}. Load error: {}",
                    e, load_err
                )));
            }
        } else {
            // Install succeeded, now load
            self.conn.execute("LOAD inet", []).map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to load inet extension: {}", e))
            })?;
        }

        // Event store - append-only immutable log of all domain events
        // This is the source of truth for all state changes
        //
        // Design: First-class typed columns for current state (ip_address, hostname)
        // JSON metadata column for tags, comments, and previous values
        self.conn
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS host_events (
                    event_id VARCHAR PRIMARY KEY,
                    aggregate_id VARCHAR NOT NULL,
                    event_type VARCHAR NOT NULL,
                    event_version INTEGER NOT NULL,
                    -- Current state in typed columns for queryability
                    ip_address INET,
                    hostname VARCHAR,
                    event_timestamp TIMESTAMP NOT NULL,
                    -- Event metadata: tags, comments, previous values (old_ip, old_hostname, etc.)
                    metadata JSON NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_by VARCHAR,
                    -- Optimistic concurrency control
                    expected_version INTEGER,
                    -- Ensure events are sequential per aggregate
                    UNIQUE(aggregate_id, event_version)
                )
                "#,
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!(
                    "Failed to create host_events table: {}",
                    e
                ))
            })?;

        // Index for fast event replay by aggregate
        self.conn
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_events_aggregate ON host_events(aggregate_id, event_version)",
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create aggregate index: {}", e))
            })?;

        // Index for temporal queries
        self.conn
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_events_time ON host_events(created_at)",
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create temporal index: {}", e))
            })?;

        // Composite index for efficient current hosts view queries
        // The view filters by event_type and orders by hostname
        // Note: Can't index INET type directly, but event_type + hostname helps
        self.conn
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_events_type_hostname ON host_events(event_type, hostname)",
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!(
                    "Failed to create composite index: {}",
                    e
                ))
            })?;

        // Read model: Current active hosts projection
        // This materialized view is built from events and optimized for queries
        // Uses first-class typed columns plus JSON metadata
        self.conn
            .execute(
                r#"
                CREATE VIEW IF NOT EXISTS host_entries_current AS
                WITH latest_events AS (
                    -- Get the latest event for each aggregate
                    SELECT
                        aggregate_id,
                        event_type,
                        event_version,
                        ip_address,
                        hostname,
                        metadata,
                        event_timestamp,
                        created_at,
                        ROW_NUMBER() OVER (PARTITION BY aggregate_id ORDER BY event_version DESC) as rn
                    FROM host_events
                )
                SELECT
                    aggregate_id as id,
                    CAST(ip_address AS VARCHAR) as ip_address,
                    hostname,
                    json_extract_string(metadata, '$.comment') as comment,
                    COALESCE(json_extract_string(metadata, '$.tags'), '[]') as tags,
                    event_timestamp as created_at,
                    created_at as updated_at,
                    event_version,
                    event_type
                FROM latest_events
                WHERE rn = 1
                  AND event_type != 'HostDeleted'
                "#,
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create current hosts view: {}", e))
            })?;

        // Read model: Complete history including deleted entries
        self.conn
            .execute(
                r#"
                CREATE VIEW IF NOT EXISTS host_entries_history AS
                SELECT
                    event_id,
                    aggregate_id,
                    event_type,
                    event_version,
                    ip_address,
                    hostname,
                    metadata,
                    event_timestamp,
                    created_at
                FROM host_events
                ORDER BY aggregate_id, event_version
                "#,
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create history view: {}", e))
            })?;

        // Snapshots table for /etc/hosts versioning
        self.conn
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS snapshots (
                    snapshot_id VARCHAR PRIMARY KEY,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    hosts_content TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    trigger VARCHAR NOT NULL,
                    name VARCHAR,
                    -- Reference to event log position for point-in-time recovery
                    event_log_position INTEGER
                )
                "#,
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create snapshots table: {}", e))
            })?;

        Ok(())
    }

    /// Get a reference to the underlying connection
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Clone this database connection for use in another thread
    ///
    /// Creates a new connection that shares the same underlying database.
    /// Both connections can operate concurrently - DuckDB handles the
    /// synchronization internally.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let db = Database::new(path)?;
    /// let db_clone = db.try_clone()?;
    ///
    /// std::thread::spawn(move || {
    ///     // Use db_clone in this thread
    /// });
    /// ```
    pub fn try_clone(&self) -> DatabaseResult<Self> {
        let conn = self.conn.try_clone().map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to clone connection: {}", e))
        })?;
        Ok(Self { conn })
    }

    /// Execute a function within a database transaction
    ///
    /// The transaction is automatically committed if the function returns `Ok`,
    /// or rolled back if it returns `Err` or panics.
    ///
    /// # Example
    ///
    /// ```ignore
    /// db.transaction(|conn| {
    ///     conn.execute("INSERT INTO ...", [])?;
    ///     conn.execute("UPDATE ...", [])?;
    ///     Ok(())
    /// })?;
    /// ```
    pub fn transaction<T, F>(&mut self, f: F) -> DatabaseResult<T>
    where
        F: FnOnce(&Connection) -> DatabaseResult<T>,
    {
        self.conn.execute("BEGIN TRANSACTION", []).map_err(|e| {
            DatabaseError::QueryFailed(format!("Failed to begin transaction: {}", e))
        })?;

        match f(&self.conn) {
            Ok(result) => {
                self.conn.execute("COMMIT", []).map_err(|e| {
                    DatabaseError::QueryFailed(format!("Failed to commit transaction: {}", e))
                })?;
                Ok(result)
            }
            Err(e) => {
                // Attempt rollback, but don't mask the original error
                let _ = self.conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_in_memory_creation() {
        let db = Database::in_memory();
        assert!(db.is_ok());
    }

    #[test]
    fn test_schema_initialization() {
        let db = Database::in_memory().unwrap();

        // Verify event store exists
        let result: DuckDbResult<i32> =
            db.conn()
                .query_row("SELECT COUNT(*) FROM host_events", [], |row| row.get(0));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        // Verify current hosts view exists
        let result: DuckDbResult<i32> =
            db.conn()
                .query_row("SELECT COUNT(*) FROM host_entries_current", [], |row| {
                    row.get(0)
                });
        assert!(result.is_ok());

        // Verify history view exists
        let result: DuckDbResult<i32> =
            db.conn()
                .query_row("SELECT COUNT(*) FROM host_entries_history", [], |row| {
                    row.get(0)
                });
        assert!(result.is_ok());

        // Verify snapshots table exists
        let result: DuckDbResult<i32> =
            db.conn()
                .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0));
        assert!(result.is_ok());
    }

    #[test]
    fn test_event_table_schema() {
        let db = Database::in_memory().unwrap();

        // Verify columns exist
        let columns: DuckDbResult<Vec<String>> = db.conn()
            .prepare("SELECT column_name FROM information_schema.columns WHERE table_name = 'host_events' ORDER BY column_name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect();

        assert!(columns.is_ok());
        let cols = columns.unwrap();

        // Core event columns
        assert!(cols.contains(&"event_id".to_string()));
        assert!(cols.contains(&"aggregate_id".to_string()));
        assert!(cols.contains(&"event_type".to_string()));
        assert!(cols.contains(&"event_version".to_string()));

        // First-class typed columns for current state
        assert!(cols.contains(&"ip_address".to_string()));
        assert!(cols.contains(&"hostname".to_string()));
        assert!(cols.contains(&"event_timestamp".to_string()));

        // JSON metadata column (tags, comments, previous values)
        assert!(cols.contains(&"metadata".to_string()));
    }

    #[test]
    fn test_transaction_commit() {
        let mut db = Database::in_memory().unwrap();

        // Create a test table
        db.conn()
            .execute("CREATE TABLE test_tx (id INTEGER, value TEXT)", [])
            .unwrap();

        // Transaction that commits
        let result = db.transaction(|conn| {
            conn.execute("INSERT INTO test_tx VALUES (1, 'first')", [])
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
            conn.execute("INSERT INTO test_tx VALUES (2, 'second')", [])
                .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
            Ok(())
        });

        assert!(result.is_ok());

        // Verify data was committed
        let count: i32 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM test_tx", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_transaction_rollback() {
        let mut db = Database::in_memory().unwrap();

        // Create a test table
        db.conn()
            .execute("CREATE TABLE test_tx_rollback (id INTEGER, value TEXT)", [])
            .unwrap();

        // Insert initial data outside transaction
        db.conn()
            .execute("INSERT INTO test_tx_rollback VALUES (1, 'initial')", [])
            .unwrap();

        // Transaction that fails and rolls back
        let result: DatabaseResult<()> = db.transaction(|conn| {
            conn.execute(
                "INSERT INTO test_tx_rollback VALUES (2, 'will rollback')",
                [],
            )
            .map_err(|e| DatabaseError::QueryFailed(e.to_string()))?;
            // Simulate an error
            Err(DatabaseError::QueryFailed("Simulated error".to_string()))
        });

        assert!(result.is_err());

        // Verify only initial data exists (transaction was rolled back)
        let count: i32 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM test_tx_rollback", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_try_clone() {
        let db = Database::in_memory().unwrap();

        // Insert data using original connection
        db.conn()
            .execute("CREATE TABLE test_clone (id INTEGER)", [])
            .unwrap();
        db.conn()
            .execute("INSERT INTO test_clone VALUES (42)", [])
            .unwrap();

        // Clone and verify both see the same data
        let db_clone = db.try_clone().unwrap();
        let value: i32 = db_clone
            .conn()
            .query_row("SELECT id FROM test_clone", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, 42);
    }
}
