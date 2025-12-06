use duckdb::Connection;
use parking_lot::ReentrantMutex;
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
/// The connection is wrapped in a ReentrantMutex to allow safe concurrent access
/// from multiple async tasks in the gRPC server. ReentrantMutex is used instead
/// of std::sync::Mutex to support reentrant locking patterns where methods like
/// list_all() call get_by_id(), both of which need to acquire the connection lock.
pub struct Database {
    conn: ReentrantMutex<Connection>,
}

impl Database {
    /// Create a new database connection from a file path
    pub fn new(path: &Path) -> DatabaseResult<Self> {
        let conn = Connection::open(path).map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to open database at {:?}: {}", path, e))
        })?;

        let mut db = Self {
            conn: ReentrantMutex::new(conn),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> DatabaseResult<Self> {
        let conn = Connection::open_in_memory().map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to open in-memory database: {}", e))
        })?;

        let mut db = Self {
            conn: ReentrantMutex::new(conn),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    /// Initialize CQRS event-sourced schema
    fn initialize_schema(&mut self) -> DatabaseResult<()> {
        let conn = self.conn.lock();

        // Use VARCHAR for IP addresses instead of INET type to avoid extension dependency
        // Validation happens at the application layer via router_hosts_common::validation
        //
        // Note: Metadata is stored as VARCHAR (JSON string) to avoid DuckDB JSON extension
        // dependency. JSON parsing happens in Rust code (see projections.rs).

        // Event store - append-only immutable log of all domain events
        // This is the source of truth for all state changes
        //
        // Design: First-class typed columns for current state (ip_address, hostname, comment, tags)
        // These columns enable LAST_VALUE(... IGNORE NULLS) in views for proper state merging.
        // Metadata stored as VARCHAR (JSON string) for previous values and extension data.
        conn.execute(
            r#"
                CREATE TABLE IF NOT EXISTS host_events (
                    event_id VARCHAR PRIMARY KEY,
                    aggregate_id VARCHAR NOT NULL,
                    event_type VARCHAR NOT NULL,
                    event_version INTEGER NOT NULL,
                    -- Current state in typed columns for queryability
                    ip_address VARCHAR,
                    hostname VARCHAR,
                    -- Comment field (nullable - NULL means "no change" for proper LAST_VALUE IGNORE NULLS)
                    comment VARCHAR,
                    -- Tags as JSON array string (nullable - NULL means "no change")
                    tags VARCHAR,
                    event_timestamp TIMESTAMP NOT NULL,
                    -- Event metadata: previous values and extension data (stored as JSON string)
                    metadata VARCHAR NOT NULL,
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
            DatabaseError::SchemaInitFailed(format!("Failed to create host_events table: {}", e))
        })?;

        // Index for fast event replay by aggregate
        conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_aggregate ON host_events(aggregate_id, event_version)",
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create aggregate index: {}", e))
            })?;

        // Index for temporal queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_time ON host_events(created_at)",
            [],
        )
        .map_err(|e| {
            DatabaseError::SchemaInitFailed(format!("Failed to create temporal index: {}", e))
        })?;

        // Read model: Current active hosts projection
        // This materialized view is built from events and optimized for queries
        // Uses window functions to carry forward the most recent non-null value for each field,
        // since update events only set the fields they change (e.g., IpAddressChanged
        // only sets ip_address, not hostname).
        //
        // FIX for #35: Use LAST_VALUE(... IGNORE NULLS) on comment and tags columns
        // to properly merge partial updates. Previously used LAST_VALUE(metadata) which
        // only returned the last event's metadata, losing other fields.
        conn.execute(
                r#"
                CREATE VIEW IF NOT EXISTS host_entries_current AS
                WITH windowed AS (
                    -- Build current state using window functions
                    SELECT
                        aggregate_id,
                        event_version,
                        event_type,
                        LAST_VALUE(ip_address IGNORE NULLS) OVER (
                            PARTITION BY aggregate_id
                            ORDER BY event_version
                            ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                        ) as ip_address,
                        LAST_VALUE(hostname IGNORE NULLS) OVER (
                            PARTITION BY aggregate_id
                            ORDER BY event_version
                            ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                        ) as hostname,
                        -- FIX #35: Use dedicated columns with IGNORE NULLS for proper merging
                        LAST_VALUE(comment IGNORE NULLS) OVER (
                            PARTITION BY aggregate_id
                            ORDER BY event_version
                            ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                        ) as comment,
                        LAST_VALUE(tags IGNORE NULLS) OVER (
                            PARTITION BY aggregate_id
                            ORDER BY event_version
                            ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                        ) as tags,
                        FIRST_VALUE(event_timestamp) OVER (
                            PARTITION BY aggregate_id
                            ORDER BY event_version
                            ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                        ) as created_at,
                        LAST_VALUE(created_at) OVER (
                            PARTITION BY aggregate_id
                            ORDER BY event_version
                            ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                        ) as updated_at,
                        LAST_VALUE(event_type) OVER (
                            PARTITION BY aggregate_id
                            ORDER BY event_version
                            ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                        ) as latest_event_type,
                        ROW_NUMBER() OVER (PARTITION BY aggregate_id ORDER BY event_version DESC) as rn
                    FROM host_events
                )
                SELECT
                    aggregate_id as id,
                    CAST(ip_address AS VARCHAR) as ip_address,
                    hostname,
                    comment,
                    tags,
                    CAST(EXTRACT(EPOCH FROM created_at) * 1000000 AS BIGINT) as created_at,
                    CAST(EXTRACT(EPOCH FROM updated_at) * 1000000 AS BIGINT) as updated_at,
                    event_version
                FROM windowed
                WHERE rn = 1
                  AND latest_event_type != 'HostDeleted'
                "#,
                [],
            )
            .map_err(|e| {
                DatabaseError::SchemaInitFailed(format!("Failed to create current hosts view: {}", e))
            })?;

        // Read model: Complete history including deleted entries
        conn.execute(
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
        conn.execute(
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
    ///
    /// This locks the mutex and returns a guard. The lock is released when
    /// the guard is dropped. Uses ReentrantMutex to support reentrant locking
    /// from the same thread.
    pub(crate) fn conn(&self) -> parking_lot::ReentrantMutexGuard<'_, Connection> {
        self.conn.lock()
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

        // First-class columns for comment and tags (fix for #35)
        assert!(cols.contains(&"comment".to_string()));
        assert!(cols.contains(&"tags".to_string()));

        // JSON metadata column (previous values and extension data)
        assert!(cols.contains(&"metadata".to_string()));
    }
}
