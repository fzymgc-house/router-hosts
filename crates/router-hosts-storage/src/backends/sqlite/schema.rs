//! Database schema definitions and migrations for SQLite
//!
//! This module defines the SQLite table schemas for:
//! - Event log (event sourcing write side)
//! - Host entries projection (CQRS read side)
//! - Snapshots (versioned hosts file storage)
//!
//! # Differences from DuckDB
//!
//! SQLite doesn't support `IGNORE NULLS` in window functions, so we use
//! correlated subqueries to get the last non-null value for each column.
//!
//! # Ordering Strategy: rowid vs event_version
//!
//! We use SQLite's `rowid` for ordering instead of `event_version` (ULID) because:
//!
//! 1. **ULID limitation**: ULIDs contain a 48-bit timestamp plus 80-bit random suffix.
//!    Events created within the same millisecond have arbitrary lexicographic order
//!    determined by the random suffix, not insertion order.
//!
//! 2. **rowid guarantee**: SQLite's `rowid` is a 64-bit integer that's guaranteed to
//!    be unique and monotonically increasing for inserts (without explicit ROWID values).
//!    This makes it reliable for tracking insertion order.
//!
//! 3. **Consistency**: All queries that need insertion order use `ORDER BY rowid`,
//!    including the `host_entries_current` view's subqueries.

use super::SqliteStorage;
use crate::error::StorageError;

/// Initialize the SQLite schema for event-sourced storage
///
/// Creates all tables, indexes, and views required for the CQRS event sourcing pattern.
pub async fn initialize_schema(storage: &SqliteStorage) -> Result<(), StorageError> {
    let conn = storage.conn();

    tokio::task::spawn_blocking(move || {
        let conn = conn.lock();

        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
            .map_err(|e| StorageError::migration("failed to set SQLite pragmas", e))?;

        // Event store - append-only immutable log of all domain events
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS host_events (
                event_id TEXT PRIMARY KEY,
                aggregate_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_version TEXT NOT NULL,
                ip_address TEXT,
                hostname TEXT,
                comment TEXT,
                tags TEXT,
                event_timestamp INTEGER NOT NULL,
                metadata TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                created_by TEXT,
                expected_version TEXT,
                UNIQUE(aggregate_id, event_version)
            )
            "#,
            [],
        )
        .map_err(|e| StorageError::migration("failed to create host_events table", e))?;

        // Index for fast event replay by aggregate
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_aggregate ON host_events(aggregate_id, event_version)",
            [],
        )
        .map_err(|e| StorageError::migration("failed to create aggregate index", e))?;

        // Index for temporal queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_time ON host_events(created_at)",
            [],
        )
        .map_err(|e| StorageError::migration("failed to create temporal index", e))?;

        // Note: The existing idx_events_aggregate index on (aggregate_id, event_version)
        // provides good performance for the view's subqueries. SQLite's rowid cannot be
        // directly indexed, but lookups by aggregate_id use the existing index and then
        // scan by rowid which is the primary key ordering.

        // Read model: Current active hosts projection
        // SQLite doesn't support IGNORE NULLS, so we use correlated subqueries
        // to find the last non-null value for each field.
        // NOTE: We use rowid for ordering instead of event_version because ULIDs
        // created within the same millisecond have arbitrary lexicographic order.
        conn.execute(
            r#"
            CREATE VIEW IF NOT EXISTS host_entries_current AS
            WITH latest_events AS (
                SELECT
                    aggregate_id,
                    MAX(rowid) as max_rowid
                FROM host_events
                GROUP BY aggregate_id
            ),
            latest_event_details AS (
                SELECT
                    e.aggregate_id,
                    e.event_type as latest_event_type,
                    e.event_version as max_version
                FROM host_events e
                INNER JOIN latest_events le ON e.aggregate_id = le.aggregate_id AND e.rowid = le.max_rowid
            )
            SELECT
                e.aggregate_id as id,
                -- Get last non-null ip_address
                (SELECT ip_address FROM host_events h
                 WHERE h.aggregate_id = e.aggregate_id AND h.ip_address IS NOT NULL
                 ORDER BY h.rowid DESC LIMIT 1) as ip_address,
                -- Get last non-null hostname
                (SELECT hostname FROM host_events h
                 WHERE h.aggregate_id = e.aggregate_id AND h.hostname IS NOT NULL
                 ORDER BY h.rowid DESC LIMIT 1) as hostname,
                -- Get last non-null comment
                (SELECT comment FROM host_events h
                 WHERE h.aggregate_id = e.aggregate_id AND h.comment IS NOT NULL
                 ORDER BY h.rowid DESC LIMIT 1) as comment,
                -- Get last non-null tags
                (SELECT tags FROM host_events h
                 WHERE h.aggregate_id = e.aggregate_id AND h.tags IS NOT NULL
                 ORDER BY h.rowid DESC LIMIT 1) as tags,
                -- First event timestamp as created_at
                (SELECT event_timestamp FROM host_events h
                 WHERE h.aggregate_id = e.aggregate_id
                 ORDER BY h.rowid ASC LIMIT 1) as created_at,
                -- Last event created_at as updated_at
                (SELECT created_at FROM host_events h
                 WHERE h.aggregate_id = e.aggregate_id
                 ORDER BY h.rowid DESC LIMIT 1) as updated_at,
                -- Current version
                led.max_version as event_version
            FROM latest_events le
            INNER JOIN host_events e ON e.aggregate_id = le.aggregate_id AND e.rowid = le.max_rowid
            INNER JOIN latest_event_details led ON led.aggregate_id = e.aggregate_id
            WHERE led.latest_event_type != 'HostDeleted'
            GROUP BY e.aggregate_id
            "#,
            [],
        )
        .map_err(|e| StorageError::migration("failed to create current hosts view", e))?;

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
            ORDER BY aggregate_id, rowid
            "#,
            [],
        )
        .map_err(|e| StorageError::migration("failed to create history view", e))?;

        // Snapshots table for /etc/hosts versioning
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL,
                hosts_content TEXT NOT NULL,
                entry_count INTEGER NOT NULL,
                trigger TEXT NOT NULL,
                name TEXT,
                event_log_position INTEGER
            )
            "#,
            [],
        )
        .map_err(|e| StorageError::migration("failed to create snapshots table", e))?;

        // Index for snapshot queries by time
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_snapshots_created ON snapshots(created_at DESC)",
            [],
        )
        .map_err(|e| StorageError::migration("failed to create snapshot index", e))?;

        Ok(())
    })
    .await
    .map_err(|e| StorageError::migration("spawn_blocking panicked during schema initialization", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_schema_initialization() -> Result<(), StorageError> {
        let storage = SqliteStorage::new(":memory:")
            .await
            .expect("failed to create in-memory storage");

        initialize_schema(&storage).await?;

        // Verify tables exist by querying them
        let conn = storage.conn();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();

            // Verify event store exists
            conn.query_row("SELECT COUNT(*) FROM host_events", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|e| StorageError::migration("host_events table not found", e))?;

            // Verify current hosts view exists
            conn.query_row("SELECT COUNT(*) FROM host_entries_current", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|e| StorageError::migration("host_entries_current view not found", e))?;

            // Verify history view exists
            conn.query_row("SELECT COUNT(*) FROM host_entries_history", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|e| StorageError::migration("host_entries_history view not found", e))?;

            // Verify snapshots table exists
            conn.query_row("SELECT COUNT(*) FROM snapshots", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|e| StorageError::migration("snapshots table not found", e))?;

            Ok(())
        })
        .await
        .map_err(|e| StorageError::migration("spawn_blocking panicked during verification", e))?
    }
}
