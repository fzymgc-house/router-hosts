//! Database schema definitions and migrations
//!
//! This module defines the DuckDB table schemas for:
//! - Event log (event sourcing write side)
//! - Host entries projection (CQRS read side)
//! - Snapshots (versioned hosts file storage)

use crate::backends::duckdb::DuckDbStorage;
use crate::error::StorageError;

/// Initialize the DuckDB schema for event-sourced storage
///
/// Creates all tables, indexes, and views required for the CQRS event sourcing pattern:
/// - `host_events` table (append-only event log)
/// - Indexes for fast event replay and temporal queries
/// - `host_entries_current` view (current state projection)
/// - `host_entries_history` view (complete history)
/// - `snapshots` table (versioned hosts file storage)
///
/// # Errors
///
/// Returns `StorageError::Migration` if schema initialization fails.
///
/// # Examples
///
/// ```no_run
/// use router_hosts_storage::backends::duckdb::DuckDbStorage;
/// use router_hosts_storage::Storage;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let storage = DuckDbStorage::new(":memory:").await?;
/// storage.initialize().await?;
/// # Ok(())
/// # }
/// ```
pub async fn initialize_schema(storage: &DuckDbStorage) -> Result<(), StorageError> {
    let conn = storage.conn();

    tokio::task::spawn_blocking(move || {
        let conn = conn.lock();

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
                    event_version VARCHAR NOT NULL,
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
                    expected_version VARCHAR,
                    -- Ensure events are sequential per aggregate
                    UNIQUE(aggregate_id, event_version)
                )
                "#,
            [],
        )
        .map_err(|e| {
            StorageError::migration("failed to create host_events table", e)
        })?;

        // Index for fast event replay by aggregate
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_aggregate ON host_events(aggregate_id, event_version)",
            [],
        )
        .map_err(|e| {
            StorageError::migration("failed to create aggregate index", e)
        })?;

        // Index for temporal queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_time ON host_events(created_at)",
            [],
        )
        .map_err(|e| {
            StorageError::migration("failed to create temporal index", e)
        })?;

        // Read model: Current active hosts projection
        // This materialized view is built from events and optimized for queries
        // Uses window functions to carry forward the most recent non-null value for each field,
        // since update events only set the fields they change (e.g., IpAddressChanged
        // only sets ip_address, not hostname).
        //
        // Uses LAST_VALUE(... IGNORE NULLS) on comment and tags columns
        // to properly merge partial updates.
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
                        -- Use dedicated columns with IGNORE NULLS for proper merging
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
            StorageError::migration("failed to create current hosts view", e)
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
            StorageError::migration("failed to create history view", e)
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
            StorageError::migration("failed to create snapshots table", e)
        })?;

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
        let storage = DuckDbStorage::new(":memory:")
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

    #[tokio::test]
    async fn test_event_table_columns() -> Result<(), StorageError> {
        let storage = DuckDbStorage::new(":memory:")
            .await
            .expect("failed to create in-memory storage");

        initialize_schema(&storage).await?;

        let conn = storage.conn();
        let cols: Vec<String> = tokio::task::spawn_blocking(move || {
            let conn = conn.lock();

            let mut stmt = conn
                .prepare("SELECT column_name FROM information_schema.columns WHERE table_name = 'host_events' ORDER BY column_name")
                .map_err(|e| StorageError::migration("failed to query columns", e))?;

            let columns: Result<Vec<String>, duckdb::Error> = stmt
                .query_map([], |row| row.get(0))
                .map_err(|e| StorageError::migration("failed to query columns", e))?
                .collect();

            columns.map_err(|e| StorageError::migration("failed to collect columns", e))
        })
        .await
        .map_err(|e| StorageError::migration("spawn_blocking panicked during column verification", e))??;

        // Core event columns
        assert!(cols.contains(&"event_id".to_string()));
        assert!(cols.contains(&"aggregate_id".to_string()));
        assert!(cols.contains(&"event_type".to_string()));
        assert!(cols.contains(&"event_version".to_string()));

        // First-class typed columns for current state
        assert!(cols.contains(&"ip_address".to_string()));
        assert!(cols.contains(&"hostname".to_string()));
        assert!(cols.contains(&"event_timestamp".to_string()));

        // First-class columns for comment and tags
        assert!(cols.contains(&"comment".to_string()));
        assert!(cols.contains(&"tags".to_string()));

        // JSON metadata column (previous values and extension data)
        assert!(cols.contains(&"metadata".to_string()));

        Ok(())
    }
}
