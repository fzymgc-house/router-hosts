//! Database schema definitions for PostgreSQL
//!
//! Creates tables, indexes, and views for event-sourced storage.
//! Uses CREATE TABLE IF NOT EXISTS for idempotent initialization.

use super::PostgresStorage;
use crate::error::StorageError;

/// Initialize the PostgreSQL schema for event-sourced storage
///
/// Creates all tables, indexes, and views required for CQRS event sourcing.
/// Safe to call multiple times (uses IF NOT EXISTS).
pub async fn initialize_schema(storage: &PostgresStorage) -> Result<(), StorageError> {
    let pool = storage.pool();

    // Event store - append-only immutable log of all domain events
    sqlx::query(
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
            event_timestamp TIMESTAMPTZ NOT NULL,
            metadata TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by TEXT,
            expected_version TEXT,
            UNIQUE(aggregate_id, event_version)
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::migration("failed to create host_events table", e))?;

    // Index for fast event replay by aggregate
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_events_aggregate ON host_events(aggregate_id, event_version)",
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::migration("failed to create aggregate index", e))?;

    // Index for temporal queries
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_time ON host_events(created_at)")
        .execute(pool)
        .await
        .map_err(|e| StorageError::migration("failed to create temporal index", e))?;

    // Drop existing view to recreate (views can't use IF NOT EXISTS with OR REPLACE in all PG versions)
    sqlx::query("DROP VIEW IF EXISTS host_entries_current")
        .execute(pool)
        .await
        .map_err(|e| StorageError::migration("failed to drop existing view", e))?;

    // Current hosts view using window functions with IGNORE NULLS
    sqlx::query(
        r#"
        CREATE VIEW host_entries_current AS
        WITH windowed AS (
            SELECT
                aggregate_id,
                event_version,
                event_type,
                LAST_VALUE(ip_address) IGNORE NULLS OVER w as ip_address,
                LAST_VALUE(hostname) IGNORE NULLS OVER w as hostname,
                LAST_VALUE(comment) IGNORE NULLS OVER w as comment,
                LAST_VALUE(tags) IGNORE NULLS OVER w as tags,
                FIRST_VALUE(event_timestamp) OVER w as created_at,
                LAST_VALUE(created_at) OVER w as updated_at,
                LAST_VALUE(event_type) OVER w as latest_event_type,
                ROW_NUMBER() OVER (PARTITION BY aggregate_id ORDER BY event_version DESC) as rn
            FROM host_events
            WINDOW w AS (PARTITION BY aggregate_id ORDER BY event_version
                         ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)
        )
        SELECT
            aggregate_id as id,
            ip_address,
            hostname,
            comment,
            tags,
            created_at,
            updated_at,
            event_version
        FROM windowed
        WHERE rn = 1 AND latest_event_type != 'HostDeleted'
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::migration("failed to create current hosts view", e))?;

    // Drop existing history view
    sqlx::query("DROP VIEW IF EXISTS host_entries_history")
        .execute(pool)
        .await
        .map_err(|e| StorageError::migration("failed to drop existing history view", e))?;

    // History view
    sqlx::query(
        r#"
        CREATE VIEW host_entries_history AS
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
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::migration("failed to create history view", e))?;

    // Snapshots table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS snapshots (
            snapshot_id TEXT PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            hosts_content TEXT NOT NULL,
            entry_count INTEGER NOT NULL,
            trigger TEXT NOT NULL,
            name TEXT,
            event_log_position BIGINT
        )
        "#,
    )
    .execute(pool)
    .await
    .map_err(|e| StorageError::migration("failed to create snapshots table", e))?;

    // Index for snapshot queries by time
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_snapshots_created ON snapshots(created_at DESC)")
        .execute(pool)
        .await
        .map_err(|e| StorageError::migration("failed to create snapshot index", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests will use testcontainers in the integration test file
}
