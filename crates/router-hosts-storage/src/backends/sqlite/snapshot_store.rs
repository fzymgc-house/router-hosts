//! Snapshot store implementation for SQLite
//!
//! This module implements versioned storage of /etc/hosts snapshots:
//! - Save snapshots with metadata
//! - Retrieve snapshots by ID
//! - List snapshots (metadata only)
//! - Delete snapshots
//! - Apply retention policies (max count and max age)

use chrono::{DateTime, Utc};
use sqlx::FromRow;

use super::SqliteStorage;
use crate::error::StorageError;
use crate::types::{Snapshot, SnapshotId, SnapshotMetadata};

/// Row type for full snapshot queries.
///
/// Uses `#[derive(FromRow)]` for automatic mapping from database columns.
#[derive(Debug, FromRow)]
struct SnapshotRow {
    snapshot_id: String,
    created_at: i64,
    hosts_content: String,
    entry_count: i32,
    trigger: String,
    name: Option<String>,
    event_log_position: Option<i64>,
}

/// Row type for snapshot metadata queries (excludes hosts_content for efficiency).
#[derive(Debug, FromRow)]
struct SnapshotMetadataRow {
    snapshot_id: String,
    created_at: i64,
    entry_count: i32,
    trigger: String,
    name: Option<String>,
}

impl SqliteStorage {
    /// Save a snapshot to the store
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn save_snapshot_impl(&self, snapshot: Snapshot) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO snapshots (
                snapshot_id,
                created_at,
                hosts_content,
                entry_count,
                trigger,
                name,
                event_log_position
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(snapshot.snapshot_id.as_str())
        .bind(snapshot.created_at.timestamp_micros())
        .bind(&snapshot.hosts_content)
        .bind(snapshot.entry_count)
        .bind(&snapshot.trigger)
        .bind(&snapshot.name)
        .bind(snapshot.event_log_position)
        .execute(self.pool())
        .await
        .map_err(|e| StorageError::query("failed to insert snapshot", e))?;

        Ok(())
    }

    /// Get a snapshot by ID
    ///
    /// # Errors
    ///
    /// Returns `StorageError::NotFound` if the snapshot doesn't exist.
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn get_snapshot_impl(
        &self,
        snapshot_id: &SnapshotId,
    ) -> Result<Snapshot, StorageError> {
        let snapshot_id_str = snapshot_id.as_str().to_string();

        let row: Option<SnapshotRow> = sqlx::query_as(
            r#"
                SELECT
                    snapshot_id,
                    created_at,
                    hosts_content,
                    entry_count,
                    trigger,
                    name,
                    event_log_position
                FROM snapshots
                WHERE snapshot_id = ?1
                "#,
        )
        .bind(&snapshot_id_str)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| StorageError::query("failed to get snapshot", e))?;

        match row {
            None => Err(StorageError::NotFound {
                entity_type: "snapshot",
                id: snapshot_id_str,
            }),
            Some(row) => {
                let created_at =
                    DateTime::from_timestamp_micros(row.created_at).ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid created_at timestamp: {}",
                            row.created_at
                        ))
                    })?;

                Ok(Snapshot {
                    snapshot_id: SnapshotId::from(row.snapshot_id),
                    created_at,
                    hosts_content: row.hosts_content,
                    entry_count: row.entry_count,
                    trigger: row.trigger,
                    name: row.name,
                    event_log_position: row.event_log_position,
                })
            }
        }
    }

    /// List snapshots with optional pagination (metadata only, no content)
    ///
    /// Results are ordered by created_at DESC (newest first).
    ///
    /// # Arguments
    ///
    /// * `limit` - Maximum number of snapshots to return (None = unlimited)
    /// * `offset` - Number of snapshots to skip (None = 0)
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn list_snapshots_impl(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<SnapshotMetadata>, StorageError> {
        // Convert Option<u32> to i64 for SQLite binding
        // Use i64::MAX for "unlimited" since SQLite doesn't support NULL for LIMIT
        let limit_param: i64 = limit.map_or(i64::MAX, i64::from);
        let offset_param: i64 = offset.map_or(0, i64::from);

        let rows: Vec<SnapshotMetadataRow> = sqlx::query_as(
            r#"
            SELECT
                snapshot_id,
                created_at,
                entry_count,
                trigger,
                name
            FROM snapshots
            ORDER BY created_at DESC
            LIMIT ?1
            OFFSET ?2
            "#,
        )
        .bind(limit_param)
        .bind(offset_param)
        .fetch_all(self.pool())
        .await
        .map_err(|e| StorageError::query("failed to query snapshots", e))?;

        rows.into_iter()
            .map(|row| {
                let created_at =
                    DateTime::from_timestamp_micros(row.created_at).ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid created_at timestamp: {}",
                            row.created_at
                        ))
                    })?;

                Ok(SnapshotMetadata {
                    snapshot_id: SnapshotId::from(row.snapshot_id),
                    created_at,
                    entry_count: row.entry_count,
                    trigger: row.trigger,
                    name: row.name,
                })
            })
            .collect()
    }

    /// Delete a snapshot by ID
    ///
    /// # Errors
    ///
    /// Returns `StorageError::NotFound` if the snapshot doesn't exist.
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn delete_snapshot_impl(
        &self,
        snapshot_id: &SnapshotId,
    ) -> Result<(), StorageError> {
        let snapshot_id_str = snapshot_id.as_str().to_string();

        let result = sqlx::query("DELETE FROM snapshots WHERE snapshot_id = ?1")
            .bind(&snapshot_id_str)
            .execute(self.pool())
            .await
            .map_err(|e| StorageError::query("failed to delete snapshot", e))?;

        if result.rows_affected() == 0 {
            Err(StorageError::NotFound {
                entity_type: "snapshot",
                id: snapshot_id_str,
            })
        } else {
            Ok(())
        }
    }

    /// Apply retention policy to snapshots
    ///
    /// Deletes old snapshots based on:
    /// - `max_count`: Keep at most N most recent snapshots
    /// - `max_age_days`: Delete snapshots older than N days
    ///
    /// Both policies are applied independently (logical AND).
    /// Returns the count of deleted snapshots.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn apply_retention_policy_impl(
        &self,
        max_count: Option<usize>,
        max_age_days: Option<u32>,
    ) -> Result<usize, StorageError> {
        let mut total_deleted: usize = 0;

        // Apply max count policy (delete oldest snapshots beyond limit)
        if let Some(max_count) = max_count {
            if max_count > 0 {
                // SQLite subquery to find snapshots beyond the retention limit
                let result = sqlx::query(
                    r#"
                    DELETE FROM snapshots
                    WHERE snapshot_id NOT IN (
                        SELECT snapshot_id
                        FROM snapshots
                        ORDER BY created_at DESC
                        LIMIT ?1
                    )
                    "#,
                )
                .bind(max_count as i64)
                .execute(self.pool())
                .await
                .map_err(|e| {
                    StorageError::query("failed to apply max_count retention policy", e)
                })?;

                total_deleted += result.rows_affected() as usize;
            }
        }

        // Apply max age policy (delete snapshots older than N days)
        if let Some(max_age_days) = max_age_days {
            if max_age_days > 0 {
                let cutoff_time = Utc::now() - chrono::Duration::days(i64::from(max_age_days));
                let cutoff_micros = cutoff_time.timestamp_micros();

                let result = sqlx::query(
                    r#"
                    DELETE FROM snapshots
                    WHERE created_at < ?1
                    "#,
                )
                .bind(cutoff_micros)
                .execute(self.pool())
                .await
                .map_err(|e| StorageError::query("failed to apply max_age retention policy", e))?;

                total_deleted += result.rows_affected() as usize;
            }
        }

        Ok(total_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Storage;

    async fn create_test_storage() -> SqliteStorage {
        let storage = SqliteStorage::new(":memory:")
            .await
            .expect("failed to create in-memory storage");
        storage.initialize().await.expect("failed to initialize");
        storage
    }

    #[tokio::test]
    async fn test_save_and_get_snapshot() {
        let storage = create_test_storage().await;

        let snapshot = Snapshot {
            snapshot_id: SnapshotId::from("snap-001"),
            created_at: Utc::now(),
            hosts_content: "127.0.0.1 localhost".to_string(),
            entry_count: 1,
            trigger: "manual".to_string(),
            name: Some("Test snapshot".to_string()),
            event_log_position: Some(42),
        };

        storage
            .save_snapshot_impl(snapshot.clone())
            .await
            .expect("failed to save snapshot");

        let retrieved = storage
            .get_snapshot_impl(&SnapshotId::from("snap-001"))
            .await
            .expect("failed to get snapshot");

        assert_eq!(retrieved.snapshot_id, snapshot.snapshot_id);
        assert_eq!(retrieved.hosts_content, snapshot.hosts_content);
        assert_eq!(retrieved.entry_count, snapshot.entry_count);
        assert_eq!(retrieved.trigger, snapshot.trigger);
        assert_eq!(retrieved.name, snapshot.name);
        assert_eq!(retrieved.event_log_position, snapshot.event_log_position);
    }

    #[tokio::test]
    async fn test_get_snapshot_not_found() {
        let storage = create_test_storage().await;

        let result = storage
            .get_snapshot_impl(&SnapshotId::from("nonexistent"))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StorageError::NotFound { .. }));
    }

    #[tokio::test]
    async fn test_list_snapshots() {
        let storage = create_test_storage().await;

        // Initially empty
        let snapshots = storage
            .list_snapshots_impl(None, None)
            .await
            .expect("failed to list snapshots");
        assert_eq!(snapshots.len(), 0);

        // Add multiple snapshots
        for i in 1..=3 {
            let snapshot = Snapshot {
                snapshot_id: SnapshotId::from(format!("snap-{:03}", i)),
                created_at: Utc::now(),
                hosts_content: format!("127.0.0.{} localhost", i),
                entry_count: i,
                trigger: "auto".to_string(),
                name: None,
                event_log_position: None,
            };

            storage
                .save_snapshot_impl(snapshot)
                .await
                .expect("failed to save snapshot");

            // Small delay to ensure different timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // List all snapshots
        let snapshots = storage
            .list_snapshots_impl(None, None)
            .await
            .expect("failed to list snapshots");
        assert_eq!(snapshots.len(), 3);

        // Verify ordering (newest first)
        assert_eq!(snapshots[0].snapshot_id.as_str(), "snap-003");
        assert_eq!(snapshots[1].snapshot_id.as_str(), "snap-002");
        assert_eq!(snapshots[2].snapshot_id.as_str(), "snap-001");

        // Verify metadata only (no content)
        assert_eq!(snapshots[0].entry_count, 3);
        assert_eq!(snapshots[0].trigger, "auto");
    }

    #[tokio::test]
    async fn test_list_snapshots_with_pagination() {
        let storage = create_test_storage().await;

        // Add 5 snapshots
        for i in 1..=5 {
            let snapshot = Snapshot {
                snapshot_id: SnapshotId::from(format!("snap-{:03}", i)),
                created_at: Utc::now(),
                hosts_content: format!("127.0.0.{} localhost", i),
                entry_count: i,
                trigger: "auto".to_string(),
                name: None,
                event_log_position: None,
            };

            storage
                .save_snapshot_impl(snapshot)
                .await
                .expect("failed to save snapshot");

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // Test limit only
        let snapshots = storage
            .list_snapshots_impl(Some(2), None)
            .await
            .expect("failed to list snapshots");
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].snapshot_id.as_str(), "snap-005");
        assert_eq!(snapshots[1].snapshot_id.as_str(), "snap-004");

        // Test offset only
        let snapshots = storage
            .list_snapshots_impl(None, Some(2))
            .await
            .expect("failed to list snapshots");
        assert_eq!(snapshots.len(), 3);
        assert_eq!(snapshots[0].snapshot_id.as_str(), "snap-003");

        // Test both limit and offset
        let snapshots = storage
            .list_snapshots_impl(Some(2), Some(1))
            .await
            .expect("failed to list snapshots");
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].snapshot_id.as_str(), "snap-004");
        assert_eq!(snapshots[1].snapshot_id.as_str(), "snap-003");

        // Test offset beyond available items
        let snapshots = storage
            .list_snapshots_impl(None, Some(10))
            .await
            .expect("failed to list snapshots");
        assert!(snapshots.is_empty());
    }

    #[tokio::test]
    async fn test_delete_snapshot() {
        let storage = create_test_storage().await;

        let snapshot = Snapshot {
            snapshot_id: SnapshotId::from("snap-delete"),
            created_at: Utc::now(),
            hosts_content: "test".to_string(),
            entry_count: 1,
            trigger: "manual".to_string(),
            name: None,
            event_log_position: None,
        };

        storage
            .save_snapshot_impl(snapshot)
            .await
            .expect("failed to save snapshot");

        // Verify exists
        let retrieved = storage
            .get_snapshot_impl(&SnapshotId::from("snap-delete"))
            .await;
        assert!(retrieved.is_ok());

        // Delete
        storage
            .delete_snapshot_impl(&SnapshotId::from("snap-delete"))
            .await
            .expect("failed to delete snapshot");

        // Verify deleted
        let result = storage
            .get_snapshot_impl(&SnapshotId::from("snap-delete"))
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StorageError::NotFound { .. }));
    }

    #[tokio::test]
    async fn test_delete_snapshot_not_found() {
        let storage = create_test_storage().await;

        let result = storage
            .delete_snapshot_impl(&SnapshotId::from("nonexistent"))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StorageError::NotFound { .. }));
    }

    #[tokio::test]
    async fn test_retention_policy_max_count() {
        let storage = create_test_storage().await;

        // Create 5 snapshots
        for i in 1..=5 {
            let snapshot = Snapshot {
                snapshot_id: SnapshotId::from(format!("snap-{:03}", i)),
                created_at: Utc::now(),
                hosts_content: format!("test {}", i),
                entry_count: i,
                trigger: "auto".to_string(),
                name: None,
                event_log_position: None,
            };

            storage
                .save_snapshot_impl(snapshot)
                .await
                .expect("failed to save snapshot");

            // Small delay to ensure different timestamps
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // Keep only 3 most recent
        let deleted = storage
            .apply_retention_policy_impl(Some(3), None)
            .await
            .expect("failed to apply retention policy");

        assert_eq!(deleted, 2);

        // Verify only 3 remain
        let snapshots = storage
            .list_snapshots_impl(None, None)
            .await
            .expect("failed to list snapshots");
        assert_eq!(snapshots.len(), 3);

        // Verify the 3 newest remain
        assert_eq!(snapshots[0].snapshot_id.as_str(), "snap-005");
        assert_eq!(snapshots[1].snapshot_id.as_str(), "snap-004");
        assert_eq!(snapshots[2].snapshot_id.as_str(), "snap-003");
    }

    #[tokio::test]
    async fn test_retention_policy_max_age() {
        let storage = create_test_storage().await;

        // Create a snapshot that's "old"
        // Note: In a real test, we'd insert with a specific timestamp,
        // but for this test we'll just verify the logic doesn't error
        let snapshot = Snapshot {
            snapshot_id: SnapshotId::from("snap-old"),
            created_at: Utc::now() - chrono::Duration::days(10),
            hosts_content: "old".to_string(),
            entry_count: 1,
            trigger: "auto".to_string(),
            name: None,
            event_log_position: None,
        };

        storage
            .save_snapshot_impl(snapshot)
            .await
            .expect("failed to save snapshot");

        // Create a recent snapshot
        let snapshot = Snapshot {
            snapshot_id: SnapshotId::from("snap-new"),
            created_at: Utc::now(),
            hosts_content: "new".to_string(),
            entry_count: 1,
            trigger: "auto".to_string(),
            name: None,
            event_log_position: None,
        };

        storage
            .save_snapshot_impl(snapshot)
            .await
            .expect("failed to save snapshot");

        // Delete snapshots older than 5 days
        let deleted = storage
            .apply_retention_policy_impl(None, Some(5))
            .await
            .expect("failed to apply retention policy");

        assert_eq!(deleted, 1);

        // Verify only new snapshot remains
        let snapshots = storage
            .list_snapshots_impl(None, None)
            .await
            .expect("failed to list snapshots");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].snapshot_id.as_str(), "snap-new");
    }

    #[tokio::test]
    async fn test_retention_policy_both_policies() {
        let storage = create_test_storage().await;

        // Create multiple snapshots
        for i in 1..=5 {
            let snapshot = Snapshot {
                snapshot_id: SnapshotId::from(format!("snap-{:03}", i)),
                created_at: Utc::now(),
                hosts_content: format!("test {}", i),
                entry_count: i,
                trigger: "auto".to_string(),
                name: None,
                event_log_position: None,
            };

            storage
                .save_snapshot_impl(snapshot)
                .await
                .expect("failed to save snapshot");

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        // Apply both policies
        let deleted = storage
            .apply_retention_policy_impl(Some(3), Some(365))
            .await
            .expect("failed to apply retention policy");

        // Max count should delete 2 oldest snapshots
        assert_eq!(deleted, 2);

        let snapshots = storage
            .list_snapshots_impl(None, None)
            .await
            .expect("failed to list snapshots");
        assert_eq!(snapshots.len(), 3);
    }
}
