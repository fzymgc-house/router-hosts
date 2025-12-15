//! SnapshotStore implementation for PostgreSQL
//!
//! Provides versioned /etc/hosts snapshots with retention policies.

use chrono::Utc;
use sqlx::Row;

use super::PostgresStorage;
use crate::error::StorageError;
use crate::types::{Snapshot, SnapshotId, SnapshotMetadata};

impl PostgresStorage {
    /// Save a snapshot
    pub(crate) async fn save_snapshot_impl(&self, snapshot: Snapshot) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO snapshots (
                snapshot_id, created_at, hosts_content,
                entry_count, trigger, name, event_log_position
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (snapshot_id) DO UPDATE SET
                hosts_content = EXCLUDED.hosts_content,
                entry_count = EXCLUDED.entry_count,
                trigger = EXCLUDED.trigger,
                name = EXCLUDED.name,
                event_log_position = EXCLUDED.event_log_position
            "#,
        )
        .bind(snapshot.snapshot_id.as_str())
        .bind(snapshot.created_at)
        .bind(&snapshot.hosts_content)
        .bind(snapshot.entry_count)
        .bind(&snapshot.trigger)
        .bind(&snapshot.name)
        .bind(snapshot.event_log_position)
        .execute(self.pool())
        .await
        .map_err(|e| StorageError::query("save_snapshot failed", e))?;

        Ok(())
    }

    /// Get a snapshot by ID
    pub(crate) async fn get_snapshot_impl(
        &self,
        snapshot_id: &SnapshotId,
    ) -> Result<Snapshot, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT snapshot_id, created_at, hosts_content,
                   entry_count, trigger, name, event_log_position
            FROM snapshots
            WHERE snapshot_id = $1
            "#,
        )
        .bind(snapshot_id.as_str())
        .fetch_optional(self.pool())
        .await
        .map_err(|e| StorageError::query("get_snapshot failed", e))?
        .ok_or_else(|| StorageError::NotFound {
            entity_type: "Snapshot",
            id: snapshot_id.to_string(),
        })?;

        Ok(Snapshot {
            snapshot_id: SnapshotId::new(row.get::<String, _>("snapshot_id")),
            created_at: row.get("created_at"),
            hosts_content: row.get("hosts_content"),
            entry_count: row.get("entry_count"),
            trigger: row.get("trigger"),
            name: row.get("name"),
            event_log_position: row.get("event_log_position"),
        })
    }

    /// List snapshots with pagination
    pub(crate) async fn list_snapshots_impl(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<SnapshotMetadata>, StorageError> {
        let limit = limit.unwrap_or(100) as i64;
        let offset = offset.unwrap_or(0) as i64;

        let rows = sqlx::query(
            r#"
            SELECT snapshot_id, created_at, entry_count, trigger, name
            FROM snapshots
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool())
        .await
        .map_err(|e| StorageError::query("list_snapshots failed", e))?;

        let snapshots = rows
            .into_iter()
            .map(|row| SnapshotMetadata {
                snapshot_id: SnapshotId::new(row.get::<String, _>("snapshot_id")),
                created_at: row.get("created_at"),
                entry_count: row.get("entry_count"),
                trigger: row.get("trigger"),
                name: row.get("name"),
            })
            .collect();

        Ok(snapshots)
    }

    /// Delete a snapshot by ID
    pub(crate) async fn delete_snapshot_impl(
        &self,
        snapshot_id: &SnapshotId,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("DELETE FROM snapshots WHERE snapshot_id = $1")
            .bind(snapshot_id.as_str())
            .execute(self.pool())
            .await
            .map_err(|e| StorageError::query("delete_snapshot failed", e))?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound {
                entity_type: "Snapshot",
                id: snapshot_id.to_string(),
            });
        }

        Ok(())
    }

    /// Apply retention policy
    pub(crate) async fn apply_retention_policy_impl(
        &self,
        max_count: Option<usize>,
        max_age_days: Option<u32>,
    ) -> Result<usize, StorageError> {
        let mut deleted = 0usize;

        // Delete by age first
        if let Some(max_age) = max_age_days {
            let cutoff = Utc::now() - chrono::Duration::days(max_age as i64);

            let result = sqlx::query("DELETE FROM snapshots WHERE created_at < $1")
                .bind(cutoff)
                .execute(self.pool())
                .await
                .map_err(|e| StorageError::query("retention by age failed", e))?;

            deleted += result.rows_affected() as usize;
        }

        // Delete by count
        if let Some(max_count) = max_count {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM snapshots")
                .fetch_one(self.pool())
                .await
                .map_err(|e| StorageError::query("count snapshots failed", e))?;

            if count as usize > max_count {
                let to_delete = count as usize - max_count;

                let result = sqlx::query(
                    r#"
                    DELETE FROM snapshots
                    WHERE snapshot_id IN (
                        SELECT snapshot_id FROM snapshots
                        ORDER BY created_at ASC
                        LIMIT $1
                    )
                    "#,
                )
                .bind(to_delete as i64)
                .execute(self.pool())
                .await
                .map_err(|e| StorageError::query("retention by count failed", e))?;

                deleted += result.rows_affected() as usize;
            }
        }

        Ok(deleted)
    }
}
