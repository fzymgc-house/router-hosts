use super::schema::{Database, DatabaseError, DatabaseResult};
use super::{Snapshot, SnapshotTrigger};
use chrono::Utc;
use uuid::Uuid;

/// Repository for snapshot operations
pub struct SnapshotsRepository;

impl SnapshotsRepository {
    /// Create a new snapshot
    pub fn create(
        db: &Database,
        hosts_content: &str,
        entry_count: i32,
        trigger: SnapshotTrigger,
        name: Option<&str>,
    ) -> DatabaseResult<Snapshot> {
        let snapshot_id = Uuid::new_v4();
        let created_at = Utc::now();

        db.conn().execute(
            r#"
            INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
            [
                &snapshot_id.to_string() as &dyn duckdb::ToSql,
                &created_at.to_rfc3339() as &dyn duckdb::ToSql,
                &hosts_content as &dyn duckdb::ToSql,
                &entry_count as &dyn duckdb::ToSql,
                &trigger.to_string() as &dyn duckdb::ToSql,
                &name.unwrap_or("") as &dyn duckdb::ToSql,
            ],
        )
        .map_err(|e| DatabaseError::QueryFailed(format!("Failed to create snapshot: {}", e)))?;

        Ok(Snapshot {
            snapshot_id,
            created_at,
            hosts_content: hosts_content.to_string(),
            entry_count,
            trigger,
            name: name.map(String::from),
        })
    }

    /// Get a snapshot by ID
    pub fn get(db: &Database, snapshot_id: &Uuid) -> DatabaseResult<Snapshot> {
        let mut stmt = db
            .conn()
            .prepare("SELECT snapshot_id, created_at, hosts_content, entry_count, trigger, name FROM snapshots WHERE snapshot_id = ?")
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to prepare query: {}", e)))?;

        let snapshot = stmt
            .query_row([&snapshot_id.to_string()], |row| {
                let snapshot_id_str: String = row.get(0)?;
                let created_at_str: String = row.get(1)?;
                let hosts_content: String = row.get(2)?;
                let entry_count: i32 = row.get(3)?;
                let trigger_str: String = row.get(4)?;
                let name: String = row.get(5)?;

                Ok((
                    snapshot_id_str,
                    created_at_str,
                    hosts_content,
                    entry_count,
                    trigger_str,
                    name,
                ))
            })
            .map_err(|e| {
                DatabaseError::SnapshotNotFound(format!(
                    "Snapshot {} not found: {}",
                    snapshot_id, e
                ))
            })?;

        let trigger = match snapshot.4.as_str() {
            "manual" => SnapshotTrigger::Manual,
            "auto_before_change" => SnapshotTrigger::AutoBeforeChange,
            "scheduled" => SnapshotTrigger::Scheduled,
            _ => {
                return Err(DatabaseError::InvalidData(format!(
                    "Invalid trigger type: {}",
                    snapshot.4
                )))
            }
        };

        Ok(Snapshot {
            snapshot_id: Uuid::parse_str(&snapshot.0)
                .map_err(|e| DatabaseError::InvalidData(e.to_string()))?,
            created_at: chrono::DateTime::parse_from_rfc3339(&snapshot.1)
                .map_err(|e| DatabaseError::InvalidData(e.to_string()))?
                .with_timezone(&Utc),
            hosts_content: snapshot.2,
            entry_count: snapshot.3,
            trigger,
            name: if snapshot.5.is_empty() {
                None
            } else {
                Some(snapshot.5)
            },
        })
    }

    /// List all snapshots (ordered by creation date, newest first)
    pub fn list(db: &Database) -> DatabaseResult<Vec<Snapshot>> {
        let mut stmt = db
            .conn()
            .prepare("SELECT snapshot_id, created_at, hosts_content, entry_count, trigger, name FROM snapshots ORDER BY created_at DESC")
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to prepare query: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                let snapshot_id_str: String = row.get(0)?;
                let created_at_str: String = row.get(1)?;
                let hosts_content: String = row.get(2)?;
                let entry_count: i32 = row.get(3)?;
                let trigger_str: String = row.get(4)?;
                let name: String = row.get(5)?;

                Ok((
                    snapshot_id_str,
                    created_at_str,
                    hosts_content,
                    entry_count,
                    trigger_str,
                    name,
                ))
            })
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to query snapshots: {}", e)))?;

        let mut snapshots = Vec::new();
        for row in rows {
            let snapshot =
                row.map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;

            let trigger = match snapshot.4.as_str() {
                "manual" => SnapshotTrigger::Manual,
                "auto_before_change" => SnapshotTrigger::AutoBeforeChange,
                "scheduled" => SnapshotTrigger::Scheduled,
                _ => {
                    return Err(DatabaseError::InvalidData(format!(
                        "Invalid trigger type: {}",
                        snapshot.4
                    )))
                }
            };

            snapshots.push(Snapshot {
                snapshot_id: Uuid::parse_str(&snapshot.0)
                    .map_err(|e| DatabaseError::InvalidData(e.to_string()))?,
                created_at: chrono::DateTime::parse_from_rfc3339(&snapshot.1)
                    .map_err(|e| DatabaseError::InvalidData(e.to_string()))?
                    .with_timezone(&Utc),
                hosts_content: snapshot.2,
                entry_count: snapshot.3,
                trigger,
                name: if snapshot.5.is_empty() {
                    None
                } else {
                    Some(snapshot.5)
                },
            });
        }

        Ok(snapshots)
    }

    /// Delete a snapshot
    pub fn delete(db: &Database, snapshot_id: &Uuid) -> DatabaseResult<()> {
        let rows_affected = db
            .conn()
            .execute(
                "DELETE FROM snapshots WHERE snapshot_id = ?",
                [&snapshot_id.to_string()],
            )
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to delete snapshot: {}", e)))?;

        if rows_affected == 0 {
            return Err(DatabaseError::SnapshotNotFound(format!(
                "Snapshot {} not found",
                snapshot_id
            )));
        }

        Ok(())
    }

    /// Count total snapshots
    pub fn count(db: &Database) -> DatabaseResult<i32> {
        let count: i32 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to count snapshots: {}", e)))?;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_snapshot() {
        let db = Database::in_memory().unwrap();
        let snapshot = SnapshotsRepository::create(
            &db,
            "# test content",
            42,
            SnapshotTrigger::Manual,
            Some("Test snapshot"),
        );

        assert!(snapshot.is_ok());
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.hosts_content, "# test content");
        assert_eq!(snapshot.entry_count, 42);
        assert_eq!(snapshot.trigger, SnapshotTrigger::Manual);
        assert_eq!(snapshot.name, Some("Test snapshot".to_string()));
    }

    #[test]
    fn test_get_snapshot() {
        let db = Database::in_memory().unwrap();
        let created = SnapshotsRepository::create(
            &db,
            "# content",
            10,
            SnapshotTrigger::AutoBeforeChange,
            None,
        )
        .unwrap();

        let retrieved = SnapshotsRepository::get(&db, &created.snapshot_id);
        assert!(retrieved.is_ok());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.snapshot_id, created.snapshot_id);
        assert_eq!(retrieved.hosts_content, "# content");
        assert_eq!(retrieved.trigger, SnapshotTrigger::AutoBeforeChange);
    }

    #[test]
    fn test_get_nonexistent_snapshot() {
        let db = Database::in_memory().unwrap();
        let result = SnapshotsRepository::get(&db, &Uuid::new_v4());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DatabaseError::SnapshotNotFound(_)
        ));
    }

    #[test]
    fn test_list_snapshots() {
        let db = Database::in_memory().unwrap();
        SnapshotsRepository::create(&db, "# first", 10, SnapshotTrigger::Manual, Some("First"))
            .unwrap();
        SnapshotsRepository::create(
            &db,
            "# second",
            20,
            SnapshotTrigger::AutoBeforeChange,
            Some("Second"),
        )
        .unwrap();

        let snapshots = SnapshotsRepository::list(&db).unwrap();
        assert_eq!(snapshots.len(), 2);
        // Should be ordered by creation date, newest first
        assert_eq!(snapshots[0].name, Some("Second".to_string()));
        assert_eq!(snapshots[1].name, Some("First".to_string()));
    }

    #[test]
    fn test_delete_snapshot() {
        let db = Database::in_memory().unwrap();
        let created =
            SnapshotsRepository::create(&db, "# content", 10, SnapshotTrigger::Manual, None)
                .unwrap();

        let result = SnapshotsRepository::delete(&db, &created.snapshot_id);
        assert!(result.is_ok());

        // Verify it's deleted
        let result = SnapshotsRepository::get(&db, &created.snapshot_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_count_snapshots() {
        let db = Database::in_memory().unwrap();
        assert_eq!(SnapshotsRepository::count(&db).unwrap(), 0);

        SnapshotsRepository::create(&db, "# first", 10, SnapshotTrigger::Manual, None).unwrap();
        assert_eq!(SnapshotsRepository::count(&db).unwrap(), 1);

        SnapshotsRepository::create(&db, "# second", 20, SnapshotTrigger::AutoBeforeChange, None)
            .unwrap();
        assert_eq!(SnapshotsRepository::count(&db).unwrap(), 2);
    }

    #[test]
    fn test_all_trigger_types() {
        let db = Database::in_memory().unwrap();

        SnapshotsRepository::create(&db, "# manual", 1, SnapshotTrigger::Manual, None).unwrap();
        SnapshotsRepository::create(&db, "# auto", 2, SnapshotTrigger::AutoBeforeChange, None)
            .unwrap();
        SnapshotsRepository::create(&db, "# scheduled", 3, SnapshotTrigger::Scheduled, None)
            .unwrap();

        let snapshots = SnapshotsRepository::list(&db).unwrap();
        assert_eq!(snapshots.len(), 3);
    }
}
