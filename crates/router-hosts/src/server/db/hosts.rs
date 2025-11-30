use super::schema::{Database, DatabaseError, DatabaseResult};
use super::HostEntry;
use chrono::Utc;
use duckdb::OptionalExt;
use router_hosts_common::validation::{validate_hostname, validate_ip_address};
use ulid::Ulid;
use uuid::Uuid;

/// Repository for host entry operations
pub struct HostsRepository;

impl HostsRepository {
    /// Add a new host entry
    /// If an inactive entry with the same ip/hostname exists, it will be reactivated
    pub fn add(
        db: &Database,
        ip_address: &str,
        hostname: &str,
        comment: Option<&str>,
        tags: &[String],
    ) -> DatabaseResult<HostEntry> {
        // Validate inputs
        validate_ip_address(ip_address)
            .map_err(|e| DatabaseError::InvalidData(format!("Invalid IP address: {}", e)))?;
        validate_hostname(hostname)
            .map_err(|e| DatabaseError::InvalidData(format!("Invalid hostname: {}", e)))?;

        // Check if an entry with this ip/hostname already exists
        let mut stmt = db
            .conn()
            .prepare("SELECT id, active, created_at FROM host_entries WHERE ip_address = ? AND hostname = ?")
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to check existing entry: {}", e)))?;

        let existing = stmt
            .query_row([&ip_address as &dyn duckdb::ToSql, &hostname as &dyn duckdb::ToSql], |row| {
                let id_str: String = row.get(0)?;
                let active: bool = row.get(1)?;
                let created_at_str: String = row.get(2)?;
                Ok((id_str, active, created_at_str))
            })
            .optional()
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to query existing entry: {}", e)))?;

        match existing {
            Some((_id_str, true, _created_at_str)) => {
                // Entry exists and is active - return error
                Err(DatabaseError::DuplicateEntry(format!(
                    "Host entry {}@{} already exists",
                    hostname, ip_address
                )))
            }
            Some((id_str, false, created_at_str)) => {
                // Entry exists but is inactive - reactivate it
                let id = Uuid::parse_str(&id_str)
                    .map_err(|e| DatabaseError::InvalidData(format!("Invalid UUID: {}", e)))?;
                let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| DatabaseError::InvalidData(format!("Invalid timestamp: {}", e)))?
                    .with_timezone(&Utc);

                let now = Utc::now();
                let new_version = Ulid::new();
                let tags_json = serde_json::to_string(tags)
                    .map_err(|e| DatabaseError::InvalidData(e.to_string()))?;

                // Reactivate and update the entry with new version tag
                db.conn()
                    .execute(
                        "UPDATE host_entries SET active = true, comment = ?, tags = ?, updated_at = ?, version_tag = ? WHERE id = ?",
                        [
                            &comment.unwrap_or("") as &dyn duckdb::ToSql,
                            &tags_json as &dyn duckdb::ToSql,
                            &now.to_rfc3339() as &dyn duckdb::ToSql,
                            &new_version.to_string() as &dyn duckdb::ToSql,
                            &id.to_string() as &dyn duckdb::ToSql,
                        ],
                    )
                    .map_err(|e| {
                        DatabaseError::QueryFailed(format!("Failed to reactivate entry: {}", e))
                    })?;

                Ok(HostEntry {
                    id,
                    ip_address: ip_address.to_string(),
                    hostname: hostname.to_string(),
                    comment: comment.map(String::from),
                    tags: tags.to_vec(),
                    created_at,
                    updated_at: now,
                    active: true,
                    version_tag: new_version,
                })
            }
            None => {
                // Entry doesn't exist - insert new
                let id = Uuid::new_v4();
                let now = Utc::now();
                let version = Ulid::new();
                let tags_json = serde_json::to_string(tags)
                    .map_err(|e| DatabaseError::InvalidData(e.to_string()))?;

                db.conn()
                    .execute(
                        r#"
                        INSERT INTO host_entries (id, ip_address, hostname, comment, tags, created_at, updated_at, active, version_tag)
                        VALUES (?, ?, ?, ?, ?, ?, ?, true, ?)
                        "#,
                        [
                            &id.to_string() as &dyn duckdb::ToSql,
                            &ip_address as &dyn duckdb::ToSql,
                            &hostname as &dyn duckdb::ToSql,
                            &comment.unwrap_or("") as &dyn duckdb::ToSql,
                            &tags_json as &dyn duckdb::ToSql,
                            &now.to_rfc3339() as &dyn duckdb::ToSql,
                            &now.to_rfc3339() as &dyn duckdb::ToSql,
                            &version.to_string() as &dyn duckdb::ToSql,
                        ],
                    )
                    .map_err(|e| DatabaseError::QueryFailed(format!("Failed to insert host entry: {}", e)))?;

                Ok(HostEntry {
                    id,
                    ip_address: ip_address.to_string(),
                    hostname: hostname.to_string(),
                    comment: comment.map(String::from),
                    tags: tags.to_vec(),
                    created_at: now,
                    updated_at: now,
                    active: true,
                    version_tag: version,
                })
            }
        }
    }

    /// Get a host entry by ID
    pub fn get(db: &Database, id: &Uuid) -> DatabaseResult<HostEntry> {
        let mut stmt = db
            .conn()
            .prepare("SELECT id, ip_address, hostname, comment, tags, created_at, updated_at, active, version_tag FROM host_entries WHERE id = ?")
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to prepare query: {}", e)))?;

        let entry = stmt
            .query_row([&id.to_string()], |row| {
                let id_str: String = row.get(0)?;
                let ip_address: String = row.get(1)?;
                let hostname: String = row.get(2)?;
                let comment: String = row.get(3)?;
                let tags_json: String = row.get(4)?;
                let created_at_str: String = row.get(5)?;
                let updated_at_str: String = row.get(6)?;
                let active: bool = row.get(7)?;
                let version_tag_str: String = row.get(8)?;

                Ok((
                    id_str,
                    ip_address,
                    hostname,
                    comment,
                    tags_json,
                    created_at_str,
                    updated_at_str,
                    active,
                    version_tag_str,
                ))
            })
            .map_err(|e| {
                DatabaseError::HostNotFound(format!("Host entry {} not found: {}", id, e))
            })?;

        let tags: Vec<String> = serde_json::from_str(&entry.4)
            .map_err(|e| DatabaseError::InvalidData(e.to_string()))?;

        Ok(HostEntry {
            id: Uuid::parse_str(&entry.0).map_err(|e| DatabaseError::InvalidData(e.to_string()))?,
            ip_address: entry.1,
            hostname: entry.2,
            comment: if entry.3.is_empty() {
                None
            } else {
                Some(entry.3)
            },
            tags,
            created_at: chrono::DateTime::parse_from_rfc3339(&entry.5)
                .map_err(|e| DatabaseError::InvalidData(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&entry.6)
                .map_err(|e| DatabaseError::InvalidData(e.to_string()))?
                .with_timezone(&Utc),
            active: entry.7,
            version_tag: Ulid::from_string(&entry.8)
                .map_err(|e| DatabaseError::InvalidData(format!("Invalid ULID: {}", e)))?,
        })
    }

    /// List all active host entries
    pub fn list_active(db: &Database) -> DatabaseResult<Vec<HostEntry>> {
        let mut stmt = db
            .conn()
            .prepare("SELECT id, ip_address, hostname, comment, tags, created_at, updated_at, active, version_tag FROM host_entries WHERE active = true ORDER BY ip_address, hostname")
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to prepare query: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                let id_str: String = row.get(0)?;
                let ip_address: String = row.get(1)?;
                let hostname: String = row.get(2)?;
                let comment: String = row.get(3)?;
                let tags_json: String = row.get(4)?;
                let created_at_str: String = row.get(5)?;
                let updated_at_str: String = row.get(6)?;
                let active: bool = row.get(7)?;
                let version_tag_str: String = row.get(8)?;

                Ok((
                    id_str,
                    ip_address,
                    hostname,
                    comment,
                    tags_json,
                    created_at_str,
                    updated_at_str,
                    active,
                    version_tag_str,
                ))
            })
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to query host entries: {}", e))
            })?;

        let mut entries = Vec::new();
        for row in rows {
            let entry =
                row.map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;
            let tags: Vec<String> = serde_json::from_str(&entry.4)
                .map_err(|e| DatabaseError::InvalidData(e.to_string()))?;

            entries.push(HostEntry {
                id: Uuid::parse_str(&entry.0)
                    .map_err(|e| DatabaseError::InvalidData(e.to_string()))?,
                ip_address: entry.1,
                hostname: entry.2,
                comment: if entry.3.is_empty() {
                    None
                } else {
                    Some(entry.3)
                },
                tags,
                created_at: chrono::DateTime::parse_from_rfc3339(&entry.5)
                    .map_err(|e| DatabaseError::InvalidData(e.to_string()))?
                    .with_timezone(&Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&entry.6)
                    .map_err(|e| DatabaseError::InvalidData(e.to_string()))?
                    .with_timezone(&Utc),
                active: entry.7,
                version_tag: Ulid::from_string(&entry.8)
                    .map_err(|e| DatabaseError::InvalidData(format!("Invalid ULID: {}", e)))?,
            });
        }

        Ok(entries)
    }

    /// Update a host entry with optimistic locking
    /// Returns ConcurrentModification error if expected_version doesn't match current version
    pub fn update(
        db: &Database,
        id: &Uuid,
        expected_version: &Ulid,
        ip_address: Option<&str>,
        hostname: Option<&str>,
        comment: Option<Option<&str>>,
        tags: Option<&[String]>,
    ) -> DatabaseResult<HostEntry> {
        // First, get the existing entry
        let existing = Self::get(db, id)?;

        let new_ip = ip_address.unwrap_or(&existing.ip_address);
        let new_hostname = hostname.unwrap_or(&existing.hostname);

        // Validate new values
        validate_ip_address(new_ip)
            .map_err(|e| DatabaseError::InvalidData(format!("Invalid IP address: {}", e)))?;
        validate_hostname(new_hostname)
            .map_err(|e| DatabaseError::InvalidData(format!("Invalid hostname: {}", e)))?;

        let new_comment = comment
            .map(|c| c.map(String::from))
            .unwrap_or(existing.comment.clone());
        let new_tags = tags.map(|t| t.to_vec()).unwrap_or(existing.tags.clone());
        let now = Utc::now();
        let new_version = Ulid::new();

        let tags_json = serde_json::to_string(&new_tags)
            .map_err(|e| DatabaseError::InvalidData(e.to_string()))?;

        let rows_affected = db.conn()
            .execute(
                r#"
            UPDATE host_entries
            SET ip_address = ?, hostname = ?, comment = ?, tags = ?, updated_at = ?, version_tag = ?
            WHERE id = ? AND version_tag = ?
            "#,
                [
                    &new_ip as &dyn duckdb::ToSql,
                    &new_hostname as &dyn duckdb::ToSql,
                    &new_comment.as_deref().unwrap_or("") as &dyn duckdb::ToSql,
                    &tags_json as &dyn duckdb::ToSql,
                    &now.to_rfc3339() as &dyn duckdb::ToSql,
                    &new_version.to_string() as &dyn duckdb::ToSql,
                    &id.to_string() as &dyn duckdb::ToSql,
                    &expected_version.to_string() as &dyn duckdb::ToSql,
                ],
            )
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to update host entry: {}", e))
            })?;

        if rows_affected == 0 {
            return Err(DatabaseError::ConcurrentModification(format!(
                "Host entry {} was modified by another process (expected version: {})",
                id, expected_version
            )));
        }

        Ok(HostEntry {
            id: *id,
            ip_address: new_ip.to_string(),
            hostname: new_hostname.to_string(),
            comment: new_comment,
            tags: new_tags,
            created_at: existing.created_at,
            updated_at: now,
            active: existing.active,
            version_tag: new_version,
        })
    }

    /// Delete a host entry (soft delete) with optimistic locking
    /// Returns ConcurrentModification error if expected_version doesn't match current version
    pub fn delete(db: &Database, id: &Uuid, expected_version: &Ulid) -> DatabaseResult<()> {
        let new_version = Ulid::new();
        let rows_affected = db
            .conn()
            .execute(
                "UPDATE host_entries SET active = false, version_tag = ? WHERE id = ? AND version_tag = ?",
                [&new_version.to_string(), &id.to_string(), &expected_version.to_string()],
            )
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to delete host entry: {}", e))
            })?;

        if rows_affected == 0 {
            // Check if entry exists to differentiate between NotFound and ConcurrentModification
            let exists = db.conn()
                .query_row(
                    "SELECT version_tag FROM host_entries WHERE id = ?",
                    [&id.to_string()],
                    |row| {
                        let version_str: String = row.get(0)?;
                        Ok(version_str)
                    },
                )
                .optional()
                .map_err(|e| DatabaseError::QueryFailed(format!("Failed to check entry existence: {}", e)))?;

            match exists {
                Some(current_version) => {
                    return Err(DatabaseError::ConcurrentModification(format!(
                        "Host entry {} was modified by another process (expected version: {}, current version: {})",
                        id, expected_version, current_version
                    )));
                }
                None => {
                    return Err(DatabaseError::HostNotFound(format!(
                        "Host entry {} not found",
                        id
                    )));
                }
            }
        }

        Ok(())
    }

    /// Count active host entries
    pub fn count_active(db: &Database) -> DatabaseResult<i32> {
        let count: i32 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM host_entries WHERE active = true",
                [],
                |row| row.get(0),
            )
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to count host entries: {}", e))
            })?;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_host_entry() {
        let db = Database::in_memory().unwrap();
        let entry = HostsRepository::add(
            &db,
            "192.168.1.10",
            "server.local",
            Some("Test server"),
            &["test".to_string()],
        );

        assert!(entry.is_ok());
        let entry = entry.unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, Some("Test server".to_string()));
        assert_eq!(entry.tags, vec!["test".to_string()]);
        assert!(entry.active);
    }

    #[test]
    fn test_add_duplicate_host_entry() {
        let db = Database::in_memory().unwrap();
        HostsRepository::add(&db, "192.168.1.10", "server.local", None, &[]).unwrap();

        let result = HostsRepository::add(&db, "192.168.1.10", "server.local", None, &[]);
        assert!(result.is_err(), "Should return error for duplicate");
        let err = result.unwrap_err();
        assert!(
            matches!(err, DatabaseError::DuplicateEntry(_)),
            "Expected DuplicateEntry, got: {:?}",
            err
        );
    }

    #[test]
    fn test_get_host_entry() {
        let db = Database::in_memory().unwrap();
        let added = HostsRepository::add(
            &db,
            "192.168.1.10",
            "server.local",
            Some("Test"),
            &["tag1".to_string()],
        )
        .unwrap();

        let retrieved = HostsRepository::get(&db, &added.id);
        assert!(retrieved.is_ok());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, added.id);
        assert_eq!(retrieved.ip_address, "192.168.1.10");
        assert_eq!(retrieved.hostname, "server.local");
    }

    #[test]
    fn test_get_nonexistent_host_entry() {
        let db = Database::in_memory().unwrap();
        let result = HostsRepository::get(&db, &Uuid::new_v4());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DatabaseError::HostNotFound(_)
        ));
    }

    #[test]
    fn test_list_active_host_entries() {
        let db = Database::in_memory().unwrap();
        HostsRepository::add(&db, "192.168.1.10", "server1.local", None, &[]).unwrap();
        HostsRepository::add(&db, "192.168.1.20", "server2.local", None, &[]).unwrap();

        let entries = HostsRepository::list_active(&db).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip_address, "192.168.1.10");
        assert_eq!(entries[1].ip_address, "192.168.1.20");
    }

    #[test]
    fn test_update_host_entry() {
        let db = Database::in_memory().unwrap();
        let added = HostsRepository::add(&db, "192.168.1.10", "server.local", None, &[]).unwrap();

        let updated = HostsRepository::update(
            &db,
            &added.id,
            &added.version_tag,
            Some("192.168.1.11"),
            Some("newserver.local"),
            None,
            None,
        );
        assert!(updated.is_ok());
        let updated = updated.unwrap();
        assert_eq!(updated.ip_address, "192.168.1.11");
        assert_eq!(updated.hostname, "newserver.local");
    }

    #[test]
    fn test_delete_host_entry() {
        let db = Database::in_memory().unwrap();
        let added = HostsRepository::add(&db, "192.168.1.10", "server.local", None, &[]).unwrap();

        let result = HostsRepository::delete(&db, &added.id, &added.version_tag);
        assert!(result.is_ok());

        // Verify it's soft deleted (not in active list)
        let entries = HostsRepository::list_active(&db).unwrap();
        assert_eq!(entries.len(), 0);

        // But still in database
        let retrieved = HostsRepository::get(&db, &added.id).unwrap();
        assert!(!retrieved.active);
    }

    #[test]
    fn test_readd_deleted_entry() {
        let db = Database::in_memory().unwrap();

        // Add an entry
        let first = HostsRepository::add(&db, "192.168.1.10", "server.local", Some("First"), &[]).unwrap();
        let first_id = first.id;
        let first_created_at = first.created_at;

        // Delete it (soft delete)
        HostsRepository::delete(&db, &first.id, &first.version_tag).unwrap();

        // Re-add the same ip/hostname combination - should reactivate the SAME entry
        let second = HostsRepository::add(&db, "192.168.1.10", "server.local", Some("Second"), &[]);
        assert!(second.is_ok(), "Should be able to re-add deleted entry");

        // Verify it reactivated the SAME entry (same ID), not created a new one
        let second = second.unwrap();
        assert_eq!(second.id, first_id, "Should reactivate same entry, not create new one");
        assert!(second.active);
        assert_eq!(second.comment, Some("Second".to_string()), "Comment should be updated");
        assert_eq!(second.created_at, first_created_at, "created_at should be preserved");

        // Verify only ONE record exists in database (no duplicate inactive records)
        let total_count: i32 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM host_entries WHERE ip_address = ? AND hostname = ?",
                [&"192.168.1.10", &"server.local"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(total_count, 1, "Should have exactly one record, not duplicates");

        // Verify only one active entry
        let active_entries = HostsRepository::list_active(&db).unwrap();
        assert_eq!(active_entries.len(), 1);
        assert_eq!(active_entries[0].id, second.id);
    }

    #[test]
    fn test_count_active_entries() {
        let db = Database::in_memory().unwrap();
        assert_eq!(HostsRepository::count_active(&db).unwrap(), 0);

        HostsRepository::add(&db, "192.168.1.10", "server1.local", None, &[]).unwrap();
        assert_eq!(HostsRepository::count_active(&db).unwrap(), 1);

        HostsRepository::add(&db, "192.168.1.20", "server2.local", None, &[]).unwrap();
        assert_eq!(HostsRepository::count_active(&db).unwrap(), 2);
    }

    #[test]
    fn test_concurrent_update_detection() {
        let db = Database::in_memory().unwrap();
        let added = HostsRepository::add(&db, "192.168.1.10", "server.local", None, &[]).unwrap();
        let original_version = added.version_tag;

        // First update succeeds
        let updated = HostsRepository::update(
            &db,
            &added.id,
            &original_version,
            Some("192.168.1.11"),
            None,
            None,
            None,
        )
        .unwrap();

        // Version has changed
        assert_ne!(updated.version_tag, original_version);

        // Second update with old version fails
        let result = HostsRepository::update(
            &db,
            &added.id,
            &original_version, // Using OLD version tag
            Some("192.168.1.12"),
            None,
            None,
            None,
        );

        assert!(result.is_err(), "Update with old version should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, DatabaseError::ConcurrentModification(_)),
            "Expected ConcurrentModification error, got: {:?}",
            err
        );

        // Verify entry wasn't modified
        let current = HostsRepository::get(&db, &added.id).unwrap();
        assert_eq!(current.ip_address, "192.168.1.11", "Entry should not be modified");
        assert_eq!(current.version_tag, updated.version_tag);
    }

    #[test]
    fn test_concurrent_delete_detection() {
        let db = Database::in_memory().unwrap();
        let added = HostsRepository::add(&db, "192.168.1.10", "server.local", None, &[]).unwrap();
        let original_version = added.version_tag;

        // Simulate an update by another process
        let updated = HostsRepository::update(
            &db,
            &added.id,
            &original_version,
            Some("192.168.1.11"),
            None,
            None,
            None,
        )
        .unwrap();

        // Try to delete with old version
        let result = HostsRepository::delete(&db, &added.id, &original_version);

        assert!(result.is_err(), "Delete with old version should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, DatabaseError::ConcurrentModification(_)),
            "Expected ConcurrentModification error, got: {:?}",
            err
        );

        // Verify entry is still active
        let current = HostsRepository::get(&db, &added.id).unwrap();
        assert!(current.active, "Entry should still be active");
        assert_eq!(current.version_tag, updated.version_tag);
    }

    #[test]
    fn test_delete_nonexistent_vs_concurrent_modification() {
        let db = Database::in_memory().unwrap();
        let fake_id = Uuid::new_v4();
        let fake_version = Ulid::new();

        // Delete non-existent entry should return HostNotFound
        let result = HostsRepository::delete(&db, &fake_id, &fake_version);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), DatabaseError::HostNotFound(_)),
            "Expected HostNotFound for non-existent entry"
        );
    }
}
