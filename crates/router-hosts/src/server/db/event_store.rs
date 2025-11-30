use super::events::{EventEnvelope, EventMetadata, HostEvent};
use super::schema_v2::{Database, DatabaseError, DatabaseResult};
use chrono::{DateTime, Utc};
use duckdb::OptionalExt;
use uuid::Uuid;

/// Event store for persisting and retrieving domain events
///
/// This implements an append-only event log with:
/// - Optimistic concurrency control via event versioning
/// - Sequential event ordering per aggregate
/// - Efficient event replay for rebuilding state
pub struct EventStore;

impl EventStore {
    /// Append a new event to the store
    ///
    /// # Optimistic Concurrency
    ///
    /// The `expected_version` parameter implements optimistic locking:
    /// - Pass `None` when creating a new aggregate (first event)
    /// - Pass `Some(n)` where `n` is the last known version number
    /// - Returns `ConcurrentWriteConflict` if another write occurred
    ///
    /// # Arguments
    ///
    /// * `db` - Database connection
    /// * `aggregate_id` - ID of the aggregate (host entry)
    /// * `event` - Domain event to store
    /// * `expected_version` - Expected current version for optimistic locking
    /// * `created_by` - Optional user/system identifier
    /// * `metadata` - Optional event metadata
    ///
    /// # Returns
    ///
    /// Returns the stored `EventEnvelope` with generated event_id and version
    pub fn append_event(
        db: &Database,
        aggregate_id: &Uuid,
        event: HostEvent,
        expected_version: Option<i64>,
        created_by: Option<String>,
        metadata: Option<EventMetadata>,
    ) -> DatabaseResult<EventEnvelope> {
        // Get current version for this aggregate
        let current_version = Self::get_current_version(db, aggregate_id)?;

        // Verify expected version matches (optimistic concurrency control)
        if expected_version != current_version {
            return Err(DatabaseError::ConcurrentWriteConflict(format!(
                "Expected version {:?} but current version is {:?} for aggregate {}",
                expected_version, current_version, aggregate_id
            )));
        }

        // Calculate next version
        let new_version = current_version.unwrap_or(0) + 1;

        // Generate event ID
        let event_id = Uuid::new_v4();
        let now = Utc::now();

        // Serialize metadata to JSON
        let metadata_json = metadata
            .as_ref()
            .map(|m| {
                serde_json::to_string(m).map_err(|e| {
                    DatabaseError::InvalidData(format!("Failed to serialize metadata: {}", e))
                })
            })
            .transpose()?;

        // Extract event fields into typed columns
        // Only tags are stored as JSON, everything else is a first-class column
        let result = match &event {
            HostEvent::HostCreated {
                ip_address,
                hostname,
                comment,
                tags,
                created_at,
            } => {
                let tags_json = serde_json::to_string(tags).map_err(|e| {
                    DatabaseError::InvalidData(format!("Failed to serialize tags: {}", e))
                })?;

                db.conn().execute(
                    r#"
                    INSERT INTO host_events (
                        event_id, aggregate_id, event_type, event_version,
                        ip_address, hostname, comment, tags, event_timestamp,
                        event_metadata, created_at, created_by, expected_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    [
                        &event_id.to_string() as &dyn duckdb::ToSql,
                        &aggregate_id.to_string(),
                        &event.event_type(),
                        &new_version,
                        &ip_address as &dyn duckdb::ToSql,
                        &hostname as &dyn duckdb::ToSql,
                        &comment as &dyn duckdb::ToSql,
                        &tags_json as &dyn duckdb::ToSql,
                        &created_at.to_rfc3339(),
                        &metadata_json.as_deref().unwrap_or("null"),
                        &now.to_rfc3339(),
                        &created_by.as_deref().unwrap_or("system"),
                        &expected_version,
                    ],
                )
            }
            HostEvent::IpAddressChanged {
                new_ip, changed_at, ..
            } => db.conn().execute(
                r#"
                    INSERT INTO host_events (
                        event_id, aggregate_id, event_type, event_version,
                        ip_address, event_timestamp,
                        event_metadata, created_at, created_by, expected_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                [
                    &event_id.to_string() as &dyn duckdb::ToSql,
                    &aggregate_id.to_string(),
                    &event.event_type(),
                    &new_version,
                    &new_ip as &dyn duckdb::ToSql,
                    &changed_at.to_rfc3339(),
                    &metadata_json.as_deref().unwrap_or("null"),
                    &now.to_rfc3339(),
                    &created_by.as_deref().unwrap_or("system"),
                    &expected_version,
                ],
            ),
            HostEvent::HostnameChanged {
                new_hostname,
                changed_at,
                ..
            } => db.conn().execute(
                r#"
                    INSERT INTO host_events (
                        event_id, aggregate_id, event_type, event_version,
                        hostname, event_timestamp,
                        event_metadata, created_at, created_by, expected_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                [
                    &event_id.to_string() as &dyn duckdb::ToSql,
                    &aggregate_id.to_string(),
                    &event.event_type(),
                    &new_version,
                    &new_hostname as &dyn duckdb::ToSql,
                    &changed_at.to_rfc3339(),
                    &metadata_json.as_deref().unwrap_or("null"),
                    &now.to_rfc3339(),
                    &created_by.as_deref().unwrap_or("system"),
                    &expected_version,
                ],
            ),
            HostEvent::CommentUpdated {
                new_comment,
                updated_at,
                ..
            } => db.conn().execute(
                r#"
                    INSERT INTO host_events (
                        event_id, aggregate_id, event_type, event_version,
                        comment, event_timestamp,
                        event_metadata, created_at, created_by, expected_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                [
                    &event_id.to_string() as &dyn duckdb::ToSql,
                    &aggregate_id.to_string(),
                    &event.event_type(),
                    &new_version,
                    &new_comment as &dyn duckdb::ToSql,
                    &updated_at.to_rfc3339(),
                    &metadata_json.as_deref().unwrap_or("null"),
                    &now.to_rfc3339(),
                    &created_by.as_deref().unwrap_or("system"),
                    &expected_version,
                ],
            ),
            HostEvent::TagsModified {
                new_tags,
                modified_at,
                ..
            } => {
                let new_tags_json = serde_json::to_string(new_tags).map_err(|e| {
                    DatabaseError::InvalidData(format!("Failed to serialize new_tags: {}", e))
                })?;

                db.conn().execute(
                    r#"
                    INSERT INTO host_events (
                        event_id, aggregate_id, event_type, event_version,
                        tags, event_timestamp,
                        event_metadata, created_at, created_by, expected_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    [
                        &event_id.to_string() as &dyn duckdb::ToSql,
                        &aggregate_id.to_string(),
                        &event.event_type(),
                        &new_version,
                        &new_tags_json as &dyn duckdb::ToSql,
                        &modified_at.to_rfc3339(),
                        &metadata_json.as_deref().unwrap_or("null"),
                        &now.to_rfc3339(),
                        &created_by.as_deref().unwrap_or("system"),
                        &expected_version,
                    ],
                )
            }
            HostEvent::HostDeleted {
                ip_address,
                hostname,
                deleted_at,
                reason,
            } => db.conn().execute(
                r#"
                    INSERT INTO host_events (
                        event_id, aggregate_id, event_type, event_version,
                        ip_address, hostname, deleted_reason, event_timestamp,
                        event_metadata, created_at, created_by, expected_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                [
                    &event_id.to_string() as &dyn duckdb::ToSql,
                    &aggregate_id.to_string(),
                    &event.event_type(),
                    &new_version,
                    &ip_address as &dyn duckdb::ToSql,
                    &hostname as &dyn duckdb::ToSql,
                    &reason as &dyn duckdb::ToSql,
                    &deleted_at.to_rfc3339(),
                    &metadata_json.as_deref().unwrap_or("null"),
                    &now.to_rfc3339(),
                    &created_by.as_deref().unwrap_or("system"),
                    &expected_version,
                ],
            ),
        };

        result.map_err(|e: duckdb::Error| {
            // Check if this was a uniqueness violation (concurrent write)
            let error_str = e.to_string();
            if error_str.contains("UNIQUE") || error_str.contains("unique constraint") {
                DatabaseError::ConcurrentWriteConflict(format!(
                    "Concurrent write detected for aggregate {} at version {}",
                    aggregate_id, new_version
                ))
            } else {
                DatabaseError::QueryFailed(format!("Failed to insert event: {}", e))
            }
        })?;

        Ok(EventEnvelope {
            event_id,
            aggregate_id: *aggregate_id,
            event,
            event_version: new_version,
            created_at: now,
            created_by,
            metadata,
        })
    }

    /// Get the current version number for an aggregate
    ///
    /// Returns `None` if the aggregate doesn't exist yet (no events)
    fn get_current_version(db: &Database, aggregate_id: &Uuid) -> DatabaseResult<Option<i64>> {
        let version = db
            .conn()
            .query_row(
                "SELECT MAX(event_version) FROM host_events WHERE aggregate_id = ?",
                [&aggregate_id.to_string()],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|e| {
                DatabaseError::QueryFailed(format!(
                    "Failed to get current version for {}: {}",
                    aggregate_id, e
                ))
            })?;

        Ok(version.flatten())
    }

    /// Load all events for an aggregate in order
    ///
    /// This is used to rebuild aggregate state from the event log.
    /// Note: For change events (IpAddressChanged, etc.), we only store the new value.
    /// The old value is reconstructed by replaying events in order.
    pub fn load_events(db: &Database, aggregate_id: &Uuid) -> DatabaseResult<Vec<EventEnvelope>> {
        let mut stmt = db
            .conn()
            .prepare(
                r#"
                SELECT
                    event_id,
                    aggregate_id,
                    event_type,
                    event_version,
                    CAST(ip_address AS VARCHAR) as ip_address,
                    hostname,
                    comment,
                    COALESCE(CAST(tags AS VARCHAR), '[]') as tags,
                    deleted_reason,
                    event_timestamp,
                    event_metadata,
                    created_at,
                    created_by
                FROM host_events
                WHERE aggregate_id = ?
                ORDER BY event_version ASC
                "#,
            )
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to prepare query: {}", e)))?;

        let rows = stmt
            .query_map([&aggregate_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,         // event_id
                    row.get::<_, String>(1)?,         // aggregate_id
                    row.get::<_, String>(2)?,         // event_type
                    row.get::<_, i64>(3)?,            // event_version
                    row.get::<_, Option<String>>(4)?, // ip_address
                    row.get::<_, Option<String>>(5)?, // hostname
                    row.get::<_, Option<String>>(6)?, // comment
                    row.get::<_, Option<String>>(7)?, // tags
                    row.get::<_, Option<String>>(8)?, // deleted_reason
                    row.get::<_, i64>(9)?,            // event_timestamp
                    row.get::<_, String>(10)?,        // event_metadata
                    row.get::<_, i64>(11)?,           // created_at
                    row.get::<_, String>(12)?,        // created_by
                ))
            })
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to query events: {}", e)))?;

        let mut envelopes = Vec::new();
        let mut current_state: Option<(String, String, Option<String>, Vec<String>)> = None; // (ip, hostname, comment, tags)

        for row in rows {
            let (
                event_id_str,
                aggregate_id_str,
                event_type,
                event_version,
                ip_address,
                hostname,
                comment,
                tags_json,
                deleted_reason,
                event_timestamp_micros,
                metadata_json,
                created_at_micros,
                created_by,
            ) =
                row.map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;

            let event_id = Uuid::parse_str(&event_id_str)
                .map_err(|e| DatabaseError::InvalidData(format!("Invalid event_id UUID: {}", e)))?;

            let agg_id = Uuid::parse_str(&aggregate_id_str).map_err(|e| {
                DatabaseError::InvalidData(format!("Invalid aggregate_id UUID: {}", e))
            })?;

            let event_timestamp = DateTime::from_timestamp_micros(event_timestamp_micros)
                .ok_or_else(|| {
                    DatabaseError::InvalidData(format!(
                        "Invalid event timestamp: {}",
                        event_timestamp_micros
                    ))
                })?;

            // Reconstruct the event from typed columns based on event_type
            // For change events, we reconstruct old_* values from current_state
            let event = match event_type.as_str() {
                "HostCreated" => {
                    let tags: Vec<String> = tags_json
                        .as_ref()
                        .map(|j| serde_json::from_str(j))
                        .transpose()
                        .map_err(|e| {
                            DatabaseError::InvalidData(format!("Failed to parse tags: {}", e))
                        })?
                        .unwrap_or_default();

                    let ip = ip_address.ok_or_else(|| {
                        DatabaseError::InvalidData("HostCreated missing ip_address".to_string())
                    })?;
                    let host = hostname.ok_or_else(|| {
                        DatabaseError::InvalidData("HostCreated missing hostname".to_string())
                    })?;

                    // Update current state
                    current_state = Some((ip.clone(), host.clone(), comment.clone(), tags.clone()));

                    HostEvent::HostCreated {
                        ip_address: ip,
                        hostname: host,
                        comment,
                        tags,
                        created_at: event_timestamp,
                    }
                }
                "IpAddressChanged" => {
                    let new_ip = ip_address.ok_or_else(|| {
                        DatabaseError::InvalidData(
                            "IpAddressChanged missing ip_address".to_string(),
                        )
                    })?;

                    // Get old_ip from current state
                    let old_ip = current_state
                        .as_ref()
                        .map(|(ip, _, _, _)| ip.clone())
                        .ok_or_else(|| {
                            DatabaseError::InvalidEventSequence(
                                "IpAddressChanged before HostCreated".to_string(),
                            )
                        })?;

                    // Update current state
                    if let Some((ref mut ip, _, _, _)) = current_state {
                        *ip = new_ip.clone();
                    }

                    HostEvent::IpAddressChanged {
                        old_ip,
                        new_ip,
                        changed_at: event_timestamp,
                    }
                }
                "HostnameChanged" => {
                    let new_hostname = hostname.ok_or_else(|| {
                        DatabaseError::InvalidData("HostnameChanged missing hostname".to_string())
                    })?;

                    // Get old_hostname from current state
                    let old_hostname = current_state
                        .as_ref()
                        .map(|(_, host, _, _)| host.clone())
                        .ok_or_else(|| {
                        DatabaseError::InvalidEventSequence(
                            "HostnameChanged before HostCreated".to_string(),
                        )
                    })?;

                    // Update current state
                    if let Some((_, ref mut host, _, _)) = current_state {
                        *host = new_hostname.clone();
                    }

                    HostEvent::HostnameChanged {
                        old_hostname,
                        new_hostname,
                        changed_at: event_timestamp,
                    }
                }
                "CommentUpdated" => {
                    // Get old_comment from current state
                    let old_comment = current_state.as_ref().and_then(|(_, _, c, _)| c.clone());

                    // Update current state
                    if let Some((_, _, ref mut c, _)) = current_state {
                        *c = comment.clone();
                    }

                    HostEvent::CommentUpdated {
                        old_comment,
                        new_comment: comment,
                        updated_at: event_timestamp,
                    }
                }
                "TagsModified" => {
                    let new_tags: Vec<String> = tags_json
                        .as_ref()
                        .map(|j| serde_json::from_str(j))
                        .transpose()
                        .map_err(|e| {
                            DatabaseError::InvalidData(format!("Failed to parse tags: {}", e))
                        })?
                        .unwrap_or_default();

                    // Get old_tags from current state
                    let old_tags = current_state
                        .as_ref()
                        .map(|(_, _, _, tags)| tags.clone())
                        .unwrap_or_default();

                    // Update current state
                    if let Some((_, _, _, ref mut tags)) = current_state {
                        *tags = new_tags.clone();
                    }

                    HostEvent::TagsModified {
                        old_tags,
                        new_tags,
                        modified_at: event_timestamp,
                    }
                }
                "HostDeleted" => {
                    let event = HostEvent::HostDeleted {
                        ip_address: ip_address.ok_or_else(|| {
                            DatabaseError::InvalidData("HostDeleted missing ip_address".to_string())
                        })?,
                        hostname: hostname.ok_or_else(|| {
                            DatabaseError::InvalidData("HostDeleted missing hostname".to_string())
                        })?,
                        deleted_at: event_timestamp,
                        reason: deleted_reason,
                    };

                    // Clear current state
                    current_state = None;

                    event
                }
                _ => {
                    return Err(DatabaseError::InvalidData(format!(
                        "Unknown event type: {}",
                        event_type
                    )))
                }
            };

            let metadata: Option<EventMetadata> =
                if metadata_json == "null" || metadata_json.is_empty() {
                    None
                } else {
                    Some(serde_json::from_str(&metadata_json).map_err(|e| {
                        DatabaseError::InvalidData(format!("Failed to deserialize metadata: {}", e))
                    })?)
                };

            let created_at =
                DateTime::from_timestamp_micros(created_at_micros).ok_or_else(|| {
                    DatabaseError::InvalidData(format!("Invalid timestamp: {}", created_at_micros))
                })?;

            envelopes.push(EventEnvelope {
                event_id,
                aggregate_id: agg_id,
                event,
                event_version,
                created_at,
                created_by: if created_by == "system" {
                    None
                } else {
                    Some(created_by)
                },
                metadata,
            });
        }

        Ok(envelopes)
    }

    /// Count total events for an aggregate
    pub fn count_events(db: &Database, aggregate_id: &Uuid) -> DatabaseResult<i64> {
        let count = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM host_events WHERE aggregate_id = ?",
                [&aggregate_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to count events: {}", e)))?;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_first_event() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Uuid::new_v4();

        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        let result = EventStore::append_event(&db, &aggregate_id, event, None, None, None);
        assert!(result.is_ok());

        let envelope = result.unwrap();
        assert_eq!(envelope.aggregate_id, aggregate_id);
        assert_eq!(envelope.event_version, 1);
    }

    #[test]
    fn test_append_sequential_events() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Uuid::new_v4();

        // First event
        let event1 = HostEvent::HostCreated {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };
        let envelope1 =
            EventStore::append_event(&db, &aggregate_id, event1, None, None, None).unwrap();
        assert_eq!(envelope1.event_version, 1);

        // Second event
        let event2 = HostEvent::IpAddressChanged {
            old_ip: "192.168.1.10".to_string(),
            new_ip: "192.168.1.11".to_string(),
            changed_at: Utc::now(),
        };
        let envelope2 =
            EventStore::append_event(&db, &aggregate_id, event2, Some(1), None, None).unwrap();
        assert_eq!(envelope2.event_version, 2);
    }

    #[test]
    fn test_optimistic_concurrency_conflict() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Uuid::new_v4();

        // First event
        let event1 = HostEvent::HostCreated {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };
        EventStore::append_event(&db, &aggregate_id, event1, None, None, None).unwrap();

        // Try to append with wrong expected version
        let event2 = HostEvent::IpAddressChanged {
            old_ip: "192.168.1.10".to_string(),
            new_ip: "192.168.1.11".to_string(),
            changed_at: Utc::now(),
        };
        let result = EventStore::append_event(&db, &aggregate_id, event2, Some(5), None, None);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DatabaseError::ConcurrentWriteConflict(_)
        ));
    }

    #[test]
    fn test_load_events() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Uuid::new_v4();

        // Add multiple events
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
            Some(1),
            None,
            None,
        )
        .unwrap();

        // Load all events
        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_version, 1);
        assert_eq!(events[1].event_version, 2);
    }

    #[test]
    fn test_count_events() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Uuid::new_v4();

        assert_eq!(EventStore::count_events(&db, &aggregate_id).unwrap(), 0);

        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(EventStore::count_events(&db, &aggregate_id).unwrap(), 1);
    }
}
