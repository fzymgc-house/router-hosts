use super::events::{EventData, EventEnvelope, EventMetadata, HostEvent};
use super::schema::{Database, DatabaseError, DatabaseResult};
use chrono::{DateTime, Utc};
use duckdb::OptionalExt;
use ulid::Ulid;

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
        aggregate_id: &Ulid,
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
        let event_id = Ulid::new();
        let now = Utc::now();

        // Note: EventMetadata (correlation/causation/user_agent/source_ip) parameter is accepted
        // but not currently persisted to the database. Only EventData is stored in metadata column.
        // To persist EventMetadata, we would need to add a separate column or extend the schema.
        let _ = metadata; // Acknowledge unused parameter

        // Build event data and extract typed columns
        // EventData (JSON metadata): tags, comments, previous values
        // Typed columns: ip_address, hostname (for queryability)
        let (ip_address_opt, hostname_opt, event_timestamp, event_data) = match &event {
            HostEvent::HostCreated {
                ip_address,
                hostname,
                comment,
                tags,
                created_at,
            } => (
                Some(ip_address.clone()),
                Some(hostname.clone()),
                *created_at,
                EventData {
                    comment: comment.clone(),
                    tags: Some(tags.clone()),
                    ..Default::default()
                },
            ),
            HostEvent::IpAddressChanged {
                old_ip,
                new_ip,
                changed_at,
            } => (
                Some(new_ip.clone()),
                None,
                *changed_at,
                EventData {
                    previous_ip: Some(old_ip.clone()),
                    ..Default::default()
                },
            ),
            HostEvent::HostnameChanged {
                old_hostname,
                new_hostname,
                changed_at,
            } => (
                None,
                Some(new_hostname.clone()),
                *changed_at,
                EventData {
                    previous_hostname: Some(old_hostname.clone()),
                    ..Default::default()
                },
            ),
            HostEvent::CommentUpdated {
                old_comment,
                new_comment,
                updated_at,
            } => (
                None,
                None,
                *updated_at,
                EventData {
                    comment: new_comment.clone(),
                    previous_comment: old_comment.clone(),
                    ..Default::default()
                },
            ),
            HostEvent::TagsModified {
                old_tags,
                new_tags,
                modified_at,
            } => (
                None,
                None,
                *modified_at,
                EventData {
                    tags: Some(new_tags.clone()),
                    previous_tags: Some(old_tags.clone()),
                    ..Default::default()
                },
            ),
            HostEvent::HostDeleted {
                ip_address,
                hostname,
                deleted_at,
                reason,
            } => (
                Some(ip_address.clone()),
                Some(hostname.clone()),
                *deleted_at,
                EventData {
                    deleted_reason: reason.clone(),
                    ..Default::default()
                },
            ),
        };

        // Serialize EventData to JSON
        let event_data_json = serde_json::to_string(&event_data).map_err(|e| {
            DatabaseError::InvalidData(format!("Failed to serialize event data: {}", e))
        })?;

        // Single INSERT statement for all event types
        // Use make_timestamp() to convert microseconds to TIMESTAMP
        db.conn()
            .execute(
                r#"
                INSERT INTO host_events (
                    event_id, aggregate_id, event_type, event_version,
                    ip_address, hostname, event_timestamp, metadata,
                    created_at, created_by, expected_version
                ) VALUES (?, ?, ?, ?, ?, ?, make_timestamp(?), ?, make_timestamp(?), ?, ?)
                "#,
                [
                    &event_id.to_string() as &dyn duckdb::ToSql,
                    &aggregate_id.to_string(),
                    &event.event_type(),
                    &new_version,
                    &ip_address_opt as &dyn duckdb::ToSql,
                    &hostname_opt as &dyn duckdb::ToSql,
                    &event_timestamp.timestamp_micros(),
                    &event_data_json as &dyn duckdb::ToSql,
                    &now.timestamp_micros(),
                    &created_by.as_deref().unwrap_or("system"),
                    &expected_version,
                ],
            )
            .map_err(|e: duckdb::Error| {
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
    fn get_current_version(db: &Database, aggregate_id: &Ulid) -> DatabaseResult<Option<i64>> {
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
    pub fn load_events(db: &Database, aggregate_id: &Ulid) -> DatabaseResult<Vec<EventEnvelope>> {
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
                    CAST(metadata AS VARCHAR) as metadata,
                    event_timestamp,
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
                    row.get::<_, String>(6)?,         // metadata
                    row.get::<_, i64>(7)?,            // event_timestamp
                    row.get::<_, i64>(8)?,            // created_at
                    row.get::<_, String>(9)?,         // created_by
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
                metadata_json,
                event_timestamp_micros,
                created_at_micros,
                created_by,
            ) =
                row.map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;

            let event_id = Ulid::from_string(&event_id_str)
                .map_err(|e| DatabaseError::InvalidData(format!("Invalid event_id UUID: {}", e)))?;

            let agg_id = Ulid::from_string(&aggregate_id_str).map_err(|e| {
                DatabaseError::InvalidData(format!("Invalid aggregate_id UUID: {}", e))
            })?;

            let event_timestamp = DateTime::from_timestamp_micros(event_timestamp_micros)
                .ok_or_else(|| {
                    DatabaseError::InvalidData(format!(
                        "Invalid event timestamp: {}",
                        event_timestamp_micros
                    ))
                })?;

            // Deserialize EventData from metadata JSON
            let event_data: EventData = serde_json::from_str(&metadata_json).map_err(|e| {
                DatabaseError::InvalidData(format!("Failed to deserialize event metadata: {}", e))
            })?;

            // Reconstruct the event from typed columns + metadata based on event_type
            // For change events, we reconstruct old_* values from current_state
            let event = match event_type.as_str() {
                "HostCreated" => {
                    let ip = ip_address.ok_or_else(|| {
                        DatabaseError::InvalidData("HostCreated missing ip_address".to_string())
                    })?;
                    let host = hostname.ok_or_else(|| {
                        DatabaseError::InvalidData("HostCreated missing hostname".to_string())
                    })?;

                    let tags = event_data.tags.clone().unwrap_or_default();
                    let comment = event_data.comment.clone();

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

                    // Get old_ip from metadata
                    let old_ip = event_data.previous_ip.ok_or_else(|| {
                        DatabaseError::InvalidData(
                            "IpAddressChanged missing previous_ip in metadata".to_string(),
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

                    // Get old_hostname from metadata
                    let old_hostname = event_data.previous_hostname.ok_or_else(|| {
                        DatabaseError::InvalidData(
                            "HostnameChanged missing previous_hostname in metadata".to_string(),
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
                    // Get old_comment and new_comment from metadata
                    let old_comment = event_data.previous_comment.clone();
                    let new_comment = event_data.comment.clone();

                    // Update current state
                    if let Some((_, _, ref mut c, _)) = current_state {
                        *c = new_comment.clone();
                    }

                    HostEvent::CommentUpdated {
                        old_comment,
                        new_comment,
                        updated_at: event_timestamp,
                    }
                }
                "TagsModified" => {
                    // Get old_tags and new_tags from metadata
                    let old_tags = event_data.previous_tags.clone().unwrap_or_default();
                    let new_tags = event_data.tags.clone().unwrap_or_default();

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
                        reason: event_data.deleted_reason.clone(),
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

            // Note: EventMetadata (correlation/causation/user_agent/source_ip) is not currently
            // stored in the database. The metadata column contains EventData (domain event data).
            // EventMetadata would need a separate column if we want to persist it.
            let metadata: Option<EventMetadata> = None;

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
    pub fn count_events(db: &Database, aggregate_id: &Ulid) -> DatabaseResult<i64> {
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
        let aggregate_id = Ulid::new();

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
        let aggregate_id = Ulid::new();

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
        let aggregate_id = Ulid::new();

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
        let aggregate_id = Ulid::new();

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
        let aggregate_id = Ulid::new();

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

    // Boundary and edge case tests

    #[test]
    fn test_host_created_with_all_metadata() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        let event = HostEvent::HostCreated {
            ip_address: "2001:0db8:85a3:0000:0000:8a2e:0370:7334".to_string(),
            hostname: "very-long-hostname-with-many-parts.subdomain.example.com".to_string(),
            comment: Some("This is a detailed comment with special chars: <>&\"'".to_string()),
            tags: vec![
                "production".to_string(),
                "critical".to_string(),
                "team-alpha".to_string(),
            ],
            created_at: Utc::now(),
        };

        let result = EventStore::append_event(&db, &aggregate_id, event.clone(), None, None, None);
        assert!(result.is_ok());

        // Verify the event can be loaded and metadata is preserved
        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(events.len(), 1);

        if let HostEvent::HostCreated {
            ip_address,
            hostname,
            comment,
            tags,
            ..
        } = &events[0].event
        {
            // DuckDB INET type normalizes IPv6 addresses (removes leading zeros, compresses)
            assert_eq!(ip_address, "2001:db8:85a3::8a2e:370:7334");
            assert_eq!(
                hostname,
                "very-long-hostname-with-many-parts.subdomain.example.com"
            );
            assert_eq!(
                comment.as_deref(),
                Some("This is a detailed comment with special chars: <>&\"'")
            );
            assert_eq!(tags.len(), 3);
            assert_eq!(tags[0], "production");
        } else {
            panic!("Expected HostCreated event");
        }
    }

    #[test]
    fn test_all_event_types_roundtrip() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // HostCreated
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "10.0.0.1".to_string(),
                hostname: "test.local".to_string(),
                comment: Some("Initial".to_string()),
                tags: vec!["dev".to_string()],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        // IpAddressChanged
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::IpAddressChanged {
                old_ip: "10.0.0.1".to_string(),
                new_ip: "10.0.0.2".to_string(),
                changed_at: Utc::now(),
            },
            Some(1),
            None,
            None,
        )
        .unwrap();

        // HostnameChanged
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostnameChanged {
                old_hostname: "test.local".to_string(),
                new_hostname: "test2.local".to_string(),
                changed_at: Utc::now(),
            },
            Some(2),
            None,
            None,
        )
        .unwrap();

        // CommentUpdated
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: Some("Initial".to_string()),
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
            Some(3),
            None,
            None,
        )
        .unwrap();

        // TagsModified
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::TagsModified {
                old_tags: vec!["dev".to_string()],
                new_tags: vec!["dev".to_string(), "production".to_string()],
                modified_at: Utc::now(),
            },
            Some(4),
            None,
            None,
        )
        .unwrap();

        // HostDeleted
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostDeleted {
                ip_address: "10.0.0.2".to_string(),
                hostname: "test2.local".to_string(),
                deleted_at: Utc::now(),
                reason: Some("Decommissioned".to_string()),
            },
            Some(5),
            None,
            None,
        )
        .unwrap();

        // Verify all events
        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(events.len(), 6);

        // Verify event types and versions
        assert!(matches!(events[0].event, HostEvent::HostCreated { .. }));
        assert!(matches!(
            events[1].event,
            HostEvent::IpAddressChanged { .. }
        ));
        assert!(matches!(events[2].event, HostEvent::HostnameChanged { .. }));
        assert!(matches!(events[3].event, HostEvent::CommentUpdated { .. }));
        assert!(matches!(events[4].event, HostEvent::TagsModified { .. }));
        assert!(matches!(events[5].event, HostEvent::HostDeleted { .. }));

        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.event_version, (i + 1) as i64);
        }
    }

    #[test]
    fn test_empty_and_null_metadata() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Empty comment and tags
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "192.168.1.1".to_string(),
                hostname: "minimal.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        // Comment cleared (Some -> None)
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: None,
                updated_at: Utc::now(),
            },
            Some(1),
            None,
            None,
        )
        .unwrap();

        // Tags cleared ([] -> [])
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::TagsModified {
                old_tags: vec![],
                new_tags: vec![],
                modified_at: Utc::now(),
            },
            Some(2),
            None,
            None,
        )
        .unwrap();

        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(events.len(), 3);

        if let HostEvent::HostCreated { comment, tags, .. } = &events[0].event {
            assert!(comment.is_none());
            assert!(tags.is_empty());
        } else {
            panic!("Expected HostCreated");
        }
    }

    #[test]
    fn test_unicode_and_special_characters() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.100".to_string(),
            hostname: "unicode-测试-тест.local".to_string(),
            comment: Some("Emoji: 🚀🔥 Special: <>&\"'`".to_string()),
            tags: vec![
                "日本語".to_string(),
                "Русский".to_string(),
                "emoji-🎉".to_string(),
            ],
            created_at: Utc::now(),
        };

        let result = EventStore::append_event(&db, &aggregate_id, event, None, None, None);
        assert!(result.is_ok());

        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        if let HostEvent::HostCreated {
            hostname,
            comment,
            tags,
            ..
        } = &events[0].event
        {
            assert_eq!(hostname, "unicode-测试-тест.local");
            assert!(comment.as_ref().unwrap().contains("🚀"));
            assert_eq!(tags[0], "日本語");
            assert_eq!(tags[2], "emoji-🎉");
        } else {
            panic!("Expected HostCreated");
        }
    }

    #[test]
    fn test_very_long_strings() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        let long_comment = "a".repeat(10000);
        let many_tags: Vec<String> = (0..100).map(|i| format!("tag-{}", i)).collect();

        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "long-data.local".to_string(),
            comment: Some(long_comment.clone()),
            tags: many_tags.clone(),
            created_at: Utc::now(),
        };

        let result = EventStore::append_event(&db, &aggregate_id, event, None, None, None);
        assert!(result.is_ok());

        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        if let HostEvent::HostCreated { comment, tags, .. } = &events[0].event {
            assert_eq!(comment.as_ref().unwrap().len(), 10000);
            assert_eq!(tags.len(), 100);
            assert_eq!(tags[99], "tag-99");
        } else {
            panic!("Expected HostCreated");
        }
    }

    #[test]
    fn test_ipv4_and_ipv6_addresses() {
        let db = Database::in_memory().unwrap();

        // IPv4
        let agg1 = Ulid::new();
        EventStore::append_event(
            &db,
            &agg1,
            HostEvent::HostCreated {
                ip_address: "192.168.1.1".to_string(),
                hostname: "ipv4.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        // IPv6
        let agg2 = Ulid::new();
        EventStore::append_event(
            &db,
            &agg2,
            HostEvent::HostCreated {
                ip_address: "2001:db8::1".to_string(),
                hostname: "ipv6.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        // IPv6 with IPv4 mapping
        let agg3 = Ulid::new();
        EventStore::append_event(
            &db,
            &agg3,
            HostEvent::HostCreated {
                ip_address: "::ffff:192.0.2.1".to_string(),
                hostname: "mapped.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        let events1 = EventStore::load_events(&db, &agg1).unwrap();
        let events2 = EventStore::load_events(&db, &agg2).unwrap();
        let events3 = EventStore::load_events(&db, &agg3).unwrap();

        assert_eq!(events1.len(), 1);
        assert_eq!(events2.len(), 1);
        assert_eq!(events3.len(), 1);
    }

    #[test]
    fn test_created_by_field() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        // With created_by
        let result = EventStore::append_event(
            &db,
            &aggregate_id,
            event.clone(),
            None,
            Some("admin@example.com".to_string()),
            None,
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().created_by,
            Some("admin@example.com".to_string())
        );

        // Without created_by (defaults to None)
        let agg2 = Ulid::new();
        let result2 = EventStore::append_event(&db, &agg2, event, None, None, None);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().created_by, None);
    }

    #[test]
    fn test_multiple_aggregates_isolation() {
        let db = Database::in_memory().unwrap();
        let agg1 = Ulid::new();
        let agg2 = Ulid::new();

        // Add events to first aggregate
        EventStore::append_event(
            &db,
            &agg1,
            HostEvent::HostCreated {
                ip_address: "192.168.1.1".to_string(),
                hostname: "host1.local".to_string(),
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
            &agg1,
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

        // Add events to second aggregate
        EventStore::append_event(
            &db,
            &agg2,
            HostEvent::HostCreated {
                ip_address: "192.168.1.2".to_string(),
                hostname: "host2.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        // Verify isolation
        let events1 = EventStore::load_events(&db, &agg1).unwrap();
        let events2 = EventStore::load_events(&db, &agg2).unwrap();

        assert_eq!(events1.len(), 2);
        assert_eq!(events2.len(), 1);
        assert_eq!(EventStore::count_events(&db, &agg1).unwrap(), 2);
        assert_eq!(EventStore::count_events(&db, &agg2).unwrap(), 1);
    }

    #[test]
    fn test_load_events_empty_aggregate() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn test_event_versioning_sequence() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Add 10 events
        for i in 0..10 {
            let expected_version = if i == 0 { None } else { Some(i) };
            EventStore::append_event(
                &db,
                &aggregate_id,
                HostEvent::CommentUpdated {
                    old_comment: None,
                    new_comment: Some(format!("Version {}", i + 1)),
                    updated_at: Utc::now(),
                },
                expected_version,
                None,
                None,
            )
            .unwrap();
        }

        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(events.len(), 10);

        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.event_version, (i + 1) as i64);
        }
    }

    #[test]
    fn test_concurrent_write_with_same_expected_version() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // First event
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "192.168.1.1".to_string(),
                hostname: "test.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
            None,
        )
        .unwrap();

        // Second event with correct version
        let result = EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("First".to_string()),
                updated_at: Utc::now(),
            },
            Some(1),
            None,
            None,
        );
        assert!(result.is_ok());

        // Try to append another event with the same expected version (should fail)
        let result2 = EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("Second".to_string()),
                updated_at: Utc::now(),
            },
            Some(1), // Same expected version - conflict!
            None,
            None,
        );
        assert!(result2.is_err());
        assert!(matches!(
            result2.unwrap_err(),
            DatabaseError::ConcurrentWriteConflict(_)
        ));
    }
}
