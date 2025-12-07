use super::event_store::EventStore;
use super::events::{EventData, EventEnvelope, HostEvent};
use super::schema::{Database, DatabaseError, DatabaseResult};
use chrono::{DateTime, Utc};
use duckdb::OptionalExt;
use router_hosts_common::proto;
use ulid::Ulid;

/// Read model for current host entries (CQRS Query side)
///
/// This struct provides query methods that read from materialized views
/// built from the event log. All queries are eventually consistent with
/// the event stream.
#[derive(Debug, Clone, PartialEq)]
pub struct HostEntry {
    pub id: Ulid,
    pub ip_address: String,
    pub hostname: String,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: String,
}

/// Repository for querying host projections
pub struct HostProjections;

impl HostProjections {
    /// Get current state of a host entry by aggregate ID
    ///
    /// This rebuilds the current state by replaying all events for the aggregate.
    /// Returns `None` if the host doesn't exist or has been deleted.
    pub fn get_by_id(db: &Database, id: &Ulid) -> DatabaseResult<Option<HostEntry>> {
        let events = EventStore::load_events(db, id)?;

        if events.is_empty() {
            return Ok(None);
        }

        Self::rebuild_from_events(&events)
    }

    /// List all active host entries
    ///
    /// Uses the `host_entries_current` materialized view for O(n) performance
    /// instead of N+1 queries. The view is automatically maintained by DuckDB.
    ///
    /// FIX #35: View now uses LAST_VALUE(... IGNORE NULLS) for comment and tags
    /// columns, ensuring partial updates are properly merged.
    pub fn list_all(db: &Database) -> DatabaseResult<Vec<HostEntry>> {
        let conn = db.conn();
        let mut stmt = conn
            .prepare(
                r#"
                SELECT
                    id,
                    ip_address,
                    hostname,
                    comment,
                    tags,
                    created_at,
                    updated_at,
                    event_version
                FROM host_entries_current
                ORDER BY ip_address, hostname
                "#,
            )
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to prepare list query: {}", e))
            })?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,         // id
                    row.get::<_, String>(1)?,         // ip_address
                    row.get::<_, String>(2)?,         // hostname
                    row.get::<_, Option<String>>(3)?, // comment (nullable)
                    row.get::<_, Option<String>>(4)?, // tags (JSON array, nullable)
                    row.get::<_, i64>(5)?,            // created_at
                    row.get::<_, i64>(6)?,            // updated_at
                    row.get::<_, String>(7)?,         // event_version
                ))
            })
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to query host entries: {}", e))
            })?;

        let mut entries = Vec::new();
        for row_result in rows {
            let (
                id_str,
                ip_address,
                hostname,
                comment_str,
                tags_json,
                created_at_micros,
                updated_at_micros,
                version,
            ) = row_result
                .map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;

            let id = Ulid::from_string(&id_str)
                .map_err(|e| DatabaseError::InvalidData(format!("Invalid ULID: {}", e)))?;

            // Parse comment: empty string means no comment
            let comment = comment_str.filter(|s| !s.is_empty());

            // Parse tags from JSON array
            let tags: Vec<String> = tags_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            let created_at =
                DateTime::from_timestamp_micros(created_at_micros).ok_or_else(|| {
                    DatabaseError::InvalidData(format!(
                        "Invalid created_at timestamp: {}",
                        created_at_micros
                    ))
                })?;

            let updated_at =
                DateTime::from_timestamp_micros(updated_at_micros).ok_or_else(|| {
                    DatabaseError::InvalidData(format!(
                        "Invalid updated_at timestamp: {}",
                        updated_at_micros
                    ))
                })?;

            entries.push(HostEntry {
                id,
                ip_address,
                hostname,
                comment,
                tags,
                created_at,
                updated_at,
                version,
            });
        }

        Ok(entries)
    }

    /// Search hosts by IP address or hostname pattern
    ///
    /// This rebuilds state from events and filters in memory.
    pub fn search(db: &Database, pattern: &str) -> DatabaseResult<Vec<HostEntry>> {
        let all_entries = Self::list_all(db)?;
        let pattern_lower = pattern.to_lowercase();

        let filtered: Vec<HostEntry> = all_entries
            .into_iter()
            .filter(|entry| {
                entry.ip_address.to_lowercase().contains(&pattern_lower)
                    || entry.hostname.to_lowercase().contains(&pattern_lower)
            })
            .collect();

        Ok(filtered)
    }

    /// Find host by exact IP and hostname match
    ///
    /// FIX #35: Uses new view columns for comment and tags.
    pub fn find_by_ip_and_hostname(
        db: &Database,
        ip_address: &str,
        hostname: &str,
    ) -> DatabaseResult<Option<HostEntry>> {
        let result = db
            .conn()
            .query_row(
                r#"
                SELECT
                    id,
                    ip_address,
                    hostname,
                    comment,
                    tags,
                    created_at,
                    updated_at,
                    event_version
                FROM host_entries_current
                WHERE ip_address = ? AND hostname = ?
                "#,
                [ip_address, hostname],
                |row| {
                    let id_str: String = row.get(0)?;
                    let ip_address: String = row.get(1)?;
                    let hostname: String = row.get(2)?;
                    let comment_str: Option<String> = row.get(3)?;
                    let tags_json: Option<String> = row.get(4)?;
                    let created_at_micros: i64 = row.get(5)?;
                    let updated_at_micros: i64 = row.get(6)?;
                    let version: String = row.get(7)?;

                    Ok((
                        id_str,
                        ip_address,
                        hostname,
                        comment_str,
                        tags_json,
                        created_at_micros,
                        updated_at_micros,
                        version,
                    ))
                },
            )
            .optional()
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to find host: {}", e)))?;

        match result {
            None => Ok(None),
            Some((
                id_str,
                ip_address,
                hostname,
                comment_str,
                tags_json,
                created_at_micros,
                updated_at_micros,
                version,
            )) => {
                let id = Ulid::from_string(&id_str)
                    .map_err(|e| DatabaseError::InvalidData(format!("Invalid UUID: {}", e)))?;

                // Parse comment: empty string means no comment
                let comment = comment_str.filter(|s| !s.is_empty());

                // Parse tags from JSON array
                let tags: Vec<String> = tags_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();

                let created_at =
                    DateTime::from_timestamp_micros(created_at_micros).ok_or_else(|| {
                        DatabaseError::InvalidData(format!(
                            "Invalid created_at timestamp: {}",
                            created_at_micros
                        ))
                    })?;

                let updated_at =
                    DateTime::from_timestamp_micros(updated_at_micros).ok_or_else(|| {
                        DatabaseError::InvalidData(format!(
                            "Invalid updated_at timestamp: {}",
                            updated_at_micros
                        ))
                    })?;

                Ok(Some(HostEntry {
                    id,
                    ip_address,
                    hostname,
                    comment,
                    tags,
                    created_at,
                    updated_at,
                    version,
                }))
            }
        }
    }

    /// Rebuild aggregate state from event stream
    ///
    /// This is the core projection logic that applies events sequentially
    /// to build the current state.
    fn rebuild_from_events(events: &[EventEnvelope]) -> DatabaseResult<Option<HostEntry>> {
        if events.is_empty() {
            return Ok(None);
        }

        let mut state: Option<HostEntry> = None;

        for envelope in events {
            match &envelope.event {
                HostEvent::HostCreated {
                    ip_address,
                    hostname,
                    comment,
                    tags,
                    created_at,
                } => {
                    state = Some(HostEntry {
                        id: envelope.aggregate_id,
                        ip_address: ip_address.clone(),
                        hostname: hostname.clone(),
                        comment: comment.clone(),
                        tags: tags.clone(),
                        created_at: *created_at,
                        updated_at: envelope.created_at,
                        version: envelope.event_version.clone(),
                    });
                }
                HostEvent::IpAddressChanged { new_ip, .. } => {
                    if let Some(ref mut entry) = state {
                        entry.ip_address = new_ip.clone();
                        entry.updated_at = envelope.created_at;
                        entry.version = envelope.event_version.clone();
                    }
                }
                HostEvent::HostnameChanged { new_hostname, .. } => {
                    if let Some(ref mut entry) = state {
                        entry.hostname = new_hostname.clone();
                        entry.updated_at = envelope.created_at;
                        entry.version = envelope.event_version.clone();
                    }
                }
                HostEvent::CommentUpdated { new_comment, .. } => {
                    if let Some(ref mut entry) = state {
                        entry.comment = new_comment.clone();
                        entry.updated_at = envelope.created_at;
                        entry.version = envelope.event_version.clone();
                    }
                }
                HostEvent::TagsModified { new_tags, .. } => {
                    if let Some(ref mut entry) = state {
                        entry.tags = new_tags.clone();
                        entry.updated_at = envelope.created_at;
                        entry.version = envelope.event_version.clone();
                    }
                }
                HostEvent::HostDeleted { .. } => {
                    // Deleted hosts should not appear in current state
                    state = None;
                }
            }
        }

        Ok(state)
    }

    /// Get historical state of a host at a specific point in time
    ///
    /// Replays events up to the given timestamp to reconstruct past state.
    pub fn get_at_time(
        db: &Database,
        id: &Ulid,
        at_time: DateTime<Utc>,
    ) -> DatabaseResult<Option<HostEntry>> {
        let conn = db.conn();
        let mut stmt = conn.prepare(
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
                WHERE aggregate_id = ? AND CAST(EXTRACT(EPOCH FROM created_at) * 1000000 AS BIGINT) <= ?
                ORDER BY event_version ASC
                "#,
            )
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to prepare time travel query: {}", e))
            })?;

        let at_time_micros = at_time.timestamp_micros();

        let rows = stmt
            .query_map(
                [
                    &id.to_string() as &dyn duckdb::ToSql,
                    &at_time_micros as &dyn duckdb::ToSql,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,         // event_id
                        row.get::<_, String>(1)?,         // aggregate_id
                        row.get::<_, String>(2)?,         // event_type
                        row.get::<_, String>(3)?,         // event_version
                        row.get::<_, Option<String>>(4)?, // ip_address
                        row.get::<_, Option<String>>(5)?, // hostname
                        row.get::<_, String>(6)?,         // metadata
                        row.get::<_, i64>(7)?,            // event_timestamp
                        row.get::<_, i64>(8)?,            // created_at
                        row.get::<_, String>(9)?,         // created_by
                    ))
                },
            )
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to query events: {}", e)))?;

        // Reuse the same event reconstruction logic as load_events
        let mut envelopes = Vec::new();
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
                .map_err(|e| DatabaseError::InvalidData(format!("Invalid event_id ULID: {}", e)))?;

            let agg_id = Ulid::from_string(&aggregate_id_str).map_err(|e| {
                DatabaseError::InvalidData(format!("Invalid aggregate_id ULID: {}", e))
            })?;

            let event_timestamp = DateTime::from_timestamp_micros(event_timestamp_micros)
                .ok_or_else(|| {
                    DatabaseError::InvalidData(format!(
                        "Invalid event timestamp: {}",
                        event_timestamp_micros
                    ))
                })?;

            use super::events::EventData;
            let event_data: EventData = serde_json::from_str(&metadata_json).map_err(|e| {
                DatabaseError::InvalidData(format!("Failed to deserialize event metadata: {}", e))
            })?;

            let event = match event_type.as_str() {
                "HostCreated" => {
                    let ip = ip_address.ok_or_else(|| {
                        DatabaseError::InvalidData("HostCreated missing ip_address".to_string())
                    })?;
                    let host = hostname.ok_or_else(|| {
                        DatabaseError::InvalidData("HostCreated missing hostname".to_string())
                    })?;
                    HostEvent::HostCreated {
                        ip_address: ip,
                        hostname: host,
                        comment: event_data.comment.clone(),
                        tags: event_data.tags.clone().unwrap_or_default(),
                        created_at: event_timestamp,
                    }
                }
                "IpAddressChanged" => {
                    let new_ip = ip_address.ok_or_else(|| {
                        DatabaseError::InvalidData(
                            "IpAddressChanged missing ip_address".to_string(),
                        )
                    })?;
                    let old_ip = event_data.previous_ip.clone().ok_or_else(|| {
                        DatabaseError::InvalidData(
                            "IpAddressChanged missing previous_ip".to_string(),
                        )
                    })?;
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
                    let old_hostname = event_data.previous_hostname.clone().ok_or_else(|| {
                        DatabaseError::InvalidData(
                            "HostnameChanged missing previous_hostname".to_string(),
                        )
                    })?;
                    HostEvent::HostnameChanged {
                        old_hostname,
                        new_hostname,
                        changed_at: event_timestamp,
                    }
                }
                "CommentUpdated" => HostEvent::CommentUpdated {
                    old_comment: event_data.previous_comment.clone(),
                    new_comment: event_data.comment.clone(),
                    updated_at: event_timestamp,
                },
                "TagsModified" => HostEvent::TagsModified {
                    old_tags: event_data.previous_tags.clone().unwrap_or_default(),
                    new_tags: event_data.tags.clone().unwrap_or_default(),
                    modified_at: event_timestamp,
                },
                "HostDeleted" => HostEvent::HostDeleted {
                    ip_address: ip_address.ok_or_else(|| {
                        DatabaseError::InvalidData("HostDeleted missing ip_address".to_string())
                    })?,
                    hostname: hostname.ok_or_else(|| {
                        DatabaseError::InvalidData("HostDeleted missing hostname".to_string())
                    })?,
                    deleted_at: event_timestamp,
                    reason: event_data.deleted_reason.clone(),
                },
                _ => {
                    return Err(DatabaseError::InvalidData(format!(
                        "Unknown event type: {}",
                        event_type
                    )))
                }
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
                metadata: None,
            });
        }

        Self::rebuild_from_events(&envelopes)
    }
}

/// Convert database HostEntry to protobuf HostEntry
impl From<HostEntry> for proto::HostEntry {
    fn from(entry: HostEntry) -> Self {
        proto::HostEntry {
            id: entry.id.to_string(),
            ip_address: entry.ip_address,
            hostname: entry.hostname,
            comment: entry.comment,
            tags: entry.tags,
            created_at: Some(prost_types::Timestamp {
                seconds: entry.created_at.timestamp(),
                nanos: entry.created_at.timestamp_subsec_nanos() as i32,
            }),
            updated_at: Some(prost_types::Timestamp {
                seconds: entry.updated_at.timestamp(),
                nanos: entry.updated_at.timestamp_subsec_nanos() as i32,
            }),
            version: entry.version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rebuild_from_events() {
        let aggregate_id = Ulid::new();
        let now = Utc::now();

        let events = vec![
            EventEnvelope {
                event_id: Ulid::new(),
                aggregate_id,
                event: HostEvent::HostCreated {
                    ip_address: "192.168.1.10".to_string(),
                    hostname: "server.local".to_string(),
                    comment: None,
                    tags: vec![],
                    created_at: now,
                },
                event_version: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
                created_at: now,
                created_by: None,
                metadata: None,
            },
            EventEnvelope {
                event_id: Ulid::new(),
                aggregate_id,
                event: HostEvent::CommentUpdated {
                    old_comment: None,
                    new_comment: Some("Test server".to_string()),
                    updated_at: now,
                },
                event_version: "01ARZ3NDEKTSV4RRFFQ69G5FAQ".to_string(),
                created_at: now,
                created_by: None,
                metadata: None,
            },
        ];

        let result = HostProjections::rebuild_from_events(&events).unwrap();
        assert!(result.is_some());

        let entry = result.unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, Some("Test server".to_string()));
        assert_eq!(entry.version, "01ARZ3NDEKTSV4RRFFQ69G5FAQ");
    }

    #[test]
    fn test_rebuild_deleted_host() {
        let aggregate_id = Ulid::new();
        let now = Utc::now();

        let events = vec![
            EventEnvelope {
                event_id: Ulid::new(),
                aggregate_id,
                event: HostEvent::HostCreated {
                    ip_address: "192.168.1.10".to_string(),
                    hostname: "server.local".to_string(),
                    comment: None,
                    tags: vec![],
                    created_at: now,
                },
                event_version: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
                created_at: now,
                created_by: None,
                metadata: None,
            },
            EventEnvelope {
                event_id: Ulid::new(),
                aggregate_id,
                event: HostEvent::HostDeleted {
                    ip_address: "192.168.1.10".to_string(),
                    hostname: "server.local".to_string(),
                    deleted_at: now,
                    reason: None,
                },
                event_version: "01ARZ3NDEKTSV4RRFFQ69G5FAQ".to_string(),
                created_at: now,
                created_by: None,
                metadata: None,
            },
        ];

        let result = HostProjections::rebuild_from_events(&events).unwrap();
        assert!(
            result.is_none(),
            "Deleted host should not have current state"
        );
    }

    #[test]
    fn test_get_by_id() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Create a host
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
        )
        .unwrap();

        // Retrieve via projection
        let result = HostProjections::get_by_id(&db, &aggregate_id).unwrap();
        assert!(result.is_some());

        let entry = result.unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
    }

    #[test]
    fn test_find_by_ip_and_hostname() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Create a host
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
        )
        .unwrap();

        // Find by IP and hostname
        let result =
            HostProjections::find_by_ip_and_hostname(&db, "192.168.1.10", "server.local").unwrap();
        assert!(result.is_some());

        let entry = result.unwrap();
        assert_eq!(entry.id, aggregate_id);
    }

    #[test]
    fn test_list_all() {
        let db = Database::in_memory().unwrap();

        // Create multiple hosts
        for i in 1..=3 {
            EventStore::append_event(
                &db,
                &Ulid::new(),
                HostEvent::HostCreated {
                    ip_address: format!("192.168.1.{}", i + 10),
                    hostname: format!("server{}.local", i),
                    comment: None,
                    tags: vec![],
                    created_at: Utc::now(),
                },
                None,
                None,
            )
            .unwrap();
        }

        let entries = HostProjections::list_all(&db).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_search() {
        let db = Database::in_memory().unwrap();

        EventStore::append_event(
            &db,
            &Ulid::new(),
            HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
        )
        .unwrap();

        EventStore::append_event(
            &db,
            &Ulid::new(),
            HostEvent::HostCreated {
                ip_address: "192.168.1.20".to_string(),
                hostname: "nas.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
        )
        .unwrap();

        // Search by IP pattern
        let results = HostProjections::search(&db, "192.168.1.1").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hostname, "server.local");

        // Search by hostname pattern
        let results = HostProjections::search(&db, "nas").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hostname, "nas.local");
    }

    #[test]
    fn test_get_at_time() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();
        let t0 = Utc::now();

        // Create host
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "192.168.1.1".to_string(),
                hostname: "original.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: t0,
            },
            None,
            None,
        )
        .unwrap();

        // Get the version from the first event
        let first_version = HostProjections::get_by_id(&db, &aggregate_id)
            .unwrap()
            .unwrap()
            .version;

        // Capture time after first event but before second event
        std::thread::sleep(std::time::Duration::from_millis(10));
        let between_time = Utc::now();

        // Small delay before second event
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Update hostname
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostnameChanged {
                old_hostname: "original.local".to_string(),
                new_hostname: "updated.local".to_string(),
                changed_at: Utc::now(),
            },
            Some(first_version),
            None,
        )
        .unwrap();

        // Query at time between the two events - should see original hostname
        let state_at_t0 = HostProjections::get_at_time(&db, &aggregate_id, between_time).unwrap();
        assert!(
            state_at_t0.is_some(),
            "Expected to find host state at time between creation and update"
        );
        assert_eq!(state_at_t0.unwrap().hostname, "original.local");

        // Query at current time - should see updated hostname
        let state_now = HostProjections::get_at_time(&db, &aggregate_id, Utc::now()).unwrap();
        assert!(state_now.is_some());
        assert_eq!(state_now.unwrap().hostname, "updated.local");
    }

    /// Regression test for issue #35: SQL view doesn't properly merge partial metadata updates
    ///
    /// This test verifies that updating only comment doesn't lose tags, and vice versa.
    /// Previously, the view used LAST_VALUE(metadata) which took the entire metadata JSON
    /// from the last event, losing fields that weren't updated.
    #[test]
    fn test_list_all_preserves_metadata_after_partial_update_issue_35() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Create host with comment and tags
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "192.168.1.1".to_string(),
                hostname: "test.local".to_string(),
                comment: Some("Initial comment".to_string()),
                tags: vec!["production".to_string(), "critical".to_string()],
                created_at: Utc::now(),
            },
            None,
            None,
        )
        .unwrap();

        // Verify initial state via list_all
        let entries = HostProjections::list_all(&db).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, Some("Initial comment".to_string()));
        assert_eq!(
            entries[0].tags,
            vec!["production".to_string(), "critical".to_string()]
        );
        let version_after_create = entries[0].version.clone();

        // Update ONLY the comment (not tags)
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: Some("Initial comment".to_string()),
                new_comment: Some("Updated comment".to_string()),
                updated_at: Utc::now(),
            },
            Some(version_after_create),
            None,
        )
        .unwrap();

        // CRITICAL: list_all should preserve tags after comment-only update
        // This was the bug in issue #35 - LAST_VALUE(metadata) lost the tags
        let entries = HostProjections::list_all(&db).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].comment,
            Some("Updated comment".to_string()),
            "Comment should be updated"
        );
        assert_eq!(
            entries[0].tags,
            vec!["production".to_string(), "critical".to_string()],
            "REGRESSION #35: Tags lost after comment-only update!"
        );
        let version_after_comment_update = entries[0].version.clone();

        // Now update ONLY the tags (not comment)
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::TagsModified {
                old_tags: vec!["production".to_string(), "critical".to_string()],
                new_tags: vec!["staging".to_string()],
                modified_at: Utc::now(),
            },
            Some(version_after_comment_update),
            None,
        )
        .unwrap();

        // CRITICAL: list_all should preserve comment after tags-only update
        let entries = HostProjections::list_all(&db).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].comment,
            Some("Updated comment".to_string()),
            "REGRESSION #35: Comment lost after tags-only update!"
        );
        assert_eq!(
            entries[0].tags,
            vec!["staging".to_string()],
            "Tags should be updated"
        );

        // Also verify find_by_ip_and_hostname works correctly
        let entry =
            HostProjections::find_by_ip_and_hostname(&db, "192.168.1.1", "test.local").unwrap();
        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.comment, Some("Updated comment".to_string()));
        assert_eq!(entry.tags, vec!["staging".to_string()]);
    }

    /// Test clearing comment and tags works correctly
    #[test]
    fn test_list_all_handles_cleared_metadata() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Create host with comment and tags
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "192.168.1.2".to_string(),
                hostname: "test2.local".to_string(),
                comment: Some("Has comment".to_string()),
                tags: vec!["tagged".to_string()],
                created_at: Utc::now(),
            },
            None,
            None,
        )
        .unwrap();

        // Get version after create
        let version_after_create = HostProjections::get_by_id(&db, &aggregate_id)
            .unwrap()
            .unwrap()
            .version;

        // Clear comment (set to None)
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: Some("Has comment".to_string()),
                new_comment: None,
                updated_at: Utc::now(),
            },
            Some(version_after_create),
            None,
        )
        .unwrap();

        let entries = HostProjections::list_all(&db).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, None, "Comment should be cleared");
        assert_eq!(
            entries[0].tags,
            vec!["tagged".to_string()],
            "Tags should be preserved"
        );
        let version_after_comment_clear = entries[0].version.clone();

        // Clear tags
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::TagsModified {
                old_tags: vec!["tagged".to_string()],
                new_tags: vec![],
                modified_at: Utc::now(),
            },
            Some(version_after_comment_clear),
            None,
        )
        .unwrap();

        let entries = HostProjections::list_all(&db).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, None, "Comment should remain cleared");
        assert!(entries[0].tags.is_empty(), "Tags should be cleared");
    }
}
