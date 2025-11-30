use super::event_store::EventStore;
use super::events::{EventEnvelope, HostEvent};
use super::schema::{Database, DatabaseError, DatabaseResult};
use chrono::{DateTime, Utc};
use duckdb::OptionalExt;
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
    pub version: i64,
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
    /// This queries the materialized view for efficient access.
    pub fn list_all(db: &Database) -> DatabaseResult<Vec<HostEntry>> {
        let mut stmt = db
            .conn()
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
                let id_str: String = row.get(0)?;
                let ip_address: String = row.get(1)?;
                let hostname: String = row.get(2)?;
                let comment: Option<String> = row.get(3)?;
                let tags_json: String = row.get(4)?;
                // DuckDB returns TIMESTAMP as i64 microseconds since epoch
                let created_at_micros: i64 = row.get(5)?;
                let updated_at_micros: i64 = row.get(6)?;
                let version: i64 = row.get(7)?;

                Ok((
                    id_str,
                    ip_address,
                    hostname,
                    comment,
                    tags_json,
                    created_at_micros,
                    updated_at_micros,
                    version,
                ))
            })
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to query hosts: {}", e)))?;

        let mut entries = Vec::new();
        for row in rows {
            let (
                id_str,
                ip_address,
                hostname,
                comment,
                tags_json,
                created_at_micros,
                updated_at_micros,
                version,
            ) =
                row.map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;

            let id = Ulid::from_string(&id_str)
                .map_err(|e| DatabaseError::InvalidData(format!("Invalid UUID: {}", e)))?;

            let tags: Vec<String> = serde_json::from_str(&tags_json)
                .map_err(|e| DatabaseError::InvalidData(format!("Failed to parse tags: {}", e)))?;

            // Convert DuckDB timestamp (microseconds since epoch) to DateTime<Utc>
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
    pub fn search(db: &Database, pattern: &str) -> DatabaseResult<Vec<HostEntry>> {
        let search_pattern = format!("%{}%", pattern);

        let mut stmt = db
            .conn()
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
                WHERE ip_address LIKE ? OR hostname LIKE ?
                ORDER BY ip_address, hostname
                "#,
            )
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to prepare search query: {}", e))
            })?;

        let rows = stmt
            .query_map([&search_pattern, &search_pattern], |row| {
                let id_str: String = row.get(0)?;
                let ip_address: String = row.get(1)?;
                let hostname: String = row.get(2)?;
                let comment: Option<String> = row.get(3)?;
                let tags_json: String = row.get(4)?;
                let created_at_micros: i64 = row.get(5)?;
                let updated_at_micros: i64 = row.get(6)?;
                let version: i64 = row.get(7)?;

                Ok((
                    id_str,
                    ip_address,
                    hostname,
                    comment,
                    tags_json,
                    created_at_micros,
                    updated_at_micros,
                    version,
                ))
            })
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to execute search: {}", e)))?;

        let mut entries = Vec::new();
        for row in rows {
            let (
                id_str,
                ip_address,
                hostname,
                comment,
                tags_json,
                created_at_micros,
                updated_at_micros,
                version,
            ) =
                row.map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;

            let id = Ulid::from_string(&id_str)
                .map_err(|e| DatabaseError::InvalidData(format!("Invalid UUID: {}", e)))?;

            let tags: Vec<String> = serde_json::from_str(&tags_json)
                .map_err(|e| DatabaseError::InvalidData(format!("Failed to parse tags: {}", e)))?;

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

    /// Find host by exact IP and hostname match
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
                    let comment: Option<String> = row.get(3)?;
                    let tags_json: String = row.get(4)?;
                    let created_at_micros: i64 = row.get(5)?;
                    let updated_at_micros: i64 = row.get(6)?;
                    let version: i64 = row.get(7)?;

                    Ok((
                        id_str,
                        ip_address,
                        hostname,
                        comment,
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
                comment,
                tags_json,
                created_at_micros,
                updated_at_micros,
                version,
            )) => {
                let id = Ulid::from_string(&id_str)
                    .map_err(|e| DatabaseError::InvalidData(format!("Invalid UUID: {}", e)))?;

                let tags: Vec<String> = serde_json::from_str(&tags_json).map_err(|e| {
                    DatabaseError::InvalidData(format!("Failed to parse tags: {}", e))
                })?;

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
                        version: envelope.event_version,
                    });
                }
                HostEvent::IpAddressChanged { new_ip, .. } => {
                    if let Some(ref mut entry) = state {
                        entry.ip_address = new_ip.clone();
                        entry.updated_at = envelope.created_at;
                        entry.version = envelope.event_version;
                    }
                }
                HostEvent::HostnameChanged { new_hostname, .. } => {
                    if let Some(ref mut entry) = state {
                        entry.hostname = new_hostname.clone();
                        entry.updated_at = envelope.created_at;
                        entry.version = envelope.event_version;
                    }
                }
                HostEvent::CommentUpdated { new_comment, .. } => {
                    if let Some(ref mut entry) = state {
                        entry.comment = new_comment.clone();
                        entry.updated_at = envelope.created_at;
                        entry.version = envelope.event_version;
                    }
                }
                HostEvent::TagsModified { new_tags, .. } => {
                    if let Some(ref mut entry) = state {
                        entry.tags = new_tags.clone();
                        entry.updated_at = envelope.created_at;
                        entry.version = envelope.event_version;
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
        let mut stmt = db
            .conn()
            .prepare(
                r#"
                SELECT
                    event_id,
                    aggregate_id,
                    event_type,
                    event_version,
                    event_data,
                    event_metadata,
                    created_at,
                    created_by
                FROM host_events
                WHERE aggregate_id = ? AND created_at <= ?
                ORDER BY event_version ASC
                "#,
            )
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to prepare time travel query: {}", e))
            })?;

        // Convert timestamp to microseconds for DuckDB comparison
        let at_time_micros = at_time.timestamp_micros();

        let rows = stmt
            .query_map([&id.to_string(), &at_time_micros.to_string()], |row| {
                let event_id_str: String = row.get(0)?;
                let aggregate_id_str: String = row.get(1)?;
                let _event_type: String = row.get(2)?;
                let event_version: i64 = row.get(3)?;
                let event_data: String = row.get(4)?;
                let metadata_json: String = row.get(5)?;
                let created_at_micros: i64 = row.get(6)?;
                let created_by: String = row.get(7)?;

                Ok((
                    event_id_str,
                    aggregate_id_str,
                    event_version,
                    event_data,
                    metadata_json,
                    created_at_micros,
                    created_by,
                ))
            })
            .map_err(|e| DatabaseError::QueryFailed(format!("Failed to query events: {}", e)))?;

        let mut envelopes = Vec::new();
        for row in rows {
            let (
                event_id_str,
                aggregate_id_str,
                event_version,
                event_data,
                metadata_json,
                created_at_micros,
                created_by,
            ) =
                row.map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;

            let event_id = Ulid::from_string(&event_id_str)
                .map_err(|e| DatabaseError::InvalidData(format!("Invalid event_id UUID: {}", e)))?;

            let agg_id = Ulid::from_string(&aggregate_id_str).map_err(|e| {
                DatabaseError::InvalidData(format!("Invalid aggregate_id UUID: {}", e))
            })?;

            let event: HostEvent = serde_json::from_str(&event_data).map_err(|e| {
                DatabaseError::InvalidData(format!("Failed to deserialize event: {}", e))
            })?;

            let metadata = if metadata_json == "null" || metadata_json.is_empty() {
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

        Self::rebuild_from_events(&envelopes)
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
                event_version: 1,
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
                event_version: 2,
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
        assert_eq!(entry.version, 2);
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
                event_version: 1,
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
                event_version: 2,
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
}
