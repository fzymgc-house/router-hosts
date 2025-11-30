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
    /// For large datasets, prefer [`list_paginated`](Self::list_paginated) to avoid
    /// loading all entries into memory.
    pub fn list_all(db: &Database) -> DatabaseResult<Vec<HostEntry>> {
        Self::list_paginated(db, None, None)
    }

    /// List active host entries with pagination
    ///
    /// # Arguments
    ///
    /// * `db` - Database connection
    /// * `limit` - Maximum number of entries to return (None = unlimited)
    /// * `offset` - Number of entries to skip (None = start from beginning)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Get first 100 entries
    /// let page1 = HostProjections::list_paginated(&db, Some(100), None)?;
    ///
    /// // Get next 100 entries
    /// let page2 = HostProjections::list_paginated(&db, Some(100), Some(100))?;
    /// ```
    pub fn list_paginated(
        db: &Database,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> DatabaseResult<Vec<HostEntry>> {
        // Build query with optional LIMIT/OFFSET
        let query = match (limit, offset) {
            (Some(l), Some(o)) => format!(
                r#"
                SELECT id, ip_address, hostname, comment, tags, created_at, updated_at, event_version
                FROM host_entries_current
                ORDER BY ip_address, hostname
                LIMIT {} OFFSET {}
                "#,
                l, o
            ),
            (Some(l), None) => format!(
                r#"
                SELECT id, ip_address, hostname, comment, tags, created_at, updated_at, event_version
                FROM host_entries_current
                ORDER BY ip_address, hostname
                LIMIT {}
                "#,
                l
            ),
            (None, Some(o)) => format!(
                r#"
                SELECT id, ip_address, hostname, comment, tags, created_at, updated_at, event_version
                FROM host_entries_current
                ORDER BY ip_address, hostname
                OFFSET {}
                "#,
                o
            ),
            (None, None) => r#"
                SELECT id, ip_address, hostname, comment, tags, created_at, updated_at, event_version
                FROM host_entries_current
                ORDER BY ip_address, hostname
                "#
            .to_string(),
        };

        let mut stmt = db.conn().prepare(&query).map_err(|e| {
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
        use super::events::EventData;

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
                WHERE aggregate_id = ? AND created_at <= make_timestamp(?)
                ORDER BY event_version ASC
                "#,
            )
            .map_err(|e| {
                DatabaseError::QueryFailed(format!("Failed to prepare time travel query: {}", e))
            })?;

        // Convert timestamp to microseconds for DuckDB comparison
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
                        row.get::<_, i64>(3)?,            // event_version
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

            // Reconstruct the event from typed columns + metadata
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
                    let old_ip = event_data.previous_ip.ok_or_else(|| {
                        DatabaseError::InvalidData(
                            "IpAddressChanged missing previous_ip in metadata".to_string(),
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
                    let old_hostname = event_data.previous_hostname.ok_or_else(|| {
                        DatabaseError::InvalidData(
                            "HostnameChanged missing previous_hostname in metadata".to_string(),
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

    #[test]
    fn test_list_paginated() {
        let db = Database::in_memory().unwrap();

        // Create 5 hosts
        for i in 1..=5 {
            EventStore::append_event(
                &db,
                &Ulid::new(),
                HostEvent::HostCreated {
                    ip_address: format!("192.168.1.{}", i),
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

        // Test limit only
        let page1 = HostProjections::list_paginated(&db, Some(2), None).unwrap();
        assert_eq!(page1.len(), 2);

        // Test limit and offset
        let page2 = HostProjections::list_paginated(&db, Some(2), Some(2)).unwrap();
        assert_eq!(page2.len(), 2);

        // Test offset beyond data
        let empty = HostProjections::list_paginated(&db, Some(10), Some(100)).unwrap();
        assert_eq!(empty.len(), 0);

        // Test no limit (should get all)
        let all = HostProjections::list_paginated(&db, None, None).unwrap();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn test_get_at_time() {
        use std::thread::sleep;
        use std::time::Duration;

        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Create a host
        let created_time = Utc::now();
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                comment: Some("Initial".to_string()),
                tags: vec!["prod".to_string()],
                created_at: created_time,
            },
            None,
            None,
            None,
        )
        .unwrap();

        // Small delay to ensure time difference
        sleep(Duration::from_millis(10));
        let after_create = Utc::now();

        // Modify the host
        sleep(Duration::from_millis(10));
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: Some("Initial".to_string()),
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
            Some(1),
            None,
            None,
        )
        .unwrap();

        // Query at time after creation but before update
        let entry_at_create = HostProjections::get_at_time(&db, &aggregate_id, after_create)
            .unwrap()
            .expect("Should find entry");
        assert_eq!(entry_at_create.comment, Some("Initial".to_string()));
        assert_eq!(entry_at_create.version, 1);

        // Query at current time (after update)
        let entry_now = HostProjections::get_at_time(&db, &aggregate_id, Utc::now())
            .unwrap()
            .expect("Should find entry");
        assert_eq!(entry_now.comment, Some("Updated".to_string()));
        assert_eq!(entry_now.version, 2);
    }

    #[test]
    fn test_get_at_time_deleted_host() {
        use std::thread::sleep;
        use std::time::Duration;

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

        sleep(Duration::from_millis(10));
        let before_delete = Utc::now();

        // Delete the host
        sleep(Duration::from_millis(10));
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostDeleted {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                deleted_at: Utc::now(),
                reason: Some("Decommissioned".to_string()),
            },
            Some(1),
            None,
            None,
        )
        .unwrap();

        // Query before deletion - should exist
        let before = HostProjections::get_at_time(&db, &aggregate_id, before_delete).unwrap();
        assert!(before.is_some());

        // Query after deletion - should not exist (deleted)
        let after = HostProjections::get_at_time(&db, &aggregate_id, Utc::now()).unwrap();
        assert!(after.is_none());
    }
}
