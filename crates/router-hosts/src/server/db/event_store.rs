use super::events::{EventData, EventEnvelope, EventMetadata, HostEvent};
use super::projections::HostProjections;
use super::schema::{Database, DatabaseError, DatabaseResult};
use chrono::{DateTime, Utc};
use duckdb::OptionalExt;
use tracing::error;
use ulid::Ulid;

/// Event store for persisting and retrieving domain events
///
/// This implements an append-only event log with:
/// - Optimistic concurrency control via event versioning
/// - Sequential event ordering per aggregate
/// - Efficient event replay for rebuilding state
///
/// # NULL vs Empty String Semantics for Comment/Tags
///
/// The `comment` and `tags` columns use specific semantics to enable
/// `LAST_VALUE(... IGNORE NULLS)` in the SQL view for proper state merging:
///
/// - **NULL**: Means "no change" - the field was not modified by this event.
///   Used by partial update events (e.g., `IpAddressChanged` doesn't touch comment).
///
/// - **Empty string `""`**: Means "cleared/no value" - the field was explicitly
///   set to have no comment. Used when a user clears their comment.
///
/// This distinction is critical for the SQL view to correctly merge partial
/// updates using `LAST_VALUE(comment IGNORE NULLS)`. Without it, an update
/// to just the IP address would incorrectly "clear" the comment.
///
/// Example event sequence:
/// 1. `HostCreated { comment: "server", ... }` → comment column = "server"
/// 2. `IpAddressChanged { ... }` → comment column = NULL (no change)
/// 3. View shows comment = "server" (LAST_VALUE IGNORE NULLS finds event 1)
pub struct EventStore;

impl EventStore {
    /// Rollback a transaction and return the provided error.
    ///
    /// If rollback fails, returns an error that includes both the original error
    /// and the rollback failure. This ensures rollback failures are never silently ignored.
    fn rollback_and_return(db: &Database, error: DatabaseError) -> DatabaseError {
        if let Err(rollback_err) = db.conn().execute("ROLLBACK", []) {
            error!(
                "Transaction rollback failed after error '{}': {}",
                error, rollback_err
            );
            DatabaseError::QueryFailed(format!(
                "Original error: {}; Rollback also failed: {}",
                error, rollback_err
            ))
        } else {
            error
        }
    }
}

impl EventStore {
    /// Append a new event to the store
    ///
    /// # Optimistic Concurrency
    ///
    /// The `expected_version` parameter implements optimistic locking:
    /// - Pass `None` when creating a new aggregate (first event)
    /// - Pass `Some(ulid_string)` where ulid_string is the last known version
    /// - Returns `ConcurrentWriteConflict` if another write occurred
    ///
    /// # Arguments
    ///
    /// * `db` - Database connection
    /// * `aggregate_id` - ID of the aggregate (host entry)
    /// * `event` - Domain event to store
    /// * `expected_version` - Expected current version for optimistic locking
    /// * `created_by` - Optional user/system identifier
    ///
    /// # Returns
    ///
    /// Returns the stored `EventEnvelope` with generated event_id and version
    pub fn append_event(
        db: &Database,
        aggregate_id: &Ulid,
        event: HostEvent,
        expected_version: Option<String>,
        created_by: Option<String>,
    ) -> DatabaseResult<EventEnvelope> {
        // Begin transaction for atomic version check + insert
        db.conn().execute("BEGIN TRANSACTION", []).map_err(|e| {
            DatabaseError::QueryFailed(format!("Failed to begin transaction: {}", e))
        })?;

        // Check for duplicate IP+hostname on HostCreated events
        if let HostEvent::HostCreated {
            ip_address,
            hostname,
            ..
        } = &event
        {
            if HostProjections::find_by_ip_and_hostname(db, ip_address, hostname)?.is_some() {
                return Err(Self::rollback_and_return(
                    db,
                    DatabaseError::DuplicateEntry(format!(
                        "Host with IP {} and hostname {} already exists",
                        ip_address, hostname
                    )),
                ));
            }
        }

        // Get current version for this aggregate
        let current_version = Self::get_current_version(db, aggregate_id)
            .map_err(|e| Self::rollback_and_return(db, e))?;

        // Verify expected version matches (optimistic concurrency control)
        if expected_version != current_version {
            return Err(Self::rollback_and_return(
                db,
                DatabaseError::ConcurrentWriteConflict(format!(
                    "Expected version {:?} but current version is {:?} for aggregate {}",
                    expected_version, current_version, aggregate_id
                )),
            ));
        }

        // Generate new ULID version using monotonic generator
        // This ensures version < event_id lexicographically through monotonic counter increment
        use std::time::SystemTime;
        let mut gen = ulid::Generator::new();
        let timestamp = SystemTime::now();
        let new_version = gen
            .generate_from_datetime(timestamp)
            .map_err(|e| {
                DatabaseError::InvalidData(format!("Failed to generate ULID version: {}", e))
            })?
            .to_string();
        let event_id = gen.generate_from_datetime(timestamp).map_err(|e| {
            DatabaseError::InvalidData(format!("Failed to generate ULID event_id: {}", e))
        })?;
        let now = Utc::now();

        // Build event data and extract typed columns
        // Typed columns: ip_address, hostname, comment, tags (for queryability via LAST_VALUE IGNORE NULLS)
        // EventData (JSON metadata): previous values and extension data
        //
        // IMPORTANT: comment and tags columns are only set for events that change them.
        // NULL means "no change", enabling LAST_VALUE(... IGNORE NULLS) to properly merge state.
        let (ip_address_opt, hostname_opt, comment_opt, tags_opt, event_timestamp, event_data) =
            match &event {
                HostEvent::HostCreated {
                    ip_address,
                    hostname,
                    comment,
                    tags,
                    created_at,
                } => (
                    Some(ip_address.clone()),
                    Some(hostname.clone()),
                    // For HostCreated: store comment even if None (establishes initial state)
                    // Use empty string "" to represent "no comment" vs NULL which means "no change"
                    Some(comment.clone().unwrap_or_default()),
                    Some(serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string())),
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
                    None, // comment unchanged
                    None, // tags unchanged
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
                    None, // comment unchanged
                    None, // tags unchanged
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
                    // Store new comment (empty string if cleared)
                    Some(new_comment.clone().unwrap_or_default()),
                    None, // tags unchanged
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
                    None, // comment unchanged
                    Some(serde_json::to_string(new_tags).unwrap_or_else(|_| "[]".to_string())),
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
                    None, // comment unchanged
                    None, // tags unchanged
                    *deleted_at,
                    EventData {
                        deleted_reason: reason.clone(),
                        ..Default::default()
                    },
                ),
            };

        // Serialize EventData to JSON
        let event_data_json = serde_json::to_string(&event_data).map_err(|e| {
            Self::rollback_and_return(
                db,
                DatabaseError::InvalidData(format!("Failed to serialize event data: {}", e)),
            )
        })?;

        // Single INSERT statement for all event types
        db.conn()
            .execute(
                r#"
                INSERT INTO host_events (
                    event_id, aggregate_id, event_type, event_version,
                    ip_address, hostname, comment, tags,
                    event_timestamp, metadata,
                    created_at, created_by, expected_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, to_timestamp(?::BIGINT / 1000000.0), ?, to_timestamp(?::BIGINT / 1000000.0), ?, ?)
                "#,
                [
                    &event_id.to_string() as &dyn duckdb::ToSql,
                    &aggregate_id.to_string(),
                    &event.event_type(),
                    &new_version,
                    &ip_address_opt as &dyn duckdb::ToSql,
                    &hostname_opt as &dyn duckdb::ToSql,
                    &comment_opt as &dyn duckdb::ToSql,
                    &tags_opt as &dyn duckdb::ToSql,
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
                let db_error = if error_str.contains("UNIQUE") || error_str.contains("unique constraint") {
                    DatabaseError::ConcurrentWriteConflict(format!(
                        "Concurrent write detected for aggregate {} at version {}",
                        aggregate_id, new_version
                    ))
                } else {
                    DatabaseError::QueryFailed(format!("Failed to insert event: {}", e))
                };
                Self::rollback_and_return(db, db_error)
            })?;

        // Commit transaction
        db.conn().execute("COMMIT", []).map_err(|e| {
            DatabaseError::QueryFailed(format!("Failed to commit transaction: {}", e))
        })?;

        Ok(EventEnvelope {
            event_id,
            aggregate_id: *aggregate_id,
            event,
            event_version: new_version,
            created_at: now,
            created_by,
            metadata: None,
        })
    }

    /// Get the current ULID version for an aggregate
    ///
    /// Returns the most recent event's ULID version, or `None` if no events exist yet.
    /// Used for optimistic concurrency control during append operations.
    fn get_current_version(db: &Database, aggregate_id: &Ulid) -> DatabaseResult<Option<String>> {
        let version = db
            .conn()
            .query_row(
                // Use ORDER BY DESC LIMIT 1 instead of MAX() for ULID strings
                // ULIDs are lexicographically sortable by design, ensuring correct temporal ordering
                "SELECT event_version FROM host_events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1",
                [&aggregate_id.to_string()],
                |row| row.get::<_, Option<String>>(0),
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
        let conn = db.conn();
        let mut stmt = conn
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
                    row.get::<_, String>(3)?,         // event_version
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

    /// Append multiple events atomically to the store
    ///
    /// This method ensures that either ALL events are committed or NONE are,
    /// preventing partial updates from race conditions. This is critical for
    /// multi-field updates where several events need to be applied together.
    ///
    /// # Optimistic Concurrency
    ///
    /// The `expected_version` parameter implements optimistic locking for the first event:
    /// - Pass `None` when creating a new aggregate (first event)
    /// - Pass `Some(ulid_string)` where ulid_string is the last known version
    /// - Returns `ConcurrentWriteConflict` if another write occurred
    /// - Subsequent events use new ULID versions automatically
    ///
    /// # Arguments
    ///
    /// * `db` - Database connection
    /// * `aggregate_id` - ID of the aggregate (host entry)
    /// * `events` - Domain events to store (must be non-empty)
    /// * `expected_version` - Expected current version for optimistic locking
    /// * `created_by` - Optional user/system identifier
    ///
    /// # Returns
    ///
    /// Returns the stored `EventEnvelope`s with generated event_ids and versions
    pub fn append_events(
        db: &Database,
        aggregate_id: &Ulid,
        events: Vec<HostEvent>,
        expected_version: Option<String>,
        created_by: Option<String>,
    ) -> DatabaseResult<Vec<EventEnvelope>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        // Begin transaction for atomic multi-event insert
        db.conn().execute("BEGIN TRANSACTION", []).map_err(|e| {
            DatabaseError::QueryFailed(format!("Failed to begin transaction: {}", e))
        })?;

        // Get current version for this aggregate
        let current_version = Self::get_current_version(db, aggregate_id)
            .map_err(|e| Self::rollback_and_return(db, e))?;

        // Verify expected version matches (optimistic concurrency control)
        if expected_version != current_version {
            return Err(Self::rollback_and_return(
                db,
                DatabaseError::ConcurrentWriteConflict(format!(
                    "Expected version {:?} but current version is {:?} for aggregate {}",
                    expected_version, current_version, aggregate_id
                )),
            ));
        }

        let mut envelopes = Vec::with_capacity(events.len());
        let now = Utc::now();

        // Generate ULIDs for each event with monotonic ordering
        // Use a per-invocation generator with a single timestamp to ensure strict monotonic
        // ordering within the batch. The generator increments its internal counter when
        // generating multiple ULIDs with the same timestamp, guaranteeing lexicographic order.
        // Note: Per-invocation generator (not thread-local) is required for async safety,
        // as Tokio may migrate tasks between threads during .await points.
        use std::time::SystemTime;
        let mut gen = ulid::Generator::new();
        let batch_timestamp = SystemTime::now();

        for event in events {
            let version = gen
                .generate_from_datetime(batch_timestamp)
                .map_err(|e| {
                    DatabaseError::InvalidData(format!("Failed to generate ULID version: {}", e))
                })?
                .to_string();
            let event_id = gen.generate_from_datetime(batch_timestamp).map_err(|e| {
                DatabaseError::InvalidData(format!("Failed to generate ULID event_id: {}", e))
            })?;

            // Build event data and extract typed columns
            // comment and tags columns are only set for events that change them.
            // NULL means "no change", enabling LAST_VALUE(... IGNORE NULLS) to properly merge state.
            let (ip_address_opt, hostname_opt, comment_opt, tags_opt, event_timestamp, event_data) =
                match &event {
                    HostEvent::HostCreated {
                        ip_address,
                        hostname,
                        comment,
                        tags,
                        created_at,
                    } => (
                        Some(ip_address.clone()),
                        Some(hostname.clone()),
                        Some(comment.clone().unwrap_or_default()),
                        Some(serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string())),
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
                        None,
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
                        None,
                        None,
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
                        Some(new_comment.clone().unwrap_or_default()),
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
                        None,
                        Some(serde_json::to_string(new_tags).unwrap_or_else(|_| "[]".to_string())),
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
                        None,
                        None,
                        *deleted_at,
                        EventData {
                            deleted_reason: reason.clone(),
                            ..Default::default()
                        },
                    ),
                };

            // Serialize EventData to JSON
            let event_data_json = match serde_json::to_string(&event_data) {
                Ok(json) => json,
                Err(e) => {
                    return Err(Self::rollback_and_return(
                        db,
                        DatabaseError::InvalidData(format!(
                            "Failed to serialize event data: {}",
                            e
                        )),
                    ));
                }
            };

            // Insert event
            if let Err(e) = db.conn().execute(
                r#"
                INSERT INTO host_events (
                    event_id, aggregate_id, event_type, event_version,
                    ip_address, hostname, comment, tags,
                    event_timestamp, metadata,
                    created_at, created_by, expected_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, to_timestamp(?::BIGINT / 1000000.0), ?, to_timestamp(?::BIGINT / 1000000.0), ?, ?)
                "#,
                [
                    &event_id.to_string() as &dyn duckdb::ToSql,
                    &aggregate_id.to_string(),
                    &event.event_type(),
                    &version,
                    &ip_address_opt as &dyn duckdb::ToSql,
                    &hostname_opt as &dyn duckdb::ToSql,
                    &comment_opt as &dyn duckdb::ToSql,
                    &tags_opt as &dyn duckdb::ToSql,
                    &event_timestamp.timestamp_micros(),
                    &event_data_json as &dyn duckdb::ToSql,
                    &now.timestamp_micros(),
                    &created_by.as_deref().unwrap_or("system"),
                    &expected_version,
                ],
            ) {
                let error_str = e.to_string();
                let db_error = if error_str.contains("UNIQUE") || error_str.contains("unique constraint") {
                    DatabaseError::ConcurrentWriteConflict(format!(
                        "Concurrent write detected for aggregate {} at version {}",
                        aggregate_id, version
                    ))
                } else {
                    DatabaseError::QueryFailed(format!("Failed to insert event: {}", e))
                };
                return Err(Self::rollback_and_return(db, db_error));
            }

            envelopes.push(EventEnvelope {
                event_id,
                aggregate_id: *aggregate_id,
                event,
                event_version: version,
                created_at: now,
                created_by: created_by.clone(),
                metadata: None,
            });
        }

        // Commit transaction - all events or none
        db.conn().execute("COMMIT", []).map_err(|e| {
            DatabaseError::QueryFailed(format!("Failed to commit transaction: {}", e))
        })?;

        Ok(envelopes)
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

        let result = EventStore::append_event(&db, &aggregate_id, event, None, None);
        assert!(result.is_ok());

        let envelope = result.unwrap();
        assert_eq!(envelope.aggregate_id, aggregate_id);
        assert_eq!(envelope.event_version.len(), 26); // ULID is 26 chars
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
        let envelope1 = EventStore::append_event(&db, &aggregate_id, event1, None, None).unwrap();
        assert_eq!(envelope1.event_version.len(), 26); // ULID is 26 chars

        let version1 = envelope1.event_version.clone();

        // Second event
        let event2 = HostEvent::IpAddressChanged {
            old_ip: "192.168.1.10".to_string(),
            new_ip: "192.168.1.11".to_string(),
            changed_at: Utc::now(),
        };
        let envelope2 =
            EventStore::append_event(&db, &aggregate_id, event2, Some(version1), None).unwrap();
        assert_eq!(envelope2.event_version.len(), 26); // ULID is 26 chars
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
        EventStore::append_event(&db, &aggregate_id, event1, None, None).unwrap();

        // Try to append with wrong expected version
        let event2 = HostEvent::IpAddressChanged {
            old_ip: "192.168.1.10".to_string(),
            new_ip: "192.168.1.11".to_string(),
            changed_at: Utc::now(),
        };
        let result = EventStore::append_event(
            &db,
            &aggregate_id,
            event2,
            Some("01INVALID0000000000000000".to_string()),
            None,
        );

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
        let env1 = EventStore::append_event(
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

        let version1 = env1.event_version.clone();

        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
            Some(version1),
            None,
        )
        .unwrap();

        // Load all events
        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_version.len(), 26); // ULID is 26 chars
        assert_eq!(events[1].event_version.len(), 26); // ULID is 26 chars
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

        let result = EventStore::append_event(&db, &aggregate_id, event.clone(), None, None);
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
            // IP addresses are stored as VARCHAR (validation at app layer)
            assert_eq!(ip_address, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
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
        let v1 = EventStore::append_event(
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
        )
        .unwrap()
        .event_version;

        // IpAddressChanged
        let v2 = EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::IpAddressChanged {
                old_ip: "10.0.0.1".to_string(),
                new_ip: "10.0.0.2".to_string(),
                changed_at: Utc::now(),
            },
            Some(v1),
            None,
        )
        .unwrap()
        .event_version;

        // HostnameChanged
        let v3 = EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::HostnameChanged {
                old_hostname: "test.local".to_string(),
                new_hostname: "test2.local".to_string(),
                changed_at: Utc::now(),
            },
            Some(v2),
            None,
        )
        .unwrap()
        .event_version;

        // CommentUpdated
        let v4 = EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: Some("Initial".to_string()),
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
            Some(v3),
            None,
        )
        .unwrap()
        .event_version;

        // TagsModified
        let v5 = EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::TagsModified {
                old_tags: vec!["dev".to_string()],
                new_tags: vec!["dev".to_string(), "production".to_string()],
                modified_at: Utc::now(),
            },
            Some(v4),
            None,
        )
        .unwrap()
        .event_version;

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
            Some(v5),
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

        for event in events.iter() {
            assert_eq!(event.event_version.len(), 26); // ULID is 26 chars
        }
    }

    #[test]
    fn test_empty_and_null_metadata() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Empty comment and tags
        let env1 = EventStore::append_event(
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
        )
        .unwrap();

        // Comment cleared (Some -> None)
        let v1 = EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: None,
                updated_at: Utc::now(),
            },
            Some(env1.event_version.clone()),
            None,
        )
        .unwrap()
        .event_version;

        // Tags cleared ([] -> [])
        EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::TagsModified {
                old_tags: vec![],
                new_tags: vec![],
                modified_at: Utc::now(),
            },
            Some(v1),
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

        let result = EventStore::append_event(&db, &aggregate_id, event, None, None);
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

        let result = EventStore::append_event(&db, &aggregate_id, event, None, None);
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
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().created_by,
            Some("admin@example.com".to_string())
        );

        // Without created_by (defaults to None) - use different IP+hostname to avoid duplicate
        let agg2 = Ulid::new();
        let event2 = HostEvent::HostCreated {
            ip_address: "192.168.1.2".to_string(),
            hostname: "test2.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };
        let result2 = EventStore::append_event(&db, &agg2, event2, None, None);
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap().created_by, None);
    }

    #[test]
    fn test_multiple_aggregates_isolation() {
        let db = Database::in_memory().unwrap();
        let agg1 = Ulid::new();
        let agg2 = Ulid::new();

        // Add events to first aggregate
        let v1 = EventStore::append_event(
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
        )
        .unwrap()
        .event_version;

        EventStore::append_event(
            &db,
            &agg1,
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
            Some(v1),
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
        let mut current_version: Option<String> = None;
        for i in 0..10 {
            let env = EventStore::append_event(
                &db,
                &aggregate_id,
                HostEvent::CommentUpdated {
                    old_comment: None,
                    new_comment: Some(format!("Version {}", i + 1)),
                    updated_at: Utc::now(),
                },
                current_version,
                None,
            )
            .unwrap();
            current_version = Some(env.event_version);
        }

        let events = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(events.len(), 10);

        for event in events.iter() {
            assert_eq!(event.event_version.len(), 26); // ULID is 26 chars
        }
    }

    #[test]
    fn test_concurrent_write_with_same_expected_version() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // First event
        let v1 = EventStore::append_event(
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
        )
        .unwrap()
        .event_version;

        // Second event with correct version
        let result = EventStore::append_event(
            &db,
            &aggregate_id,
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("First".to_string()),
                updated_at: Utc::now(),
            },
            Some(v1.clone()),
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
            Some(v1), // Same expected version - conflict!
            None,
        );
        assert!(result2.is_err());
        assert!(matches!(
            result2.unwrap_err(),
            DatabaseError::ConcurrentWriteConflict(_)
        ));
    }

    #[test]
    fn test_reject_duplicate_ip_hostname() {
        let db = Database::in_memory().unwrap();

        // Create first host
        EventStore::append_event(
            &db,
            &Ulid::new(),
            HostEvent::HostCreated {
                ip_address: "192.168.1.100".to_string(),
                hostname: "server.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
        )
        .unwrap();

        // Try to create duplicate
        let result = EventStore::append_event(
            &db,
            &Ulid::new(),
            HostEvent::HostCreated {
                ip_address: "192.168.1.100".to_string(),
                hostname: "server.local".to_string(),
                comment: Some("Different comment".to_string()),
                tags: vec![],
                created_at: Utc::now(),
            },
            None,
            None,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DatabaseError::DuplicateEntry(_)
        ));
    }

    // Tests for append_events (atomic batch insertion)

    #[test]
    fn test_append_events_empty_list() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        let result = EventStore::append_events(&db, &aggregate_id, vec![], None, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_append_events_single_event() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        let events = vec![HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "single.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        }];

        let result = EventStore::append_events(&db, &aggregate_id, events, None, None);
        assert!(result.is_ok());

        let envelopes = result.unwrap();
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].event_version.len(), 26); // ULID is 26 chars
    }

    #[test]
    fn test_append_events_multiple_atomic() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // First create the host
        let v1 = EventStore::append_event(
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
        )
        .unwrap()
        .event_version;

        // Now update multiple fields atomically
        let events = vec![
            HostEvent::IpAddressChanged {
                old_ip: "192.168.1.1".to_string(),
                new_ip: "192.168.1.2".to_string(),
                changed_at: Utc::now(),
            },
            HostEvent::HostnameChanged {
                old_hostname: "test.local".to_string(),
                new_hostname: "updated.local".to_string(),
                changed_at: Utc::now(),
            },
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
        ];

        let result = EventStore::append_events(&db, &aggregate_id, events, Some(v1), None);
        assert!(result.is_ok());

        let envelopes = result.unwrap();
        assert_eq!(envelopes.len(), 3);
        assert_eq!(envelopes[0].event_version.len(), 26); // ULID is 26 chars
        assert_eq!(envelopes[1].event_version.len(), 26); // ULID is 26 chars
        assert_eq!(envelopes[2].event_version.len(), 26); // ULID is 26 chars

        // Verify all events were stored
        let loaded = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(loaded.len(), 4);
    }

    #[test]
    fn test_append_events_optimistic_concurrency() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Create host
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
        )
        .unwrap();

        // Try to append events with wrong expected version
        let events = vec![HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("Test".to_string()),
            updated_at: Utc::now(),
        }];

        let result = EventStore::append_events(
            &db,
            &aggregate_id,
            events,
            Some("01INVALID0000000000000000".to_string()),
            None,
        );
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DatabaseError::ConcurrentWriteConflict(_)
        ));

        // Verify no events were added (atomicity)
        let loaded = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(loaded.len(), 1); // Only the original HostCreated
    }

    #[test]
    fn test_append_events_all_or_nothing() {
        let db = Database::in_memory().unwrap();
        let aggregate_id = Ulid::new();

        // Create host
        let env1 = EventStore::append_event(
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
        )
        .unwrap();

        // Append multiple events successfully
        let events = vec![
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("First update".to_string()),
                updated_at: Utc::now(),
            },
            HostEvent::TagsModified {
                old_tags: vec![],
                new_tags: vec!["tag1".to_string()],
                modified_at: Utc::now(),
            },
        ];

        let v1 = env1.event_version.clone();
        let result = EventStore::append_events(&db, &aggregate_id, events, Some(v1), None);
        assert!(result.is_ok());

        // Verify both events were stored atomically
        let loaded = EventStore::load_events(&db, &aggregate_id).unwrap();
        assert_eq!(loaded.len(), 3);
        assert!(matches!(loaded[1].event, HostEvent::CommentUpdated { .. }));
        assert!(matches!(loaded[2].event, HostEvent::TagsModified { .. }));
    }
}
