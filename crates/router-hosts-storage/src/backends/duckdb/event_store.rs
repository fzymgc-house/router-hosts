//! Event store implementation for DuckDB
//!
//! This module implements the event sourcing write side:
//! - Append events with optimistic concurrency control
//! - Load event streams for aggregates
//! - Version management for conflict detection

use chrono::{DateTime, Utc};

/// Extracted event data for database insertion
/// (ip_address, hostname, comment, tags, aliases, event_timestamp, event_data)
type ExtractedEventData = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    DateTime<Utc>,
    EventData,
);
use duckdb::OptionalExt;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::backends::duckdb::DuckDbStorage;
use crate::error::StorageError;
use crate::types::{EventEnvelope, HostEvent};

/// Event-specific data stored as JSON metadata
/// Contains tags, comments, aliases, and previous values (for change events)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EventData {
    // Common fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,

    // Previous values for change events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_aliases: Option<Vec<String>>,

    // For deleted events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_reason: Option<String>,
}

impl DuckDbStorage {
    /// Append a single event to the store
    ///
    /// # Optimistic Concurrency
    ///
    /// The `expected_version` parameter implements optimistic locking:
    /// - Pass `None` when creating a new aggregate (first event)
    /// - Pass `Some(ulid_string)` where ulid_string is the last known version
    /// - Returns `ConcurrentWriteConflict` if another write occurred
    pub(super) async fn append_event_impl(
        &self,
        aggregate_id: Ulid,
        envelope: EventEnvelope,
        expected_version: Option<String>,
    ) -> Result<(), StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();

            // Begin transaction for atomic version check + insert
            conn.execute("BEGIN TRANSACTION", [])
                .map_err(|e| StorageError::query("failed to begin transaction", e))?;

            // Check for duplicate IP+hostname on HostCreated events
            if let HostEvent::HostCreated {
                ip_address,
                hostname,
                ..
            } = &envelope.event
            {
                let exists: bool = conn
                    .query_row(
                        r#"
                        SELECT COUNT(*) > 0
                        FROM host_entries_current
                        WHERE ip_address = ? AND hostname = ?
                        "#,
                        [ip_address, hostname],
                        |row| row.get(0),
                    )
                    .map_err(|e| {
                        let _ = conn.execute("ROLLBACK", []);
                        StorageError::query("failed to check for duplicate entry", e)
                    })?;

                if exists {
                    let _ = conn.execute("ROLLBACK", []);
                    return Err(StorageError::DuplicateEntry {
                        ip: ip_address.clone(),
                        hostname: hostname.clone(),
                    });
                }
            }

            // Get current version for this aggregate
            let current_version: Option<String> = conn
                .query_row(
                    "SELECT event_version FROM host_events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1",
                    [&aggregate_id.to_string()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|e| {
                    let _ = conn.execute("ROLLBACK", []);
                    StorageError::query("failed to get current version", e)
                })?
                .flatten();

            // Verify expected version matches (optimistic concurrency control)
            if expected_version != current_version {
                let _ = conn.execute("ROLLBACK", []);
                return Err(StorageError::ConcurrentWriteConflict {
                    aggregate_id: aggregate_id.to_string(),
                });
            }

            // Extract typed columns and build metadata
            let (ip_address_opt, hostname_opt, comment_opt, tags_opt, aliases_opt, event_timestamp, event_data) =
                extract_event_data(&envelope.event);

            // Serialize EventData to JSON
            let event_data_json = serde_json::to_string(&event_data).map_err(|e| {
                let _ = conn.execute("ROLLBACK", []);
                StorageError::InvalidData(format!("failed to serialize event data: {}", e))
            })?;

            // Insert event
            conn.execute(
                r#"
                INSERT INTO host_events (
                    event_id, aggregate_id, event_type, event_version,
                    ip_address, hostname, comment, tags, aliases,
                    event_timestamp, metadata,
                    created_at, created_by, expected_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, to_timestamp(?::BIGINT / 1000000.0), ?, to_timestamp(?::BIGINT / 1000000.0), ?, ?)
                "#,
                [
                    &envelope.event_id.to_string() as &dyn duckdb::ToSql,
                    &aggregate_id.to_string(),
                    &envelope.event.event_type(),
                    &envelope.event_version,
                    &ip_address_opt as &dyn duckdb::ToSql,
                    &hostname_opt as &dyn duckdb::ToSql,
                    &comment_opt as &dyn duckdb::ToSql,
                    &tags_opt as &dyn duckdb::ToSql,
                    &aliases_opt as &dyn duckdb::ToSql,
                    &event_timestamp.timestamp_micros(),
                    &event_data_json as &dyn duckdb::ToSql,
                    &envelope.created_at.timestamp_micros(),
                    &envelope.created_by.as_deref().unwrap_or("system"),
                    &expected_version,
                ],
            )
            .map_err(|e| {
                let _ = conn.execute("ROLLBACK", []);
                let error_str = e.to_string();
                if error_str.contains("UNIQUE") || error_str.contains("unique constraint") {
                    StorageError::ConcurrentWriteConflict {
                        aggregate_id: aggregate_id.to_string(),
                    }
                } else {
                    StorageError::query("failed to insert event", e)
                }
            })?;

            // Commit transaction
            conn.execute("COMMIT", [])
                .map_err(|e| StorageError::query("failed to commit transaction", e))?;

            Ok(())
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during append_event", e))?
    }

    /// Append multiple events atomically to the store
    ///
    /// This method ensures that either ALL events are committed or NONE are,
    /// preventing partial updates from race conditions.
    pub(super) async fn append_events_impl(
        &self,
        aggregate_id: Ulid,
        envelopes: Vec<EventEnvelope>,
        expected_version: Option<String>,
    ) -> Result<(), StorageError> {
        if envelopes.is_empty() {
            return Ok(());
        }

        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();

            // Begin transaction for atomic multi-event insert
            conn.execute("BEGIN TRANSACTION", [])
                .map_err(|e| StorageError::query("failed to begin transaction", e))?;

            // Get current version for this aggregate
            let current_version: Option<String> = conn
                .query_row(
                    "SELECT event_version FROM host_events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1",
                    [&aggregate_id.to_string()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|e| {
                    let _ = conn.execute("ROLLBACK", []);
                    StorageError::query("failed to get current version", e)
                })?
                .flatten();

            // Verify expected version matches (optimistic concurrency control)
            if expected_version != current_version {
                let _ = conn.execute("ROLLBACK", []);
                return Err(StorageError::ConcurrentWriteConflict {
                    aggregate_id: aggregate_id.to_string(),
                });
            }

            // Insert each event
            for envelope in envelopes {
                let (ip_address_opt, hostname_opt, comment_opt, tags_opt, aliases_opt, event_timestamp, event_data) =
                    extract_event_data(&envelope.event);

                let event_data_json = serde_json::to_string(&event_data).map_err(|e| {
                    let _ = conn.execute("ROLLBACK", []);
                    StorageError::InvalidData(format!("failed to serialize event data: {}", e))
                })?;

                conn.execute(
                    r#"
                    INSERT INTO host_events (
                        event_id, aggregate_id, event_type, event_version,
                        ip_address, hostname, comment, tags, aliases,
                        event_timestamp, metadata,
                        created_at, created_by, expected_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, to_timestamp(?::BIGINT / 1000000.0), ?, to_timestamp(?::BIGINT / 1000000.0), ?, ?)
                    "#,
                    [
                        &envelope.event_id.to_string() as &dyn duckdb::ToSql,
                        &aggregate_id.to_string(),
                        &envelope.event.event_type(),
                        &envelope.event_version,
                        &ip_address_opt as &dyn duckdb::ToSql,
                        &hostname_opt as &dyn duckdb::ToSql,
                        &comment_opt as &dyn duckdb::ToSql,
                        &tags_opt as &dyn duckdb::ToSql,
                        &aliases_opt as &dyn duckdb::ToSql,
                        &event_timestamp.timestamp_micros(),
                        &event_data_json as &dyn duckdb::ToSql,
                        &envelope.created_at.timestamp_micros(),
                        &envelope.created_by.as_deref().unwrap_or("system"),
                        &expected_version,
                    ],
                )
                .map_err(|e| {
                    let _ = conn.execute("ROLLBACK", []);
                    let error_str = e.to_string();
                    if error_str.contains("UNIQUE") || error_str.contains("unique constraint") {
                        StorageError::ConcurrentWriteConflict {
                            aggregate_id: aggregate_id.to_string(),
                        }
                    } else {
                        StorageError::query("failed to insert event", e)
                    }
                })?;
            }

            // Commit transaction - all events or none
            conn.execute("COMMIT", [])
                .map_err(|e| StorageError::query("failed to commit transaction", e))?;

            Ok(())
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during append_events", e))?
    }

    /// Load all events for an aggregate in order
    pub(super) async fn load_events_impl(
        &self,
        aggregate_id: Ulid,
    ) -> Result<Vec<EventEnvelope>, StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();

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
                .map_err(|e| StorageError::query("failed to prepare query", e))?;

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
                .map_err(|e| StorageError::query("failed to query events", e))?;

            let mut envelopes = Vec::new();
            let mut current_state: Option<(
                String,
                String,
                Option<String>,
                Vec<String>,
                Vec<String>,
            )> = None; // (ip, hostname, comment, tags, aliases)

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
                ) = row.map_err(|e| StorageError::query("failed to read row", e))?;

                let event_id = Ulid::from_string(&event_id_str).map_err(|e| {
                    StorageError::InvalidData(format!("invalid event_id ULID: {}", e))
                })?;

                let agg_id = Ulid::from_string(&aggregate_id_str).map_err(|e| {
                    StorageError::InvalidData(format!("invalid aggregate_id ULID: {}", e))
                })?;

                let event_timestamp = DateTime::from_timestamp_micros(event_timestamp_micros)
                    .ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid event timestamp: {}",
                            event_timestamp_micros
                        ))
                    })?;

                // Deserialize EventData from metadata JSON
                let event_data: EventData = serde_json::from_str(&metadata_json).map_err(|e| {
                    StorageError::InvalidData(format!(
                        "failed to deserialize event metadata: {}",
                        e
                    ))
                })?;

                // Reconstruct the event from typed columns + metadata based on event_type
                let event = reconstruct_event(
                    &event_type,
                    ip_address,
                    hostname,
                    &event_data,
                    event_timestamp,
                    &mut current_state,
                )?;

                let created_at =
                    DateTime::from_timestamp_micros(created_at_micros).ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid timestamp: {}",
                            created_at_micros
                        ))
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
                });
            }

            Ok(envelopes)
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during load_events", e))?
    }

    /// Get the current version for an aggregate
    pub(super) async fn get_current_version_impl(
        &self,
        aggregate_id: Ulid,
    ) -> Result<Option<String>, StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let version = conn
                .lock()
                .query_row(
                    "SELECT event_version FROM host_events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1",
                    [&aggregate_id.to_string()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|e| {
                    StorageError::query("failed to get current version", e)
                })?
                .flatten();

            Ok(version)
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during get_current_version", e))?
    }

    /// Count total events for an aggregate
    pub(super) async fn count_events_impl(&self, aggregate_id: Ulid) -> Result<i64, StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let count = conn
                .lock()
                .query_row(
                    "SELECT COUNT(*) FROM host_events WHERE aggregate_id = ?",
                    [&aggregate_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(|e| StorageError::query("failed to count events", e))?;

            Ok(count)
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during count_events", e))?
    }
}

/// Extract typed columns and metadata from a HostEvent
///
/// Returns: (ip_address, hostname, comment, tags, aliases, event_timestamp, event_data)
fn extract_event_data(event: &HostEvent) -> ExtractedEventData {
    match event {
        HostEvent::HostCreated {
            ip_address,
            hostname,
            aliases,
            comment,
            tags,
            created_at,
        } => (
            Some(ip_address.clone()),
            Some(hostname.clone()),
            Some(comment.clone().unwrap_or_default()),
            Some(serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string())),
            Some(serde_json::to_string(aliases).unwrap_or_else(|_| "[]".to_string())),
            *created_at,
            EventData {
                comment: comment.clone(),
                tags: Some(tags.clone()),
                aliases: Some(aliases.clone()),
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
            None,
            *modified_at,
            EventData {
                tags: Some(new_tags.clone()),
                previous_tags: Some(old_tags.clone()),
                ..Default::default()
            },
        ),
        HostEvent::AliasesModified {
            old_aliases,
            new_aliases,
            modified_at,
        } => (
            None,
            None,
            None,
            None,
            Some(serde_json::to_string(new_aliases).unwrap_or_else(|_| "[]".to_string())),
            *modified_at,
            EventData {
                aliases: Some(new_aliases.clone()),
                previous_aliases: Some(old_aliases.clone()),
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
            None,
            *deleted_at,
            EventData {
                deleted_reason: reason.clone(),
                ..Default::default()
            },
        ),
    }
}

/// Reconstruct a HostEvent from database columns
fn reconstruct_event(
    event_type: &str,
    ip_address: Option<String>,
    hostname: Option<String>,
    event_data: &EventData,
    event_timestamp: DateTime<Utc>,
    current_state: &mut Option<(String, String, Option<String>, Vec<String>, Vec<String>)>,
) -> Result<HostEvent, StorageError> {
    match event_type {
        "HostCreated" => {
            let ip = ip_address.ok_or_else(|| {
                StorageError::InvalidData("HostCreated missing ip_address".into())
            })?;
            let host = hostname
                .ok_or_else(|| StorageError::InvalidData("HostCreated missing hostname".into()))?;

            let tags = event_data.tags.clone().unwrap_or_default();
            let aliases = event_data.aliases.clone().unwrap_or_default();
            let comment = event_data.comment.clone();

            // Update current state (ip, hostname, comment, tags, aliases)
            *current_state = Some((
                ip.clone(),
                host.clone(),
                comment.clone(),
                tags.clone(),
                aliases.clone(),
            ));

            Ok(HostEvent::HostCreated {
                ip_address: ip,
                hostname: host,
                aliases,
                comment,
                tags,
                created_at: event_timestamp,
            })
        }
        "IpAddressChanged" => {
            let new_ip = ip_address.ok_or_else(|| {
                StorageError::InvalidData("IpAddressChanged missing ip_address".into())
            })?;

            let old_ip = event_data.previous_ip.clone().ok_or_else(|| {
                StorageError::InvalidData("IpAddressChanged missing previous_ip in metadata".into())
            })?;

            // Update current state
            if let Some((ref mut ip, _, _, _, _)) = current_state {
                *ip = new_ip.clone();
            }

            Ok(HostEvent::IpAddressChanged {
                old_ip,
                new_ip,
                changed_at: event_timestamp,
            })
        }
        "HostnameChanged" => {
            let new_hostname = hostname.ok_or_else(|| {
                StorageError::InvalidData("HostnameChanged missing hostname".into())
            })?;

            let old_hostname = event_data.previous_hostname.clone().ok_or_else(|| {
                StorageError::InvalidData(
                    "HostnameChanged missing previous_hostname in metadata".into(),
                )
            })?;

            // Update current state
            if let Some((_, ref mut host, _, _, _)) = current_state {
                *host = new_hostname.clone();
            }

            Ok(HostEvent::HostnameChanged {
                old_hostname,
                new_hostname,
                changed_at: event_timestamp,
            })
        }
        "CommentUpdated" => {
            let old_comment = event_data.previous_comment.clone();
            let new_comment = event_data.comment.clone();

            // Update current state
            if let Some((_, _, ref mut c, _, _)) = current_state {
                *c = new_comment.clone();
            }

            Ok(HostEvent::CommentUpdated {
                old_comment,
                new_comment,
                updated_at: event_timestamp,
            })
        }
        "TagsModified" => {
            let old_tags = event_data.previous_tags.clone().unwrap_or_default();
            let new_tags = event_data.tags.clone().unwrap_or_default();

            // Update current state
            if let Some((_, _, _, ref mut tags, _)) = current_state {
                *tags = new_tags.clone();
            }

            Ok(HostEvent::TagsModified {
                old_tags,
                new_tags,
                modified_at: event_timestamp,
            })
        }
        "AliasesModified" => {
            let old_aliases = event_data.previous_aliases.clone().unwrap_or_default();
            let new_aliases = event_data.aliases.clone().unwrap_or_default();

            // Update current state
            if let Some((_, _, _, _, ref mut aliases)) = current_state {
                *aliases = new_aliases.clone();
            }

            Ok(HostEvent::AliasesModified {
                old_aliases,
                new_aliases,
                modified_at: event_timestamp,
            })
        }
        "HostDeleted" => {
            let event = HostEvent::HostDeleted {
                ip_address: ip_address.ok_or_else(|| {
                    StorageError::InvalidData("HostDeleted missing ip_address".into())
                })?,
                hostname: hostname.ok_or_else(|| {
                    StorageError::InvalidData("HostDeleted missing hostname".into())
                })?,
                deleted_at: event_timestamp,
                reason: event_data.deleted_reason.clone(),
            };

            // Clear current state
            *current_state = None;

            Ok(event)
        }
        _ => Err(StorageError::InvalidData(format!(
            "unknown event type: {}",
            event_type
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Storage;

    async fn create_test_storage() -> DuckDbStorage {
        let storage = DuckDbStorage::new(":memory:")
            .await
            .expect("failed to create in-memory storage");
        storage.initialize().await.expect("failed to initialize");
        storage
    }

    #[tokio::test]
    async fn test_append_single_event() {
        let storage = create_test_storage().await;
        let aggregate_id = Ulid::new();

        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        let envelope = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event,
            event_version: Ulid::new().to_string(),
            created_at: Utc::now(),
            created_by: None,
        };

        let result = storage
            .append_event_impl(aggregate_id, envelope, None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_optimistic_concurrency_conflict() {
        let storage = create_test_storage().await;
        let aggregate_id = Ulid::new();

        // First event
        let event1 = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                aliases: vec![],
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            event_version: Ulid::new().to_string(),
            created_at: Utc::now(),
            created_by: None,
        };

        storage
            .append_event_impl(aggregate_id, event1, None)
            .await
            .unwrap();

        // Try to append with wrong expected version
        let event2 = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
            event_version: Ulid::new().to_string(),
            created_at: Utc::now(),
            created_by: None,
        };

        let result = storage
            .append_event_impl(
                aggregate_id,
                event2,
                Some("01INVALID0000000000000000".to_string()),
            )
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StorageError::ConcurrentWriteConflict { .. }
        ));
    }

    #[tokio::test]
    async fn test_load_events_ordered() {
        let storage = create_test_storage().await;
        let aggregate_id = Ulid::new();

        // Add multiple events
        let v1 = Ulid::new().to_string();
        let event1 = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                aliases: vec![],
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            event_version: v1.clone(),
            created_at: Utc::now(),
            created_by: None,
        };

        storage
            .append_event_impl(aggregate_id, event1, None)
            .await
            .unwrap();

        let v2 = Ulid::new().to_string();
        let event2 = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("Updated".to_string()),
                updated_at: Utc::now(),
            },
            event_version: v2.clone(),
            created_at: Utc::now(),
            created_by: None,
        };

        storage
            .append_event_impl(aggregate_id, event2, Some(v1))
            .await
            .unwrap();

        // Load all events
        let events = storage.load_events_impl(aggregate_id).await.unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0].event, HostEvent::HostCreated { .. }));
        assert!(matches!(events[1].event, HostEvent::CommentUpdated { .. }));
    }

    #[tokio::test]
    async fn test_count_events() {
        let storage = create_test_storage().await;
        let aggregate_id = Ulid::new();

        assert_eq!(storage.count_events_impl(aggregate_id).await.unwrap(), 0);

        let event = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                aliases: vec![],
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
            },
            event_version: Ulid::new().to_string(),
            created_at: Utc::now(),
            created_by: None,
        };

        storage
            .append_event_impl(aggregate_id, event, None)
            .await
            .unwrap();

        assert_eq!(storage.count_events_impl(aggregate_id).await.unwrap(), 1);
    }
}
