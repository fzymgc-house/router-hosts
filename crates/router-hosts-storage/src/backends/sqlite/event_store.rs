//! Event store implementation for SQLite
//!
//! This module implements the event sourcing write side:
//! - Append events with optimistic concurrency control
//! - Load event streams for aggregates
//! - Version management for conflict detection
//!
//! # Note on Ordering
//!
//! All queries use `ORDER BY rowid` instead of `ORDER BY event_version` because
//! ULIDs created within the same millisecond have arbitrary lexicographic order.
//! SQLite's rowid guarantees insertion order. See `schema.rs` for details.

use chrono::{DateTime, Utc};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use super::SqliteStorage;
use crate::error::StorageError;
use crate::types::{EventEnvelope, HostEvent};

/// Extracted event data for database insertion
/// (ip_address, hostname, comment, tags, aliases, timestamp, metadata)
type ExtractedEventData = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    DateTime<Utc>,
    EventData,
);

/// Event-specific data stored as JSON metadata
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EventData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_reason: Option<String>,
}

impl SqliteStorage {
    /// Append a single event to the store
    pub(super) async fn append_event_impl(
        &self,
        aggregate_id: Ulid,
        envelope: EventEnvelope,
        expected_version: Option<String>,
    ) -> Result<(), StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();

            // Begin transaction
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
                        WHERE ip_address = ?1 AND hostname = ?2
                        "#,
                        rusqlite::params![ip_address, hostname],
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

            // Get current version (use rowid for ordering, not event_version)
            // ULIDs within the same millisecond have arbitrary lexicographic order,
            // so we use SQLite's rowid to find the most recent event.
            let current_version: Option<String> = conn
                .query_row(
                    "SELECT event_version FROM host_events WHERE aggregate_id = ?1 ORDER BY rowid DESC LIMIT 1",
                    [&aggregate_id.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| {
                    let _ = conn.execute("ROLLBACK", []);
                    StorageError::query("failed to get current version", e)
                })?;

            // Verify expected version
            if expected_version != current_version {
                let _ = conn.execute("ROLLBACK", []);
                return Err(StorageError::ConcurrentWriteConflict {
                    aggregate_id: aggregate_id.to_string(),
                });
            }

            // Extract typed columns and metadata
            let (ip_address_opt, hostname_opt, comment_opt, tags_opt, aliases_opt, event_timestamp, event_data) =
                extract_event_data(&envelope.event).inspect_err(|_| {
                    let _ = conn.execute("ROLLBACK", []);
                })?;

            let event_data_json = serde_json::to_string(&event_data).map_err(|e| {
                let _ = conn.execute("ROLLBACK", []);
                StorageError::InvalidData(format!("failed to serialize event data: {}", e))
            })?;

            // Insert event (SQLite uses INTEGER for timestamps as microseconds)
            conn.execute(
                r#"
                INSERT INTO host_events (
                    event_id, aggregate_id, event_type, event_version,
                    ip_address, hostname, comment, tags, aliases,
                    event_timestamp, metadata,
                    created_at, created_by, expected_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                "#,
                rusqlite::params![
                    envelope.event_id.to_string(),
                    aggregate_id.to_string(),
                    envelope.event.event_type(),
                    envelope.event_version,
                    ip_address_opt,
                    hostname_opt,
                    comment_opt,
                    tags_opt,
                    aliases_opt,
                    event_timestamp.timestamp_micros(),
                    event_data_json,
                    envelope.created_at.timestamp_micros(),
                    envelope.created_by.as_deref().unwrap_or("system"),
                    expected_version,
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

            conn.execute("COMMIT", [])
                .map_err(|e| StorageError::query("failed to commit transaction", e))?;

            Ok(())
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during append_event", e))?
    }

    /// Append multiple events atomically
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

            conn.execute("BEGIN TRANSACTION", [])
                .map_err(|e| StorageError::query("failed to begin transaction", e))?;

            // Get current version (use rowid for ordering, not event_version)
            // ULIDs within the same millisecond have arbitrary lexicographic order,
            // so we use SQLite's rowid to find the most recent event.
            let current_version: Option<String> = conn
                .query_row(
                    "SELECT event_version FROM host_events WHERE aggregate_id = ?1 ORDER BY rowid DESC LIMIT 1",
                    [&aggregate_id.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| {
                    let _ = conn.execute("ROLLBACK", []);
                    StorageError::query("failed to get current version", e)
                })?;

            if expected_version != current_version {
                let _ = conn.execute("ROLLBACK", []);
                return Err(StorageError::ConcurrentWriteConflict {
                    aggregate_id: aggregate_id.to_string(),
                });
            }

            for envelope in envelopes {
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
                            WHERE ip_address = ?1 AND hostname = ?2
                            "#,
                            rusqlite::params![ip_address, hostname],
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

                let (ip_address_opt, hostname_opt, comment_opt, tags_opt, aliases_opt, event_timestamp, event_data) =
                    extract_event_data(&envelope.event).inspect_err(|_| {
                        let _ = conn.execute("ROLLBACK", []);
                    })?;

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
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                    "#,
                    rusqlite::params![
                        envelope.event_id.to_string(),
                        aggregate_id.to_string(),
                        envelope.event.event_type(),
                        envelope.event_version,
                        ip_address_opt,
                        hostname_opt,
                        comment_opt,
                        tags_opt,
                        aliases_opt,
                        event_timestamp.timestamp_micros(),
                        event_data_json,
                        envelope.created_at.timestamp_micros(),
                        envelope.created_by.as_deref().unwrap_or("system"),
                        expected_version,
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
                        ip_address,
                        hostname,
                        metadata,
                        event_timestamp,
                        created_at,
                        created_by
                    FROM host_events
                    WHERE aggregate_id = ?1
                    ORDER BY rowid ASC
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
            let mut current_state: Option<(String, String, Option<String>, Vec<String>)> = None;

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

                let event_data: EventData = serde_json::from_str(&metadata_json).map_err(|e| {
                    StorageError::InvalidData(format!(
                        "failed to deserialize event metadata: {}",
                        e
                    ))
                })?;

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

    /// Get current version for an aggregate
    pub(super) async fn get_current_version_impl(
        &self,
        aggregate_id: Ulid,
    ) -> Result<Option<String>, StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            // Use created_at for ordering - ULIDs within the same millisecond
            // have arbitrary lexicographic order
            let version = conn
                .lock()
                .query_row(
                    "SELECT event_version FROM host_events WHERE aggregate_id = ?1 ORDER BY rowid DESC LIMIT 1",
                    [&aggregate_id.to_string()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| StorageError::query("failed to get current version", e))?;

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
                    "SELECT COUNT(*) FROM host_events WHERE aggregate_id = ?1",
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
/// # Errors
///
/// Returns `StorageError::InvalidData` if tags cannot be serialized to JSON.
fn extract_event_data(event: &HostEvent) -> Result<ExtractedEventData, StorageError> {
    match event {
        HostEvent::HostCreated {
            ip_address,
            hostname,
            aliases,
            comment,
            tags,
            created_at,
        } => Ok((
            Some(ip_address.clone()),
            Some(hostname.clone()),
            comment.clone(),
            Some(serde_json::to_string(tags).map_err(|e| {
                StorageError::InvalidData(format!("failed to serialize tags: {}", e))
            })?),
            Some(serde_json::to_string(aliases).map_err(|e| {
                StorageError::InvalidData(format!("failed to serialize aliases: {}", e))
            })?),
            *created_at,
            EventData {
                comment: comment.clone(),
                tags: Some(tags.clone()),
                aliases: Some(aliases.clone()),
                ..Default::default()
            },
        )),
        HostEvent::IpAddressChanged {
            old_ip,
            new_ip,
            changed_at,
        } => Ok((
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
        )),
        HostEvent::HostnameChanged {
            old_hostname,
            new_hostname,
            changed_at,
        } => Ok((
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
        )),
        HostEvent::CommentUpdated {
            old_comment,
            new_comment,
            updated_at,
        } => Ok((
            None,
            None,
            new_comment.clone(),
            None,
            None,
            *updated_at,
            EventData {
                comment: new_comment.clone(),
                previous_comment: old_comment.clone(),
                ..Default::default()
            },
        )),
        HostEvent::TagsModified {
            old_tags,
            new_tags,
            modified_at,
        } => Ok((
            None,
            None,
            None,
            Some(serde_json::to_string(new_tags).map_err(|e| {
                StorageError::InvalidData(format!("failed to serialize tags: {}", e))
            })?),
            None,
            *modified_at,
            EventData {
                tags: Some(new_tags.clone()),
                previous_tags: Some(old_tags.clone()),
                ..Default::default()
            },
        )),
        HostEvent::AliasesModified {
            old_aliases,
            new_aliases,
            modified_at,
        } => Ok((
            None,
            None,
            None,
            None,
            Some(serde_json::to_string(new_aliases).map_err(|e| {
                StorageError::InvalidData(format!("failed to serialize aliases: {}", e))
            })?),
            *modified_at,
            EventData {
                aliases: Some(new_aliases.clone()),
                previous_aliases: Some(old_aliases.clone()),
                ..Default::default()
            },
        )),
        HostEvent::HostDeleted {
            ip_address,
            hostname,
            deleted_at,
            reason,
        } => Ok((
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
        )),
    }
}

/// Reconstruct a HostEvent from database columns
fn reconstruct_event(
    event_type: &str,
    ip_address: Option<String>,
    hostname: Option<String>,
    event_data: &EventData,
    event_timestamp: DateTime<Utc>,
    current_state: &mut Option<(String, String, Option<String>, Vec<String>)>,
) -> Result<HostEvent, StorageError> {
    match event_type {
        "HostCreated" => {
            let ip = ip_address.ok_or_else(|| {
                StorageError::InvalidData("HostCreated missing ip_address".into())
            })?;
            let host = hostname
                .ok_or_else(|| StorageError::InvalidData("HostCreated missing hostname".into()))?;

            let tags = event_data.tags.clone().unwrap_or_default();
            let comment = event_data.comment.clone();

            *current_state = Some((ip.clone(), host.clone(), comment.clone(), tags.clone()));

            Ok(HostEvent::HostCreated {
                ip_address: ip,
                hostname: host,
                aliases: event_data.aliases.clone().unwrap_or_default(),
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

            if let Some((ref mut ip, _, _, _)) = current_state {
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

            if let Some((_, ref mut host, _, _)) = current_state {
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

            if let Some((_, _, ref mut c, _)) = current_state {
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

            if let Some((_, _, _, ref mut tags)) = current_state {
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

            *current_state = None;

            Ok(event)
        }
        _ => Err(StorageError::InvalidData(format!(
            "unknown event type: {}",
            event_type
        ))),
    }
}
