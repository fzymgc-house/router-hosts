//! EventStore implementation for SQLite using sqlx
//!
//! This module implements the event sourcing write side:
//! - Append events with optimistic concurrency control
//! - Load event streams for aggregates
//! - Version management for conflict detection
//!
//! All operations use transactions for atomicity.
//!
//! # Note on Ordering
//!
//! SQLite queries use `ORDER BY rowid` for insertion order because ULIDs
//! created within the same millisecond have arbitrary lexicographic order.

use chrono::{DateTime, Utc};
use sqlx::Row;
use ulid::Ulid;

use super::SqliteStorage;
use crate::error::StorageError;
use crate::types::{EventEnvelope, HostEvent};

/// Serialize a value to JSON, returning an error if serialization fails.
///
/// Unlike using `.unwrap_or_else()`, this ensures serialization failures are
/// propagated as errors rather than silently falling back to default values.
fn serialize_json<T: serde::Serialize>(
    value: &T,
    field_name: &str,
) -> Result<String, StorageError> {
    serde_json::to_string(value).map_err(|e| {
        StorageError::InvalidData(format!("failed to serialize {}: {}", field_name, e))
    })
}

/// Convert a timestamp to microseconds.
///
/// chrono 0.4.34+ changed `timestamp_micros()` to return `i64` directly
/// (previously returned `Option<i64>` via `timestamp_micros_opt()`).
///
/// # Panics
///
/// Panics if the timestamp is outside the representable range for i64
/// microseconds since Unix epoch. Valid range: 1970-01-01 00:00:00 UTC
/// to 294247-01-10 04:00:54 UTC. In practice, this is unreachable for
/// any realistic timestamps.
fn timestamp_to_micros(ts: &DateTime<Utc>) -> i64 {
    ts.timestamp_micros()
}

/// Event-specific metadata serialized as JSON in the database.
///
/// Used for storing additional event data that doesn't have dedicated columns,
/// and for reconstructing events when loading from the database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct EventData {
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aliases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_aliases: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted_reason: Option<String>,
}

/// Intermediate struct for database INSERT operations.
///
/// Contains typed column values extracted from a `HostEvent` plus the
/// serialized metadata JSON. The timestamp is stored as microseconds
/// since epoch (i64) rather than `DateTime<Utc>` for direct database binding.
///
/// # Timestamp Range
///
/// Timestamps are stored as i64 microseconds since Unix epoch (1970-01-01).
/// Valid range: 1970-01-01 00:00:00 UTC to 294247-01-10 04:00:54 UTC
/// (i64::MAX microseconds). This exceeds any practical deployment lifetime.
struct ExtractedEventData {
    ip_address: Option<String>,
    hostname: Option<String>,
    comment: Option<String>,
    tags: Option<String>,
    aliases: Option<String>,
    event_timestamp: i64,
    metadata_json: String,
}

impl SqliteStorage {
    /// Append a single event
    pub(crate) async fn append_event_impl(
        &self,
        aggregate_id: Ulid,
        event: EventEnvelope,
        expected_version: Option<String>,
    ) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::query("failed to begin transaction", e))?;

        // Check for duplicate on HostCreated
        //
        // Note: This check is within a transaction, but SQLite's single-writer model
        // (enforced by WAL mode) means only one write transaction can be active at a
        // time. This prevents the classic TOCTOU race where two transactions both see
        // "no duplicate" and then both insert. The second writer will block until the
        // first commits, at which point it will see the committed data.
        //
        // For deployments requiring stronger isolation (e.g., multi-instance with
        // PostgreSQL), consider using a unique constraint on a materialized table.
        if let HostEvent::HostCreated {
            ref ip_address,
            ref hostname,
            ..
        } = event.event
        {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM host_entries_current WHERE ip_address = ?1 AND hostname = ?2)",
            )
            .bind(ip_address)
            .bind(hostname)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| StorageError::query("duplicate check failed", e))?;

            if exists {
                return Err(StorageError::DuplicateEntry {
                    ip: ip_address.clone(),
                    hostname: hostname.clone(),
                });
            }
        }

        // Version check - use rowid for ordering, not event_version
        let current_version: Option<String> = sqlx::query_scalar(
            "SELECT event_version FROM host_events WHERE aggregate_id = ?1 ORDER BY rowid DESC LIMIT 1",
        )
        .bind(aggregate_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| StorageError::query("version check failed", e))?;

        // Transaction is automatically rolled back when dropped on early return.
        // sqlx transactions implement Drop, so no explicit rollback is needed.
        if expected_version != current_version {
            return Err(StorageError::ConcurrentWriteConflict {
                aggregate_id: aggregate_id.to_string(),
            });
        }

        // Extract event data
        let extracted = extract_event_data(&event.event)?;

        // Insert event (SQLite uses INTEGER for timestamps as microseconds)
        sqlx::query(
            r#"
            INSERT INTO host_events (
                event_id, aggregate_id, event_type, event_version,
                ip_address, hostname, comment, tags, aliases,
                event_timestamp, metadata,
                created_at, created_by, expected_version
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
        )
        .bind(event.event_id.to_string())
        .bind(aggregate_id.to_string())
        .bind(event.event.event_type())
        .bind(&event.event_version)
        .bind(&extracted.ip_address)
        .bind(&extracted.hostname)
        .bind(&extracted.comment)
        .bind(&extracted.tags)
        .bind(&extracted.aliases)
        .bind(extracted.event_timestamp)
        .bind(&extracted.metadata_json)
        .bind(timestamp_to_micros(&event.created_at))
        .bind(&event.created_by)
        .bind(&expected_version)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            // Use sqlx's typed error detection instead of string matching
            if let Some(db_err) = e.as_database_error() {
                if db_err.is_unique_violation() {
                    return StorageError::ConcurrentWriteConflict {
                        aggregate_id: aggregate_id.to_string(),
                    };
                }
            }
            StorageError::query("insert event failed", e)
        })?;

        tx.commit()
            .await
            .map_err(|e| StorageError::query("commit failed", e))?;

        Ok(())
    }

    /// Append multiple events atomically
    pub(crate) async fn append_events_impl(
        &self,
        aggregate_id: Ulid,
        events: Vec<EventEnvelope>,
        expected_version: Option<String>,
    ) -> Result<(), StorageError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::query("failed to begin transaction", e))?;

        // Version check - use rowid for ordering
        let current_version: Option<String> = sqlx::query_scalar(
            "SELECT event_version FROM host_events WHERE aggregate_id = ?1 ORDER BY rowid DESC LIMIT 1",
        )
        .bind(aggregate_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| StorageError::query("version check failed", e))?;

        // Transaction is automatically rolled back when dropped on early return.
        // sqlx transactions implement Drop, so no explicit rollback is needed.
        if expected_version != current_version {
            return Err(StorageError::ConcurrentWriteConflict {
                aggregate_id: aggregate_id.to_string(),
            });
        }

        // Check for duplicates on any HostCreated events
        for event in &events {
            if let HostEvent::HostCreated {
                ref ip_address,
                ref hostname,
                ..
            } = event.event
            {
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM host_entries_current WHERE ip_address = ?1 AND hostname = ?2)",
                )
                .bind(ip_address)
                .bind(hostname)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| StorageError::query("duplicate check failed", e))?;

                if exists {
                    return Err(StorageError::DuplicateEntry {
                        ip: ip_address.clone(),
                        hostname: hostname.clone(),
                    });
                }
            }
        }

        // Insert all events
        for event in events {
            let extracted = extract_event_data(&event.event)?;

            sqlx::query(
                r#"
                INSERT INTO host_events (
                    event_id, aggregate_id, event_type, event_version,
                    ip_address, hostname, comment, tags, aliases,
                    event_timestamp, metadata,
                    created_at, created_by, expected_version
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                "#,
            )
            .bind(event.event_id.to_string())
            .bind(aggregate_id.to_string())
            .bind(event.event.event_type())
            .bind(&event.event_version)
            .bind(&extracted.ip_address)
            .bind(&extracted.hostname)
            .bind(&extracted.comment)
            .bind(&extracted.tags)
            .bind(&extracted.aliases)
            .bind(extracted.event_timestamp)
            .bind(&extracted.metadata_json)
            .bind(timestamp_to_micros(&event.created_at))
            .bind(&event.created_by)
            .bind(&expected_version)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::query("insert event failed", e))?;
        }

        tx.commit()
            .await
            .map_err(|e| StorageError::query("commit failed", e))?;

        Ok(())
    }

    /// Load all events for an aggregate
    pub(crate) async fn load_events_impl(
        &self,
        aggregate_id: Ulid,
    ) -> Result<Vec<EventEnvelope>, StorageError> {
        // Use rowid for ordering to ensure insertion order
        let rows = sqlx::query(
            r#"
            SELECT
                event_id, aggregate_id, event_type, event_version,
                ip_address, hostname, metadata, event_timestamp,
                created_at, created_by
            FROM host_events
            WHERE aggregate_id = ?1
            ORDER BY rowid ASC
            "#,
        )
        .bind(aggregate_id.to_string())
        .fetch_all(self.pool())
        .await
        .map_err(|e| StorageError::query("load_events failed", e))?;

        let mut envelopes = Vec::with_capacity(rows.len());

        for row in rows {
            let event_id_str: String = row.get("event_id");
            let event_type: String = row.get("event_type");
            let event_version: String = row.get("event_version");
            let ip_address: Option<String> = row.get("ip_address");
            let hostname: Option<String> = row.get("hostname");
            let metadata_json: String = row.get("metadata");
            let event_timestamp_micros: i64 = row.get("event_timestamp");
            let created_at_micros: i64 = row.get("created_at");
            let created_by: Option<String> = row.get("created_by");

            let event_id = Ulid::from_string(&event_id_str)
                .map_err(|e| StorageError::InvalidData(format!("invalid event_id: {}", e)))?;

            let event_timestamp = DateTime::from_timestamp_micros(event_timestamp_micros)
                .ok_or_else(|| {
                    StorageError::InvalidData(format!(
                        "invalid event_timestamp: {}",
                        event_timestamp_micros
                    ))
                })?;

            let created_at =
                DateTime::from_timestamp_micros(created_at_micros).ok_or_else(|| {
                    StorageError::InvalidData(format!("invalid created_at: {}", created_at_micros))
                })?;

            let event_data: EventData = serde_json::from_str(&metadata_json)
                .map_err(|e| StorageError::InvalidData(format!("JSON parse failed: {}", e)))?;

            let event = reconstruct_event(
                &event_type,
                ip_address,
                hostname,
                event_timestamp,
                &event_data,
            )?;

            envelopes.push(EventEnvelope {
                event_id,
                aggregate_id,
                event,
                event_version,
                created_at,
                created_by,
            });
        }

        Ok(envelopes)
    }

    /// Get current version for an aggregate
    pub(crate) async fn get_current_version_impl(
        &self,
        aggregate_id: Ulid,
    ) -> Result<Option<String>, StorageError> {
        // Use rowid for ordering
        let version: Option<String> = sqlx::query_scalar(
            "SELECT event_version FROM host_events WHERE aggregate_id = ?1 ORDER BY rowid DESC LIMIT 1",
        )
        .bind(aggregate_id.to_string())
        .fetch_optional(self.pool())
        .await
        .map_err(|e| StorageError::query("get_current_version failed", e))?;

        Ok(version)
    }

    /// Count events for an aggregate
    pub(crate) async fn count_events_impl(&self, aggregate_id: Ulid) -> Result<i64, StorageError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM host_events WHERE aggregate_id = ?1")
                .bind(aggregate_id.to_string())
                .fetch_one(self.pool())
                .await
                .map_err(|e| StorageError::query("count_events failed", e))?;

        Ok(count)
    }
}

/// Extract column values and metadata JSON from an event.
///
/// Separates event data into:
/// - Typed columns (ip_address, hostname, comment, tags, aliases) for indexed queries
/// - JSON metadata for event-type-specific data (previous values, deleted_reason)
///
/// The timestamp is converted to microseconds for SQLite INTEGER storage.
fn extract_event_data(event: &HostEvent) -> Result<ExtractedEventData, StorageError> {
    let (ip_address, hostname, comment, tags, aliases, event_timestamp, event_data) = match event {
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
            comment.clone(),
            Some(serialize_json(tags, "tags")?),
            Some(serialize_json(aliases, "aliases")?),
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
            new_comment.clone(),
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
            Some(serialize_json(new_tags, "tags")?),
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
            Some(serialize_json(new_aliases, "aliases")?),
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
    };

    let metadata_json = serialize_json(&event_data, "event metadata")?;

    Ok(ExtractedEventData {
        ip_address,
        hostname,
        comment,
        tags,
        aliases,
        event_timestamp: timestamp_to_micros(&event_timestamp),
        metadata_json,
    })
}

/// Reconstruct a HostEvent from database columns
fn reconstruct_event(
    event_type: &str,
    ip: Option<String>,
    hostname: Option<String>,
    event_ts: DateTime<Utc>,
    data: &EventData,
) -> Result<HostEvent, StorageError> {
    match event_type {
        "HostCreated" => Ok(HostEvent::HostCreated {
            ip_address: ip.ok_or_else(|| StorageError::InvalidData("missing ip".into()))?,
            hostname: hostname
                .ok_or_else(|| StorageError::InvalidData("missing hostname".into()))?,
            aliases: data.aliases.clone().unwrap_or_default(),
            comment: data.comment.clone(),
            tags: data.tags.clone().unwrap_or_default(),
            created_at: event_ts,
        }),
        "IpAddressChanged" => Ok(HostEvent::IpAddressChanged {
            old_ip: data
                .previous_ip
                .clone()
                .ok_or_else(|| StorageError::InvalidData("missing previous_ip".into()))?,
            new_ip: ip.ok_or_else(|| StorageError::InvalidData("missing ip".into()))?,
            changed_at: event_ts,
        }),
        "HostnameChanged" => Ok(HostEvent::HostnameChanged {
            old_hostname: data
                .previous_hostname
                .clone()
                .ok_or_else(|| StorageError::InvalidData("missing previous_hostname".into()))?,
            new_hostname: hostname
                .ok_or_else(|| StorageError::InvalidData("missing hostname".into()))?,
            changed_at: event_ts,
        }),
        "CommentUpdated" => Ok(HostEvent::CommentUpdated {
            old_comment: data.previous_comment.clone(),
            new_comment: data.comment.clone(),
            updated_at: event_ts,
        }),
        "TagsModified" => Ok(HostEvent::TagsModified {
            old_tags: data.previous_tags.clone().ok_or_else(|| {
                StorageError::InvalidData("TagsModified missing previous_tags".into())
            })?,
            new_tags: data
                .tags
                .clone()
                .ok_or_else(|| StorageError::InvalidData("TagsModified missing tags".into()))?,
            modified_at: event_ts,
        }),
        "AliasesModified" => Ok(HostEvent::AliasesModified {
            old_aliases: data.previous_aliases.clone().ok_or_else(|| {
                StorageError::InvalidData("AliasesModified missing previous_aliases".into())
            })?,
            new_aliases: data.aliases.clone().ok_or_else(|| {
                StorageError::InvalidData("AliasesModified missing aliases".into())
            })?,
            modified_at: event_ts,
        }),
        "HostDeleted" => Ok(HostEvent::HostDeleted {
            ip_address: ip.ok_or_else(|| StorageError::InvalidData("missing ip".into()))?,
            hostname: hostname
                .ok_or_else(|| StorageError::InvalidData("missing hostname".into()))?,
            deleted_at: event_ts,
            reason: data.deleted_reason.clone(),
        }),
        _ => Err(StorageError::InvalidData(format!(
            "unknown event type: {}",
            event_type
        ))),
    }
}
