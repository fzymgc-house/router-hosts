//! Host projection implementation for SQLite (CQRS read side)
//!
//! This module implements the materialized view of current host entries:
//! - List all hosts
//! - Get host by ID
//! - Find host by IP + hostname (duplicate detection)
//! - Search hosts with filters (IP pattern, hostname pattern, tags)
//! - Time-travel queries (get state at specific timestamp)
//!
//! The projection is built by replaying events from the event store.
//! It provides optimized queries for the read side of CQRS.
//!
//! See `mod.rs` module docs for performance characteristics and scaling guidance.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use tracing::error;
use ulid::Ulid;

use super::SqliteStorage;
use crate::error::StorageError;
use crate::types::{HostEntry, HostFilter};

/// Row type for host entry queries from the `host_entries_current` view.
///
/// Uses `#[derive(FromRow)]` for automatic mapping from database columns.
/// Field names must match SQL column names exactly.
#[derive(Debug, FromRow)]
struct HostEntryRow {
    id: String,
    ip_address: String,
    hostname: String,
    comment: Option<String>,
    tags: Option<String>,
    aliases: Option<String>,
    created_at: i64,
    updated_at: i64,
    event_version: String,
}

/// Row type for event queries used in time-travel reconstruction.
#[derive(Debug, FromRow)]
struct EventRow {
    event_type: String,
    ip_address: Option<String>,
    hostname: Option<String>,
    metadata: String,
    event_timestamp: i64,
}

/// Intermediate state for rebuilding host from events.
#[derive(Debug)]
struct HostState {
    ip_address: String,
    hostname: String,
    comment: Option<String>,
    tags: Vec<String>,
    aliases: Vec<String>,
}

/// Parse a JSON string array, returning an error if parsing fails.
///
/// This ensures corrupt or malformed JSON doesn't silently become empty data.
fn parse_json_array(json: Option<String>, field_name: &str) -> Result<Vec<String>, StorageError> {
    match json {
        Some(s) if !s.is_empty() => serde_json::from_str(&s).map_err(|e| {
            StorageError::InvalidData(format!(
                "failed to parse {} JSON '{}': {}",
                field_name, s, e
            ))
        }),
        _ => Ok(Vec::new()),
    }
}

/// Parse a JSON array from event metadata, returning an error if parsing fails.
///
/// Used for extracting tags/aliases from event metadata during time-travel queries.
fn parse_event_json_array(
    event_data: &serde_json::Value,
    field_name: &str,
) -> Result<Vec<String>, StorageError> {
    match event_data.get(field_name) {
        Some(value) => serde_json::from_value(value.clone()).map_err(|e| {
            StorageError::InvalidData(format!(
                "failed to parse {} from event metadata: {}",
                field_name, e
            ))
        }),
        None => Ok(Vec::new()),
    }
}

/// Convert a database row to a HostEntry.
///
/// Handles ULID parsing, timestamp conversion, and JSON array parsing
/// with proper error propagation.
fn row_to_host_entry(row: HostEntryRow) -> Result<HostEntry, StorageError> {
    let id = Ulid::from_string(&row.id)
        .map_err(|e| StorageError::InvalidData(format!("invalid ULID '{}': {}", row.id, e)))?;

    // Empty string means no comment
    let comment = row.comment.filter(|s| !s.is_empty());

    // Parse JSON arrays with proper error handling
    let tags = parse_json_array(row.tags, "tags")?;
    let aliases = parse_json_array(row.aliases, "aliases")?;

    let created_at = DateTime::from_timestamp_micros(row.created_at).ok_or_else(|| {
        StorageError::InvalidData(format!("invalid created_at timestamp: {}", row.created_at))
    })?;

    let updated_at = DateTime::from_timestamp_micros(row.updated_at).ok_or_else(|| {
        StorageError::InvalidData(format!("invalid updated_at timestamp: {}", row.updated_at))
    })?;

    Ok(HostEntry {
        id,
        ip_address: row.ip_address,
        hostname: row.hostname,
        aliases,
        comment,
        tags,
        created_at,
        updated_at,
        version: row.event_version,
    })
}

impl SqliteStorage {
    /// List all active host entries
    ///
    /// Uses the `host_entries_current` view which reconstructs current state
    /// from the event log. See module docs for performance characteristics.
    ///
    /// Results are sorted by IP address, then hostname.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    /// Returns `StorageError::InvalidData` if stored JSON is malformed.
    pub(super) async fn list_all_impl(&self) -> Result<Vec<HostEntry>, StorageError> {
        let rows: Vec<HostEntryRow> = sqlx::query_as(
            r#"
            SELECT
                id,
                ip_address,
                hostname,
                comment,
                tags,
                aliases,
                created_at,
                updated_at,
                event_version
            FROM host_entries_current
            ORDER BY ip_address, hostname
            "#,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| StorageError::query("failed to query host entries", e))?;

        rows.into_iter().map(row_to_host_entry).collect()
    }

    /// Get current state of a host entry by ID
    ///
    /// # Errors
    ///
    /// Returns `StorageError::NotFound` if the host doesn't exist or has been deleted.
    /// Returns `StorageError::Query` if the database operation fails.
    /// Returns `StorageError::InvalidData` if stored JSON is malformed.
    pub(super) async fn get_by_id_impl(&self, id: Ulid) -> Result<HostEntry, StorageError> {
        let id_str = id.to_string();

        let row: Option<HostEntryRow> = sqlx::query_as(
            r#"
            SELECT
                id,
                ip_address,
                hostname,
                comment,
                tags,
                aliases,
                created_at,
                updated_at,
                event_version
            FROM host_entries_current
            WHERE id = ?1
            "#,
        )
        .bind(&id_str)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| StorageError::query("failed to get host by id", e))?;

        match row {
            None => Err(StorageError::NotFound {
                entity_type: "host",
                id: id_str,
            }),
            Some(row) => row_to_host_entry(row),
        }
    }

    /// Find host by exact IP and hostname match
    ///
    /// This is used for duplicate detection when creating new host entries.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    /// Returns `StorageError::InvalidData` if stored JSON is malformed.
    pub(super) async fn find_by_ip_and_hostname_impl(
        &self,
        ip_address: &str,
        hostname: &str,
    ) -> Result<Option<HostEntry>, StorageError> {
        let row: Option<HostEntryRow> = sqlx::query_as(
            r#"
            SELECT
                id,
                ip_address,
                hostname,
                comment,
                tags,
                aliases,
                created_at,
                updated_at,
                event_version
            FROM host_entries_current
            WHERE ip_address = ?1 AND hostname = ?2
            "#,
        )
        .bind(ip_address)
        .bind(hostname)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| StorageError::query("failed to find host", e))?;

        row.map(row_to_host_entry).transpose()
    }

    /// Search hosts by IP address pattern, hostname pattern, or tags
    ///
    /// Filters are applied with LIKE pattern matching for IP/hostname.
    /// Tag filtering matches any entry with at least one of the specified tags.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    ///
    /// # Security
    ///
    /// Uses dynamic WHERE clause construction with parameterized values only - no user input
    /// is interpolated into SQL. All filter patterns are bound via `?` placeholders.
    pub(super) async fn search_impl(
        &self,
        filter: HostFilter,
    ) -> Result<Vec<HostEntry>, StorageError> {
        // Build dynamic WHERE clause and params
        // Security: All user input goes through params vector (parameterized), not string interpolation
        let mut where_clauses: Vec<String> = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if let Some(ip_pattern) = &filter.ip_pattern {
            where_clauses.push("ip_address LIKE ?".to_string());
            params.push(format!("%{}%", ip_pattern));
        }

        if let Some(hostname_pattern) = &filter.hostname_pattern {
            // Use LIKE with COLLATE NOCASE for case-insensitive matching (DNS is case-insensitive)
            where_clauses.push("(hostname LIKE ? COLLATE NOCASE OR EXISTS (SELECT 1 FROM json_each(aliases) WHERE value LIKE ? COLLATE NOCASE))".to_string());
            let pattern = format!("%{}%", hostname_pattern);
            params.push(pattern.clone());
            params.push(pattern);
        }

        // For tag filtering, check if any tag appears in the JSON array
        // Limit tag count to prevent query explosion from unbounded OR conditions
        const MAX_FILTER_TAGS: usize = 20;
        if let Some(tags) = &filter.tags {
            if tags.len() > MAX_FILTER_TAGS {
                return Err(StorageError::InvalidData(format!(
                    "too many filter tags: {} (max {})",
                    tags.len(),
                    MAX_FILTER_TAGS
                )));
            }
            if !tags.is_empty() {
                // Build OR conditions for each tag
                let tag_conditions: Vec<String> =
                    tags.iter().map(|_| "tags LIKE ?".to_string()).collect();

                where_clauses.push(format!("({})", tag_conditions.join(" OR ")));

                for tag in tags {
                    // Use LIKE pattern to find tag in JSON array
                    params.push(format!("%\"{}\"%", tag));
                }
            }
        }

        let where_clause = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let query = format!(
            r#"
            SELECT
                id,
                ip_address,
                hostname,
                comment,
                tags,
                aliases,
                created_at,
                updated_at,
                event_version
            FROM host_entries_current
            {}
            ORDER BY ip_address, hostname
            "#,
            where_clause
        );

        // For dynamic queries with variable parameters, we need to use sqlx::query
        // and bind each parameter individually
        let mut query_builder = sqlx::query_as::<_, HostEntryRow>(&query);

        for param in &params {
            query_builder = query_builder.bind(param);
        }

        let rows = query_builder
            .fetch_all(self.pool())
            .await
            .map_err(|e| StorageError::query("failed to execute search query", e))?;

        rows.into_iter().map(row_to_host_entry).collect()
    }

    /// Get historical state of all hosts at a specific point in time
    ///
    /// Replays events up to the given timestamp to reconstruct past state.
    /// Filters out deleted hosts.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    /// Returns `StorageError::InvalidData` if event data is malformed.
    pub(super) async fn get_at_time_impl(
        &self,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<HostEntry>, StorageError> {
        let at_time_micros = at_time.timestamp_micros();

        // Get all aggregates that have events before the cutoff time
        let aggregate_ids: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT aggregate_id
            FROM host_events
            WHERE created_at <= ?1
            "#,
        )
        .bind(at_time_micros)
        .fetch_all(self.pool())
        .await
        .map_err(|e| StorageError::query("failed to query aggregate ids", e))?;

        let mut entries = Vec::new();

        // For each aggregate, rebuild state from events up to the cutoff time
        for (aggregate_id_str,) in aggregate_ids {
            let aggregate_id = Ulid::from_string(&aggregate_id_str)
                .map_err(|e| StorageError::InvalidData(format!("invalid ULID: {}", e)))?;

            // Load events for this aggregate up to the cutoff time
            let event_rows: Vec<EventRow> = sqlx::query_as(
                r#"
                    SELECT
                        event_type,
                        ip_address,
                        hostname,
                        metadata,
                        event_timestamp
                    FROM host_events
                    WHERE aggregate_id = ?1 AND created_at <= ?2
                    ORDER BY rowid ASC
                    "#,
            )
            .bind(&aggregate_id_str)
            .bind(at_time_micros)
            .fetch_all(self.pool())
            .await
            .map_err(|e| StorageError::query("failed to query events", e))?;

            // Rebuild state by applying events
            let mut current_state: Option<HostState> = None;

            for row in event_rows {
                let _event_timestamp = DateTime::from_timestamp_micros(row.event_timestamp)
                    .ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid event timestamp: {}",
                            row.event_timestamp
                        ))
                    })?;

                // Deserialize metadata
                let event_data: serde_json::Value =
                    serde_json::from_str(&row.metadata).map_err(|e| {
                        StorageError::InvalidData(format!("failed to deserialize metadata: {}", e))
                    })?;

                // Apply event based on type
                match row.event_type.as_str() {
                    "HostCreated" => {
                        let ip = row.ip_address.ok_or_else(|| {
                            StorageError::InvalidData("HostCreated missing ip_address".into())
                        })?;
                        let host = row.hostname.ok_or_else(|| {
                            StorageError::InvalidData("HostCreated missing hostname".into())
                        })?;

                        let comment = event_data
                            .get("comment")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        let tags = parse_event_json_array(&event_data, "tags")?;
                        let aliases = parse_event_json_array(&event_data, "aliases")?;

                        current_state = Some(HostState {
                            ip_address: ip,
                            hostname: host,
                            comment,
                            tags,
                            aliases,
                        });
                    }
                    "IpAddressChanged" => {
                        if let Some(ref mut state) = current_state {
                            if let Some(new_ip) = row.ip_address {
                                state.ip_address = new_ip;
                            }
                        }
                    }
                    "HostnameChanged" => {
                        if let Some(ref mut state) = current_state {
                            if let Some(new_hostname) = row.hostname {
                                state.hostname = new_hostname;
                            }
                        }
                    }
                    "CommentUpdated" => {
                        if let Some(ref mut state) = current_state {
                            state.comment = event_data
                                .get("comment")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                        }
                    }
                    "TagsModified" => {
                        if let Some(ref mut state) = current_state {
                            state.tags = parse_event_json_array(&event_data, "tags")?;
                        }
                    }
                    "AliasesModified" => {
                        if let Some(ref mut state) = current_state {
                            state.aliases = parse_event_json_array(&event_data, "aliases")?;
                        }
                    }
                    "HostDeleted" => {
                        // Clear state - this host was deleted
                        current_state = None;
                    }
                    unknown => {
                        error!(
                            aggregate_id = %aggregate_id_str,
                            event_type = %unknown,
                            "unknown event type in time-travel query - possible version mismatch or data corruption, skipping"
                        );
                    }
                }
            }

            // If state exists (not deleted), add to results
            if let Some(state) = current_state {
                // For historical queries, we use a synthetic version and timestamp
                entries.push(HostEntry {
                    id: aggregate_id,
                    ip_address: state.ip_address,
                    hostname: state.hostname,
                    aliases: state.aliases,
                    comment: state.comment,
                    tags: state.tags,
                    created_at: at_time,
                    updated_at: at_time,
                    version: format!("historical-{}", at_time_micros),
                });
            }
        }

        // Sort by IP and hostname for consistency
        entries.sort_by(|a, b| {
            a.ip_address
                .cmp(&b.ip_address)
                .then_with(|| a.hostname.cmp(&b.hostname))
        });

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventEnvelope, HostEvent};
    use crate::{EventStore, Storage};

    async fn create_test_storage() -> SqliteStorage {
        let storage = SqliteStorage::new(":memory:")
            .await
            .expect("failed to create in-memory storage");
        storage.initialize().await.expect("failed to initialize");
        storage
    }

    #[tokio::test]
    async fn test_list_all_empty() {
        let storage = create_test_storage().await;

        let entries = storage.list_all_impl().await.expect("failed to list hosts");

        assert_eq!(entries.len(), 0);
    }

    #[tokio::test]
    async fn test_list_all_with_entries() {
        let storage = create_test_storage().await;

        // Create multiple hosts
        for i in 1..=3 {
            let aggregate_id = Ulid::new();
            let envelope = EventEnvelope {
                event_id: Ulid::new(),
                aggregate_id,
                event: HostEvent::HostCreated {
                    ip_address: format!("192.168.1.{}", i + 10),
                    hostname: format!("server{}.local", i),
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
                .append_event(aggregate_id, envelope, None)
                .await
                .expect("failed to append event");
        }

        let entries = storage.list_all_impl().await.expect("failed to list hosts");

        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn test_get_by_id() {
        let storage = create_test_storage().await;

        let aggregate_id = Ulid::new();
        let envelope = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                aliases: vec![],
                comment: Some("Test server".to_string()),
                tags: vec!["prod".to_string()],
                created_at: Utc::now(),
            },
            event_version: Ulid::new().to_string(),
            created_at: Utc::now(),
            created_by: None,
        };

        storage
            .append_event(aggregate_id, envelope, None)
            .await
            .expect("failed to append event");

        let entry = storage
            .get_by_id_impl(aggregate_id)
            .await
            .expect("failed to get host");

        assert_eq!(entry.id, aggregate_id);
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, Some("Test server".to_string()));
        assert_eq!(entry.tags, vec!["prod".to_string()]);
    }

    #[tokio::test]
    async fn test_get_by_id_not_found() {
        let storage = create_test_storage().await;

        let result = storage.get_by_id_impl(Ulid::new()).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StorageError::NotFound { .. }));
    }

    #[tokio::test]
    async fn test_find_by_ip_and_hostname() {
        let storage = create_test_storage().await;

        let aggregate_id = Ulid::new();
        let envelope = EventEnvelope {
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
            .append_event(aggregate_id, envelope, None)
            .await
            .expect("failed to append event");

        // Find existing host
        let result = storage
            .find_by_ip_and_hostname_impl("192.168.1.10", "server.local")
            .await
            .expect("failed to find host");

        assert!(result.is_some());
        assert_eq!(result.unwrap().id, aggregate_id);

        // Find non-existent host
        let result = storage
            .find_by_ip_and_hostname_impl("192.168.1.99", "nonexistent.local")
            .await
            .expect("failed to find host");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_search_by_ip_pattern() {
        let storage = create_test_storage().await;

        // Create multiple hosts
        let hosts = vec![
            ("192.168.1.10", "server1.local"),
            ("192.168.1.20", "server2.local"),
            ("10.0.0.1", "gateway.local"),
        ];

        for (ip, hostname) in hosts {
            let envelope = EventEnvelope {
                event_id: Ulid::new(),
                aggregate_id: Ulid::new(),
                event: HostEvent::HostCreated {
                    ip_address: ip.to_string(),
                    hostname: hostname.to_string(),
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
                .append_event(envelope.aggregate_id, envelope, None)
                .await
                .expect("failed to append event");
        }

        // Search by IP pattern
        let filter = HostFilter {
            ip_pattern: Some("192.168.1".to_string()),
            hostname_pattern: None,
            tags: None,
        };

        let results = storage.search_impl(filter).await.expect("failed to search");

        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|e| e.ip_address.starts_with("192.168.1")));
    }

    #[tokio::test]
    async fn test_search_by_tag() {
        let storage = create_test_storage().await;

        // Create hosts with different tags
        let envelope1 = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id: Ulid::new(),
            event: HostEvent::HostCreated {
                ip_address: "192.168.1.10".to_string(),
                hostname: "prod1.local".to_string(),
                aliases: vec![],
                comment: None,
                tags: vec!["production".to_string(), "critical".to_string()],
                created_at: Utc::now(),
            },
            event_version: Ulid::new().to_string(),
            created_at: Utc::now(),
            created_by: None,
        };

        let envelope2 = EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id: Ulid::new(),
            event: HostEvent::HostCreated {
                ip_address: "192.168.1.20".to_string(),
                hostname: "dev1.local".to_string(),
                aliases: vec![],
                comment: None,
                tags: vec!["development".to_string()],
                created_at: Utc::now(),
            },
            event_version: Ulid::new().to_string(),
            created_at: Utc::now(),
            created_by: None,
        };

        storage
            .append_event(envelope1.aggregate_id, envelope1, None)
            .await
            .expect("failed to append event");

        storage
            .append_event(envelope2.aggregate_id, envelope2, None)
            .await
            .expect("failed to append event");

        // Search by tag
        let filter = HostFilter {
            ip_pattern: None,
            hostname_pattern: None,
            tags: Some(vec!["production".to_string()]),
        };

        let results = storage.search_impl(filter).await.expect("failed to search");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hostname, "prod1.local");
    }
}
