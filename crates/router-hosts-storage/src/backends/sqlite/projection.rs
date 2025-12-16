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

use chrono::{DateTime, Utc};
use rusqlite::OptionalExtension;
use ulid::Ulid;

use super::SqliteStorage;
use crate::error::StorageError;
use crate::types::{HostEntry, HostFilter};

impl SqliteStorage {
    /// List all active host entries
    ///
    /// Uses the `host_entries_current` view for O(n) performance
    /// instead of N+1 queries.
    ///
    /// Results are sorted by IP address, then hostname.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn list_all_impl(&self) -> Result<Vec<HostEntry>, StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();
            let mut stmt = conn
                .prepare(
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
                .map_err(|e| StorageError::query("failed to prepare list query", e))?;

            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,         // id
                        row.get::<_, String>(1)?,         // ip_address
                        row.get::<_, String>(2)?,         // hostname
                        row.get::<_, Option<String>>(3)?, // comment (nullable)
                        row.get::<_, Option<String>>(4)?, // tags (JSON array, nullable)
                        row.get::<_, Option<String>>(5)?, // aliases (JSON array, nullable)
                        row.get::<_, i64>(6)?,            // created_at
                        row.get::<_, i64>(7)?,            // updated_at
                        row.get::<_, String>(8)?,         // event_version
                    ))
                })
                .map_err(|e| StorageError::query("failed to query host entries", e))?;

            let mut entries = Vec::new();
            for row_result in rows {
                let (
                    id_str,
                    ip_address,
                    hostname,
                    comment_str,
                    tags_json,
                    aliases_json,
                    created_at_micros,
                    updated_at_micros,
                    version,
                ) = row_result.map_err(|e| StorageError::query("failed to read row", e))?;

                let id = Ulid::from_string(&id_str)
                    .map_err(|e| StorageError::InvalidData(format!("invalid ULID: {}", e)))?;

                // Parse comment: empty string means no comment
                let comment = comment_str.filter(|s| !s.is_empty());

                // Parse tags from JSON array
                let tags: Vec<String> = tags_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();

                // Parse aliases from JSON array
                let aliases: Vec<String> = aliases_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();

                let created_at =
                    DateTime::from_timestamp_micros(created_at_micros).ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid created_at timestamp: {}",
                            created_at_micros
                        ))
                    })?;

                let updated_at =
                    DateTime::from_timestamp_micros(updated_at_micros).ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid updated_at timestamp: {}",
                            updated_at_micros
                        ))
                    })?;

                entries.push(HostEntry {
                    id,
                    ip_address,
                    hostname,
                    aliases,
                    comment,
                    tags,
                    created_at,
                    updated_at,
                    version,
                });
            }

            Ok(entries)
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during list_all", e))?
    }

    /// Get current state of a host entry by ID
    ///
    /// # Errors
    ///
    /// Returns `StorageError::NotFound` if the host doesn't exist or has been deleted.
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn get_by_id_impl(&self, id: Ulid) -> Result<HostEntry, StorageError> {
        let id_str = id.to_string();
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let result = conn
                .lock()
                .query_row(
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
                    rusqlite::params![&id_str],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,         // id
                            row.get::<_, String>(1)?,         // ip_address
                            row.get::<_, String>(2)?,         // hostname
                            row.get::<_, Option<String>>(3)?, // comment
                            row.get::<_, Option<String>>(4)?, // tags
                            row.get::<_, Option<String>>(5)?, // aliases
                            row.get::<_, i64>(6)?,            // created_at
                            row.get::<_, i64>(7)?,            // updated_at
                            row.get::<_, String>(8)?,         // event_version
                        ))
                    },
                )
                .optional()
                .map_err(|e| StorageError::query("failed to get host by id", e))?;

            match result {
                None => Err(StorageError::NotFound {
                    entity_type: "host",
                    id: id_str,
                }),
                Some((
                    id_str,
                    ip_address,
                    hostname,
                    comment_str,
                    tags_json,
                    aliases_json,
                    created_at_micros,
                    updated_at_micros,
                    version,
                )) => {
                    let id = Ulid::from_string(&id_str)
                        .map_err(|e| StorageError::InvalidData(format!("invalid ULID: {}", e)))?;

                    let comment = comment_str.filter(|s| !s.is_empty());
                    let tags: Vec<String> = tags_json
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();
                    let aliases: Vec<String> = aliases_json
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();

                    let created_at = DateTime::from_timestamp_micros(created_at_micros)
                        .ok_or_else(|| {
                            StorageError::InvalidData(format!(
                                "invalid created_at timestamp: {}",
                                created_at_micros
                            ))
                        })?;

                    let updated_at = DateTime::from_timestamp_micros(updated_at_micros)
                        .ok_or_else(|| {
                            StorageError::InvalidData(format!(
                                "invalid updated_at timestamp: {}",
                                updated_at_micros
                            ))
                        })?;

                    Ok(HostEntry {
                        id,
                        ip_address,
                        hostname,
                        aliases,
                        comment,
                        tags,
                        created_at,
                        updated_at,
                        version,
                    })
                }
            }
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during get_by_id", e))?
    }

    /// Find host by exact IP and hostname match
    ///
    /// This is used for duplicate detection when creating new host entries.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn find_by_ip_and_hostname_impl(
        &self,
        ip_address: &str,
        hostname: &str,
    ) -> Result<Option<HostEntry>, StorageError> {
        let ip_address = ip_address.to_string();
        let hostname = hostname.to_string();
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let result = conn
                .lock()
                .query_row(
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
                    rusqlite::params![&ip_address, &hostname],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,         // id
                            row.get::<_, String>(1)?,         // ip_address
                            row.get::<_, String>(2)?,         // hostname
                            row.get::<_, Option<String>>(3)?, // comment
                            row.get::<_, Option<String>>(4)?, // tags
                            row.get::<_, Option<String>>(5)?, // aliases
                            row.get::<_, i64>(6)?,            // created_at
                            row.get::<_, i64>(7)?,            // updated_at
                            row.get::<_, String>(8)?,         // event_version
                        ))
                    },
                )
                .optional()
                .map_err(|e| StorageError::query("failed to find host", e))?;

            match result {
                None => Ok(None),
                Some((
                    id_str,
                    ip_address,
                    hostname,
                    comment_str,
                    tags_json,
                    aliases_json,
                    created_at_micros,
                    updated_at_micros,
                    version,
                )) => {
                    let id = Ulid::from_string(&id_str)
                        .map_err(|e| StorageError::InvalidData(format!("invalid ULID: {}", e)))?;

                    let comment = comment_str.filter(|s| !s.is_empty());
                    let tags: Vec<String> = tags_json
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();
                    let aliases: Vec<String> = aliases_json
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_default();

                    let created_at = DateTime::from_timestamp_micros(created_at_micros)
                        .ok_or_else(|| {
                            StorageError::InvalidData(format!(
                                "invalid created_at timestamp: {}",
                                created_at_micros
                            ))
                        })?;

                    let updated_at = DateTime::from_timestamp_micros(updated_at_micros)
                        .ok_or_else(|| {
                            StorageError::InvalidData(format!(
                                "invalid updated_at timestamp: {}",
                                updated_at_micros
                            ))
                        })?;

                    Ok(Some(HostEntry {
                        id,
                        ip_address,
                        hostname,
                        aliases,
                        comment,
                        tags,
                        created_at,
                        updated_at,
                        version,
                    }))
                }
            }
        })
        .await
        .map_err(|e| {
            StorageError::connection("spawn_blocking panicked during find_by_ip_and_hostname", e)
        })?
    }

    /// Search hosts by IP address pattern, hostname pattern, or tags
    ///
    /// Filters are applied with LIKE pattern matching for IP/hostname.
    /// Tag filtering matches any entry with at least one of the specified tags.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn search_impl(
        &self,
        filter: HostFilter,
    ) -> Result<Vec<HostEntry>, StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            // Build dynamic WHERE clause and params
            let mut where_clauses: Vec<String> = Vec::new();
            let mut params: Vec<String> = Vec::new();

            if let Some(ip_pattern) = &filter.ip_pattern {
                where_clauses.push("ip_address LIKE ?".to_string());
                params.push(format!("%{}%", ip_pattern));
            }

            if let Some(hostname_pattern) = &filter.hostname_pattern {
                where_clauses.push("(hostname LIKE ? OR EXISTS (SELECT 1 FROM json_each(aliases) WHERE value LIKE ?))".to_string());
                let pattern = format!("%{}%", hostname_pattern);
                params.push(pattern.clone());
                params.push(pattern);
            }

            // For tag filtering, check if any tag appears in the JSON array
            if let Some(tags) = &filter.tags {
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

            let conn = conn.lock();
            let mut stmt = conn
                .prepare(&query)
                .map_err(|e| StorageError::query("failed to prepare search query", e))?;

            // Convert params to references for query_map
            let param_refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();

            let rows = stmt
                .query_map(param_refs.as_slice(), |row| {
                    Ok((
                        row.get::<_, String>(0)?,         // id
                        row.get::<_, String>(1)?,         // ip_address
                        row.get::<_, String>(2)?,         // hostname
                        row.get::<_, Option<String>>(3)?, // comment
                        row.get::<_, Option<String>>(4)?, // tags
                        row.get::<_, Option<String>>(5)?, // aliases
                        row.get::<_, i64>(6)?,            // created_at
                        row.get::<_, i64>(7)?,            // updated_at
                        row.get::<_, String>(8)?,         // event_version
                    ))
                })
                .map_err(|e| StorageError::query("failed to execute search query", e))?;

            let mut entries = Vec::new();
            for row_result in rows {
                let (
                    id_str,
                    ip_address,
                    hostname,
                    comment_str,
                    tags_json,
                    aliases_json,
                    created_at_micros,
                    updated_at_micros,
                    version,
                ) = row_result.map_err(|e| StorageError::query("failed to read search row", e))?;

                let id = Ulid::from_string(&id_str)
                    .map_err(|e| StorageError::InvalidData(format!("invalid ULID: {}", e)))?;

                let comment = comment_str.filter(|s| !s.is_empty());
                let tags: Vec<String> = tags_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                let aliases: Vec<String> = aliases_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();

                let created_at =
                    DateTime::from_timestamp_micros(created_at_micros).ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid created_at timestamp: {}",
                            created_at_micros
                        ))
                    })?;

                let updated_at =
                    DateTime::from_timestamp_micros(updated_at_micros).ok_or_else(|| {
                        StorageError::InvalidData(format!(
                            "invalid updated_at timestamp: {}",
                            updated_at_micros
                        ))
                    })?;

                entries.push(HostEntry {
                    id,
                    ip_address,
                    hostname,
                    aliases,
                    comment,
                    tags,
                    created_at,
                    updated_at,
                    version,
                });
            }

            Ok(entries)
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during search", e))?
    }

    /// Get historical state of all hosts at a specific point in time
    ///
    /// Replays events up to the given timestamp to reconstruct past state.
    /// Filters out deleted hosts.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    pub(super) async fn get_at_time_impl(
        &self,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<HostEntry>, StorageError> {
        let conn = self.conn();

        tokio::task::spawn_blocking(move || {
            let conn = conn.lock();
            let at_time_micros = at_time.timestamp_micros();

            // Get all aggregates that have events before the cutoff time
            let mut stmt = conn
                .prepare(
                    r#"
                    SELECT DISTINCT aggregate_id
                    FROM host_events
                    WHERE created_at <= ?1
                    "#,
                )
                .map_err(|e| StorageError::query("failed to prepare aggregate query", e))?;

            let aggregate_ids: Result<Vec<String>, rusqlite::Error> = stmt
                .query_map(rusqlite::params![at_time_micros], |row| row.get(0))
                .map_err(|e| StorageError::query("failed to query aggregate ids", e))?
                .collect();

            let aggregate_ids =
                aggregate_ids.map_err(|e| StorageError::query("failed to get aggregate ids", e))?;

            let mut entries = Vec::new();

            // For each aggregate, rebuild state from events up to the cutoff time
            for aggregate_id_str in aggregate_ids {
                let aggregate_id = Ulid::from_string(&aggregate_id_str)
                    .map_err(|e| StorageError::InvalidData(format!("invalid ULID: {}", e)))?;

                // Load events for this aggregate up to the cutoff time
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
                        WHERE aggregate_id = ?1 AND created_at <= ?2
                        ORDER BY rowid ASC
                        "#,
                    )
                    .map_err(|e| StorageError::query("failed to prepare event query", e))?;

                let rows = stmt
                    .query_map(
                        rusqlite::params![&aggregate_id_str, at_time_micros],
                        |row| {
                            Ok((
                                row.get::<_, String>(2)?,         // event_type
                                row.get::<_, Option<String>>(4)?, // ip_address
                                row.get::<_, Option<String>>(5)?, // hostname
                                row.get::<_, String>(6)?,         // metadata
                                row.get::<_, i64>(7)?,            // event_timestamp
                            ))
                        },
                    )
                    .map_err(|e| StorageError::query("failed to query events", e))?;

                // Rebuild state by applying events (ip, hostname, comment, tags, aliases)
                let mut current_state: Option<(
                    String,
                    String,
                    Option<String>,
                    Vec<String>,
                    Vec<String>,
                )> = None;

                for row in rows {
                    let (event_type, ip_address, hostname, metadata_json, event_timestamp_micros) =
                        row.map_err(|e| StorageError::query("failed to read event row", e))?;

                    let _event_timestamp = DateTime::from_timestamp_micros(event_timestamp_micros)
                        .ok_or_else(|| {
                            StorageError::InvalidData(format!(
                                "invalid event timestamp: {}",
                                event_timestamp_micros
                            ))
                        })?;

                    // Deserialize metadata
                    let event_data: serde_json::Value = serde_json::from_str(&metadata_json)
                        .map_err(|e| {
                            StorageError::InvalidData(format!(
                                "failed to deserialize metadata: {}",
                                e
                            ))
                        })?;

                    // Apply event based on type
                    match event_type.as_str() {
                        "HostCreated" => {
                            let ip = ip_address.ok_or_else(|| {
                                StorageError::InvalidData("HostCreated missing ip_address".into())
                            })?;
                            let host = hostname.ok_or_else(|| {
                                StorageError::InvalidData("HostCreated missing hostname".into())
                            })?;

                            let comment = event_data
                                .get("comment")
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let tags: Vec<String> = event_data
                                .get("tags")
                                .and_then(|v| serde_json::from_value(v.clone()).ok())
                                .unwrap_or_default();
                            let aliases: Vec<String> = event_data
                                .get("aliases")
                                .and_then(|v| serde_json::from_value(v.clone()).ok())
                                .unwrap_or_default();

                            current_state = Some((ip, host, comment, tags, aliases));
                        }
                        "IpAddressChanged" => {
                            if let Some((ref mut ip, _, _, _, _)) = current_state {
                                if let Some(new_ip) = ip_address {
                                    *ip = new_ip;
                                }
                            }
                        }
                        "HostnameChanged" => {
                            if let Some((_, ref mut host, _, _, _)) = current_state {
                                if let Some(new_hostname) = hostname {
                                    *host = new_hostname;
                                }
                            }
                        }
                        "CommentUpdated" => {
                            if let Some((_, _, ref mut c, _, _)) = current_state {
                                *c = event_data
                                    .get("comment")
                                    .and_then(|v| v.as_str())
                                    .map(String::from);
                            }
                        }
                        "TagsModified" => {
                            if let Some((_, _, _, ref mut tags, _)) = current_state {
                                *tags = event_data
                                    .get("tags")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or_default();
                            }
                        }
                        "AliasesModified" => {
                            if let Some((_, _, _, _, ref mut aliases)) = current_state {
                                *aliases = event_data
                                    .get("aliases")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                                    .unwrap_or_default();
                            }
                        }
                        "HostDeleted" => {
                            // Clear state - this host was deleted
                            current_state = None;
                        }
                        _ => {}
                    }
                }

                // If state exists (not deleted), add to results
                if let Some((ip_address, hostname, comment, tags, aliases)) = current_state {
                    // For historical queries, we use a synthetic version and timestamp
                    entries.push(HostEntry {
                        id: aggregate_id,
                        ip_address,
                        hostname,
                        aliases,
                        comment,
                        tags,
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
        })
        .await
        .map_err(|e| StorageError::connection("spawn_blocking panicked during get_at_time", e))?
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
