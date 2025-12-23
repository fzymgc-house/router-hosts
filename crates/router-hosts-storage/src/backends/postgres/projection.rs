//! HostProjection implementation for PostgreSQL
//!
//! Provides CQRS read-side queries using the host_entries_current view.

use chrono::{DateTime, Utc};
use sqlx::postgres::PgArguments;
use sqlx::{Arguments, Row};
use ulid::Ulid;

use super::PostgresStorage;
use crate::error::StorageError;
use crate::types::{HostEntry, HostFilter};

/// Helper to add a value to PgArguments with proper error handling
///
/// sqlx's Arguments::add() returns Box<dyn Error> which doesn't implement Error trait,
/// so we can't use ? directly. For strings, encoding is infallible, but we handle
/// the error case properly to comply with project standards.
fn add_arg(args: &mut PgArguments, value: String) -> Result<(), StorageError> {
    args.add(value).map_err(|e| {
        StorageError::Query {
            message: format!("failed to encode query parameter: {}", e),
            source: None, // Box<dyn Error> doesn't implement Error, can't wrap directly
        }
    })
}

impl PostgresStorage {
    /// List all active hosts
    pub(crate) async fn list_all_impl(&self) -> Result<Vec<HostEntry>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, ip_address, hostname, comment, tags, aliases,
                   created_at, updated_at, event_version
            FROM host_entries_current
            ORDER BY ip_address, hostname
            "#,
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| StorageError::query("list_all failed", e))?;

        rows.into_iter()
            .map(|row| row_to_host_entry(&row))
            .collect()
    }

    /// Get a host by ID
    pub(crate) async fn get_by_id_impl(&self, id: Ulid) -> Result<HostEntry, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, ip_address, hostname, comment, tags, aliases,
                   created_at, updated_at, event_version
            FROM host_entries_current
            WHERE id = $1
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(self.pool())
        .await
        .map_err(|e| StorageError::query("get_by_id failed", e))?
        .ok_or_else(|| StorageError::NotFound {
            entity_type: "HostEntry",
            id: id.to_string(),
        })?;

        row_to_host_entry(&row)
    }

    /// Find by IP and hostname
    pub(crate) async fn find_by_ip_and_hostname_impl(
        &self,
        ip_address: &str,
        hostname: &str,
    ) -> Result<Option<HostEntry>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, ip_address, hostname, comment, tags, aliases,
                   created_at, updated_at, event_version
            FROM host_entries_current
            WHERE ip_address = $1 AND hostname = $2
            "#,
        )
        .bind(ip_address)
        .bind(hostname)
        .fetch_optional(self.pool())
        .await
        .map_err(|e| StorageError::query("find_by_ip_and_hostname failed", e))?;

        match row {
            Some(r) => Ok(Some(row_to_host_entry(&r)?)),
            None => Ok(None),
        }
    }

    /// Search with filters
    ///
    /// # Safety (SQL Injection Prevention)
    ///
    /// This function uses dynamic SQL query construction with `format!()` but is safe because:
    /// 1. **Column names are hardcoded constants** - Only static strings like "ip_address",
    ///    "hostname", "aliases", "tags" appear in the query structure.
    /// 2. **All user input is parameterized** - Filter patterns (ip_pattern, hostname_pattern, tags)
    ///    are bound via positional `$N` placeholders and `PgArguments`, never interpolated into SQL.
    /// 3. **Query structure is fixed** - Only the WHERE clause presence changes based on filter,
    ///    and the clause content uses positional placeholders.
    /// 4. **PostgreSQL parameterization** - The `sqlx::query_with(&query, args)` call ensures
    ///    all values are properly escaped by the database driver.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Query` if the database operation fails.
    pub(crate) async fn search_impl(
        &self,
        filter: HostFilter,
    ) -> Result<Vec<HostEntry>, StorageError> {
        // Build dynamic query with safe parameterized conditions
        // SAFETY: All user input is bound via PgArguments, never interpolated into SQL
        let mut conditions: Vec<String> = Vec::new();
        let mut args = PgArguments::default();
        let mut param_idx = 0;

        // Build WHERE conditions - column names are constants, values are parameterized
        if let Some(ref ip_pattern) = filter.ip_pattern {
            param_idx += 1;
            conditions.push(format!("ip_address LIKE ${}", param_idx));
            add_arg(&mut args, format!("%{}%", ip_pattern))?;
        }

        if let Some(ref hostname_pattern) = filter.hostname_pattern {
            param_idx += 1;
            let pattern1_idx = param_idx;
            param_idx += 1;
            let pattern2_idx = param_idx;
            // Use ILIKE for case-insensitive matching (DNS is case-insensitive)
            conditions.push(format!(
                "(hostname ILIKE ${} OR aliases ILIKE ${})",
                pattern1_idx, pattern2_idx
            ));
            let pattern = format!("%{}%", hostname_pattern);
            add_arg(&mut args, pattern.clone())?;
            add_arg(&mut args, pattern)?;
        }

        // Handle tag filters - each tag becomes a separate LIKE condition
        if let Some(ref tags) = filter.tags {
            for tag in tags {
                param_idx += 1;
                conditions.push(format!("tags LIKE ${}", param_idx));
                add_arg(&mut args, format!("%\"{}%", tag))?;
            }
        }

        // Build final query - structure is static, only values are parameterized
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query = format!(
            r#"
            SELECT id, ip_address, hostname, comment, tags, aliases,
                   created_at, updated_at, event_version
            FROM host_entries_current
            {}
            ORDER BY ip_address, hostname
            "#,
            where_clause
        );

        let rows = sqlx::query_with(&query, args)
            .fetch_all(self.pool())
            .await
            .map_err(|e| {
                StorageError::query(
                    format!(
                        "search failed (ip={:?}, hostname={:?}, tags={:?})",
                        filter.ip_pattern, filter.hostname_pattern, filter.tags
                    ),
                    e,
                )
            })?;

        rows.into_iter()
            .map(|row| row_to_host_entry(&row))
            .collect()
    }

    /// Get state at a specific point in time
    ///
    /// Uses PostgreSQL-compatible syntax with DISTINCT ON instead of IGNORE NULLS
    pub(crate) async fn get_at_time_impl(
        &self,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<HostEntry>, StorageError> {
        // Query events up to the given time and reconstruct state
        // PostgreSQL doesn't support IGNORE NULLS, so we use CTEs with DISTINCT ON
        let rows = sqlx::query(
            r#"
            WITH
            -- Filter events up to the specified time
            events_at_time AS (
                SELECT * FROM host_events
                WHERE created_at <= $1
            ),
            -- Get the latest event for each aggregate to determine if deleted
            latest_events AS (
                SELECT DISTINCT ON (aggregate_id)
                    aggregate_id,
                    event_type as latest_event_type,
                    event_version,
                    created_at as updated_at
                FROM events_at_time
                ORDER BY aggregate_id, event_version DESC
            ),
            -- Get first event timestamp (created_at)
            first_events AS (
                SELECT DISTINCT ON (aggregate_id)
                    aggregate_id,
                    event_timestamp as created_at
                FROM events_at_time
                ORDER BY aggregate_id, event_version ASC
            ),
            -- Get last non-null ip_address
            ip_values AS (
                SELECT DISTINCT ON (aggregate_id)
                    aggregate_id,
                    ip_address
                FROM events_at_time
                WHERE ip_address IS NOT NULL
                ORDER BY aggregate_id, event_version DESC
            ),
            -- Get last non-null hostname
            hostname_values AS (
                SELECT DISTINCT ON (aggregate_id)
                    aggregate_id,
                    hostname
                FROM events_at_time
                WHERE hostname IS NOT NULL
                ORDER BY aggregate_id, event_version DESC
            ),
            -- Get last non-null comment
            comment_values AS (
                SELECT DISTINCT ON (aggregate_id)
                    aggregate_id,
                    comment
                FROM events_at_time
                WHERE comment IS NOT NULL
                ORDER BY aggregate_id, event_version DESC
            ),
            -- Get last non-null tags
            tags_values AS (
                SELECT DISTINCT ON (aggregate_id)
                    aggregate_id,
                    tags
                FROM events_at_time
                WHERE tags IS NOT NULL
                ORDER BY aggregate_id, event_version DESC
            ),
            -- Get last non-null aliases
            aliases_values AS (
                SELECT DISTINCT ON (aggregate_id)
                    aggregate_id,
                    aliases
                FROM events_at_time
                WHERE aliases IS NOT NULL
                ORDER BY aggregate_id, event_version DESC
            )
            SELECT
                le.aggregate_id as id,
                ip.ip_address,
                hn.hostname,
                cv.comment,
                tv.tags,
                av.aliases,
                fe.created_at,
                le.updated_at,
                le.event_version
            FROM latest_events le
            LEFT JOIN first_events fe ON fe.aggregate_id = le.aggregate_id
            LEFT JOIN ip_values ip ON ip.aggregate_id = le.aggregate_id
            LEFT JOIN hostname_values hn ON hn.aggregate_id = le.aggregate_id
            LEFT JOIN comment_values cv ON cv.aggregate_id = le.aggregate_id
            LEFT JOIN tags_values tv ON tv.aggregate_id = le.aggregate_id
            LEFT JOIN aliases_values av ON av.aggregate_id = le.aggregate_id
            WHERE le.latest_event_type != 'HostDeleted'
            ORDER BY ip.ip_address, hn.hostname
            "#,
        )
        .bind(at_time)
        .fetch_all(self.pool())
        .await
        .map_err(|e| StorageError::query("get_at_time failed", e))?;

        rows.into_iter()
            .map(|row| row_to_host_entry(&row))
            .collect()
    }
}

/// Convert a database row to HostEntry
fn row_to_host_entry(row: &sqlx::postgres::PgRow) -> Result<HostEntry, StorageError> {
    let id_str: String = row.get("id");
    let id = Ulid::from_string(&id_str)
        .map_err(|e| StorageError::InvalidData(format!("invalid id: {}", e)))?;

    let tags_json: Option<String> = row.get("tags");
    let tags: Vec<String> = tags_json
        .map(|s| serde_json::from_str(&s).unwrap_or_default())
        .unwrap_or_default();

    let aliases_json: Option<String> = row.get("aliases");
    let aliases: Vec<String> = aliases_json
        .map(|s| serde_json::from_str(&s).unwrap_or_default())
        .unwrap_or_default();

    Ok(HostEntry {
        id,
        ip_address: row.get("ip_address"),
        hostname: row.get("hostname"),
        aliases,
        comment: row.get("comment"),
        tags,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        version: row.get("event_version"),
    })
}
