//! HostProjection implementation for PostgreSQL
//!
//! Provides CQRS read-side queries using the host_entries_current view.

use chrono::{DateTime, Utc};
use sqlx::Row;
use ulid::Ulid;

use super::PostgresStorage;
use crate::error::StorageError;
use crate::types::{HostEntry, HostFilter};

impl PostgresStorage {
    /// List all active hosts
    pub(crate) async fn list_all_impl(&self) -> Result<Vec<HostEntry>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, ip_address, hostname, comment, tags,
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
            SELECT id, ip_address, hostname, comment, tags,
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
            SELECT id, ip_address, hostname, comment, tags,
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
    pub(crate) async fn search_impl(
        &self,
        filter: HostFilter,
    ) -> Result<Vec<HostEntry>, StorageError> {
        // Build dynamic query based on filters
        let mut conditions = Vec::new();
        let mut params: Vec<String> = Vec::new();

        if let Some(ref ip_pattern) = filter.ip_pattern {
            params.push(format!("%{}%", ip_pattern));
            conditions.push(format!("ip_address LIKE ${}", params.len()));
        }

        if let Some(ref hostname_pattern) = filter.hostname_pattern {
            params.push(format!("%{}%", hostname_pattern));
            conditions.push(format!("hostname LIKE ${}", params.len()));
        }

        if let Some(ref tags) = filter.tags {
            if !tags.is_empty() {
                // Check if any tag matches
                for tag in tags {
                    params.push(format!("%\"{}%", tag));
                    conditions.push(format!("tags LIKE ${}", params.len()));
                }
            }
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query = format!(
            r#"
            SELECT id, ip_address, hostname, comment, tags,
                   created_at, updated_at, event_version
            FROM host_entries_current
            {}
            ORDER BY ip_address, hostname
            "#,
            where_clause
        );

        // Build query with dynamic parameters
        let mut q = sqlx::query(&query);
        for param in &params {
            q = q.bind(param);
        }

        let rows = q
            .fetch_all(self.pool())
            .await
            .map_err(|e| StorageError::query("search failed", e))?;

        rows.into_iter()
            .map(|row| row_to_host_entry(&row))
            .collect()
    }

    /// Get state at a specific point in time
    pub(crate) async fn get_at_time_impl(
        &self,
        at_time: DateTime<Utc>,
    ) -> Result<Vec<HostEntry>, StorageError> {
        // Query events up to the given time and reconstruct state
        let rows = sqlx::query(
            r#"
            WITH events_at_time AS (
                SELECT * FROM host_events
                WHERE created_at <= $1
            ),
            windowed AS (
                SELECT
                    aggregate_id,
                    event_version,
                    event_type,
                    LAST_VALUE(ip_address) IGNORE NULLS OVER w as ip_address,
                    LAST_VALUE(hostname) IGNORE NULLS OVER w as hostname,
                    LAST_VALUE(comment) IGNORE NULLS OVER w as comment,
                    LAST_VALUE(tags) IGNORE NULLS OVER w as tags,
                    FIRST_VALUE(event_timestamp) OVER w as created_at,
                    LAST_VALUE(created_at) OVER w as updated_at,
                    LAST_VALUE(event_type) OVER w as latest_event_type,
                    ROW_NUMBER() OVER (PARTITION BY aggregate_id ORDER BY event_version DESC) as rn
                FROM events_at_time
                WINDOW w AS (PARTITION BY aggregate_id ORDER BY event_version
                             ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)
            )
            SELECT
                aggregate_id as id,
                ip_address,
                hostname,
                comment,
                tags,
                created_at,
                updated_at,
                event_version
            FROM windowed
            WHERE rn = 1 AND latest_event_type != 'HostDeleted'
            ORDER BY ip_address, hostname
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

    Ok(HostEntry {
        id,
        ip_address: row.get("ip_address"),
        hostname: row.get("hostname"),
        comment: row.get("comment"),
        tags,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        version: row.get("event_version"),
    })
}
