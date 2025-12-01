//! Command handlers for host management operations
//!
//! This module centralizes validation and event generation for all write operations.
//! All operations are immediate - there is no session/batching support.

use crate::server::db::{
    Database, DatabaseError, EventStore, HostEntry, HostEvent, HostProjections,
};
use crate::server::hooks::HookExecutor;
use crate::server::hosts_file::HostsFileGenerator;
use chrono::Utc;
use router_hosts_common::validation::{validate_hostname, validate_ip_address};
use std::sync::Arc;
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Version conflict: expected {expected}, actual {actual}")]
    VersionConflict { expected: String, actual: String },

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("File generation error: {0}")]
    FileGeneration(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type CommandResult<T> = Result<T, CommandError>;

pub struct CommandHandler {
    db: Arc<Database>,
    hosts_file: Arc<HostsFileGenerator>,
    hooks: Arc<HookExecutor>,
}

impl CommandHandler {
    pub fn new(
        db: Arc<Database>,
        hosts_file: Arc<HostsFileGenerator>,
        hooks: Arc<HookExecutor>,
    ) -> Self {
        Self {
            db,
            hosts_file,
            hooks,
        }
    }

    /// Add a new host entry
    pub async fn add_host(
        &self,
        ip_address: String,
        hostname: String,
        comment: Option<String>,
        tags: Vec<String>,
    ) -> CommandResult<HostEntry> {
        // Validate inputs
        validate_ip_address(&ip_address)
            .map_err(|e| CommandError::ValidationFailed(e.to_string()))?;
        validate_hostname(&hostname).map_err(|e| CommandError::ValidationFailed(e.to_string()))?;

        // Check for duplicates
        if let Some(_existing) =
            HostProjections::find_by_ip_and_hostname(&self.db, &ip_address, &hostname)?
        {
            return Err(CommandError::DuplicateEntry(format!(
                "Host with IP {} and hostname {} already exists",
                ip_address, hostname
            )));
        }

        let aggregate_id = Ulid::new();
        let event = HostEvent::HostCreated {
            ip_address,
            hostname,
            comment,
            tags,
            created_at: Utc::now(),
        };

        // Commit immediately
        EventStore::append_event(&self.db, &aggregate_id, event, None, None)?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        // Return the created entry
        self.get_host(aggregate_id)
            .await?
            .ok_or_else(|| CommandError::Internal("Entry not found after creation".to_string()))
    }

    /// Update an existing host entry
    ///
    /// If `expected_version` is provided, the update will only succeed if the
    /// current version matches. This enables optimistic concurrency control.
    pub async fn update_host(
        &self,
        id: Ulid,
        ip_address: Option<String>,
        hostname: Option<String>,
        comment: Option<Option<String>>,
        tags: Option<Vec<String>>,
        expected_version: Option<String>,
    ) -> CommandResult<HostEntry> {
        // Get current state
        let current = HostProjections::get_by_id(&self.db, &id)?
            .ok_or_else(|| CommandError::NotFound(format!("Host {} not found", id)))?;

        let current_version = current.version;

        // Check expected version if provided (optimistic concurrency)
        if let Some(expected) = expected_version {
            if expected.is_empty() {
                return Err(CommandError::ValidationFailed(
                    "expected_version cannot be empty".to_string(),
                ));
            }
            let actual = current_version.to_string();
            if expected != actual {
                return Err(CommandError::VersionConflict { expected, actual });
            }
        }
        let mut events = Vec::new();

        // Track final IP and hostname for duplicate check
        let mut final_ip = current.ip_address.clone();
        let mut final_hostname = current.hostname.clone();

        // Generate events for each change
        if let Some(new_ip) = ip_address {
            validate_ip_address(&new_ip)
                .map_err(|e| CommandError::ValidationFailed(e.to_string()))?;
            if new_ip != current.ip_address {
                final_ip = new_ip.clone();
                events.push(HostEvent::IpAddressChanged {
                    old_ip: current.ip_address.clone(),
                    new_ip,
                    changed_at: Utc::now(),
                });
            }
        }

        if let Some(new_hostname) = hostname {
            validate_hostname(&new_hostname)
                .map_err(|e| CommandError::ValidationFailed(e.to_string()))?;
            if new_hostname != current.hostname {
                final_hostname = new_hostname.clone();
                events.push(HostEvent::HostnameChanged {
                    old_hostname: current.hostname.clone(),
                    new_hostname,
                    changed_at: Utc::now(),
                });
            }
        }

        // Check for duplicate IP+hostname (if either changed)
        if final_ip != current.ip_address || final_hostname != current.hostname {
            if let Some(existing) =
                HostProjections::find_by_ip_and_hostname(&self.db, &final_ip, &final_hostname)?
            {
                if existing.id != id {
                    return Err(CommandError::DuplicateEntry(format!(
                        "Host with IP {} and hostname {} already exists",
                        final_ip, final_hostname
                    )));
                }
            }
        }

        if let Some(new_comment) = comment {
            if new_comment != current.comment {
                events.push(HostEvent::CommentUpdated {
                    old_comment: current.comment.clone(),
                    new_comment,
                    updated_at: Utc::now(),
                });
            }
        }

        if let Some(new_tags) = tags {
            if new_tags != current.tags {
                events.push(HostEvent::TagsModified {
                    old_tags: current.tags.clone(),
                    new_tags,
                    modified_at: Utc::now(),
                });
            }
        }

        if events.is_empty() {
            return Ok(current);
        }

        // Commit all events atomically - prevents race condition where partial
        // updates could be committed if a concurrent write occurs mid-loop
        EventStore::append_events(&self.db, &id, events, Some(current_version), None)?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        // Return updated entry
        self.get_host(id)
            .await?
            .ok_or_else(|| CommandError::Internal("Entry not found after update".to_string()))
    }

    /// Delete a host entry
    pub async fn delete_host(&self, id: Ulid, reason: Option<String>) -> CommandResult<()> {
        let current = HostProjections::get_by_id(&self.db, &id)?
            .ok_or_else(|| CommandError::NotFound(format!("Host {} not found", id)))?;

        let event = HostEvent::HostDeleted {
            ip_address: current.ip_address.clone(),
            hostname: current.hostname.clone(),
            deleted_at: Utc::now(),
            reason,
        };

        // Commit immediately
        EventStore::append_event(&self.db, &id, event, Some(current.version), None)?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        Ok(())
    }

    /// Get a host by ID
    pub async fn get_host(&self, id: Ulid) -> CommandResult<Option<HostEntry>> {
        Ok(HostProjections::get_by_id(&self.db, &id)?)
    }

    /// List all hosts
    pub async fn list_hosts(&self) -> CommandResult<Vec<HostEntry>> {
        Ok(HostProjections::list_all(&self.db)?)
    }

    /// Search hosts
    pub async fn search_hosts(&self, pattern: &str) -> CommandResult<Vec<HostEntry>> {
        Ok(HostProjections::search(&self.db, pattern)?)
    }

    async fn regenerate_hosts_file(&self) -> CommandResult<()> {
        match self.hosts_file.regenerate(&self.db).await {
            Ok(count) => {
                let hook_failures = self.hooks.run_success(count).await;
                if hook_failures > 0 {
                    tracing::warn!(
                        hook_failures,
                        entry_count = count,
                        "Hosts file updated but some hooks failed"
                    );
                }
                Ok(())
            }
            Err(e) => {
                let hook_failures = self.hooks.run_failure(0, &e.to_string()).await;
                if hook_failures > 0 {
                    tracing::error!(
                        hook_failures,
                        "Hosts file regeneration failed AND failure hooks also failed"
                    );
                }
                Err(CommandError::FileGeneration(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn setup() -> CommandHandler {
        let db = Arc::new(Database::in_memory().unwrap());

        // Create a unique temp file for each test
        let temp_file = temp_dir().join(format!("test_hosts_{}", ulid::Ulid::new()));
        let hosts_file = Arc::new(HostsFileGenerator::new(temp_file));

        let hooks = Arc::new(HookExecutor::default());
        CommandHandler::new(db, hosts_file, hooks)
    }

    #[tokio::test]
    async fn test_add_host() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        assert_eq!(entry.ip_address, "192.168.1.1");
        assert_eq!(entry.hostname, "test.local");
    }

    #[tokio::test]
    async fn test_add_host_validation_failure() {
        let handler = setup();
        let result = handler
            .add_host(
                "invalid-ip".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await;

        assert!(matches!(result, Err(CommandError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn test_add_host_duplicate() {
        let handler = setup();
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        // Try to add duplicate
        let result = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await;

        assert!(matches!(result, Err(CommandError::DuplicateEntry(_))));
    }

    #[tokio::test]
    async fn test_update_host() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let updated = handler
            .update_host(
                entry.id,
                Some("192.168.1.2".to_string()),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(updated.ip_address, "192.168.1.2");
    }

    #[tokio::test]
    async fn test_delete_host() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        handler.delete_host(entry.id, None).await.unwrap();

        let result = handler.get_host(entry.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_hosts() {
        let handler = setup();

        handler
            .add_host(
                "192.168.1.1".to_string(),
                "host1.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        handler
            .add_host(
                "192.168.1.2".to_string(),
                "host2.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let hosts = handler.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 2);
    }

    #[tokio::test]
    async fn test_search_hosts() {
        let handler = setup();

        handler
            .add_host(
                "192.168.1.1".to_string(),
                "server.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        handler
            .add_host(
                "192.168.1.2".to_string(),
                "client.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let results = handler.search_hosts("server").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hostname, "server.local");
    }

    #[tokio::test]
    async fn test_update_hostname() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "old.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let updated = handler
            .update_host(
                entry.id,
                None,
                Some("new.local".to_string()),
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(updated.hostname, "new.local");
    }

    #[tokio::test]
    async fn test_update_comment() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let updated = handler
            .update_host(
                entry.id,
                None,
                None,
                Some(Some("Test comment".to_string())),
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(updated.comment, Some("Test comment".to_string()));
    }

    #[tokio::test]
    async fn test_update_tags() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let updated = handler
            .update_host(
                entry.id,
                None,
                None,
                None,
                Some(vec!["prod".to_string(), "web".to_string()]),
                None,
            )
            .await
            .unwrap();

        assert_eq!(updated.tags, vec!["prod".to_string(), "web".to_string()]);
    }

    #[tokio::test]
    async fn test_update_no_changes() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        // Update with no actual changes
        let result = handler
            .update_host(entry.id, None, None, None, None, None)
            .await
            .unwrap();

        assert_eq!(result.id, entry.id);
        assert_eq!(result.version, entry.version); // Version should not increment
    }

    #[tokio::test]
    async fn test_delete_not_found() {
        let handler = setup();
        let fake_id = Ulid::new();

        let result = handler.delete_host(fake_id, None).await;
        assert!(matches!(result, Err(CommandError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let handler = setup();
        let fake_id = Ulid::new();

        let result = handler
            .update_host(fake_id, None, None, None, None, None)
            .await;
        assert!(matches!(result, Err(CommandError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation() {
        let handler = setup();

        let result = handler
            .add_host(
                "192.168.1.1".to_string(),
                "invalid..hostname".to_string(),
                None,
                vec![],
            )
            .await;

        assert!(matches!(result, Err(CommandError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn test_update_duplicate_detection() {
        let handler = setup();

        // Create two hosts
        let entry_a = handler
            .add_host(
                "192.168.1.1".to_string(),
                "host-a.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        handler
            .add_host(
                "192.168.1.2".to_string(),
                "host-b.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        // Try to update host A to have same IP+hostname as host B
        let result = handler
            .update_host(
                entry_a.id,
                Some("192.168.1.2".to_string()),
                Some("host-b.local".to_string()),
                None,
                None,
                None,
            )
            .await;

        assert!(
            matches!(result, Err(CommandError::DuplicateEntry(_))),
            "Expected DuplicateEntry error, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_empty_expected_version() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        // Update with empty expected_version should fail validation
        let result = handler
            .update_host(
                entry.id,
                Some("192.168.1.2".to_string()),
                None,
                None,
                None,
                Some(String::new()),
            )
            .await;

        assert!(
            matches!(result, Err(CommandError::ValidationFailed(_))),
            "Expected ValidationFailed error for empty version, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_version_conflict() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let current_version = entry.version.to_string();

        // Update with correct expected_version should succeed
        let updated = handler
            .update_host(
                entry.id,
                Some("192.168.1.2".to_string()),
                None,
                None,
                None,
                Some(current_version),
            )
            .await
            .unwrap();

        assert_eq!(updated.ip_address, "192.168.1.2");

        // Update with wrong expected_version should fail with VersionConflict
        let result = handler
            .update_host(
                entry.id,
                Some("192.168.1.3".to_string()),
                None,
                None,
                None,
                Some("wrong-version".to_string()),
            )
            .await;

        assert!(
            matches!(result, Err(CommandError::VersionConflict { .. })),
            "Expected VersionConflict error, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_update_version_conflict_stale_version() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let stale_version = entry.version.to_string();

        // First update succeeds, changing the version
        handler
            .update_host(
                entry.id,
                Some("192.168.1.2".to_string()),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // Second update with stale version should fail
        let result = handler
            .update_host(
                entry.id,
                Some("192.168.1.3".to_string()),
                None,
                None,
                None,
                Some(stale_version),
            )
            .await;

        assert!(
            matches!(result, Err(CommandError::VersionConflict { .. })),
            "Expected VersionConflict error for stale version, got {:?}",
            result
        );
    }
}
