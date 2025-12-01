//! Command handlers for host management operations
//!
//! This module centralizes validation and event generation for all write operations.

use crate::server::db::{
    Database, DatabaseError, EventStore, HostEntry, HostEvent, HostProjections,
};
use crate::server::hooks::HookExecutor;
use crate::server::hosts_file::HostsFileGenerator;
use crate::server::session::{SessionError, SessionManager};
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

    #[error("Session conflict: another edit session is active")]
    SessionConflict,

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("No active session")]
    NoActiveSession,

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("File generation error: {0}")]
    FileGeneration(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<SessionError> for CommandError {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::SessionAlreadyActive => CommandError::SessionConflict,
            SessionError::InvalidToken => CommandError::InvalidToken,
            SessionError::Expired => CommandError::SessionExpired,
            SessionError::NoActiveSession => CommandError::NoActiveSession,
            SessionError::DuplicateEntry(msg) => CommandError::DuplicateEntry(msg),
        }
    }
}

pub type CommandResult<T> = Result<T, CommandError>;

pub struct CommandHandler {
    db: Arc<Database>,
    session_mgr: Arc<SessionManager>,
    hosts_file: Arc<HostsFileGenerator>,
    hooks: Arc<HookExecutor>,
}

impl CommandHandler {
    pub fn new(
        db: Arc<Database>,
        session_mgr: Arc<SessionManager>,
        hosts_file: Arc<HostsFileGenerator>,
        hooks: Arc<HookExecutor>,
    ) -> Self {
        Self {
            db,
            session_mgr,
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
        edit_token: Option<String>,
    ) -> CommandResult<HostEntry> {
        // Validate inputs
        validate_ip_address(&ip_address)
            .map_err(|e| CommandError::ValidationFailed(e.to_string()))?;
        validate_hostname(&hostname).map_err(|e| CommandError::ValidationFailed(e.to_string()))?;

        let aggregate_id = Ulid::new();
        let now = Utc::now();
        let event = HostEvent::HostCreated {
            ip_address: ip_address.clone(),
            hostname: hostname.clone(),
            comment: comment.clone(),
            tags: tags.clone(),
            created_at: now,
        };

        if let Some(ref token) = edit_token {
            // Stage the event
            self.session_mgr.stage_event(token, aggregate_id, event)?;
            // Return a preview of the entry (not yet committed to DB)
            // This allows callers to see what will be created when the session is committed
            return Ok(HostEntry {
                id: aggregate_id,
                ip_address,
                hostname,
                comment,
                tags,
                created_at: now,
                updated_at: now,
                version: 0, // Will be 1 after commit
            });
        }

        // Immediate commit
        EventStore::append_event(&self.db, &aggregate_id, event, None, None)?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        // Return the created entry
        self.get_host(aggregate_id)
            .await?
            .ok_or_else(|| CommandError::Internal("Entry not found after creation".to_string()))
    }

    /// Update an existing host entry
    pub async fn update_host(
        &self,
        id: Ulid,
        ip_address: Option<String>,
        hostname: Option<String>,
        comment: Option<Option<String>>,
        tags: Option<Vec<String>>,
        edit_token: Option<String>,
    ) -> CommandResult<HostEntry> {
        // Get current state
        let current = HostProjections::get_by_id(&self.db, &id)?
            .ok_or_else(|| CommandError::NotFound(format!("Host {} not found", id)))?;

        let current_version = current.version;
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
            // Check database for existing entries
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

            // If in a session, also check staged events for duplicates
            if let Some(ref token) = edit_token {
                if !self
                    .session_mgr
                    .check_staged_duplicate(token, &final_ip, &final_hostname)?
                {
                    return Err(CommandError::DuplicateEntry(format!(
                        "Host with IP {} and hostname {} already staged in this session",
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

        if let Some(ref token) = edit_token {
            // Stage all events
            for event in events {
                self.session_mgr.stage_event(token, id, event)?;
            }
            // Register the final IP+hostname if changed, for future duplicate checks
            if final_ip != current.ip_address || final_hostname != current.hostname {
                self.session_mgr
                    .register_staged_ip_hostname(token, &final_ip, &final_hostname)?;
            }
            return Ok(current);
        }

        // Immediate commit
        let mut version = current_version;
        for event in events {
            EventStore::append_event(&self.db, &id, event, Some(version), None)?;
            version += 1;
        }

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        // Return updated entry
        self.get_host(id)
            .await?
            .ok_or_else(|| CommandError::Internal("Entry not found after update".to_string()))
    }

    /// Delete a host entry
    pub async fn delete_host(
        &self,
        id: Ulid,
        reason: Option<String>,
        edit_token: Option<String>,
    ) -> CommandResult<()> {
        let current = HostProjections::get_by_id(&self.db, &id)?
            .ok_or_else(|| CommandError::NotFound(format!("Host {} not found", id)))?;

        let event = HostEvent::HostDeleted {
            ip_address: current.ip_address.clone(),
            hostname: current.hostname.clone(),
            deleted_at: Utc::now(),
            reason,
        };

        if let Some(ref token) = edit_token {
            self.session_mgr.stage_event(token, id, event)?;
            return Ok(());
        }

        // Immediate commit
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

    /// Start an edit session
    pub fn start_edit(&self) -> CommandResult<String> {
        Ok(self.session_mgr.start_edit()?)
    }

    /// Finish an edit session and commit all staged changes
    ///
    /// # Transaction Semantics
    ///
    /// **IMPORTANT**: This operation does NOT provide all-or-nothing atomicity.
    /// Each event is committed in its own transaction. If event N fails,
    /// events 1 through N-1 remain committed in the database.
    ///
    /// This design is intentional because:
    /// 1. Each event represents a valid, independent state transition
    /// 2. The hosts file is only regenerated after ALL events succeed
    /// 3. Partial failure leaves the database consistent (committed events are valid)
    /// 4. Recovery: If partial commit occurs, the hosts file remains unchanged,
    ///    and the operator can inspect the database to see what was committed
    ///
    /// If full atomicity is required, consider implementing a saga pattern or
    /// wrapping all events in a single database transaction at the event store level.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session token is invalid or expired
    /// - Any event fails to commit (partial commit may have occurred)
    /// - Hosts file regeneration fails (all events are committed but file unchanged)
    pub async fn finish_edit(&self, token: &str) -> CommandResult<usize> {
        let staged_events = self.session_mgr.finish_edit(token)?;
        let count = staged_events.len();

        // Commit all staged events (each in its own transaction)
        for (agg_id, event) in staged_events {
            // Get current version for this aggregate
            let version = match HostProjections::get_by_id(&self.db, &agg_id)? {
                Some(entry) => Some(entry.version),
                None => None,
            };
            EventStore::append_event(&self.db, &agg_id, event, version, None)?;
        }

        // Regenerate hosts file only after all events committed successfully
        self.regenerate_hosts_file().await?;

        Ok(count)
    }

    /// Cancel an edit session
    pub fn cancel_edit(&self, token: &str) -> CommandResult<()> {
        Ok(self.session_mgr.cancel_edit(token)?)
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
        let session_mgr = Arc::new(SessionManager::new(15));

        // Create a unique temp file for each test
        let temp_file = temp_dir().join(format!("test_hosts_{}", ulid::Ulid::new()));
        let hosts_file = Arc::new(HostsFileGenerator::new(temp_file));

        let hooks = Arc::new(HookExecutor::default());
        CommandHandler::new(db, session_mgr, hosts_file, hooks)
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
                None,
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
                None,
            )
            .await;

        assert!(matches!(result, Err(CommandError::ValidationFailed(_))));
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
                None,
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
                None,
            )
            .await
            .unwrap();

        handler.delete_host(entry.id, None, None).await.unwrap();

        let result = handler.get_host(entry.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_edit_session_workflow() {
        let handler = setup();

        // Start session
        let token = handler.start_edit().unwrap();

        // Add host in session
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
                Some(token.clone()),
            )
            .await
            .unwrap();

        // Finish session
        let count = handler.finish_edit(&token).await.unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_list_hosts() {
        let handler = setup();

        // Add multiple hosts
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "host1.local".to_string(),
                None,
                vec![],
                None,
            )
            .await
            .unwrap();

        handler
            .add_host(
                "192.168.1.2".to_string(),
                "host2.local".to_string(),
                None,
                vec![],
                None,
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
                None,
            )
            .await
            .unwrap();

        handler
            .add_host(
                "192.168.1.2".to_string(),
                "client.local".to_string(),
                None,
                vec![],
                None,
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
                None,
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
                None,
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
                None,
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
    async fn test_session_staging() {
        let handler = setup();
        let token = handler.start_edit().unwrap();

        // Add host in session
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
                Some(token.clone()),
            )
            .await
            .unwrap();

        // Should not be visible yet
        let hosts = handler.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 0);

        // Finish session
        handler.finish_edit(&token).await.unwrap();

        // Now visible
        let hosts = handler.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 1);
    }

    #[tokio::test]
    async fn test_session_cancel() {
        let handler = setup();
        let token = handler.start_edit().unwrap();

        // Add host in session
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
                Some(token.clone()),
            )
            .await
            .unwrap();

        // Cancel session
        handler.cancel_edit(&token).unwrap();

        // Should not be visible
        let hosts = handler.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 0);
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
                None,
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

        let result = handler.delete_host(fake_id, None, None).await;
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
                None,
            )
            .await;

        assert!(matches!(result, Err(CommandError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn test_session_conflict() {
        let handler = setup();
        let _token1 = handler.start_edit().unwrap();

        // Try to start second session
        let result = handler.start_edit();
        assert!(matches!(result, Err(CommandError::SessionConflict)));
    }

    #[tokio::test]
    async fn test_session_duplicate_detection_on_updates() {
        // Regression test for duplicate detection race condition in edit sessions
        // Scenario: Two existing hosts, update both to same IP+hostname in one session
        let handler = setup();

        // Create two hosts with different IPs
        let entry_a = handler
            .add_host(
                "192.168.1.1".to_string(),
                "host-a.local".to_string(),
                None,
                vec![],
                None,
            )
            .await
            .unwrap();

        let entry_b = handler
            .add_host(
                "192.168.1.2".to_string(),
                "host-b.local".to_string(),
                None,
                vec![],
                None,
            )
            .await
            .unwrap();

        // Start edit session
        let token = handler.start_edit().unwrap();

        // Update host A to 192.168.1.100:target.local
        handler
            .update_host(
                entry_a.id,
                Some("192.168.1.100".to_string()),
                Some("target.local".to_string()),
                None,
                None,
                Some(token.clone()),
            )
            .await
            .unwrap();

        // Try to update host B to same IP+hostname - should fail
        let result = handler
            .update_host(
                entry_b.id,
                Some("192.168.1.100".to_string()),
                Some("target.local".to_string()),
                None,
                None,
                Some(token.clone()),
            )
            .await;

        assert!(
            matches!(result, Err(CommandError::DuplicateEntry(_))),
            "Expected DuplicateEntry error, got {:?}",
            result
        );

        // Cancel to clean up
        handler.cancel_edit(&token).unwrap();
    }

    #[tokio::test]
    async fn test_session_duplicate_detection_on_create() {
        // Test that creating two hosts with same IP+hostname in one session fails
        let handler = setup();

        // Start edit session
        let token = handler.start_edit().unwrap();

        // Create first host
        handler
            .add_host(
                "192.168.1.50".to_string(),
                "duplicate.local".to_string(),
                None,
                vec![],
                Some(token.clone()),
            )
            .await
            .unwrap();

        // Try to create second host with same IP+hostname - should fail
        let result = handler
            .add_host(
                "192.168.1.50".to_string(),
                "duplicate.local".to_string(),
                None,
                vec![],
                Some(token.clone()),
            )
            .await;

        assert!(
            matches!(result, Err(CommandError::DuplicateEntry(_))),
            "Expected DuplicateEntry error, got {:?}",
            result
        );

        // Cancel to clean up
        handler.cancel_edit(&token).unwrap();
    }
}
