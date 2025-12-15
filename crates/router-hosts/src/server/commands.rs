//! Command handlers for host management operations
//!
//! This module centralizes validation and event generation for all write operations.
//! All operations are immediate - there is no session/batching support.

use crate::server::hooks::HookExecutor;
use crate::server::hosts_file::HostsFileGenerator;
use crate::server::import::{parse_import, ImportFormat};
use chrono::Utc;
use router_hosts_common::validation::{validate_hostname, validate_ip_address};
use router_hosts_storage::{
    EventEnvelope, HostEntry, HostEvent, HostFilter, Snapshot, SnapshotMetadata, Storage,
    StorageError,
};
use std::sync::Arc;
use thiserror::Error;
use ulid::Ulid;

/// Result of a snapshot rollback operation
#[must_use = "rollback result should be checked for success and backup snapshot ID"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackResult {
    /// Whether the rollback succeeded
    pub success: bool,
    /// ID of the backup snapshot created before rollback
    pub backup_snapshot_id: String,
    /// Number of entries restored from the snapshot
    pub restored_entry_count: i32,
}

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

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("File generation error: {0}")]
    FileGeneration(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type CommandResult<T> = Result<T, CommandError>;

pub struct CommandHandler {
    storage: Arc<dyn Storage>,
    hosts_file: Arc<HostsFileGenerator>,
    hooks: Arc<HookExecutor>,
    config: Arc<crate::server::config::Config>,
}

impl CommandHandler {
    pub fn new(
        storage: Arc<dyn Storage>,
        hosts_file: Arc<HostsFileGenerator>,
        hooks: Arc<HookExecutor>,
        config: Arc<crate::server::config::Config>,
    ) -> Self {
        Self {
            storage,
            hosts_file,
            hooks,
            config,
        }
    }

    /// Create an event envelope from a HostEvent
    fn create_envelope(&self, aggregate_id: Ulid, event: HostEvent) -> EventEnvelope {
        EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event,
            event_version: Ulid::new().to_string(),
            created_at: Utc::now(),
            created_by: None,
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
        if let Some(_existing) = self
            .storage
            .find_by_ip_and_hostname(&ip_address, &hostname)
            .await?
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

        // Create envelope and commit immediately
        let envelope = self.create_envelope(aggregate_id, event);
        self.storage
            .append_event(aggregate_id, envelope, None)
            .await?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        // Return the created entry
        self.get_host(aggregate_id).await
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
        let current = match self.storage.get_by_id(id).await {
            Ok(entry) => entry,
            Err(StorageError::NotFound { .. }) => {
                return Err(CommandError::NotFound(format!("Host {} not found", id)));
            }
            Err(e) => return Err(e.into()),
        };

        let current_version = current.version.clone();

        // Check expected version if provided (optimistic concurrency)
        if let Some(expected) = expected_version {
            if expected.is_empty() {
                return Err(CommandError::ValidationFailed(
                    "expected_version cannot be empty".to_string(),
                ));
            }
            if expected != current_version {
                return Err(CommandError::VersionConflict {
                    expected,
                    actual: current_version,
                });
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
            if let Some(existing) = self
                .storage
                .find_by_ip_and_hostname(&final_ip, &final_hostname)
                .await?
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

        // Create envelopes for all events
        let envelopes: Vec<EventEnvelope> = events
            .into_iter()
            .map(|event| self.create_envelope(id, event))
            .collect();

        // Commit all events atomically - prevents race condition where partial
        // updates could be committed if a concurrent write occurs mid-loop
        self.storage
            .append_events(id, envelopes, Some(current_version))
            .await?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        // Return updated entry
        self.get_host(id).await
    }

    /// Delete a host entry
    pub async fn delete_host(&self, id: Ulid, reason: Option<String>) -> CommandResult<()> {
        let current = match self.storage.get_by_id(id).await {
            Ok(entry) => entry,
            Err(StorageError::NotFound { .. }) => {
                return Err(CommandError::NotFound(format!("Host {} not found", id)));
            }
            Err(e) => return Err(e.into()),
        };

        let event = HostEvent::HostDeleted {
            ip_address: current.ip_address.clone(),
            hostname: current.hostname.clone(),
            deleted_at: Utc::now(),
            reason,
        };

        // Create envelope and commit immediately
        let envelope = self.create_envelope(id, event);
        self.storage
            .append_event(id, envelope, Some(current.version.clone()))
            .await?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        Ok(())
    }

    /// Get a host by ID
    ///
    /// # Errors
    ///
    /// Returns `CommandError::NotFound` if the host doesn't exist.
    /// This follows the storage trait design where missing entities
    /// are errors rather than `Option::None`.
    pub async fn get_host(&self, id: Ulid) -> CommandResult<HostEntry> {
        match self.storage.get_by_id(id).await {
            Ok(entry) => Ok(entry),
            Err(StorageError::NotFound { .. }) => {
                Err(CommandError::NotFound(format!("Host {} not found", id)))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// List all hosts
    pub async fn list_hosts(&self) -> CommandResult<Vec<HostEntry>> {
        Ok(self.storage.list_all().await?)
    }

    /// Search hosts by pattern
    pub async fn search_hosts(&self, pattern: &str) -> CommandResult<Vec<HostEntry>> {
        let filter = HostFilter {
            hostname_pattern: Some(pattern.to_string()),
            ..Default::default()
        };
        Ok(self.storage.search(filter).await?)
    }

    /// Import multiple hosts with conflict handling
    ///
    /// Unlike add_host, this commits all events in a batch and
    /// only regenerates the hosts file once at the end.
    ///
    /// # Fail-Fast Behavior
    ///
    /// This function uses fail-fast semantics for certain error conditions:
    ///
    /// - **Duplicate aggregate updates**: If the same IP+hostname appears multiple
    ///   times in the import batch (when `conflict_mode` is `Replace`), the entire
    ///   operation fails with `ValidationFailed`. No partial results are preserved.
    ///   This prevents non-deterministic outcomes where the "winner" depends on
    ///   iteration order.
    ///
    /// - **Strict mode duplicates**: If `conflict_mode` is `Strict` and any entry
    ///   already exists, the operation fails immediately with `DuplicateEntry`.
    ///
    /// Validation failures (invalid IP/hostname) do NOT trigger fail-fast. Instead,
    /// they are counted in `failed` and recorded in `validation_errors`, allowing
    /// the import to continue with valid entries.
    ///
    /// # Design Rationale
    ///
    /// Fail-fast on duplicate aggregates ensures deterministic behavior and surfaces
    /// malformed import data early. Users should deduplicate their import data before
    /// sending. The alternative (last-wins or first-wins) would silently discard data.
    pub async fn import_hosts(
        &self,
        entries: Vec<crate::server::write_queue::ParsedEntry>,
        conflict_mode: crate::server::write_queue::ConflictMode,
    ) -> CommandResult<crate::server::write_queue::ImportResult> {
        use crate::server::write_queue::{ConflictMode, ImportResult};
        use std::collections::HashMap;

        let mut result = ImportResult {
            processed: 0,
            created: 0,
            updated: 0,
            skipped: 0,
            failed: 0,
            validation_errors: Vec::new(),
        };

        // Group envelopes by aggregate_id: (aggregate_id, envelopes, expected_version)
        let mut envelopes_by_aggregate: HashMap<Ulid, (Vec<EventEnvelope>, Option<String>)> =
            HashMap::new();

        for entry in entries {
            result.processed = result.processed.saturating_add(1);

            // Validate
            if let Err(e) = validate_ip_address(&entry.ip_address) {
                let error_msg = format!(
                    "Line {}: Invalid IP '{}': {}",
                    entry.line_number, entry.ip_address, e
                );
                tracing::warn!(
                    line = entry.line_number,
                    ip = %entry.ip_address,
                    error = %e,
                    "Import validation failed"
                );
                result.validation_errors.push(error_msg);
                result.failed = result.failed.saturating_add(1);
                continue;
            }
            if let Err(e) = validate_hostname(&entry.hostname) {
                let error_msg = format!(
                    "Line {}: Invalid hostname '{}': {}",
                    entry.line_number, entry.hostname, e
                );
                tracing::warn!(
                    line = entry.line_number,
                    hostname = %entry.hostname,
                    error = %e,
                    "Import validation failed"
                );
                result.validation_errors.push(error_msg);
                result.failed = result.failed.saturating_add(1);
                continue;
            }

            // Check for existing entry
            let existing = self
                .storage
                .find_by_ip_and_hostname(&entry.ip_address, &entry.hostname)
                .await?;

            match (existing, conflict_mode) {
                (Some(_), ConflictMode::Skip) => {
                    result.skipped = result.skipped.saturating_add(1);
                }
                (Some(existing_entry), ConflictMode::Replace) => {
                    // Reject duplicate aggregate updates within a single batch.
                    // Rationale:
                    // 1. Indicates malformed import data (same IP+hostname appears twice)
                    // 2. Outcome would be non-deterministic (which entry's values win?)
                    // 3. Fail-fast with clear error is better than silent last-wins behavior
                    // Users should deduplicate their import data before sending.
                    //
                    // Note: Cross-batch duplicates (same host in concurrent imports) are safe
                    // because WriteQueue serializes all imports - they never interleave.
                    if envelopes_by_aggregate.contains_key(&existing_entry.id) {
                        return Err(CommandError::ValidationFailed(format!(
                            "Line {}: Multiple updates to same host in import batch (IP {} hostname {})",
                            entry.line_number, entry.ip_address, entry.hostname
                        )));
                    }

                    // Generate update events
                    let mut update_envelopes = Vec::new();

                    if entry.comment != existing_entry.comment {
                        let event = HostEvent::CommentUpdated {
                            old_comment: existing_entry.comment.clone(),
                            new_comment: entry.comment.clone(),
                            updated_at: Utc::now(),
                        };
                        update_envelopes.push(self.create_envelope(existing_entry.id, event));
                    }
                    if entry.tags != existing_entry.tags {
                        let event = HostEvent::TagsModified {
                            old_tags: existing_entry.tags.clone(),
                            new_tags: entry.tags.clone(),
                            modified_at: Utc::now(),
                        };
                        update_envelopes.push(self.create_envelope(existing_entry.id, event));
                    }

                    if !update_envelopes.is_empty() {
                        envelopes_by_aggregate.insert(
                            existing_entry.id,
                            (update_envelopes, Some(existing_entry.version)),
                        );
                        result.updated = result.updated.saturating_add(1);
                    } else {
                        // No changes needed, count as skipped
                        result.skipped = result.skipped.saturating_add(1);
                    }
                }
                (Some(_), ConflictMode::Strict) => {
                    return Err(CommandError::DuplicateEntry(format!(
                        "Line {}: Host with IP {} and hostname {} already exists",
                        entry.line_number, entry.ip_address, entry.hostname
                    )));
                }
                (None, _) => {
                    // Create new entry
                    let aggregate_id = Ulid::new();
                    let event = HostEvent::HostCreated {
                        ip_address: entry.ip_address,
                        hostname: entry.hostname,
                        comment: entry.comment,
                        tags: entry.tags,
                        created_at: Utc::now(),
                    };
                    let envelope = self.create_envelope(aggregate_id, event);
                    envelopes_by_aggregate.insert(aggregate_id, (vec![envelope], None));
                    result.created = result.created.saturating_add(1);
                }
            }
        }

        // Commit all events grouped by aggregate
        for (aggregate_id, (envelopes, expected_version)) in envelopes_by_aggregate {
            self.storage
                .append_events(aggregate_id, envelopes, expected_version)
                .await?;
        }

        // Regenerate hosts file once at end if any changes were made
        if result.created > 0 || result.updated > 0 {
            self.regenerate_hosts_file().await?;
        }

        Ok(result)
    }

    /// Delete a snapshot by ID
    ///
    /// Returns true if snapshot was deleted, false if not found
    pub async fn delete_snapshot(&self, snapshot_id: &str) -> CommandResult<bool> {
        match self.storage.delete_snapshot(snapshot_id).await {
            Ok(()) => Ok(true),
            Err(StorageError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// List snapshots with optional pagination
    ///
    /// Returns snapshots ordered by created_at DESC (newest first).
    /// Pagination is handled at the storage layer for efficiency.
    pub async fn list_snapshots(
        &self,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> CommandResult<Vec<SnapshotMetadata>> {
        let snapshots = self.storage.list_snapshots(limit, offset).await?;
        Ok(snapshots)
    }

    /// Create a snapshot of the current hosts file state
    ///
    /// Generates snapshot from current database projections, not from reading /etc/hosts
    pub async fn create_snapshot(
        &self,
        name: Option<String>,
        trigger: String,
    ) -> CommandResult<Snapshot> {
        // Query all active hosts
        let hosts = self.storage.list_all().await?;
        let entry_count = hosts.len() as i32;

        // Generate hosts file content
        let hosts_content = self.hosts_file.format_hosts_file(&hosts);

        // Generate snapshot name if not provided
        let snapshot_name =
            name.unwrap_or_else(|| format!("snapshot-{}", Utc::now().format("%Y%m%d-%H%M%S")));

        // Generate ULID for snapshot_id
        let snapshot_id = Ulid::new().to_string();
        let created_at = Utc::now();

        // Create snapshot
        let snapshot = Snapshot {
            snapshot_id: snapshot_id.clone(),
            created_at,
            hosts_content: hosts_content.clone(),
            entry_count,
            trigger: trigger.clone(),
            name: Some(snapshot_name.clone()),
            event_log_position: None,
        };

        // Save snapshot
        self.storage.save_snapshot(snapshot).await?;

        // Run retention cleanup
        let _deleted = self.cleanup_old_snapshots().await?;

        Ok(Snapshot {
            snapshot_id,
            created_at,
            hosts_content,
            entry_count,
            trigger,
            name: Some(snapshot_name),
            event_log_position: None,
        })
    }

    /// Rollback to a previous snapshot
    ///
    /// Creates a backup snapshot before rollback, then restores the database
    /// to the state captured in the target snapshot by parsing its hosts file
    /// content and recreating entries.
    pub async fn rollback_to_snapshot(&self, snapshot_id: &str) -> CommandResult<RollbackResult> {
        // 1. Fetch snapshot from storage
        let snapshot = match self.storage.get_snapshot(snapshot_id).await {
            Ok(s) => s,
            Err(StorageError::NotFound { .. }) => {
                return Err(CommandError::NotFound(format!(
                    "Snapshot not found: {}",
                    snapshot_id
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let hosts_content = snapshot.hosts_content;

        // 2. Create pre-rollback backup snapshot
        let backup = self
            .create_snapshot(None, "pre-rollback".to_string())
            .await?;
        let backup_snapshot_id = backup.snapshot_id;

        // 3. Parse snapshot content
        let parsed_entries =
            parse_import(hosts_content.as_bytes(), ImportFormat::Hosts).map_err(|e| {
                CommandError::ValidationFailed(format!("Failed to parse snapshot content: {}", e))
            })?;

        // 4. Clear current state (delete all existing hosts)
        let current_hosts = self.storage.list_all().await?;
        for host in &current_hosts {
            self.delete_host(host.id, Some("Deleted during rollback".to_string()))
                .await?;
        }

        // 5. Import parsed entries from snapshot
        let mut restored_count = 0;
        for entry in parsed_entries {
            match self
                .add_host(entry.ip_address, entry.hostname, entry.comment, entry.tags)
                .await
            {
                Ok(_) => restored_count += 1,
                Err(e) => {
                    // Log but don't fail entire rollback for individual entry failures
                    tracing::warn!("Failed to restore entry during rollback: {}", e);
                }
            }
        }

        // Note: regenerate_hosts_file is called by each add_host/delete_host
        // so the final state is already persisted to disk

        Ok(RollbackResult {
            success: true,
            backup_snapshot_id,
            restored_entry_count: restored_count,
        })
    }

    /// Clean up old snapshots based on retention policy
    ///
    /// Deletes snapshots that violate either max_snapshots OR max_age_days
    async fn cleanup_old_snapshots(&self) -> CommandResult<usize> {
        let max_snapshots = self.config.retention.max_snapshots;
        let max_age_days = self.config.retention.max_age_days;

        // Retention disabled if both limits are 0
        if max_snapshots == 0 && max_age_days == 0 {
            return Ok(0);
        }

        // Pass config values directly to storage (types now match)
        let max_count = if max_snapshots > 0 {
            Some(max_snapshots)
        } else {
            None
        };
        let max_age = if max_age_days > 0 {
            Some(max_age_days)
        } else {
            None
        };

        let deleted_count = self
            .storage
            .apply_retention_policy(max_count, max_age)
            .await?;

        Ok(deleted_count)
    }

    async fn regenerate_hosts_file(&self) -> CommandResult<()> {
        match self.hosts_file.regenerate(self.storage.as_ref()).await {
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
    use router_hosts_storage::backends::duckdb::DuckDbStorage;
    use std::env::temp_dir;
    use std::path::PathBuf;

    fn test_config() -> crate::server::config::Config {
        crate::server::config::Config {
            server: crate::server::config::ServerConfig {
                bind_address: "127.0.0.1:50051".to_string(),
                hosts_file_path: "/tmp/test_hosts".to_string(),
            },
            database: crate::server::config::DatabaseConfig {
                path: None,
                url: Some("duckdb://:memory:".to_string()),
            },
            tls: crate::server::config::TlsConfig {
                cert_path: PathBuf::from("/tmp/cert.pem"),
                key_path: PathBuf::from("/tmp/key.pem"),
                ca_cert_path: PathBuf::from("/tmp/ca.pem"),
            },
            retention: crate::server::config::RetentionConfig {
                max_snapshots: 50,
                max_age_days: 30,
            },
            hooks: crate::server::config::HooksConfig::default(),
        }
    }

    async fn setup() -> CommandHandler {
        let storage = DuckDbStorage::new("duckdb://:memory:")
            .await
            .expect("failed to create in-memory storage");
        storage
            .initialize()
            .await
            .expect("failed to initialize storage");
        let storage: Arc<dyn Storage> = Arc::new(storage);

        // Create a unique temp file for each test
        let temp_file = temp_dir().join(format!("test_hosts_{}", ulid::Ulid::new()));
        let hosts_file = Arc::new(HostsFileGenerator::new(temp_file));

        let hooks = Arc::new(HookExecutor::default());
        let config = Arc::new(test_config());

        CommandHandler::new(storage, hosts_file, hooks, config)
    }

    #[tokio::test]
    async fn test_add_host() {
        let handler = setup().await;
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
        let handler = setup().await;
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
        let handler = setup().await;
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
        let handler = setup().await;
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
        let handler = setup().await;
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

        let result = handler.get_host(entry.id).await;
        assert!(matches!(result, Err(CommandError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_list_hosts() {
        let handler = setup().await;

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
        let handler = setup().await;

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
        let handler = setup().await;
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
        let handler = setup().await;
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
        let handler = setup().await;
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
        let handler = setup().await;
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
        let handler = setup().await;
        let fake_id = Ulid::new();

        let result = handler.delete_host(fake_id, None).await;
        assert!(matches!(result, Err(CommandError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_update_not_found() {
        let handler = setup().await;
        let fake_id = Ulid::new();

        let result = handler
            .update_host(fake_id, None, None, None, None, None)
            .await;
        assert!(matches!(result, Err(CommandError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_hostname_validation() {
        let handler = setup().await;

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
        let handler = setup().await;

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
        let handler = setup().await;
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
        let handler = setup().await;
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
        let handler = setup().await;
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

    #[tokio::test]
    async fn test_import_hosts_skip_mode() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup().await;

        // Add existing host
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "existing.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let entries = vec![
            ParsedEntry {
                ip_address: "192.168.1.1".to_string(),
                hostname: "existing.local".to_string(),
                comment: Some("New comment".to_string()),
                tags: vec![],
                line_number: 1,
            },
            ParsedEntry {
                ip_address: "192.168.1.2".to_string(),
                hostname: "new.local".to_string(),
                comment: None,
                tags: vec![],
                line_number: 2,
            },
        ];

        let result = handler
            .import_hosts(entries, ConflictMode::Skip)
            .await
            .unwrap();

        assert_eq!(result.processed, 2);
        assert_eq!(result.created, 1);
        assert_eq!(result.skipped, 1);
        assert_eq!(result.failed, 0);

        // Verify existing host unchanged
        let hosts = handler.list_hosts().await.unwrap();
        let existing = hosts
            .iter()
            .find(|h| h.ip_address == "192.168.1.1")
            .unwrap();
        assert!(existing.comment.is_none()); // Original had no comment
    }

    #[tokio::test]
    async fn test_import_hosts_replace_mode() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup().await;

        // Add existing host
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "existing.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let entries = vec![ParsedEntry {
            ip_address: "192.168.1.1".to_string(),
            hostname: "existing.local".to_string(),
            comment: Some("Updated comment".to_string()),
            tags: vec!["updated".to_string()],
            line_number: 1,
        }];

        let result = handler
            .import_hosts(entries, ConflictMode::Replace)
            .await
            .unwrap();

        assert_eq!(result.processed, 1);
        assert_eq!(result.created, 0);
        assert_eq!(result.updated, 1); // Replace mode: updated existing entry
        assert_eq!(result.skipped, 0);
        assert_eq!(result.failed, 0);

        // Verify host was updated via list_hosts (fixed in #35)
        let hosts = handler.list_hosts().await.unwrap();
        let updated = &hosts[0];
        assert_eq!(updated.comment, Some("Updated comment".to_string()));
        assert_eq!(updated.tags, vec!["updated".to_string()]);
    }

    #[tokio::test]
    async fn test_import_hosts_strict_mode() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup().await;

        // Add existing host
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "existing.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let entries = vec![ParsedEntry {
            ip_address: "192.168.1.1".to_string(),
            hostname: "existing.local".to_string(),
            comment: None,
            tags: vec![],
            line_number: 1,
        }];

        let result = handler.import_hosts(entries, ConflictMode::Strict).await;

        assert!(matches!(result, Err(CommandError::DuplicateEntry(_))));
    }

    #[tokio::test]
    async fn test_import_hosts_duplicate_aggregate_in_batch() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup().await;

        // Add existing host
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "existing.local".to_string(),
                Some("Original comment".to_string()),
                vec![],
            )
            .await
            .unwrap();

        // Try to import two updates to the same host in one batch
        let entries = vec![
            ParsedEntry {
                ip_address: "192.168.1.1".to_string(),
                hostname: "existing.local".to_string(),
                comment: Some("First update".to_string()),
                tags: vec![],
                line_number: 1,
            },
            ParsedEntry {
                ip_address: "192.168.1.1".to_string(),
                hostname: "existing.local".to_string(),
                comment: Some("Second update".to_string()),
                tags: vec![],
                line_number: 2,
            },
        ];

        let result = handler.import_hosts(entries, ConflictMode::Replace).await;

        assert!(
            matches!(&result, Err(CommandError::ValidationFailed(msg)) if msg.contains("Multiple updates to same host")),
            "Expected ValidationFailed error about duplicate aggregate updates, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_import_hosts_replace_mode_no_changes() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup().await;

        // Add existing host
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "existing.local".to_string(),
                Some("Same comment".to_string()),
                vec!["tag1".to_string()],
            )
            .await
            .unwrap();

        // Import same values (no actual changes)
        let entries = vec![ParsedEntry {
            ip_address: "192.168.1.1".to_string(),
            hostname: "existing.local".to_string(),
            comment: Some("Same comment".to_string()),
            tags: vec!["tag1".to_string()],
            line_number: 1,
        }];

        let result = handler
            .import_hosts(entries, ConflictMode::Replace)
            .await
            .unwrap();

        assert_eq!(result.processed, 1);
        assert_eq!(result.created, 0);
        assert_eq!(result.updated, 0);
        assert_eq!(result.skipped, 1); // No changes needed, counted as skipped
        assert_eq!(result.failed, 0);
    }

    #[tokio::test]
    async fn test_import_hosts_validation_failures() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup().await;

        // Mix of valid and invalid entries
        let entries = vec![
            // Valid entry
            ParsedEntry {
                ip_address: "192.168.1.1".to_string(),
                hostname: "valid.local".to_string(),
                comment: None,
                tags: vec![],
                line_number: 1,
            },
            // Invalid IP address
            ParsedEntry {
                ip_address: "not-an-ip".to_string(),
                hostname: "badip.local".to_string(),
                comment: None,
                tags: vec![],
                line_number: 2,
            },
            // Invalid hostname (contains underscore, which is invalid per RFC)
            ParsedEntry {
                ip_address: "192.168.1.3".to_string(),
                hostname: "bad_hostname".to_string(),
                comment: None,
                tags: vec![],
                line_number: 3,
            },
            // Another valid entry
            ParsedEntry {
                ip_address: "192.168.1.4".to_string(),
                hostname: "valid2.local".to_string(),
                comment: None,
                tags: vec![],
                line_number: 4,
            },
        ];

        let result = handler
            .import_hosts(entries, ConflictMode::Skip)
            .await
            .unwrap();

        // Should process all 4, create 2 valid ones, fail 2 invalid ones
        assert_eq!(result.processed, 4);
        assert_eq!(result.created, 2);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.failed, 2);

        // Verify only valid entries were created
        let hosts = handler.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 2);
        assert!(hosts.iter().any(|h| h.hostname == "valid.local"));
        assert!(hosts.iter().any(|h| h.hostname == "valid2.local"));
    }

    // Snapshot tests

    #[tokio::test]
    async fn test_delete_snapshot_not_found() {
        let handler = setup().await;

        let result = handler.delete_snapshot("01JDTEST000000000000000000").await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_delete_snapshot() {
        let handler = setup().await;

        // First create a snapshot
        let snapshot = handler
            .create_snapshot(None, "manual".to_string())
            .await
            .unwrap();

        // Delete it
        let result = handler.delete_snapshot(&snapshot.snapshot_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify it's gone
        let result = handler.delete_snapshot(&snapshot.snapshot_id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_list_snapshots_empty() {
        let handler = setup().await;

        let snapshots = handler.list_snapshots(None, None).await.unwrap();
        assert!(snapshots.is_empty());
    }

    #[tokio::test]
    async fn test_create_snapshot_with_custom_name() {
        let handler = setup().await;

        let snapshot = handler
            .create_snapshot(Some("test-snapshot".to_string()), "manual".to_string())
            .await
            .unwrap();

        assert!(!snapshot.snapshot_id.is_empty());
        assert_eq!(snapshot.name, Some("test-snapshot".to_string()));
        assert_eq!(snapshot.trigger, "manual");
        assert_eq!(snapshot.entry_count, 0); // Empty database
                                             // Verify created_at is set to a reasonable time (not the Unix epoch)
        assert!(snapshot.created_at.timestamp() > 0);
    }

    #[tokio::test]
    async fn test_create_snapshot_auto_generated_name() {
        let handler = setup().await;

        let snapshot = handler
            .create_snapshot(None, "manual".to_string())
            .await
            .unwrap();

        // Verify auto-generated name has correct format
        let name = snapshot.name.unwrap();
        assert!(name.starts_with("snapshot-"));
        assert!(name.len() > 15); // snapshot-YYYYMMDD-HHMMSS
    }

    #[tokio::test]
    async fn test_create_snapshot_captures_hosts() {
        let handler = setup().await;

        // Add a host
        handler
            .add_host(
                "192.168.1.10".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        // Create snapshot
        let snapshot = handler
            .create_snapshot(None, "manual".to_string())
            .await
            .unwrap();

        assert_eq!(snapshot.entry_count, 1);
        assert!(snapshot.hosts_content.contains("192.168.1.10"));
        assert!(snapshot.hosts_content.contains("test.local"));
    }

    #[tokio::test]
    async fn test_cleanup_retention_disabled() {
        let mut handler = setup().await;
        // Set both limits to 0 (disabled)
        let config = Arc::get_mut(&mut handler.config).unwrap();
        config.retention.max_snapshots = 0;
        config.retention.max_age_days = 0;

        // Create multiple snapshots
        for i in 0..5 {
            handler
                .create_snapshot(Some(format!("s{}", i)), "manual".to_string())
                .await
                .unwrap();
        }

        // Verify all snapshots still exist (cleanup was disabled during create)
        let snapshots = handler.list_snapshots(None, None).await.unwrap();
        assert_eq!(snapshots.len(), 5);
    }

    #[tokio::test]
    async fn test_cleanup_by_count_only() {
        let mut handler = setup().await;
        let config = Arc::get_mut(&mut handler.config).unwrap();
        config.retention.max_snapshots = 3;
        config.retention.max_age_days = 0; // Disabled

        // Create 5 snapshots
        for i in 0..5 {
            handler
                .create_snapshot(Some(format!("s{}", i)), "manual".to_string())
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        // Cleanup runs automatically in create_snapshot, so verify final state
        let snapshots = handler.list_snapshots(None, None).await.unwrap();
        assert_eq!(snapshots.len(), 3);

        // Verify we kept the 3 most recent (s2, s3, s4)
        assert_eq!(snapshots[0].name, Some("s4".to_string()));
        assert_eq!(snapshots[1].name, Some("s3".to_string()));
        assert_eq!(snapshots[2].name, Some("s2".to_string()));
    }
}
