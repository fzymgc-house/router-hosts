//! TTL-based deletion scheduler
//!
//! Manages graceful deletion of host entries with configurable grace periods.
//! Pre-existing entries (adopted by operator) only have tags removed, not deleted.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::client::{ClientError, RouterHostsClientTrait};
use crate::config::tags;

/// Entry scheduled for deletion
#[derive(Debug, Clone)]
struct PendingDeletion {
    /// router-hosts entry ID
    entry_id: String,
    /// Hostname (for logging)
    hostname: String,
    /// When the deletion was scheduled
    scheduled_at: Instant,
    /// Grace period before actual deletion
    grace_period: Duration,
    /// Whether this was a pre-existing entry (just remove tags, don't delete)
    pre_existing: bool,
}

/// Manages scheduled deletions with grace periods
pub struct DeletionScheduler {
    pending: Arc<RwLock<HashMap<String, PendingDeletion>>>,
    default_grace_period: Duration,
}

impl DeletionScheduler {
    pub fn new(default_grace_period: Duration) -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            default_grace_period,
        }
    }

    /// Schedule an entry for deletion after grace period
    pub async fn schedule(
        &self,
        entry_id: String,
        hostname: String,
        pre_existing: bool,
        grace_period: Option<Duration>,
    ) {
        let grace = grace_period.unwrap_or(self.default_grace_period);

        let deletion = PendingDeletion {
            entry_id: entry_id.clone(),
            hostname: hostname.clone(),
            scheduled_at: Instant::now(),
            grace_period: grace,
            pre_existing,
        };

        info!(
            entry_id = %entry_id,
            hostname = %hostname,
            grace_seconds = grace.as_secs(),
            pre_existing = pre_existing,
            "Scheduled entry for deletion"
        );

        self.pending.write().await.insert(entry_id, deletion);
    }

    /// Cancel a scheduled deletion (entry reappeared)
    pub async fn cancel(&self, entry_id: &str) -> bool {
        let removed = self.pending.write().await.remove(entry_id).is_some();
        if removed {
            debug!(entry_id = %entry_id, "Cancelled pending deletion");
        }
        removed
    }

    /// Check if an entry is pending deletion
    pub async fn is_pending(&self, entry_id: &str) -> bool {
        self.pending.read().await.contains_key(entry_id)
    }

    /// Process expired deletions
    pub async fn process_expired<C: RouterHostsClientTrait>(
        &self,
        client: &C,
    ) -> Result<ProcessResult, ClientError> {
        let now = Instant::now();
        let mut expired = Vec::new();

        // Find expired entries
        {
            let pending = self.pending.read().await;
            for deletion in pending.values() {
                if now.duration_since(deletion.scheduled_at) >= deletion.grace_period {
                    expired.push(deletion.clone());
                }
            }
        }

        let mut result = ProcessResult::default();

        // Process each expired entry
        for deletion in expired {
            let id = &deletion.entry_id;
            if deletion.pre_existing {
                // Just remove operator tags, don't delete
                match self.remove_operator_tags(client, id).await {
                    Ok(_) => {
                        info!(
                            entry_id = %id,
                            hostname = %deletion.hostname,
                            "Removed operator tags from pre-existing entry"
                        );
                        result.tags_removed += 1;
                    }
                    Err(e) => {
                        warn!(
                            entry_id = %id,
                            error = %e,
                            "Failed to remove tags from entry"
                        );
                        result.errors += 1;
                        continue; // Don't remove from pending, will retry
                    }
                }
            } else {
                // Actually delete the entry
                match client.delete_host(id).await {
                    Ok(true) => {
                        info!(
                            entry_id = %id,
                            hostname = %deletion.hostname,
                            "Deleted host entry"
                        );
                        result.deleted += 1;
                    }
                    Ok(false) => {
                        warn!(entry_id = %id, "Delete returned false");
                        result.errors += 1;
                    }
                    Err(e) => {
                        warn!(entry_id = %id, error = %e, "Failed to delete entry");
                        result.errors += 1;
                        continue; // Don't remove from pending, will retry
                    }
                }
            }

            // Remove from pending
            self.pending.write().await.remove(id);
        }

        Ok(result)
    }

    async fn remove_operator_tags<C: RouterHostsClientTrait>(
        &self,
        client: &C,
        entry_id: &str,
    ) -> Result<(), ClientError> {
        // Get current entry to filter tags
        let entries = client.find_by_tag(tags::OPERATOR).await?;
        let entry = entries.iter().find(|e| e.id == entry_id);

        let Some(entry) = entry else {
            // Entry may have been deleted externally - not an error
            debug!(entry_id = %entry_id, "Entry not found when removing operator tags");
            return Ok(());
        };

        // Remove all operator-related tags
        let new_tags: Vec<String> = entry
            .tags
            .iter()
            .filter(|t| !Self::is_operator_tag(t))
            .cloned()
            .collect();

        client
            .update_host(
                entry_id,
                None,
                None,
                Some(new_tags),
                Some(entry.version.clone()),
            )
            .await?;

        Ok(())
    }

    fn is_operator_tag(tag: &str) -> bool {
        tag == tags::OPERATOR
            || tag == tags::PRE_EXISTING
            || tag.starts_with(tags::PENDING_DELETION)
            || tag.starts_with(tags::SOURCE_PREFIX)
            || tag.starts_with(tags::NAMESPACE_PREFIX)
            || tag.starts_with(tags::KIND_PREFIX)
            || tag.starts_with(tags::CLUSTER_PREFIX)
    }

    /// Get count of pending deletions
    pub async fn pending_count(&self) -> usize {
        self.pending.read().await.len()
    }
}

/// Result of processing expired deletions
#[derive(Debug, Default)]
pub struct ProcessResult {
    /// Entries fully deleted
    pub deleted: usize,
    /// Pre-existing entries with tags removed
    pub tags_removed: usize,
    /// Errors encountered
    pub errors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{HostEntry, MockRouterHostsClientTrait};

    #[test]
    fn test_is_operator_tag() {
        assert!(DeletionScheduler::is_operator_tag("k8s-operator"));
        assert!(DeletionScheduler::is_operator_tag("pre-existing:true"));
        assert!(DeletionScheduler::is_operator_tag("source:abc-123"));
        assert!(DeletionScheduler::is_operator_tag("namespace:default"));
        assert!(DeletionScheduler::is_operator_tag("kind:Ingress"));
        assert!(DeletionScheduler::is_operator_tag("cluster:homelab"));

        assert!(!DeletionScheduler::is_operator_tag("custom-tag"));
        assert!(!DeletionScheduler::is_operator_tag("production"));
    }

    #[test]
    fn test_is_operator_tag_pending_deletion() {
        // pending-deletion: with timestamp suffix
        assert!(DeletionScheduler::is_operator_tag(
            "pending-deletion:2024-01-15T12:00:00Z"
        ));
        assert!(DeletionScheduler::is_operator_tag("pending-deletion:"));
    }

    #[tokio::test]
    async fn test_schedule_and_cancel() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(300));

        scheduler
            .schedule(
                "entry-1".to_string(),
                "test.example.com".to_string(),
                false,
                None,
            )
            .await;

        assert!(scheduler.is_pending("entry-1").await);
        assert_eq!(scheduler.pending_count().await, 1);

        scheduler.cancel("entry-1").await;
        assert!(!scheduler.is_pending("entry-1").await);
        assert_eq!(scheduler.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_schedule_with_custom_grace_period() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(300));

        // Schedule with custom 10 second grace period
        scheduler
            .schedule(
                "entry-1".to_string(),
                "test.example.com".to_string(),
                false,
                Some(Duration::from_secs(10)),
            )
            .await;

        assert!(scheduler.is_pending("entry-1").await);
    }

    #[tokio::test]
    async fn test_schedule_multiple_entries() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(300));

        scheduler
            .schedule(
                "entry-1".to_string(),
                "host1.example.com".to_string(),
                false,
                None,
            )
            .await;
        scheduler
            .schedule(
                "entry-2".to_string(),
                "host2.example.com".to_string(),
                true,
                None,
            )
            .await;
        scheduler
            .schedule(
                "entry-3".to_string(),
                "host3.example.com".to_string(),
                false,
                None,
            )
            .await;

        assert_eq!(scheduler.pending_count().await, 3);
        assert!(scheduler.is_pending("entry-1").await);
        assert!(scheduler.is_pending("entry-2").await);
        assert!(scheduler.is_pending("entry-3").await);
    }

    #[tokio::test]
    async fn test_cancel_nonexistent_entry() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(300));

        // Cancel should return false for non-existent entry
        let result = scheduler.cancel("nonexistent").await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_process_expired_deletes_entry() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(0)); // Zero grace period

        // Schedule for immediate expiry
        scheduler
            .schedule(
                "entry-1".to_string(),
                "test.example.com".to_string(),
                false,
                None,
            )
            .await;

        // Create mock client that returns success
        let mut mock_client = MockRouterHostsClientTrait::new();
        mock_client
            .expect_delete_host()
            .with(mockall::predicate::eq("entry-1"))
            .times(1)
            .returning(|_| Ok(true));

        let result = scheduler.process_expired(&mock_client).await.unwrap();

        assert_eq!(result.deleted, 1);
        assert_eq!(result.tags_removed, 0);
        assert_eq!(result.errors, 0);
        assert!(!scheduler.is_pending("entry-1").await);
    }

    #[tokio::test]
    async fn test_process_expired_removes_tags_for_pre_existing() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(0));

        // Schedule pre-existing entry
        scheduler
            .schedule(
                "entry-1".to_string(),
                "test.example.com".to_string(),
                true,
                None,
            )
            .await;

        // Mock client: find_by_tag returns the entry, update_host succeeds
        let mut mock_client = MockRouterHostsClientTrait::new();

        mock_client
            .expect_find_by_tag()
            .with(mockall::predicate::eq(tags::OPERATOR))
            .times(1)
            .returning(|_| {
                Ok(vec![HostEntry {
                    id: "entry-1".to_string(),
                    hostname: "test.example.com".to_string(),
                    ip_address: "192.168.1.1".to_string(),
                    aliases: vec![],
                    tags: vec![
                        tags::OPERATOR.to_string(),
                        tags::PRE_EXISTING.to_string(),
                        "source:abc-123".to_string(),
                        "custom-tag".to_string(),
                    ],
                    version: "v1".to_string(),
                }])
            });

        mock_client
            .expect_update_host()
            .withf(|id, _ip, _aliases, tags, version| {
                id == "entry-1"
                    && tags
                        .as_ref()
                        .is_some_and(|t| t.len() == 1 && t.contains(&"custom-tag".to_string()))
                    && version == &Some("v1".to_string())
            })
            .times(1)
            .returning(|_, _, _, _, _| {
                Ok(HostEntry {
                    id: "entry-1".to_string(),
                    hostname: "test.example.com".to_string(),
                    ip_address: "192.168.1.1".to_string(),
                    aliases: vec![],
                    tags: vec!["custom-tag".to_string()],
                    version: "v2".to_string(),
                })
            });

        let result = scheduler.process_expired(&mock_client).await.unwrap();

        assert_eq!(result.deleted, 0);
        assert_eq!(result.tags_removed, 1);
        assert_eq!(result.errors, 0);
        assert!(!scheduler.is_pending("entry-1").await);
    }

    #[tokio::test]
    async fn test_process_expired_handles_delete_failure() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(0));

        scheduler
            .schedule(
                "entry-1".to_string(),
                "test.example.com".to_string(),
                false,
                None,
            )
            .await;

        // Mock client that returns error
        let mut mock_client = MockRouterHostsClientTrait::new();
        mock_client.expect_delete_host().times(1).returning(|_| {
            Err(ClientError::GrpcError(tonic::Status::internal(
                "test error",
            )))
        });

        let result = scheduler.process_expired(&mock_client).await.unwrap();

        assert_eq!(result.deleted, 0);
        assert_eq!(result.errors, 1);
        // Entry should still be pending (will retry)
        assert!(scheduler.is_pending("entry-1").await);
    }

    #[tokio::test]
    async fn test_process_expired_handles_delete_false() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(0));

        scheduler
            .schedule(
                "entry-1".to_string(),
                "test.example.com".to_string(),
                false,
                None,
            )
            .await;

        // Mock client that returns false (delete failed on server)
        let mut mock_client = MockRouterHostsClientTrait::new();
        mock_client
            .expect_delete_host()
            .times(1)
            .returning(|_| Ok(false));

        let result = scheduler.process_expired(&mock_client).await.unwrap();

        assert_eq!(result.deleted, 0);
        assert_eq!(result.errors, 1);
    }

    #[tokio::test]
    async fn test_process_expired_with_nonexpired_entries() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(3600)); // 1 hour grace

        scheduler
            .schedule(
                "entry-1".to_string(),
                "test.example.com".to_string(),
                false,
                None,
            )
            .await;

        // Mock client - should not be called
        let mock_client = MockRouterHostsClientTrait::new();

        let result = scheduler.process_expired(&mock_client).await.unwrap();

        assert_eq!(result.deleted, 0);
        assert_eq!(result.tags_removed, 0);
        assert_eq!(result.errors, 0);
        // Entry still pending
        assert!(scheduler.is_pending("entry-1").await);
    }

    #[tokio::test]
    async fn test_remove_tags_entry_not_found() {
        let scheduler = DeletionScheduler::new(Duration::from_secs(0));

        scheduler
            .schedule(
                "entry-1".to_string(),
                "test.example.com".to_string(),
                true,
                None,
            )
            .await;

        // Mock: entry not found when searching by tag
        let mut mock_client = MockRouterHostsClientTrait::new();
        mock_client
            .expect_find_by_tag()
            .times(1)
            .returning(|_| Ok(vec![])); // Empty result - entry not found

        let result = scheduler.process_expired(&mock_client).await.unwrap();

        // Should count as tags_removed (entry may have been deleted externally)
        assert_eq!(result.tags_removed, 1);
        assert_eq!(result.errors, 0);
    }

    #[tokio::test]
    async fn test_process_result_default() {
        let result = ProcessResult::default();
        assert_eq!(result.deleted, 0);
        assert_eq!(result.tags_removed, 0);
        assert_eq!(result.errors, 0);
    }
}
