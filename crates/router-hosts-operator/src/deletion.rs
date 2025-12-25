//! TTL-based deletion scheduler
//!
//! Manages graceful deletion of host entries with configurable grace periods.
//! Pre-existing entries (adopted by operator) only have tags removed, not deleted.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::client::{ClientError, RouterHostsClient};
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
    pub async fn process_expired(
        &self,
        client: &RouterHostsClient,
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

    async fn remove_operator_tags(
        &self,
        client: &RouterHostsClient,
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
            .update_host(entry_id, None, None, Some(new_tags), Some(&entry.version))
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
}
