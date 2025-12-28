//! Retry policy with exponential backoff for controller errors
//!
//! Provides a shared error classification and backoff strategy for all controllers.
//! Errors are classified as transient or permanent to determine appropriate retry behavior.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use kube::runtime::controller::Action;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Maximum number of retries before giving up
const MAX_RETRIES: u32 = 10;

/// Base delay for exponential backoff (seconds)
const BASE_DELAY_SECS: u64 = 5;

/// Maximum delay between retries (1 hour)
const MAX_DELAY_SECS: u64 = 3600;

/// Tracks retry attempts per resource
#[derive(Debug, Default)]
pub struct RetryTracker {
    /// Map of resource UID to retry count
    attempts: Mutex<HashMap<String, u32>>,
}

impl RetryTracker {
    /// Create a new retry tracker
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    /// Increment retry count for a resource and return the new count
    pub async fn increment(&self, uid: &str) -> u32 {
        let mut attempts = self.attempts.lock().await;
        let count = attempts.entry(uid.to_string()).or_insert(0);
        *count += 1;
        *count
    }

    /// Reset retry count for a resource (call on successful reconciliation)
    pub async fn reset(&self, uid: &str) {
        let mut attempts = self.attempts.lock().await;
        attempts.remove(uid);
    }

    /// Get current retry count for a resource
    pub async fn get(&self, uid: &str) -> u32 {
        let attempts = self.attempts.lock().await;
        attempts.get(uid).copied().unwrap_or(0)
    }

    /// Clean up entries for resources that no longer exist
    pub async fn cleanup(&self, active_uids: &[String]) {
        let mut attempts = self.attempts.lock().await;
        attempts.retain(|uid, _| active_uids.contains(uid));
    }
}

/// Error classification for retry behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Transient errors that should be retried with backoff
    /// Examples: network issues, temporary unavailability, rate limiting
    Transient,
    /// Permanent errors that will not recover without intervention
    /// Examples: validation errors, missing required fields, invalid configuration
    Permanent,
}

/// Determine retry action based on error kind and attempt count
///
/// Returns the action to take and whether max retries has been exceeded.
pub fn compute_backoff(attempt: u32, kind: ErrorKind) -> Action {
    match kind {
        ErrorKind::Transient => {
            if attempt >= MAX_RETRIES {
                warn!(
                    attempt,
                    max_retries = MAX_RETRIES,
                    "Max retries exceeded, waiting for resource change"
                );
                // Stop retrying until the resource changes
                Action::await_change()
            } else {
                // Exponential backoff: 5s, 10s, 20s, 40s, ... up to 1 hour
                let delay_secs = BASE_DELAY_SECS * 2u64.pow(attempt.saturating_sub(1));
                let capped_delay = delay_secs.min(MAX_DELAY_SECS);
                debug!(
                    attempt,
                    delay_secs = capped_delay,
                    "Scheduling retry with exponential backoff"
                );
                Action::requeue(Duration::from_secs(capped_delay))
            }
        }
        ErrorKind::Permanent => {
            // Permanent errors: wait for resource change, no point retrying
            warn!("Permanent error, waiting for resource change");
            Action::await_change()
        }
    }
}

/// Convenience function to create retry tracker wrapped in Arc
pub fn new_tracker() -> Arc<RetryTracker> {
    Arc::new(RetryTracker::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_retry_tracker_increment() {
        let tracker = RetryTracker::new();

        assert_eq!(tracker.get("uid-1").await, 0);
        assert_eq!(tracker.increment("uid-1").await, 1);
        assert_eq!(tracker.increment("uid-1").await, 2);
        assert_eq!(tracker.get("uid-1").await, 2);
    }

    #[tokio::test]
    async fn test_retry_tracker_reset() {
        let tracker = RetryTracker::new();

        tracker.increment("uid-1").await;
        tracker.increment("uid-1").await;
        assert_eq!(tracker.get("uid-1").await, 2);

        tracker.reset("uid-1").await;
        assert_eq!(tracker.get("uid-1").await, 0);
    }

    #[tokio::test]
    async fn test_retry_tracker_cleanup() {
        let tracker = RetryTracker::new();

        tracker.increment("uid-1").await;
        tracker.increment("uid-2").await;
        tracker.increment("uid-3").await;

        // Keep only uid-1 and uid-3
        tracker
            .cleanup(&["uid-1".to_string(), "uid-3".to_string()])
            .await;

        assert_eq!(tracker.get("uid-1").await, 1);
        assert_eq!(tracker.get("uid-2").await, 0); // Cleaned up
        assert_eq!(tracker.get("uid-3").await, 1);
    }

    #[test]
    fn test_compute_backoff_transient() {
        // First attempt: should requeue with backoff (requeue_after: Some)
        let action = compute_backoff(1, ErrorKind::Transient);
        let debug = format!("{:?}", action);
        assert!(
            debug.contains("Some"),
            "Expected requeue (Some duration): {debug}"
        );

        // Second attempt: should still requeue
        let action = compute_backoff(2, ErrorKind::Transient);
        let debug = format!("{:?}", action);
        assert!(
            debug.contains("Some"),
            "Expected requeue (Some duration): {debug}"
        );
    }

    #[test]
    fn test_compute_backoff_max_retries() {
        // After MAX_RETRIES, should await change (requeue_after: None)
        let action = compute_backoff(MAX_RETRIES, ErrorKind::Transient);
        let debug = format!("{:?}", action);
        assert!(
            debug.contains("None"),
            "Expected await_change (None duration): {debug}"
        );
    }

    #[test]
    fn test_compute_backoff_permanent() {
        // Permanent errors should await change immediately (requeue_after: None)
        let action = compute_backoff(1, ErrorKind::Permanent);
        let debug = format!("{:?}", action);
        assert!(
            debug.contains("None"),
            "Expected await_change (None duration): {debug}"
        );
    }
}
