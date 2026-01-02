//! Kubernetes controllers for watched resources

pub mod hostmapping;
pub mod ingress;
pub mod ingressroute;
pub mod ingressroutetcp;
pub mod retry;
pub mod service;

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use kube::Client;

use crate::client::RouterHostsClientTrait;
use crate::config::{annotations, RouterHostsConfigSpec};
use crate::deletion::DeletionScheduler;
use crate::resolver::IpResolverTrait;

use self::retry::RetryTracker;

/// Compare two tag lists regardless of order using HashSet for O(n) comparison.
///
/// This is a shared utility used by all controllers to compare tags
/// without being affected by ordering differences.
pub fn tags_equal(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let a_set: HashSet<_> = a.iter().collect();
    let b_set: HashSet<_> = b.iter().collect();
    a_set == b_set
}

/// Parse aliases from annotation (comma-separated list).
///
/// Returns an empty vec if annotation is not present.
pub fn parse_aliases(annotations: &BTreeMap<String, String>) -> Vec<String> {
    annotations
        .get(annotations::ALIASES)
        .map(|s| {
            s.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Parse custom tags from annotation (comma-separated list).
///
/// Returns an empty vec if annotation is not present.
pub fn parse_custom_tags(annotations: &BTreeMap<String, String>) -> Vec<String> {
    annotations
        .get(annotations::TAGS)
        .map(|s| {
            s.split(',')
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Shared state for all controllers
pub struct ControllerContext {
    /// router-hosts gRPC client (trait object for testability)
    pub client: Arc<dyn RouterHostsClientTrait>,
    /// IP resolution strategies (trait object for testability)
    pub resolver: Arc<dyn IpResolverTrait>,
    /// TTL-based deletion scheduler
    pub deletion: Arc<DeletionScheduler>,
    /// Operator configuration
    pub config: Arc<RouterHostsConfigSpec>,
    /// Kubernetes API client (shared across controllers)
    pub kube_client: Client,
    /// Retry tracker for exponential backoff
    pub retry_tracker: Arc<RetryTracker>,
}
