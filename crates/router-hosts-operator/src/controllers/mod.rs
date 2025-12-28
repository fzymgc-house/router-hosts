//! Kubernetes controllers for watched resources

pub mod hostmapping;
pub mod ingress;
pub mod ingressroute;
pub mod ingressroutetcp;
pub mod retry;

use std::sync::Arc;

use kube::Client;

use crate::client::RouterHostsClientTrait;
use crate::config::RouterHostsConfigSpec;
use crate::deletion::DeletionScheduler;
use crate::resolver::IpResolverTrait;

use self::retry::RetryTracker;

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
