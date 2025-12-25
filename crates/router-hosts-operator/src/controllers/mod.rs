//! Kubernetes controllers for watched resources

pub mod hostmapping;
pub mod ingress;
pub mod ingressroute;
pub mod ingressroutetcp;

use std::sync::Arc;

use kube::Client;

use crate::client::RouterHostsClient;
use crate::config::RouterHostsConfigSpec;
use crate::deletion::DeletionScheduler;
use crate::resolver::IpResolver;

/// Shared state for all controllers
pub struct ControllerContext {
    /// router-hosts gRPC client
    pub client: Arc<RouterHostsClient>,
    /// IP resolution strategies
    pub resolver: Arc<IpResolver>,
    /// TTL-based deletion scheduler
    pub deletion: Arc<DeletionScheduler>,
    /// Operator configuration
    pub config: Arc<RouterHostsConfigSpec>,
    /// Kubernetes API client (shared across controllers)
    pub kube_client: Client,
}
