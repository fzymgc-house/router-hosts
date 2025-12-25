//! Kubernetes controllers for watched resources

pub mod hostmapping;
pub mod ingress;
pub mod ingressroute;
pub mod ingressroutetcp;

use std::sync::Arc;

use crate::client::RouterHostsClient;
use crate::config::RouterHostsConfigSpec;
use crate::deletion::DeletionScheduler;
use crate::resolver::IpResolver;

/// Shared state for all controllers
pub struct ControllerContext {
    pub client: Arc<RouterHostsClient>,
    pub resolver: Arc<IpResolver>,
    pub deletion: Arc<DeletionScheduler>,
    pub config: Arc<RouterHostsConfigSpec>,
}
