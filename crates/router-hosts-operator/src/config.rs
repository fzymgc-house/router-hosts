//! CRD and configuration types

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// IP resolution strategy
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum IpResolutionStrategy {
    /// Discover IP from an ingress controller Service
    IngressController {
        /// Service name
        #[serde(rename = "serviceName")]
        service_name: String,
        /// Service namespace
        #[serde(rename = "serviceNamespace")]
        service_namespace: String,
    },
    /// Use a static IP address
    Static {
        /// The IP address to use
        address: String,
    },
}

/// Reference to a Kubernetes Secret
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretReference {
    /// Secret name
    pub name: String,
    /// Secret namespace
    pub namespace: String,
}

/// Server connection configuration
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    /// gRPC endpoint (host:port)
    pub endpoint: String,
    /// Reference to Secret containing mTLS certificates
    pub tls_secret_ref: SecretReference,
}

/// Deletion behavior configuration
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeletionConfig {
    /// Grace period before deleting entries (seconds)
    #[serde(default = "default_grace_period")]
    pub grace_period_seconds: u32,
}

impl Default for DeletionConfig {
    fn default() -> Self {
        Self {
            grace_period_seconds: default_grace_period(),
        }
    }
}

fn default_grace_period() -> u32 {
    300 // 5 minutes
}

/// RouterHostsConfig spec
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "router-hosts.fzymgc.house",
    version = "v1alpha1",
    kind = "RouterHostsConfig",
    plural = "routerhostsconfigs",
    shortname = "rhc",
    namespaced = false
)]
#[serde(rename_all = "camelCase")]
pub struct RouterHostsConfigSpec {
    /// Server connection settings
    pub server: ServerConfig,
    /// IP resolution strategies (tried in order)
    pub ip_resolution: Vec<IpResolutionStrategy>,
    /// Deletion behavior
    #[serde(default)]
    pub deletion: DeletionConfig,
    /// Default tags added to all managed entries
    #[serde(default)]
    pub default_tags: Vec<String>,
}

/// Annotations used by the operator
pub mod annotations {
    /// Opt-in annotation - must be "true" to process resource
    pub const ENABLED: &str = "router-hosts.fzymgc.house/enabled";
    /// Override IP address for this resource
    pub const IP_ADDRESS: &str = "router-hosts.fzymgc.house/ip-address";
    /// Additional tags (comma-separated)
    pub const TAGS: &str = "router-hosts.fzymgc.house/tags";
    /// Hostname aliases (comma-separated)
    pub const ALIASES: &str = "router-hosts.fzymgc.house/aliases";
    /// Override grace period (seconds)
    pub const GRACE_PERIOD: &str = "router-hosts.fzymgc.house/grace-period";
}

/// Tags used for ownership tracking
pub mod tags {
    /// Marks entry as managed by operator
    pub const OPERATOR: &str = "k8s-operator";
    /// Entry existed before operator adopted it
    pub const PRE_EXISTING: &str = "pre-existing:true";
    /// Prefix for pending deletion timestamp
    pub const PENDING_DELETION: &str = "pending-deletion:";
    /// Prefix for source resource UID
    pub const SOURCE_PREFIX: &str = "source:";
    /// Prefix for namespace
    pub const NAMESPACE_PREFIX: &str = "namespace:";
    /// Prefix for resource kind
    pub const KIND_PREFIX: &str = "kind:";
    /// Prefix for cluster name
    pub const CLUSTER_PREFIX: &str = "cluster:";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_config() {
        let yaml = r#"
server:
  endpoint: "router.lan:50051"
  tlsSecretRef:
    name: router-hosts-mtls
    namespace: router-hosts-system
ipResolution:
  - type: ingressController
    serviceName: traefik
    serviceNamespace: traefik-system
  - type: static
    address: "192.168.1.100"
deletion:
  gracePeriodSeconds: 600
defaultTags:
  - k8s-operator
  - cluster:homelab
"#;
        let spec: RouterHostsConfigSpec =
            serde_yaml::from_str(yaml).expect("test YAML should parse successfully");
        assert_eq!(spec.server.endpoint, "router.lan:50051");
        assert_eq!(spec.ip_resolution.len(), 2);
        assert_eq!(spec.deletion.grace_period_seconds, 600);
        assert_eq!(spec.default_tags.len(), 2);
    }

    #[test]
    fn test_default_grace_period() {
        let yaml = r#"
server:
  endpoint: "router.lan:50051"
  tlsSecretRef:
    name: mtls
    namespace: default
ipResolution: []
"#;
        let spec: RouterHostsConfigSpec =
            serde_yaml::from_str(yaml).expect("test YAML should parse successfully");
        assert_eq!(spec.deletion.grace_period_seconds, 300);
    }
}
