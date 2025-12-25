# router-hosts-operator Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Kubernetes operator that syncs Ingress and Traefik IngressRoute hostnames to router-hosts for internal DNS resolution.

**Architecture:** Controller pattern using kube-rs with multiple reconcilers watching Ingress, IngressRoute, IngressRouteTCP, and HostMapping CRDs. Each reconciler extracts hostnames, resolves IPs, and syncs to router-hosts via gRPC/mTLS. Leader election ensures single-writer semantics.

**Tech Stack:** Rust, kube-rs, tonic (gRPC), tokio, k8s-openapi

---

## Phase 1: Project Scaffolding

### Task 1.1: Create Crate Structure

**Files:**
- Create: `crates/router-hosts-operator/Cargo.toml`
- Create: `crates/router-hosts-operator/src/lib.rs`
- Create: `crates/router-hosts-operator/src/main.rs`
- Modify: `Cargo.toml` (workspace)

**Step 1: Add crate to workspace Cargo.toml**

Add to `members` array in root `Cargo.toml`:

```toml
members = [
    "crates/router-hosts-common",
    "crates/router-hosts-storage",
    "crates/router-hosts",
    "crates/router-hosts-duckdb",
    "crates/router-hosts-e2e",
    "crates/router-hosts-operator",  # Add this
]
```

**Step 2: Create crate Cargo.toml**

Create `crates/router-hosts-operator/Cargo.toml`:

```toml
[package]
name = "router-hosts-operator"
version = "0.1.0"
edition = "2021"
authors = ["Sean Fitzgerald <sean@fzymgc.dev>"]
description = "Kubernetes operator for syncing Ingress hostnames to router-hosts"
license = "MIT"
repository = "https://github.com/fzymgc-house/router-hosts"

[dependencies]
router-hosts-common = { path = "../router-hosts-common" }

# Kubernetes
kube = { version = "0.98", features = ["runtime", "derive", "client"] }
k8s-openapi = { version = "0.24", features = ["v1_31"] }

# Async
tokio = { version = "1", features = ["full"] }
futures = "0.3"

# gRPC
tonic = { version = "0.12", features = ["tls"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"

# Error handling
thiserror = "2"
anyhow = "1"

# Logging/tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# Metrics
prometheus = "0.13"

# Utilities
regex = "1"
chrono = { version = "0.4", features = ["serde"] }

[dev-dependencies]
tokio-test = "0.4"
```

**Step 3: Create lib.rs stub**

Create `crates/router-hosts-operator/src/lib.rs`:

```rust
//! router-hosts-operator: Kubernetes controller for DNS host synchronization

pub mod config;
pub mod controllers;
pub mod client;
pub mod deletion;
pub mod matcher;
pub mod resolver;

pub use config::RouterHostsConfig;
```

**Step 4: Create main.rs stub**

Create `crates/router-hosts-operator/src/main.rs`:

```rust
use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("router-hosts-operator starting");
    Ok(())
}
```

**Step 5: Create module stubs**

Create empty module files:

`crates/router-hosts-operator/src/config.rs`:
```rust
//! CRD and configuration types
```

`crates/router-hosts-operator/src/controllers/mod.rs`:
```rust
//! Kubernetes controllers for watched resources

pub mod ingress;
pub mod ingressroute;
pub mod ingressroutetcp;
pub mod hostmapping;
```

`crates/router-hosts-operator/src/controllers/ingress.rs`:
```rust
//! Ingress controller
```

`crates/router-hosts-operator/src/controllers/ingressroute.rs`:
```rust
//! Traefik IngressRoute controller
```

`crates/router-hosts-operator/src/controllers/ingressroutetcp.rs`:
```rust
//! Traefik IngressRouteTCP controller
```

`crates/router-hosts-operator/src/controllers/hostmapping.rs`:
```rust
//! HostMapping CRD controller
```

`crates/router-hosts-operator/src/client.rs`:
```rust
//! router-hosts gRPC client wrapper
```

`crates/router-hosts-operator/src/deletion.rs`:
```rust
//! TTL-based deletion scheduler
```

`crates/router-hosts-operator/src/matcher.rs`:
```rust
//! Traefik match expression parser
```

`crates/router-hosts-operator/src/resolver.rs`:
```rust
//! IP resolution strategies
```

**Step 6: Verify build**

Run: `cargo build -p router-hosts-operator`
Expected: Build succeeds with warnings about unused code

**Step 7: Commit**

```bash
git add -A
git commit -m "feat(operator): scaffold router-hosts-operator crate

Initial project structure with module stubs for:
- CRD configuration
- Controllers (Ingress, IngressRoute, IngressRouteTCP, HostMapping)
- router-hosts client wrapper
- Deletion scheduler
- Traefik match parser
- IP resolver"
```

---

## Phase 2: Traefik Match Parser

### Task 2.1: Host() Matcher Tests

**Files:**
- Modify: `crates/router-hosts-operator/src/matcher.rs`

**Step 1: Write failing tests for Host() extraction**

Replace `crates/router-hosts-operator/src/matcher.rs`:

```rust
//! Traefik match expression parser
//!
//! Extracts hostnames from Traefik match expressions like:
//! - `Host(\`foo.example.com\`)`
//! - `Host(\`a.com\`) || Host(\`b.com\`)`
//! - `HostSNI(\`db.example.com\`)`

use regex::Regex;
use std::sync::LazyLock;

static HOST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Host\(`([^`]+)`\)").expect("valid regex")
});

static HOST_SNI_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"HostSNI\(`([^`]+)`\)").expect("valid regex")
});

/// Extract all hostnames from a Traefik match expression.
///
/// Handles both `Host()` and `HostSNI()` matchers.
/// Complex boolean logic is ignored - all host values are extracted.
pub fn extract_hosts(match_expr: &str) -> Vec<String> {
    let mut hosts = Vec::new();

    for cap in HOST_REGEX.captures_iter(match_expr) {
        if let Some(host) = cap.get(1) {
            hosts.push(host.as_str().to_string());
        }
    }

    for cap in HOST_SNI_REGEX.captures_iter(match_expr) {
        if let Some(host) = cap.get(1) {
            hosts.push(host.as_str().to_string());
        }
    }

    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_host() {
        let expr = "Host(`foo.example.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["foo.example.com"]);
    }

    #[test]
    fn test_multiple_hosts_or() {
        let expr = "Host(`a.com`) || Host(`b.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_host_with_path_prefix() {
        let expr = "Host(`api.example.com`) && PathPrefix(`/v1`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["api.example.com"]);
    }

    #[test]
    fn test_host_sni() {
        let expr = "HostSNI(`db.example.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["db.example.com"]);
    }

    #[test]
    fn test_mixed_host_and_sni() {
        let expr = "Host(`web.example.com`) || HostSNI(`db.example.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["web.example.com", "db.example.com"]);
    }

    #[test]
    fn test_complex_expression() {
        let expr = "(Host(`a.com`) || Host(`b.com`)) && PathPrefix(`/api`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_no_hosts() {
        let expr = "PathPrefix(`/api`)";
        let hosts = extract_hosts(expr);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_empty_expression() {
        let hosts = extract_hosts("");
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_subdomain() {
        let expr = "Host(`app.staging.example.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["app.staging.example.com"]);
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p router-hosts-operator matcher`
Expected: All 9 tests pass

**Step 3: Commit**

```bash
git add crates/router-hosts-operator/src/matcher.rs
git commit -m "feat(operator): add Traefik match expression parser

Extracts Host() and HostSNI() hostnames from Traefik match
expressions using regex. Handles:
- Single hosts
- Multiple hosts with || operator
- HostSNI for TCP routes
- Complex expressions (extracts all hosts, ignores boolean logic)"
```

---

## Phase 3: CRD Definitions

### Task 3.1: RouterHostsConfig CRD

**Files:**
- Modify: `crates/router-hosts-operator/src/config.rs`

**Step 1: Define RouterHostsConfig types**

Replace `crates/router-hosts-operator/src/config.rs`:

```rust
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
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeletionConfig {
    /// Grace period before deleting entries (seconds)
    #[serde(default = "default_grace_period")]
    pub grace_period_seconds: u32,
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
        let spec: RouterHostsConfigSpec = serde_yaml::from_str(yaml).unwrap();
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
        let spec: RouterHostsConfigSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.deletion.grace_period_seconds, 300);
    }
}
```

**Step 2: Update lib.rs to add schemars**

Add to `Cargo.toml` dependencies:

```toml
schemars = "0.8"
```

**Step 3: Run tests**

Run: `cargo test -p router-hosts-operator config`
Expected: 2 tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(operator): add RouterHostsConfig CRD definition

Defines the cluster-scoped configuration CRD with:
- Server connection (endpoint, mTLS secret ref)
- IP resolution strategies (IngressController, Static)
- Deletion grace period config
- Default tags
- Annotation and tag constants for ownership tracking"
```

### Task 3.2: HostMapping CRD

**Files:**
- Create: `crates/router-hosts-operator/src/hostmapping.rs`
- Modify: `crates/router-hosts-operator/src/lib.rs`

**Step 1: Define HostMapping CRD**

Create `crates/router-hosts-operator/src/hostmapping.rs`:

```rust
//! HostMapping CRD for explicit host-to-IP mappings

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// HostMapping spec - defines a single hostname mapping
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "router-hosts.fzymgc.house",
    version = "v1alpha1",
    kind = "HostMapping",
    plural = "hostmappings",
    shortname = "hm",
    namespaced = true,
    status = "HostMappingStatus",
    printcolumn = r#"{"name":"Hostname", "type":"string", "jsonPath":".spec.hostname"}"#,
    printcolumn = r#"{"name":"IP", "type":"string", "jsonPath":".spec.ipAddress"}"#,
    printcolumn = r#"{"name":"Synced", "type":"string", "jsonPath":".status.synced"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct HostMappingSpec {
    /// The hostname to create in router-hosts
    pub hostname: String,
    /// Optional IP address (uses IP resolution if omitted)
    pub ip_address: Option<String>,
    /// Optional hostname aliases
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Optional additional tags
    #[serde(default)]
    pub tags: Vec<String>,
}

/// HostMapping status
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostMappingStatus {
    /// Whether the entry is synced to router-hosts
    #[serde(default)]
    pub synced: bool,
    /// The router-hosts entry ID (if synced)
    pub router_hosts_id: Option<String>,
    /// Last successful sync time
    pub last_sync_time: Option<String>,
    /// Error message if sync failed
    pub error: Option<String>,
    /// Status conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

/// Kubernetes-style condition
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Type of condition (e.g., "Synced", "Ready")
    #[serde(rename = "type")]
    pub type_: String,
    /// Status: "True", "False", or "Unknown"
    pub status: String,
    /// Last time the condition transitioned
    pub last_transition_time: String,
    /// Machine-readable reason for the condition
    pub reason: String,
    /// Human-readable message
    pub message: String,
}

impl Condition {
    pub fn synced(success: bool, reason: &str, message: &str) -> Self {
        Self {
            type_: "Synced".to_string(),
            status: if success { "True" } else { "False" }.to_string(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            message: message.to_string(),
        }
    }

    pub fn ready(ready: bool, reason: &str, message: &str) -> Self {
        Self {
            type_: "Ready".to_string(),
            status: if ready { "True" } else { "False" }.to_string(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            message: message.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_hostmapping() {
        let yaml = r#"
hostname: legacy-app.example.com
ipAddress: 10.0.0.50
aliases:
  - legacy.local
tags:
  - external
"#;
        let spec: HostMappingSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.hostname, "legacy-app.example.com");
        assert_eq!(spec.ip_address, Some("10.0.0.50".to_string()));
        assert_eq!(spec.aliases, vec!["legacy.local"]);
    }

    #[test]
    fn test_minimal_hostmapping() {
        let yaml = r#"
hostname: app.example.com
"#;
        let spec: HostMappingSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.hostname, "app.example.com");
        assert!(spec.ip_address.is_none());
        assert!(spec.aliases.is_empty());
    }

    #[test]
    fn test_condition_creation() {
        let cond = Condition::synced(true, "Success", "Entry synced");
        assert_eq!(cond.type_, "Synced");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason, "Success");
    }
}
```

**Step 2: Update lib.rs**

Update `crates/router-hosts-operator/src/lib.rs`:

```rust
//! router-hosts-operator: Kubernetes controller for DNS host synchronization

pub mod client;
pub mod config;
pub mod controllers;
pub mod deletion;
pub mod hostmapping;
pub mod matcher;
pub mod resolver;

pub use config::RouterHostsConfig;
pub use hostmapping::HostMapping;
```

**Step 3: Run tests**

Run: `cargo test -p router-hosts-operator hostmapping`
Expected: 3 tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(operator): add HostMapping CRD definition

Namespaced CRD for explicit hostname-to-IP mappings with:
- Optional IP address (falls back to IP resolution)
- Aliases and tags
- Status with sync state, router-hosts ID, conditions
- Print columns for kubectl output"
```

---

## Phase 4: IP Resolver

### Task 4.1: IP Resolution Strategies

**Files:**
- Modify: `crates/router-hosts-operator/src/resolver.rs`

**Step 1: Implement IP resolver**

Replace `crates/router-hosts-operator/src/resolver.rs`:

```rust
//! IP resolution strategies
//!
//! Resolves target IP addresses for host entries using a fallback chain:
//! 1. Annotation override on the resource
//! 2. Ingress controller Service IP
//! 3. Static configured IP

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::Service;
use kube::{Api, Client};
use thiserror::Error;

use crate::config::{annotations, IpResolutionStrategy};

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("No IP resolution strategy succeeded")]
    NoIpResolved,
    #[error("Service {namespace}/{name} not found")]
    ServiceNotFound { namespace: String, name: String },
    #[error("Service {namespace}/{name} has no external IP")]
    NoExternalIp { namespace: String, name: String },
    #[error("Invalid IP address in annotation: {0}")]
    InvalidAnnotationIp(String),
    #[error("Kubernetes API error: {0}")]
    KubeError(#[from] kube::Error),
}

/// Resolves IP addresses for host entries
pub struct IpResolver {
    client: Client,
    strategies: Vec<IpResolutionStrategy>,
}

impl IpResolver {
    pub fn new(client: Client, strategies: Vec<IpResolutionStrategy>) -> Self {
        Self { client, strategies }
    }

    /// Resolve IP for a resource, checking annotation override first
    pub async fn resolve(
        &self,
        annotations: &BTreeMap<String, String>,
    ) -> Result<String, ResolverError> {
        // Check annotation override first
        if let Some(ip) = annotations.get(annotations::IP_ADDRESS) {
            if Self::is_valid_ip(ip) {
                return Ok(ip.clone());
            }
            return Err(ResolverError::InvalidAnnotationIp(ip.clone()));
        }

        // Try each strategy in order
        for strategy in &self.strategies {
            match self.try_strategy(strategy).await {
                Ok(ip) => return Ok(ip),
                Err(_) => continue,
            }
        }

        Err(ResolverError::NoIpResolved)
    }

    async fn try_strategy(
        &self,
        strategy: &IpResolutionStrategy,
    ) -> Result<String, ResolverError> {
        match strategy {
            IpResolutionStrategy::IngressController {
                service_name,
                service_namespace,
            } => self.resolve_from_service(service_namespace, service_name).await,
            IpResolutionStrategy::Static { address } => Ok(address.clone()),
        }
    }

    async fn resolve_from_service(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<String, ResolverError> {
        let services: Api<Service> = Api::namespaced(self.client.clone(), namespace);

        let svc = services.get(name).await.map_err(|e| match e {
            kube::Error::Api(ref ae) if ae.code == 404 => ResolverError::ServiceNotFound {
                namespace: namespace.to_string(),
                name: name.to_string(),
            },
            other => ResolverError::KubeError(other),
        })?;

        // Try LoadBalancer external IP first
        if let Some(status) = &svc.status {
            if let Some(lb) = &status.load_balancer {
                if let Some(ingresses) = &lb.ingress {
                    for ingress in ingresses {
                        if let Some(ip) = &ingress.ip {
                            return Ok(ip.clone());
                        }
                    }
                }
            }
        }

        // Fall back to ClusterIP
        if let Some(spec) = &svc.spec {
            if let Some(cluster_ip) = &spec.cluster_ip {
                if cluster_ip != "None" {
                    return Ok(cluster_ip.clone());
                }
            }
        }

        Err(ResolverError::NoExternalIp {
            namespace: namespace.to_string(),
            name: name.to_string(),
        })
    }

    fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4() {
        assert!(IpResolver::is_valid_ip("192.168.1.1"));
        assert!(IpResolver::is_valid_ip("10.0.0.1"));
    }

    #[test]
    fn test_valid_ipv6() {
        assert!(IpResolver::is_valid_ip("::1"));
        assert!(IpResolver::is_valid_ip("2001:db8::1"));
    }

    #[test]
    fn test_invalid_ip() {
        assert!(!IpResolver::is_valid_ip("not-an-ip"));
        assert!(!IpResolver::is_valid_ip("192.168.1.999"));
        assert!(!IpResolver::is_valid_ip(""));
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p router-hosts-operator resolver`
Expected: 3 tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(operator): add IP resolution with fallback chain

Resolves IPs using ordered strategies:
1. Annotation override (router-hosts.fzymgc.house/ip-address)
2. Ingress controller Service (LoadBalancer IP or ClusterIP)
3. Static configured IP

Validates IP addresses and provides clear error messages."
```

---

## Phase 5: router-hosts Client

### Task 5.1: gRPC Client Wrapper

**Files:**
- Modify: `crates/router-hosts-operator/src/client.rs`

**Step 1: Implement client wrapper**

Replace `crates/router-hosts-operator/src/client.rs`:

```rust
//! router-hosts gRPC client wrapper
//!
//! Provides a high-level interface for interacting with the router-hosts server.

use router_hosts_common::proto::router_hosts::v1::{
    hosts_service_client::HostsServiceClient, AddHostRequest, DeleteHostRequest,
    ListHostsRequest, SearchHostsRequest, UpdateHostRequest, TagsUpdate,
};
use thiserror::Error;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, instrument};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Failed to connect to router-hosts: {0}")]
    ConnectionFailed(#[from] tonic::transport::Error),
    #[error("gRPC error: {0}")]
    GrpcError(#[from] tonic::Status),
    #[error("TLS configuration error: {0}")]
    TlsError(String),
}

/// Entry found in router-hosts
#[derive(Debug, Clone)]
pub struct HostEntry {
    pub id: String,
    pub hostname: String,
    pub ip_address: String,
    pub aliases: Vec<String>,
    pub tags: Vec<String>,
    pub version: String,
}

/// Client for router-hosts gRPC API
pub struct RouterHostsClient {
    inner: HostsServiceClient<Channel>,
}

impl RouterHostsClient {
    /// Create a new client with mTLS
    pub async fn new(
        endpoint: &str,
        ca_cert: &[u8],
        client_cert: &[u8],
        client_key: &[u8],
    ) -> Result<Self, ClientError> {
        let ca = Certificate::from_pem(ca_cert);
        let identity = Identity::from_pem(client_cert, client_key);

        let tls = ClientTlsConfig::new()
            .ca_certificate(ca)
            .identity(identity);

        let channel = Channel::from_shared(format!("https://{endpoint}"))
            .map_err(|e| ClientError::TlsError(e.to_string()))?
            .tls_config(tls)?
            .connect()
            .await?;

        Ok(Self {
            inner: HostsServiceClient::new(channel),
        })
    }

    /// Search for entries by hostname
    #[instrument(skip(self))]
    pub async fn find_by_hostname(&self, hostname: &str) -> Result<Option<HostEntry>, ClientError> {
        let mut client = self.inner.clone();
        let request = SearchHostsRequest {
            query: hostname.to_string(),
        };

        let mut stream = client.search_hosts(request).await?.into_inner();

        while let Some(response) = stream.message().await? {
            if let Some(entry) = response.entry {
                if entry.hostname == hostname {
                    return Ok(Some(HostEntry {
                        id: entry.id,
                        hostname: entry.hostname,
                        ip_address: entry.ip_address,
                        aliases: entry.aliases,
                        tags: entry.tags,
                        version: entry.version,
                    }));
                }
            }
        }

        Ok(None)
    }

    /// Search for entries by tag
    #[instrument(skip(self))]
    pub async fn find_by_tag(&self, tag: &str) -> Result<Vec<HostEntry>, ClientError> {
        let mut client = self.inner.clone();
        let request = ListHostsRequest {
            filter: Some(format!("tag:{tag}")),
            limit: None,
            offset: None,
        };

        let mut stream = client.list_hosts(request).await?.into_inner();
        let mut entries = Vec::new();

        while let Some(response) = stream.message().await? {
            if let Some(entry) = response.entry {
                if entry.tags.contains(&tag.to_string()) {
                    entries.push(HostEntry {
                        id: entry.id,
                        hostname: entry.hostname,
                        ip_address: entry.ip_address,
                        aliases: entry.aliases,
                        tags: entry.tags,
                        version: entry.version,
                    });
                }
            }
        }

        Ok(entries)
    }

    /// Add a new host entry
    #[instrument(skip(self))]
    pub async fn add_host(
        &self,
        hostname: &str,
        ip_address: &str,
        aliases: Vec<String>,
        tags: Vec<String>,
    ) -> Result<HostEntry, ClientError> {
        let mut client = self.inner.clone();
        let request = AddHostRequest {
            hostname: hostname.to_string(),
            ip_address: ip_address.to_string(),
            aliases,
            tags,
            comment: Some(format!("Managed by router-hosts-operator")),
        };

        let response = client.add_host(request).await?.into_inner();
        let entry = response.entry.expect("AddHost returns entry");

        debug!(id = %entry.id, hostname = %entry.hostname, "Added host entry");

        Ok(HostEntry {
            id: entry.id,
            hostname: entry.hostname,
            ip_address: entry.ip_address,
            aliases: entry.aliases,
            tags: entry.tags,
            version: entry.version,
        })
    }

    /// Update an existing host entry
    #[instrument(skip(self))]
    pub async fn update_host(
        &self,
        id: &str,
        ip_address: Option<&str>,
        aliases: Option<Vec<String>>,
        tags: Option<Vec<String>>,
        expected_version: Option<&str>,
    ) -> Result<HostEntry, ClientError> {
        let mut client = self.inner.clone();
        let request = UpdateHostRequest {
            id: id.to_string(),
            ip_address: ip_address.map(String::from),
            hostname: None,
            comment: None,
            expected_version: expected_version.map(String::from),
            aliases: aliases.map(|v| router_hosts_common::proto::router_hosts::v1::AliasesUpdate { values: v }),
            tags: tags.map(|v| TagsUpdate { values: v }),
        };

        let response = client.update_host(request).await?.into_inner();
        let entry = response.entry.expect("UpdateHost returns entry");

        debug!(id = %entry.id, "Updated host entry");

        Ok(HostEntry {
            id: entry.id,
            hostname: entry.hostname,
            ip_address: entry.ip_address,
            aliases: entry.aliases,
            tags: entry.tags,
            version: entry.version,
        })
    }

    /// Delete a host entry
    #[instrument(skip(self))]
    pub async fn delete_host(&self, id: &str) -> Result<bool, ClientError> {
        let mut client = self.inner.clone();
        let request = DeleteHostRequest {
            id: id.to_string(),
        };

        let response = client.delete_host(request).await?.into_inner();
        debug!(id = %id, success = %response.success, "Deleted host entry");

        Ok(response.success)
    }
}
```

**Step 2: Verify build**

Run: `cargo build -p router-hosts-operator`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(operator): add router-hosts gRPC client wrapper

High-level client interface with:
- mTLS connection setup
- find_by_hostname and find_by_tag queries
- add_host, update_host, delete_host operations
- Proper error handling and tracing instrumentation"
```

---

## Phase 6: Deletion Scheduler

### Task 6.1: TTL-Based Deletion

**Files:**
- Modify: `crates/router-hosts-operator/src/deletion.rs`

**Step 1: Implement deletion scheduler**

Replace `crates/router-hosts-operator/src/deletion.rs`:

```rust
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
            for (id, deletion) in pending.iter() {
                if now.duration_since(deletion.scheduled_at) >= deletion.grace_period {
                    expired.push((id.clone(), deletion.clone()));
                }
            }
        }

        let mut result = ProcessResult::default();

        // Process each expired entry
        for (id, deletion) in expired {
            if deletion.pre_existing {
                // Just remove operator tags, don't delete
                match self.remove_operator_tags(client, &id).await {
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
                match client.delete_host(&id).await {
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
            self.pending.write().await.remove(&id);
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

        if let Some(entry) = entry {
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
        }

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
```

**Step 2: Run tests**

Run: `cargo test -p router-hosts-operator deletion`
Expected: 2 tests pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(operator): add TTL-based deletion scheduler

Graceful deletion with configurable grace periods:
- Schedule entries for deletion after grace period
- Cancel deletion if resource reappears
- Pre-existing entries only have operator tags removed
- Background processing of expired deletions
- Clear separation of operator-owned vs adopted entries"
```

---

## Phase 7: Ingress Controller

### Task 7.1: Ingress Reconciler

**Files:**
- Modify: `crates/router-hosts-operator/src/controllers/ingress.rs`
- Modify: `crates/router-hosts-operator/src/controllers/mod.rs`

**Step 1: Implement shared reconciler types**

Update `crates/router-hosts-operator/src/controllers/mod.rs`:

```rust
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
```

**Step 2: Implement Ingress reconciler**

Replace `crates/router-hosts-operator/src/controllers/ingress.rs`:

```rust
//! Ingress controller
//!
//! Watches networking.k8s.io/v1 Ingress resources and syncs hostnames to router-hosts.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config;
use kube::runtime::Controller;
use kube::{Api, Client, ResourceExt};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use super::ControllerContext;
use crate::config::{annotations, tags};

#[derive(Debug, Error)]
pub enum IngressError {
    #[error("Failed to resolve IP: {0}")]
    IpResolution(#[from] crate::resolver::ResolverError),
    #[error("router-hosts client error: {0}")]
    Client(#[from] crate::client::ClientError),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Check if an Ingress has the opt-in annotation
pub fn is_enabled(ingress: &Ingress) -> bool {
    ingress
        .annotations()
        .get(annotations::ENABLED)
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Extract hostnames from an Ingress
pub fn extract_hosts(ingress: &Ingress) -> Vec<String> {
    let mut hosts = Vec::new();

    if let Some(spec) = &ingress.spec {
        if let Some(rules) = &spec.rules {
            for rule in rules {
                if let Some(host) = &rule.host {
                    hosts.push(host.clone());
                }
            }
        }
    }

    hosts
}

/// Build ownership tags for an entry
pub fn build_tags(
    ingress: &Ingress,
    default_tags: &[String],
    pre_existing: bool,
) -> Vec<String> {
    let mut result: Vec<String> = default_tags.to_vec();

    // Always add operator marker
    if !result.contains(&tags::OPERATOR.to_string()) {
        result.push(tags::OPERATOR.to_string());
    }

    // Add source tracking
    if let Some(uid) = ingress.uid() {
        result.push(format!("{}{}", tags::SOURCE_PREFIX, uid));
    }

    // Add namespace
    if let Some(ns) = ingress.namespace() {
        result.push(format!("{}{}", tags::NAMESPACE_PREFIX, ns));
    }

    // Add kind
    result.push(format!("{}Ingress", tags::KIND_PREFIX));

    // Add pre-existing marker if applicable
    if pre_existing {
        result.push(tags::PRE_EXISTING.to_string());
    }

    // Add custom tags from annotation
    if let Some(custom) = ingress.annotations().get(annotations::TAGS) {
        for tag in custom.split(',') {
            let tag = tag.trim();
            if !tag.is_empty() && !result.contains(&tag.to_string()) {
                result.push(tag.to_string());
            }
        }
    }

    result
}

/// Parse aliases from annotation
pub fn parse_aliases(ingress: &Ingress) -> Vec<String> {
    ingress
        .annotations()
        .get(annotations::ALIASES)
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

/// Reconcile an Ingress resource
#[instrument(skip(ctx, ingress), fields(name = %ingress.name_any(), namespace = ingress.namespace()))]
pub async fn reconcile(
    ingress: Arc<Ingress>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, IngressError> {
    let name = ingress.name_any();
    let namespace = ingress.namespace().unwrap_or_default();

    // Check opt-in annotation
    if !is_enabled(&ingress) {
        debug!(name = %name, "Ingress not enabled, skipping");
        return Ok(Action::await_change());
    }

    // Extract hostnames
    let hosts = extract_hosts(&ingress);
    if hosts.is_empty() {
        debug!(name = %name, "No hosts in Ingress, skipping");
        return Ok(Action::await_change());
    }

    info!(name = %name, hosts = ?hosts, "Reconciling Ingress");

    // Resolve IP
    let ip = ctx.resolver.resolve(ingress.annotations()).await?;
    let aliases = parse_aliases(&ingress);

    // Process each hostname
    for hostname in &hosts {
        // Check if entry already exists
        let existing = ctx.client.find_by_hostname(hostname).await?;

        match existing {
            Some(entry) => {
                // Check if we own it
                let is_ours = entry.tags.contains(&tags::OPERATOR.to_string());

                if is_ours {
                    // Update if needed
                    if entry.ip_address != ip || entry.aliases != aliases {
                        let new_tags = build_tags(&ingress, &ctx.config.default_tags, false);
                        ctx.client
                            .update_host(
                                &entry.id,
                                Some(&ip),
                                Some(aliases.clone()),
                                Some(new_tags),
                                Some(&entry.version),
                            )
                            .await?;
                        info!(hostname = %hostname, "Updated host entry");
                    }

                    // Cancel any pending deletion
                    ctx.deletion.cancel(&entry.id).await;
                } else {
                    // Adopt existing entry
                    let new_tags = build_tags(&ingress, &ctx.config.default_tags, true);
                    ctx.client
                        .update_host(
                            &entry.id,
                            Some(&ip),
                            Some(aliases.clone()),
                            Some(new_tags),
                            Some(&entry.version),
                        )
                        .await?;
                    info!(hostname = %hostname, "Adopted pre-existing entry");
                }
            }
            None => {
                // Create new entry
                let new_tags = build_tags(&ingress, &ctx.config.default_tags, false);
                ctx.client
                    .add_host(hostname, &ip, aliases.clone(), new_tags)
                    .await?;
                info!(hostname = %hostname, ip = %ip, "Created host entry");
            }
        }
    }

    // Requeue after 5 minutes for periodic sync
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Handle reconciliation errors
pub fn error_policy(
    ingress: Arc<Ingress>,
    error: &IngressError,
    _ctx: Arc<ControllerContext>,
) -> Action {
    error!(
        name = %ingress.name_any(),
        error = %error,
        "Reconciliation failed"
    );
    // Exponential backoff on errors
    Action::requeue(Duration::from_secs(30))
}

/// Start the Ingress controller
pub async fn run(client: Client, ctx: Arc<ControllerContext>) {
    let ingresses: Api<Ingress> = Api::all(client);

    Controller::new(ingresses, Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    debug!(name = %obj.name, "Reconciled successfully");
                }
                Err(e) => {
                    warn!(error = %e, "Controller error");
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::{IngressRule, IngressSpec};

    fn make_ingress(name: &str, hosts: Vec<&str>, enabled: bool) -> Ingress {
        let mut ingress = Ingress::default();
        ingress.metadata.name = Some(name.to_string());
        ingress.metadata.namespace = Some("default".to_string());

        if enabled {
            ingress
                .metadata
                .annotations
                .get_or_insert_with(BTreeMap::new)
                .insert(annotations::ENABLED.to_string(), "true".to_string());
        }

        ingress.spec = Some(IngressSpec {
            rules: Some(
                hosts
                    .into_iter()
                    .map(|h| IngressRule {
                        host: Some(h.to_string()),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        });

        ingress
    }

    #[test]
    fn test_is_enabled() {
        let enabled = make_ingress("test", vec!["app.example.com"], true);
        assert!(is_enabled(&enabled));

        let disabled = make_ingress("test", vec!["app.example.com"], false);
        assert!(!is_enabled(&disabled));
    }

    #[test]
    fn test_extract_hosts() {
        let ingress = make_ingress("test", vec!["a.com", "b.com"], true);
        let hosts = extract_hosts(&ingress);
        assert_eq!(hosts, vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_build_tags() {
        let ingress = make_ingress("test", vec!["app.com"], true);
        let tags = build_tags(&ingress, &["cluster:test".to_string()], false);

        assert!(tags.contains(&"k8s-operator".to_string()));
        assert!(tags.contains(&"cluster:test".to_string()));
        assert!(tags.contains(&"kind:Ingress".to_string()));
        assert!(tags.iter().any(|t| t.starts_with("namespace:")));
    }

    #[test]
    fn test_build_tags_pre_existing() {
        let ingress = make_ingress("test", vec!["app.com"], true);
        let tags = build_tags(&ingress, &[], true);

        assert!(tags.contains(&"pre-existing:true".to_string()));
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p router-hosts-operator ingress`
Expected: 4 tests pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(operator): add Ingress controller

Watches networking.k8s.io/v1 Ingress resources:
- Opt-in via router-hosts.fzymgc.house/enabled annotation
- Extracts hosts from spec.rules[].host
- Resolves IP, creates/updates/adopts entries
- Builds ownership tags with source tracking
- Supports custom tags and aliases via annotations
- Periodic resync every 5 minutes"
```

---

## Phase 8: Continue with remaining controllers

The remaining tasks follow the same pattern:

### Task 8.1: IngressRoute Controller
Similar to Ingress but uses `matcher::extract_hosts()` on `spec.routes[].match`

### Task 8.2: IngressRouteTCP Controller
Similar but watches IngressRouteTCP and extracts HostSNI() patterns

### Task 8.3: HostMapping Controller
Simplest controller - reads hostname directly from spec, manages status

### Task 8.4: Main Entry Point
Wire up all controllers with:
- Config loading from CRD
- mTLS setup from Secret
- Leader election
- Metrics server
- Graceful shutdown

### Task 8.5: Helm Chart
Create chart with:
- CRD manifests
- RBAC resources
- Deployment with leader election
- ServiceMonitor (optional)

---

## Summary

| Phase | Tasks | Focus |
|-------|-------|-------|
| 1 | 1.1 | Crate scaffolding |
| 2 | 2.1 | Traefik match parser |
| 3 | 3.1-3.2 | CRD definitions |
| 4 | 4.1 | IP resolution |
| 5 | 5.1 | gRPC client |
| 6 | 6.1 | Deletion scheduler |
| 7 | 7.1 | Ingress controller |
| 8 | 8.1-8.5 | Remaining controllers, main, Helm |

Each phase builds on the previous. Run `cargo test -p router-hosts-operator` after each task to verify.
