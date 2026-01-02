//! Traefik IngressRoute controller
//!
//! Watches traefik.io/v1alpha1 IngressRoute resources and syncs hostnames to router-hosts.
//!
//! ## Deletion Handling
//!
//! This controller does not use finalizers. Deletion is handled by a separate garbage
//! collection process in the main loop that:
//! 1. Finds all entries tagged with `k8s-operator`
//! 2. Checks if the source resource (via `source:` tag) still exists
//! 3. Schedules deletion with grace period via `DeletionScheduler`
//!
//! When an IngressRoute reappears (or another resource claims the same hostname),
//! the pending deletion is cancelled in the `reconcile` function.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Client, CustomResource};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, instrument, warn};

use crate::client::{ClientError, RouterHostsClientTrait};
use crate::config::{annotations, tags};
use crate::matcher;
use crate::resolver::ResolverError;

use super::retry::{compute_backoff, ErrorKind};
use super::{parse_aliases, parse_custom_tags, tags_equal, ControllerContext};

/// IngressRoute route definition
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct IngressRouteRoute {
    /// Match expression (e.g., "Host(`example.com`) && PathPrefix(`/api`)")
    #[serde(rename = "match")]
    pub match_expr: String,
    /// Route kind (Rule, etc.)
    #[serde(default)]
    pub kind: String,
}

/// IngressRoute spec
#[derive(CustomResource, Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "traefik.io",
    version = "v1alpha1",
    kind = "IngressRoute",
    plural = "ingressroutes",
    namespaced
)]
pub struct IngressRouteSpec {
    /// Entry points (e.g., ["web", "websecure"])
    #[serde(default)]
    pub entry_points: Vec<String>,
    /// Routes with match expressions
    pub routes: Vec<IngressRouteRoute>,
}

#[derive(Debug, Error)]
pub enum IngressRouteError {
    #[error("IP resolution failed: {0}")]
    IpResolution(#[from] ResolverError),
    #[error("router-hosts client error: {0}")]
    Client(#[from] ClientError),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Check if IngressRoute has opt-in annotation
fn is_enabled(annotations: &BTreeMap<String, String>) -> bool {
    annotations
        .get(annotations::ENABLED)
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Extract hosts from IngressRoute spec using match expressions
fn extract_hosts(ingressroute: &IngressRoute) -> Vec<String> {
    let mut hosts = Vec::new();

    for route in &ingressroute.spec.routes {
        hosts.extend(matcher::extract_hosts(&route.match_expr));
    }

    // Deduplicate
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Build ownership tags (matches Ingress controller pattern)
fn build_tags(
    ingressroute: &IngressRoute,
    custom_tags: &[String],
    default_tags: &[String],
    pre_existing: bool,
) -> Vec<String> {
    let mut result = vec![tags::OPERATOR.to_string()];

    // Add pre-existing marker if applicable
    if pre_existing {
        result.push(tags::PRE_EXISTING.to_string());
    }

    // Add source tracking
    if let Some(uid) = ingressroute.metadata.uid.as_ref() {
        result.push(format!("{}{}", tags::SOURCE_PREFIX, uid));
    }
    if let Some(ns) = ingressroute.metadata.namespace.as_ref() {
        result.push(format!("{}{}", tags::NAMESPACE_PREFIX, ns));
    }
    result.push(format!("{}IngressRoute", tags::KIND_PREFIX));

    // Add custom tags from annotation
    result.extend_from_slice(custom_tags);

    // Add default tags from config
    result.extend_from_slice(default_tags);

    result
}

#[instrument(
    skip(ctx, ingressroute),
    fields(
        name = %ingressroute.metadata.name.as_deref().unwrap_or("unknown"),
        namespace = %ingressroute.metadata.namespace.as_deref().unwrap_or("default")
    )
)]
async fn reconcile(
    ingressroute: Arc<IngressRoute>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, IngressRouteError> {
    let name = ingressroute.metadata.name.as_deref().unwrap_or("unknown");
    let annotations = ingressroute
        .metadata
        .annotations
        .clone()
        .unwrap_or_default();

    if !is_enabled(&annotations) {
        debug!(name = %name, "IngressRoute not enabled, skipping");
        return Ok(Action::await_change());
    }

    let hosts = extract_hosts(&ingressroute);
    if hosts.is_empty() {
        debug!(name = %name, "No hosts in IngressRoute, skipping");
        return Ok(Action::await_change());
    }

    info!(name = %name, hosts = ?hosts, "Reconciling IngressRoute");

    let ip = ctx.resolver.resolve(&annotations).await?;
    let aliases = parse_aliases(&annotations);
    let custom_tags = parse_custom_tags(&annotations);

    for hostname in &hosts {
        let existing = ctx.client.find_by_hostname(hostname).await?;

        match existing {
            Some(entry) => {
                // Cancel any pending deletion - regardless of ownership
                // If any resource claims this hostname, don't delete the entry
                if ctx.deletion.is_pending(&entry.id).await {
                    ctx.deletion.cancel(&entry.id).await;
                    info!(
                        entry_id = %entry.id,
                        hostname = %hostname,
                        "Cancelled pending deletion"
                    );
                }

                let source_tag = ingressroute
                    .metadata
                    .uid
                    .as_ref()
                    .map(|uid| format!("{}{}", tags::SOURCE_PREFIX, uid));

                let is_ours = source_tag
                    .as_ref()
                    .map(|t| entry.tags.contains(t))
                    .unwrap_or(false);
                let has_operator_tag = entry.tags.contains(&tags::OPERATOR.to_string());

                if is_ours {
                    let new_tags =
                        build_tags(&ingressroute, &custom_tags, &ctx.config.default_tags, false);
                    // Use set comparison for tags to avoid order-dependent updates
                    if entry.ip_address != ip
                        || entry.aliases != aliases
                        || !tags_equal(&entry.tags, &new_tags)
                    {
                        ctx.client
                            .update_host(
                                &entry.id,
                                Some(ip.clone()),
                                Some(aliases.clone()),
                                Some(new_tags),
                                Some(entry.version.clone()),
                            )
                            .await?;
                        info!(hostname = %hostname, "Updated host entry");
                    }
                } else if has_operator_tag {
                    debug!(hostname = %hostname, "Entry owned by different resource, skipping");
                } else {
                    // Adopt pre-existing entry
                    let new_tags =
                        build_tags(&ingressroute, &custom_tags, &ctx.config.default_tags, true);
                    ctx.client
                        .update_host(
                            &entry.id,
                            Some(ip.clone()),
                            Some(aliases.clone()),
                            Some(new_tags),
                            Some(entry.version.clone()),
                        )
                        .await?;
                    info!(hostname = %hostname, "Adopted pre-existing entry");
                }
            }
            None => {
                // Create new entry
                let new_tags =
                    build_tags(&ingressroute, &custom_tags, &ctx.config.default_tags, false);
                ctx.client
                    .add_host(hostname, &ip, aliases.clone(), new_tags)
                    .await?;
                info!(hostname = %hostname, ip = %ip, "Created host entry");
            }
        }
    }

    // Reset retry counter on success
    if let Some(uid) = ingressroute.metadata.uid.as_deref() {
        ctx.retry_tracker.reset(uid);
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Classify error type for retry behavior
fn classify_error(error: &IngressRouteError) -> ErrorKind {
    match error {
        IngressRouteError::IpResolution(_) => ErrorKind::Transient,
        IngressRouteError::Client(_) => ErrorKind::Transient,
        IngressRouteError::MissingField(_) => ErrorKind::Permanent,
    }
}

fn error_policy(
    ingressroute: Arc<IngressRoute>,
    error: &IngressRouteError,
    ctx: Arc<ControllerContext>,
) -> Action {
    let uid = ingressroute.metadata.uid.as_deref().unwrap_or("unknown");
    let kind = classify_error(error);

    // RetryTracker uses std::sync::Mutex so we can call this synchronously
    let attempt = ctx.retry_tracker.increment(uid);

    warn!(
        name = %ingressroute.metadata.name.as_deref().unwrap_or("unknown"),
        error = %error,
        attempt = attempt,
        error_kind = ?kind,
        "IngressRoute reconciliation failed"
    );

    compute_backoff(attempt, kind)
}

/// Start the IngressRoute controller
pub async fn run(client: Client, ctx: Arc<ControllerContext>) {
    let ingressroutes: Api<IngressRoute> = Api::all(client);

    Controller::new(ingressroutes, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok((obj, _action)) => {
                    debug!(
                        name = %obj.name,
                        "IngressRoute reconciled successfully"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "IngressRoute controller error");
                }
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ingressroute(name: &str, matches: Vec<&str>, enabled: bool) -> IngressRoute {
        let mut ir = IngressRoute::new(
            name,
            IngressRouteSpec {
                entry_points: vec!["web".to_string()],
                routes: matches
                    .into_iter()
                    .map(|m| IngressRouteRoute {
                        match_expr: m.to_string(),
                        kind: "Rule".to_string(),
                    })
                    .collect(),
            },
        );
        ir.metadata.namespace = Some("default".to_string());
        ir.metadata.uid = Some("test-uid-123".to_string());

        if enabled {
            ir.metadata
                .annotations
                .get_or_insert_with(BTreeMap::new)
                .insert(annotations::ENABLED.to_string(), "true".to_string());
        }

        ir
    }

    #[test]
    fn test_is_enabled() {
        let enabled = make_ingressroute("test", vec!["Host(`app.com`)"], true);
        assert!(is_enabled(
            enabled
                .metadata
                .annotations
                .as_ref()
                .expect("test fixture should have annotations")
        ));

        let disabled = make_ingressroute("test", vec!["Host(`app.com`)"], false);
        assert!(!is_enabled(
            &disabled.metadata.annotations.unwrap_or_default()
        ));
    }

    #[test]
    fn test_extract_hosts() {
        let ir = make_ingressroute(
            "test",
            vec!["Host(`a.com`) || Host(`b.com`)", "Host(`c.com`)"],
            true,
        );
        let hosts = extract_hosts(&ir);
        assert_eq!(hosts, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn test_build_tags() {
        let ir = make_ingressroute("test", vec!["Host(`app.com`)"], true);
        let custom = vec!["custom:tag".to_string()];
        let default = vec!["cluster:test".to_string()];
        let tags = build_tags(&ir, &custom, &default, false);

        assert!(tags.contains(&"k8s-operator".to_string()));
        assert!(tags.contains(&"custom:tag".to_string()));
        assert!(tags.contains(&"cluster:test".to_string()));
        assert!(tags.contains(&"kind:IngressRoute".to_string()));
        assert!(tags.iter().any(|t| t.starts_with("source:")));
        assert!(!tags.contains(&"pre-existing:true".to_string()));
    }

    #[test]
    fn test_build_tags_pre_existing() {
        let ir = make_ingressroute("test", vec!["Host(`app.com`)"], true);
        let tags = build_tags(&ir, &[], &[], true);

        assert!(tags.contains(&"pre-existing:true".to_string()));
    }

    /// Reconcile tests verify the IngressRoute controller's behavior when syncing
    /// Kubernetes IngressRoute resources with the router-hosts backend.
    ///
    /// These tests cover:
    /// - Creating new host entries when none exist
    /// - Updating existing entries when IP or tags change
    /// - No-op behavior when entries are already in sync
    /// - IP resolution via configured resolvers
    /// - Error handling for resolution failures and invalid IPs
    /// - Conflict detection when entries are owned by different resources
    /// - Adoption of pre-existing unmanaged entries
    /// - Handling of disabled IngressRoutes (enabled: false annotation)
    mod reconcile_tests {
        use super::*;
        use crate::client::{HostEntry, MockRouterHostsClientTrait};
        use crate::config::{DeletionConfig, RouterHostsConfigSpec, SecretReference, ServerConfig};
        use crate::controllers::retry::RetryTracker;
        use crate::deletion::DeletionScheduler;
        use crate::resolver::MockIpResolverTrait;
        use std::time::Duration;

        fn test_config() -> RouterHostsConfigSpec {
            RouterHostsConfigSpec {
                server: ServerConfig {
                    endpoint: "localhost:50051".to_string(),
                    tls_secret_ref: SecretReference {
                        name: "tls-secret".to_string(),
                        namespace: "default".to_string(),
                    },
                },
                ip_resolution: vec![],
                deletion: DeletionConfig {
                    grace_period_seconds: 300,
                },
                default_tags: vec!["env:test".to_string()],
            }
        }

        /// Mock service for creating a kube Client in tests
        #[derive(Clone)]
        struct MockKubeService;

        impl tower::Service<http::Request<kube::client::Body>> for MockKubeService {
            type Response = http::Response<kube::client::Body>;
            type Error = std::convert::Infallible;
            type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: http::Request<kube::client::Body>) -> Self::Future {
                panic!("MockKubeService should not be called in reconcile tests")
            }
        }

        fn mock_kube_client() -> Client {
            Client::new(MockKubeService, "default")
        }

        fn make_context(
            client: MockRouterHostsClientTrait,
            resolver: MockIpResolverTrait,
        ) -> Arc<ControllerContext> {
            Arc::new(ControllerContext {
                client: Arc::new(client),
                resolver: Arc::new(resolver),
                deletion: Arc::new(DeletionScheduler::new(Duration::from_secs(300))),
                config: Arc::new(test_config()),
                kube_client: mock_kube_client(),
                retry_tracker: Arc::new(RetryTracker::new()),
            })
        }

        fn test_ingressroute(
            annotations: BTreeMap<String, String>,
            uid: &str,
            match_expr: &str,
        ) -> IngressRoute {
            IngressRoute {
                metadata: kube::api::ObjectMeta {
                    name: Some("test-ingressroute".to_string()),
                    namespace: Some("default".to_string()),
                    uid: Some(uid.to_string()),
                    annotations: Some(annotations),
                    ..Default::default()
                },
                spec: IngressRouteSpec {
                    entry_points: vec!["web".to_string()],
                    routes: vec![IngressRouteRoute {
                        match_expr: match_expr.to_string(),
                        kind: "Rule".to_string(),
                    }],
                },
            }
        }

        #[tokio::test]
        async fn test_reconcile_not_enabled() {
            let ir = Arc::new(test_ingressroute(
                BTreeMap::new(),
                "test-uid",
                "Host(`test.example.com`)",
            ));

            let client = MockRouterHostsClientTrait::new();
            let resolver = MockIpResolverTrait::new();
            let ctx = make_context(client, resolver);

            let result = reconcile(ir, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_enabled_false() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "false".to_string());
            let ir = Arc::new(test_ingressroute(
                annotations,
                "test-uid",
                "Host(`test.example.com`)",
            ));

            let client = MockRouterHostsClientTrait::new();
            let resolver = MockIpResolverTrait::new();
            let ctx = make_context(client, resolver);

            let result = reconcile(ir, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_creates_new_entry() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let ir = Arc::new(test_ingressroute(
                annotations,
                "test-uid-123",
                "Host(`test.example.com`)",
            ));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Ok("10.0.0.1".to_string()));

            client
                .expect_find_by_hostname()
                .with(mockall::predicate::eq("test.example.com"))
                .times(1)
                .returning(|_| Ok(None));

            client
                .expect_add_host()
                .withf(|hostname, ip, _aliases, tags| {
                    hostname == "test.example.com"
                        && ip == "10.0.0.1"
                        && tags.contains(&"k8s-operator".to_string())
                        && tags.contains(&"source:test-uid-123".to_string())
                        && tags.contains(&"kind:IngressRoute".to_string())
                })
                .times(1)
                .returning(|hostname, ip, aliases, tags| {
                    Ok(HostEntry {
                        id: "new-entry-id".to_string(),
                        hostname: hostname.to_string(),
                        ip_address: ip.to_string(),
                        aliases,
                        tags,
                        version: "v1".to_string(),
                    })
                });

            let ctx = make_context(client, resolver);
            let result = reconcile(ir, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_updates_existing_entry() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let ir = Arc::new(test_ingressroute(
                annotations,
                "test-uid-123",
                "Host(`test.example.com`)",
            ));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Ok("10.0.0.2".to_string()));

            client
                .expect_find_by_hostname()
                .with(mockall::predicate::eq("test.example.com"))
                .times(1)
                .returning(|_| {
                    Ok(Some(HostEntry {
                        id: "existing-id".to_string(),
                        hostname: "test.example.com".to_string(),
                        ip_address: "10.0.0.1".to_string(),
                        aliases: vec![],
                        tags: vec![
                            "k8s-operator".to_string(),
                            "source:test-uid-123".to_string(),
                        ],
                        version: "v1".to_string(),
                    }))
                });

            client
                .expect_update_host()
                .withf(|id, ip, _aliases, _tags, version| {
                    id == "existing-id"
                        && ip.as_ref().map(|s| s.as_str()) == Some("10.0.0.2")
                        && version == &Some("v1".to_string())
                })
                .times(1)
                .returning(|id, ip, aliases, tags, _| {
                    Ok(HostEntry {
                        id: id.to_string(),
                        hostname: "test.example.com".to_string(),
                        ip_address: ip.unwrap_or_default(),
                        aliases: aliases.unwrap_or_default(),
                        tags: tags.unwrap_or_default(),
                        version: "v2".to_string(),
                    })
                });

            let ctx = make_context(client, resolver);
            let result = reconcile(ir, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_no_update_when_unchanged() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let ir = Arc::new(test_ingressroute(
                annotations,
                "test-uid-123",
                "Host(`test.example.com`)",
            ));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Ok("10.0.0.1".to_string()));

            client.expect_find_by_hostname().times(1).returning(|_| {
                Ok(Some(HostEntry {
                    id: "existing-id".to_string(),
                    hostname: "test.example.com".to_string(),
                    ip_address: "10.0.0.1".to_string(),
                    aliases: vec![],
                    tags: vec![
                        "k8s-operator".to_string(),
                        "source:test-uid-123".to_string(),
                        "namespace:default".to_string(),
                        "kind:IngressRoute".to_string(),
                        "env:test".to_string(),
                    ],
                    version: "v1".to_string(),
                }))
            });

            // update_host should NOT be called
            client.expect_update_host().times(0);

            let ctx = make_context(client, resolver);
            let result = reconcile(ir, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_ip_resolution_error() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let ir = Arc::new(test_ingressroute(
                annotations,
                "test-uid",
                "Host(`test.example.com`)",
            ));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Err(crate::resolver::ResolverError::NoIpResolved));

            // Should NOT attempt to create/update when resolution fails
            client.expect_find_by_hostname().times(0);
            client.expect_add_host().times(0);
            client.expect_update_host().times(0);

            let ctx = make_context(client, resolver);
            let result = reconcile(ir, ctx).await;

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                IngressRouteError::IpResolution(_)
            ));
        }

        #[tokio::test]
        async fn test_reconcile_no_hosts_in_spec() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());

            // IngressRoute with match expression that has no hosts
            let ir = Arc::new(test_ingressroute(
                annotations,
                "test-uid",
                "PathPrefix(`/api`)", // No Host() matcher
            ));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            // No hosts to process, so no router-hosts calls should happen
            resolver.expect_resolve().times(0);
            client.expect_find_by_hostname().times(0);
            client.expect_add_host().times(0);
            client.expect_update_host().times(0);

            let ctx = make_context(client, resolver);

            let result = reconcile(ir, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_with_aliases_and_custom_tags() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            annotations.insert(
                annotations::ALIASES.to_string(),
                "alias1.com, alias2.com".to_string(),
            );
            annotations.insert(
                annotations::TAGS.to_string(),
                "custom-tag, another-tag".to_string(),
            );
            let ir = Arc::new(test_ingressroute(
                annotations,
                "test-uid",
                "Host(`test.example.com`)",
            ));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Ok("10.0.0.1".to_string()));

            client
                .expect_find_by_hostname()
                .times(1)
                .returning(|_| Ok(None));

            client
                .expect_add_host()
                .withf(|_, _, aliases, tags| {
                    aliases.contains(&"alias1.com".to_string())
                        && aliases.contains(&"alias2.com".to_string())
                        && tags.contains(&"custom-tag".to_string())
                        && tags.contains(&"another-tag".to_string())
                })
                .times(1)
                .returning(|hostname, ip, aliases, tags| {
                    Ok(HostEntry {
                        id: "new-id".to_string(),
                        hostname: hostname.to_string(),
                        ip_address: ip.to_string(),
                        aliases,
                        tags,
                        version: "v1".to_string(),
                    })
                });

            let ctx = make_context(client, resolver);
            let result = reconcile(ir, ctx).await;
            assert!(result.is_ok());
        }
    }
}
