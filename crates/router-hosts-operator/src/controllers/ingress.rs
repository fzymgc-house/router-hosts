//! Ingress controller
//!
//! Watches networking.k8s.io/v1 Ingress resources and creates/updates/deletes
//! corresponding router-hosts entries.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use crate::client::{ClientError, RouterHostsClientTrait};
use crate::config::{annotations, tags};
use crate::resolver::ResolverError;

use super::retry::{compute_backoff, ErrorKind};
use super::{parse_aliases, parse_custom_tags, tags_equal, ControllerContext};

#[derive(Debug, Error)]
pub enum IngressError {
    #[error("IP resolution failed: {0}")]
    IpResolution(#[from] ResolverError),
    #[error("router-hosts client error: {0}")]
    Client(#[from] ClientError),
    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Check if Ingress has opt-in annotation
fn is_enabled(annotations: &BTreeMap<String, String>) -> bool {
    annotations
        .get(annotations::ENABLED)
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Extract hosts from Ingress spec
fn extract_hosts(ingress: &Ingress) -> Vec<String> {
    let mut hosts = Vec::new();

    if let Some(spec) = &ingress.spec {
        if let Some(rules) = &spec.rules {
            for rule in rules {
                if let Some(host) = &rule.host {
                    if !host.is_empty() {
                        hosts.push(host.clone());
                    }
                }
            }
        }
    }

    hosts
}

/// Build ownership tags for the Ingress
fn build_tags(
    ingress: &Ingress,
    custom_tags: &[String],
    default_tags: &[String],
    pre_existing: bool,
) -> Vec<String> {
    let mut tags = vec![tags::OPERATOR.to_string()];

    // Add pre-existing marker if applicable
    if pre_existing {
        tags.push(tags::PRE_EXISTING.to_string());
    }

    // Add source tracking
    if let Some(uid) = ingress.metadata.uid.as_ref() {
        tags.push(format!("{}{}", tags::SOURCE_PREFIX, uid));
    }
    if let Some(namespace) = ingress.metadata.namespace.as_ref() {
        tags.push(format!("{}{}", tags::NAMESPACE_PREFIX, namespace));
    }
    tags.push(format!("{}Ingress", tags::KIND_PREFIX));

    // Add custom tags from annotation
    tags.extend_from_slice(custom_tags);

    // Add default tags from config
    tags.extend_from_slice(default_tags);

    tags
}

/// Reconcile a single Ingress resource
#[instrument(skip(ctx, ingress), fields(
    namespace = %ingress.metadata.namespace.as_deref().unwrap_or("default"),
    name = %ingress.metadata.name.as_deref().unwrap_or("unknown"),
))]
pub(crate) async fn reconcile(
    ingress: Arc<Ingress>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, IngressError> {
    let annotations = ingress.metadata.annotations.as_ref();

    // Skip if not enabled
    if let Some(annots) = annotations {
        if !is_enabled(annots) {
            debug!("Ingress not enabled, skipping");
            return Ok(Action::await_change());
        }
    } else {
        debug!("No annotations, skipping");
        return Ok(Action::await_change());
    }

    let annotations = annotations.ok_or(IngressError::MissingField("annotations".to_string()))?;

    // Extract hosts from spec
    let hosts = extract_hosts(&ingress);
    if hosts.is_empty() {
        debug!("No hosts found in Ingress spec");
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // Resolve IP address
    let ip = ctx.resolver.resolve(annotations).await?;
    debug!(ip = %ip, "Resolved IP address");

    // Parse additional configuration
    let aliases = parse_aliases(annotations);
    let custom_tags = parse_custom_tags(annotations);

    // Process each host
    for hostname in hosts {
        // Check if entry already exists
        match ctx.client.find_by_hostname(&hostname).await? {
            Some(existing) => {
                // Check if this entry is owned by us
                let source_tag = format!(
                    "{}{}",
                    tags::SOURCE_PREFIX,
                    ingress.metadata.uid.as_deref().unwrap_or("")
                );
                let owned_by_us = existing.tags.contains(&source_tag);
                let pre_existing =
                    !owned_by_us && !existing.tags.contains(&tags::OPERATOR.to_string());

                // Cancel any pending deletion
                if ctx.deletion.is_pending(&existing.id).await {
                    ctx.deletion.cancel(&existing.id).await;
                    info!(
                        entry_id = %existing.id,
                        hostname = %hostname,
                        "Cancelled pending deletion"
                    );
                }

                // Build tags, marking as pre-existing if we're adopting it
                let new_tags = build_tags(
                    &ingress,
                    &custom_tags,
                    &ctx.config.default_tags,
                    pre_existing,
                );

                // Update entry if needed (use set comparison for tags to avoid order-dependent updates)
                if existing.ip_address != ip
                    || existing.aliases != aliases
                    || !tags_equal(&existing.tags, &new_tags)
                {
                    ctx.client
                        .update_host(
                            &existing.id,
                            Some(ip.clone()),
                            Some(aliases.clone()),
                            Some(new_tags),
                            Some(existing.version.clone()),
                        )
                        .await?;

                    info!(
                        entry_id = %existing.id,
                        hostname = %hostname,
                        ip = %ip,
                        pre_existing = pre_existing,
                        "Updated host entry"
                    );
                } else {
                    debug!(hostname = %hostname, "Entry unchanged");
                }
            }
            None => {
                // Create new entry
                let new_tags = build_tags(&ingress, &custom_tags, &ctx.config.default_tags, false);
                let entry = ctx
                    .client
                    .add_host(&hostname, &ip, aliases.clone(), new_tags)
                    .await?;

                info!(
                    entry_id = %entry.id,
                    hostname = %hostname,
                    ip = %ip,
                    "Created host entry"
                );
            }
        }
    }

    // Reset retry counter on success
    if let Some(uid) = ingress.metadata.uid.as_deref() {
        ctx.retry_tracker.reset(uid);
    }

    // Requeue for periodic resync
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Classify error type for retry behavior
fn classify_error(error: &IngressError) -> ErrorKind {
    match error {
        // Network and client errors are transient
        IngressError::IpResolution(_) => ErrorKind::Transient,
        IngressError::Client(_) => ErrorKind::Transient,
        // Missing fields are permanent - won't resolve without resource change
        IngressError::MissingField(_) => ErrorKind::Permanent,
    }
}

/// Error policy for the controller with exponential backoff
fn error_policy(
    ingress: Arc<Ingress>,
    error: &IngressError,
    ctx: Arc<ControllerContext>,
) -> Action {
    let uid = ingress.metadata.uid.as_deref().unwrap_or("unknown");
    let kind = classify_error(error);

    // RetryTracker uses std::sync::Mutex so we can call this synchronously
    let attempt = ctx.retry_tracker.increment(uid);

    warn!(
        error = %error,
        attempt = attempt,
        error_kind = ?kind,
        "Reconciliation error"
    );

    compute_backoff(attempt, kind)
}

/// Run the Ingress controller
pub async fn run(client: Client, ctx: Arc<ControllerContext>) {
    let ingresses: Api<Ingress> = Api::all(client.clone());

    info!("Starting Ingress controller");

    Controller::new(ingresses, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            if let Err(e) = result {
                error!(error = ?e, "Ingress controller stream error");
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn test_ingress(annotations: BTreeMap<String, String>, uid: &str) -> Ingress {
        Ingress {
            metadata: ObjectMeta {
                name: Some("test-ingress".to_string()),
                namespace: Some("default".to_string()),
                uid: Some(uid.to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::networking::v1::IngressSpec {
                rules: Some(vec![k8s_openapi::api::networking::v1::IngressRule {
                    host: Some("test.example.com".to_string()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            status: None,
        }
    }

    #[test]
    fn test_is_enabled() {
        let mut annotations = BTreeMap::new();
        assert!(!is_enabled(&annotations));

        annotations.insert(annotations::ENABLED.to_string(), "false".to_string());
        assert!(!is_enabled(&annotations));

        annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
        assert!(is_enabled(&annotations));
    }

    #[test]
    fn test_extract_hosts() {
        let ingress = test_ingress(BTreeMap::new(), "test-uid");
        let hosts = extract_hosts(&ingress);
        assert_eq!(hosts, vec!["test.example.com"]);

        // Test with no spec
        let ingress_no_spec = Ingress {
            metadata: ObjectMeta::default(),
            spec: None,
            status: None,
        };
        let hosts = extract_hosts(&ingress_no_spec);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_build_tags() {
        let ingress = test_ingress(BTreeMap::new(), "abc-123");
        let custom_tags = vec!["custom".to_string()];
        let default_tags = vec!["default".to_string()];

        let tags = build_tags(&ingress, &custom_tags, &default_tags, false);

        assert!(tags.contains(&"k8s-operator".to_string()));
        assert!(tags.contains(&"source:abc-123".to_string()));
        assert!(tags.contains(&"namespace:default".to_string()));
        assert!(tags.contains(&"kind:Ingress".to_string()));
        assert!(tags.contains(&"custom".to_string()));
        assert!(tags.contains(&"default".to_string()));
        assert!(!tags.contains(&"pre-existing:true".to_string()));
    }

    #[test]
    fn test_build_tags_pre_existing() {
        let ingress = test_ingress(BTreeMap::new(), "abc-123");
        let tags = build_tags(&ingress, &[], &[], true);

        assert!(tags.contains(&"pre-existing:true".to_string()));
    }

    #[test]
    fn test_parse_aliases() {
        let mut annotations = BTreeMap::new();
        assert!(parse_aliases(&annotations).is_empty());

        annotations.insert(annotations::ALIASES.to_string(), "a.com, b.com".to_string());
        assert_eq!(parse_aliases(&annotations), vec!["a.com", "b.com"]);

        // Handles empty entries
        annotations.insert(
            annotations::ALIASES.to_string(),
            "a.com,,b.com,".to_string(),
        );
        assert_eq!(parse_aliases(&annotations), vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_parse_custom_tags() {
        let mut annotations = BTreeMap::new();
        assert!(parse_custom_tags(&annotations).is_empty());

        annotations.insert(annotations::TAGS.to_string(), "tag1, tag2".to_string());
        assert_eq!(parse_custom_tags(&annotations), vec!["tag1", "tag2"]);
    }

    #[test]
    fn test_extract_hosts_multiple_rules() {
        let ingress = Ingress {
            metadata: ObjectMeta::default(),
            spec: Some(k8s_openapi::api::networking::v1::IngressSpec {
                rules: Some(vec![
                    k8s_openapi::api::networking::v1::IngressRule {
                        host: Some("host1.example.com".to_string()),
                        ..Default::default()
                    },
                    k8s_openapi::api::networking::v1::IngressRule {
                        host: Some("host2.example.com".to_string()),
                        ..Default::default()
                    },
                    k8s_openapi::api::networking::v1::IngressRule {
                        host: None, // Rule without host (should be skipped)
                        ..Default::default()
                    },
                    k8s_openapi::api::networking::v1::IngressRule {
                        host: Some("".to_string()), // Empty host (should be skipped)
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            status: None,
        };

        let hosts = extract_hosts(&ingress);
        assert_eq!(hosts, vec!["host1.example.com", "host2.example.com"]);
    }

    #[test]
    fn test_extract_hosts_no_rules() {
        let ingress = Ingress {
            metadata: ObjectMeta::default(),
            spec: Some(k8s_openapi::api::networking::v1::IngressSpec {
                rules: None,
                ..Default::default()
            }),
            status: None,
        };

        let hosts = extract_hosts(&ingress);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_classify_error_transient() {
        use crate::client::ClientError;
        use crate::resolver::ResolverError;

        // IP resolution errors are transient (might succeed on retry)
        let ip_err = IngressError::IpResolution(ResolverError::NoIpResolved);
        assert!(matches!(classify_error(&ip_err), ErrorKind::Transient));

        // Client errors are transient (network issues, etc.)
        let client_err = IngressError::Client(ClientError::TlsError("test".to_string()));
        assert!(matches!(classify_error(&client_err), ErrorKind::Transient));
    }

    #[test]
    fn test_classify_error_permanent() {
        // Missing field errors are permanent (won't resolve without resource change)
        let missing_err = IngressError::MissingField("test".to_string());
        assert!(matches!(classify_error(&missing_err), ErrorKind::Permanent));
    }

    // Reconcile function tests using mocks
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
        /// This service will panic if actually called - reconcile doesn't use kube_client
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
                // This should never be called - reconcile uses mocked traits, not kube_client
                panic!("MockKubeService should not be called in reconcile tests")
            }
        }

        /// Create a mock kube Client for testing
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

        #[tokio::test]
        async fn test_reconcile_not_enabled() {
            // Ingress without enabled annotation should be skipped
            let ingress = Arc::new(test_ingress(BTreeMap::new(), "test-uid"));

            let client = MockRouterHostsClientTrait::new();
            let resolver = MockIpResolverTrait::new();
            let ctx = make_context(client, resolver);

            let result = reconcile(ingress, ctx).await;

            assert!(result.is_ok());
            // Should return await_change (wait for annotation to be added)
        }

        #[tokio::test]
        async fn test_reconcile_enabled_false() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "false".to_string());
            let ingress = Arc::new(test_ingress(annotations, "test-uid"));

            let client = MockRouterHostsClientTrait::new();
            let resolver = MockIpResolverTrait::new();
            let ctx = make_context(client, resolver);

            let result = reconcile(ingress, ctx).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_creates_new_entry() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let ingress = Arc::new(test_ingress(annotations, "test-uid-123"));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            // Resolver returns an IP
            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Ok("10.0.0.1".to_string()));

            // No existing entry found
            client
                .expect_find_by_hostname()
                .with(mockall::predicate::eq("test.example.com"))
                .times(1)
                .returning(|_| Ok(None));

            // Entry should be created
            client
                .expect_add_host()
                .withf(|hostname, ip, _aliases, tags| {
                    hostname == "test.example.com"
                        && ip == "10.0.0.1"
                        && tags.contains(&"k8s-operator".to_string())
                        && tags.contains(&"source:test-uid-123".to_string())
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

            let result = reconcile(ingress, ctx).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_updates_existing_entry() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let ingress = Arc::new(test_ingress(annotations, "test-uid-123"));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            // Resolver returns a new IP
            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Ok("10.0.0.2".to_string()));

            // Existing entry found with old IP
            client
                .expect_find_by_hostname()
                .with(mockall::predicate::eq("test.example.com"))
                .times(1)
                .returning(|_| {
                    Ok(Some(HostEntry {
                        id: "existing-id".to_string(),
                        hostname: "test.example.com".to_string(),
                        ip_address: "10.0.0.1".to_string(), // Old IP
                        aliases: vec![],
                        tags: vec![
                            "k8s-operator".to_string(),
                            "source:test-uid-123".to_string(),
                        ],
                        version: "v1".to_string(),
                    }))
                });

            // Entry should be updated with new IP
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

            let result = reconcile(ingress, ctx).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_no_update_when_unchanged() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let ingress = Arc::new(test_ingress(annotations, "test-uid-123"));

            let mut client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Ok("10.0.0.1".to_string()));

            // Existing entry with same IP and matching tags
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
                        "kind:Ingress".to_string(),
                        "env:test".to_string(),
                    ],
                    version: "v1".to_string(),
                }))
            });

            // update_host should NOT be called (entry unchanged)
            // No expectation set means it will fail if called

            let ctx = make_context(client, resolver);

            let result = reconcile(ingress, ctx).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_ip_resolution_error() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let ingress = Arc::new(test_ingress(annotations, "test-uid"));

            let client = MockRouterHostsClientTrait::new();
            let mut resolver = MockIpResolverTrait::new();

            // Resolver fails
            resolver
                .expect_resolve()
                .times(1)
                .returning(|_| Err(crate::resolver::ResolverError::NoIpResolved));

            let ctx = make_context(client, resolver);

            let result = reconcile(ingress, ctx).await;

            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), IngressError::IpResolution(_)));
        }

        #[tokio::test]
        async fn test_reconcile_no_hosts_in_spec() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());

            // Ingress with no hosts in spec
            let ingress = Arc::new(Ingress {
                metadata: ObjectMeta {
                    name: Some("test-ingress".to_string()),
                    namespace: Some("default".to_string()),
                    uid: Some("test-uid".to_string()),
                    annotations: Some(annotations),
                    ..Default::default()
                },
                spec: Some(k8s_openapi::api::networking::v1::IngressSpec {
                    rules: Some(vec![]), // Empty rules
                    ..Default::default()
                }),
                status: None,
            });

            let client = MockRouterHostsClientTrait::new();
            let resolver = MockIpResolverTrait::new();
            let ctx = make_context(client, resolver);

            let result = reconcile(ingress, ctx).await;

            // Should requeue (no hosts to process)
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
            let ingress = Arc::new(test_ingress(annotations, "test-uid"));

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

            let result = reconcile(ingress, ctx).await;

            assert!(result.is_ok());
        }
    }
}
