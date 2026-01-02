//! Service controller
//!
//! Watches v1/Service resources and creates/updates/deletes
//! corresponding router-hosts entries for LoadBalancer and NodePort types.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::runtime::Controller;
use kube::{Api, Client};
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

use crate::client::{ClientError, RouterHostsClientTrait};
use crate::config::{annotations, tags};

use super::retry::{compute_backoff, ErrorKind};
use super::ControllerContext;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("router-hosts client error: {0}")]
    Client(#[from] ClientError),
    #[error("Missing required annotation: {0}")]
    MissingAnnotation(String),
    #[error("Invalid service type: {0}")]
    InvalidServiceType(String),
    #[error("Pending LoadBalancer IP")]
    PendingLoadBalancerIp,
}

/// Check if Service has opt-in annotation
fn is_enabled(annotations: &BTreeMap<String, String>) -> bool {
    annotations
        .get(annotations::ENABLED)
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Validate Service type is LoadBalancer or NodePort
fn validate_service_type(service: &Service) -> Result<&str, ServiceError> {
    let service_type = service
        .spec
        .as_ref()
        .and_then(|s| s.type_.as_deref())
        .unwrap_or("ClusterIP");

    match service_type {
        "LoadBalancer" | "NodePort" => Ok(service_type),
        other => Err(ServiceError::InvalidServiceType(other.to_string())),
    }
}

/// Extract hostname from annotation (required for Services)
fn extract_hostname(annotations: &BTreeMap<String, String>) -> Result<String, ServiceError> {
    annotations
        .get(annotations::HOSTNAME)
        .filter(|h| !h.is_empty())
        .cloned()
        .ok_or_else(|| ServiceError::MissingAnnotation(annotations::HOSTNAME.to_string()))
}

/// Resolve IP address based on Service type
fn resolve_ip(
    service: &Service,
    service_type: &str,
    annotations: &BTreeMap<String, String>,
) -> Result<String, ServiceError> {
    // Check for explicit IP override first
    if let Some(ip) = annotations.get(annotations::IP_ADDRESS) {
        if !ip.is_empty() {
            return Ok(ip.clone());
        }
    }

    match service_type {
        "LoadBalancer" => {
            // Get IP from status
            service
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_ref())
                .and_then(|ingress| ingress.first())
                .and_then(|ing| ing.ip.clone().or_else(|| ing.hostname.clone()))
                .ok_or(ServiceError::PendingLoadBalancerIp)
        }
        "NodePort" => {
            // NodePort requires explicit IP annotation
            Err(ServiceError::MissingAnnotation(
                annotations::IP_ADDRESS.to_string(),
            ))
        }
        _ => Err(ServiceError::InvalidServiceType(service_type.to_string())),
    }
}

/// Compare two tag lists regardless of order
fn tags_equal(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a_sorted: Vec<_> = a.iter().collect();
    let mut b_sorted: Vec<_> = b.iter().collect();
    a_sorted.sort();
    b_sorted.sort();
    a_sorted == b_sorted
}

/// Build ownership tags for the Service
fn build_tags(
    service: &Service,
    custom_tags: &[String],
    default_tags: &[String],
    pre_existing: bool,
) -> Vec<String> {
    let mut result = vec![tags::OPERATOR.to_string()];

    if pre_existing {
        result.push(tags::PRE_EXISTING.to_string());
    }

    if let Some(uid) = service.metadata.uid.as_ref() {
        result.push(format!("{}{}", tags::SOURCE_PREFIX, uid));
    }
    if let Some(namespace) = service.metadata.namespace.as_ref() {
        result.push(format!("{}{}", tags::NAMESPACE_PREFIX, namespace));
    }
    result.push(format!("{}Service", tags::KIND_PREFIX));

    result.extend_from_slice(custom_tags);
    result.extend_from_slice(default_tags);

    result
}

/// Parse aliases from annotation
fn parse_aliases(annotations: &BTreeMap<String, String>) -> Vec<String> {
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

/// Parse custom tags from annotation
fn parse_custom_tags(annotations: &BTreeMap<String, String>) -> Vec<String> {
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

/// Reconcile a single Service resource
#[instrument(skip(ctx, service), fields(
    namespace = %service.metadata.namespace.as_deref().unwrap_or("default"),
    name = %service.metadata.name.as_deref().unwrap_or("unknown"),
))]
pub(crate) async fn reconcile(
    service: Arc<Service>,
    ctx: Arc<ControllerContext>,
) -> Result<Action, ServiceError> {
    let annotations = service.metadata.annotations.as_ref();

    // Skip if not enabled
    if let Some(annots) = annotations {
        if !is_enabled(annots) {
            debug!("Service not enabled, skipping");
            return Ok(Action::await_change());
        }
    } else {
        debug!("No annotations, skipping");
        return Ok(Action::await_change());
    }

    let annotations =
        annotations.ok_or(ServiceError::MissingAnnotation("annotations".to_string()))?;

    // Validate service type
    let service_type = validate_service_type(&service)?;
    debug!(service_type = %service_type, "Validated service type");

    // Extract hostname from annotation
    let hostname = extract_hostname(annotations)?;
    debug!(hostname = %hostname, "Extracted hostname");

    // Resolve IP address
    let ip = resolve_ip(&service, service_type, annotations)?;
    debug!(ip = %ip, "Resolved IP address");

    // Parse additional configuration
    let aliases = parse_aliases(annotations);
    let custom_tags = parse_custom_tags(annotations);

    // Check if entry already exists
    match ctx.client.find_by_hostname(&hostname).await? {
        Some(existing) => {
            // Check if this entry is owned by us
            let source_tag = format!(
                "{}{}",
                tags::SOURCE_PREFIX,
                service.metadata.uid.as_deref().unwrap_or("")
            );
            let owned_by_us = existing.tags.contains(&source_tag);
            let pre_existing = !owned_by_us && !existing.tags.contains(&tags::OPERATOR.to_string());

            // Cancel any pending deletion
            if ctx.deletion.is_pending(&existing.id).await {
                ctx.deletion.cancel(&existing.id).await;
                info!(
                    entry_id = %existing.id,
                    hostname = %hostname,
                    "Cancelled pending deletion"
                );
            }

            // Build tags
            let new_tags = build_tags(
                &service,
                &custom_tags,
                &ctx.config.default_tags,
                pre_existing,
            );

            // Update entry if needed
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
            let new_tags = build_tags(&service, &custom_tags, &ctx.config.default_tags, false);
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

    // Reset retry counter on success
    if let Some(uid) = service.metadata.uid.as_deref() {
        ctx.retry_tracker.reset(uid);
    }

    // Requeue for periodic resync
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Classify error type for retry behavior
fn classify_error(error: &ServiceError) -> ErrorKind {
    match error {
        // Network errors are transient
        ServiceError::Client(_) => ErrorKind::Transient,
        // Pending LB IP will resolve eventually
        ServiceError::PendingLoadBalancerIp => ErrorKind::Transient,
        // Missing annotations and invalid types are permanent
        ServiceError::MissingAnnotation(_) => ErrorKind::Permanent,
        ServiceError::InvalidServiceType(_) => ErrorKind::Permanent,
    }
}

/// Error policy for the controller with exponential backoff
fn error_policy(
    service: Arc<Service>,
    error: &ServiceError,
    ctx: Arc<ControllerContext>,
) -> Action {
    let uid = service.metadata.uid.as_deref().unwrap_or("unknown");
    let kind = classify_error(error);

    let attempt = ctx.retry_tracker.increment(uid);

    warn!(
        error = %error,
        attempt = attempt,
        error_kind = ?kind,
        "Reconciliation error"
    );

    compute_backoff(attempt, kind)
}

/// Run the Service controller
pub async fn run(client: Client, ctx: Arc<ControllerContext>) {
    let services: Api<Service> = Api::all(client.clone());

    info!("Starting Service controller");

    Controller::new(services, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            if let Err(e) = result {
                error!(error = ?e, "Service controller stream error");
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ServiceSpec, ServiceStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn test_service(
        service_type: &str,
        annotations: BTreeMap<String, String>,
        uid: &str,
    ) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some("test-service".to_string()),
                namespace: Some("default".to_string()),
                uid: Some(uid.to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some(service_type.to_string()),
                ..Default::default()
            }),
            status: None,
        }
    }

    fn test_service_with_lb_ip(ip: &str, annotations: BTreeMap<String, String>) -> Service {
        use k8s_openapi::api::core::v1::{LoadBalancerIngress, LoadBalancerStatus};

        Service {
            metadata: ObjectMeta {
                name: Some("test-service".to_string()),
                namespace: Some("default".to_string()),
                uid: Some("test-uid".to_string()),
                annotations: Some(annotations),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("LoadBalancer".to_string()),
                ..Default::default()
            }),
            status: Some(ServiceStatus {
                load_balancer: Some(LoadBalancerStatus {
                    ingress: Some(vec![LoadBalancerIngress {
                        ip: Some(ip.to_string()),
                        hostname: None,
                        ip_mode: None,
                        ports: None,
                    }]),
                }),
                ..Default::default()
            }),
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
    fn test_validate_service_type_loadbalancer() {
        let service = test_service("LoadBalancer", BTreeMap::new(), "uid");
        assert_eq!(validate_service_type(&service).unwrap(), "LoadBalancer");
    }

    #[test]
    fn test_validate_service_type_nodeport() {
        let service = test_service("NodePort", BTreeMap::new(), "uid");
        assert_eq!(validate_service_type(&service).unwrap(), "NodePort");
    }

    #[test]
    fn test_validate_service_type_clusterip_rejected() {
        let service = test_service("ClusterIP", BTreeMap::new(), "uid");
        let result = validate_service_type(&service);
        assert!(matches!(result, Err(ServiceError::InvalidServiceType(t)) if t == "ClusterIP"));
    }

    #[test]
    fn test_validate_service_type_externalname_rejected() {
        let service = test_service("ExternalName", BTreeMap::new(), "uid");
        let result = validate_service_type(&service);
        assert!(matches!(result, Err(ServiceError::InvalidServiceType(t)) if t == "ExternalName"));
    }

    #[test]
    fn test_validate_service_type_defaults_to_clusterip() {
        // Service with no type specified defaults to ClusterIP
        let service = Service {
            metadata: ObjectMeta::default(),
            spec: Some(ServiceSpec {
                type_: None,
                ..Default::default()
            }),
            status: None,
        };
        let result = validate_service_type(&service);
        assert!(matches!(result, Err(ServiceError::InvalidServiceType(t)) if t == "ClusterIP"));
    }

    #[test]
    fn test_extract_hostname_present() {
        let mut annotations = BTreeMap::new();
        annotations.insert(annotations::HOSTNAME.to_string(), "my.host.com".to_string());
        assert_eq!(extract_hostname(&annotations).unwrap(), "my.host.com");
    }

    #[test]
    fn test_extract_hostname_missing() {
        let annotations = BTreeMap::new();
        let result = extract_hostname(&annotations);
        assert!(matches!(result, Err(ServiceError::MissingAnnotation(_))));
    }

    #[test]
    fn test_extract_hostname_empty() {
        let mut annotations = BTreeMap::new();
        annotations.insert(annotations::HOSTNAME.to_string(), "".to_string());
        let result = extract_hostname(&annotations);
        assert!(matches!(result, Err(ServiceError::MissingAnnotation(_))));
    }

    #[test]
    fn test_resolve_ip_loadbalancer_from_status() {
        let annotations = BTreeMap::new();
        let service = test_service_with_lb_ip("10.0.0.1", annotations.clone());
        let result = resolve_ip(&service, "LoadBalancer", &annotations);
        assert_eq!(result.unwrap(), "10.0.0.1");
    }

    #[test]
    fn test_resolve_ip_loadbalancer_pending() {
        let annotations = BTreeMap::new();
        let service = test_service("LoadBalancer", annotations.clone(), "uid");
        let result = resolve_ip(&service, "LoadBalancer", &annotations);
        assert!(matches!(result, Err(ServiceError::PendingLoadBalancerIp)));
    }

    #[test]
    fn test_resolve_ip_loadbalancer_with_override() {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            annotations::IP_ADDRESS.to_string(),
            "192.168.1.1".to_string(),
        );
        let service = test_service_with_lb_ip("10.0.0.1", annotations.clone());
        let result = resolve_ip(&service, "LoadBalancer", &annotations);
        // Override takes precedence
        assert_eq!(result.unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_resolve_ip_nodeport_requires_annotation() {
        let annotations = BTreeMap::new();
        let service = test_service("NodePort", annotations.clone(), "uid");
        let result = resolve_ip(&service, "NodePort", &annotations);
        assert!(matches!(result, Err(ServiceError::MissingAnnotation(_))));
    }

    #[test]
    fn test_resolve_ip_nodeport_with_annotation() {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            annotations::IP_ADDRESS.to_string(),
            "192.168.1.100".to_string(),
        );
        let service = test_service("NodePort", annotations.clone(), "uid");
        let result = resolve_ip(&service, "NodePort", &annotations);
        assert_eq!(result.unwrap(), "192.168.1.100");
    }

    #[test]
    fn test_build_tags() {
        let service = test_service("LoadBalancer", BTreeMap::new(), "abc-123");
        let custom_tags = vec!["custom".to_string()];
        let default_tags = vec!["default".to_string()];

        let tags = build_tags(&service, &custom_tags, &default_tags, false);

        assert!(tags.contains(&"k8s-operator".to_string()));
        assert!(tags.contains(&"source:abc-123".to_string()));
        assert!(tags.contains(&"namespace:default".to_string()));
        assert!(tags.contains(&"kind:Service".to_string()));
        assert!(tags.contains(&"custom".to_string()));
        assert!(tags.contains(&"default".to_string()));
        assert!(!tags.contains(&"pre-existing:true".to_string()));
    }

    #[test]
    fn test_build_tags_pre_existing() {
        let service = test_service("LoadBalancer", BTreeMap::new(), "abc-123");
        let tags = build_tags(&service, &[], &[], true);
        assert!(tags.contains(&"pre-existing:true".to_string()));
    }

    mod reconcile_tests {
        use super::*;
        use crate::client::{HostEntry, MockRouterHostsClientTrait};
        use crate::config::{DeletionConfig, RouterHostsConfigSpec, SecretReference, ServerConfig};
        use crate::controllers::retry::RetryTracker;
        use crate::deletion::DeletionScheduler;
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

        fn make_context(client: MockRouterHostsClientTrait) -> Arc<ControllerContext> {
            use crate::resolver::MockIpResolverTrait;

            Arc::new(ControllerContext {
                client: Arc::new(client),
                resolver: Arc::new(MockIpResolverTrait::new()),
                deletion: Arc::new(DeletionScheduler::new(Duration::from_secs(300))),
                config: Arc::new(test_config()),
                kube_client: mock_kube_client(),
                retry_tracker: Arc::new(RetryTracker::new()),
            })
        }

        #[tokio::test]
        async fn test_reconcile_not_enabled() {
            let service = Arc::new(test_service("LoadBalancer", BTreeMap::new(), "uid"));
            let client = MockRouterHostsClientTrait::new();
            let ctx = make_context(client);

            let result = reconcile(service, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_invalid_service_type() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let service = Arc::new(test_service("ClusterIP", annotations, "uid"));

            let client = MockRouterHostsClientTrait::new();
            let ctx = make_context(client);

            let result = reconcile(service, ctx).await;
            assert!(matches!(result, Err(ServiceError::InvalidServiceType(_))));
        }

        #[tokio::test]
        async fn test_reconcile_missing_hostname() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            let service = Arc::new(test_service("LoadBalancer", annotations, "uid"));

            let client = MockRouterHostsClientTrait::new();
            let ctx = make_context(client);

            let result = reconcile(service, ctx).await;
            assert!(matches!(result, Err(ServiceError::MissingAnnotation(_))));
        }

        #[tokio::test]
        async fn test_reconcile_loadbalancer_creates_entry() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            annotations.insert(
                annotations::HOSTNAME.to_string(),
                "lb.example.com".to_string(),
            );

            let service = Arc::new(test_service_with_lb_ip("10.0.0.1", annotations));

            let mut client = MockRouterHostsClientTrait::new();

            client
                .expect_find_by_hostname()
                .with(mockall::predicate::eq("lb.example.com"))
                .times(1)
                .returning(|_| Ok(None));

            client
                .expect_add_host()
                .withf(|hostname, ip, _aliases, tags| {
                    hostname == "lb.example.com"
                        && ip == "10.0.0.1"
                        && tags.contains(&"kind:Service".to_string())
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

            let ctx = make_context(client);
            let result = reconcile(service, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_nodeport_creates_entry() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            annotations.insert(
                annotations::HOSTNAME.to_string(),
                "np.example.com".to_string(),
            );
            annotations.insert(
                annotations::IP_ADDRESS.to_string(),
                "192.168.1.100".to_string(),
            );

            let service = Arc::new(test_service("NodePort", annotations, "uid-123"));

            let mut client = MockRouterHostsClientTrait::new();

            client
                .expect_find_by_hostname()
                .times(1)
                .returning(|_| Ok(None));

            client
                .expect_add_host()
                .withf(|hostname, ip, _aliases, _tags| {
                    hostname == "np.example.com" && ip == "192.168.1.100"
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

            let ctx = make_context(client);
            let result = reconcile(service, ctx).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_reconcile_nodeport_without_ip_fails() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            annotations.insert(
                annotations::HOSTNAME.to_string(),
                "np.example.com".to_string(),
            );
            // No IP_ADDRESS annotation

            let service = Arc::new(test_service("NodePort", annotations, "uid"));

            let client = MockRouterHostsClientTrait::new();
            let ctx = make_context(client);

            let result = reconcile(service, ctx).await;
            assert!(matches!(result, Err(ServiceError::MissingAnnotation(_))));
        }

        #[tokio::test]
        async fn test_reconcile_pending_loadbalancer_returns_error() {
            let mut annotations = BTreeMap::new();
            annotations.insert(annotations::ENABLED.to_string(), "true".to_string());
            annotations.insert(
                annotations::HOSTNAME.to_string(),
                "lb.example.com".to_string(),
            );

            // LoadBalancer without status (pending)
            let service = Arc::new(test_service("LoadBalancer", annotations, "uid"));

            let client = MockRouterHostsClientTrait::new();
            let ctx = make_context(client);

            let result = reconcile(service, ctx).await;
            assert!(matches!(result, Err(ServiceError::PendingLoadBalancerIp)));
        }
    }
}
