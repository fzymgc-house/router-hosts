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
}
