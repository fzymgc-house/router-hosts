//! IP resolution strategies
//!
//! Resolves target IP addresses for host entries using a fallback chain:
//! 1. Annotation override on the resource
//! 2. Ingress controller Service IP
//! 3. Static configured IP

use std::collections::BTreeMap;

use async_trait::async_trait;
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

/// Trait for IP resolution (enables mocking in tests)
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait IpResolverTrait: Send + Sync {
    /// Resolve IP for a resource, checking annotation override first
    async fn resolve(
        &self,
        annotations: &BTreeMap<String, String>,
    ) -> Result<String, ResolverError>;
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

    async fn resolve_internal(
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

    async fn try_strategy(&self, strategy: &IpResolutionStrategy) -> Result<String, ResolverError> {
        match strategy {
            IpResolutionStrategy::IngressController {
                service_name,
                service_namespace,
            } => {
                self.resolve_from_service(service_namespace, service_name)
                    .await
            }
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

#[async_trait]
impl IpResolverTrait for IpResolver {
    async fn resolve(
        &self,
        annotations: &BTreeMap<String, String>,
    ) -> Result<String, ResolverError> {
        self.resolve_internal(annotations).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4() {
        assert!(IpResolver::is_valid_ip("192.168.1.1"));
        assert!(IpResolver::is_valid_ip("10.0.0.1"));
        assert!(IpResolver::is_valid_ip("0.0.0.0"));
        assert!(IpResolver::is_valid_ip("255.255.255.255"));
        assert!(IpResolver::is_valid_ip("172.16.0.1"));
    }

    #[test]
    fn test_valid_ipv6() {
        assert!(IpResolver::is_valid_ip("::1"));
        assert!(IpResolver::is_valid_ip("2001:db8::1"));
        assert!(IpResolver::is_valid_ip("fe80::1"));
        assert!(IpResolver::is_valid_ip("::"));
        assert!(IpResolver::is_valid_ip("::ffff:192.168.1.1"));
    }

    #[test]
    fn test_invalid_ip() {
        assert!(!IpResolver::is_valid_ip("not-an-ip"));
        assert!(!IpResolver::is_valid_ip("192.168.1.999"));
        assert!(!IpResolver::is_valid_ip(""));
        assert!(!IpResolver::is_valid_ip("example.com"));
        assert!(!IpResolver::is_valid_ip("192.168.1"));
        assert!(!IpResolver::is_valid_ip("192.168.1.1.1"));
        assert!(!IpResolver::is_valid_ip("::gggg"));
    }

    #[test]
    fn test_resolver_error_display_no_ip() {
        let err = ResolverError::NoIpResolved;
        assert_eq!(err.to_string(), "No IP resolution strategy succeeded");
    }

    #[test]
    fn test_resolver_error_display_service_not_found() {
        let err = ResolverError::ServiceNotFound {
            namespace: "kube-system".to_string(),
            name: "traefik".to_string(),
        };
        assert_eq!(err.to_string(), "Service kube-system/traefik not found");
    }

    #[test]
    fn test_resolver_error_display_no_external_ip() {
        let err = ResolverError::NoExternalIp {
            namespace: "default".to_string(),
            name: "my-service".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Service default/my-service has no external IP"
        );
    }

    #[test]
    fn test_resolver_error_display_invalid_annotation() {
        let err = ResolverError::InvalidAnnotationIp("not-valid".to_string());
        assert_eq!(
            err.to_string(),
            "Invalid IP address in annotation: not-valid"
        );
    }

    #[test]
    fn test_resolver_error_debug() {
        // Ensure Debug is implemented
        let err = ResolverError::NoIpResolved;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("NoIpResolved"));
    }

    #[test]
    fn test_ip_resolution_strategy_static() {
        // Static strategy should work without k8s client
        let strategy = IpResolutionStrategy::Static {
            address: "192.168.1.100".to_string(),
        };
        match &strategy {
            IpResolutionStrategy::Static { address } => {
                assert_eq!(address, "192.168.1.100");
            }
            _ => panic!("Expected Static strategy"),
        }
    }

    #[test]
    fn test_ip_resolution_strategy_ingress_controller() {
        let strategy = IpResolutionStrategy::IngressController {
            service_name: "traefik".to_string(),
            service_namespace: "kube-system".to_string(),
        };
        match &strategy {
            IpResolutionStrategy::IngressController {
                service_name,
                service_namespace,
            } => {
                assert_eq!(service_name, "traefik");
                assert_eq!(service_namespace, "kube-system");
            }
            _ => panic!("Expected IngressController strategy"),
        }
    }
}
