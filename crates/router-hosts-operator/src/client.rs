//! router-hosts gRPC client wrapper
//!
//! Provides a high-level interface for interacting with the router-hosts server.

use std::sync::Arc;

use async_trait::async_trait;
use router_hosts_common::proto::router_hosts::v1::{
    hosts_service_client::HostsServiceClient, AddHostRequest, DeleteHostRequest, ListHostsRequest,
    ReadinessRequest, SearchHostsRequest, TagsUpdate, UpdateHostRequest,
};
use thiserror::Error;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, instrument};

/// Trait for router-hosts client operations
///
/// This trait allows for mocking in tests while keeping the concrete
/// implementation for production use.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait RouterHostsClientTrait: Send + Sync {
    /// Search for entries by hostname
    async fn find_by_hostname(&self, hostname: &str) -> Result<Option<HostEntry>, ClientError>;

    /// Search for entries by tag
    async fn find_by_tag(&self, tag: &str) -> Result<Vec<HostEntry>, ClientError>;

    /// Add a new host entry
    async fn add_host(
        &self,
        hostname: &str,
        ip_address: &str,
        aliases: Vec<String>,
        tags: Vec<String>,
    ) -> Result<HostEntry, ClientError>;

    /// Update an existing host entry
    async fn update_host(
        &self,
        id: &str,
        ip_address: Option<String>,
        aliases: Option<Vec<String>>,
        tags: Option<Vec<String>>,
        expected_version: Option<String>,
    ) -> Result<HostEntry, ClientError>;

    /// Delete a host entry
    async fn delete_host(&self, id: &str) -> Result<bool, ClientError>;

    /// Check server readiness (database connectivity)
    ///
    /// Returns `Ok(true)` if ready, `Ok(false)` if not ready (with reason logged).
    /// Returns `Err` on connection/transport failures.
    async fn check_readiness(&self) -> Result<bool, ClientError>;
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Failed to connect to router-hosts: {0}")]
    ConnectionFailed(#[from] tonic::transport::Error),
    #[error("gRPC error: {0}")]
    GrpcError(#[from] tonic::Status),
    #[error("TLS configuration error: {0}")]
    TlsError(String),
    #[error("Server response missing required field: {0}")]
    MissingResponseField(String),
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

        let tls = ClientTlsConfig::new().ca_certificate(ca).identity(identity);

        let channel = Channel::from_shared(format!("https://{endpoint}"))
            .map_err(|e| ClientError::TlsError(e.to_string()))?
            .tls_config(tls)?
            .connect()
            .await?;

        Ok(Self {
            inner: HostsServiceClient::new(channel),
        })
    }
}

#[async_trait]
impl RouterHostsClientTrait for RouterHostsClient {
    #[instrument(skip(self))]
    async fn find_by_hostname(&self, hostname: &str) -> Result<Option<HostEntry>, ClientError> {
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

    #[instrument(skip(self))]
    async fn find_by_tag(&self, tag: &str) -> Result<Vec<HostEntry>, ClientError> {
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

    #[instrument(skip(self))]
    async fn add_host(
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
            comment: Some("Managed by router-hosts-operator".to_string()),
        };

        let response = client.add_host(request).await?.into_inner();
        let entry = response
            .entry
            .ok_or(ClientError::MissingResponseField("entry".to_string()))?;

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

    #[instrument(skip(self))]
    async fn update_host(
        &self,
        id: &str,
        ip_address: Option<String>,
        aliases: Option<Vec<String>>,
        tags: Option<Vec<String>>,
        expected_version: Option<String>,
    ) -> Result<HostEntry, ClientError> {
        let mut client = self.inner.clone();
        let request = UpdateHostRequest {
            id: id.to_string(),
            ip_address,
            hostname: None,
            comment: None,
            expected_version,
            aliases: aliases
                .map(|v| router_hosts_common::proto::router_hosts::v1::AliasesUpdate { values: v }),
            tags: tags.map(|v| TagsUpdate { values: v }),
        };

        let response = client.update_host(request).await?.into_inner();
        let entry = response
            .entry
            .ok_or(ClientError::MissingResponseField("entry".to_string()))?;

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

    #[instrument(skip(self))]
    async fn delete_host(&self, id: &str) -> Result<bool, ClientError> {
        let mut client = self.inner.clone();
        let request = DeleteHostRequest { id: id.to_string() };

        let response = client.delete_host(request).await?.into_inner();
        debug!(id = %id, success = %response.success, "Deleted host entry");

        Ok(response.success)
    }

    #[instrument(skip(self))]
    async fn check_readiness(&self) -> Result<bool, ClientError> {
        let mut client = self.inner.clone();
        let response = client.readiness(ReadinessRequest {}).await?.into_inner();

        if response.ready {
            debug!("Server readiness check: OK");
        } else {
            debug!(reason = %response.reason, "Server readiness check: NOT READY");
        }

        Ok(response.ready)
    }
}

/// Implement trait for Arc-wrapped clients to support shared ownership
#[async_trait]
impl<T: RouterHostsClientTrait + ?Sized> RouterHostsClientTrait for Arc<T> {
    async fn find_by_hostname(&self, hostname: &str) -> Result<Option<HostEntry>, ClientError> {
        (**self).find_by_hostname(hostname).await
    }

    async fn find_by_tag(&self, tag: &str) -> Result<Vec<HostEntry>, ClientError> {
        (**self).find_by_tag(tag).await
    }

    async fn add_host(
        &self,
        hostname: &str,
        ip_address: &str,
        aliases: Vec<String>,
        tags: Vec<String>,
    ) -> Result<HostEntry, ClientError> {
        (**self).add_host(hostname, ip_address, aliases, tags).await
    }

    async fn update_host(
        &self,
        id: &str,
        ip_address: Option<String>,
        aliases: Option<Vec<String>>,
        tags: Option<Vec<String>>,
        expected_version: Option<String>,
    ) -> Result<HostEntry, ClientError> {
        (**self)
            .update_host(id, ip_address, aliases, tags, expected_version)
            .await
    }

    async fn delete_host(&self, id: &str) -> Result<bool, ClientError> {
        (**self).delete_host(id).await
    }

    async fn check_readiness(&self) -> Result<bool, ClientError> {
        (**self).check_readiness().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_error_display_connection() {
        // Test TlsError display
        let err = ClientError::TlsError("invalid certificate".to_string());
        assert_eq!(
            err.to_string(),
            "TLS configuration error: invalid certificate"
        );
    }

    #[test]
    fn test_client_error_display_missing_field() {
        let err = ClientError::MissingResponseField("entry".to_string());
        assert_eq!(
            err.to_string(),
            "Server response missing required field: entry"
        );
    }

    #[test]
    fn test_client_error_debug() {
        let err = ClientError::TlsError("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("TlsError"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_host_entry_clone() {
        let entry = HostEntry {
            id: "test-id".to_string(),
            hostname: "example.com".to_string(),
            ip_address: "192.168.1.1".to_string(),
            aliases: vec!["alias1.com".to_string()],
            tags: vec!["tag1".to_string()],
            version: "v1".to_string(),
        };

        let cloned = entry.clone();
        assert_eq!(entry.id, cloned.id);
        assert_eq!(entry.hostname, cloned.hostname);
        assert_eq!(entry.ip_address, cloned.ip_address);
        assert_eq!(entry.aliases, cloned.aliases);
        assert_eq!(entry.tags, cloned.tags);
        assert_eq!(entry.version, cloned.version);
    }

    #[test]
    fn test_host_entry_debug() {
        let entry = HostEntry {
            id: "test-id".to_string(),
            hostname: "example.com".to_string(),
            ip_address: "192.168.1.1".to_string(),
            aliases: vec![],
            tags: vec![],
            version: "v1".to_string(),
        };

        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("example.com"));
        assert!(debug_str.contains("192.168.1.1"));
    }
}
