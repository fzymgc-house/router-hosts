//! router-hosts gRPC client wrapper
//!
//! Provides a high-level interface for interacting with the router-hosts server.

use router_hosts_common::proto::router_hosts::v1::{
    hosts_service_client::HostsServiceClient, AddHostRequest, DeleteHostRequest, ListHostsRequest,
    SearchHostsRequest, TagsUpdate, UpdateHostRequest,
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
            aliases: aliases
                .map(|v| router_hosts_common::proto::router_hosts::v1::AliasesUpdate { values: v }),
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
        let request = DeleteHostRequest { id: id.to_string() };

        let response = client.delete_host(request).await?.into_inner();
        debug!(id = %id, success = %response.success, "Deleted host entry");

        Ok(response.success)
    }
}
