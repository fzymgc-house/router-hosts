use anyhow::{Context, Result};
use router_hosts_common::proto::{
    hosts_service_client::HostsServiceClient, AddHostRequest, AddHostResponse,
    CreateSnapshotRequest, CreateSnapshotResponse, DeleteHostRequest, DeleteHostResponse,
    DeleteSnapshotRequest, DeleteSnapshotResponse, ExportHostsRequest, GetHostRequest,
    GetHostResponse, ImportHostsRequest, ImportHostsResponse, ListHostsRequest, ListHostsResponse,
    ListSnapshotsRequest, ListSnapshotsResponse, RollbackToSnapshotRequest,
    RollbackToSnapshotResponse, SearchHostsRequest, SearchHostsResponse, UpdateHostRequest,
    UpdateHostResponse,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use super::config::ClientConfig;

/// Buffer size for import streaming channel
const IMPORT_CHANNEL_BUFFER_SIZE: usize = 4;

/// gRPC client wrapper with mTLS support
pub struct Client {
    inner: HostsServiceClient<Channel>,
}

impl Client {
    /// Connect to the server with mTLS
    pub async fn connect(config: &ClientConfig) -> Result<Self> {
        // Load client identity (cert + key)
        let cert_pem = tokio::fs::read(&config.cert_path).await.with_context(|| {
            format!("Failed to read client certificate: {:?}", config.cert_path)
        })?;
        let key_pem = tokio::fs::read(&config.key_path)
            .await
            .with_context(|| format!("Failed to read client key: {:?}", config.key_path))?;
        let identity = Identity::from_pem(cert_pem, key_pem);

        // Load CA certificate
        let ca_pem = tokio::fs::read(&config.ca_cert_path)
            .await
            .with_context(|| format!("Failed to read CA certificate: {:?}", config.ca_cert_path))?;
        let ca_cert = Certificate::from_pem(ca_pem);

        // Configure TLS
        let tls_config = ClientTlsConfig::new()
            .identity(identity)
            .ca_certificate(ca_cert);

        // Build channel
        let endpoint = format!("https://{}", config.server_address);
        let channel = Channel::from_shared(endpoint)?
            .tls_config(tls_config)?
            .connect()
            .await
            .context("Failed to connect to server")?;

        Ok(Self {
            inner: HostsServiceClient::new(channel),
        })
    }

    // Host operations

    /// Add a new host entry
    pub async fn add_host(&mut self, request: AddHostRequest) -> Result<AddHostResponse> {
        let hostname = request.hostname.clone();
        let response = self
            .inner
            .add_host(request)
            .await
            .with_context(|| format!("Failed to add host: {}", hostname))?;
        Ok(response.into_inner())
    }

    /// Get a host entry by ID
    pub async fn get_host(&mut self, request: GetHostRequest) -> Result<GetHostResponse> {
        let id = request.id.clone();
        let response = self
            .inner
            .get_host(request)
            .await
            .with_context(|| format!("Failed to get host: {}", id))?;
        Ok(response.into_inner())
    }

    /// Update an existing host entry
    pub async fn update_host(&mut self, request: UpdateHostRequest) -> Result<UpdateHostResponse> {
        let id = request.id.clone();
        let response = self
            .inner
            .update_host(request)
            .await
            .with_context(|| format!("Failed to update host: {}", id))?;
        Ok(response.into_inner())
    }

    /// Delete a host entry
    pub async fn delete_host(&mut self, request: DeleteHostRequest) -> Result<DeleteHostResponse> {
        let id = request.id.clone();
        let response = self
            .inner
            .delete_host(request)
            .await
            .with_context(|| format!("Failed to delete host: {}", id))?;
        Ok(response.into_inner())
    }

    /// List all host entries (collects server stream into Vec)
    pub async fn list_hosts(
        &mut self,
        request: ListHostsRequest,
    ) -> Result<Vec<ListHostsResponse>> {
        let mut stream = self
            .inner
            .list_hosts(request)
            .await
            .context("Failed to list hosts")?
            .into_inner();

        let mut results = Vec::new();
        while let Some(response) = stream
            .message()
            .await
            .context("Failed to read from list_hosts stream")?
        {
            results.push(response);
        }
        Ok(results)
    }

    /// Search host entries (collects server stream into Vec)
    pub async fn search_hosts(
        &mut self,
        request: SearchHostsRequest,
    ) -> Result<Vec<SearchHostsResponse>> {
        let mut stream = self
            .inner
            .search_hosts(request)
            .await
            .context("Failed to search hosts")?
            .into_inner();

        let mut results = Vec::new();
        while let Some(response) = stream
            .message()
            .await
            .context("Failed to read from search_hosts stream")?
        {
            results.push(response);
        }
        Ok(results)
    }

    // Snapshot operations

    /// Create a new snapshot
    pub async fn create_snapshot(
        &mut self,
        request: CreateSnapshotRequest,
    ) -> Result<CreateSnapshotResponse> {
        let response = self
            .inner
            .create_snapshot(request)
            .await
            .context("Failed to create snapshot")?;
        Ok(response.into_inner())
    }

    /// List all snapshots (collects server stream into Vec)
    pub async fn list_snapshots(
        &mut self,
        request: ListSnapshotsRequest,
    ) -> Result<Vec<ListSnapshotsResponse>> {
        let mut stream = self
            .inner
            .list_snapshots(request)
            .await
            .context("Failed to list snapshots")?
            .into_inner();

        let mut results = Vec::new();
        while let Some(response) = stream
            .message()
            .await
            .context("Failed to read from list_snapshots stream")?
        {
            results.push(response);
        }
        Ok(results)
    }

    /// Rollback to a previous snapshot
    pub async fn rollback_to_snapshot(
        &mut self,
        request: RollbackToSnapshotRequest,
    ) -> Result<RollbackToSnapshotResponse> {
        let snapshot_id = request.snapshot_id.clone();
        let response = self
            .inner
            .rollback_to_snapshot(request)
            .await
            .with_context(|| format!("Failed to rollback to snapshot: {}", snapshot_id))?;
        Ok(response.into_inner())
    }

    /// Delete a snapshot
    pub async fn delete_snapshot(
        &mut self,
        request: DeleteSnapshotRequest,
    ) -> Result<DeleteSnapshotResponse> {
        let snapshot_id = request.snapshot_id.clone();
        let response = self
            .inner
            .delete_snapshot(request)
            .await
            .with_context(|| format!("Failed to delete snapshot: {}", snapshot_id))?;
        Ok(response.into_inner())
    }

    // Export/Import operations

    /// Export hosts (collects server stream into concatenated bytes)
    pub async fn export_hosts(&mut self, request: ExportHostsRequest) -> Result<Vec<u8>> {
        let mut stream = self
            .inner
            .export_hosts(request)
            .await
            .context("Failed to export hosts")?
            .into_inner();

        let mut output = Vec::new();
        while let Some(response) = stream
            .message()
            .await
            .context("Failed to read from export_hosts stream")?
        {
            output.extend_from_slice(&response.chunk);
        }
        Ok(output)
    }

    /// Import hosts with bidirectional streaming and progress callback
    pub async fn import_hosts<F>(
        &mut self,
        chunks: Vec<ImportHostsRequest>,
        mut on_progress: F,
    ) -> Result<ImportHostsResponse>
    where
        F: FnMut(&ImportHostsResponse),
    {
        // Create channel for bidirectional streaming
        let (tx, rx) = tokio::sync::mpsc::channel(IMPORT_CHANNEL_BUFFER_SIZE);

        // Spawn task to send chunks
        tokio::spawn(async move {
            for chunk in chunks {
                if tx.send(chunk).await.is_err() {
                    // Receiver dropped, stop sending
                    break;
                }
            }
        });

        // Convert receiver to stream and send to server
        let request_stream = ReceiverStream::new(rx);
        let mut response_stream = self
            .inner
            .import_hosts(request_stream)
            .await
            .context("Failed to import hosts")?
            .into_inner();

        // Read progress updates and final result
        let mut final_response = None;
        while let Some(response) = response_stream
            .message()
            .await
            .context("Failed to read from import_hosts stream")?
        {
            on_progress(&response);
            final_response = Some(response);
        }

        final_response.ok_or_else(|| anyhow::anyhow!("No response received from import_hosts"))
    }
}
