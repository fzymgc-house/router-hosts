//! gRPC service layer for router-hosts server
//!
//! This module contains the HostsService implementation that handles
//! all gRPC requests and delegates to the command handler layer.

mod bulk;
mod health;
mod hosts;
mod snapshots;

use crate::server::commands::CommandHandler;
use crate::server::hooks::HookExecutor;
use crate::server::write_queue::WriteQueue;
use router_hosts_common::proto::hosts_service_server::HostsService;
use router_hosts_common::proto::{
    AddHostRequest, AddHostResponse, CreateSnapshotRequest, CreateSnapshotResponse,
    DeleteHostRequest, DeleteHostResponse, DeleteSnapshotRequest, DeleteSnapshotResponse,
    ExportHostsRequest, ExportHostsResponse, GetHostRequest, GetHostResponse, HealthRequest,
    HealthResponse, ImportHostsRequest, ImportHostsResponse, ListHostsRequest, ListHostsResponse,
    ListSnapshotsRequest, ListSnapshotsResponse, LivenessRequest, LivenessResponse,
    ReadinessRequest, ReadinessResponse, RollbackToSnapshotRequest, RollbackToSnapshotResponse,
    SearchHostsRequest, SearchHostsResponse, UpdateHostRequest, UpdateHostResponse,
};
use router_hosts_storage::Storage;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

/// Main gRPC service implementation
pub struct HostsServiceImpl {
    /// Write queue for serialized mutation operations
    pub(crate) write_queue: WriteQueue,
    /// Command handler for read operations and snapshot management
    pub(crate) commands: Arc<CommandHandler>,
    /// Storage backend (used by export and snapshot handlers)
    pub(crate) storage: Arc<dyn Storage>,
    /// Hook executor for health reporting
    pub(crate) hooks: Arc<HookExecutor>,
    /// Server start time for uptime calculation
    pub(crate) start_time: Instant,
    /// Whether ACME certificate management is enabled
    pub(crate) acme_enabled: bool,
    /// Path to TLS certificate (for reading expiry in health checks)
    pub(crate) tls_cert_path: Option<PathBuf>,
}

impl HostsServiceImpl {
    /// Create a new service instance
    pub fn new(
        write_queue: WriteQueue,
        commands: Arc<CommandHandler>,
        storage: Arc<dyn Storage>,
        hooks: Arc<HookExecutor>,
        acme_enabled: bool,
        tls_cert_path: Option<PathBuf>,
    ) -> Self {
        Self {
            write_queue,
            commands,
            storage,
            hooks,
            start_time: Instant::now(),
            acme_enabled,
            tls_cert_path,
        }
    }
}

type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl HostsService for HostsServiceImpl {
    // Host CRUD operations
    async fn add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<AddHostResponse>, Status> {
        self.handle_add_host(request).await
    }

    async fn get_host(
        &self,
        request: Request<GetHostRequest>,
    ) -> Result<Response<GetHostResponse>, Status> {
        self.handle_get_host(request).await
    }

    async fn update_host(
        &self,
        request: Request<UpdateHostRequest>,
    ) -> Result<Response<UpdateHostResponse>, Status> {
        self.handle_update_host(request).await
    }

    async fn delete_host(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        self.handle_delete_host(request).await
    }

    // Streaming list/search
    type ListHostsStream = ResponseStream<ListHostsResponse>;

    async fn list_hosts(
        &self,
        request: Request<ListHostsRequest>,
    ) -> Result<Response<Self::ListHostsStream>, Status> {
        let responses = self.handle_list_hosts(request).await?;
        let stream = futures::stream::iter(responses.into_inner().into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }

    type SearchHostsStream = ResponseStream<SearchHostsResponse>;

    async fn search_hosts(
        &self,
        request: Request<SearchHostsRequest>,
    ) -> Result<Response<Self::SearchHostsStream>, Status> {
        let responses = self.handle_search_hosts(request).await?;
        let stream = futures::stream::iter(responses.into_inner().into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }

    // Import/Export operations
    type ImportHostsStream = ResponseStream<ImportHostsResponse>;

    async fn import_hosts(
        &self,
        request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Self::ImportHostsStream>, Status> {
        let responses = self.handle_import_hosts(request).await?;
        let stream = futures::stream::iter(responses.into_inner().into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }

    type ExportHostsStream = ResponseStream<ExportHostsResponse>;

    async fn export_hosts(
        &self,
        request: Request<ExportHostsRequest>,
    ) -> Result<Response<Self::ExportHostsStream>, Status> {
        let responses = self
            .handle_export_hosts(request, Arc::clone(&self.storage))
            .await?;
        let stream = futures::stream::iter(responses.into_inner().into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }

    // Snapshots
    async fn create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        self.handle_create_snapshot(request).await
    }

    type ListSnapshotsStream = ResponseStream<ListSnapshotsResponse>;

    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<Self::ListSnapshotsStream>, Status> {
        let responses = self.handle_list_snapshots(request).await?;
        let stream = futures::stream::iter(responses.into_inner().into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream) as Self::ListSnapshotsStream))
    }

    async fn rollback_to_snapshot(
        &self,
        request: Request<RollbackToSnapshotRequest>,
    ) -> Result<Response<RollbackToSnapshotResponse>, Status> {
        self.handle_rollback_to_snapshot(request).await
    }

    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        self.handle_delete_snapshot(request).await
    }

    // Health checks
    async fn liveness(
        &self,
        request: Request<LivenessRequest>,
    ) -> Result<Response<LivenessResponse>, Status> {
        self.handle_liveness(request).await
    }

    async fn readiness(
        &self,
        request: Request<ReadinessRequest>,
    ) -> Result<Response<ReadinessResponse>, Status> {
        self.handle_readiness(request).await
    }

    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        self.handle_health(request).await
    }
}
