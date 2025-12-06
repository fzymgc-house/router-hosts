//! gRPC service layer for router-hosts server
//!
//! This module contains the HostsService implementation that handles
//! all gRPC requests and delegates to the command handler layer.

mod bulk;
mod hosts;
mod snapshots;

use crate::server::commands::CommandHandler;
use crate::server::db::Database;
use crate::server::write_queue::WriteQueue;
use router_hosts_common::proto::hosts_service_server::HostsService;
use router_hosts_common::proto::{
    AddHostRequest, AddHostResponse, CreateSnapshotRequest, CreateSnapshotResponse,
    DeleteHostRequest, DeleteHostResponse, DeleteSnapshotRequest, DeleteSnapshotResponse,
    ExportHostsRequest, ExportHostsResponse, GetHostRequest, GetHostResponse, ImportHostsRequest,
    ImportHostsResponse, ListHostsRequest, ListHostsResponse, ListSnapshotsRequest,
    ListSnapshotsResponse, RollbackToSnapshotRequest, RollbackToSnapshotResponse,
    SearchHostsRequest, SearchHostsResponse, UpdateHostRequest, UpdateHostResponse,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;
use tonic::{Request, Response, Status, Streaming};

/// Main gRPC service implementation
pub struct HostsServiceImpl {
    /// Write queue for serialized mutation operations
    pub(crate) write_queue: WriteQueue,
    /// Command handler for read operations and snapshot management
    pub(crate) commands: Arc<CommandHandler>,
    /// Database connection (used by export and snapshot handlers)
    pub(crate) db: Arc<Database>,
}

impl HostsServiceImpl {
    /// Create a new service instance
    pub fn new(write_queue: WriteQueue, commands: Arc<CommandHandler>, db: Arc<Database>) -> Self {
        Self {
            write_queue,
            commands,
            db,
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
            .handle_export_hosts(request, Arc::clone(&self.db))
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
}
