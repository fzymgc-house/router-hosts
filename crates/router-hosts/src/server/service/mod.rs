//! gRPC service layer for router-hosts server
//!
//! This module contains the HostsService implementation that handles
//! all gRPC requests and delegates to the command handler layer.

mod bulk;
mod hosts;
mod sessions;
mod snapshots;

use crate::server::commands::CommandHandler;
use crate::server::db::Database;
use crate::server::session::SessionManager;
use router_hosts_common::proto::hosts_service_server::HostsService;
use router_hosts_common::proto::{
    AddHostRequest, AddHostResponse, BulkAddHostsRequest, BulkAddHostsResponse, CancelEditRequest,
    CancelEditResponse, CreateSnapshotRequest, CreateSnapshotResponse, DeleteHostRequest,
    DeleteHostResponse, DeleteSnapshotRequest, DeleteSnapshotResponse, ExportHostsRequest,
    ExportHostsResponse, FinishEditRequest, FinishEditResponse, GetHostRequest, GetHostResponse,
    ImportHostsRequest, ImportHostsResponse, ListHostsRequest, ListHostsResponse,
    ListSnapshotsRequest, ListSnapshotsResponse, RollbackToSnapshotRequest,
    RollbackToSnapshotResponse, SearchHostsRequest, SearchHostsResponse, StartEditRequest,
    StartEditResponse, UpdateHostRequest, UpdateHostResponse,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};

/// Main gRPC service implementation
pub struct HostsServiceImpl {
    /// Command handler for business logic
    pub(crate) commands: Arc<CommandHandler>,
    /// Session manager for edit sessions (used by snapshot handlers)
    #[allow(dead_code)]
    pub(crate) session_mgr: Arc<SessionManager>,
    /// Database connection (used by snapshot handlers)
    #[allow(dead_code)]
    pub(crate) db: Arc<Database>,
}

impl HostsServiceImpl {
    /// Create a new service instance
    pub fn new(
        commands: Arc<CommandHandler>,
        session_mgr: Arc<SessionManager>,
        db: Arc<Database>,
    ) -> Self {
        Self {
            commands,
            session_mgr,
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

    // Edit sessions
    async fn start_edit(
        &self,
        request: Request<StartEditRequest>,
    ) -> Result<Response<StartEditResponse>, Status> {
        self.handle_start_edit(request).await
    }

    async fn finish_edit(
        &self,
        request: Request<FinishEditRequest>,
    ) -> Result<Response<FinishEditResponse>, Status> {
        self.handle_finish_edit(request).await
    }

    async fn cancel_edit(
        &self,
        request: Request<CancelEditRequest>,
    ) -> Result<Response<CancelEditResponse>, Status> {
        self.handle_cancel_edit(request).await
    }

    // Bulk operations (bidirectional streaming)
    type BulkAddHostsStream = ResponseStream<BulkAddHostsResponse>;

    async fn bulk_add_hosts(
        &self,
        request: Request<Streaming<BulkAddHostsRequest>>,
    ) -> Result<Response<Self::BulkAddHostsStream>, Status> {
        let mut in_stream = request.into_inner();
        let commands = Arc::clone(&self.commands);

        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            while let Some(result) = in_stream.next().await {
                match result {
                    Ok(req) => {
                        let response = match commands
                            .add_host(
                                req.ip_address,
                                req.hostname,
                                req.comment,
                                req.tags,
                                req.edit_token,
                            )
                            .await
                        {
                            Ok(entry) => BulkAddHostsResponse {
                                id: Some(entry.id.to_string()),
                                error: None,
                            },
                            Err(e) => BulkAddHostsResponse {
                                id: None,
                                error: Some(e.to_string()),
                            },
                        };
                        if tx.send(Ok(response)).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    type ImportHostsStream = ResponseStream<ImportHostsResponse>;

    async fn import_hosts(
        &self,
        _request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Self::ImportHostsStream>, Status> {
        Err(Status::unimplemented("ImportHosts not yet implemented"))
    }

    type ExportHostsStream = ResponseStream<ExportHostsResponse>;

    async fn export_hosts(
        &self,
        _request: Request<ExportHostsRequest>,
    ) -> Result<Response<Self::ExportHostsStream>, Status> {
        Err(Status::unimplemented("ExportHosts not yet implemented"))
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
