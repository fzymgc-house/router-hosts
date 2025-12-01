//! Snapshot management handlers

use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    CreateSnapshotRequest, CreateSnapshotResponse, DeleteSnapshotRequest, DeleteSnapshotResponse,
    ListSnapshotsRequest, ListSnapshotsResponse, RollbackToSnapshotRequest,
    RollbackToSnapshotResponse,
};
use tonic::{Request, Response, Status};

impl HostsServiceImpl {
    /// Create a new snapshot
    pub async fn handle_create_snapshot(
        &self,
        _request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        // TODO: Implement snapshot creation
        Err(Status::unimplemented("CreateSnapshot not yet implemented"))
    }

    /// List all snapshots
    pub async fn handle_list_snapshots(
        &self,
        _request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<Vec<ListSnapshotsResponse>>, Status> {
        // TODO: Implement snapshot listing
        Err(Status::unimplemented("ListSnapshots not yet implemented"))
    }

    /// Rollback to a previous snapshot
    pub async fn handle_rollback_to_snapshot(
        &self,
        _request: Request<RollbackToSnapshotRequest>,
    ) -> Result<Response<RollbackToSnapshotResponse>, Status> {
        // TODO: Implement snapshot rollback
        Err(Status::unimplemented(
            "RollbackToSnapshot not yet implemented",
        ))
    }

    /// Delete a snapshot
    pub async fn handle_delete_snapshot(
        &self,
        _request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        // TODO: Implement snapshot deletion
        Err(Status::unimplemented("DeleteSnapshot not yet implemented"))
    }
}
