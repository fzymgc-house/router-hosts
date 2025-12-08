//! Snapshot management handlers

use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    CreateSnapshotRequest, CreateSnapshotResponse, DeleteSnapshotRequest, DeleteSnapshotResponse,
    ListSnapshotsRequest, ListSnapshotsResponse, RollbackToSnapshotRequest,
    RollbackToSnapshotResponse, Snapshot,
};
use tonic::{Request, Response, Status};

impl HostsServiceImpl {
    /// Create a new snapshot
    pub async fn handle_create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        let req = request.into_inner();

        // Validate trigger field
        let trigger = if req.trigger.is_empty() {
            "manual".to_string()
        } else {
            req.trigger
        };

        // Create snapshot
        let snapshot = self
            .commands
            .create_snapshot(
                if req.name.is_empty() {
                    None
                } else {
                    Some(req.name)
                },
                trigger,
            )
            .map_err(|e| Status::internal(format!("Failed to create snapshot: {}", e)))?;

        Ok(Response::new(CreateSnapshotResponse {
            snapshot_id: snapshot.snapshot_id,
            created_at: snapshot.created_at,
            entry_count: snapshot.entry_count,
        }))
    }

    /// List all snapshots
    pub async fn handle_list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<Vec<ListSnapshotsResponse>>, Status> {
        let req = request.into_inner();

        // Convert u32 to Option<u32> for limit/offset
        let limit = if req.limit == 0 {
            None
        } else {
            Some(req.limit)
        };
        let offset = if req.offset == 0 {
            None
        } else {
            Some(req.offset)
        };

        // List snapshots
        let snapshots = self
            .commands
            .list_snapshots(limit, offset)
            .map_err(|e| Status::internal(format!("Failed to list snapshots: {}", e)))?;

        // Convert to proto snapshots
        let proto_snapshots: Vec<ListSnapshotsResponse> = snapshots
            .into_iter()
            .map(|s| {
                use prost_types::Timestamp;
                // Convert microseconds to seconds and nanos for protobuf Timestamp
                let seconds = s.created_at / 1_000_000;
                let nanos = ((s.created_at % 1_000_000) * 1000) as i32;

                ListSnapshotsResponse {
                    snapshot: Some(Snapshot {
                        snapshot_id: s.snapshot_id,
                        created_at: Some(Timestamp { seconds, nanos }),
                        entry_count: s.entry_count,
                        trigger: s.trigger,
                        name: s.name.unwrap_or_default(),
                    }),
                }
            })
            .collect();

        Ok(Response::new(proto_snapshots))
    }

    /// Rollback to a previous snapshot
    pub async fn handle_rollback_to_snapshot(
        &self,
        _request: Request<RollbackToSnapshotRequest>,
    ) -> Result<Response<RollbackToSnapshotResponse>, Status> {
        // TODO: Implement snapshot rollback (out of scope for v1)
        Err(Status::unimplemented(
            "RollbackToSnapshot not yet implemented",
        ))
    }

    /// Delete a snapshot
    pub async fn handle_delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        let req = request.into_inner();

        if req.snapshot_id.is_empty() {
            return Err(Status::invalid_argument("snapshot_id is required"));
        }

        // Delete snapshot
        let deleted = self
            .commands
            .delete_snapshot(&req.snapshot_id)
            .map_err(|e| Status::internal(format!("Failed to delete snapshot: {}", e)))?;

        if !deleted {
            return Err(Status::not_found(format!(
                "Snapshot not found: {}",
                req.snapshot_id
            )));
        }

        Ok(Response::new(DeleteSnapshotResponse { success: true }))
    }
}
