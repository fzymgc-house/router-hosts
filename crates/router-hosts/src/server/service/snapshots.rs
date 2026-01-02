//! Snapshot management handlers

use crate::server::metrics::counters::TimedOperation;
use crate::server::propagation;
use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    CreateSnapshotRequest, CreateSnapshotResponse, DeleteSnapshotRequest, DeleteSnapshotResponse,
    ListSnapshotsRequest, ListSnapshotsResponse, RollbackToSnapshotRequest,
    RollbackToSnapshotResponse, Snapshot,
};
use tonic::{Request, Response, Status};
use tracing_opentelemetry::OpenTelemetrySpanExt;

impl HostsServiceImpl {
    /// Create a new snapshot
    pub async fn handle_create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        // Extract W3C trace context from gRPC metadata for distributed tracing
        let parent_cx = propagation::extract_context(request.metadata());
        // Distributed tracing is best-effort: continue if parent context cannot be set
        let _ = tracing::Span::current().set_parent(parent_cx);

        let timer = TimedOperation::new("CreateSnapshot");
        let req = request.into_inner();

        // Validate trigger field
        let trigger = if req.trigger.is_empty() {
            "manual".to_string()
        } else {
            req.trigger
        };

        // Create snapshot
        match self
            .commands
            .create_snapshot(
                if req.name.is_empty() {
                    None
                } else {
                    Some(req.name)
                },
                trigger,
            )
            .await
        {
            Ok(snapshot) => {
                timer.finish("ok");
                Ok(Response::new(CreateSnapshotResponse {
                    snapshot_id: snapshot.snapshot_id.into_inner(),
                    created_at: snapshot.created_at.timestamp_micros(),
                    entry_count: snapshot.entry_count,
                }))
            }
            Err(e) => {
                timer.finish("error");
                Err(Status::internal(format!(
                    "Failed to create snapshot: {}",
                    e
                )))
            }
        }
    }

    /// List all snapshots
    pub async fn handle_list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<Vec<ListSnapshotsResponse>>, Status> {
        // Extract W3C trace context from gRPC metadata for distributed tracing
        let parent_cx = propagation::extract_context(request.metadata());
        // Distributed tracing is best-effort: continue if parent context cannot be set
        let _ = tracing::Span::current().set_parent(parent_cx);

        let timer = TimedOperation::new("ListSnapshots");
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
        match self.commands.list_snapshots(limit, offset).await {
            Ok(snapshots) => {
                timer.finish("ok");
                // Convert to proto snapshots
                let proto_snapshots: Vec<ListSnapshotsResponse> = snapshots
                    .into_iter()
                    .map(|s| {
                        use prost_types::Timestamp;
                        // Convert DateTime<Utc> to protobuf Timestamp
                        let seconds = s.created_at.timestamp();
                        let nanos = s.created_at.timestamp_subsec_nanos() as i32;

                        ListSnapshotsResponse {
                            snapshot: Some(Snapshot {
                                snapshot_id: s.snapshot_id.into_inner(),
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
            Err(e) => {
                timer.finish("error");
                Err(Status::internal(format!("Failed to list snapshots: {}", e)))
            }
        }
    }

    /// Rollback to a previous snapshot
    pub async fn handle_rollback_to_snapshot(
        &self,
        request: Request<RollbackToSnapshotRequest>,
    ) -> Result<Response<RollbackToSnapshotResponse>, Status> {
        // Extract W3C trace context from gRPC metadata for distributed tracing
        let parent_cx = propagation::extract_context(request.metadata());
        // Distributed tracing is best-effort: continue if parent context cannot be set
        let _ = tracing::Span::current().set_parent(parent_cx);

        let timer = TimedOperation::new("RollbackToSnapshot");
        let req = request.into_inner();

        if req.snapshot_id.is_empty() {
            timer.finish("error");
            return Err(Status::invalid_argument("snapshot_id is required"));
        }

        match self.commands.rollback_to_snapshot(&req.snapshot_id).await {
            Ok(result) => {
                timer.finish("ok");
                Ok(Response::new(RollbackToSnapshotResponse {
                    success: result.success,
                    new_snapshot_id: result.backup_snapshot_id,
                    restored_entry_count: result.restored_entry_count,
                }))
            }
            Err(e) => {
                timer.finish("error");
                Err(match e {
                    crate::server::commands::CommandError::NotFound(_) => {
                        Status::not_found(e.to_string())
                    }
                    crate::server::commands::CommandError::ValidationFailed(msg) => {
                        Status::invalid_argument(msg)
                    }
                    _ => Status::internal(e.to_string()),
                })
            }
        }
    }

    /// Delete a snapshot
    pub async fn handle_delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        // Extract W3C trace context from gRPC metadata for distributed tracing
        let parent_cx = propagation::extract_context(request.metadata());
        // Distributed tracing is best-effort: continue if parent context cannot be set
        let _ = tracing::Span::current().set_parent(parent_cx);

        let timer = TimedOperation::new("DeleteSnapshot");
        let req = request.into_inner();

        if req.snapshot_id.is_empty() {
            timer.finish("error");
            return Err(Status::invalid_argument("snapshot_id is required"));
        }

        // Delete snapshot
        match self.commands.delete_snapshot(&req.snapshot_id).await {
            Ok(deleted) => {
                if !deleted {
                    timer.finish("error");
                    return Err(Status::not_found(format!(
                        "Snapshot not found: {}",
                        req.snapshot_id
                    )));
                }
                timer.finish("ok");
                Ok(Response::new(DeleteSnapshotResponse { success: true }))
            }
            Err(e) => {
                timer.finish("error");
                Err(Status::internal(format!(
                    "Failed to delete snapshot: {}",
                    e
                )))
            }
        }
    }
}
