//! Edit session handlers

use crate::server::commands::CommandError;
use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    CancelEditRequest, CancelEditResponse, FinishEditRequest, FinishEditResponse,
    StartEditRequest, StartEditResponse,
};
use tonic::{Request, Response, Status};

impl HostsServiceImpl {
    /// Start a new edit session
    pub async fn handle_start_edit(
        &self,
        _request: Request<StartEditRequest>,
    ) -> Result<Response<StartEditResponse>, Status> {
        let token = self
            .commands
            .start_edit()
            .map_err(command_error_to_status)?;

        Ok(Response::new(StartEditResponse { edit_token: token }))
    }

    /// Finish an edit session and commit changes
    pub async fn handle_finish_edit(
        &self,
        request: Request<FinishEditRequest>,
    ) -> Result<Response<FinishEditResponse>, Status> {
        let req = request.into_inner();

        let entries_changed = self
            .commands
            .finish_edit(&req.edit_token)
            .await
            .map_err(command_error_to_status)?;

        Ok(Response::new(FinishEditResponse {
            success: true,
            entries_changed: entries_changed as i32,
        }))
    }

    /// Cancel an edit session and discard changes
    pub async fn handle_cancel_edit(
        &self,
        request: Request<CancelEditRequest>,
    ) -> Result<Response<CancelEditResponse>, Status> {
        let req = request.into_inner();

        self.commands
            .cancel_edit(&req.edit_token)
            .map_err(command_error_to_status)?;

        Ok(Response::new(CancelEditResponse { success: true }))
    }
}

/// Convert CommandError to gRPC Status
fn command_error_to_status(err: CommandError) -> Status {
    match err {
        CommandError::ValidationFailed(msg) => Status::invalid_argument(msg),
        CommandError::DuplicateEntry(msg) => Status::already_exists(msg),
        CommandError::NotFound(msg) => Status::not_found(msg),
        CommandError::SessionConflict => {
            Status::failed_precondition("Session conflict: another edit session is active")
        }
        CommandError::SessionExpired => Status::failed_precondition("Session expired"),
        CommandError::InvalidToken => Status::failed_precondition("Invalid token"),
        CommandError::NoActiveSession => Status::failed_precondition("No active session"),
        CommandError::Database(e) => Status::internal(format!("Database error: {}", e)),
        CommandError::FileGeneration(msg) => Status::internal(format!("File generation error: {}", msg)),
        CommandError::Internal(msg) => Status::internal(msg),
    }
}
