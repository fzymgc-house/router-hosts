//! Host CRUD operation handlers

use crate::server::commands::CommandError;
use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    AddHostRequest, AddHostResponse, DeleteHostRequest, DeleteHostResponse, GetHostRequest,
    GetHostResponse, ListHostsRequest, ListHostsResponse, SearchHostsRequest, SearchHostsResponse,
    UpdateHostRequest, UpdateHostResponse,
};
use tonic::{Request, Response, Status};
use ulid::Ulid;

impl HostsServiceImpl {
    /// Add a new host entry
    pub async fn handle_add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<AddHostResponse>, Status> {
        let req = request.into_inner();

        let entry = self
            .commands
            .add_host(req.ip_address, req.hostname, req.comment, req.tags)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(AddHostResponse {
            id: entry.id.to_string(),
            entry: Some(entry.into()),
        }))
    }

    /// Get a host entry by ID
    pub async fn handle_get_host(
        &self,
        request: Request<GetHostRequest>,
    ) -> Result<Response<GetHostResponse>, Status> {
        let req = request.into_inner();

        let id = Ulid::from_string(&req.id)
            .map_err(|e| Status::invalid_argument(format!("Invalid ID format: {}", e)))?;

        let entry = self
            .commands
            .get_host(id)
            .await
            .map_err(Status::from)?
            .ok_or_else(|| Status::not_found(format!("Host {} not found", req.id)))?;

        Ok(Response::new(GetHostResponse {
            entry: Some(entry.into()),
        }))
    }

    /// Update an existing host entry
    pub async fn handle_update_host(
        &self,
        request: Request<UpdateHostRequest>,
    ) -> Result<Response<UpdateHostResponse>, Status> {
        let req = request.into_inner();

        let id = Ulid::from_string(&req.id)
            .map_err(|e| Status::invalid_argument(format!("Invalid ID format: {}", e)))?;

        // Convert optional fields properly from proto optional fields
        // For comment: None = no change, Some(None) = clear, Some(Some(val)) = set value
        let comment = req
            .comment
            .map(|c| if c.is_empty() { None } else { Some(c) });

        // For tags: if provided and empty, clear tags; if not provided, keep existing
        let tags = if req.tags.is_empty() {
            None
        } else {
            Some(req.tags)
        };

        let entry = self
            .commands
            .update_host(
                id,
                req.ip_address, // Already Option<String> from proto
                req.hostname,   // Already Option<String> from proto
                comment,
                tags,
            )
            .await
            .map_err(Status::from)?;

        Ok(Response::new(UpdateHostResponse {
            entry: Some(entry.into()),
        }))
    }

    /// Delete a host entry
    pub async fn handle_delete_host(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        let req = request.into_inner();

        let id = Ulid::from_string(&req.id)
            .map_err(|e| Status::invalid_argument(format!("Invalid ID format: {}", e)))?;

        self.commands
            .delete_host(id, None)
            .await
            .map_err(Status::from)?;

        Ok(Response::new(DeleteHostResponse { success: true }))
    }

    /// List all host entries (server streaming)
    pub async fn handle_list_hosts(
        &self,
        _request: Request<ListHostsRequest>,
    ) -> Result<Response<Vec<ListHostsResponse>>, Status> {
        let entries = self.commands.list_hosts().await.map_err(Status::from)?;

        let responses: Vec<ListHostsResponse> = entries
            .into_iter()
            .map(|entry| ListHostsResponse {
                entry: Some(entry.into()),
            })
            .collect();

        Ok(Response::new(responses))
    }

    /// Search for host entries (server streaming)
    pub async fn handle_search_hosts(
        &self,
        request: Request<SearchHostsRequest>,
    ) -> Result<Response<Vec<SearchHostsResponse>>, Status> {
        let req = request.into_inner();

        let entries = self
            .commands
            .search_hosts(&req.query)
            .await
            .map_err(Status::from)?;

        let responses: Vec<SearchHostsResponse> = entries
            .into_iter()
            .map(|entry| SearchHostsResponse {
                entry: Some(entry.into()),
            })
            .collect();

        Ok(Response::new(responses))
    }
}

/// Convert CommandError to gRPC Status using idiomatic From trait
///
/// This centralized implementation ensures consistent error mapping across
/// all gRPC service methods. Each CommandError variant maps to the appropriate
/// gRPC status code per the error handling guidelines in CLAUDE.md.
impl From<CommandError> for Status {
    fn from(err: CommandError) -> Self {
        match err {
            CommandError::ValidationFailed(msg) => Status::invalid_argument(msg),
            CommandError::DuplicateEntry(msg) => Status::already_exists(msg),
            CommandError::NotFound(msg) => Status::not_found(msg),
            CommandError::Database(e) => Status::internal(format!("Database error: {}", e)),
            CommandError::FileGeneration(msg) => {
                Status::internal(format!("File generation error: {}", msg))
            }
            CommandError::Internal(msg) => Status::internal(msg),
        }
    }
}
