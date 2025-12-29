//! Host CRUD operation handlers

use crate::server::commands::CommandError;
use crate::server::metrics::counters::TimedOperation;
use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    self, AddHostRequest, AddHostResponse, DeleteHostRequest, DeleteHostResponse, GetHostRequest,
    GetHostResponse, ListHostsRequest, ListHostsResponse, SearchHostsRequest, SearchHostsResponse,
    UpdateHostRequest, UpdateHostResponse,
};
use router_hosts_storage::HostEntry;
use tonic::{Request, Response, Status};
use ulid::Ulid;

impl HostsServiceImpl {
    /// Add a new host entry
    pub async fn handle_add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<AddHostResponse>, Status> {
        let timer = TimedOperation::new("AddHost");
        let req = request.into_inner();

        let result = self
            .write_queue
            .add_host(
                req.ip_address,
                req.hostname,
                req.aliases,
                req.comment,
                req.tags,
            )
            .await;

        match result {
            Ok(entry) => {
                timer.finish("ok");
                Ok(Response::new(AddHostResponse {
                    id: entry.id.to_string(),
                    entry: Some(host_entry_to_proto(entry)),
                }))
            }
            Err(e) => {
                timer.finish("error");
                Err(Status::from(e))
            }
        }
    }

    /// Get a host entry by ID
    pub async fn handle_get_host(
        &self,
        request: Request<GetHostRequest>,
    ) -> Result<Response<GetHostResponse>, Status> {
        let timer = TimedOperation::new("GetHost");
        let req = request.into_inner();

        let id = match Ulid::from_string(&req.id) {
            Ok(id) => id,
            Err(e) => {
                timer.finish("error");
                return Err(Status::invalid_argument(format!(
                    "Invalid ID format: {}",
                    e
                )));
            }
        };

        match self.commands.get_host(id).await {
            Ok(entry) => {
                timer.finish("ok");
                Ok(Response::new(GetHostResponse {
                    entry: Some(host_entry_to_proto(entry)),
                }))
            }
            Err(e) => {
                timer.finish("error");
                Err(Status::from(e))
            }
        }
    }

    /// Update an existing host entry
    pub async fn handle_update_host(
        &self,
        request: Request<UpdateHostRequest>,
    ) -> Result<Response<UpdateHostResponse>, Status> {
        let timer = TimedOperation::new("UpdateHost");
        let req = request.into_inner();

        let id = match Ulid::from_string(&req.id) {
            Ok(id) => id,
            Err(e) => {
                timer.finish("error");
                return Err(Status::invalid_argument(format!(
                    "Invalid ID format: {}",
                    e
                )));
            }
        };

        // Convert optional fields properly from proto optional fields
        // For comment: None = no change, Some(None) = clear, Some(Some(val)) = set value
        let comment = req
            .comment
            .map(|c| if c.is_empty() { None } else { Some(c) });

        // For aliases: wrapper pattern - None = no change, Some(wrapper) = update
        let aliases = req.aliases.map(|wrapper| wrapper.values);

        // For tags: wrapper pattern - None = no change, Some(wrapper) = update
        let tags = req.tags.map(|wrapper| wrapper.values);

        match self
            .write_queue
            .update_host(
                id,
                req.ip_address, // Already Option<String> from proto
                req.hostname,   // Already Option<String> from proto
                comment,
                aliases,
                tags,
                req.expected_version, // For optimistic concurrency
            )
            .await
        {
            Ok(entry) => {
                timer.finish("ok");
                Ok(Response::new(UpdateHostResponse {
                    entry: Some(host_entry_to_proto(entry)),
                }))
            }
            Err(e) => {
                timer.finish("error");
                Err(Status::from(e))
            }
        }
    }

    /// Delete a host entry
    pub async fn handle_delete_host(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        let timer = TimedOperation::new("DeleteHost");
        let req = request.into_inner();

        let id = match Ulid::from_string(&req.id) {
            Ok(id) => id,
            Err(e) => {
                timer.finish("error");
                return Err(Status::invalid_argument(format!(
                    "Invalid ID format: {}",
                    e
                )));
            }
        };

        match self.write_queue.delete_host(id, None).await {
            Ok(()) => {
                timer.finish("ok");
                Ok(Response::new(DeleteHostResponse { success: true }))
            }
            Err(e) => {
                timer.finish("error");
                Err(Status::from(e))
            }
        }
    }

    /// List all host entries (server streaming)
    pub async fn handle_list_hosts(
        &self,
        _request: Request<ListHostsRequest>,
    ) -> Result<Response<Vec<ListHostsResponse>>, Status> {
        let timer = TimedOperation::new("ListHosts");

        match self.commands.list_hosts().await {
            Ok(entries) => {
                timer.finish("ok");
                let responses: Vec<ListHostsResponse> = entries
                    .into_iter()
                    .map(|entry| ListHostsResponse {
                        entry: Some(host_entry_to_proto(entry)),
                    })
                    .collect();
                Ok(Response::new(responses))
            }
            Err(e) => {
                timer.finish("error");
                Err(Status::from(e))
            }
        }
    }

    /// Search for host entries (server streaming)
    pub async fn handle_search_hosts(
        &self,
        request: Request<SearchHostsRequest>,
    ) -> Result<Response<Vec<SearchHostsResponse>>, Status> {
        let timer = TimedOperation::new("SearchHosts");
        let req = request.into_inner();

        match self.commands.search_hosts(&req.query).await {
            Ok(entries) => {
                timer.finish("ok");
                let responses: Vec<SearchHostsResponse> = entries
                    .into_iter()
                    .map(|entry| SearchHostsResponse {
                        entry: Some(host_entry_to_proto(entry)),
                    })
                    .collect();
                Ok(Response::new(responses))
            }
            Err(e) => {
                timer.finish("error");
                Err(Status::from(e))
            }
        }
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
            CommandError::VersionConflict { expected, actual } => Status::aborted(format!(
                "Version conflict: expected {}, actual {}",
                expected, actual
            )),
            CommandError::Storage(e) => Status::internal(format!("Storage error: {}", e)),
            CommandError::FileGeneration(msg) => {
                Status::internal(format!("File generation error: {}", msg))
            }
            CommandError::Internal(msg) => Status::internal(msg),
        }
    }
}

/// Convert storage HostEntry to proto HostEntry
fn host_entry_to_proto(entry: HostEntry) -> proto::HostEntry {
    proto::HostEntry {
        id: entry.id.to_string(),
        ip_address: entry.ip_address,
        hostname: entry.hostname,
        aliases: entry.aliases,
        comment: entry.comment,
        tags: entry.tags,
        created_at: Some(prost_types::Timestamp {
            seconds: entry.created_at.timestamp(),
            nanos: entry.created_at.timestamp_subsec_nanos() as i32,
        }),
        updated_at: Some(prost_types::Timestamp {
            seconds: entry.updated_at.timestamp(),
            nanos: entry.updated_at.timestamp_subsec_nanos() as i32,
        }),
        version: entry.version,
    }
}
