//! Bulk operation handlers (streaming)

use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    BulkAddHostsRequest, BulkAddHostsResponse, ExportHostsRequest, ExportHostsResponse,
    ImportHostsRequest, ImportHostsResponse,
};
use tonic::{Request, Response, Status, Streaming};

impl HostsServiceImpl {
    /// Bulk add hosts via bidirectional streaming
    pub async fn handle_bulk_add_hosts(
        &self,
        _request: Request<Streaming<BulkAddHostsRequest>>,
    ) -> Result<Response<Vec<BulkAddHostsResponse>>, Status> {
        // TODO: Implement streaming bulk add
        Err(Status::unimplemented("BulkAddHosts not yet implemented"))
    }

    /// Import hosts from file format via streaming
    pub async fn handle_import_hosts(
        &self,
        _request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Vec<ImportHostsResponse>>, Status> {
        // TODO: Implement streaming import
        Err(Status::unimplemented("ImportHosts not yet implemented"))
    }

    /// Export hosts in specified format via streaming
    pub async fn handle_export_hosts(
        &self,
        _request: Request<ExportHostsRequest>,
    ) -> Result<Response<Vec<ExportHostsResponse>>, Status> {
        // TODO: Implement streaming export
        Err(Status::unimplemented("ExportHosts not yet implemented"))
    }
}
