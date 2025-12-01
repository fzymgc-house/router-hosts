//! Import/Export operation handlers (streaming)

use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    ExportHostsRequest, ExportHostsResponse, ImportHostsRequest, ImportHostsResponse,
};
use tonic::{Request, Response, Status, Streaming};

#[allow(dead_code)]
impl HostsServiceImpl {
    /// Import hosts from file format via streaming
    pub async fn handle_import_hosts(
        &self,
        _request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Vec<ImportHostsResponse>>, Status> {
        // TODO: Implement streaming import with conflict handling
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
