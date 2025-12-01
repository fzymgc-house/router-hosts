//! Import/Export operation handlers (streaming)

use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    ExportHostsRequest, ExportHostsResponse, ImportHostsRequest, ImportHostsResponse,
};
use tonic::{Request, Response, Status, Streaming};

#[allow(dead_code)]
impl HostsServiceImpl {
    /// Import hosts from file format via streaming
    ///
    /// Supports conflict handling modes via `conflict_mode` field:
    /// - "skip" (default): Skip entries that already exist (same IP+hostname)
    /// - "replace": Update existing entries with imported values
    /// - "strict": Fail if any duplicate is found
    ///
    /// Progress is reported via streaming ImportHostsResponse with counters:
    /// - processed: Total entries parsed from input
    /// - created: New entries added
    /// - skipped: Duplicates skipped (when conflict_mode = "skip")
    /// - failed: Validation failures
    pub async fn handle_import_hosts(
        &self,
        _request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Vec<ImportHostsResponse>>, Status> {
        // TODO: Implement streaming import
        // - Parse format field (default "hosts", also "json", "csv")
        // - Collect chunks until last_chunk = true
        // - Parse entries from collected data
        // - Apply conflict_mode handling
        // - Return progress updates
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
