//! Import/Export operation handlers (streaming)

use crate::server::db::HostProjections;
use crate::server::db::Database;
use crate::server::export::{
    format_csv_entry, format_csv_header, format_hosts_entry, format_hosts_header,
    format_json_entry, ExportFormat,
};
use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    ExportHostsRequest, ExportHostsResponse, ImportHostsRequest, ImportHostsResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status, Streaming};

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
        Err(Status::unimplemented("ImportHosts not yet implemented"))
    }

    /// Export hosts in specified format via streaming
    ///
    /// Each host entry is sent as a separate response message.
    /// Format-specific headers (if any) are sent first.
    pub async fn handle_export_hosts(
        &self,
        request: Request<ExportHostsRequest>,
        db: Arc<Database>,
    ) -> Result<Response<Vec<ExportHostsResponse>>, Status> {
        let req = request.into_inner();

        // Parse and validate format
        let format = ExportFormat::from_str(&req.format).ok_or_else(|| {
            Status::invalid_argument(format!(
                "Invalid format '{}'. Supported: hosts, json, csv",
                req.format
            ))
        })?;

        // Query all hosts
        let entries = HostProjections::list_all(&db).map_err(|e| {
            Status::internal(format!("Failed to query hosts: {}", e))
        })?;

        let mut responses = Vec::new();

        // Send header if applicable
        match format {
            ExportFormat::Hosts => {
                responses.push(ExportHostsResponse {
                    chunk: format_hosts_header(entries.len()),
                });
            }
            ExportFormat::Csv => {
                responses.push(ExportHostsResponse {
                    chunk: format_csv_header(),
                });
            }
            ExportFormat::Json => {
                // No header for JSONL
            }
        }

        // Send each entry
        for entry in entries {
            let chunk = match format {
                ExportFormat::Hosts => format_hosts_entry(&entry),
                ExportFormat::Json => format_json_entry(&entry),
                ExportFormat::Csv => format_csv_entry(&entry),
            };
            responses.push(ExportHostsResponse { chunk });
        }

        Ok(Response::new(responses))
    }
}
