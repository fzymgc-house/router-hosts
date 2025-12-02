//! Import/Export operation handlers (streaming)

use crate::server::db::Database;
use crate::server::db::HostProjections;
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

/// Maximum size of import data in bytes (10 MiB)
///
/// This limit prevents OOM on resource-constrained devices like routers.
/// A typical hosts file with 10,000 entries is ~500KB, so 10MB allows for
/// very large imports while protecting against memory exhaustion.
const MAX_IMPORT_SIZE: usize = 10 * 1024 * 1024;

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
    /// - updated: Existing entries updated (when conflict_mode = "replace")
    /// - skipped: Duplicates skipped (when conflict_mode = "skip")
    /// - failed: Validation failures
    pub async fn handle_import_hosts(
        &self,
        request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Vec<ImportHostsResponse>>, Status> {
        use crate::server::import::{parse_import, ImportFormat};
        use crate::server::write_queue::ConflictMode;
        use tokio_stream::StreamExt;

        let mut stream = request.into_inner();
        let mut data = Vec::new();
        let mut format: Option<String> = None;
        let mut conflict_mode: Option<String> = None;

        // Collect all chunks with size limit check
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;

            // Check size limit before extending buffer
            if data.len() + chunk.chunk.len() > MAX_IMPORT_SIZE {
                return Err(Status::resource_exhausted(format!(
                    "Import data exceeds maximum size of {} bytes",
                    MAX_IMPORT_SIZE
                )));
            }

            data.extend_from_slice(&chunk.chunk);

            // Capture format and conflict_mode from first message that has them
            if format.is_none() && chunk.format.is_some() {
                format = chunk.format;
            }
            if conflict_mode.is_none() && chunk.conflict_mode.is_some() {
                conflict_mode = chunk.conflict_mode;
            }

            if chunk.last_chunk {
                break;
            }
        }

        // Parse format
        let import_format: ImportFormat =
            format.as_deref().unwrap_or("").parse().map_err(|_| {
                Status::invalid_argument(format!(
                    "Invalid format '{}'. Supported: hosts, json, csv",
                    format.as_deref().unwrap_or("")
                ))
            })?;

        // Parse conflict mode
        let mode: ConflictMode = conflict_mode
            .as_deref()
            .unwrap_or("")
            .parse()
            .map_err(Status::invalid_argument)?;

        // Parse the import data
        let entries = parse_import(&data, import_format)
            .map_err(|e| Status::invalid_argument(format!("Parse error: {}", e)))?;

        // Import via write queue for serialization
        let result = self
            .write_queue
            .import_hosts(entries, mode)
            .await
            .map_err(|e| match e {
                crate::server::commands::CommandError::DuplicateEntry(msg) => {
                    Status::already_exists(msg)
                }
                crate::server::commands::CommandError::ValidationFailed(msg) => {
                    Status::invalid_argument(msg)
                }
                other => Status::internal(other.to_string()),
            })?;

        Ok(Response::new(vec![ImportHostsResponse {
            processed: result.processed,
            created: result.created,
            updated: result.updated,
            skipped: result.skipped,
            failed: result.failed,
            error: None,
        }]))
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
        let format: ExportFormat = req.format.parse().map_err(|_| {
            Status::invalid_argument(format!(
                "Invalid format '{}'. Supported: hosts, json, csv",
                req.format
            ))
        })?;

        // Query all hosts
        let entries = HostProjections::list_all(&db)
            .map_err(|e| Status::internal(format!("Failed to query hosts: {}", e)))?;

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
                ExportFormat::Json => format_json_entry(&entry)
                    .map_err(|e| Status::internal(format!("Failed to format entry: {}", e)))?,
                ExportFormat::Csv => format_csv_entry(&entry),
            };
            responses.push(ExportHostsResponse { chunk });
        }

        Ok(Response::new(responses))
    }
}
