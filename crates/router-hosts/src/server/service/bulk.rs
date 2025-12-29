//! Import/Export operation handlers (streaming)

use crate::server::export::{
    format_csv_entry, format_csv_header, format_hosts_entry, format_hosts_header,
    format_json_entry, ExportFormat,
};
use crate::server::metrics::counters::TimedOperation;
use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    ExportHostsRequest, ExportHostsResponse, ImportHostsRequest, ImportHostsResponse,
};
use router_hosts_storage::Storage;
use std::sync::Arc;
use tonic::{Request, Response, Status, Streaming};

/// Maximum size of import data in bytes (10 MiB)
///
/// This limit prevents OOM on resource-constrained devices like routers.
/// A typical hosts file with 10,000 entries is ~500KB, so 10MB allows for
/// very large imports while protecting against memory exhaustion.
const MAX_IMPORT_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of chunks allowed in an import stream
///
/// Prevents DoS attacks where a client sends many small chunks without
/// terminating the stream. With MAX_IMPORT_SIZE of 10MB, this allows
/// chunks as small as 1KB on average.
const MAX_CHUNKS: usize = 10_000;

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

        let timer = TimedOperation::new("ImportHosts");
        let mut stream = request.into_inner();
        let mut data = Vec::new();
        let mut format: Option<String> = None;
        let mut conflict_mode: Option<String> = None;
        let mut chunk_count: usize = 0;

        // Collect all chunks with size and count limit checks
        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    timer.finish("error");
                    return Err(e);
                }
            };

            // Check chunk count limit to prevent DoS via endless small chunks
            chunk_count += 1;
            if chunk_count > MAX_CHUNKS {
                timer.finish("error");
                return Err(Status::resource_exhausted(format!(
                    "Import stream exceeds maximum chunk count of {}",
                    MAX_CHUNKS
                )));
            }

            // Check size limit before extending buffer
            if data.len() + chunk.chunk.len() > MAX_IMPORT_SIZE {
                timer.finish("error");
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
        let import_format: ImportFormat = match format.as_deref().unwrap_or("").parse() {
            Ok(f) => f,
            Err(_) => {
                timer.finish("error");
                return Err(Status::invalid_argument(format!(
                    "Invalid format '{}'. Supported: hosts, json, csv",
                    format.as_deref().unwrap_or("")
                )));
            }
        };

        // Parse conflict mode
        let mode: ConflictMode = match conflict_mode.as_deref().unwrap_or("").parse() {
            Ok(m) => m,
            Err(e) => {
                timer.finish("error");
                return Err(Status::invalid_argument(e));
            }
        };

        // Parse the import data
        let entries = match parse_import(&data, import_format) {
            Ok(e) => e,
            Err(e) => {
                timer.finish("error");
                return Err(Status::invalid_argument(format!("Parse error: {}", e)));
            }
        };

        // Import via write queue for serialization
        match self.write_queue.import_hosts(entries, mode).await {
            Ok(result) => {
                timer.finish("ok");
                Ok(Response::new(vec![ImportHostsResponse {
                    processed: result.processed,
                    created: result.created,
                    updated: result.updated,
                    skipped: result.skipped,
                    failed: result.failed,
                    error: None,
                    validation_errors: result.validation_errors,
                }]))
            }
            Err(e) => {
                timer.finish("error");
                Err(match e {
                    crate::server::commands::CommandError::DuplicateEntry(msg) => {
                        Status::already_exists(msg)
                    }
                    crate::server::commands::CommandError::ValidationFailed(msg) => {
                        Status::invalid_argument(msg)
                    }
                    other => Status::internal(other.to_string()),
                })
            }
        }
    }

    /// Export hosts in specified format via streaming
    ///
    /// Each host entry is sent as a separate response message.
    /// Format-specific headers (if any) are sent first.
    pub async fn handle_export_hosts(
        &self,
        request: Request<ExportHostsRequest>,
        storage: Arc<dyn Storage>,
    ) -> Result<Response<Vec<ExportHostsResponse>>, Status> {
        let timer = TimedOperation::new("ExportHosts");
        let req = request.into_inner();

        // Parse and validate format
        let format: ExportFormat = match req.format.parse() {
            Ok(f) => f,
            Err(_) => {
                timer.finish("error");
                return Err(Status::invalid_argument(format!(
                    "Invalid format '{}'. Supported: hosts, json, csv",
                    req.format
                )));
            }
        };

        // Query all hosts from storage
        let entries = match storage.list_all().await {
            Ok(e) => e,
            Err(e) => {
                timer.finish("error");
                return Err(Status::internal(format!("Failed to query hosts: {}", e)));
            }
        };

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
                ExportFormat::Json => match format_json_entry(&entry) {
                    Ok(c) => c,
                    Err(e) => {
                        timer.finish("error");
                        return Err(Status::internal(format!("Failed to format entry: {}", e)));
                    }
                },
                ExportFormat::Csv => format_csv_entry(&entry),
            };
            responses.push(ExportHostsResponse { chunk });
        }

        timer.finish("ok");
        Ok(Response::new(responses))
    }
}
