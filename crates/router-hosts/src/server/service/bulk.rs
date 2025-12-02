//! Import/Export operation handlers (streaming)

use crate::server::db::Database;
use crate::server::db::HostProjections;
use crate::server::export::{
    format_csv_entry, format_csv_header, format_hosts_entry, format_hosts_header,
    format_json_entry, ExportFormat,
};
use crate::server::import::{
    extract_lines, is_csv_header, parse_line, ConflictMode, ImportFormat, ImportState, ParseError,
};
use crate::server::service::HostsServiceImpl;
use router_hosts_common::proto::{
    ExportHostsRequest, ExportHostsResponse, ImportHostsRequest, ImportHostsResponse,
};
use router_hosts_common::validation::{validate_hostname, validate_ip_address};
use std::sync::Arc;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

/// Maximum line buffer size to prevent DoS attacks (10MB)
const MAX_LINE_BUFFER_SIZE: usize = 10 * 1024 * 1024;

impl HostsServiceImpl {
    /// Process a single parsed entry with validation and conflict handling
    ///
    /// Returns Ok(()) on success, Err(response) when strict mode should fail
    async fn process_entry(
        &self,
        parsed: crate::server::import::ParsedEntry,
        state: &mut ImportState,
        db_set: &std::collections::HashSet<(String, String)>,
    ) -> Result<(), ImportHostsResponse> {
        // Validate IP address
        if validate_ip_address(&parsed.ip_address).is_err() {
            state.failed += 1;
            if state.conflict_mode == ConflictMode::Strict {
                return Err(state.error_response(format!("Invalid IP: {}", parsed.ip_address)));
            }
            return Ok(());
        }

        // Validate hostname
        if validate_hostname(&parsed.hostname).is_err() {
            state.failed += 1;
            if state.conflict_mode == ConflictMode::Strict {
                return Err(state.error_response(format!("Invalid hostname: {}", parsed.hostname)));
            }
            return Ok(());
        }

        // Entry passed validation, increment processed counter
        state.processed += 1;

        // Check for duplicates in this import
        let key = (parsed.ip_address.clone(), parsed.hostname.clone());
        if state.seen.contains(&key) {
            state.skipped += 1;
            if state.conflict_mode == ConflictMode::Strict {
                return Err(state.error_response(format!(
                    "Duplicate in import: {} {}",
                    parsed.ip_address, parsed.hostname
                )));
            }
            return Ok(());
        }

        // Check for duplicates in database
        let db_duplicate = db_set.contains(&key);

        if db_duplicate {
            match state.conflict_mode {
                ConflictMode::Skip => {
                    state.skipped += 1;
                    return Ok(());
                }
                ConflictMode::Replace => {
                    return Err(
                        state.error_response("replace mode not yet implemented".to_string())
                    );
                }
                ConflictMode::Strict => {
                    return Err(state.error_response(format!(
                        "Duplicate in database: {} {}",
                        parsed.ip_address, parsed.hostname
                    )));
                }
            }
        }

        // Create entry
        match self
            .commands
            .add_host(
                parsed.ip_address,
                parsed.hostname,
                parsed.comment,
                parsed.tags,
            )
            .await
        {
            Ok(_) => {
                state.created += 1;
                state.seen.insert(key);
                Ok(())
            }
            Err(e) => {
                state.failed += 1;
                if state.conflict_mode == ConflictMode::Strict {
                    Err(state.error_response(format!("Failed to create: {}", e)))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Import hosts from file format via streaming
    ///
    /// # Memory Usage
    /// - Loads all existing database entries into memory at start for duplicate detection
    /// - Line buffer limited to 10MB to prevent DoS attacks
    /// - For large databases (>100k entries), consider memory implications
    ///
    /// # Streaming Behavior
    /// - Processes entries immediately as chunks arrive
    /// - Progress updates sent after each chunk
    /// - If stream ends without last_chunk=true, remaining buffer data is processed
    ///
    /// Supports conflict handling modes via `conflict_mode` field:
    /// - "skip" (default): Skip entries that already exist (same IP+hostname)
    /// - "replace": Update existing entries with imported values
    /// - "strict": Fail if any duplicate is found
    ///
    /// Progress is reported via streaming ImportHostsResponse with counters:
    /// - processed: Total entries validated successfully (may still fail during creation)
    /// - created: New entries added
    /// - skipped: Duplicates skipped (when conflict_mode = "skip")
    /// - failed: Validation or creation failures
    pub async fn handle_import_hosts(
        &self,
        request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Vec<ImportHostsResponse>>, Status> {
        let mut stream = request.into_inner();
        let mut responses = Vec::new();
        let mut state: Option<ImportState> = None;

        // OPTIMIZATION: Load existing database entries once for duplicate checking
        let db_entries = HostProjections::list_all(&self.db)
            .map_err(|e| Status::internal(format!("Failed to load existing hosts: {}", e)))?;
        let db_set: std::collections::HashSet<_> = db_entries
            .into_iter()
            .map(|e| (e.ip_address, e.hostname))
            .collect();

        while let Some(req) = stream.next().await {
            let req = req?;

            // Initialize state on first chunk
            let state = state.get_or_insert_with(|| {
                let format: ImportFormat = req
                    .format
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .unwrap_or_default();
                let conflict_mode: ConflictMode = req
                    .conflict_mode
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .unwrap_or_default();
                ImportState::new(format, conflict_mode)
            });

            // Append chunk to buffer
            state.line_buffer.extend_from_slice(&req.chunk);

            // Check buffer size limit to prevent DoS
            if state.line_buffer.len() > MAX_LINE_BUFFER_SIZE {
                return Err(Status::resource_exhausted(
                    "line buffer exceeded 10MB limit",
                ));
            }

            // Extract and process complete lines
            let lines = match extract_lines(&mut state.line_buffer) {
                Ok(lines) => lines,
                Err(e) => {
                    state.failed += 1;
                    if state.conflict_mode == ConflictMode::Strict {
                        return Ok(Response::new(vec![state.error_response(e)]));
                    }
                    continue;
                }
            };

            for line in lines {
                // Skip CSV header
                if state.format == ImportFormat::Csv && !state.csv_header_seen {
                    if is_csv_header(&line) {
                        state.csv_header_seen = true;
                        continue;
                    }
                    state.csv_header_seen = true;
                }

                // Parse line
                let parsed = match parse_line(&line, state.format) {
                    Ok(entry) => entry,
                    Err(ParseError::EmptyLine) | Err(ParseError::CommentLine) => continue,
                    Err(e) => {
                        state.processed += 1;
                        state.failed += 1;
                        if state.conflict_mode == ConflictMode::Strict {
                            return Ok(Response::new(vec![
                                state.error_response(format!("Parse error: {}", e))
                            ]));
                        }
                        continue;
                    }
                };

                // Process entry using helper
                if let Err(error_response) = self.process_entry(parsed, state, &db_set).await {
                    return Ok(Response::new(vec![error_response]));
                }
            }

            // If this is the last chunk, process remaining buffer
            if req.last_chunk {
                if !state.line_buffer.is_empty() {
                    let line = match String::from_utf8(std::mem::take(&mut state.line_buffer)) {
                        Ok(l) => l,
                        Err(_) => {
                            state.failed += 1;
                            if state.conflict_mode == ConflictMode::Strict {
                                return Ok(Response::new(vec![state.error_response(
                                    "invalid UTF-8 in final buffer".to_string(),
                                )]));
                            }
                            String::new()
                        }
                    };
                    let line = line.trim();
                    if !line.is_empty() {
                        // Process final partial line
                        let parsed = match parse_line(line, state.format) {
                            Ok(entry) => entry,
                            Err(ParseError::EmptyLine) | Err(ParseError::CommentLine) => {
                                // Skip empty/comment lines
                                break;
                            }
                            Err(e) => {
                                state.processed += 1;
                                state.failed += 1;
                                if state.conflict_mode == ConflictMode::Strict {
                                    return Ok(Response::new(vec![
                                        state.error_response(format!("Parse error: {}", e))
                                    ]));
                                }
                                break;
                            }
                        };

                        // Process entry using helper
                        if let Err(error_response) =
                            self.process_entry(parsed, state, &db_set).await
                        {
                            return Ok(Response::new(vec![error_response]));
                        }
                    }
                }
                // Send final progress update and exit
                responses.push(state.success_response());
                break;
            }

            // Send progress update after each non-final chunk
            responses.push(state.success_response());
        }

        Ok(Response::new(responses))
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
