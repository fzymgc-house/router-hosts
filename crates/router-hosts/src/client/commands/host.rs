use anyhow::{bail, Context, Result};
use router_hosts_common::proto::{
    AddHostRequest, DeleteHostRequest, ExportHostsRequest, GetHostRequest, ImportHostsRequest,
    ListHostsRequest, SearchHostsRequest, UpdateHostRequest,
};
use std::io::{self, Write};
use std::path::Path;

use crate::client::{
    grpc::Client,
    output::{print_item, print_items},
    HostCommand, OutputFormat,
};

const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

pub async fn handle(
    client: &mut Client,
    command: HostCommand,
    format: OutputFormat,
    quiet: bool,
) -> Result<()> {
    match command {
        HostCommand::Add {
            ip,
            hostname,
            comment,
            tags,
        } => {
            let request = AddHostRequest {
                ip_address: ip,
                hostname,
                comment,
                tags,
            };
            let response = client.add_host(request).await?;
            if !quiet {
                if let Some(entry) = response.entry {
                    print_item(&entry, format);
                }
            }
        }

        HostCommand::Get { id } => {
            let request = GetHostRequest { id };
            let response = client.get_host(request).await?;
            if let Some(entry) = response.entry {
                print_item(&entry, format);
            }
        }

        HostCommand::Update {
            id,
            ip,
            hostname,
            comment,
            tags,
            version,
        } => {
            let request = UpdateHostRequest {
                id,
                ip_address: ip,
                hostname,
                comment,
                tags: tags.unwrap_or_default(),
                expected_version: version,
            };
            let response = client.update_host(request).await?;
            if !quiet {
                if let Some(entry) = response.entry {
                    print_item(&entry, format);
                }
            }
        }

        HostCommand::Delete { id } => {
            let request = DeleteHostRequest { id };
            let response = client.delete_host(request).await?;
            if !quiet && response.success {
                eprintln!("Deleted successfully");
            }
        }

        HostCommand::List {
            filter,
            limit,
            offset,
        } => {
            let request = ListHostsRequest {
                filter,
                limit,
                offset,
            };
            let responses = client.list_hosts(request).await?;
            let entries: Vec<_> = responses.into_iter().filter_map(|r| r.entry).collect();
            print_items(&entries, format);
        }

        HostCommand::Search { query } => {
            let request = SearchHostsRequest { query };
            let responses = client.search_hosts(request).await?;
            let entries: Vec<_> = responses.into_iter().filter_map(|r| r.entry).collect();
            print_items(&entries, format);
        }

        HostCommand::Export {
            format: export_format,
        } => {
            let request = ExportHostsRequest {
                format: export_format,
            };
            let data = client.export_hosts(request).await?;
            io::stdout().write_all(&data)?;
        }

        HostCommand::Import {
            file,
            format: import_format,
            conflict_mode,
        } => {
            let chunks = read_file_chunks(&file, &import_format, &conflict_mode)?;

            let final_response = client
                .import_hosts(chunks, |progress| {
                    if !quiet {
                        eprint!(
                            "\rProcessed: {}, Created: {}, Updated: {}, Skipped: {}, Failed: {}",
                            progress.processed,
                            progress.created,
                            progress.updated,
                            progress.skipped,
                            progress.failed
                        );
                    }
                })
                .await?;

            if !quiet {
                eprintln!(); // New line after progress
                eprintln!(
                    "Import complete: {} processed, {} created, {} updated, {} skipped, {} failed",
                    final_response.processed,
                    final_response.created,
                    final_response.updated,
                    final_response.skipped,
                    final_response.failed
                );

                for error in &final_response.validation_errors {
                    eprintln!("  {}", error);
                }
            }
        }
    }
    Ok(())
}

/// Read a file and split it into chunks for streaming import.
///
/// # Security Notes
/// - Symlinks are followed during path canonicalization. This is intentional
///   for CLI usability, allowing users to import from symlinked files.
/// - Directory traversal is prevented by verifying the resolved path is a regular file.
fn read_file_chunks(
    path: &Path,
    format: &str,
    conflict_mode: &str,
) -> Result<Vec<ImportHostsRequest>> {
    // Validate and canonicalize the path (note: this follows symlinks)
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("Cannot resolve path: {}", path.display()))?;

    // Ensure it's a regular file (not a directory, symlink, or special file)
    let metadata = std::fs::metadata(&canonical_path)
        .with_context(|| format!("Cannot read file metadata: {}", canonical_path.display()))?;

    if !metadata.is_file() {
        bail!("Not a regular file: {}", canonical_path.display());
    }

    let data = std::fs::read(&canonical_path)
        .with_context(|| format!("Failed to read file: {}", canonical_path.display()))?;

    if data.is_empty() {
        bail!("Import file is empty: {}", canonical_path.display());
    }

    let mut chunks = Vec::new();
    let total_chunks = data.len().div_ceil(CHUNK_SIZE);

    for (i, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
        let is_last = i == total_chunks - 1;
        chunks.push(ImportHostsRequest {
            chunk: chunk_data.to_vec(),
            last_chunk: is_last,
            format: if i == 0 {
                Some(format.to_string())
            } else {
                None
            },
            conflict_mode: if i == 0 {
                Some(conflict_mode.to_string())
            } else {
                None
            },
        });
    }

    Ok(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_file_chunks_valid_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "192.168.1.1 test.local").unwrap();

        let chunks = read_file_chunks(file.path(), "hosts", "skip").unwrap();

        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].last_chunk);
        assert_eq!(chunks[0].format, Some("hosts".to_string()));
        assert_eq!(chunks[0].conflict_mode, Some("skip".to_string()));
    }

    #[test]
    fn test_read_file_chunks_nonexistent_file() {
        let result = read_file_chunks(Path::new("/nonexistent/file.txt"), "hosts", "skip");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Cannot resolve path"));
    }

    #[test]
    fn test_read_file_chunks_directory() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_file_chunks(dir.path(), "hosts", "skip");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Not a regular file"));
    }

    #[test]
    fn test_read_file_chunks_large_file() {
        let mut file = NamedTempFile::new().unwrap();
        // Write more than CHUNK_SIZE bytes (64KB + 1)
        let data = "x".repeat(CHUNK_SIZE + 1);
        write!(file, "{}", data).unwrap();

        let chunks = read_file_chunks(file.path(), "json", "replace").unwrap();

        assert_eq!(chunks.len(), 2);
        assert!(!chunks[0].last_chunk);
        assert!(chunks[1].last_chunk);
        // Only first chunk has format and conflict_mode
        assert!(chunks[0].format.is_some());
        assert!(chunks[1].format.is_none());
    }

    #[test]
    fn test_read_file_chunks_empty_file() {
        let file = NamedTempFile::new().unwrap();
        // File is empty

        let result = read_file_chunks(file.path(), "csv", "strict");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Import file is empty"));
    }
}
