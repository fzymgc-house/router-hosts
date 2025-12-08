//! Write serialization queue for mutation operations
//!
//! All write operations are serialized through a channel queue to prevent
//! race conditions in duplicate detection and hosts file regeneration.
//!
//! ## Queue Capacity
//!
//! The queue uses a bounded channel with capacity of 100 commands. This capacity
//! was chosen to:
//! - Handle typical burst patterns (multiple rapid client requests)
//! - Limit memory usage on resource-constrained routers
//! - Provide backpressure when operations are slow
//!
//! When the queue is full, new operations will wait (not fail immediately).
//! If the queue is closed (server shutdown), operations return an error.
//!
//! ## Timeout Handling
//!
//! Each operation has a configurable timeout (default 30s) to prevent indefinite
//! hangs. If an operation times out, it returns an error but the worker continues
//! processing other commands.

use crate::server::db::HostEntry;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use ulid::Ulid;

/// Default timeout for write operations (30 seconds per CLAUDE.md)
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of an import operation
///
/// Counter fields use `i32` for protobuf compatibility - the gRPC proto uses int32
/// for these counters in ImportHostsResponse, and protobuf int32 maps to Rust i32.
///
/// # Overflow Safety
///
/// Counters are incremented using `saturating_add(1)` which caps at `i32::MAX` rather
/// than panicking. This is safe because:
/// - MAX_IMPORT_SIZE is 10 MiB (10,485,760 bytes)
/// - Minimum viable entry is ~10 bytes (e.g., "1.1.1.1 a\n")
/// - Maximum possible entries: ~1 million
/// - i32::MAX is ~2.1 billion, providing a 2000x safety margin
///
/// The DoS limits structurally prevent overflow from ever occurring.
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// Total entries parsed from input data
    pub processed: i32,
    /// New entries successfully created
    pub created: i32,
    /// Existing entries updated (replace mode only)
    pub updated: i32,
    /// Entries skipped due to existing duplicates (skip mode)
    pub skipped: i32,
    /// Entries that failed validation (invalid IP/hostname)
    pub failed: i32,
    /// Details of validation failures (line number and reason)
    pub validation_errors: Vec<String>,
}

/// Conflict handling mode for imports
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub enum ConflictMode {
    /// Skip entries that already exist (default)
    #[default]
    Skip,
    /// Update existing entries with imported values
    Replace,
    /// Fail entire import on first duplicate
    Strict,
}

impl std::str::FromStr for ConflictMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "skip" | "" => Ok(Self::Skip),
            "replace" => Ok(Self::Replace),
            "strict" => Ok(Self::Strict),
            other => Err(format!("Invalid conflict mode: '{}'", other)),
        }
    }
}

/// A parsed entry from import data
#[derive(Debug, Clone)]
pub struct ParsedEntry {
    pub ip_address: String,
    pub hostname: String,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub line_number: usize,
}

/// Commands that can be sent to the write worker
pub enum WriteCommand {
    AddHost {
        ip_address: String,
        hostname: String,
        comment: Option<String>,
        tags: Vec<String>,
        reply: oneshot::Sender<Result<HostEntry, crate::server::commands::CommandError>>,
    },
    UpdateHost {
        id: Ulid,
        ip_address: Option<String>,
        hostname: Option<String>,
        comment: Option<Option<String>>,
        tags: Option<Vec<String>>,
        expected_version: Option<String>,
        reply: oneshot::Sender<Result<HostEntry, crate::server::commands::CommandError>>,
    },
    DeleteHost {
        id: Ulid,
        reason: Option<String>,
        reply: oneshot::Sender<Result<(), crate::server::commands::CommandError>>,
    },
    ImportHosts {
        entries: Vec<ParsedEntry>,
        conflict_mode: ConflictMode,
        reply: oneshot::Sender<Result<ImportResult, crate::server::commands::CommandError>>,
    },
}

use crate::server::commands::CommandHandler as CommandHandlerInner;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Queue capacity - number of commands that can be buffered before backpressure
///
/// This value balances:
/// - Memory usage (each command holds request data)
/// - Burst handling (typical API usage patterns)
/// - Responsiveness (avoid indefinite waits)
const QUEUE_CAPACITY: usize = 100;

/// Queue for serializing write operations
///
/// All mutation operations (add, update, delete, import) are processed
/// sequentially by a single background worker. This ensures:
/// - No race conditions in duplicate detection
/// - Consistent event ordering in the event store
/// - Single hosts file regeneration per operation
///
/// Read operations bypass this queue and access the database directly.
#[derive(Clone)]
pub struct WriteQueue {
    tx: mpsc::Sender<WriteCommand>,
}

impl WriteQueue {
    /// Create a new write queue and spawn the worker task
    ///
    /// The worker runs until the queue is dropped (all senders closed).
    /// Operations have a default timeout of 30 seconds.
    pub fn new(handler: Arc<CommandHandlerInner>) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        tokio::spawn(write_worker(rx, handler));
        info!(capacity = QUEUE_CAPACITY, "Write queue initialized");
        Self { tx }
    }

    /// Send an add host command and wait for result
    ///
    /// Returns error if:
    /// - Queue is closed (server shutting down)
    /// - Operation times out (30s default)
    /// - Underlying command fails (validation, duplicate, etc.)
    pub async fn add_host(
        &self,
        ip_address: String,
        hostname: String,
        comment: Option<String>,
        tags: Vec<String>,
    ) -> Result<HostEntry, crate::server::commands::CommandError> {
        debug!(ip = %ip_address, hostname = %hostname, "Queueing add_host");
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::AddHost {
                ip_address: ip_address.clone(),
                hostname: hostname.clone(),
                comment,
                tags,
                reply: reply_tx,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to queue add_host: channel closed");
                crate::server::commands::CommandError::Internal(
                    "Write queue closed - server may be shutting down".to_string(),
                )
            })?;

        match timeout(DEFAULT_OPERATION_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                warn!(ip = %ip_address, hostname = %hostname, "add_host reply channel dropped");
                Err(crate::server::commands::CommandError::Internal(
                    "Write worker dropped reply channel unexpectedly".to_string(),
                ))
            }
            Err(_) => {
                warn!(ip = %ip_address, hostname = %hostname, timeout_secs = DEFAULT_OPERATION_TIMEOUT.as_secs(), "add_host timed out");
                Err(crate::server::commands::CommandError::Internal(format!(
                    "Operation timed out after {} seconds",
                    DEFAULT_OPERATION_TIMEOUT.as_secs()
                )))
            }
        }
    }

    /// Send an update host command and wait for result
    pub async fn update_host(
        &self,
        id: Ulid,
        ip_address: Option<String>,
        hostname: Option<String>,
        comment: Option<Option<String>>,
        tags: Option<Vec<String>>,
        expected_version: Option<String>,
    ) -> Result<HostEntry, crate::server::commands::CommandError> {
        debug!(id = %id, "Queueing update_host");
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::UpdateHost {
                id,
                ip_address,
                hostname,
                comment,
                tags,
                expected_version,
                reply: reply_tx,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to queue update_host: channel closed");
                crate::server::commands::CommandError::Internal(
                    "Write queue closed - server may be shutting down".to_string(),
                )
            })?;

        match timeout(DEFAULT_OPERATION_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                warn!(id = %id, "update_host reply channel dropped");
                Err(crate::server::commands::CommandError::Internal(
                    "Write worker dropped reply channel unexpectedly".to_string(),
                ))
            }
            Err(_) => {
                warn!(id = %id, timeout_secs = DEFAULT_OPERATION_TIMEOUT.as_secs(), "update_host timed out");
                Err(crate::server::commands::CommandError::Internal(format!(
                    "Operation timed out after {} seconds",
                    DEFAULT_OPERATION_TIMEOUT.as_secs()
                )))
            }
        }
    }

    /// Send a delete host command and wait for result
    pub async fn delete_host(
        &self,
        id: Ulid,
        reason: Option<String>,
    ) -> Result<(), crate::server::commands::CommandError> {
        debug!(id = %id, "Queueing delete_host");
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::DeleteHost {
                id,
                reason,
                reply: reply_tx,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to queue delete_host: channel closed");
                crate::server::commands::CommandError::Internal(
                    "Write queue closed - server may be shutting down".to_string(),
                )
            })?;

        match timeout(DEFAULT_OPERATION_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                warn!(id = %id, "delete_host reply channel dropped");
                Err(crate::server::commands::CommandError::Internal(
                    "Write worker dropped reply channel unexpectedly".to_string(),
                ))
            }
            Err(_) => {
                warn!(id = %id, timeout_secs = DEFAULT_OPERATION_TIMEOUT.as_secs(), "delete_host timed out");
                Err(crate::server::commands::CommandError::Internal(format!(
                    "Operation timed out after {} seconds",
                    DEFAULT_OPERATION_TIMEOUT.as_secs()
                )))
            }
        }
    }

    /// Send an import hosts command and wait for result
    ///
    /// Import operations use a longer timeout (5 minutes) to process many entries.
    ///
    /// **Note**: This is the timeout for the import operation itself, not including
    /// any time spent waiting in the queue for previous operations to complete.
    /// If the queue is processing a slow operation, total wait time will be
    /// that operation's duration plus this timeout.
    pub async fn import_hosts(
        &self,
        entries: Vec<ParsedEntry>,
        conflict_mode: ConflictMode,
    ) -> Result<ImportResult, crate::server::commands::CommandError> {
        let entry_count = entries.len();
        debug!(entry_count, conflict_mode = ?conflict_mode, "Queueing import_hosts");

        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::ImportHosts {
                entries,
                conflict_mode,
                reply: reply_tx,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to queue import_hosts: channel closed");
                crate::server::commands::CommandError::Internal(
                    "Write queue closed - server may be shutting down".to_string(),
                )
            })?;

        // Import gets a longer timeout (5 min) since it processes many entries
        let import_timeout = Duration::from_secs(300);
        match timeout(import_timeout, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                warn!(entry_count, "import_hosts reply channel dropped");
                Err(crate::server::commands::CommandError::Internal(
                    "Write worker dropped reply channel unexpectedly".to_string(),
                ))
            }
            Err(_) => {
                warn!(
                    entry_count,
                    timeout_secs = import_timeout.as_secs(),
                    "import_hosts timed out"
                );
                Err(crate::server::commands::CommandError::Internal(format!(
                    "Import operation timed out after {} seconds ({} entries)",
                    import_timeout.as_secs(),
                    entry_count
                )))
            }
        }
    }
}

/// Background worker that processes write commands sequentially
///
/// Processes commands in FIFO order. Each command is executed to completion
/// before the next one starts. This ensures consistent state for duplicate
/// detection and hosts file regeneration.
async fn write_worker(mut rx: mpsc::Receiver<WriteCommand>, handler: Arc<CommandHandlerInner>) {
    let mut commands_processed: u64 = 0;

    while let Some(cmd) = rx.recv().await {
        commands_processed += 1;
        let start = std::time::Instant::now();

        match cmd {
            WriteCommand::AddHost {
                ip_address,
                hostname,
                comment,
                tags,
                reply,
            } => {
                debug!(commands_processed, ip = %ip_address, hostname = %hostname, "Processing add_host");
                let result = handler.add_host(ip_address, hostname, comment, tags).await;
                let elapsed = start.elapsed();
                debug!(
                    elapsed_ms = elapsed.as_millis(),
                    success = result.is_ok(),
                    "add_host completed"
                );
                if reply.send(result).is_err() {
                    warn!("add_host: client disconnected before receiving reply");
                }
            }
            WriteCommand::UpdateHost {
                id,
                ip_address,
                hostname,
                comment,
                tags,
                expected_version,
                reply,
            } => {
                debug!(commands_processed, id = %id, "Processing update_host");
                let result = handler
                    .update_host(id, ip_address, hostname, comment, tags, expected_version)
                    .await;
                let elapsed = start.elapsed();
                debug!(
                    elapsed_ms = elapsed.as_millis(),
                    success = result.is_ok(),
                    "update_host completed"
                );
                if reply.send(result).is_err() {
                    warn!("update_host: client disconnected before receiving reply");
                }
            }
            WriteCommand::DeleteHost { id, reason, reply } => {
                debug!(commands_processed, id = %id, "Processing delete_host");
                let result = handler.delete_host(id, reason).await;
                let elapsed = start.elapsed();
                debug!(
                    elapsed_ms = elapsed.as_millis(),
                    success = result.is_ok(),
                    "delete_host completed"
                );
                if reply.send(result).is_err() {
                    warn!("delete_host: client disconnected before receiving reply");
                }
            }
            WriteCommand::ImportHosts {
                entries,
                conflict_mode,
                reply,
            } => {
                let entry_count = entries.len();
                debug!(commands_processed, entry_count, conflict_mode = ?conflict_mode, "Processing import_hosts");
                let result = handler.import_hosts(entries, conflict_mode).await;
                let elapsed = start.elapsed();
                debug!(
                    elapsed_ms = elapsed.as_millis(),
                    entry_count,
                    success = result.is_ok(),
                    "import_hosts completed"
                );
                if reply.send(result).is_err() {
                    warn!(
                        entry_count,
                        "import_hosts: client disconnected before receiving reply"
                    );
                }
            }
        }
    }

    info!(commands_processed, "Write worker shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::commands::CommandHandler;
    use crate::server::db::Database;
    use crate::server::hooks::HookExecutor;
    use crate::server::hosts_file::HostsFileGenerator;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn setup_write_queue() -> (WriteQueue, Arc<CommandHandler>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let hosts_path = temp_dir.path().join("hosts");

        let db = Arc::new(Database::new(&db_path).unwrap());
        let hosts_file = Arc::new(HostsFileGenerator::new(hosts_path));
        let hooks = Arc::new(HookExecutor::new(vec![], vec![], 30));

        let config = Arc::new(crate::server::config::Config {
            server: crate::server::config::ServerConfig {
                bind_address: "127.0.0.1:50051".to_string(),
                hosts_file_path: "/tmp/test_hosts".to_string(),
            },
            database: crate::server::config::DatabaseConfig {
                path: std::path::PathBuf::from("/tmp/test.db"),
            },
            tls: crate::server::config::TlsConfig {
                cert_path: std::path::PathBuf::from("/tmp/cert.pem"),
                key_path: std::path::PathBuf::from("/tmp/key.pem"),
                ca_cert_path: std::path::PathBuf::from("/tmp/ca.pem"),
            },
            retention: crate::server::config::RetentionConfig {
                max_snapshots: 50,
                max_age_days: 30,
            },
            hooks: crate::server::config::HooksConfig::default(),
        });

        let commands = Arc::new(CommandHandler::new(
            Arc::clone(&db),
            hosts_file,
            hooks,
            config,
        ));

        let write_queue = WriteQueue::new(Arc::clone(&commands));
        (write_queue, commands, temp_dir)
    }

    #[tokio::test]
    async fn test_concurrent_add_host_operations() {
        let (write_queue, commands, _temp_dir) = setup_write_queue();

        // Spawn 20 concurrent add operations with unique IPs
        let mut handles = vec![];
        for i in 0..20 {
            let wq = write_queue.clone();
            let handle = tokio::spawn(async move {
                wq.add_host(
                    format!("192.168.1.{}", i),
                    format!("host{}.local", i),
                    Some(format!("Host {}", i)),
                    vec![],
                )
                .await
            });
            handles.push(handle);
        }

        // Wait for all to complete
        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should succeed
        let successes: Vec<_> = results
            .into_iter()
            .filter_map(|r| r.ok())
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(
            successes.len(),
            20,
            "All 20 concurrent add operations should succeed"
        );

        // Verify all entries exist in database
        let hosts = commands.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 20, "Should have 20 hosts in database");

        // Verify no duplicates by checking unique IPs
        let unique_ips: std::collections::HashSet<_> =
            hosts.iter().map(|h| &h.ip_address).collect();
        assert_eq!(unique_ips.len(), 20, "All IPs should be unique");
    }

    #[tokio::test]
    async fn test_queue_serializes_duplicate_detection() {
        let (write_queue, _commands, _temp_dir) = setup_write_queue();

        // Try to add the same host twice concurrently
        let wq1 = write_queue.clone();
        let wq2 = write_queue.clone();

        let handle1 = tokio::spawn(async move {
            wq1.add_host(
                "192.168.1.1".to_string(),
                "same.local".to_string(),
                None,
                vec![],
            )
            .await
        });

        let handle2 = tokio::spawn(async move {
            wq2.add_host(
                "192.168.1.1".to_string(),
                "same.local".to_string(),
                None,
                vec![],
            )
            .await
        });

        let (result1, result2) = tokio::join!(handle1, handle2);
        let result1 = result1.unwrap();
        let result2 = result2.unwrap();

        // Exactly one should succeed, one should fail with DuplicateEntry
        let successes = [&result1, &result2].iter().filter(|r| r.is_ok()).count();
        let duplicates = [&result1, &result2]
            .iter()
            .filter(|r| {
                matches!(
                    r,
                    Err(crate::server::commands::CommandError::DuplicateEntry(_))
                )
            })
            .count();

        assert_eq!(successes, 1, "Exactly one add should succeed");
        assert_eq!(duplicates, 1, "Exactly one should fail with DuplicateEntry");
    }

    #[tokio::test]
    async fn test_concurrent_import_operations() {
        let (write_queue, commands, _temp_dir) = setup_write_queue();

        // Create two sets of entries for concurrent import
        let entries1: Vec<ParsedEntry> = (0..10)
            .map(|i| ParsedEntry {
                ip_address: format!("10.0.0.{}", i),
                hostname: format!("batch1-host{}.local", i),
                comment: Some(format!("Batch 1 host {}", i)),
                tags: vec!["batch1".to_string()],
                line_number: i + 1,
            })
            .collect();

        let entries2: Vec<ParsedEntry> = (0..10)
            .map(|i| ParsedEntry {
                ip_address: format!("10.0.1.{}", i),
                hostname: format!("batch2-host{}.local", i),
                comment: Some(format!("Batch 2 host {}", i)),
                tags: vec!["batch2".to_string()],
                line_number: i + 1,
            })
            .collect();

        // Spawn concurrent imports
        let wq1 = write_queue.clone();
        let wq2 = write_queue.clone();

        let handle1 =
            tokio::spawn(async move { wq1.import_hosts(entries1, ConflictMode::Skip).await });

        let handle2 =
            tokio::spawn(async move { wq2.import_hosts(entries2, ConflictMode::Skip).await });

        // Both should succeed
        let (result1, result2) = tokio::join!(handle1, handle2);
        let import1 = result1.unwrap().unwrap();
        let import2 = result2.unwrap().unwrap();

        // Both imports should complete successfully
        assert_eq!(import1.processed, 10, "Import 1 should process 10 entries");
        assert_eq!(import1.created, 10, "Import 1 should create 10 entries");
        assert_eq!(import2.processed, 10, "Import 2 should process 10 entries");
        assert_eq!(import2.created, 10, "Import 2 should create 10 entries");

        // Verify all 20 entries exist
        let hosts = commands.list_hosts().await.unwrap();
        assert_eq!(
            hosts.len(),
            20,
            "Should have 20 hosts total from both imports"
        );

        // Verify entries from both batches exist
        let batch1_count = hosts
            .iter()
            .filter(|h| h.tags.contains(&"batch1".to_string()))
            .count();
        let batch2_count = hosts
            .iter()
            .filter(|h| h.tags.contains(&"batch2".to_string()))
            .count();
        assert_eq!(batch1_count, 10, "Should have 10 hosts from batch 1");
        assert_eq!(batch2_count, 10, "Should have 10 hosts from batch 2");
    }

    #[tokio::test]
    async fn test_concurrent_imports_with_overlapping_entries() {
        let (write_queue, commands, _temp_dir) = setup_write_queue();

        // Create entries with some overlap
        let entries1: Vec<ParsedEntry> = (0..5)
            .map(|i| ParsedEntry {
                ip_address: format!("10.0.0.{}", i),
                hostname: format!("shared-host{}.local", i),
                comment: Some("From batch 1".to_string()),
                tags: vec!["batch1".to_string()],
                line_number: i + 1,
            })
            .collect();

        let entries2: Vec<ParsedEntry> = (0..5)
            .map(|i| ParsedEntry {
                ip_address: format!("10.0.0.{}", i), // Same IPs/hostnames as batch 1
                hostname: format!("shared-host{}.local", i),
                comment: Some("From batch 2".to_string()),
                tags: vec!["batch2".to_string()],
                line_number: i + 1,
            })
            .collect();

        let wq1 = write_queue.clone();
        let wq2 = write_queue.clone();

        let handle1 =
            tokio::spawn(async move { wq1.import_hosts(entries1, ConflictMode::Skip).await });

        let handle2 =
            tokio::spawn(async move { wq2.import_hosts(entries2, ConflictMode::Skip).await });

        let (result1, result2) = tokio::join!(handle1, handle2);
        let import1 = result1.unwrap().unwrap();
        let import2 = result2.unwrap().unwrap();

        // One import creates all, the other skips all (serialized)
        let total_created = import1.created + import2.created;
        let total_skipped = import1.skipped + import2.skipped;

        assert_eq!(total_created, 5, "Exactly 5 entries should be created");
        assert_eq!(total_skipped, 5, "Exactly 5 entries should be skipped");

        // Verify only 5 unique hosts exist
        let hosts = commands.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 5, "Should have exactly 5 unique hosts");
    }

    /// Tests queue behavior with 150 concurrent operations (exceeds queue capacity of 100).
    /// Verifies that:
    /// 1. All operations eventually complete (backpressure works correctly)
    /// 2. Data integrity is maintained (no duplicates, correct count)
    /// 3. No deadlocks or timeouts occur
    #[tokio::test]
    async fn test_backpressure_with_high_concurrency() {
        let (write_queue, commands, _tempdir) = setup_write_queue();

        // Spawn 150 concurrent add_host operations (exceeds QUEUE_CAPACITY of 100)
        let mut handles = Vec::with_capacity(150);

        for i in 0..150 {
            let wq = write_queue.clone();
            let handle = tokio::spawn(async move {
                wq.add_host(
                    format!("192.168.{}.{}", i / 256, i % 256),
                    format!("host{}.local", i),
                    Some(format!("Host {}", i)),
                    vec![format!("batch{}", i / 50)],
                )
                .await
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        let mut success_count = 0;
        let mut error_count = 0;

        for handle in handles {
            match handle.await {
                Ok(Ok(_)) => success_count += 1,
                Ok(Err(e)) => {
                    error_count += 1;
                    // Log the error for debugging but don't fail
                    eprintln!("Operation failed: {:?}", e);
                }
                Err(e) => panic!("Task panicked: {:?}", e),
            }
        }

        // All 150 operations should succeed
        assert_eq!(
            success_count, 150,
            "All 150 operations should succeed, but {} failed",
            error_count
        );

        // Verify all hosts were created
        let hosts = commands.list_hosts().await.unwrap();
        assert_eq!(
            hosts.len(),
            150,
            "Should have exactly 150 hosts after all operations complete"
        );
    }

    /// Tests concurrent imports targeting the same existing host in Replace mode.
    ///
    /// This tests the scenario where two imports are queued, both trying to update
    /// the same host. Since imports are serialized through the WriteQueue:
    /// - First import succeeds and updates the host
    /// - Second import succeeds because it gets the updated version from the first
    ///
    /// This is the expected behavior because the queue serializes operations,
    /// so there's no true race condition - each import sees the result of the previous.
    #[tokio::test]
    async fn test_concurrent_imports_same_host_replace_mode() {
        let (write_queue, commands, _tempdir) = setup_write_queue();

        // Create an existing host that both imports will try to update
        write_queue
            .add_host(
                "192.168.1.1".to_string(),
                "shared.local".to_string(),
                Some("Original comment".to_string()),
                vec!["original".to_string()],
            )
            .await
            .unwrap();

        // Two imports targeting the same host with different values
        let entries1 = vec![ParsedEntry {
            ip_address: "192.168.1.1".to_string(),
            hostname: "shared.local".to_string(),
            comment: Some("Comment from import 1".to_string()),
            tags: vec!["import1".to_string()],
            line_number: 1,
        }];

        let entries2 = vec![ParsedEntry {
            ip_address: "192.168.1.1".to_string(),
            hostname: "shared.local".to_string(),
            comment: Some("Comment from import 2".to_string()),
            tags: vec!["import2".to_string()],
            line_number: 1,
        }];

        let wq1 = write_queue.clone();
        let wq2 = write_queue.clone();

        // Launch both imports concurrently
        let handle1 =
            tokio::spawn(async move { wq1.import_hosts(entries1, ConflictMode::Replace).await });
        let handle2 =
            tokio::spawn(async move { wq2.import_hosts(entries2, ConflictMode::Replace).await });

        let (result1, result2) = tokio::join!(handle1, handle2);

        // Both imports should succeed (serialized, no race)
        let import1 = result1.unwrap().unwrap();
        let import2 = result2.unwrap().unwrap();

        // Verify both processed their entries
        assert_eq!(import1.processed, 1);
        assert_eq!(import2.processed, 1);

        // One will update (first to run), one will also update (sees new version)
        // or potentially skip if the values happen to match
        let total_updated = import1.updated + import2.updated;
        assert!(
            total_updated >= 1,
            "At least one import should have updated the host"
        );

        // Verify final state - should have exactly one host
        let hosts = commands.list_hosts().await.unwrap();
        assert_eq!(hosts.len(), 1, "Should have exactly 1 host");

        // The final comment should be from one of the imports (whichever ran last)
        let host = commands.get_host(hosts[0].id).await.unwrap().unwrap();
        assert!(
            host.comment == Some("Comment from import 1".to_string())
                || host.comment == Some("Comment from import 2".to_string()),
            "Final comment should be from one of the imports, got {:?}",
            host.comment
        );
    }

    #[tokio::test]
    async fn test_write_worker_graceful_shutdown() {
        use crate::server::commands::CommandError;

        let (write_queue, _commands, _temp_dir) = setup_write_queue();

        // Clone for spawned task
        let wq = write_queue.clone();

        // Spawn an operation that will race with shutdown
        let handle = tokio::spawn(async move {
            // Small delay to ensure the drop happens while operation is queued
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            wq.add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
            )
            .await
        });

        // Drop the original write queue to trigger shutdown
        drop(write_queue);

        // The operation should either succeed (if it started before shutdown)
        // or fail with a channel closed error
        let result = handle.await.unwrap();

        // If it failed, verify it's the expected error type
        if let Err(ref e) = result {
            match e {
                CommandError::Internal(msg) => {
                    assert!(
                        msg.contains("queue closed")
                            || msg.contains("shutting down")
                            || msg.contains("channel"),
                        "Expected shutdown-related error, got: {}",
                        msg
                    );
                }
                other => {
                    // Operation might have succeeded before shutdown, that's OK
                    panic!("Unexpected error type: {:?}", other);
                }
            }
        }
        // If it succeeded, that's also valid - the operation completed before shutdown
    }
}
