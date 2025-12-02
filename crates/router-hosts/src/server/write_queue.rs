//! Write serialization queue for mutation operations
//!
//! All write operations are serialized through a channel queue to prevent
//! race conditions in duplicate detection and hosts file regeneration.

use crate::server::db::HostEntry;
use tokio::sync::oneshot;
use ulid::Ulid;

/// Result of an import operation
#[derive(Debug, Clone)]
pub struct ImportResult {
    pub processed: i32,
    pub created: i32,
    pub updated: i32,
    pub skipped: i32,
    pub failed: i32,
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

/// Queue for serializing write operations
#[derive(Clone)]
pub struct WriteQueue {
    tx: mpsc::Sender<WriteCommand>,
}

impl WriteQueue {
    /// Create a new write queue and spawn the worker task
    pub fn new(handler: Arc<CommandHandlerInner>) -> Self {
        let (tx, rx) = mpsc::channel(100);
        tokio::spawn(write_worker(rx, handler));
        Self { tx }
    }

    /// Send an add host command and wait for result
    pub async fn add_host(
        &self,
        ip_address: String,
        hostname: String,
        comment: Option<String>,
        tags: Vec<String>,
    ) -> Result<HostEntry, crate::server::commands::CommandError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::AddHost {
                ip_address,
                hostname,
                comment,
                tags,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                crate::server::commands::CommandError::Internal("Write queue closed".to_string())
            })?;
        reply_rx.await.map_err(|_| {
            crate::server::commands::CommandError::Internal(
                "Write worker dropped reply channel".to_string(),
            )
        })?
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
            .map_err(|_| {
                crate::server::commands::CommandError::Internal("Write queue closed".to_string())
            })?;
        reply_rx.await.map_err(|_| {
            crate::server::commands::CommandError::Internal(
                "Write worker dropped reply channel".to_string(),
            )
        })?
    }

    /// Send a delete host command and wait for result
    pub async fn delete_host(
        &self,
        id: Ulid,
        reason: Option<String>,
    ) -> Result<(), crate::server::commands::CommandError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::DeleteHost {
                id,
                reason,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                crate::server::commands::CommandError::Internal("Write queue closed".to_string())
            })?;
        reply_rx.await.map_err(|_| {
            crate::server::commands::CommandError::Internal(
                "Write worker dropped reply channel".to_string(),
            )
        })?
    }

    /// Send an import hosts command and wait for result
    pub async fn import_hosts(
        &self,
        entries: Vec<ParsedEntry>,
        conflict_mode: ConflictMode,
    ) -> Result<ImportResult, crate::server::commands::CommandError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(WriteCommand::ImportHosts {
                entries,
                conflict_mode,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                crate::server::commands::CommandError::Internal("Write queue closed".to_string())
            })?;
        reply_rx.await.map_err(|_| {
            crate::server::commands::CommandError::Internal(
                "Write worker dropped reply channel".to_string(),
            )
        })?
    }
}

/// Background worker that processes write commands sequentially
async fn write_worker(mut rx: mpsc::Receiver<WriteCommand>, handler: Arc<CommandHandlerInner>) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            WriteCommand::AddHost {
                ip_address,
                hostname,
                comment,
                tags,
                reply,
            } => {
                let result = handler.add_host(ip_address, hostname, comment, tags).await;
                let _ = reply.send(result);
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
                let result = handler
                    .update_host(id, ip_address, hostname, comment, tags, expected_version)
                    .await;
                let _ = reply.send(result);
            }
            WriteCommand::DeleteHost { id, reason, reply } => {
                let result = handler.delete_host(id, reason).await;
                let _ = reply.send(result);
            }
            WriteCommand::ImportHosts {
                entries,
                conflict_mode,
                reply,
            } => {
                let result = handler.import_hosts(entries, conflict_mode).await;
                let _ = reply.send(result);
            }
        }
    }
    tracing::info!("Write worker shutting down");
}
