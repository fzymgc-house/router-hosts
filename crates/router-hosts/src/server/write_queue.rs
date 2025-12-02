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
