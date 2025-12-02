//! Import format helpers for ImportHosts RPC

use std::collections::HashSet;

/// Supported import formats
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ImportFormat {
    #[default]
    Hosts,
    Json,
    Csv,
}

/// Error type for invalid import format strings
#[derive(Debug, Clone, PartialEq)]
pub struct InvalidImportFormat;

impl std::fmt::Display for InvalidImportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid import format")
    }
}

impl std::error::Error for InvalidImportFormat {}

impl std::str::FromStr for ImportFormat {
    type Err = InvalidImportFormat;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hosts" | "" => Ok(Self::Hosts),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            _ => Err(InvalidImportFormat),
        }
    }
}

/// Conflict handling modes
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ConflictMode {
    #[default]
    Skip,
    Replace,
    Strict,
}

/// Error type for invalid conflict mode strings
#[derive(Debug, Clone, PartialEq)]
pub struct InvalidConflictMode;

impl std::fmt::Display for InvalidConflictMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid conflict mode")
    }
}

impl std::error::Error for InvalidConflictMode {}

impl std::str::FromStr for ConflictMode {
    type Err = InvalidConflictMode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "skip" | "" => Ok(Self::Skip),
            "replace" => Ok(Self::Replace),
            "strict" => Ok(Self::Strict),
            _ => Err(InvalidConflictMode),
        }
    }
}

/// A parsed entry from import data
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedEntry {
    pub ip_address: String,
    pub hostname: String,
    pub comment: Option<String>,
    pub tags: Vec<String>,
}

/// Import state tracking for bidirectional streaming
///
/// Maintains stateful context across multiple streaming chunks during
/// import operations, including format detection, deduplication, and
/// progress counters.
pub struct ImportState {
    /// Partial line data accumulated across chunk boundaries
    pub line_buffer: Vec<u8>,
    /// Deduplicate entries within a single import stream (ip, hostname) pairs
    pub seen: HashSet<(String, String)>,
    /// Import format being processed
    pub format: ImportFormat,
    /// How to handle duplicate entries
    pub conflict_mode: ConflictMode,
    /// Total entries processed (successful + failed)
    pub processed: i32,
    /// Entries successfully created in database
    pub created: i32,
    /// Entries skipped due to conflicts (conflict_mode=Skip)
    pub skipped: i32,
    /// Entries that failed validation or database insertion
    pub failed: i32,
    /// CSV header row has been seen and validated
    pub csv_header_seen: bool,
}

impl ImportState {
    pub fn new(format: ImportFormat, conflict_mode: ConflictMode) -> Self {
        Self {
            line_buffer: Vec::new(),
            seen: HashSet::new(),
            format,
            conflict_mode,
            processed: 0,
            created: 0,
            skipped: 0,
            failed: 0,
            csv_header_seen: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_format_parsing() {
        assert_eq!("hosts".parse::<ImportFormat>().unwrap(), ImportFormat::Hosts);
        assert_eq!("".parse::<ImportFormat>().unwrap(), ImportFormat::Hosts);
        assert_eq!("json".parse::<ImportFormat>().unwrap(), ImportFormat::Json);
        assert_eq!("JSON".parse::<ImportFormat>().unwrap(), ImportFormat::Json);
        assert_eq!("csv".parse::<ImportFormat>().unwrap(), ImportFormat::Csv);
        assert!("invalid".parse::<ImportFormat>().is_err());
    }

    #[test]
    fn test_conflict_mode_parsing() {
        assert_eq!("skip".parse::<ConflictMode>().unwrap(), ConflictMode::Skip);
        assert_eq!("".parse::<ConflictMode>().unwrap(), ConflictMode::Skip);
        assert_eq!("replace".parse::<ConflictMode>().unwrap(), ConflictMode::Replace);
        assert_eq!("strict".parse::<ConflictMode>().unwrap(), ConflictMode::Strict);
        assert!("invalid".parse::<ConflictMode>().is_err());
    }
}
