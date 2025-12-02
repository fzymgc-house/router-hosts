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

/// Parse error for import lines
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    EmptyLine,
    CommentLine,
    InvalidFormat(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLine => write!(f, "empty line"),
            Self::CommentLine => write!(f, "comment line"),
            Self::InvalidFormat(msg) => write!(f, "invalid format: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

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

/// Parse a hosts file line
/// Format: IP HOSTNAME [# COMMENT [tags]]
pub fn parse_hosts_line(line: &str) -> Result<ParsedEntry, ParseError> {
    let line = line.trim();

    if line.is_empty() {
        return Err(ParseError::EmptyLine);
    }

    if line.starts_with('#') {
        return Err(ParseError::CommentLine);
    }

    // Split on # to separate entry from comment
    let (entry_part, comment_part) = match line.split_once('#') {
        Some((entry, comment)) => (entry.trim(), Some(comment.trim())),
        None => (line, None),
    };

    // Parse IP and hostname from entry part
    let mut parts = entry_part.split_whitespace();
    let ip_address = parts
        .next()
        .ok_or_else(|| ParseError::InvalidFormat("missing IP address".to_string()))?
        .to_string();
    let hostname = parts
        .next()
        .ok_or_else(|| ParseError::InvalidFormat("missing hostname".to_string()))?
        .to_string();

    // Parse comment and tags
    let (comment, tags) = if let Some(comment_str) = comment_part {
        parse_comment_and_tags(comment_str)
    } else {
        (None, vec![])
    };

    Ok(ParsedEntry {
        ip_address,
        hostname,
        comment,
        tags,
    })
}

/// Parse comment and tags from comment string
/// Tags are in format [tag1, tag2] at end
fn parse_comment_and_tags(s: &str) -> (Option<String>, Vec<String>) {
    let s = s.trim();

    if let Some(bracket_start) = s.rfind('[') {
        if let Some(bracket_end) = s.rfind(']') {
            if bracket_end > bracket_start {
                let tags_str = &s[bracket_start + 1..bracket_end];
                let tags: Vec<String> = tags_str
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();

                let comment = s[..bracket_start].trim();
                let comment = if comment.is_empty() {
                    None
                } else {
                    Some(comment.to_string())
                };

                return (comment, tags);
            }
        }
    }

    // No tags found
    let comment = if s.is_empty() { None } else { Some(s.to_string()) };
    (comment, vec![])
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

    #[test]
    fn test_parse_hosts_line_simple() {
        let entry = parse_hosts_line("192.168.1.10\tserver.local").unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, None);
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_parse_hosts_line_with_comment() {
        let entry = parse_hosts_line("192.168.1.10 server.local # My server").unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, Some("My server".to_string()));
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_parse_hosts_line_with_tags() {
        let entry = parse_hosts_line("192.168.1.10 server.local # [homelab, prod]").unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, None);
        assert_eq!(entry.tags, vec!["homelab", "prod"]);
    }

    #[test]
    fn test_parse_hosts_line_with_comment_and_tags() {
        let entry = parse_hosts_line("192.168.1.10 server.local # Web server [prod]").unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, Some("Web server".to_string()));
        assert_eq!(entry.tags, vec!["prod"]);
    }

    #[test]
    fn test_parse_hosts_line_empty() {
        assert_eq!(parse_hosts_line("").unwrap_err(), ParseError::EmptyLine);
        assert_eq!(parse_hosts_line("   ").unwrap_err(), ParseError::EmptyLine);
    }

    #[test]
    fn test_parse_hosts_line_comment() {
        assert_eq!(parse_hosts_line("# This is a comment").unwrap_err(), ParseError::CommentLine);
    }

    #[test]
    fn test_parse_hosts_line_missing_hostname() {
        let err = parse_hosts_line("192.168.1.10").unwrap_err();
        assert!(matches!(err, ParseError::InvalidFormat(_)));
    }
}
