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
    let comment = if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    };
    (comment, vec![])
}

/// Parse a JSON line (JSONL format)
pub fn parse_json_line(line: &str) -> Result<ParsedEntry, ParseError> {
    let line = line.trim();

    if line.is_empty() {
        return Err(ParseError::EmptyLine);
    }

    #[derive(serde::Deserialize)]
    struct JsonEntry {
        ip_address: String,
        hostname: String,
        comment: Option<String>,
        #[serde(default)]
        tags: Vec<String>,
    }

    let parsed: JsonEntry =
        serde_json::from_str(line).map_err(|e| ParseError::InvalidFormat(e.to_string()))?;

    Ok(ParsedEntry {
        ip_address: parsed.ip_address,
        hostname: parsed.hostname,
        comment: parsed.comment,
        tags: parsed.tags,
    })
}

/// Parse a CSV line (after header)
pub fn parse_csv_line(line: &str) -> Result<ParsedEntry, ParseError> {
    let line = line.trim();

    if line.is_empty() {
        return Err(ParseError::EmptyLine);
    }

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(line.as_bytes());

    let record = reader
        .records()
        .next()
        .ok_or_else(|| ParseError::InvalidFormat("no CSV record found".to_string()))?
        .map_err(|e| ParseError::InvalidFormat(e.to_string()))?;

    if record.len() < 2 {
        return Err(ParseError::InvalidFormat(
            "expected at least ip_address,hostname".to_string(),
        ));
    }

    let ip_address = record.get(0).unwrap_or("").to_string();
    let hostname = record.get(1).unwrap_or("").to_string();
    let comment = record
        .get(2)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let tags: Vec<String> = record
        .get(3)
        .map(|s| {
            s.split(';')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();

    Ok(ParsedEntry {
        ip_address,
        hostname,
        comment,
        tags,
    })
}

/// Check if line is CSV header
pub fn is_csv_header(line: &str) -> bool {
    let line = line.trim().to_lowercase();
    line.starts_with("ip_address,") || line == "ip_address,hostname,comment,tags"
}

/// Extract complete lines from buffer, returning lines and remaining partial data
///
/// Returns an error message if UTF-8 decoding fails, otherwise returns the list of lines.
pub fn extract_lines(buffer: &mut Vec<u8>) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();

    // Find last newline position
    if let Some(last_newline) = buffer.iter().rposition(|&b| b == b'\n') {
        // Extract everything up to and including last newline
        let complete: Vec<u8> = buffer.drain(..=last_newline).collect();

        // Parse as string and split into lines
        let text =
            String::from_utf8(complete).map_err(|_| "invalid UTF-8 in input data".to_string())?;
        for line in text.lines() {
            lines.push(line.to_string());
        }
    }

    Ok(lines)
}

/// Parse a line based on format
pub fn parse_line(line: &str, format: ImportFormat) -> Result<ParsedEntry, ParseError> {
    match format {
        ImportFormat::Hosts => parse_hosts_line(line),
        ImportFormat::Json => parse_json_line(line),
        ImportFormat::Csv => parse_csv_line(line),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_format_parsing() {
        assert_eq!(
            "hosts".parse::<ImportFormat>().unwrap(),
            ImportFormat::Hosts
        );
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
        assert_eq!(
            "replace".parse::<ConflictMode>().unwrap(),
            ConflictMode::Replace
        );
        assert_eq!(
            "strict".parse::<ConflictMode>().unwrap(),
            ConflictMode::Strict
        );
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
        assert_eq!(
            parse_hosts_line("# This is a comment").unwrap_err(),
            ParseError::CommentLine
        );
    }

    #[test]
    fn test_parse_hosts_line_missing_hostname() {
        let err = parse_hosts_line("192.168.1.10").unwrap_err();
        assert!(matches!(err, ParseError::InvalidFormat(_)));
    }

    #[test]
    fn test_parse_json_line() {
        let entry =
            parse_json_line(r#"{"ip_address":"192.168.1.10","hostname":"server.local"}"#).unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, None);
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_parse_json_line_full() {
        let entry = parse_json_line(r#"{"ip_address":"192.168.1.10","hostname":"server.local","comment":"Test","tags":["a","b"]}"#).unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, Some("Test".to_string()));
        assert_eq!(entry.tags, vec!["a", "b"]);
    }

    #[test]
    fn test_parse_json_line_invalid() {
        assert!(parse_json_line("not json").is_err());
        assert!(parse_json_line(r#"{"hostname":"only"}"#).is_err());
    }

    #[test]
    fn test_parse_csv_line() {
        let entry = parse_csv_line("192.168.1.10,server.local,,").unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, None);
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_parse_csv_line_with_tags() {
        let entry = parse_csv_line("192.168.1.10,server.local,comment,tag1;tag2").unwrap();
        assert_eq!(entry.ip_address, "192.168.1.10");
        assert_eq!(entry.hostname, "server.local");
        assert_eq!(entry.comment, Some("comment".to_string()));
        assert_eq!(entry.tags, vec!["tag1", "tag2"]);
    }

    #[test]
    fn test_parse_csv_line_quoted() {
        let entry = parse_csv_line(r#"192.168.1.10,server.local,"hello, world",tag1"#).unwrap();
        assert_eq!(entry.comment, Some("hello, world".to_string()));
    }

    #[test]
    fn test_is_csv_header() {
        assert!(is_csv_header("ip_address,hostname,comment,tags"));
        assert!(is_csv_header("IP_ADDRESS,HOSTNAME"));
        assert!(is_csv_header("ip_address,hostname"));
        assert!(!is_csv_header("192.168.1.10,server.local"));
        assert!(!is_csv_header("ip,hostname.local")); // Should not match "ip," prefix
    }

    #[test]
    fn test_extract_lines_complete() {
        let mut buffer = b"line1\nline2\nline3\n".to_vec();
        let lines = extract_lines(&mut buffer).unwrap();
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_extract_lines_partial() {
        let mut buffer = b"line1\nline2\npartial".to_vec();
        let lines = extract_lines(&mut buffer).unwrap();
        assert_eq!(lines, vec!["line1", "line2"]);
        assert_eq!(buffer, b"partial");
    }

    #[test]
    fn test_extract_lines_no_newline() {
        let mut buffer = b"partial data".to_vec();
        let lines = extract_lines(&mut buffer).unwrap();
        assert!(lines.is_empty());
        assert_eq!(buffer, b"partial data");
    }

    #[test]
    fn test_extract_lines_invalid_utf8() {
        let mut buffer = b"line1\n\xFF\xFE invalid\n".to_vec();
        let result = extract_lines(&mut buffer);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "invalid UTF-8 in input data");
    }

    #[test]
    fn test_parse_line_dispatch() {
        let hosts_entry = parse_line("192.168.1.1 host.local", ImportFormat::Hosts).unwrap();
        assert_eq!(hosts_entry.hostname, "host.local");

        let json_entry = parse_line(
            r#"{"ip_address":"192.168.1.1","hostname":"host.local"}"#,
            ImportFormat::Json,
        )
        .unwrap();
        assert_eq!(json_entry.hostname, "host.local");

        let csv_entry = parse_line("192.168.1.1,host.local,,", ImportFormat::Csv).unwrap();
        assert_eq!(csv_entry.hostname, "host.local");
    }
}
