// crates/router-hosts/src/server/import.rs
//! Import format parsing for ImportHosts RPC

use crate::server::write_queue::ParsedEntry;
use serde::Deserialize;
use thiserror::Error;

/// Supported import formats
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ImportFormat {
    /// Standard /etc/hosts format
    #[default]
    Hosts,
    /// JSON Lines (one JSON object per line)
    Json,
    /// CSV with header row
    Csv,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InvalidImportFormat;

impl std::fmt::Display for InvalidImportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid import format")
    }
}

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

/// Error during import parsing
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Line {line}: {message}")]
    InvalidLine { line: usize, message: String },

    #[error("Invalid UTF-8 in input")]
    InvalidUtf8,

    #[error("JSON parse error on line {line}: {message}")]
    JsonError { line: usize, message: String },

    #[error("CSV parse error: {0}")]
    CsvError(String),
}

/// Parse import data in the specified format
pub fn parse_import(data: &[u8], format: ImportFormat) -> Result<Vec<ParsedEntry>, ParseError> {
    let text = std::str::from_utf8(data).map_err(|_| ParseError::InvalidUtf8)?;

    match format {
        ImportFormat::Hosts => parse_hosts_format(text),
        ImportFormat::Json => parse_json_format(text),
        ImportFormat::Csv => parse_csv_format(text),
    }
}

fn parse_hosts_format(text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    let mut entries = Vec::new();

    for (line_num, line) in text.lines().enumerate() {
        let line_number = line_num + 1;
        let line = line.trim();

        // Skip empty lines and comment-only lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split on first # to separate entry from comment
        let (entry_part, comment_part) = match line.split_once('#') {
            Some((e, c)) => (e.trim(), Some(c.trim())),
            None => (line, None),
        };

        // Split entry on whitespace: IP hostname
        let mut parts = entry_part.split_whitespace();
        let ip_address = parts.next().ok_or_else(|| ParseError::InvalidLine {
            line: line_number,
            message: "Missing IP address".to_string(),
        })?;
        let hostname = parts.next().ok_or_else(|| ParseError::InvalidLine {
            line: line_number,
            message: "Missing hostname".to_string(),
        })?;

        // Parse comment and tags from comment part
        let (comment, tags) = parse_comment_and_tags(comment_part);

        entries.push(ParsedEntry {
            ip_address: ip_address.to_string(),
            hostname: hostname.to_string(),
            aliases: vec![], // TODO: Task 9 - parse aliases from hosts format
            comment,
            tags,
            line_number,
        });
    }

    Ok(entries)
}

/// Parse comment text and extract tags in [tag1, tag2] format
fn parse_comment_and_tags(comment_part: Option<&str>) -> (Option<String>, Vec<String>) {
    let Some(text) = comment_part else {
        return (None, vec![]);
    };

    // Look for [tags] at the end
    if let Some(bracket_start) = text.rfind('[') {
        if let Some(bracket_end) = text.rfind(']') {
            if bracket_end > bracket_start {
                let tags_str = &text[bracket_start + 1..bracket_end];
                let tags: Vec<String> = tags_str
                    .split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();

                let comment_text = text[..bracket_start].trim();
                let comment = if comment_text.is_empty() {
                    None
                } else {
                    Some(comment_text.to_string())
                };

                return (comment, tags);
            }
        }
    }

    // No tags, just comment
    let trimmed = text.trim();
    if trimmed.is_empty() {
        (None, vec![])
    } else {
        (Some(trimmed.to_string()), vec![])
    }
}

/// Normalize empty string to None for consistent comparison
///
/// This ensures that `Some("")` is treated as equivalent to `None`,
/// preventing spurious update events when comparing imported entries
/// to existing entries.
fn normalize_comment(comment: Option<String>) -> Option<String> {
    comment.filter(|s| !s.is_empty())
}

/// JSON entry format for import
#[derive(Debug, Deserialize)]
struct JsonEntry {
    ip_address: String,
    hostname: String,
    comment: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

fn parse_json_format(text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    let mut entries = Vec::new();

    for (line_num, line) in text.lines().enumerate() {
        let line_number = line_num + 1;
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        let json_entry: JsonEntry =
            serde_json::from_str(line).map_err(|e| ParseError::JsonError {
                line: line_number,
                message: e.to_string(),
            })?;

        entries.push(ParsedEntry {
            ip_address: json_entry.ip_address,
            hostname: json_entry.hostname,
            aliases: vec![], // TODO: Task 9 - parse aliases from JSON format
            comment: normalize_comment(json_entry.comment),
            tags: json_entry.tags,
            line_number,
        });
    }

    Ok(entries)
}

fn parse_csv_format(text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    let mut entries = Vec::new();

    // Use csv crate for robust parsing of quoted fields, escaped quotes, etc.
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true) // Allow varying number of fields per row
        .trim(csv::Trim::All)
        .from_reader(text.as_bytes());

    for (record_idx, result) in reader.records().enumerate() {
        // Line number is record index + 2 (1 for 0-indexing, 1 for header row)
        let line_number = record_idx + 2;

        let record = result.map_err(|e| ParseError::CsvError(e.to_string()))?;

        if record.len() < 2 {
            return Err(ParseError::InvalidLine {
                line: line_number,
                message: "CSV row must have at least ip_address and hostname".to_string(),
            });
        }

        let ip_address = record.get(0).unwrap_or("").trim().to_string();
        let hostname = record.get(1).unwrap_or("").trim().to_string();

        // Skip rows where both required fields are empty (allows blank lines in CSV)
        if ip_address.is_empty() && hostname.is_empty() {
            continue;
        }

        let comment = record.get(2).and_then(|s| {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        });

        let tags = record
            .get(3)
            .map(|s| {
                s.split(';')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        entries.push(ParsedEntry {
            ip_address,
            hostname,
            aliases: vec![], // TODO: Task 9 - parse aliases from CSV format
            comment,
            tags,
            line_number,
        });
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts_simple() {
        let input = b"192.168.1.10\tserver.local\n";
        let entries = parse_import(input, ImportFormat::Hosts).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip_address, "192.168.1.10");
        assert_eq!(entries[0].hostname, "server.local");
        assert!(entries[0].comment.is_none());
        assert!(entries[0].tags.is_empty());
    }

    #[test]
    fn test_parse_hosts_with_comment() {
        let input = b"192.168.1.20\tnas.local\t# NAS storage\n";
        let entries = parse_import(input, ImportFormat::Hosts).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, Some("NAS storage".to_string()));
    }

    #[test]
    fn test_parse_hosts_with_tags() {
        let input = b"192.168.1.30\tiot.local\t# [homelab, iot]\n";
        let entries = parse_import(input, ImportFormat::Hosts).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tags, vec!["homelab", "iot"]);
        assert!(entries[0].comment.is_none());
    }

    #[test]
    fn test_parse_hosts_with_comment_and_tags() {
        let input = b"192.168.1.40\tdb.local\t# Database server [prod, db]\n";
        let entries = parse_import(input, ImportFormat::Hosts).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, Some("Database server".to_string()));
        assert_eq!(entries[0].tags, vec!["prod", "db"]);
    }

    #[test]
    fn test_parse_hosts_skips_comments_and_empty() {
        let input = b"# This is a comment\n\n192.168.1.10\tserver.local\n   \n";
        let entries = parse_import(input, ImportFormat::Hosts).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_parse_hosts_multiple_entries() {
        let input = b"192.168.1.10\tserver1.local\n192.168.1.11\tserver2.local\n";
        let entries = parse_import(input, ImportFormat::Hosts).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_hosts_spaces_instead_of_tabs() {
        let input = b"192.168.1.10   server.local\n";
        let entries = parse_import(input, ImportFormat::Hosts).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].hostname, "server.local");
    }

    #[test]
    fn test_parse_json_simple() {
        let input = br#"{"ip_address": "192.168.1.10", "hostname": "server.local"}"#;
        let entries = parse_import(input, ImportFormat::Json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip_address, "192.168.1.10");
        assert_eq!(entries[0].hostname, "server.local");
    }

    #[test]
    fn test_parse_json_with_all_fields() {
        let input = br#"{"ip_address": "192.168.1.10", "hostname": "server.local", "comment": "My server", "tags": ["prod", "web"]}"#;
        let entries = parse_import(input, ImportFormat::Json).unwrap();
        assert_eq!(entries[0].comment, Some("My server".to_string()));
        assert_eq!(entries[0].tags, vec!["prod", "web"]);
    }

    #[test]
    fn test_parse_json_multiple_lines() {
        let input = br#"{"ip_address": "192.168.1.10", "hostname": "server1.local"}
{"ip_address": "192.168.1.11", "hostname": "server2.local"}"#;
        let entries = parse_import(input, ImportFormat::Json).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_json_skips_empty_lines() {
        let input = br#"{"ip_address": "192.168.1.10", "hostname": "server.local"}

"#;
        let entries = parse_import(input, ImportFormat::Json).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_parse_csv_simple() {
        let input = b"ip_address,hostname,comment,tags\n192.168.1.10,server.local,,\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip_address, "192.168.1.10");
        assert_eq!(entries[0].hostname, "server.local");
    }

    #[test]
    fn test_parse_csv_with_all_fields() {
        let input =
            b"ip_address,hostname,comment,tags\n192.168.1.10,server.local,My server,prod;web\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries[0].comment, Some("My server".to_string()));
        assert_eq!(entries[0].tags, vec!["prod", "web"]);
    }

    #[test]
    fn test_parse_csv_escaped_fields() {
        let input =
            b"ip_address,hostname,comment,tags\n192.168.1.10,server.local,\"Hello, world\",\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries[0].comment, Some("Hello, world".to_string()));
    }

    #[test]
    fn test_parse_csv_multiple_rows() {
        let input = b"ip_address,hostname,comment,tags\n192.168.1.10,server1.local,,\n192.168.1.11,server2.local,,\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_csv_escaped_quotes() {
        // CSV with embedded quotes (escaped as "")
        let input = b"ip_address,hostname,comment,tags\n192.168.1.10,server.local,\"He said \"\"hello\"\"\",\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, Some("He said \"hello\"".to_string()));
    }

    #[test]
    fn test_parse_csv_multiline_field() {
        // CSV with newline inside quoted field (the csv crate handles this)
        let input =
            b"ip_address,hostname,comment,tags\n192.168.1.10,server.local,\"Line 1\nLine 2\",\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].comment, Some("Line 1\nLine 2".to_string()));
    }

    #[test]
    fn test_import_format_from_str() {
        assert_eq!(
            "hosts".parse::<ImportFormat>().unwrap(),
            ImportFormat::Hosts
        );
        assert_eq!(
            "HOSTS".parse::<ImportFormat>().unwrap(),
            ImportFormat::Hosts
        );
        assert_eq!("".parse::<ImportFormat>().unwrap(), ImportFormat::Hosts);
        assert_eq!("json".parse::<ImportFormat>().unwrap(), ImportFormat::Json);
        assert_eq!("JSON".parse::<ImportFormat>().unwrap(), ImportFormat::Json);
        assert_eq!("csv".parse::<ImportFormat>().unwrap(), ImportFormat::Csv);
        assert_eq!("CSV".parse::<ImportFormat>().unwrap(), ImportFormat::Csv);
    }

    #[test]
    fn test_import_format_from_str_invalid() {
        let result = "invalid".parse::<ImportFormat>();
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_import_format_display() {
        let err = InvalidImportFormat;
        assert_eq!(err.to_string(), "invalid import format");
    }

    #[test]
    fn test_parse_error_display() {
        let err = ParseError::InvalidLine {
            line: 5,
            message: "Missing IP".to_string(),
        };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("Missing IP"));

        let err = ParseError::InvalidUtf8;
        assert!(err.to_string().contains("UTF-8"));

        let err = ParseError::JsonError {
            line: 3,
            message: "parse failed".to_string(),
        };
        assert!(err.to_string().contains("3"));

        let err = ParseError::CsvError("csv failed".to_string());
        assert!(err.to_string().contains("csv failed"));
    }

    #[test]
    fn test_parse_invalid_utf8() {
        let invalid_utf8 = vec![0xff, 0xfe];
        let result = parse_import(&invalid_utf8, ImportFormat::Hosts);
        assert!(matches!(result, Err(ParseError::InvalidUtf8)));
    }

    #[test]
    fn test_parse_hosts_missing_hostname() {
        let input = b"192.168.1.10\n";
        let result = parse_import(input, ImportFormat::Hosts);
        assert!(result.is_err());
        match result {
            Err(ParseError::InvalidLine { line, message }) => {
                assert_eq!(line, 1);
                assert!(message.contains("hostname"));
            }
            _ => panic!("Expected InvalidLine error"),
        }
    }

    #[test]
    fn test_parse_json_invalid() {
        let input = b"{invalid json}";
        let result = parse_import(input, ImportFormat::Json);
        assert!(result.is_err());
    }

    #[test]
    fn test_import_format_default() {
        assert_eq!(ImportFormat::default(), ImportFormat::Hosts);
    }
}
