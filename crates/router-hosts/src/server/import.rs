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
            comment: json_entry.comment,
            tags: json_entry.tags,
            line_number,
        });
    }

    Ok(entries)
}

fn parse_csv_format(text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    let mut entries = Vec::new();
    let mut lines = text.lines().enumerate();

    // Skip header row
    if lines.next().is_none() {
        return Ok(entries);
    }

    for (line_num, line) in lines {
        let line_number = line_num + 1;
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        let fields = parse_csv_line(line).map_err(|e| ParseError::CsvError(e))?;

        if fields.len() < 2 {
            return Err(ParseError::InvalidLine {
                line: line_number,
                message: "CSV row must have at least ip_address and hostname".to_string(),
            });
        }

        let comment = fields.get(2).and_then(|s| {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        });

        let tags = fields
            .get(3)
            .map(|s| {
                s.split(';')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        entries.push(ParsedEntry {
            ip_address: fields[0].clone(),
            hostname: fields[1].clone(),
            comment,
            tags,
            line_number,
        });
    }

    Ok(entries)
}

/// Parse a CSV line, handling quoted fields
fn parse_csv_line(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                // Check for escaped quote
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' if !in_quotes => {
                in_quotes = true;
            }
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => {
                current.push(c);
            }
        }
    }
    fields.push(current);

    if in_quotes {
        return Err("Unclosed quote in CSV".to_string());
    }

    Ok(fields)
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
        let input = b"ip_address,hostname,comment,tags\n192.168.1.10,server.local,My server,prod;web\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries[0].comment, Some("My server".to_string()));
        assert_eq!(entries[0].tags, vec!["prod", "web"]);
    }

    #[test]
    fn test_parse_csv_escaped_fields() {
        let input = b"ip_address,hostname,comment,tags\n192.168.1.10,server.local,\"Hello, world\",\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries[0].comment, Some("Hello, world".to_string()));
    }

    #[test]
    fn test_parse_csv_multiple_rows() {
        let input = b"ip_address,hostname,comment,tags\n192.168.1.10,server1.local,,\n192.168.1.11,server2.local,,\n";
        let entries = parse_import(input, ImportFormat::Csv).unwrap();
        assert_eq!(entries.len(), 2);
    }
}
