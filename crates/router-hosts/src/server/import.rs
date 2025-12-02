// crates/router-hosts/src/server/import.rs
//! Import format parsing for ImportHosts RPC

use crate::server::write_queue::ParsedEntry;
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

fn parse_json_format(_text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    // TODO: Implement
    Ok(vec![])
}

fn parse_csv_format(_text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    // TODO: Implement
    Ok(vec![])
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
}
