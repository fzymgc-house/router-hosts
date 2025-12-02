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

fn parse_hosts_format(_text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    // TODO: Implement
    Ok(vec![])
}

fn parse_json_format(_text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    // TODO: Implement
    Ok(vec![])
}

fn parse_csv_format(_text: &str) -> Result<Vec<ParsedEntry>, ParseError> {
    // TODO: Implement
    Ok(vec![])
}
