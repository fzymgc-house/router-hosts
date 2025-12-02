# ImportHosts Implementation Plan

**Status:** ✅ Complete (2025-12-02)
**PR:** #33

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the ImportHosts bidirectional streaming RPC with write serialization, multi-format parsing, and conflict handling.

**Architecture:** Write operations are serialized through a channel queue processed by a single worker task. Import collects all chunks, parses based on format (hosts/json/csv), processes entries with conflict handling (skip/replace/strict), commits events in a single transaction, and regenerates hosts file once.

**Tech Stack:** Rust, tokio (mpsc + oneshot channels), tonic (gRPC streaming), serde_json (JSON parsing)

---

## Task 1: Write Serialization - Define WriteCommand Enum

**Files:**
- Create: `crates/router-hosts/src/server/write_queue.rs`
- Modify: `crates/router-hosts/src/server/mod.rs`

**Step 1: Create write_queue module with WriteCommand enum**

```rust
// crates/router-hosts/src/server/write_queue.rs
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
```

**Step 2: Add module to server/mod.rs**

In `crates/router-hosts/src/server/mod.rs`, add:
```rust
pub mod write_queue;
```

**Step 3: Run build to verify compilation**

Run: `cargo build -p router-hosts 2>&1 | grep -E "(error|warning:.*write_queue)"`
Expected: No errors (warnings about unused code OK for now)

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/write_queue.rs crates/router-hosts/src/server/mod.rs
git commit -m "feat(server): add WriteCommand enum for write serialization"
```

---

## Task 2: Write Serialization - Add WriteQueue and Worker

**Files:**
- Modify: `crates/router-hosts/src/server/write_queue.rs`

**Step 1: Add WriteQueue struct and worker function**

Append to `crates/router-hosts/src/server/write_queue.rs`:

```rust
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
                crate::server::commands::CommandError::Internal(
                    "Write queue closed".to_string(),
                )
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
                crate::server::commands::CommandError::Internal(
                    "Write queue closed".to_string(),
                )
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
                crate::server::commands::CommandError::Internal(
                    "Write queue closed".to_string(),
                )
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
                crate::server::commands::CommandError::Internal(
                    "Write queue closed".to_string(),
                )
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
```

**Step 2: Run build to verify compilation**

Run: `cargo build -p router-hosts 2>&1 | grep "error"`
Expected: Error about missing `import_hosts` method on CommandHandler (expected - we'll add it later)

**Step 3: Commit (partial - will fix in next task)**

```bash
git add crates/router-hosts/src/server/write_queue.rs
git commit -m "wip: add WriteQueue struct and worker function"
```

---

## Task 3: Add import_hosts Stub to CommandHandler

**Files:**
- Modify: `crates/router-hosts/src/server/commands.rs`

**Step 1: Add import_hosts stub method**

Add to `CommandHandler` impl in `crates/router-hosts/src/server/commands.rs`:

```rust
    /// Import multiple hosts with conflict handling
    ///
    /// Unlike add_host, this commits all events in a single batch and
    /// only regenerates the hosts file once at the end.
    pub async fn import_hosts(
        &self,
        entries: Vec<crate::server::write_queue::ParsedEntry>,
        conflict_mode: crate::server::write_queue::ConflictMode,
    ) -> CommandResult<crate::server::write_queue::ImportResult> {
        use crate::server::write_queue::{ConflictMode, ImportResult};

        let mut result = ImportResult {
            processed: 0,
            created: 0,
            skipped: 0,
            failed: 0,
        };

        // TODO: Implement import logic
        let _ = (entries, conflict_mode);

        // Regenerate hosts file once at end
        if result.created > 0 {
            self.regenerate_hosts_file().await?;
        }

        Ok(result)
    }
```

**Step 2: Run build to verify compilation**

Run: `cargo build -p router-hosts 2>&1 | grep "error"`
Expected: No errors

**Step 3: Run tests to verify nothing broke**

Run: `cargo test -p router-hosts 2>&1 | tail -5`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/commands.rs crates/router-hosts/src/server/write_queue.rs
git commit -m "feat(server): add WriteQueue for write serialization

Add channel-based write queue that serializes all mutation operations
through a single worker task. This prevents race conditions in
duplicate detection and hosts file regeneration."
```

---

## Task 4: Create Import Parser Module - Structure

**Files:**
- Create: `crates/router-hosts/src/server/import.rs`
- Modify: `crates/router-hosts/src/server/mod.rs`

**Step 1: Create import.rs with format enum and error types**

```rust
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
```

**Step 2: Add module to server/mod.rs**

Add to `crates/router-hosts/src/server/mod.rs`:
```rust
pub mod import;
```

**Step 3: Run build to verify**

Run: `cargo build -p router-hosts 2>&1 | grep "error"`
Expected: No errors

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/import.rs crates/router-hosts/src/server/mod.rs
git commit -m "feat(server): add import parser module structure"
```

---

## Task 5: Implement Hosts Format Parser with Tests

**Files:**
- Modify: `crates/router-hosts/src/server/import.rs`

**Step 1: Write tests for hosts format parsing**

Add to end of `import.rs`:

```rust
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
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p router-hosts import::tests --no-run 2>&1 | tail -3`
Run: `cargo test -p router-hosts import::tests 2>&1 | grep -E "(FAILED|passed|failed)"`
Expected: Tests fail (parse_hosts_format returns empty vec)

**Step 3: Implement parse_hosts_format**

Replace `parse_hosts_format` function:

```rust
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
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p router-hosts import::tests 2>&1 | grep -E "(passed|failed|FAILED)"`
Expected: All tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/import.rs
git commit -m "feat(server): implement hosts format parser with tests"
```

---

## Task 6: Implement JSON Format Parser with Tests

**Files:**
- Modify: `crates/router-hosts/src/server/import.rs`

**Step 1: Add JSON parsing tests**

Add to tests module:

```rust
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
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p router-hosts import::tests::test_parse_json 2>&1 | grep -E "(passed|failed|FAILED)"`
Expected: Tests fail

**Step 3: Implement parse_json_format**

Add serde import at top of file:
```rust
use serde::Deserialize;
```

Add JSON entry struct and implement parser:

```rust
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
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p router-hosts import::tests::test_parse_json 2>&1 | grep -E "(passed|failed|FAILED)"`
Expected: All JSON tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/import.rs
git commit -m "feat(server): implement JSON format parser with tests"
```

---

## Task 7: Implement CSV Format Parser with Tests

**Files:**
- Modify: `crates/router-hosts/src/server/import.rs`

**Step 1: Add CSV parsing tests**

Add to tests module:

```rust
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
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p router-hosts import::tests::test_parse_csv 2>&1 | grep -E "(passed|failed|FAILED)"`
Expected: Tests fail

**Step 3: Implement parse_csv_format**

```rust
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
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p router-hosts import::tests::test_parse_csv 2>&1 | grep -E "(passed|failed|FAILED)"`
Expected: All CSV tests pass

**Step 5: Run all import tests**

Run: `cargo test -p router-hosts import::tests 2>&1 | grep -E "(passed|failed|FAILED)"`
Expected: All tests pass

**Step 6: Commit**

```bash
git add crates/router-hosts/src/server/import.rs
git commit -m "feat(server): implement CSV format parser with tests"
```

---

## Task 8: Implement import_hosts in CommandHandler

**Files:**
- Modify: `crates/router-hosts/src/server/commands.rs`

**Step 1: Write test for import_hosts**

Add to tests module in `commands.rs`:

```rust
    #[tokio::test]
    async fn test_import_hosts_skip_mode() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup();

        // Add existing host
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "existing.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let entries = vec![
            ParsedEntry {
                ip_address: "192.168.1.1".to_string(),
                hostname: "existing.local".to_string(),
                comment: Some("New comment".to_string()),
                tags: vec![],
                line_number: 1,
            },
            ParsedEntry {
                ip_address: "192.168.1.2".to_string(),
                hostname: "new.local".to_string(),
                comment: None,
                tags: vec![],
                line_number: 2,
            },
        ];

        let result = handler.import_hosts(entries, ConflictMode::Skip).await.unwrap();

        assert_eq!(result.processed, 2);
        assert_eq!(result.created, 1);
        assert_eq!(result.skipped, 1);
        assert_eq!(result.failed, 0);

        // Verify existing host unchanged
        let hosts = handler.list_hosts().await.unwrap();
        let existing = hosts.iter().find(|h| h.ip_address == "192.168.1.1").unwrap();
        assert!(existing.comment.is_none()); // Original had no comment
    }

    #[tokio::test]
    async fn test_import_hosts_replace_mode() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup();

        // Add existing host
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "existing.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let entries = vec![ParsedEntry {
            ip_address: "192.168.1.1".to_string(),
            hostname: "existing.local".to_string(),
            comment: Some("Updated comment".to_string()),
            tags: vec!["updated".to_string()],
            line_number: 1,
        }];

        let result = handler.import_hosts(entries, ConflictMode::Replace).await.unwrap();

        assert_eq!(result.processed, 1);
        assert_eq!(result.created, 0);
        assert_eq!(result.skipped, 0); // Replace mode: updated instead of skipped

        // Verify host was updated
        let hosts = handler.list_hosts().await.unwrap();
        let updated = hosts.iter().find(|h| h.ip_address == "192.168.1.1").unwrap();
        assert_eq!(updated.comment, Some("Updated comment".to_string()));
        assert_eq!(updated.tags, vec!["updated".to_string()]);
    }

    #[tokio::test]
    async fn test_import_hosts_strict_mode() {
        use crate::server::write_queue::{ConflictMode, ParsedEntry};

        let handler = setup();

        // Add existing host
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "existing.local".to_string(),
                None,
                vec![],
            )
            .await
            .unwrap();

        let entries = vec![ParsedEntry {
            ip_address: "192.168.1.1".to_string(),
            hostname: "existing.local".to_string(),
            comment: None,
            tags: vec![],
            line_number: 1,
        }];

        let result = handler.import_hosts(entries, ConflictMode::Strict).await;

        assert!(matches!(result, Err(CommandError::DuplicateEntry(_))));
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p router-hosts test_import_hosts 2>&1 | grep -E "(passed|failed|FAILED)"`
Expected: Tests fail (import_hosts returns empty result)

**Step 3: Implement import_hosts**

Replace the stub `import_hosts` method in `commands.rs`:

```rust
    /// Import multiple hosts with conflict handling
    ///
    /// Unlike add_host, this commits all events in a batch and
    /// only regenerates the hosts file once at the end.
    pub async fn import_hosts(
        &self,
        entries: Vec<crate::server::write_queue::ParsedEntry>,
        conflict_mode: crate::server::write_queue::ConflictMode,
    ) -> CommandResult<crate::server::write_queue::ImportResult> {
        use crate::server::write_queue::{ConflictMode, ImportResult};
        use crate::server::db::{EventStore, HostEvent, HostProjections};

        let mut result = ImportResult {
            processed: 0,
            created: 0,
            skipped: 0,
            failed: 0,
        };

        let mut events_to_commit: Vec<(Ulid, HostEvent, Option<i64>)> = Vec::new();

        for entry in entries {
            result.processed += 1;

            // Validate
            if let Err(e) = validate_ip_address(&entry.ip_address) {
                tracing::warn!(
                    line = entry.line_number,
                    ip = %entry.ip_address,
                    error = %e,
                    "Import validation failed"
                );
                result.failed += 1;
                continue;
            }
            if let Err(e) = validate_hostname(&entry.hostname) {
                tracing::warn!(
                    line = entry.line_number,
                    hostname = %entry.hostname,
                    error = %e,
                    "Import validation failed"
                );
                result.failed += 1;
                continue;
            }

            // Check for existing entry
            let existing =
                HostProjections::find_by_ip_and_hostname(&self.db, &entry.ip_address, &entry.hostname)?;

            match (existing, conflict_mode) {
                (Some(_), ConflictMode::Skip) => {
                    result.skipped += 1;
                }
                (Some(existing_entry), ConflictMode::Replace) => {
                    // Generate update events
                    let mut update_events = Vec::new();

                    if entry.comment != existing_entry.comment {
                        update_events.push(HostEvent::CommentUpdated {
                            old_comment: existing_entry.comment.clone(),
                            new_comment: entry.comment.clone(),
                            updated_at: Utc::now(),
                        });
                    }
                    if entry.tags != existing_entry.tags {
                        update_events.push(HostEvent::TagsModified {
                            old_tags: existing_entry.tags.clone(),
                            new_tags: entry.tags.clone(),
                            modified_at: Utc::now(),
                        });
                    }

                    if !update_events.is_empty() {
                        for event in update_events {
                            events_to_commit.push((existing_entry.id, event, Some(existing_entry.version)));
                        }
                    }
                    // Count as neither created nor skipped (it's an update)
                }
                (Some(_), ConflictMode::Strict) => {
                    return Err(CommandError::DuplicateEntry(format!(
                        "Line {}: Host with IP {} and hostname {} already exists",
                        entry.line_number, entry.ip_address, entry.hostname
                    )));
                }
                (None, _) => {
                    // Create new entry
                    let aggregate_id = Ulid::new();
                    let event = HostEvent::HostCreated {
                        ip_address: entry.ip_address,
                        hostname: entry.hostname,
                        comment: entry.comment,
                        tags: entry.tags,
                        created_at: Utc::now(),
                    };
                    events_to_commit.push((aggregate_id, event, None));
                    result.created += 1;
                }
            }
        }

        // Commit all events
        for (aggregate_id, event, expected_version) in events_to_commit {
            EventStore::append_event(&self.db, &aggregate_id, event, expected_version, None)?;
        }

        // Regenerate hosts file once at end
        if result.created > 0 || result.processed > result.skipped + result.failed {
            self.regenerate_hosts_file().await?;
        }

        Ok(result)
    }
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p router-hosts test_import_hosts 2>&1 | grep -E "(passed|failed|FAILED)"`
Expected: All import tests pass

**Step 5: Run all tests**

Run: `cargo test -p router-hosts 2>&1 | tail -10`
Expected: All tests pass

**Step 6: Commit**

```bash
git add crates/router-hosts/src/server/commands.rs
git commit -m "feat(server): implement import_hosts with conflict handling

Supports three conflict modes:
- skip: ignore duplicates (default)
- replace: update existing entries
- strict: fail on first duplicate

All events committed in single batch, hosts file regenerated once."
```

---

## Task 9: Wire Up ImportHosts in Service Layer

**Files:**
- Modify: `crates/router-hosts/src/server/service/bulk.rs`
- Modify: `crates/router-hosts/src/server/service/mod.rs`

**Step 1: Implement handle_import_hosts in bulk.rs**

Replace the stub `handle_import_hosts` method in `bulk.rs`:

```rust
    /// Import hosts from file format via streaming
    pub async fn handle_import_hosts(
        &self,
        request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Vec<ImportHostsResponse>>, Status> {
        use crate::server::import::{parse_import, ImportFormat};
        use crate::server::write_queue::ConflictMode;
        use tokio_stream::StreamExt;

        let mut stream = request.into_inner();
        let mut data = Vec::new();
        let mut format: Option<String> = None;
        let mut conflict_mode: Option<String> = None;

        // Collect all chunks
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result?;

            data.extend_from_slice(&chunk.chunk);

            // Capture format and conflict_mode from first message that has them
            if format.is_none() && chunk.format.is_some() {
                format = chunk.format;
            }
            if conflict_mode.is_none() && chunk.conflict_mode.is_some() {
                conflict_mode = chunk.conflict_mode;
            }

            if chunk.last_chunk {
                break;
            }
        }

        // Parse format
        let import_format: ImportFormat = format
            .as_deref()
            .unwrap_or("")
            .parse()
            .map_err(|_| {
                Status::invalid_argument(format!(
                    "Invalid format '{}'. Supported: hosts, json, csv",
                    format.as_deref().unwrap_or("")
                ))
            })?;

        // Parse conflict mode
        let mode: ConflictMode = conflict_mode
            .as_deref()
            .unwrap_or("")
            .parse()
            .map_err(|e| Status::invalid_argument(e))?;

        // Parse the import data
        let entries = parse_import(&data, import_format).map_err(|e| {
            Status::invalid_argument(format!("Parse error: {}", e))
        })?;

        // Import via command handler
        let result = self
            .commands
            .import_hosts(entries, mode)
            .await
            .map_err(|e| match e {
                crate::server::commands::CommandError::DuplicateEntry(msg) => {
                    Status::already_exists(msg)
                }
                crate::server::commands::CommandError::ValidationFailed(msg) => {
                    Status::invalid_argument(msg)
                }
                other => Status::internal(other.to_string()),
            })?;

        Ok(Response::new(vec![ImportHostsResponse {
            processed: result.processed,
            created: result.created,
            skipped: result.skipped,
            failed: result.failed,
            error: None,
        }]))
    }
```

**Step 2: Update import_hosts in mod.rs to call handler**

In `service/mod.rs`, update the `import_hosts` method:

```rust
    async fn import_hosts(
        &self,
        request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Self::ImportHostsStream>, Status> {
        let responses = self.handle_import_hosts(request).await?;
        let stream = futures::stream::iter(responses.into_inner().into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }
```

**Step 3: Add missing imports to bulk.rs**

Ensure bulk.rs has:
```rust
use tokio_stream::StreamExt;
```

**Step 4: Run build to verify**

Run: `cargo build -p router-hosts 2>&1 | grep "error"`
Expected: No errors

**Step 5: Run all tests**

Run: `cargo test --workspace 2>&1 | tail -10`
Expected: All tests pass

**Step 6: Commit**

```bash
git add crates/router-hosts/src/server/service/bulk.rs crates/router-hosts/src/server/service/mod.rs
git commit -m "feat(server): wire up ImportHosts RPC in service layer

Complete bidirectional streaming implementation:
- Collects chunks from client stream
- Parses format and conflict_mode from messages
- Delegates to CommandHandler for import logic
- Returns progress response"
```

---

## Task 10: Add Integration Tests

**Files:**
- Modify: `crates/router-hosts/tests/integration_test.rs`

**Step 1: Add import integration test**

Add to integration tests:

```rust
#[tokio::test]
async fn test_import_hosts_via_grpc() {
    let (mut client, _server, _temp_dir) = setup_test_server().await;

    // Import some hosts
    let import_data = b"192.168.1.10\tserver1.local\n192.168.1.11\tserver2.local\t# Second server\n";

    let requests = vec![
        ImportHostsRequest {
            chunk: import_data.to_vec(),
            last_chunk: true,
            format: Some("hosts".to_string()),
            conflict_mode: Some("skip".to_string()),
        },
    ];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.processed, 2);
    assert_eq!(progress.created, 2);
    assert_eq!(progress.skipped, 0);
    assert_eq!(progress.failed, 0);

    // Verify hosts were created
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let entries: Vec<_> = list_response.into_inner().collect().await;
    assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn test_import_export_roundtrip() {
    let (mut client, _server, _temp_dir) = setup_test_server().await;

    // Add a host
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "roundtrip.local".to_string(),
            comment: Some("Roundtrip test".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap();

    // Export as hosts format
    let export_response = client
        .export_hosts(ExportHostsRequest {
            format: "hosts".to_string(),
        })
        .await
        .unwrap();

    let mut export_data = Vec::new();
    let mut stream = export_response.into_inner();
    while let Some(chunk) = stream.message().await.unwrap() {
        export_data.extend_from_slice(&chunk.chunk);
    }

    // Delete the host
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let entries: Vec<_> = list_response.into_inner().collect().await;
    let host_id = entries[0].as_ref().unwrap().entry.as_ref().unwrap().id.clone();

    client
        .delete_host(DeleteHostRequest { id: host_id })
        .await
        .unwrap();

    // Import the exported data
    let requests = vec![ImportHostsRequest {
        chunk: export_data,
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: Some("skip".to_string()),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.created, 1);

    // Verify host is back
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let entries: Vec<_> = list_response.into_inner().collect().await;
    assert_eq!(entries.len(), 1);
    let entry = entries[0].as_ref().unwrap().entry.as_ref().unwrap();
    assert_eq!(entry.hostname, "roundtrip.local");
}
```

**Step 2: Add required imports**

Ensure integration test file has:
```rust
use router_hosts_common::proto::ImportHostsRequest;
use tokio_stream::StreamExt;
```

**Step 3: Run integration tests**

Run: `cargo test --test integration_test 2>&1 | tail -20`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/router-hosts/tests/integration_test.rs
git commit -m "test(server): add ImportHosts integration tests

Tests import via gRPC streaming and export/import roundtrip."
```

---

## Task 11: Final Verification

**Step 1: Run all tests**

Run: `cargo test --workspace 2>&1 | tail -20`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings 2>&1 | tail -20`
Expected: No warnings

**Step 3: Run fmt check**

Run: `cargo fmt -- --check`
Expected: No formatting issues

**Step 4: Verify coverage meets threshold**

Run: `cargo tarpaulin --workspace --out Stdout 2>&1 | tail -10`
Expected: Coverage ≥80%

**Step 5: Create final commit if any cleanup needed**

If all checks pass, no additional commit needed.

---

## Summary

| Task | Description |
|------|-------------|
| 1 | Create WriteCommand enum in write_queue.rs |
| 2 | Add WriteQueue struct and worker function |
| 3 | Add import_hosts stub to CommandHandler |
| 4 | Create import.rs module structure |
| 5 | Implement hosts format parser with tests |
| 6 | Implement JSON format parser with tests |
| 7 | Implement CSV format parser with tests |
| 8 | Implement import_hosts in CommandHandler |
| 9 | Wire up ImportHosts in service layer |
| 10 | Add integration tests |
| 11 | Final verification |
