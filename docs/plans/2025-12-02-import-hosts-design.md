# ImportHosts RPC Design

**Date:** 2025-12-02
**Status:** Active
**Related:** [v1.0 Design Document](2025-12-01-router-hosts-v1-design.md)

## Overview

Implement the `ImportHosts` bidirectional streaming RPC to allow bulk import of host entries from hosts, JSON, or CSV formats with configurable conflict handling.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Processing approach | Parse-all-then-process | Simple logic, single hosts file regeneration; memory not a concern for typical hosts file sizes |
| Write serialization | Channel queue with worker task | Strict FIFO ordering, prevents race conditions in duplicate detection and hosts file regeneration |
| Batch commit | All events in single transaction | Performance; regenerate hosts file once at end |

## Input Formats

### Hosts Format

Standard `/etc/hosts` format with optional comment and tags:

```
# Lines starting with # are comments (skip)
# Empty lines are skipped
192.168.1.10    server.local
192.168.1.20    nas.local           # NAS storage [backup, homelab]
```

Parsing logic:
1. Split on first whitespace → IP address
2. Split remainder on first `#` → hostname (trimmed), comment part
3. Parse comment: text before `[`, tags inside `[...]`

### JSON Format (JSONL)

Each line is a complete JSON object:

```json
{"ip_address": "192.168.1.10", "hostname": "server.local", "comment": "My server", "tags": ["prod"]}
```

Fields `comment` and `tags` are optional.

### CSV Format

```csv
ip_address,hostname,comment,tags
192.168.1.10,server.local,My server,tag1;tag2
```

- First line is header (skipped)
- Tags separated by semicolons
- Standard CSV escaping for fields with commas/quotes

## Conflict Handling

Three modes controlled by `conflict_mode` field in request:

| Mode | Entry Exists? | Action |
|------|---------------|--------|
| `skip` (default) | Yes | Increment `skipped` counter, continue |
| `skip` | No | Create new entry |
| `replace` | Yes | Update existing entry with new comment/tags |
| `replace` | No | Create new entry |
| `strict` | Yes | Abort entire import with error |
| `strict` | No | Create new entry |

For `replace` mode, matching is by IP+hostname pair (imports don't have IDs). The update replaces comment and tags while preserving existing ID and timestamps.

## Write Serialization

All write operations (add, update, delete, import) are serialized through a channel queue to prevent:
- Race conditions in duplicate detection
- Interleaved events from concurrent operations
- Concurrent hosts file regenerations

### Architecture

```rust
enum WriteCommand {
    AddHost { ip, hostname, comment, tags, reply: oneshot::Sender<Result<HostEntry>> },
    UpdateHost { id, ip, hostname, comment, tags, expected_version, reply: oneshot::Sender<Result<HostEntry>> },
    DeleteHost { id, reason, reply: oneshot::Sender<Result<()>> },
    ImportHosts { entries, conflict_mode, reply: oneshot::Sender<Result<ImportResult>> },
}

// CommandHandler becomes a thin wrapper that sends to the queue
struct CommandHandler {
    tx: mpsc::Sender<WriteCommand>,
}

// Single background task processes commands sequentially
async fn write_worker(rx: mpsc::Receiver<WriteCommand>, inner: CommandHandlerInner) {
    while let Some(cmd) = rx.recv().await {
        // Process command, send result via reply channel
    }
}
```

## Data Structures

### Parsed Entry

```rust
struct ParsedEntry {
    ip_address: String,
    hostname: String,
    comment: Option<String>,
    tags: Vec<String>,
    line_number: usize,  // For error reporting
}
```

### Import Result

```rust
struct ImportResult {
    processed: i32,
    created: i32,
    skipped: i32,
    failed: i32,
}
```

### Conflict Mode Enum

```rust
enum ConflictMode {
    Skip,
    Replace,
    Strict,
}

impl FromStr for ConflictMode {
    // "skip" | "" -> Skip, "replace" -> Replace, "strict" -> Strict
}
```

## Service Integration

### Request Handling

1. Collect all chunks from the incoming stream into a buffer
2. Extract format and conflict_mode from messages (use first non-empty values)
3. Parse buffer based on format
4. Process entries with conflict handling
5. Return single response with final counts

### Response Streaming

For initial implementation: single response after processing completes.

Future optimization: periodic progress updates every N entries for large imports.

### Error Mapping

| Condition | gRPC Status |
|-----------|-------------|
| Invalid format string | `INVALID_ARGUMENT` |
| Parse error (with line number) | `INVALID_ARGUMENT` |
| Validation failure | `INVALID_ARGUMENT` |
| Duplicate in strict mode | `ALREADY_EXISTS` |
| Database error | `INTERNAL` |

## File Structure

```
crates/router-hosts/src/server/
├── import.rs          # New: parsing logic, ParsedEntry, ConflictMode
├── commands.rs        # Modified: add write serialization, import_hosts method
├── service/
│   └── bulk.rs        # Modified: implement import_hosts handler
tests/
└── fixtures/
    ├── sample.hosts   # New: test data
    ├── sample.json    # New: test data
    └── sample.csv     # New: test data
```

## Testing Strategy

### Unit Tests (import.rs)

**Parsing:**
- Hosts format: simple entry, with comment, with tags, comment+tags, empty lines, comment-only lines
- JSON format: valid object, missing fields, extra fields
- CSV format: with/without header, escaped fields, semicolon-separated tags
- Edge cases: malformed lines, invalid IP, invalid hostname

**Conflict modes:**
- Skip: verify skipped count, existing entries unchanged
- Replace: verify existing entries updated, new entries created
- Strict: verify import aborts on first duplicate, no partial commits

### Integration Tests

- Full import via gRPC client with chunked streaming
- Empty import (no entries)
- Import with validation errors (partial success in skip mode)
- Import roundtrip: export → import → verify identical data

### Coverage

Maintain ≥80% coverage as per project requirements.

## Implementation Order

1. Add write serialization to CommandHandler (refactor existing code)
2. Add import.rs with parsing logic and unit tests
3. Add CommandHandler::import_hosts method
4. Wire up service layer in bulk.rs
5. Add integration tests
6. Add test fixture files
