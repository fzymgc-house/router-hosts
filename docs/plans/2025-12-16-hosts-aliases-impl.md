# Hosts Aliases Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add hostname alias support per hosts(5) format, with breaking API change to use wrapper messages for tags/aliases updates.

**Architecture:** Add `aliases: Vec<String>` to HostEntry, `AliasesModified` event variant, wrapper messages for update semantics, and search/import/export support across all three storage backends.

**Tech Stack:** Rust, tonic/prost (gRPC), DuckDB/SQLite/PostgreSQL, clap (CLI)

---

## Task 1: Protobuf - Add Wrapper Messages

**Files:**
- Modify: `proto/router_hosts/v1/hosts.proto`

**Step 1: Add wrapper message types**

Add after line 36 (after HostEntry message):

```protobuf
// Wrapper messages for optional repeated field semantics in updates
// Absent message = preserve existing, present with empty values = clear all

message AliasesUpdate {
  repeated string values = 1;
}

message TagsUpdate {
  repeated string values = 1;
}
```

**Step 2: Add aliases to HostEntry**

Add field 9 to HostEntry message (after version field):

```protobuf
  // Optional hostname aliases (additional names resolving to same IP)
  repeated string aliases = 9;
```

**Step 3: Add aliases to AddHostRequest**

Add field 5 to AddHostRequest:

```protobuf
  // Optional hostname aliases
  repeated string aliases = 5;
```

**Step 4: Update UpdateHostRequest with wrappers**

Replace fields 5-6 with new structure. The message should become:

```protobuf
message UpdateHostRequest {
  // ID of the host entry to update (required)
  string id = 1;

  // New IP address (optional, keeps existing if not provided)
  optional string ip_address = 2;

  // New hostname (optional, keeps existing if not provided)
  optional string hostname = 3;

  // New comment (optional, keeps existing if not provided, empty string to clear)
  optional string comment = 4;

  // Field 5 reserved - was: repeated string tags (breaking change)
  reserved 5;

  // Expected version for optimistic concurrency control
  optional string expected_version = 6;

  // New aliases (wrapper for optional semantics)
  AliasesUpdate aliases = 7;

  // New tags (wrapper for optional semantics - breaking change from field 5)
  TagsUpdate tags = 8;
}
```

**Step 5: Add force flag to ImportHostsRequest**

Add field 5 to ImportHostsRequest:

```protobuf
  // Override strict mode validation (e.g., alias conflicts with existing hostname)
  optional bool force = 5;
```

**Step 6: Verify proto compiles**

Run: `cargo build -p router-hosts-common 2>&1 | head -20`
Expected: Build succeeds (warnings OK)

**Step 7: Format and lint proto**

Run: `buf format -w && buf lint`
Expected: No errors

**Step 8: Commit**

```bash
git add proto/router_hosts/v1/hosts.proto
git commit -m "proto: add aliases field and wrapper messages for updates

BREAKING CHANGE: UpdateHostRequest.tags changes from repeated string
to TagsUpdate wrapper message. Clients must update to use wrapper.

- Add AliasesUpdate and TagsUpdate wrapper messages
- Add aliases field to HostEntry (field 9) and AddHostRequest (field 5)
- Add AliasesUpdate and TagsUpdate to UpdateHostRequest (fields 7, 8)
- Reserve field 5 in UpdateHostRequest (was tags)
- Add force flag to ImportHostsRequest for strict mode override"
```

---

## Task 2: Domain Types - Add Aliases to HostEntry

**Files:**
- Modify: `crates/router-hosts-storage/src/types.rs`

**Step 1: Add aliases field to HostEntry struct**

Find `HostEntry` struct (around line 150) and add aliases field after hostname:

```rust
/// Read model for current host entries (CQRS Query side)
#[derive(Debug, Clone, PartialEq)]
pub struct HostEntry {
    pub id: Ulid,
    pub ip_address: String,
    pub hostname: String,
    pub aliases: Vec<String>,  // NEW
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// ULID version identifier for optimistic locking
    pub version: String,
}
```

**Step 2: Add aliases to HostCreated event**

Update `HostCreated` variant in `HostEvent` enum:

```rust
    /// A new host entry was created
    HostCreated {
        ip_address: String,
        hostname: String,
        #[serde(default)]  // Backward compat: old events = empty vec
        aliases: Vec<String>,
        comment: Option<String>,
        tags: Vec<String>,
        created_at: DateTime<Utc>,
    },
```

**Step 3: Add AliasesModified event variant**

Add new variant after `TagsModified`:

```rust
    /// Host aliases were modified
    AliasesModified {
        old_aliases: Vec<String>,
        new_aliases: Vec<String>,
        modified_at: DateTime<Utc>,
    },
```

**Step 4: Update event_type() method**

Add match arm in `event_type()`:

```rust
            HostEvent::AliasesModified { .. } => "AliasesModified",
```

**Step 5: Update occurred_at() method**

Add match arm in `occurred_at()`:

```rust
            HostEvent::AliasesModified { modified_at, .. } => *modified_at,
```

**Step 6: Add alias_pattern to HostFilter**

Update `HostFilter` struct:

```rust
/// Filter for searching hosts
#[derive(Debug, Clone, Default)]
pub struct HostFilter {
    /// Filter by IP address pattern
    pub ip_pattern: Option<String>,
    /// Filter by hostname pattern (also matches aliases)
    pub hostname_pattern: Option<String>,
    /// Filter by tags (any match)
    pub tags: Option<Vec<String>>,
}
```

Note: No structural change needed - we'll match aliases in the query logic.

**Step 7: Fix test compilation errors**

Update tests that create `HostCreated` events to include `aliases: vec![]`:

```rust
// In test_event_type_names
HostEvent::HostCreated {
    ip_address: "192.168.1.1".into(),
    hostname: "test.local".into(),
    aliases: vec![],  // ADD THIS
    comment: None,
    tags: vec![],
    created_at: now,
}
```

Update all similar test cases (there are ~3 occurrences).

**Step 8: Add test for AliasesModified**

Add to the test_event_type_names test:

```rust
        assert_eq!(
            HostEvent::AliasesModified {
                old_aliases: vec![],
                new_aliases: vec!["srv".into()],
                modified_at: now,
            }
            .event_type(),
            "AliasesModified"
        );
```

Add to test_event_occurred_at:

```rust
        let aliases_modified = HostEvent::AliasesModified {
            old_aliases: vec![],
            new_aliases: vec!["srv".into()],
            modified_at: now,
        };
        assert_eq!(aliases_modified.occurred_at(), now);
```

**Step 9: Add backward compat test**

Add new test:

```rust
    #[test]
    fn test_old_event_without_aliases_deserializes() {
        // Simulate old event JSON without aliases field
        let old_json = r#"{
            "type": "HostCreated",
            "ip_address": "192.168.1.1",
            "hostname": "test.local",
            "comment": null,
            "tags": [],
            "created_at": "2025-01-01T00:00:00Z"
        }"#;

        let event: HostEvent = serde_json::from_str(old_json).unwrap();
        match event {
            HostEvent::HostCreated { aliases, .. } => {
                assert!(aliases.is_empty(), "Old events should deserialize with empty aliases");
            }
            _ => panic!("Expected HostCreated"),
        }
    }
```

**Step 10: Run tests**

Run: `cargo test -p router-hosts-storage`
Expected: All tests pass

**Step 11: Commit**

```bash
git add crates/router-hosts-storage/src/types.rs
git commit -m "feat(storage): add aliases to HostEntry and HostEvent

- Add aliases field to HostEntry struct
- Add aliases to HostCreated event with #[serde(default)]
- Add AliasesModified event variant
- Add backward compat test for old events without aliases"
```

---

## Task 3: Validation - Add Alias Validation Functions

**Files:**
- Modify: `crates/router-hosts-common/src/validation.rs`

**Step 1: Read current validation module**

Run: `head -100 crates/router-hosts-common/src/validation.rs`

**Step 2: Add alias validation error variants**

Find the `ValidationError` enum and add:

```rust
    #[error("Alias '{0}' matches canonical hostname")]
    AliasMatchesHostname(String),

    #[error("Duplicate alias '{0}' in entry")]
    DuplicateAlias(String),
```

**Step 3: Add validate_alias function**

```rust
/// Validate a single alias (same rules as hostname)
pub fn validate_alias(alias: &str) -> Result<(), ValidationError> {
    validate_hostname(alias)
}
```

**Step 4: Add validate_aliases function**

```rust
/// Validate alias list for a host entry
pub fn validate_aliases(
    aliases: &[String],
    canonical_hostname: &str,
) -> Result<(), ValidationError> {
    use std::collections::HashSet;

    let mut seen = HashSet::new();

    for alias in aliases {
        // Same validation as hostname
        validate_alias(alias)?;

        // Cannot match canonical hostname
        if alias.eq_ignore_ascii_case(canonical_hostname) {
            return Err(ValidationError::AliasMatchesHostname(alias.clone()));
        }

        // No duplicates within entry (case-insensitive)
        let lower = alias.to_lowercase();
        if !seen.insert(lower) {
            return Err(ValidationError::DuplicateAlias(alias.clone()));
        }
    }

    Ok(())
}
```

**Step 5: Add unit tests**

```rust
#[cfg(test)]
mod alias_tests {
    use super::*;

    #[test]
    fn test_validate_alias_same_as_hostname() {
        // Valid hostname = valid alias
        assert!(validate_alias("server.local").is_ok());
        assert!(validate_alias("srv").is_ok());

        // Invalid hostname = invalid alias
        assert!(validate_alias("").is_err());
        assert!(validate_alias("-invalid").is_err());
    }

    #[test]
    fn test_validate_aliases_empty_allowed() {
        assert!(validate_aliases(&[], "server.local").is_ok());
    }

    #[test]
    fn test_validate_aliases_valid() {
        let aliases = vec!["srv".to_string(), "s.local".to_string()];
        assert!(validate_aliases(&aliases, "server.local").is_ok());
    }

    #[test]
    fn test_validate_aliases_matches_hostname() {
        let aliases = vec!["srv".to_string(), "server.local".to_string()];
        let err = validate_aliases(&aliases, "server.local").unwrap_err();
        assert!(matches!(err, ValidationError::AliasMatchesHostname(_)));
    }

    #[test]
    fn test_validate_aliases_matches_hostname_case_insensitive() {
        let aliases = vec!["SERVER.LOCAL".to_string()];
        let err = validate_aliases(&aliases, "server.local").unwrap_err();
        assert!(matches!(err, ValidationError::AliasMatchesHostname(_)));
    }

    #[test]
    fn test_validate_aliases_duplicate() {
        let aliases = vec!["srv".to_string(), "srv".to_string()];
        let err = validate_aliases(&aliases, "server.local").unwrap_err();
        assert!(matches!(err, ValidationError::DuplicateAlias(_)));
    }

    #[test]
    fn test_validate_aliases_duplicate_case_insensitive() {
        let aliases = vec!["srv".to_string(), "SRV".to_string()];
        let err = validate_aliases(&aliases, "server.local").unwrap_err();
        assert!(matches!(err, ValidationError::DuplicateAlias(_)));
    }

    #[test]
    fn test_validate_aliases_invalid_format() {
        let aliases = vec!["-invalid".to_string()];
        assert!(validate_aliases(&aliases, "server.local").is_err());
    }
}
```

**Step 6: Run tests**

Run: `cargo test -p router-hosts-common`
Expected: All tests pass

**Step 7: Commit**

```bash
git add crates/router-hosts-common/src/validation.rs
git commit -m "feat(validation): add alias validation functions

- validate_alias() uses same rules as hostname
- validate_aliases() checks for hostname match and duplicates
- Case-insensitive comparison for conflicts
- Add comprehensive unit tests"
```

---

## Task 4: DuckDB Backend - Add Aliases Support

**Files:**
- Modify: `crates/router-hosts-storage/src/backends/duckdb/schema.rs`
- Modify: `crates/router-hosts-storage/src/backends/duckdb/mod.rs`

**Step 1: Update schema to add aliases column**

Find `CREATE TABLE IF NOT EXISTS hosts` in schema.rs and add aliases column:

```sql
CREATE TABLE IF NOT EXISTS hosts (
    id VARCHAR PRIMARY KEY,
    ip_address VARCHAR NOT NULL,
    hostname VARCHAR NOT NULL,
    aliases VARCHAR[] DEFAULT [],
    comment VARCHAR,
    tags VARCHAR[] DEFAULT [],
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

**Step 2: Update project_host function**

Find the `project_host` function that builds HostEntry from events. Update the initial state and event handling:

Initial state should include `aliases: vec![]`.

Add handling for `AliasesModified`:

```rust
HostEvent::AliasesModified { new_aliases, modified_at, .. } => {
    entry.aliases = new_aliases.clone();
    entry.updated_at = *modified_at;
}
```

**Step 3: Update INSERT query in add_host**

Update the INSERT statement to include aliases:

```sql
INSERT INTO hosts (id, ip_address, hostname, aliases, comment, tags, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
```

And update the parameter binding to include aliases array.

**Step 4: Update search query for hostname_pattern**

Find the search/filter query and update to match aliases:

```sql
WHERE hostname ILIKE ?
   OR EXISTS (SELECT 1 FROM unnest(aliases) AS a WHERE a ILIKE ?)
```

**Step 5: Update SELECT queries to include aliases**

Ensure all SELECT queries include the aliases column and map it to HostEntry.

**Step 6: Run storage tests**

Run: `cargo test -p router-hosts-storage --features duckdb`
Expected: All tests pass

**Step 7: Commit**

```bash
git add crates/router-hosts-storage/src/backends/duckdb/
git commit -m "feat(duckdb): add aliases column and query support

- Add aliases VARCHAR[] column to schema
- Update project_host to handle AliasesModified events
- Update INSERT to include aliases
- Update search to match hostname OR aliases"
```

---

## Task 5: SQLite Backend - Add Aliases Support

**Files:**
- Modify: `crates/router-hosts-storage/src/backends/sqlite/schema.rs`
- Modify: `crates/router-hosts-storage/src/backends/sqlite/mod.rs`

**Step 1: Update schema**

SQLite doesn't have native arrays, so use JSON:

```sql
CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    hostname TEXT NOT NULL,
    aliases TEXT DEFAULT '[]',
    comment TEXT,
    tags TEXT DEFAULT '[]',
    created_at TEXT,
    updated_at TEXT
);
```

**Step 2: Update event projection**

Add `AliasesModified` handling similar to DuckDB.

**Step 3: Update search query**

```sql
WHERE hostname LIKE ?
   OR EXISTS (SELECT value FROM json_each(aliases) WHERE value LIKE ?)
```

**Step 4: Run tests**

Run: `cargo test -p router-hosts-storage --features sqlite`
Expected: All tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts-storage/src/backends/sqlite/
git commit -m "feat(sqlite): add aliases support with JSON storage

- Add aliases TEXT column (JSON array)
- Update search to query json_each(aliases)"
```

---

## Task 6: PostgreSQL Backend - Add Aliases Support

**Files:**
- Modify: `crates/router-hosts-storage/src/backends/postgres/schema.rs`
- Modify: `crates/router-hosts-storage/src/backends/postgres/mod.rs`

**Step 1: Update schema**

```sql
CREATE TABLE IF NOT EXISTS hosts (
    id VARCHAR PRIMARY KEY,
    ip_address VARCHAR NOT NULL,
    hostname VARCHAR NOT NULL,
    aliases VARCHAR[] DEFAULT '{}',
    comment VARCHAR,
    tags VARCHAR[] DEFAULT '{}',
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
```

**Step 2: Update event projection and queries**

Similar to DuckDB but with PostgreSQL array syntax:

```sql
WHERE hostname ILIKE $1
   OR $1 ILIKE ANY(aliases)
```

**Step 3: Run tests**

Run: `cargo test -p router-hosts-storage --features postgres`
Expected: All tests pass (requires Docker for PostgreSQL)

**Step 4: Commit**

```bash
git add crates/router-hosts-storage/src/backends/postgres/
git commit -m "feat(postgres): add aliases array column and query support"
```

---

## Task 7: Server - Update gRPC Handlers

**Files:**
- Modify: `crates/router-hosts/src/server/handlers.rs` (or equivalent)

**Step 1: Update AddHost handler**

Extract aliases from request, validate, include in HostCreated event:

```rust
let aliases = request.aliases.clone();
validate_aliases(&aliases, &request.hostname)?;
```

**Step 2: Update UpdateHost handler**

Handle the new wrapper pattern for tags and aliases:

```rust
// Handle aliases update
if let Some(aliases_update) = request.aliases {
    validate_aliases(&aliases_update.values, &current.hostname)?;
    // Create AliasesModified event if changed
    if aliases_update.values != current.aliases {
        events.push(HostEvent::AliasesModified {
            old_aliases: current.aliases.clone(),
            new_aliases: aliases_update.values.clone(),
            modified_at: now,
        });
    }
}

// Handle tags update (now uses wrapper)
if let Some(tags_update) = request.tags {
    if tags_update.values != current.tags {
        events.push(HostEvent::TagsModified {
            old_tags: current.tags.clone(),
            new_tags: tags_update.values.clone(),
            modified_at: now,
        });
    }
}
```

**Step 3: Update response mapping**

Ensure HostEntry responses include aliases field.

**Step 4: Run server tests**

Run: `cargo test -p router-hosts`
Expected: All tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/
git commit -m "feat(server): handle aliases in AddHost and UpdateHost RPCs

- Validate aliases on add/update
- Create AliasesModified events
- Update response mapping to include aliases"
```

---

## Task 8: CLI - Add Alias Flags

**Files:**
- Modify: `crates/router-hosts/src/client/commands/host.rs`

**Step 1: Add --alias flag to AddHostArgs**

```rust
#[derive(Args)]
pub struct AddHostArgs {
    #[arg(long)]
    pub ip: String,
    #[arg(long)]
    pub hostname: String,
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long, action = ArgAction::Append)]
    pub tag: Vec<String>,
    #[arg(long, action = ArgAction::Append)]
    pub alias: Vec<String>,
}
```

**Step 2: Add alias flags to UpdateHostArgs**

```rust
#[arg(long, action = ArgAction::Append)]
pub alias: Vec<String>,
#[arg(long)]
pub clear_aliases: bool,
#[arg(long)]
pub clear_tags: bool,
```

**Step 3: Update add command handler**

Include aliases in AddHostRequest:

```rust
let request = AddHostRequest {
    ip_address: args.ip.clone(),
    hostname: args.hostname.clone(),
    comment: args.comment.clone(),
    tags: args.tag.clone(),
    aliases: args.alias.clone(),
};
```

**Step 4: Update update command handler**

Build wrapper messages:

```rust
let aliases = if args.clear_aliases {
    Some(AliasesUpdate { values: vec![] })
} else if !args.alias.is_empty() {
    Some(AliasesUpdate { values: args.alias.clone() })
} else {
    None
};

let tags = if args.clear_tags {
    Some(TagsUpdate { values: vec![] })
} else if !args.tag.is_empty() {
    Some(TagsUpdate { values: args.tag.clone() })
} else {
    None
};
```

**Step 5: Update list output to show aliases**

Add ALIASES column to table output.

**Step 6: Run CLI tests**

Run: `cargo test -p router-hosts client::commands`
Expected: All tests pass

**Step 7: Commit**

```bash
git add crates/router-hosts/src/client/
git commit -m "feat(cli): add --alias and --clear-aliases flags

- Add --alias flag to add and update commands
- Add --clear-aliases and --clear-tags flags
- Update list output to show ALIASES column"
```

---

## Task 9: Import - Parse Aliases from Hosts Format

**Files:**
- Modify: `crates/router-hosts/src/server/import.rs` (or equivalent)

**Step 1: Update hosts line parser**

```rust
fn parse_hosts_line(line: &str) -> Result<ParsedEntry, ParseError> {
    // Split comment first
    let (entry_part, comment) = line
        .split_once('#')
        .map(|(e, c)| (e.trim(), Some(c.trim().to_string())))
        .unwrap_or((line.trim(), None));

    if entry_part.is_empty() {
        return Err(ParseError::EmptyLine);
    }

    let mut parts = entry_part.split_whitespace();
    let ip = parts.next().ok_or(ParseError::MissingIp)?;
    let hostname = parts.next().ok_or(ParseError::MissingHostname)?;
    let aliases: Vec<String> = parts.map(String::from).collect();

    // Validate
    validate_ip(ip)?;
    validate_hostname(hostname)?;
    validate_aliases(&aliases, hostname)?;

    Ok(ParsedEntry {
        ip_address: ip.to_string(),
        hostname: hostname.to_string(),
        aliases,
        comment,
    })
}
```

**Step 2: Add strict mode alias conflict check**

```rust
if conflict_mode == "strict" && !force {
    for alias in &entry.aliases {
        if let Some(existing) = storage.find_by_hostname(alias).await? {
            return Err(ImportError::AliasConflictsWithHostname {
                alias: alias.clone(),
                existing_id: existing.id.to_string(),
            });
        }
    }
}
```

**Step 3: Add import tests**

```rust
#[test]
fn test_parse_hosts_line_with_aliases() {
    let entry = parse_hosts_line("192.168.1.10 server.local srv s.local").unwrap();
    assert_eq!(entry.hostname, "server.local");
    assert_eq!(entry.aliases, vec!["srv", "s.local"]);
}

#[test]
fn test_parse_hosts_line_with_comment_and_aliases() {
    let entry = parse_hosts_line("192.168.1.10 server.local srv # main server").unwrap();
    assert_eq!(entry.aliases, vec!["srv"]);
    assert_eq!(entry.comment, Some("main server".to_string()));
}
```

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/import.rs
git commit -m "feat(import): parse aliases from hosts format

- Extract aliases (all hostnames after first)
- Add strict mode conflict checking with --force override
- Add unit tests for parsing"
```

---

## Task 10: Export - Include Aliases in Output

**Files:**
- Modify: `crates/router-hosts/src/server/export.rs` (or equivalent hosts file generator)

**Step 1: Update hosts file generation**

```rust
fn format_hosts_line(entry: &HostEntry) -> String {
    let mut line = format!("{}\t{}", entry.ip_address, entry.hostname);

    if !entry.aliases.is_empty() {
        let mut sorted = entry.aliases.clone();
        sorted.sort();
        line.push_str(&format!(" {}", sorted.join(" ")));
    }

    if let Some(comment) = &entry.comment {
        line.push_str(&format!("\t# {}", comment));
    }

    line
}
```

**Step 2: Update JSON export**

Ensure aliases field is serialized.

**Step 3: Update CSV export**

```rust
// CSV row: ip,hostname,aliases,comment,tags
let aliases_str = entry.aliases.join(",");
let tags_str = entry.tags.join(",");
format!("{},{},\"{}\",\"{}\",\"{}\"",
    entry.ip_address,
    entry.hostname,
    aliases_str,
    entry.comment.as_deref().unwrap_or(""),
    tags_str
)
```

**Step 4: Add export tests**

```rust
#[test]
fn test_format_hosts_line_with_aliases() {
    let entry = HostEntry {
        aliases: vec!["zulu".into(), "alpha".into()],
        // ... other fields
    };
    let line = format_hosts_line(&entry);
    // Aliases should be sorted
    assert!(line.contains("alpha zulu"));
}
```

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/
git commit -m "feat(export): include aliases in hosts/JSON/CSV output

- Hosts format: sorted aliases after hostname
- JSON: aliases array field
- CSV: comma-separated in quoted field"
```

---

## Task 11: Integration Tests

**Files:**
- Modify: `crates/router-hosts/tests/integration_test.rs`

**Step 1: Add test for add with aliases**

```rust
#[tokio::test]
async fn test_add_host_with_aliases() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = connect_client(addr).await;

    let response = client.add_host(AddHostRequest {
        ip_address: "192.168.1.10".into(),
        hostname: "server.local".into(),
        aliases: vec!["srv".into(), "s.local".into()],
        comment: None,
        tags: vec![],
    }).await.unwrap();

    let entry = response.into_inner().entry.unwrap();
    assert_eq!(entry.aliases, vec!["srv", "s.local"]);
}
```

**Step 2: Add test for update with alias wrapper**

```rust
#[tokio::test]
async fn test_update_host_aliases() {
    // Create host
    // Update with AliasesUpdate wrapper
    // Verify aliases changed
}
```

**Step 3: Add test for search matching alias**

```rust
#[tokio::test]
async fn test_search_matches_alias() {
    // Create host with aliases
    // Search by alias name
    // Verify host found
}
```

**Step 4: Run integration tests**

Run: `cargo test -p router-hosts --test integration_test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/tests/
git commit -m "test: add integration tests for aliases feature

- Test add with aliases
- Test update with wrapper message
- Test search matches aliases"
```

---

## Task 12: E2E Tests

**Files:**
- Modify: `crates/router-hosts-e2e/tests/scenarios/daily_operations.rs`

**Step 1: Update daily operations to include aliases**

Add aliases to test scenarios.

**Step 2: Run E2E tests**

Run: `task e2e:quick` (requires Docker image built)

**Step 3: Commit**

```bash
git add crates/router-hosts-e2e/
git commit -m "test(e2e): add aliases to daily operations scenarios"
```

---

## Task 13: Final Verification

**Step 1: Run full test suite**

Run: `cargo test --workspace --exclude router-hosts-e2e`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No errors

**Step 3: Run fmt check**

Run: `cargo fmt -- --check`
Expected: No formatting issues

**Step 4: Build release**

Run: `cargo build --release`
Expected: Build succeeds

**Step 5: Final commit if any cleanup**

```bash
git add -A
git commit -m "chore: final cleanup for aliases feature"
```

---

## Summary

| Task | Description | Est. Time |
|------|-------------|-----------|
| 1 | Protobuf changes | 10 min |
| 2 | Domain types | 15 min |
| 3 | Validation | 10 min |
| 4 | DuckDB backend | 20 min |
| 5 | SQLite backend | 15 min |
| 6 | PostgreSQL backend | 15 min |
| 7 | Server handlers | 20 min |
| 8 | CLI flags | 15 min |
| 9 | Import parsing | 15 min |
| 10 | Export formats | 10 min |
| 11 | Integration tests | 20 min |
| 12 | E2E tests | 10 min |
| 13 | Final verification | 10 min |

**Total: ~3 hours**
