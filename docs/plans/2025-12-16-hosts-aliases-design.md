# hosts(5) Alias Support Design

**Date:** 2025-12-16
**Status:** Approved
**Author:** Claude (with Sean)

## Overview

Add support for hostname aliases as defined in the hosts(5) man page. Currently, router-hosts only captures the first hostname per line during import and outputs a single hostname during export. This design adds full alias support.

## Breaking Changes

This design introduces a **breaking API change** to align the update semantics for repeated fields:

| Change | Impact |
|--------|--------|
| `UpdateHostRequest.tags` now uses `TagsUpdate` wrapper | Existing clients sending `repeated string tags` will fail |
| New `AliasesUpdate` wrapper for aliases | New field, no backward compatibility issue |

**Migration:** Clients must update to use the new wrapper message pattern. This provides clearer semantics for distinguishing "clear all" vs "preserve existing".

## Background

The hosts(5) format allows multiple hostnames per IP address:

```
IP_address canonical_hostname [aliases...]  # optional comment
192.168.1.10    server.local srv s.local    # main server
```

### Current Behavior (Gap Analysis)

| Feature | Status | Notes |
|---------|--------|-------|
| Line-starting comments | Supported | Lines starting with `#` preserved |
| Trailing comments | Supported | Text after `#` on entry lines captured |
| Canonical hostname | Supported | First hostname after IP |
| Aliases | **Not Supported** | Silently dropped on import |

**Impact:** Users importing existing hosts files lose alias information without warning.

## Design Decisions

### Use Cases

All three use cases will be supported:
- **A: Round-trip fidelity** - Import hosts file with aliases, export preserves them
- **B: Manual alias management** - Add/update aliases via CLI
- **C: Full hosts(5) compliance** - Complete format support

### Data Model

**Explicit separation of canonical hostname and aliases:**

```rust
pub struct HostEntry {
    pub id: Ulid,
    pub ip_address: String,
    pub hostname: String,        // Canonical hostname (required)
    pub aliases: Vec<String>,    // Additional hostnames (optional)
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

**Rationale:** DNS convention distinguishes canonical names from aliases (CNAME records). This model makes the distinction explicit and keeps the required `hostname` field unchanged for backward compatibility.

### Backward Compatibility

**Seamless migration with no data conversion:**
- Existing entries automatically have empty `aliases: vec![]`
- Old events without `aliases` field deserialize with `#[serde(default)]`
- No migration script required
- All existing functionality unchanged

### API Semantics

**Atomic replacement (like tags):**
- `UpdateHost` with aliases replaces entire alias list
- Clear aliases: send empty array
- Preserve aliases: omit field from update

**Wrapper message pattern for updates:**

```protobuf
message UpdateHostRequest {
    string id = 1;
    optional string ip_address = 2;
    optional string hostname = 3;
    AliasesUpdate aliases = 4;      // Wrapper for optional semantics
    optional string comment = 5;
    TagsUpdate tags = 6;
}

message AliasesUpdate {
    repeated string values = 1;     // Empty = clear, absent message = preserve
}
```

### Validation Rules

- Same validation as hostname (DNS label compliance)
- Alias cannot match the canonical hostname of the same entry
- Must be unique within the same entry (no duplicate aliases)
- Cross-entry duplicates allowed (hosts(5) permits this, DNS resolves first match)

### Output Format

**Canonical hostname first, then aliases alphabetically sorted:**

```
192.168.1.10    server.local alpha.local beta.local zulu.local    # comment
```

**Rationale:** Alphabetical sorting provides deterministic output for diffing and version control.

## Implementation Details

### Protobuf Changes (`proto/router_hosts/v1/hosts.proto`)

```protobuf
message HostEntry {
    string id = 1;
    string ip_address = 2;
    string hostname = 3;
    repeated string aliases = 4;    // NEW
    optional string comment = 5;
    repeated string tags = 6;
    google.protobuf.Timestamp created_at = 7;
    google.protobuf.Timestamp updated_at = 8;
    string version = 9;
}

message CreateHostRequest {
    string ip_address = 1;
    string hostname = 2;
    repeated string aliases = 3;    // NEW
    optional string comment = 4;
    repeated string tags = 5;
}

// Wrapper messages for optional repeated field semantics in updates
// Absent message = preserve existing, present with empty values = clear all
message AliasesUpdate {
    repeated string values = 1;
}

message TagsUpdate {
    repeated string values = 1;
}

message UpdateHostRequest {
    string id = 1;
    optional string ip_address = 2;
    optional string hostname = 3;
    AliasesUpdate aliases = 4;      // NEW - wrapper for optional semantics
    optional string comment = 5;
    TagsUpdate tags = 6;            // CHANGED - now uses wrapper (breaking change)
    optional string expected_version = 7;
}
```

**Note:** The `TagsUpdate` wrapper is a breaking change from the previous `repeated string tags` pattern. This aligns tags with aliases for consistent update semantics.

### CLI Changes

**Add command:**
```bash
# Without aliases (unchanged)
router-hosts host add --ip 192.168.1.10 --hostname server.local

# With aliases (new --alias flag, repeatable)
router-hosts host add --ip 192.168.1.10 --hostname server.local \
  --alias srv --alias s.local
```

**Update command:**
```bash
# Update aliases atomically (replaces all) - repeatable flag
router-hosts host update <id> --alias srv --alias s.local

# Clear all aliases
router-hosts host update <id> --clear-aliases

# Update without touching aliases (flag omitted)
router-hosts host update <id> --comment "new comment"
```

**Rationale:** Using repeatable `--alias` flag (not comma-separated `--aliases`) is more shell-friendly, handles spaces in values, and matches the pattern used for `--tag`.

**List output:**
```
ID          IP             HOSTNAME        ALIASES         TAGS
01ABC...    192.168.1.10   server.local    srv, s.local    [prod]
```

### Import Parsing (`import.rs`)

```rust
// Split comment first to handle # anywhere in comment text
let (entry_part, comment) = line
    .split_once('#')
    .map(|(e, c)| (e, Some(c.trim())))
    .unwrap_or((line, None));

// Parse entry part: IP hostname [aliases...]
let mut parts = entry_part.split_whitespace();
let ip_address = parts.next()?;
let hostname = parts.next()?;  // First = canonical
let aliases: Vec<String> = parts.map(String::from).collect();

// Validate each alias (same rules as hostname)
for alias in &aliases {
    validate_hostname(alias)?;
}

// Alias cannot match canonical hostname
if aliases.contains(&hostname.to_string()) {
    return Err(ParseError::AliasMatchesHostname(hostname.to_string()));
}

// Check for duplicates within entry
let mut seen = HashSet::new();
for alias in &aliases {
    if !seen.insert(alias.clone()) {
        warn!("Duplicate alias '{}' in entry, skipping duplicate", alias);
    }
}
```

### Hosts File Generation (`hosts_file.rs`)

```rust
let mut line = format!("{}\t{}", entry.ip_address, entry.hostname);

if !entry.aliases.is_empty() {
    let mut sorted_aliases = entry.aliases.clone();
    sorted_aliases.sort();
    line.push_str(" ");
    line.push_str(&sorted_aliases.join(" "));
}

if let Some(comment) = &entry.comment {
    line.push_str(&format!("\t# {}", comment));
}
```

### Export Formats

**JSON:**
```json
{
  "id": "01ABC...",
  "ip_address": "192.168.1.10",
  "hostname": "server.local",
  "aliases": ["srv", "s.local"],
  "comment": "main server",
  "tags": ["prod"]
}
```

**CSV:**
```csv
ip,hostname,aliases,comment,tags
192.168.1.10,server.local,"srv,s.local",main server,prod
```

Note: Aliases are comma-separated within a quoted field. Standard CSV parsers handle quoted comma-separated values correctly. Tags follow the same pattern.

### Storage Layer (`schema.rs`)

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

### Event Sourcing (`types.rs`)

Aliases are carried in the existing event types - no new event variant needed:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCreatedPayload {
    pub ip_address: String,
    pub hostname: String,
    #[serde(default)]  // Backward compat: old events without aliases = empty vec
    pub aliases: Vec<String>,
    pub comment: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostUpdatedPayload {
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub aliases: Option<Vec<String>>,  // None = unchanged, Some([]) = clear
    pub comment: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
}
```

**Event replay behavior:**
- Old `HostCreated` events (pre-alias): `#[serde(default)]` deserializes to `aliases: vec![]`
- Old `HostUpdated` events: Missing `aliases` field deserializes to `None` (preserve existing)
- No migration required - event log remains unchanged

**Rationale:** Aliases are a property of the host entry, not a separate entity. Using existing events maintains the simple event model and avoids event schema versioning complexity.

## Testing Strategy

### Unit Tests

```rust
// Validation
#[test] fn test_alias_validation_same_as_hostname()
#[test] fn test_alias_uniqueness_within_entry()
#[test] fn test_alias_cannot_match_canonical_hostname()
#[test] fn test_empty_aliases_allowed()

// Import parsing
#[test] fn test_import_hosts_with_aliases()
#[test] fn test_import_hosts_without_aliases_unchanged()
#[test] fn test_import_handles_comment_with_hash_in_text()
#[test] fn test_import_warns_on_duplicate_aliases_in_entry()

// Export generation
#[test] fn test_hosts_file_includes_aliases()
#[test] fn test_aliases_sorted_alphabetically()
#[test] fn test_json_export_includes_aliases_array()
#[test] fn test_csv_export_comma_delimited_aliases_in_quotes()

// Event sourcing backward compatibility
#[test] fn test_old_event_without_aliases_deserializes_to_empty_vec()
```

### Integration Tests

```rust
#[test] fn test_add_host_with_aliases_roundtrip()
#[test] fn test_update_host_aliases_atomic_replace()
#[test] fn test_update_host_clear_aliases()
#[test] fn test_update_host_omit_aliases_preserves()
#[test] fn test_import_export_preserves_aliases()
```

### E2E Tests

- Add scenario to `daily_operations`: create host with aliases, verify in hosts file
- Add to `import_export_roundtrip`: ensure aliases survive full cycle

### Property-Based Tests

```rust
proptest! {
    #[test]
    fn test_alias_validation_matches_hostname_validation(s in ".*") {
        prop_assert_eq!(validate_hostname(&s), validate_alias(&s));
    }
}
```

## Implementation Order

1. **Protobuf** - Add `aliases` field, `AliasesUpdate` and `TagsUpdate` wrappers (breaking change)
2. **Data model** - Add `aliases` field to `HostEntry` and event payloads
3. **Storage** - Update DuckDB/SQLite/PostgreSQL schemas, event serialization
4. **Validation** - Add alias validation rules (DNS compliance, no hostname match)
5. **Import** - Parse aliases from hosts format with comment handling
6. **Export** - Generate hosts file with sorted aliases, CSV with proper escaping
7. **CLI** - Add `--alias` and `--clear-aliases` flags
8. **Tests** - Unit, integration, E2E coverage including backward compat
9. **Documentation** - Update README, CLI help, and migration guide

## Migration Notes

### Breaking API Change

The `UpdateHostRequest.tags` field changes from `repeated string tags` to `TagsUpdate tags` wrapper message:

**Before (v0.x):**
```protobuf
message UpdateHostRequest {
    repeated string tags = 5;  // Direct repeated field
}
```

**After (v1.0):**
```protobuf
message UpdateHostRequest {
    TagsUpdate tags = 6;  // Wrapper message
}
```

**Client migration:**
- Wrap tag updates: `TagsUpdate { values: ["tag1", "tag2"] }`
- Clear tags: `TagsUpdate { values: [] }`
- Preserve tags: Omit the `tags` field entirely

### Backward Compatibility

- **Event replay safe:** Old events work with new code via `#[serde(default)]`
- **File format compatible:** Hosts files without aliases parse identically
- **Storage compatible:** Existing databases work (aliases defaults to empty array)
