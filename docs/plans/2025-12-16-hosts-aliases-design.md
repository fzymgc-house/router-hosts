# hosts(5) Alias Support Design

**Date:** 2025-12-16
**Status:** Approved
**Author:** Claude (with Sean)

## Overview

Add support for hostname aliases as defined in the hosts(5) man page. Currently, router-hosts only captures the first hostname per line during import and outputs a single hostname during export. This design adds full alias support while maintaining backward compatibility.

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
}

message CreateHostRequest {
    string ip_address = 1;
    string hostname = 2;
    repeated string aliases = 3;    // NEW
    optional string comment = 4;
    repeated string tags = 5;
}

message AliasesUpdate {
    repeated string values = 1;
}

message UpdateHostRequest {
    string id = 1;
    optional string ip_address = 2;
    optional string hostname = 3;
    AliasesUpdate aliases = 4;      // NEW
    optional string comment = 5;
    TagsUpdate tags = 6;
}
```

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
# Update aliases atomically (replaces all)
router-hosts host update <id> --aliases "srv,s.local"

# Clear aliases
router-hosts host update <id> --aliases ""

# Update without touching aliases (flag omitted)
router-hosts host update <id> --comment "new comment"
```

**List output:**
```
ID          IP             HOSTNAME        ALIASES         TAGS
01ABC...    192.168.1.10   server.local    srv, s.local    [prod]
```

### Import Parsing (`import.rs`)

```rust
// Parse all tokens after IP until comment marker
let mut parts = entry_part.split_whitespace();
let ip_address = parts.next()?;
let hostname = parts.next()?;  // First = canonical

let aliases: Vec<String> = parts
    .take_while(|s| !s.starts_with('#'))
    .map(String::from)
    .collect();

// Validate each alias
for alias in &aliases {
    validate_hostname(alias)?;
}

// Check for duplicates within entry
let mut seen = HashSet::new();
seen.insert(hostname.to_string());
for alias in &aliases {
    if !seen.insert(alias.clone()) {
        warn!("Duplicate alias '{}' in entry, skipping", alias);
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
192.168.1.10,server.local,"srv;s.local",main server,"prod"
```

Note: CSV uses semicolon delimiter within aliases field to avoid comma conflicts.

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

### Event Types (`types.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCreatedPayload {
    pub ip_address: String,
    pub hostname: String,
    #[serde(default)]
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

## Testing Strategy

### Unit Tests

```rust
// Validation
#[test] fn test_alias_validation_same_as_hostname()
#[test] fn test_alias_uniqueness_within_entry()
#[test] fn test_empty_aliases_allowed()

// Import parsing
#[test] fn test_import_hosts_with_aliases()
#[test] fn test_import_hosts_without_aliases_unchanged()
#[test] fn test_import_skips_comment_tokens_as_aliases()

// Export generation
#[test] fn test_hosts_file_includes_aliases()
#[test] fn test_aliases_sorted_alphabetically()
#[test] fn test_json_export_includes_aliases_array()
#[test] fn test_csv_export_semicolon_delimited_aliases()
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

1. **Data model** - Add `aliases` field to `HostEntry` and event payloads
2. **Protobuf** - Update proto definitions, regenerate code
3. **Storage** - Update DuckDB schema, event serialization
4. **Import** - Parse aliases from hosts format
5. **Export** - Generate hosts file with aliases
6. **CLI** - Add `--alias`/`--aliases` flags
7. **Tests** - Unit, integration, E2E coverage
8. **Documentation** - Update README and CLI help

## Migration Notes

- **Zero-downtime:** No migration script required
- **Event replay safe:** Old events work with new code via `#[serde(default)]`
- **API backward compatible:** Existing clients work (aliases defaults to empty)
- **File format compatible:** Hosts files without aliases parse identically
