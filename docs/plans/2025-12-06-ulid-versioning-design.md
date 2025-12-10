# ULID Versioning Implementation Design

**Date:** 2025-12-06
**Status:** Approved for implementation
**Related:** Issue #45, docs/plans/2025-12-01-router-hosts-v1-design.md

## Overview

Replace sequential integer event versioning (i64) with ULID-based versioning to align with the v0.5.0 design specification. This change affects the event store, projections, and database schema.

## Current State

The event store uses `event_version` (i64) for optimistic concurrency control, incrementing sequentially for each event. This value is converted to string when returned to clients via the gRPC API.

```rust
// Current implementation
let new_version = current_version.unwrap_or(0) + 1;  // i64
version: entry.version.to_string()                    // Convert to String for proto
```

## Proposed Implementation

### Approach

Generate a new ULID for each event as its version identifier. ULIDs provide natural ordering via embedded timestamps and are globally unique.

**Why ULID:**
- Already used for `event_id` and `aggregate_id` (consistent approach)
- Naturally ordered by timestamp (lexicographic sort works)
- 26-character string format matches proto contract
- Globally unique across all aggregates

### Database Schema Changes

**host_events table:**
```sql
-- Change column type
event_version VARCHAR NOT NULL  -- was BIGINT
```

**Migration:** None required (v0.5.0, no production data exists)

**Query compatibility:**
- `MAX(event_version)` works on VARCHAR (lexicographic order matches temporal order)
- String comparisons in optimistic concurrency checks
- `LAST_VALUE ... IGNORE NULLS` view logic unchanged

### Event Store Changes

**Version generation:**
```rust
// In append_event()
// Use per-invocation monotonic generator for async safety and collision prevention
use std::time::SystemTime;
let mut gen = ulid::Generator::new();
let timestamp = SystemTime::now();
let new_version = gen
    .generate_from_datetime(timestamp)
    .map_err(|e| {
        DatabaseError::InvalidData(format!("Failed to generate ULID version: {}", e))
    })?
    .to_string();
let event_id = gen.generate_from_datetime(timestamp).map_err(|e| {
    DatabaseError::InvalidData(format!("Failed to generate ULID event_id: {}", e))
})?;
```

**Why monotonic generator:**
- Prevents ULID collisions when generating multiple IDs within same millisecond
- Generator maintains internal counter that increments for same timestamp
- Guarantees `version < event_id` lexicographically via counter increment
- Per-invocation pattern (not thread-local) ensures async safety with Tokio's work-stealing scheduler

**Batch generation (append_events):**
```rust
// Use single timestamp for entire batch to ensure strict monotonic ordering
let mut gen = ulid::Generator::new();
let batch_timestamp = SystemTime::now();

for event in events {
    let version = gen.generate_from_datetime(batch_timestamp).map_err(...)?.to_string();
    let event_id = gen.generate_from_datetime(batch_timestamp).map_err(...)?;
    // ...
}
```

**Critical async safety requirement:**
- Thread-local storage is NOT safe in async context
- Tokio can migrate tasks between threads during `.await` points
- Thread-local state would be lost or reused incorrectly
- Solution: Per-invocation generator stays with execution context

**Type signatures:**
```rust
// EventEnvelope
pub struct EventEnvelope {
    pub event_id: Ulid,
    pub aggregate_id: Ulid,
    pub event: HostEvent,
    pub event_version: String,  // was i64
    // ...
}

// get_current_version()
fn get_current_version(
    db: &Database,
    aggregate_id: &Ulid
) -> DatabaseResult<Option<String>>  // was Option<i64>

// append_event()
pub fn append_event(
    db: &Database,
    aggregate_id: &Ulid,
    event: HostEvent,
    expected_version: Option<String>,  // was Option<i64>
    created_by: Option<String>,
) -> DatabaseResult<EventEnvelope>
```

**Optimistic concurrency:**
```rust
// Comparison logic unchanged, just type differs
if expected_version != current_version {
    return Err(DatabaseError::ConcurrentWriteConflict(...));
}
```

### Projections Changes

**HostEntry struct:**
```rust
pub struct HostEntry {
    pub id: Ulid,
    pub ip_address: String,
    pub hostname: String,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: String,  // was i64
}
```

**Protobuf conversion:**
```rust
impl From<HostEntry> for router_hosts_common::HostEntry {
    fn from(entry: HostEntry) -> Self {
        Self {
            id: entry.id.to_string(),
            ip_address: entry.ip_address,
            hostname: entry.hostname,
            comment: entry.comment.unwrap_or_default(),
            tags: entry.tags,
            created_at: Some(prost_types::Timestamp { /* ... */ }),
            updated_at: Some(prost_types::Timestamp { /* ... */ }),
            version: entry.version,  // Already String, no conversion needed
        }
    }
}
```

**Remove interim TODO comments:**
```rust
// Delete these lines from projections.rs:
// INTERIM: Using event_version (i64) converted to string until ULID implementation.
// Clients should treat as opaque version identifier, not parse as ULID.
// TODO: Full ULID-based versioning needs event store changes.
```

### Command Handler Updates

**No changes required** - handlers already use `Option<String>` for expected_version:
```rust
// commands.rs and write_queue.rs
pub async fn update_host(
    &self,
    id: &str,
    ip_address: Option<String>,
    hostname: Option<String>,
    comment: Option<Option<String>>,
    tags: Option<Vec<String>>,
    expected_version: Option<String>,  // Already correct
) -> CommandResult<HostEntry>
```

### gRPC Interface

**No changes required** - proto already defines `string version`:
```protobuf
message HostEntry {
  string id = 1;
  string ip_address = 2;
  string hostname = 3;
  string comment = 4;
  repeated string tags = 5;
  google.protobuf.Timestamp created_at = 6;
  google.protobuf.Timestamp updated_at = 7;
  string version = 8;  // Already accepts ULID strings
}
```

Client code needs no changes.

## Testing Strategy

### Unit Tests

1. **schema.rs:**
   - Verify `event_version` column is VARCHAR type
   - Update type assertion in column list check

2. **event_store.rs:**
   - Update fixtures: replace i64 with ULID strings
   - Verify `get_current_version()` returns `Option<String>`
   - Test optimistic concurrency with ULID versions
   - Verify ULID ordering (lexicographic sort matches temporal order)

3. **projections.rs:**
   - Update assertions to expect String versions
   - Verify `From<HostEntry>` conversion works correctly
   - Test `test_rebuild_from_events` with ULID versions

### Integration Tests

1. **GetHost RPC:**
   - Verify response includes ULID-formatted version string
   - Verify version is 26 characters and valid ULID format

2. **UpdateHost RPC:**
   - Test with valid ULID expected_version (should succeed)
   - Test with mismatched version (should return ABORTED)
   - Test with None (new aggregate creation)

3. **Concurrent writes:**
   - Two simultaneous updates with same expected_version
   - First succeeds, second fails with ConcurrentWriteConflict

### Coverage Target

Maintain ≥80% test coverage workspace-wide.

### Test Data Examples

```rust
// Before:
let expected_version = Some(1);

// After:
let expected_version = Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string());
```

## Error Handling

### Backward Compatibility

**No migration needed:**
- v0.5.0 release (no production deployments)
- Test databases can be deleted and recreated
- Fresh databases use ULID versions from start

### Error Scenarios

1. **Invalid ULID from client:**
   - Treated as opaque version identifier
   - String comparison works regardless of format
   - Mismatch fails optimistic lock check with clear error

2. **NULL handling:**
   - `expected_version: None` means "creating new aggregate"
   - `current_version: None` means "no events exist yet"
   - Semantics unchanged from current implementation

3. **Concurrent writes:**
   - Two clients generate different ULIDs simultaneously
   - First write succeeds and commits
   - Second write fails with `ConcurrentWriteConflict`
   - Error message includes expected vs actual version

**No new failure modes** - this is a type change with different generation logic, not a behavioral change to concurrency control.

## Implementation Checklist

- [x] Update database schema (event_version VARCHAR)
- [x] Change EventEnvelope.event_version to String
- [x] Update get_current_version() return type
- [x] Update append_event() expected_version parameter
- [x] Replace version increment with per-invocation monotonic generator
- [x] Change HostEntry.version to String
- [x] Remove .to_string() conversion in projections
- [x] Delete interim TODO comments
- [x] Update all test fixtures (i64 → String)
- [x] Update test assertions
- [x] Run full test suite (cargo test --workspace) - 146 tests passing
- [x] Verify ≥80% coverage maintained
- [x] Address async safety concerns (per-invocation vs thread-local)
- [x] Ensure monotonic ordering in batch operations

## Implementation Notes

### Key Decisions Made During Development

**1. Monotonic Generator Pattern:**
- Initially considered `Ulid::new()` for simplicity
- Code review identified collision risk when generating multiple ULIDs in same millisecond
- Solution: Use `ulid::Generator` which maintains internal counter for same timestamp
- Ensures strict lexicographic ordering: `version < event_id` always true

**2. Async Safety:**
- Initially attempted thread-local storage for generator reuse
- Code review identified critical flaw: Tokio's work-stealing scheduler can migrate tasks between threads
- Thread-local state would be lost during `.await` points
- Solution: Per-invocation generator that stays with execution context
- Pattern: `let mut gen = ulid::Generator::new()` at function start

**3. Batch Timestamp Strategy:**
- Initially called `SystemTime::now()` inside event loop
- This defeats monotonic ordering - each event gets different timestamp
- Solution: Capture timestamp once before loop: `let batch_timestamp = SystemTime::now()`
- All events in batch use same timestamp, generator increments counter
- Result: Strict ordering within batch guaranteed

**4. Why Not `Ulid::new()`:**
- `Ulid::new()` uses thread-local generator internally
- Thread-local not safe in async context
- No control over timestamp (uses current time each call)
- No guarantee of ordering when generating multiple ULIDs rapidly
- Explicit per-invocation generator gives full control and safety

### Verification

- All 146 tests passing
- Coverage maintained ≥80%
- Async safety verified (no thread-local storage)
- Monotonic ordering verified in batch operations
- CI checks passing (test, lint, claude-review)

## Dependencies

**Blocks:**
- Issue #46 (version check on update) - needs ULID versions to implement properly

**No blockers** - can implement immediately.

## Rollout

1. Implement changes in feature branch
2. Run full test suite
3. Verify coverage ≥80%
4. Open PR with conventional commit message
5. Merge after CI passes and review approval
6. Close issue #45

## Risks

**Low risk:**
- Type-only change, no algorithmic changes
- ULID crate already in use and tested
- Proto contract already expects string
- No production data to migrate

**Mitigation:**
- Comprehensive test coverage
- Integration tests verify end-to-end flow
- Clear error messages for debugging
