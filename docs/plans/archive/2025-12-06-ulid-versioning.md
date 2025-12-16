# ULID Versioning Implementation Plan

> **Status:** ✅ **COMPLETED** - Merged in PR #50

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace sequential integer event versioning with ULID-based versioning for proper optimistic concurrency control.

**Architecture:** Change `event_version` from `INTEGER` (i64) to `VARCHAR` (String) in the database schema and generate new ULID for each event instead of incrementing a counter. The ULID provides natural chronological ordering and global uniqueness.

**Tech Stack:** Rust, DuckDB, ulid crate (already in dependencies), tonic/gRPC

---

## Task 1: Update Database Schema

**Files:**
- Modify: `crates/router-hosts/src/server/db/schema.rs:106`
- Modify: `crates/router-hosts/src/server/db/schema.rs:120`
- Modify: `crates/router-hosts/src/server/db/schema.rs:133`

**Step 1: Change event_version column type to VARCHAR**

In `crates/router-hosts/src/server/db/schema.rs`, line 106, change:
```rust
event_version INTEGER NOT NULL,
```
to:
```rust
event_version VARCHAR NOT NULL,
```

**Step 2: Change expected_version column type to VARCHAR**

In `crates/router-hosts/src/server/db/schema.rs`, line 120, change:
```rust
expected_version INTEGER,
```
to:
```rust
expected_version VARCHAR,
```

**Step 3: Verify schema creates successfully**

Run: `cargo build -p router-hosts`
Expected: SUCCESS (compiles without errors)

**Step 4: Run schema tests**

Run: `cargo test -p router-hosts --lib schema::tests`
Expected: PASS (tests verify VARCHAR type)

**Step 5: Commit schema changes**

```bash
git add crates/router-hosts/src/server/db/schema.rs
git commit -m "refactor(db): change event_version from INTEGER to VARCHAR for ULID support"
```

---

## Task 2: Update EventEnvelope Struct

**Files:**
- Modify: `crates/router-hosts/src/server/db/events.rs:92`
- Test: `crates/router-hosts/src/server/db/events.rs:tests`

**Step 1: Change event_version field type**

In `crates/router-hosts/src/server/db/events.rs`, line 92, change:
```rust
pub event_version: i64,
```
to:
```rust
pub event_version: String,
```

**Step 2: Build to find compilation errors**

Run: `cargo build -p router-hosts 2>&1 | grep "error\|expected"`
Expected: Multiple errors about type mismatches (i64 vs String)

**Step 3: Update test fixtures in events.rs**

In `crates/router-hosts/src/server/db/events.rs`, find test functions and update event_version values from integers to ULID strings:

```rust
// Example: Change
event_version: 1,
// To:
event_version: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
```

**Step 4: Verify event tests compile**

Run: `cargo test -p router-hosts --lib events::tests --no-run`
Expected: SUCCESS (compiles)

**Step 5: Commit EventEnvelope changes**

```bash
git add crates/router-hosts/src/server/db/events.rs
git commit -m "refactor(events): change EventEnvelope.event_version to String"
```

---

## Task 3: Update Event Store - get_current_version()

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs:308-320`

**Step 1: Change get_current_version return type**

In `crates/router-hosts/src/server/db/event_store.rs`, find the `get_current_version` function (around line 308) and change:

```rust
fn get_current_version(
    db: &Database,
    aggregate_id: &Ulid,
) -> DatabaseResult<Option<i64>> {
```
to:
```rust
fn get_current_version(
    db: &Database,
    aggregate_id: &Ulid,
) -> DatabaseResult<Option<String>> {
```

**Step 2: Update query return type handling**

In the same function, the query extracts `i64`. Change it to extract `String`:

```rust
// Find this line (around line 315):
|row| row.get::<_, Option<i64>>(0),
// Change to:
|row| row.get::<_, Option<String>>(0),
```

**Step 3: Build to verify changes**

Run: `cargo build -p router-hosts 2>&1 | grep -A2 "event_store"`
Expected: Remaining errors in append_event function

**Step 4: Commit get_current_version changes**

```bash
git add crates/router-hosts/src/server/db/event_store.rs
git commit -m "refactor(event_store): change get_current_version to return Option<String>"
```

---

## Task 4: Update Event Store - append_event() Signature

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs:79-85`

**Step 1: Change expected_version parameter type**

In `crates/router-hosts/src/server/db/event_store.rs`, find `append_event` function (line 79) and change:

```rust
expected_version: Option<i64>,
```
to:
```rust
expected_version: Option<String>,
```

**Step 2: Build to find next errors**

Run: `cargo build -p router-hosts 2>&1 | head -20`
Expected: Error at version calculation line (new_version)

**Step 3: Commit signature change**

```bash
git add crates/router-hosts/src/server/db/event_store.rs
git commit -m "refactor(event_store): change append_event expected_version to Option<String>"
```

---

## Task 5: Update Event Store - Version Generation Logic

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs:124-125`

**Step 1: Replace version increment with ULID generation**

In `crates/router-hosts/src/server/db/event_store.rs`, find the version calculation (around line 124-125):

```rust
// Calculate next version
let new_version = current_version.unwrap_or(0) + 1;
```

Replace with:

```rust
// Generate new ULID version
let new_version = Ulid::new().to_string();
```

**Step 2: Build to check for errors**

Run: `cargo build -p router-hosts 2>&1 | grep "error"`
Expected: Should compile successfully now

**Step 3: Run event_store unit tests**

Run: `cargo test -p router-hosts --lib event_store::tests --no-run`
Expected: Compiles, but tests will fail (fixtures still use i64)

**Step 4: Commit version generation change**

```bash
git add crates/router-hosts/src/server/db/event_store.rs
git commit -m "feat(event_store): generate ULID versions instead of sequential integers"
```

---

## Task 6: Update Event Store Test Fixtures

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs:tests` (multiple test functions)

**Step 1: Find all test functions with expected_version**

Run: `grep -n "expected_version.*Some" crates/router-hosts/src/server/db/event_store.rs`
Expected: Lists line numbers with `Some(0)`, `Some(1)`, etc.

**Step 2: Update test fixtures to use ULID strings**

Replace all occurrences of `expected_version: Some(n)` with valid ULID strings:

```rust
// Example changes:
expected_version: None,              // Stays the same
expected_version: Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string()),  // Was Some(0)
expected_version: Some("01ARZ3NDEKTSV4RRFFQ69G5FAQ".to_string()),  // Was Some(1)
```

Note: Use different ULIDs for different tests to avoid confusion. You can generate them or use these examples:
- Version 1: `01ARZ3NDEKTSV4RRFFQ69G5FAV`
- Version 2: `01ARZ3NDEKTSV4RRFFQ69G5FAQ`
- Version 3: `01ARZ3NDEKTSV4RRFFQ69G5FAP`

**Step 3: Run event_store tests**

Run: `cargo test -p router-hosts --lib event_store::tests`
Expected: PASS (all tests pass with ULID versions)

**Step 4: Commit test fixture updates**

```bash
git add crates/router-hosts/src/server/db/event_store.rs
git commit -m "test(event_store): update fixtures to use ULID strings for versions"
```

---

## Task 7: Update HostEntry Struct in Projections

**Files:**
- Modify: `crates/router-hosts/src/server/db/projections.rs:23`

**Step 1: Change version field type**

In `crates/router-hosts/src/server/db/projections.rs`, line 23, change:

```rust
pub version: i64,
```
to:
```rust
pub version: String,
```

**Step 2: Build to find compilation errors in projections**

Run: `cargo build -p router-hosts 2>&1 | grep "projections"`
Expected: Errors in query result mapping and protobuf conversion

**Step 3: Commit HostEntry struct change**

```bash
git add crates/router-hosts/src/server/db/projections.rs
git commit -m "refactor(projections): change HostEntry.version to String"
```

---

## Task 8: Update Projections Query Result Mapping

**Files:**
- Modify: `crates/router-hosts/src/server/db/projections.rs` (query result mapping)

**Step 1: Find all `row.get::<_, i64>` for version field**

Run: `grep -n "version.*i64" crates/router-hosts/src/server/db/projections.rs`
Expected: Shows line numbers where version is extracted as i64

**Step 2: Change version field extraction to String**

In query result mapping code (typically in `get_by_id`, `list_all`, `search`, etc.), change:

```rust
version: row.get(N)?,  // Where N is the column index for version
```

The type is inferred, so if you see explicit types like:
```rust
let version: i64 = row.get(N)?;
```
Change to:
```rust
let version: String = row.get(N)?;
```

**Step 3: Build to verify query mapping**

Run: `cargo build -p router-hosts 2>&1 | grep "error"`
Expected: Remaining error in protobuf conversion (to_string())

**Step 4: Commit query mapping changes**

```bash
git add crates/router-hosts/src/server/db/projections.rs
git commit -m "refactor(projections): extract version as String from query results"
```

---

## Task 9: Update Protobuf Conversion

**Files:**
- Modify: `crates/router-hosts/src/server/db/projections.rs:546-550`

**Step 1: Remove .to_string() conversion and TODO comment**

In `crates/router-hosts/src/server/db/projections.rs`, find the `From<HostEntry>` impl (around line 546-550) and change:

```rust
// INTERIM: Using event_version (i64) converted to string until ULID implementation.
// Clients should treat as opaque version identifier, not parse as ULID.
// TODO: Full ULID-based versioning needs event store changes.
version: entry.version.to_string(),
```

to:

```rust
version: entry.version,
```

**Step 2: Build to verify protobuf conversion**

Run: `cargo build -p router-hosts`
Expected: SUCCESS (all compilation errors resolved)

**Step 3: Run all projections tests**

Run: `cargo test -p router-hosts --lib projections::tests`
Expected: Failures in test fixtures (still using i64)

**Step 4: Commit protobuf conversion fix**

```bash
git add crates/router-hosts/src/server/db/projections.rs
git commit -m "refactor(projections): use ULID String version directly in protobuf conversion"
```

---

## Task 10: Update Projections Test Fixtures

**Files:**
- Modify: `crates/router-hosts/src/server/db/projections.rs:tests`

**Step 1: Find test functions creating HostEntry instances**

Run: `grep -n "version:" crates/router-hosts/src/server/db/projections.rs | grep -A2 "HostEntry"`
Expected: Shows test fixtures with `version: 1,` etc.

**Step 2: Update test fixtures to use ULID strings**

Change all HostEntry test fixtures from:
```rust
version: 1,
```
to:
```rust
version: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
```

Use consistent ULID strings in related tests.

**Step 3: Run projections tests**

Run: `cargo test -p router-hosts --lib projections::tests`
Expected: PASS (all tests pass)

**Step 4: Commit test fixture updates**

```bash
git add crates/router-hosts/src/server/db/projections.rs
git commit -m "test(projections): update fixtures to use ULID strings for versions"
```

---

## Task 11: Update Integration Tests

**Files:**
- Modify: `crates/router-hosts/tests/integration_tests.rs` (if exists)
- Or: `crates/router-hosts/src/server/mod.rs:tests` (integration tests)

**Step 1: Find integration test files**

Run: `find crates/router-hosts/tests -name "*.rs" 2>/dev/null || echo "No tests/ directory"`
Expected: Lists integration test files or indicates none exist

**Step 2: Search for version-related assertions**

Run: `grep -rn "version" crates/router-hosts/tests/ 2>/dev/null | grep -i assert`
Expected: Shows assertions checking version values

**Step 3: Update integration test expectations**

Change assertions from expecting integers to expecting ULID strings:

```rust
// Before:
assert_eq!(response.version, "1");

// After:
assert!(response.version.len() == 26);  // ULID is 26 chars
assert!(!response.version.is_empty());
// Or check it's a valid ULID format (optional)
```

**Step 4: Run integration tests**

Run: `cargo test -p router-hosts --test '*'`
Expected: PASS (all integration tests pass)

**Step 5: Commit integration test updates**

```bash
git add crates/router-hosts/tests/
git commit -m "test(integration): update version assertions for ULID strings"
```

---

## Task 12: Run Full Test Suite

**Files:**
- None (verification step)

**Step 1: Run all workspace tests**

Run: `cargo test --workspace`
Expected: All tests PASS

**Step 2: Check test count**

Run: `cargo test --workspace 2>&1 | grep "test result"`
Expected: Should show 281 tests passing (same count as before)

**Step 3: If any tests fail, investigate**

If failures occur:
1. Read the error message carefully
2. Identify which test failed and why
3. Check if test fixture needs updating (version: i64 → String)
4. Fix and re-run

**Step 4: Verify build in release mode**

Run: `cargo build --release --workspace`
Expected: SUCCESS

---

## Task 13: Manual Verification

**Files:**
- None (manual testing)

**Step 1: Create test database and add entry**

```bash
# In a terminal
cargo run -- server --config <path-to-test-config> &
SERVER_PID=$!
cargo run -- add --ip 192.168.1.100 --hostname test.local
```

Expected: Entry created successfully

**Step 2: Get the entry and check version format**

```bash
cargo run -- get --id <id-from-previous-step>
```

Expected: Output shows `version: "01..."` with 26-character ULID

**Step 3: Try updating with version check**

```bash
cargo run -- update --id <id> --ip 192.168.1.101 --version <ulid-from-get>
```

Expected: Update succeeds

**Step 4: Try updating with wrong version**

```bash
cargo run -- update --id <id> --ip 192.168.1.102 --version "01INVALID0000000000000000"
```

Expected: Error about version mismatch (optimistic concurrency working)

**Step 5: Clean up test server**

```bash
kill $SERVER_PID
```

---

## Task 14: Update Documentation Comments

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs` (doc comments)
- Modify: `crates/router-hosts/src/server/db/projections.rs` (doc comments)

**Step 1: Update event_store.rs doc comments**

In `append_event` function doc comment, update the example:

```rust
/// # Optimistic Concurrency
///
/// The `expected_version` parameter implements optimistic locking:
/// - Pass `None` when creating a new aggregate (first event)
/// - Pass `Some(ulid_string)` where ulid_string is the last known version
/// - Returns `ConcurrentWriteConflict` if another write occurred
```

**Step 2: Check for any references to "i64" or "integer" for versions**

Run: `grep -n "version.*i64\|integer.*version" crates/router-hosts/src/server/db/*.rs`
Expected: Shows doc comments mentioning integer versions

**Step 3: Update doc comments to reflect ULID usage**

Change references from "integer version" or "i64" to "ULID string" or "version identifier".

**Step 4: Build and verify docs**

Run: `cargo doc --no-deps --package router-hosts --open`
Expected: Documentation builds and opens in browser, check version-related docs

**Step 5: Commit documentation updates**

```bash
git add crates/router-hosts/src/server/db/event_store.rs crates/router-hosts/src/server/db/projections.rs
git commit -m "docs(db): update version-related documentation for ULID strings"
```

---

## Task 15: Final Verification and PR

**Files:**
- None (final checks)

**Step 1: Run pre-commit checks**

Run: `cargo fmt && cargo clippy --workspace -- -D warnings && buf lint && buf format --diff --exit-code`
Expected: All checks PASS

**Step 2: Run full test suite one more time**

Run: `cargo test --workspace`
Expected: All 281 tests PASS

**Step 3: Check git status**

Run: `git status`
Expected: Clean working tree, all changes committed

**Step 4: Push branch**

Run: `git push origin feat/ulid-versioning`
Expected: Branch pushed successfully

**Step 5: Create pull request**

```bash
gh pr create --title "feat(server): implement ULID versioning for event store" --body "$(cat <<'EOF'
## Summary
Implements ULID-based versioning for event store to replace sequential integer versioning.

## Changes
- Changed `event_version` from INTEGER to VARCHAR in database schema
- Generate new ULID for each event instead of incrementing counter
- Updated EventEnvelope, HostEntry, and all related types
- Updated all test fixtures to use ULID strings
- Removed interim TODO comments about ULID implementation

## Testing
- All 281 tests passing
- Manual verification with CLI client
- Optimistic concurrency control working correctly

## Related
- Closes #45
- Blocks #46 (version check on update needs ULID versions)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: PR created successfully

---

## Implementation Notes

**ULID Format:**
- 26 characters (e.g., `01ARZ3NDEKTSV4RRFFQ69G5FAV`)
- Lexicographically sortable by timestamp
- Case-insensitive (uppercase by convention)

**Example ULIDs for testing:**
- `01ARZ3NDEKTSV4RRFFQ69G5FAV`
- `01ARZ3NDEKTSV4RRFFQ69G5FAQ`
- `01ARZ3NDEKTSV4RRFFQ69G5FAP`
- `01ARZ3NDEKTSV4RRFFQ69G5FAQ`

**Common Pitfalls:**
1. Forgetting to update test fixtures (will cause type errors)
2. Not updating query result extraction (will fail at runtime)
3. Missing doc comment updates (inconsistent documentation)

**Test Coverage:**
- Schema creation: Verifies VARCHAR type
- Event store: ULID generation and optimistic concurrency
- Projections: Query mapping and protobuf conversion
- Integration: End-to-end version handling

**Rollback Plan:**
If issues discovered:
1. Revert to main branch
2. Delete worktree
3. No production impact (v1.0, no deployments)
