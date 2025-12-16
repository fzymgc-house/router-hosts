# RollbackToSnapshot Implementation Plan

> **Status:** ✅ **COMPLETED** - Merged in PR #63

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement RollbackToSnapshot RPC to restore hosts database to a previous snapshot state.

**Architecture:** Parse snapshot hosts_content using existing import logic, delete current entries, import parsed entries, regenerate hosts file. Creates backup snapshot before modifications for undo capability.

**Tech Stack:** Rust, DuckDB, tonic/gRPC, existing import/export infrastructure

---

## Task 1: Add RollbackResult Type

**Files:**
- Modify: `crates/router-hosts/src/server/commands.rs:1-50`
- Export from: `crates/router-hosts/src/server/db/mod.rs`

**Step 1: Add RollbackResult struct to commands.rs**

Add after imports, before CommandHandler impl:

```rust
/// Result of a snapshot rollback operation
#[derive(Debug, Clone)]
pub struct RollbackResult {
    /// Whether the rollback succeeded
    pub success: bool,
    /// ID of the backup snapshot created before rollback
    pub backup_snapshot_id: String,
    /// Number of entries restored from the snapshot
    pub restored_entry_count: i32,
}
```

**Step 2: Commit type definition**

```bash
git add crates/router-hosts/src/server/commands.rs
git commit -m "feat(server): add RollbackResult type for snapshot rollback"
```

---

## Task 2: Write Failing Integration Test

**Files:**
- Modify: `crates/router-hosts/tests/integration_test.rs` (add at end before closing brace)

**Step 1: Write first rollback test**

Add after last test, before final `}`:

```rust
// ============================================================================
// Rollback Integration Tests (Issue #58)
// ============================================================================

#[tokio::test]
async fn test_rollback_to_snapshot_basic() {
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Initial state: Create host1
    let host1 = client
        .add_host(AddHostRequest {
            ip_address: "192.168.210.1".to_string(),
            hostname: "rollback-test-1.local".to_string(),
            comment: Some("Initial state".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap()
        .into_inner();

    let host1_id = host1.id.clone();

    // Create snapshot of initial state
    let snapshot = client
        .create_snapshot(CreateSnapshotRequest {
            name: "before-changes".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let snapshot_id = snapshot.snapshot_id;

    // Modify state: Update host1 and add host2
    client
        .update_host(UpdateHostRequest {
            id: host1_id.clone(),
            ip_address: Some("192.168.210.99".to_string()),
            hostname: None,
            comment: Some("Modified after snapshot".to_string()),
            tags: vec![],
            expected_version: None,
        })
        .await
        .unwrap();

    client
        .add_host(AddHostRequest {
            ip_address: "192.168.210.2".to_string(),
            hostname: "rollback-test-2.local".to_string(),
            comment: Some("Added after snapshot".to_string()),
            tags: vec![],
        })
        .await
        .unwrap();

    // Verify modified state has 2 hosts
    let mut list_stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let mut hosts_before = vec![];
    while let Some(response) = list_stream.message().await.unwrap() {
        hosts_before.push(response.entry.unwrap());
    }
    assert_eq!(hosts_before.len(), 2);

    // Rollback to initial snapshot
    let rollback_response = client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: snapshot_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(rollback_response.success);
    assert!(!rollback_response.new_snapshot_id.is_empty());

    // Verify restored state has 1 host with original values
    let mut list_stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let mut hosts_after = vec![];
    while let Some(response) = list_stream.message().await.unwrap() {
        hosts_after.push(response.entry.unwrap());
    }

    assert_eq!(hosts_after.len(), 1);
    let restored = &hosts_after[0];
    assert_eq!(restored.ip_address, "192.168.210.1");
    assert_eq!(restored.hostname, "rollback-test-1.local");
    assert_eq!(restored.comment.as_deref().unwrap(), "Initial state");
    assert_eq!(restored.tags, vec!["test"]);
}
```

**Step 2: Run test to verify it fails**

```bash
cargo test --test integration_test test_rollback_to_snapshot_basic
```

Expected: FAIL with "RollbackToSnapshot not yet implemented"

**Step 3: Commit failing test**

```bash
git add crates/router-hosts/tests/integration_test.rs
git commit -m "test(server): add failing test for rollback_to_snapshot"
```

---

## Task 3: Implement rollback_to_snapshot in CommandHandler

**Files:**
- Modify: `crates/router-hosts/src/server/commands.rs` (add method to CommandHandler impl)

**Step 1: Import parse_import at top of file**

Add to imports section:

```rust
use crate::server::import::{parse_import, ImportFormat};
```

**Step 2: Add rollback_to_snapshot method**

Add to CommandHandler impl block (after create_snapshot method):

```rust
/// Rollback to a previous snapshot
///
/// Creates a backup snapshot before rollback, then restores the database
/// to the state captured in the target snapshot by parsing its hosts file
/// content and recreating entries.
pub fn rollback_to_snapshot(&self, snapshot_id: &str) -> CommandResult<RollbackResult> {
    // 1. Fetch snapshot from database
    let conn = self.db.conn();
    let (hosts_content, entry_count): (String, i32) = conn
        .query_row(
            "SELECT hosts_content, entry_count FROM snapshots WHERE snapshot_id = ?",
            [snapshot_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| CommandError::NotFound(format!("Snapshot not found: {}", snapshot_id)))?;

    // 2. Create pre-rollback backup snapshot
    let backup = self.create_snapshot(None, "pre-rollback".to_string())?;
    let backup_snapshot_id = backup.snapshot_id;

    // 3. Parse snapshot content
    let parsed_entries = parse_import(hosts_content.as_bytes(), ImportFormat::Hosts).map_err(
        |e| {
            CommandError::ValidationFailed(format!("Failed to parse snapshot content: {}", e))
        },
    )?;

    // 4. Clear current state (delete all existing hosts)
    let current_hosts = HostProjections::list_all(&self.db)?;
    for host in &current_hosts {
        self.delete_host(&host.id)?;
    }

    // 5. Import parsed entries from snapshot
    let mut restored_count = 0;
    for entry in parsed_entries {
        match self.add_host(
            entry.ip_address,
            entry.hostname,
            entry.comment,
            entry.tags,
        ) {
            Ok(_) => restored_count += 1,
            Err(e) => {
                // Log but don't fail entire rollback for individual entry failures
                tracing::warn!("Failed to restore entry during rollback: {}", e);
            }
        }
    }

    // 6. Regenerate hosts file (includes hook execution)
    self.generate_hosts_file()?;

    Ok(RollbackResult {
        success: true,
        backup_snapshot_id,
        restored_entry_count: restored_count,
    })
}
```

**Step 3: Run test to verify it passes**

```bash
cargo test --test integration_test test_rollback_to_snapshot_basic
```

Expected: PASS

**Step 4: Commit implementation**

```bash
git add crates/router-hosts/src/server/commands.rs
git commit -m "feat(server): implement rollback_to_snapshot in CommandHandler"
```

---

## Task 4: Wire Up Service Layer

**Files:**
- Modify: `crates/router-hosts/src/server/service/snapshots.rs:96-104`

**Step 1: Replace unimplemented stub**

Replace the existing `handle_rollback_to_snapshot` method (lines 96-104):

```rust
/// Rollback to a previous snapshot
pub async fn handle_rollback_to_snapshot(
    &self,
    request: Request<RollbackToSnapshotRequest>,
) -> Result<Response<RollbackToSnapshotResponse>, Status> {
    let req = request.into_inner();

    if req.snapshot_id.is_empty() {
        return Err(Status::invalid_argument("snapshot_id is required"));
    }

    let result = self
        .commands
        .rollback_to_snapshot(&req.snapshot_id)
        .map_err(|e| match e {
            CommandError::NotFound(_) => Status::not_found(e.to_string()),
            CommandError::ValidationFailed(msg) => Status::invalid_argument(msg),
            _ => Status::internal(e.to_string()),
        })?;

    Ok(Response::new(RollbackToSnapshotResponse {
        success: result.success,
        new_snapshot_id: result.backup_snapshot_id,
    }))
}
```

**Step 2: Run all tests**

```bash
cargo test --workspace
```

Expected: All tests pass (188 tests: 163 unit + 25 integration)

**Step 3: Commit service wiring**

```bash
git add crates/router-hosts/src/server/service/snapshots.rs
git commit -m "feat(server): wire rollback_to_snapshot to service layer"
```

---

## Task 5: Add Additional Integration Tests

**Files:**
- Modify: `crates/router-hosts/tests/integration_test.rs`

**Step 1: Add test for nonexistent snapshot**

Add after `test_rollback_to_snapshot_basic`:

```rust
#[tokio::test]
async fn test_rollback_to_nonexistent_snapshot() {
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    let result = client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: "nonexistent-id".to_string(),
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    assert!(status.message().contains("Snapshot not found"));
}
```

**Step 2: Add test for backup snapshot creation**

```rust
#[tokio::test]
async fn test_rollback_creates_backup_snapshot() {
    use tonic::Streaming;

    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create initial state
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.211.1".to_string(),
            hostname: "backup-test.local".to_string(),
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Create snapshot1
    let snap1 = client
        .create_snapshot(CreateSnapshotRequest {
            name: "snapshot1".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    // Modify state
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.211.2".to_string(),
            hostname: "modified.local".to_string(),
            comment: Some("After snapshot".to_string()),
            tags: vec![],
        })
        .await
        .unwrap();

    // Count snapshots before rollback
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let mut count_before = 0;
    while let Some(_) = stream.message().await.unwrap() {
        count_before += 1;
    }
    assert_eq!(count_before, 1); // Only snapshot1

    // Rollback to snapshot1
    let rollback = client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: snap1.snapshot_id,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(rollback.success);

    // Verify backup snapshot was created
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let mut snapshots = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        snapshots.push(response.snapshot.unwrap());
    }

    assert_eq!(snapshots.len(), 2); // snapshot1 + pre-rollback backup

    // Find pre-rollback snapshot
    let backup_snap = snapshots
        .iter()
        .find(|s| s.trigger == "pre-rollback")
        .expect("Backup snapshot should exist");

    assert_eq!(backup_snap.snapshot_id, rollback.new_snapshot_id);
    assert_eq!(backup_snap.entry_count, 2); // Had 2 hosts before rollback
}
```

**Step 3: Add test for tags/comments preservation**

```rust
#[tokio::test]
async fn test_rollback_preserves_tags_and_comments() {
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create hosts with tags and comments
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.212.1".to_string(),
            hostname: "tags-test.local".to_string(),
            comment: Some("Important comment".to_string()),
            tags: vec!["production".to_string(), "critical".to_string()],
        })
        .await
        .unwrap();

    // Create snapshot
    let snapshot = client
        .create_snapshot(CreateSnapshotRequest {
            name: "with-tags".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    // Delete the host
    let hosts = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let host = hosts.message().await.unwrap().unwrap().entry.unwrap();
    client
        .delete_host(DeleteHostRequest { id: host.id })
        .await
        .unwrap();

    // Verify empty
    let mut stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let mut count = 0;
    while let Some(_) = stream.message().await.unwrap() {
        count += 1;
    }
    assert_eq!(count, 0);

    // Rollback
    client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: snapshot.snapshot_id,
        })
        .await
        .unwrap();

    // Verify tags and comment restored
    let mut stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let restored = stream.message().await.unwrap().unwrap().entry.unwrap();
    assert_eq!(restored.ip_address, "192.168.212.1");
    assert_eq!(restored.hostname, "tags-test.local");
    assert_eq!(restored.comment.as_deref().unwrap(), "Important comment");
    assert_eq!(
        restored.tags,
        vec!["production".to_string(), "critical".to_string()]
    );
}
```

**Step 4: Run all tests**

```bash
cargo test --workspace
```

Expected: All tests pass (191 tests: 163 unit + 28 integration)

**Step 5: Commit additional tests**

```bash
git add crates/router-hosts/tests/integration_test.rs
git commit -m "test(server): add comprehensive rollback integration tests"
```

---

## Task 6: Verify Coverage

**Step 1: Run coverage check**

```bash
cargo tarpaulin --workspace --out Stdout | grep -E "(coverage|snapshots.rs)"
```

Expected: snapshots.rs coverage >95% (was 89.3%)

**Step 2: Run full test suite**

```bash
cargo test --workspace
```

Expected: All 191 tests pass

---

## Task 7: Update Task Documentation

**Files:**
- Modify: `docs/plans/2025-12-01-v1-tasks.md`

**Step 1: Mark issue #58 as complete**

Update "Remaining v1.0 Work" section to add completed row:

```markdown
### Completed (New)
| Task | Completed | PR/Notes |
|------|-----------|----------|
| RollbackToSnapshot | 2025-12-08 | PR #XX - Parse snapshot, recreate entries |
```

**Step 2: Commit documentation update**

```bash
git add docs/plans/2025-12-01-v1-tasks.md
git commit -m "docs: mark RollbackToSnapshot as complete"
```

---

## Task 8: Final Verification

**Step 1: Run clippy**

```bash
cargo clippy --workspace -- -D warnings
```

Expected: No warnings

**Step 2: Run format check**

```bash
cargo fmt --check
```

Expected: All files formatted

**Step 3: Run all pre-commit hooks**

```bash
pre-commit run --all-files
```

Expected: All hooks pass

**Step 4: Final test run**

```bash
cargo test --workspace --release
```

Expected: All 191 tests pass in release mode

---

## Implementation Complete

All tasks completed. Ready to:
1. Push to feature branch
2. Create pull request
3. Reference issue #58 in PR description
4. Include coverage improvements in PR summary

@superpowers:verification-before-completion - Run before claiming work complete
@superpowers:finishing-a-development-branch - Use to merge/cleanup after PR approval
