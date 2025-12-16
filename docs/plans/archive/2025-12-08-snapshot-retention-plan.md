# Snapshot Retention Implementation Plan

> **Status:** ✅ **COMPLETED** - Merged in PR #53

**Date:** 2025-12-08
**Issue:** #48 - feat(server): implement snapshot retention policy
**Design:** [2025-12-08-snapshot-retention-design.md](2025-12-08-snapshot-retention-design.md)
**Branch:** feat/snapshot-retention

## Overview

Implement snapshot management with automatic retention policy enforcement. This plan breaks the work into small, testable increments following TDD principles.

## Implementation Sequence

### Phase 1: Core Database Operations

#### Task 1.1: Add Snapshot struct to domain model
**File:** `crates/router-hosts/src/server/db/mod.rs`

Add Snapshot struct after existing types:

```rust
/// Snapshot of hosts file at a point in time
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub snapshot_id: String,
    pub created_at: i64,  // Unix timestamp in microseconds
    pub hosts_content: String,
    pub entry_count: i32,
    pub trigger: String,
    pub name: Option<String>,
    pub event_log_position: Option<i64>,
}
```

**Verification:**
```bash
cargo build -p router-hosts
```

#### Task 1.2: Implement delete_snapshot in CommandHandler
**File:** `crates/router-hosts/src/server/commands.rs`

Add method to CommandHandler impl block:

```rust
/// Delete a snapshot by ID
///
/// Returns true if snapshot was deleted, false if not found
pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<bool, DatabaseError> {
    let conn = self.db.conn();

    let deleted = conn.execute(
        "DELETE FROM snapshots WHERE snapshot_id = ?",
        [snapshot_id],
    ).map_err(|e| {
        DatabaseError::QueryFailed(format!("Failed to delete snapshot: {}", e))
    })?;

    Ok(deleted > 0)
}
```

**Test:** Add to `crates/router-hosts/src/server/commands.rs` test module:

```rust
#[test]
fn test_delete_snapshot_not_found() {
    let handler = setup_handler();

    let result = handler.delete_snapshot("01JDTEST000000000000000000");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn test_delete_snapshot() {
    let handler = setup_handler();

    // First create a snapshot (we'll implement this next)
    let snapshot = handler.create_snapshot(None, "manual".to_string()).unwrap();

    // Delete it
    let result = handler.delete_snapshot(&snapshot.snapshot_id);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), true);

    // Verify it's gone
    let result = handler.delete_snapshot(&snapshot.snapshot_id);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}
```

**Verification:**
```bash
cargo test -p router-hosts delete_snapshot
```

#### Task 1.3: Implement list_snapshots in CommandHandler
**File:** `crates/router-hosts/src/server/commands.rs`

Add method to CommandHandler:

```rust
/// List snapshots with optional pagination
///
/// Returns snapshots ordered by created_at DESC (newest first)
pub fn list_snapshots(
    &self,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Vec<Snapshot>, DatabaseError> {
    let conn = self.db.conn();

    let limit_clause = limit.map(|l| format!("LIMIT {}", l)).unwrap_or_default();
    let offset_clause = offset.map(|o| format!("OFFSET {}", o)).unwrap_or_default();

    let query = format!(
        "SELECT snapshot_id, created_at, hosts_content, entry_count, trigger, name, event_log_position
         FROM snapshots
         ORDER BY created_at DESC
         {} {}",
        limit_clause, offset_clause
    );

    let mut stmt = conn.prepare(&query).map_err(|e| {
        DatabaseError::QueryFailed(format!("Failed to prepare list query: {}", e))
    })?;

    let snapshots: Result<Vec<Snapshot>, _> = stmt
        .query_map([], |row| {
            Ok(Snapshot {
                snapshot_id: row.get(0)?,
                created_at: row.get(1)?,
                hosts_content: row.get(2)?,
                entry_count: row.get(3)?,
                trigger: row.get(4)?,
                name: row.get(5)?,
                event_log_position: row.get(6)?,
            })
        })?
        .collect();

    snapshots.map_err(|e| {
        DatabaseError::QueryFailed(format!("Failed to fetch snapshots: {}", e))
    })
}
```

**Tests:**

```rust
#[test]
fn test_list_snapshots_empty() {
    let handler = setup_handler();

    let snapshots = handler.list_snapshots(None, None).unwrap();
    assert_eq!(snapshots.len(), 0);
}

#[test]
fn test_list_snapshots_ordering() {
    let handler = setup_handler();

    // Create multiple snapshots
    let s1 = handler.create_snapshot(Some("first".to_string()), "manual".to_string()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10)); // Ensure different timestamps
    let s2 = handler.create_snapshot(Some("second".to_string()), "manual".to_string()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let s3 = handler.create_snapshot(Some("third".to_string()), "manual".to_string()).unwrap();

    let snapshots = handler.list_snapshots(None, None).unwrap();
    assert_eq!(snapshots.len(), 3);

    // Verify DESC ordering (newest first)
    assert_eq!(snapshots[0].snapshot_id, s3.snapshot_id);
    assert_eq!(snapshots[1].snapshot_id, s2.snapshot_id);
    assert_eq!(snapshots[2].snapshot_id, s1.snapshot_id);
}

#[test]
fn test_list_snapshots_pagination() {
    let handler = setup_handler();

    // Create 5 snapshots
    for i in 0..5 {
        handler.create_snapshot(Some(format!("snapshot-{}", i)), "manual".to_string()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Get first 2
    let page1 = handler.list_snapshots(Some(2), None).unwrap();
    assert_eq!(page1.len(), 2);

    // Get next 2
    let page2 = handler.list_snapshots(Some(2), Some(2)).unwrap();
    assert_eq!(page2.len(), 2);

    // Get last page
    let page3 = handler.list_snapshots(Some(2), Some(4)).unwrap();
    assert_eq!(page3.len(), 1);
}
```

**Verification:**
```bash
cargo test -p router-hosts list_snapshots
```

#### Task 1.4: Implement create_snapshot in CommandHandler
**File:** `crates/router-hosts/src/server/commands.rs`

Add method to CommandHandler:

```rust
/// Create a snapshot of the current hosts file state
///
/// Generates snapshot from current database projections, not from reading /etc/hosts
pub fn create_snapshot(
    &self,
    name: Option<String>,
    trigger: String,
) -> Result<Snapshot, DatabaseError> {
    use ulid::Ulid;
    use chrono::Utc;

    // Query all active hosts
    let hosts = self.db.projections().list_all()?;
    let entry_count = hosts.len() as i32;

    // Generate hosts file content
    let hosts_content = self.hosts_file.format_entries(&hosts)
        .map_err(|e| DatabaseError::QueryFailed(format!("Failed to format hosts: {}", e)))?;

    // Generate snapshot name if not provided
    let snapshot_name = name.unwrap_or_else(|| {
        format!("snapshot-{}", Utc::now().format("%Y%m%d-%H%M%S"))
    });

    // Generate ULID for snapshot_id
    let snapshot_id = Ulid::new().to_string();

    // Get current timestamp in microseconds
    let created_at = Utc::now().timestamp_micros();

    // Insert snapshot
    let conn = self.db.conn();
    conn.execute(
        "INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name, event_log_position)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            &snapshot_id,
            &created_at,
            &hosts_content,
            &entry_count,
            &trigger,
            &snapshot_name,
            &None::<i64>,  // event_log_position not used in v1
        ],
    ).map_err(|e| {
        DatabaseError::QueryFailed(format!("Failed to insert snapshot: {}", e))
    })?;

    // Run retention cleanup synchronously
    let _deleted = self.cleanup_old_snapshots()?;

    Ok(Snapshot {
        snapshot_id,
        created_at,
        hosts_content,
        entry_count,
        trigger,
        name: Some(snapshot_name),
        event_log_position: None,
    })
}
```

**Tests:**

```rust
#[test]
fn test_create_snapshot_with_custom_name() {
    let handler = setup_handler();

    let snapshot = handler.create_snapshot(
        Some("test-snapshot".to_string()),
        "manual".to_string(),
    ).unwrap();

    assert!(!snapshot.snapshot_id.is_empty());
    assert_eq!(snapshot.name, Some("test-snapshot".to_string()));
    assert_eq!(snapshot.trigger, "manual");
    assert_eq!(snapshot.entry_count, 0);  // Empty database
    assert!(snapshot.created_at > 0);
}

#[test]
fn test_create_snapshot_auto_generated_name() {
    let handler = setup_handler();

    let snapshot = handler.create_snapshot(None, "manual".to_string()).unwrap();

    // Verify auto-generated name has correct format
    let name = snapshot.name.unwrap();
    assert!(name.starts_with("snapshot-"));
    assert!(name.len() > 15);  // snapshot-YYYYMMDD-HHMMSS
}

#[test]
fn test_create_snapshot_captures_hosts() {
    let handler = setup_handler();

    // Add a host
    handler.add_host(
        "192.168.1.10".to_string(),
        "test.local".to_string(),
        None,
        None,
    ).unwrap();

    // Create snapshot
    let snapshot = handler.create_snapshot(None, "manual".to_string()).unwrap();

    assert_eq!(snapshot.entry_count, 1);
    assert!(snapshot.hosts_content.contains("192.168.1.10"));
    assert!(snapshot.hosts_content.contains("test.local"));
}

#[test]
fn test_create_snapshot_empty_database() {
    let handler = setup_handler();

    // Create snapshot with no hosts
    let snapshot = handler.create_snapshot(None, "manual".to_string()).unwrap();

    assert_eq!(snapshot.entry_count, 0);
    assert!(snapshot.hosts_content.is_empty() || snapshot.hosts_content.starts_with("#"));
}
```

**Verification:**
```bash
cargo test -p router-hosts create_snapshot
```

### Phase 2: Retention Policy

#### Task 2.1: Implement cleanup_old_snapshots (count-based)
**File:** `crates/router-hosts/src/server/commands.rs`

Add private method to CommandHandler:

```rust
/// Clean up old snapshots based on retention policy
///
/// Deletes snapshots that violate either max_snapshots OR max_age_days
fn cleanup_old_snapshots(&self) -> Result<usize, DatabaseError> {
    let max_snapshots = self.config.retention.max_snapshots;
    let max_age_days = self.config.retention.max_age_days;

    // Retention disabled if both limits are 0
    if max_snapshots == 0 && max_age_days == 0 {
        return Ok(0);
    }

    // Query all snapshots ordered newest first
    let conn = self.db.conn();
    let mut stmt = conn.prepare(
        "SELECT snapshot_id, created_at FROM snapshots ORDER BY created_at DESC"
    ).map_err(|e| {
        DatabaseError::QueryFailed(format!("Failed to query snapshots for cleanup: {}", e))
    })?;

    let snapshots: Result<Vec<(String, i64)>, _> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect();

    let snapshots = snapshots.map_err(|e| {
        DatabaseError::QueryFailed(format!("Failed to fetch snapshots for cleanup: {}", e))
    })?;

    let mut to_delete = std::collections::HashSet::new();

    // Delete by count (keep max_snapshots most recent)
    if max_snapshots > 0 {
        for (id, _) in snapshots.iter().skip(max_snapshots) {
            to_delete.insert(id.clone());
        }
    }

    // Delete by age
    if max_age_days > 0 {
        use chrono::Utc;
        let cutoff_timestamp = Utc::now()
            .checked_sub_signed(chrono::Duration::days(max_age_days as i64))
            .unwrap()
            .timestamp_micros();

        for (id, created_at) in &snapshots {
            if *created_at < cutoff_timestamp {
                to_delete.insert(id.clone());
            }
        }
    }

    // Delete all snapshots in delete list
    let count = to_delete.len();
    for id in to_delete {
        self.delete_snapshot(&id)?;
    }

    Ok(count)
}
```

**Tests:**

```rust
#[test]
fn test_cleanup_retention_disabled() {
    let mut handler = setup_handler();
    // Set both limits to 0 (disabled)
    handler.config.retention.max_snapshots = 0;
    handler.config.retention.max_age_days = 0;

    // Create multiple snapshots
    for i in 0..5 {
        handler.create_snapshot(Some(format!("s{}", i)), "manual".to_string()).unwrap();
    }

    // Manually run cleanup
    let deleted = handler.cleanup_old_snapshots().unwrap();
    assert_eq!(deleted, 0);

    // Verify all snapshots still exist
    let snapshots = handler.list_snapshots(None, None).unwrap();
    assert_eq!(snapshots.len(), 5);
}

#[test]
fn test_cleanup_by_count_only() {
    let mut handler = setup_handler();
    handler.config.retention.max_snapshots = 3;
    handler.config.retention.max_age_days = 0;  // Disabled

    // Create 5 snapshots
    for i in 0..5 {
        handler.create_snapshot(Some(format!("s{}", i)), "manual".to_string()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Cleanup runs automatically in create_snapshot, but verify state
    let snapshots = handler.list_snapshots(None, None).unwrap();
    assert_eq!(snapshots.len(), 3);

    // Verify we kept the 3 most recent (s2, s3, s4)
    assert_eq!(snapshots[0].name, Some("s4".to_string()));
    assert_eq!(snapshots[1].name, Some("s3".to_string()));
    assert_eq!(snapshots[2].name, Some("s2".to_string()));
}

#[test]
fn test_cleanup_by_age_only() {
    let mut handler = setup_handler();
    handler.config.retention.max_snapshots = 0;  // Disabled
    handler.config.retention.max_age_days = 1;  // Keep only 1 day

    // Create snapshots with manual timestamps
    let conn = handler.db.conn();
    use chrono::Utc;

    // Old snapshot (3 days ago)
    let old_timestamp = Utc::now()
        .checked_sub_signed(chrono::Duration::days(3))
        .unwrap()
        .timestamp_micros();

    conn.execute(
        "INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name)
         VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params!["01JDOLD00000000000000000", old_timestamp, "", 0, "manual", "old"],
    ).unwrap();

    // Recent snapshot (1 hour ago)
    let recent_timestamp = Utc::now()
        .checked_sub_signed(chrono::Duration::hours(1))
        .unwrap()
        .timestamp_micros();

    conn.execute(
        "INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name)
         VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params!["01JDNEW00000000000000000", recent_timestamp, "", 0, "manual", "recent"],
    ).unwrap();

    drop(conn);

    // Run cleanup
    let deleted = handler.cleanup_old_snapshots().unwrap();
    assert_eq!(deleted, 1);

    // Verify only recent snapshot remains
    let snapshots = handler.list_snapshots(None, None).unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].name, Some("recent".to_string()));
}

#[test]
fn test_cleanup_or_logic() {
    let mut handler = setup_handler();
    handler.config.retention.max_snapshots = 2;
    handler.config.retention.max_age_days = 1;

    let conn = handler.db.conn();
    use chrono::Utc;

    // Snapshot 1: Old AND beyond count limit (should be deleted)
    let old_timestamp = Utc::now()
        .checked_sub_signed(chrono::Duration::days(3))
        .unwrap()
        .timestamp_micros();

    conn.execute(
        "INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name)
         VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params!["01JDS1000000000000000000", old_timestamp, "", 0, "manual", "s1"],
    ).unwrap();

    // Snapshot 2: Recent but beyond count limit (should be deleted - beyond position 2)
    let recent_timestamp = Utc::now()
        .checked_sub_signed(chrono::Duration::hours(12))
        .unwrap()
        .timestamp_micros();

    conn.execute(
        "INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name)
         VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params!["01JDS2000000000000000000", recent_timestamp, "", 0, "manual", "s2"],
    ).unwrap();

    // Snapshot 3: Very recent (should be kept)
    let very_recent = Utc::now()
        .checked_sub_signed(chrono::Duration::hours(1))
        .unwrap()
        .timestamp_micros();

    conn.execute(
        "INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name)
         VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params!["01JDS3000000000000000000", very_recent, "", 0, "manual", "s3"],
    ).unwrap();

    // Snapshot 4: Very recent (should be kept)
    let very_recent2 = Utc::now().timestamp_micros();

    conn.execute(
        "INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name)
         VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params!["01JDS4000000000000000000", very_recent2, "", 0, "manual", "s4"],
    ).unwrap();

    drop(conn);

    // Run cleanup
    let deleted = handler.cleanup_old_snapshots().unwrap();
    assert_eq!(deleted, 2);  // s1 (old) and s2 (beyond count)

    // Verify only s3 and s4 remain
    let snapshots = handler.list_snapshots(None, None).unwrap();
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].name, Some("s4".to_string()));
    assert_eq!(snapshots[1].name, Some("s3".to_string()));
}
```

**Verification:**
```bash
cargo test -p router-hosts cleanup
```

### Phase 3: gRPC Service Handlers

#### Task 3.1: Implement handle_create_snapshot
**File:** `crates/router-hosts/src/server/service/snapshots.rs`

Replace unimplemented handler:

```rust
pub async fn handle_create_snapshot(
    &self,
    request: Request<CreateSnapshotRequest>,
) -> Result<Response<CreateSnapshotResponse>, Status> {
    let req = request.into_inner();

    // Validate trigger field
    let trigger = if req.trigger.is_empty() {
        "manual".to_string()
    } else {
        req.trigger
    };

    // Create snapshot
    let snapshot = self.command_handler
        .create_snapshot(
            if req.name.is_empty() { None } else { Some(req.name) },
            trigger,
        )
        .map_err(|e| Status::internal(format!("Failed to create snapshot: {}", e)))?;

    Ok(Response::new(CreateSnapshotResponse {
        snapshot_id: snapshot.snapshot_id,
        created_at: snapshot.created_at,
        entry_count: snapshot.entry_count,
    }))
}
```

**Verification:**
```bash
cargo build -p router-hosts
```

#### Task 3.2: Implement handle_list_snapshots
**File:** `crates/router-hosts/src/server/service/snapshots.rs`

Replace unimplemented handler:

```rust
pub async fn handle_list_snapshots(
    &self,
    request: Request<ListSnapshotsRequest>,
) -> Result<Response<Self::ListSnapshotsStream>, Status> {
    let req = request.into_inner();

    // Convert u32 to Option<u32> for limit/offset
    let limit = if req.limit == 0 { None } else { Some(req.limit) };
    let offset = if req.offset == 0 { None } else { Some(req.offset) };

    // List snapshots
    let snapshots = self.command_handler
        .list_snapshots(limit, offset)
        .map_err(|e| Status::internal(format!("Failed to list snapshots: {}", e)))?;

    // Convert to proto snapshots
    let proto_snapshots: Vec<crate::proto::Snapshot> = snapshots
        .into_iter()
        .map(|s| crate::proto::Snapshot {
            snapshot_id: s.snapshot_id,
            created_at: s.created_at,
            entry_count: s.entry_count,
            trigger: s.trigger,
            name: s.name.unwrap_or_default(),
        })
        .collect();

    // Create stream
    let stream = tokio_stream::iter(proto_snapshots.into_iter().map(Ok));

    Ok(Response::new(Box::pin(stream)))
}
```

**Verification:**
```bash
cargo build -p router-hosts
```

#### Task 3.3: Implement handle_delete_snapshot
**File:** `crates/router-hosts/src/server/service/snapshots.rs`

Replace unimplemented handler:

```rust
pub async fn handle_delete_snapshot(
    &self,
    request: Request<DeleteSnapshotRequest>,
) -> Result<Response<DeleteSnapshotResponse>, Status> {
    let req = request.into_inner();

    if req.snapshot_id.is_empty() {
        return Err(Status::invalid_argument("snapshot_id is required"));
    }

    // Delete snapshot
    let deleted = self.command_handler
        .delete_snapshot(&req.snapshot_id)
        .map_err(|e| Status::internal(format!("Failed to delete snapshot: {}", e)))?;

    if !deleted {
        return Err(Status::not_found(format!("Snapshot not found: {}", req.snapshot_id)));
    }

    Ok(Response::new(DeleteSnapshotResponse {}))
}
```

**Verification:**
```bash
cargo build -p router-hosts
```

### Phase 4: Integration Tests

#### Task 4.1: Add gRPC integration tests
**File:** `crates/router-hosts/tests/integration_test.rs`

Add tests at the end of the file:

```rust
#[tokio::test]
async fn test_create_snapshot() {
    let (client, _guard) = setup_test_server().await;

    // Create a snapshot
    let request = CreateSnapshotRequest {
        name: "test-snapshot".to_string(),
        trigger: "manual".to_string(),
    };

    let response = client.create_snapshot(request).await.unwrap().into_inner();

    assert!(!response.snapshot_id.is_empty());
    assert!(response.created_at > 0);
    assert_eq!(response.entry_count, 0);
}

#[tokio::test]
async fn test_list_snapshots() {
    let (client, _guard) = setup_test_server().await;

    // Create multiple snapshots
    for i in 0..3 {
        let request = CreateSnapshotRequest {
            name: format!("snapshot-{}", i),
            trigger: "manual".to_string(),
        };
        client.create_snapshot(request).await.unwrap();
    }

    // List all snapshots
    let request = ListSnapshotsRequest {
        limit: 0,
        offset: 0,
    };

    let mut stream = client.list_snapshots(request).await.unwrap().into_inner();

    let mut count = 0;
    while let Some(snapshot) = stream.message().await.unwrap() {
        assert!(!snapshot.snapshot_id.is_empty());
        count += 1;
    }

    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_delete_snapshot() {
    let (client, _guard) = setup_test_server().await;

    // Create a snapshot
    let create_request = CreateSnapshotRequest {
        name: "to-delete".to_string(),
        trigger: "manual".to_string(),
    };

    let create_response = client.create_snapshot(create_request).await.unwrap().into_inner();
    let snapshot_id = create_response.snapshot_id;

    // Delete it
    let delete_request = DeleteSnapshotRequest {
        snapshot_id: snapshot_id.clone(),
    };

    client.delete_snapshot(delete_request).await.unwrap();

    // Verify it's gone by trying to delete again
    let delete_request2 = DeleteSnapshotRequest {
        snapshot_id,
    };

    let result = client.delete_snapshot(delete_request2).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_snapshot_captures_hosts() {
    let (client, _guard) = setup_test_server().await;

    // Add a host
    let add_request = AddHostRequest {
        ip_address: "192.168.1.100".to_string(),
        hostname: "snapshot-test.local".to_string(),
        comment: Some("test host".to_string()),
        tags: vec!["test".to_string()],
    };

    client.add_host(add_request).await.unwrap();

    // Create snapshot
    let snapshot_request = CreateSnapshotRequest {
        name: "with-host".to_string(),
        trigger: "manual".to_string(),
    };

    let response = client.create_snapshot(snapshot_request).await.unwrap().into_inner();

    assert_eq!(response.entry_count, 1);
}
```

**Verification:**
```bash
cargo test -p router-hosts --test integration_test snapshot
```

## Final Verification

Run complete test suite:
```bash
cargo test --workspace
```

Check test coverage (should remain ≥80%):
```bash
cargo tarpaulin --workspace --fail-under 80
```

Run clippy:
```bash
cargo clippy --workspace -- -D warnings
```

Format code:
```bash
cargo fmt
```

## Success Criteria

- ✅ All CommandHandler methods implemented
- ✅ All service handlers implemented
- ✅ Retention policy enforces both limits with OR logic
- ✅ All unit tests pass
- ✅ All integration tests pass
- ✅ Test coverage ≥80%
- ✅ No clippy warnings
- ✅ Code formatted

## Notes

- DuckDB uses `rusqlite::params!` macro, not `duckdb::params!`
- Timestamps stored as microseconds (i64) for consistency with host_events
- cleanup_old_snapshots is called synchronously in create_snapshot
- Retention disabled when both max_snapshots=0 and max_age_days=0
