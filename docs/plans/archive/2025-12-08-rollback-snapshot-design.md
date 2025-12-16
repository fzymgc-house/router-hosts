# Rollback to Snapshot Design

**Date:** 2025-12-08
**Status:** ✅ Implemented (PR #63)
**Issue:** #58

## Summary

Implement `RollbackToSnapshot` RPC to restore the hosts database to a previous snapshot state by parsing the snapshot's hosts file content and recreating entries.

## Background

The `RollbackToSnapshot` RPC is defined in the protobuf schema and listed as complete in project documentation, but returns `Status::unimplemented`. This design implements the feature using existing import/export infrastructure.

## Design Approach

**Selected: Approach A - Reuse Import Logic**

Parse snapshot `hosts_content` using existing `parse_hosts_format()`, delete current entries, import parsed entries.

**Alternatives considered:**
- **Approach B:** Store full JSON host data in snapshots (requires migration)
- **Approach C:** Event log position replay (not yet implemented)

**Rationale:** Approach A reuses battle-tested code, requires no schema changes, and correctly round-trips tags/comments through the hosts file format.

## High-Level Flow

```
1. Validate snapshot exists
2. Create pre-rollback backup snapshot (trigger="pre-rollback")
3. Query current active hosts
4. Parse snapshot hosts_content using parse_hosts_format()
5. Delete all current hosts (tombstone events)
6. Import parsed entries (add_host for each)
7. Regenerate /etc/hosts file
8. Execute post-edit hooks
9. Return success + backup snapshot ID
```

## Implementation

### Command Handler

**Location:** `crates/router-hosts/src/server/commands.rs`

**Method signature:**
```rust
pub fn rollback_to_snapshot(
    &self,
    snapshot_id: &str,
) -> CommandResult<RollbackResult>
```

**Return type:**
```rust
pub struct RollbackResult {
    pub success: bool,
    pub backup_snapshot_id: String,
    pub restored_entry_count: i32,
}
```

**Steps:**

1. **Fetch snapshot:**
   ```rust
   let snapshot = conn.query_row(
       "SELECT hosts_content, entry_count FROM snapshots WHERE snapshot_id = ?",
       [snapshot_id],
       |row| Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
   ).map_err(|_| CommandError::NotFound("Snapshot not found"))?;
   ```

2. **Create backup:**
   ```rust
   let backup = self.create_snapshot(None, "pre-rollback".to_string())?;
   let backup_snapshot_id = backup.snapshot_id;
   ```

3. **Parse snapshot content:**
   ```rust
   let parsed_entries = parse_import(
       snapshot.0.as_bytes(),
       ImportFormat::Hosts
   ).map_err(|e| CommandError::ValidationFailed(format!("Parse error: {}", e)))?;
   ```

4. **Clear current state:**
   ```rust
   let current_hosts = HostProjections::list_all(&self.db)?;
   for host in current_hosts {
       self.delete_host(&host.id)?; // Creates tombstone events
   }
   ```

5. **Import entries:**
   ```rust
   let mut restored_count = 0;
   for entry in parsed_entries {
       match self.add_host(
           entry.ip_address,
           entry.hostname,
           entry.comment,
           entry.tags
       ) {
           Ok(_) => restored_count += 1,
           Err(e) => warn!("Failed to restore entry: {}", e),
       }
   }
   ```

6. **Regenerate file:**
   ```rust
   self.generate_hosts_file()?; // Includes hook execution
   ```

7. **Return result:**
   ```rust
   Ok(RollbackResult {
       success: true,
       backup_snapshot_id,
       restored_entry_count: restored_count,
   })
   ```

### Service Layer

**Location:** `crates/router-hosts/src/server/service/snapshots.rs`

Replace unimplemented stub:

```rust
pub async fn handle_rollback_to_snapshot(
    &self,
    request: Request<RollbackToSnapshotRequest>,
) -> Result<Response<RollbackToSnapshotResponse>, Status> {
    let req = request.into_inner();

    if req.snapshot_id.is_empty() {
        return Err(Status::invalid_argument("snapshot_id required"));
    }

    let result = self.commands
        .rollback_to_snapshot(&req.snapshot_id)
        .map_err(|e| match e {
            CommandError::NotFound(_) => Status::not_found(e.to_string()),
            CommandError::ValidationFailed(m) => Status::invalid_argument(m),
            _ => Status::internal(e.to_string()),
        })?;

    Ok(Response::new(RollbackToSnapshotResponse {
        success: result.success,
        new_snapshot_id: result.backup_snapshot_id,
    }))
}
```

## Error Handling

| Error Type | gRPC Status | Scenario |
|------------|-------------|----------|
| `CommandError::NotFound` | `NOT_FOUND` | Snapshot doesn't exist |
| `CommandError::ValidationFailed` | `INVALID_ARGUMENT` | Parse failures, empty snapshot_id |
| Parse errors during import | Logged, continues | Individual entry validation failures |
| Database errors | `INTERNAL` | Query failures, connection issues |
| File generation errors | `INTERNAL` | Hosts file write failures |

**Partial failures:** Validation failures for individual entries are logged but don't fail the entire rollback. The backup snapshot provides recovery if needed.

**Atomicity:** Not fully atomic (delete-then-add pattern), but backup snapshot created first provides recovery path. Full atomicity would require complex transaction handling across event store.

## Data Flow

```
┌─────────────────┐
│  Snapshot DB    │
│  snapshot_id    │
│  hosts_content  │ (TEXT: formatted /etc/hosts)
└────────┬────────┘
         │
         v
  parse_hosts_format()
         │
         v
   Vec<ParsedEntry>
   { ip, hostname, comment, tags }
         │
         ├──> Current hosts → delete_host() → Tombstone events
         │
         └──> ParsedEntry → add_host() → HostCreated events
                    │
                    v
            Regenerate /etc/hosts
                    │
                    v
              Execute hooks
                    │
                    v
              Return response
         { success, backup_snapshot_id }
```

## Testing Strategy

### Integration Tests

**Location:** `crates/router-hosts/tests/integration_test.rs`

1. **`test_rollback_to_snapshot_basic`**
   - Setup: Create host1, snapshot, modify host1 + add host2
   - Action: Rollback to snapshot
   - Assert: State restored to 1 host with original values
   - Assert: Backup snapshot created

2. **`test_rollback_preserves_tags_and_comments`**
   - Setup: Create hosts with tags/comments, snapshot, delete all
   - Action: Rollback
   - Assert: Tags and comments restored correctly

3. **`test_rollback_to_nonexistent_snapshot`**
   - Action: Rollback to fake snapshot_id
   - Assert: Returns `NOT_FOUND` error

4. **`test_rollback_creates_backup_snapshot`**
   - Setup: State A → snapshot1 → State B
   - Action: Rollback to snapshot1
   - Assert: Pre-rollback backup contains State B
   - Assert: Can rollback to backup (undo the undo)

5. **`test_rollback_regenerates_hosts_file`**
   - Action: Rollback and read /etc/hosts
   - Assert: File matches snapshot content
   - Assert: Hooks executed

### Coverage Target

Bring `service/snapshots.rs` from 89.3% to 95%+ by testing rollback paths.

## Trade-offs

**Pros:**
- ✅ Reuses existing, tested import/parse code
- ✅ No database migration required
- ✅ Tags/comments round-trip correctly
- ✅ Backup snapshot provides undo capability
- ✅ Consistent with import workflow

**Cons:**
- ❌ Loses original entry IDs (generates new ULIDs)
- ❌ Loses original timestamps (uses current time)
- ❌ Not fully atomic (delete-add pattern)
- ❌ Creates many events in event log

**Mitigations:**
- Loss of IDs/timestamps acceptable for rollback scenario
- Backup snapshot provides recovery from failures
- Event log growth is normal for event sourcing

## Future Enhancements

1. **Event log position replay** (Approach C)
   - Implement `event_log_position` tracking
   - Replay events from specific point
   - True event sourcing rollback

2. **Snapshot schema v2** (Approach B)
   - Store JSON array of complete HostEntry objects
   - Preserve all metadata (IDs, timestamps, versions)
   - Requires migration strategy

3. **Transactional rollback**
   - Wrap delete+add in single transaction
   - Requires event store transaction support

## Related

- Issue #17: Test coverage audit (exposed unimplemented rollback)
- PR #59: Added snapshot tests, discovered this gap
- Proto: `proto/router_hosts/v1/hosts.proto:281-293, 346`
