# Snapshot Management with Retention Policy

**Date:** 2025-12-08
**Status:** Approved
**Issue:** #48 - feat(server): implement snapshot retention policy

## Overview

Implement snapshot management functionality for router-hosts, including creation, listing, deletion, and automatic retention policy enforcement.

## Requirements

### Functional Requirements

1. **Create snapshots** - Capture current hosts file state to database
2. **List snapshots** - Query available snapshots with pagination
3. **Delete snapshots** - Remove snapshots by ID
4. **Retention policy** - Automatically clean up old snapshots based on configured limits

### Configuration

Retention settings in `server.toml`:
```toml
[retention]
max_snapshots = 50        # Keep at most N most recent snapshots
max_age_days = 30         # Delete snapshots older than N days
```

Both limits use OR logic: delete snapshot if it violates **either** limit.

## Design Decisions

### 1. Snapshot Triggers

- **v1 implementation:** Manual snapshots only (trigger="manual")
- **Future support:** "pre-rollback" trigger when implementing RollbackToSnapshot
- Schema supports trigger field for extensibility

### 2. Snapshot Content Source

Generate from database state, not from reading `/etc/hosts`:
- Database is source of truth
- Consistent behavior (no file I/O errors)
- Manual edits to `/etc/hosts` should go through import command

### 3. Snapshot Naming

Optional user-provided name with auto-generated fallback:
- User can provide meaningful names ("before-migration", "stable-config")
- Default: `snapshot-{timestamp}` format (e.g., "snapshot-20251208-143052")
- Name stored in `name` column (nullable)

### 4. Retention Execution

Synchronous cleanup after CreateSnapshot:
- Guarantees retention limits are enforced
- Snapshot creation is infrequent, so latency is acceptable
- Simpler than async background tasks

### 5. Retention Logic

OR logic for limit enforcement:
- Delete if `created_at < (now - max_age_days)` **OR** snapshot is beyond position `max_snapshots`
- Both limits are strictly enforced
- Disabled when limit is 0 (keep all)

## Architecture

### Component Structure

**CommandHandler** (`server/commands.rs`) - New methods:
```rust
pub fn create_snapshot(
    &self,
    name: Option<String>,
    trigger: String
) -> Result<Snapshot>

pub fn list_snapshots(
    &self,
    limit: Option<u32>,
    offset: Option<u32>
) -> Result<Vec<Snapshot>>

pub fn delete_snapshot(
    &self,
    snapshot_id: &str
) -> Result<bool>

fn cleanup_old_snapshots(&self) -> Result<usize>
```

**Service handlers** (`server/service/snapshots.rs`) - Convert gRPC to CommandHandler calls

**Database schema** (already exists):
```sql
CREATE TABLE snapshots (
    snapshot_id VARCHAR PRIMARY KEY,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    hosts_content TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    trigger VARCHAR NOT NULL,
    name VARCHAR,
    event_log_position INTEGER
)
```

### Data Flow: CreateSnapshot

1. Client sends `CreateSnapshotRequest` (with optional name)
2. Service handler validates request, calls `CommandHandler::create_snapshot()`
3. CommandHandler:
   - Generates ULID for `snapshot_id`
   - Queries current projections (all active hosts)
   - Formats as hosts file content using `HostsFileGenerator`
   - Gets entry count
   - Inserts to snapshots table with trigger="manual"
   - Calls `cleanup_old_snapshots()` synchronously
   - Returns Snapshot
4. Service handler converts to `CreateSnapshotResponse`
5. Client receives `snapshot_id`, `created_at`, `entry_count`

## Implementation Details

### Snapshot Content Generation

Reuse existing `HostsFileGenerator` logic:
```rust
// Query all active hosts
let hosts = self.db.projections().list_all()?;
let entry_count = hosts.len();

// Generate hosts file content
let hosts_content = self.hosts_file.format_entries(&hosts)?;

// Generate snapshot name
let snapshot_name = name.unwrap_or_else(|| {
    format!("snapshot-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"))
});

// Insert snapshot
let snapshot_id = Ulid::new().to_string();
self.db.conn().execute(
    "INSERT INTO snapshots (snapshot_id, created_at, hosts_content,
     entry_count, trigger, name, event_log_position)
     VALUES (?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)",
    [&snapshot_id, &hosts_content, &entry_count, &trigger,
     &snapshot_name, &None::<i64>]
)?;
```

**Event log position:**
- Set to `None` in v1 (schema supports it for future point-in-time recovery)
- Future enhancement: Capture current max event_id from event store

### Retention Cleanup Algorithm

```rust
fn cleanup_old_snapshots(&self) -> Result<usize> {
    let max_snapshots = self.config.retention.max_snapshots;
    let max_age_days = self.config.retention.max_age_days;

    // Retention disabled if both limits are 0
    if max_snapshots == 0 && max_age_days == 0 {
        return Ok(0);
    }

    // Query all snapshots ordered newest first
    let snapshots: Vec<(String, i64)> = self.db.conn()
        .prepare("SELECT snapshot_id, created_at FROM snapshots
                  ORDER BY created_at DESC")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()?;

    let mut to_delete = HashSet::new();

    // Delete by count (keep max_snapshots most recent)
    if max_snapshots > 0 {
        for (id, _) in snapshots.iter().skip(max_snapshots) {
            to_delete.insert(id.clone());
        }
    }

    // Delete by age
    if max_age_days > 0 {
        let cutoff_timestamp = /* now - max_age_days */;
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

### Error Handling

**gRPC Status Code Mapping:**
- Snapshot not found → `NOT_FOUND`
- Database error → `INTERNAL`
- Invalid snapshot_id format → `INVALID_ARGUMENT`

**Edge Cases:**
- Empty database (0 hosts) → Allow, create snapshot with 0 entries
- Concurrent creates → ULIDs ensure unique IDs, cleanup is idempotent
- Deletion during iteration → Collect IDs first, then delete
- Retention disabled → Check if both limits are 0, skip cleanup

## Testing Strategy

### Unit Tests

**CommandHandler tests:**
- Create snapshot with custom name
- Create snapshot without name (auto-generated)
- Create snapshot with 0 entries (empty database)
- Verify snapshot content matches formatted hosts
- List empty snapshots table
- List multiple snapshots (verify DESC ordering)
- List with limit/offset pagination
- Delete existing snapshot
- Delete non-existent snapshot (returns false)

**Retention cleanup tests:**
- Delete by count only (keep N most recent)
- Delete by age only (delete older than N days)
- Delete by both (OR logic)
- No deletion when under both limits
- Retention disabled (both max=0)
- Verify deletion count

### Integration Tests

**gRPC end-to-end:**
- Create snapshot via gRPC, verify in database
- List snapshots, verify ordering and content
- Delete snapshot, verify removal
- Create multiple snapshots, verify retention cleanup runs
- Verify snapshot content matches current hosts state

## Out of Scope (v1)

- **RollbackToSnapshot** - Follow-up issue
  - Will create "pre-rollback" snapshot automatically
  - Restore hosts from snapshot content
- **Event log position tracking** - Schema supports it, not used in v1
- **Async retention cleanup** - Synchronous is sufficient for v1
- **Scheduled snapshots** - Use cron + CLI for now
- **Snapshot compression** - TEXT column is sufficient

## Success Criteria

- ✅ Can create manual snapshots via gRPC
- ✅ Snapshots capture current hosts file state accurately
- ✅ Can list snapshots ordered by created_at
- ✅ Can delete snapshots by ID
- ✅ Retention policy enforces both max_snapshots and max_age_days
- ✅ All unit tests pass (≥80% coverage)
- ✅ Integration tests verify end-to-end functionality

## Future Enhancements

1. **Automatic rollback snapshots** (#TBD)
   - Create "pre-rollback" snapshot before restoring
2. **Scheduled snapshots** (#TBD)
   - Cron integration or internal scheduler
3. **Snapshot compression** (#TBD)
   - Compress hosts_content for large installations
4. **Point-in-time recovery** (#TBD)
   - Use event_log_position to rebuild state at snapshot time
5. **Snapshot export/import** (#TBD)
   - Transfer snapshots between instances
