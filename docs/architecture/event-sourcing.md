# Event Sourcing Architecture

## Overview

The router-hosts server uses **CQRS (Command Query Responsibility Segregation)** with **Event Sourcing** to manage host entries. This architecture replaces the traditional CRUD soft-delete pattern with an immutable append-only event log.

## Why Event Sourcing?

The previous soft-delete CRUD pattern had critical issues:
- Soft deletes complicated queries and data integrity
- Limited audit trail and history
- Difficult time-travel queries
- Complex reactivation logic

Event sourcing solves these problems by:
- **Immutable event log** as the single source of truth
- **Complete audit trail** - every change is recorded as an event
- **Time travel** - reconstruct state at any point in time
- **No soft deletes** - deletion is just another event
- **Optimistic concurrency** via event versioning

## Architecture Components

### 1. Event Store (`event_store.rs`)

The append-only log of all domain events.

**Key features:**
- Optimistic concurrency control via `expected_version`
- Sequential event ordering per aggregate (host entry)
- Efficient event replay for rebuilding state
- DuckDB's JSON and INET extensions

**Schema:**
```sql
CREATE TABLE host_events (
    event_id VARCHAR PRIMARY KEY,         -- ULID for lexicographic ordering
    aggregate_id VARCHAR NOT NULL,        -- ULID of the host entry
    event_type VARCHAR NOT NULL,          -- HostCreated, IpAddressChanged, etc.
    event_version INTEGER NOT NULL,       -- Sequential version per aggregate
    -- Current state columns for queryability
    ip_address INET,                      -- Current IP (for HostCreated, IpAddressChanged, HostDeleted)
    hostname VARCHAR,                     -- Current hostname (for HostCreated, HostnameChanged, HostDeleted)
    event_timestamp TIMESTAMP NOT NULL,   -- When the domain event occurred
    -- Event data: tags, comments, previous values consolidated into JSON
    metadata JSON NOT NULL,               -- Contains EventData struct (see below)
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR,
    -- Optimistic concurrency control
    expected_version INTEGER,
    UNIQUE(aggregate_id, event_version)
)
```

**Metadata JSON Structure (EventData):**
```json
{
  "comment": "optional comment string",
  "tags": ["tag1", "tag2"],
  "previous_ip": "old IP for IpAddressChanged",
  "previous_hostname": "old hostname for HostnameChanged",
  "previous_comment": "old comment for CommentUpdated",
  "previous_tags": ["old", "tags"],
  "deleted_reason": "reason for HostDeleted"
}
```

> **Note:** The `EventMetadata` struct (correlation_id, causation_id, user_agent, source_ip)
> is accepted by the API but **not currently persisted**. Only domain event data is stored.

### 2. Domain Events (`events.rs`)

Immutable facts representing state changes:

- **HostCreated** - New host entry created
- **IpAddressChanged** - IP address modified
- **HostnameChanged** - Hostname modified
- **CommentUpdated** - Comment added/changed
- **TagsModified** - Tags updated
- **HostDeleted** - Tombstone event (not a soft delete!)

Each event contains:
- Event-specific data (old/new values for changes)
- Timestamp when it occurred
- Event metadata (correlation ID, causation ID, etc.)

### 3. Read Models / Projections (`projections.rs`)

Materialized views built from events for efficient queries.

**Current hosts view:**
```sql
CREATE VIEW host_entries_current AS
WITH latest_events AS (
    SELECT
        aggregate_id, event_type, event_version,
        ip_address, hostname, metadata,
        event_timestamp, created_at,
        ROW_NUMBER() OVER (PARTITION BY aggregate_id ORDER BY event_version DESC) as rn
    FROM host_events
)
SELECT
    aggregate_id as id,
    CAST(ip_address AS VARCHAR) as ip_address,
    hostname,
    json_extract_string(metadata, '$.comment') as comment,
    COALESCE(json_extract_string(metadata, '$.tags'), '[]') as tags,
    event_timestamp as created_at,
    created_at as updated_at,
    event_version,
    event_type
FROM latest_events
WHERE rn = 1 AND event_type != 'HostDeleted'
```

> **Note:** Tags and comment are extracted from the `metadata` JSON column using
> DuckDB's `json_extract_string()` function.

**Query methods:**
- `get_by_id()` - Reconstruct aggregate state from events
- `list_all()` - Query current active hosts view
- `list_paginated(limit, offset)` - Paginated listing for large datasets
- `search()` - Search by IP or hostname pattern
- `find_by_ip_and_hostname()` - Exact match lookup
- `get_at_time()` - Time-travel query (rebuild state at timestamp)

### 4. Database Schema (`schema.rs`)

DuckDB schema with event sourcing support:

**Extensions (auto-loaded during initialization):**
- **JSON** - Extract tags/comments from metadata column
- **INET** - Proper IP address type with validation

**Indexes:**
- `idx_events_aggregate` - Fast event replay by aggregate (aggregate_id, event_version)
- `idx_events_time` - Temporal queries (created_at)
- `idx_events_type_hostname` - Optimize view queries (event_type, hostname)

**Views:**
- `host_entries_current` - Active hosts projection (excludes HostDeleted)
- `host_entries_history` - Complete history including deleted

**Thread Safety:**
The `Database` struct wraps a single DuckDB connection. For concurrent access:
- Use `db.try_clone()` to create additional connections sharing the same database
- DuckDB handles synchronization internally for cloned connections

**Transaction Support:**
Use `db.transaction(|conn| { ... })` for atomic multi-statement operations with
automatic commit on success or rollback on error.

## Event Flow

### Creating a Host

```rust
let event = HostEvent::HostCreated {
    ip_address: "192.168.1.10".to_string(),
    hostname: "server.local".to_string(),
    comment: None,
    tags: vec![],
    created_at: Utc::now(),
};

// Append to event store with expected_version = None (first event)
let envelope = EventStore::append_event(
    &db,
    &aggregate_id,
    event,
    None,  // No previous version
    Some("admin".to_string()),
    None
)?;

// Version 1 is now in the event log
assert_eq!(envelope.event_version, 1);
```

### Updating a Host

```rust
// Load current state
let current = HostProjections::get_by_id(&db, &aggregate_id)?;

// Create change event (only store the NEW value)
// The old value is reconstructed from previous events during replay
let event = HostEvent::IpAddressChanged {
    old_ip: current.ip_address.clone(),  // For the domain event
    new_ip: "192.168.1.11".to_string(),
    changed_at: Utc::now(),
};

// Optimistic concurrency: expect current version
let envelope = EventStore::append_event(
    &db,
    &aggregate_id,
    event,
    Some(current.version),  // Expect version N
    Some("admin".to_string()),
    None
)?;

// Database stores only ip_address = "192.168.1.11"
// Old IP is determined by looking at previous events
// If another write happened, returns ConcurrentWriteConflict
```

### Deleting a Host

```rust
let event = HostEvent::HostDeleted {
    ip_address: current.ip_address,
    hostname: current.hostname,
    deleted_at: Utc::now(),
    reason: Some("Decommissioned".to_string()),
};

EventStore::append_event(&db, &aggregate_id, event, Some(current.version), None, None)?;

// Host no longer appears in host_entries_current view
// But complete history remains in event log
```

## Optimistic Concurrency Control

Event versioning prevents lost updates:

```rust
// Thread A loads version 5
let host_a = HostProjections::get_by_id(&db, &id)?;
assert_eq!(host_a.version, 5);

// Thread B loads version 5
let host_b = HostProjections::get_by_id(&db, &id)?;
assert_eq!(host_b.version, 5);

// Thread A writes version 6 (expected 5, OK)
EventStore::append_event(&db, &id, event_a, Some(5), None, None)?;

// Thread B tries to write (expected 5, but current is 6, FAIL)
let result = EventStore::append_event(&db, &id, event_b, Some(5), None, None);
assert!(matches!(result, Err(DatabaseError::ConcurrentWriteConflict(_))));

// Thread B must reload and retry
let host_b = HostProjections::get_by_id(&db, &id)?;
assert_eq!(host_b.version, 6);
EventStore::append_event(&db, &id, event_b, Some(6), None, None)?;
```

## Event Replay & Projections

Rebuild aggregate state from events:

```rust
pub fn rebuild_from_events(events: &[EventEnvelope]) -> Option<HostEntry> {
    let mut state: Option<HostEntry> = None;

    for envelope in events {
        match &envelope.event {
            HostEvent::HostCreated { ip_address, hostname, ... } => {
                state = Some(HostEntry {
                    id: envelope.aggregate_id,
                    ip_address: ip_address.clone(),
                    hostname: hostname.clone(),
                    version: envelope.event_version,
                    // ...
                });
            }
            HostEvent::IpAddressChanged { new_ip, ... } => {
                if let Some(ref mut entry) = state {
                    entry.ip_address = new_ip.clone();
                    entry.version = envelope.event_version;
                }
            }
            HostEvent::HostDeleted { .. } => {
                state = None;  // Tombstone
            }
            // ... handle other events
        }
    }

    state
}
```

## Time Travel Queries

Reconstruct state at any point in time:

```rust
// What was the state at midnight UTC?
let midnight = Utc.with_ymd_and_hms(2025, 11, 29, 0, 0, 0).unwrap();
let historical_state = HostProjections::get_at_time(&db, &aggregate_id, midnight)?;

// Query: WHERE created_at <= ?
// Then replay events up to that timestamp
```

## Benefits

1. **Complete Audit Trail** - Every change recorded with who, when, why
2. **Time Travel** - Query state at any historical point
3. **Event Replay** - Rebuild projections from scratch
4. **No Soft Deletes** - Deletion is just another event
5. **Optimistic Concurrency** - Prevent lost updates
6. **Scalability** - Append-only writes, materialized views for reads
7. **Debugging** - Full history makes troubleshooting easier

## Trade-offs

**Advantages:**
- Immutable event log is tamper-proof
- Complete history enables powerful analytics
- Easy to add new projections without migration
- Natural audit log for compliance

**Considerations:**
- More complex than CRUD
- Storage grows with event count (mitigated by snapshots)
- Eventually consistent read models
- Requires understanding of event sourcing patterns

## DuckDB-Specific Features

**JSON Extension:**
- Stores consolidated event data (tags, comments, previous values) in `metadata` column
- Uses `json_extract_string()` in views for field extraction
- Enables flexible schema evolution without column migrations

**INET Extension:**
- Proper IP address type with validation
- Efficient storage and queries
- Cannot be indexed directly (use VARCHAR cast for indexes)

**Views (not materialized):**
- DuckDB views are computed on query, not pre-materialized
- Fast due to efficient columnar storage
- SQL-based projections from event log

**TIMESTAMP:**
- Microsecond precision stored as i64
- Use `make_timestamp(micros)` to convert from Rust `timestamp_micros()`
- Native temporal comparisons in WHERE clauses

## Future Enhancements

- **Snapshots**: Periodic state snapshots to speed up replay
- **Event Upcasting**: Migrate old event formats
- **Projections Service**: Async projection rebuilding
- **Event Versioning**: Schema evolution for events
- **Saga Pattern**: Distributed transactions across aggregates

## Related Files

- `crates/router-hosts/src/server/db/schema.rs` - Database schema and initialization
- `crates/router-hosts/src/server/db/events.rs` - Domain events and EventData struct
- `crates/router-hosts/src/server/db/event_store.rs` - Event persistence and loading
- `crates/router-hosts/src/server/db/projections.rs` - Read models and queries
- `crates/router-hosts/src/server/db/mod.rs` - Module exports

## References

- [Event Sourcing by Martin Fowler](https://martinfowler.com/eaaDev/EventSourcing.html)
- [CQRS Pattern](https://docs.microsoft.com/en-us/azure/architecture/patterns/cqrs)
- [DuckDB JSON Extension](https://duckdb.org/docs/extensions/json)
- [DuckDB INET Extension](https://duckdb.org/docs/extensions/inet)
