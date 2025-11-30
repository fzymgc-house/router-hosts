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
    event_id VARCHAR PRIMARY KEY,
    aggregate_id VARCHAR NOT NULL,
    event_type VARCHAR NOT NULL,
    event_version INTEGER NOT NULL,
    -- Event-specific typed columns (only JSON for tags array)
    ip_address INET,
    hostname VARCHAR,
    comment VARCHAR,
    tags JSON,
    deleted_reason VARCHAR,
    event_timestamp TIMESTAMP NOT NULL,
    -- Event metadata
    event_metadata JSON,
    created_at TIMESTAMP NOT NULL,
    created_by VARCHAR,
    -- Optimistic concurrency control
    expected_version INTEGER,
    UNIQUE(aggregate_id, event_version)
)
```

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
        ip_address, hostname, comment, tags,
        event_timestamp, created_at,
        ROW_NUMBER() OVER (PARTITION BY aggregate_id ORDER BY event_version DESC) as rn
    FROM host_events
)
SELECT
    aggregate_id as id,
    CAST(ip_address AS VARCHAR) as ip_address,
    hostname,
    comment,
    COALESCE(CAST(tags AS VARCHAR), '[]') as tags,
    event_timestamp as created_at,
    created_at as updated_at,
    event_version,
    event_type
FROM latest_events
WHERE rn = 1 AND event_type != 'HostDeleted'
```

**Query methods:**
- `get_by_id()` - Reconstruct aggregate state from events
- `list_all()` - Query current active hosts view
- `search()` - Search by IP or hostname pattern
- `find_by_ip_and_hostname()` - Exact match lookup
- `get_at_time()` - Time-travel query (rebuild state at timestamp)

### 4. Database Schema (`schema_v2.rs`)

DuckDB schema with event sourcing support:

**Extensions:**
- **JSON** - Store events as JSON documents
- **INET** - Proper IP address validation and queries

**Indexes:**
- `idx_events_aggregate` - Fast event replay by aggregate
- `idx_events_time` - Temporal queries

**Views:**
- `host_entries_current` - Active hosts projection
- `host_entries_history` - Complete history including deleted

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
- Used only for tags array storage
- First-class typed columns for all other fields
- More efficient than storing everything in JSON

**INET Extension:**
- Proper IP address type
- Built-in validation
- Efficient storage and queries

**Materialized Views:**
- Fast queries without event replay
- Automatically updated
- SQL-based projections

**TIMESTAMP:**
- Microsecond precision
- Native temporal queries
- Time-travel support

## Future Enhancements

- **Snapshots**: Periodic state snapshots to speed up replay
- **Event Upcasting**: Migrate old event formats
- **Projections Service**: Async projection rebuilding
- **Event Versioning**: Schema evolution for events
- **Saga Pattern**: Distributed transactions across aggregates

## Related Files

- `crates/router-hosts/src/server/db/schema_v2.rs` - Database schema
- `crates/router-hosts/src/server/db/events.rs` - Domain events
- `crates/router-hosts/src/server/db/event_store.rs` - Event persistence
- `crates/router-hosts/src/server/db/projections.rs` - Read models

## References

- [Event Sourcing by Martin Fowler](https://martinfowler.com/eaaDev/EventSourcing.html)
- [CQRS Pattern](https://docs.microsoft.com/en-us/azure/architecture/patterns/cqrs)
- [DuckDB JSON Extension](https://duckdb.org/docs/extensions/json)
- [DuckDB INET Extension](https://duckdb.org/docs/extensions/inet)
