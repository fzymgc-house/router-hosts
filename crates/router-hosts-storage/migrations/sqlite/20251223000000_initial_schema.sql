-- Initial schema for SQLite event-sourced storage
--
-- This creates all tables, indexes, and views for the CQRS event sourcing pattern.
--
-- Note on ordering: We use SQLite's rowid for ordering instead of event_version
-- because ULIDs created within the same millisecond have arbitrary lexicographic
-- order determined by the random suffix, not insertion order.
--
-- IMPORTANT: View Update Strategy
-- --------------------------------
-- This migration uses CREATE VIEW IF NOT EXISTS which is appropriate for initial
-- schema creation. However, if a view definition needs to change in a future
-- migration, you MUST use DROP VIEW + CREATE VIEW pattern:
--
--   DROP VIEW IF EXISTS host_entries_current;
--   CREATE VIEW host_entries_current AS ...
--
-- The IF NOT EXISTS clause will NOT update an existing view, so changes would
-- be silently skipped. Always use the DROP + CREATE pattern for view modifications.

-- Event store - append-only immutable log of all domain events
CREATE TABLE IF NOT EXISTS host_events (
    event_id TEXT PRIMARY KEY,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_version TEXT NOT NULL,
    ip_address TEXT,
    hostname TEXT,
    comment TEXT,
    tags TEXT,
    aliases TEXT,
    event_timestamp INTEGER NOT NULL,
    metadata TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    created_by TEXT,
    expected_version TEXT,
    UNIQUE(aggregate_id, event_version)
);

-- Index for fast event replay by aggregate
CREATE INDEX IF NOT EXISTS idx_events_aggregate ON host_events(aggregate_id, event_version);

-- Index for temporal queries
CREATE INDEX IF NOT EXISTS idx_events_time ON host_events(created_at);

-- Compound index for duplicate checking and lookups by (ip_address, hostname)
CREATE INDEX IF NOT EXISTS idx_events_ip_hostname ON host_events(ip_address, hostname);

-- Read model: Current active hosts projection
-- SQLite doesn't support IGNORE NULLS, so we use correlated subqueries
-- to find the last non-null value for each field.
--
-- PERFORMANCE: This view is optimized for correctness over speed.
-- Each query triggers 7 correlated subqueries per host, scaling as O(n * m)
-- where n = hosts and m = events per host. For deployments with >1,000 hosts,
-- consider the DuckDB backend which uses window functions with IGNORE NULLS.
CREATE VIEW IF NOT EXISTS host_entries_current AS
WITH latest_events AS (
    SELECT
        aggregate_id,
        MAX(rowid) as max_rowid
    FROM host_events
    GROUP BY aggregate_id
),
latest_event_details AS (
    SELECT
        e.aggregate_id,
        e.event_type as latest_event_type,
        e.event_version as max_version
    FROM host_events e
    INNER JOIN latest_events le ON e.aggregate_id = le.aggregate_id AND e.rowid = le.max_rowid
)
SELECT
    e.aggregate_id as id,
    -- Get last non-null ip_address
    (SELECT ip_address FROM host_events h
     WHERE h.aggregate_id = e.aggregate_id AND h.ip_address IS NOT NULL
     ORDER BY h.rowid DESC LIMIT 1) as ip_address,
    -- Get last non-null hostname
    (SELECT hostname FROM host_events h
     WHERE h.aggregate_id = e.aggregate_id AND h.hostname IS NOT NULL
     ORDER BY h.rowid DESC LIMIT 1) as hostname,
    -- Get last non-null comment
    (SELECT comment FROM host_events h
     WHERE h.aggregate_id = e.aggregate_id AND h.comment IS NOT NULL
     ORDER BY h.rowid DESC LIMIT 1) as comment,
    -- Get last non-null tags
    (SELECT tags FROM host_events h
     WHERE h.aggregate_id = e.aggregate_id AND h.tags IS NOT NULL
     ORDER BY h.rowid DESC LIMIT 1) as tags,
    -- Get last non-null aliases
    (SELECT aliases FROM host_events h
     WHERE h.aggregate_id = e.aggregate_id AND h.aliases IS NOT NULL
     ORDER BY h.rowid DESC LIMIT 1) as aliases,
    -- First event timestamp as created_at
    (SELECT event_timestamp FROM host_events h
     WHERE h.aggregate_id = e.aggregate_id
     ORDER BY h.rowid ASC LIMIT 1) as created_at,
    -- Last event created_at as updated_at
    (SELECT created_at FROM host_events h
     WHERE h.aggregate_id = e.aggregate_id
     ORDER BY h.rowid DESC LIMIT 1) as updated_at,
    -- Current version
    led.max_version as event_version
FROM latest_events le
INNER JOIN host_events e ON e.aggregate_id = le.aggregate_id AND e.rowid = le.max_rowid
INNER JOIN latest_event_details led ON led.aggregate_id = e.aggregate_id
WHERE led.latest_event_type != 'HostDeleted'
GROUP BY e.aggregate_id;

-- Read model: Complete history including deleted entries
CREATE VIEW IF NOT EXISTS host_entries_history AS
SELECT
    event_id,
    aggregate_id,
    event_type,
    event_version,
    ip_address,
    hostname,
    metadata,
    event_timestamp,
    created_at
FROM host_events
ORDER BY aggregate_id, rowid;

-- Snapshots table for /etc/hosts versioning
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    hosts_content TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    trigger TEXT NOT NULL,
    name TEXT,
    event_log_position INTEGER
);

-- Index for snapshot queries by time
CREATE INDEX IF NOT EXISTS idx_snapshots_created ON snapshots(created_at DESC);
