-- Initial schema for PostgreSQL event-sourced storage
--
-- Creates all tables, indexes, and views for the CQRS event sourcing pattern.
-- Uses PostgreSQL-specific features like TIMESTAMPTZ and DISTINCT ON.

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
    event_timestamp TIMESTAMPTZ NOT NULL,
    metadata TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
-- PostgreSQL doesn't support IGNORE NULLS, so we use DISTINCT ON with CTEs
-- to get the last non-null value for each column
CREATE VIEW IF NOT EXISTS host_entries_current AS
WITH
-- Get the latest event for each aggregate to determine if deleted
latest_events AS (
    SELECT DISTINCT ON (aggregate_id)
        aggregate_id,
        event_type as latest_event_type,
        event_version,
        created_at as updated_at
    FROM host_events
    ORDER BY aggregate_id, event_version DESC
),
-- Get first event timestamp (created_at)
first_events AS (
    SELECT DISTINCT ON (aggregate_id)
        aggregate_id,
        event_timestamp as created_at
    FROM host_events
    ORDER BY aggregate_id, event_version ASC
),
-- Get last non-null ip_address
ip_values AS (
    SELECT DISTINCT ON (aggregate_id)
        aggregate_id,
        ip_address
    FROM host_events
    WHERE ip_address IS NOT NULL
    ORDER BY aggregate_id, event_version DESC
),
-- Get last non-null hostname
hostname_values AS (
    SELECT DISTINCT ON (aggregate_id)
        aggregate_id,
        hostname
    FROM host_events
    WHERE hostname IS NOT NULL
    ORDER BY aggregate_id, event_version DESC
),
-- Get last non-null comment
comment_values AS (
    SELECT DISTINCT ON (aggregate_id)
        aggregate_id,
        comment
    FROM host_events
    WHERE comment IS NOT NULL
    ORDER BY aggregate_id, event_version DESC
),
-- Get last non-null tags
tags_values AS (
    SELECT DISTINCT ON (aggregate_id)
        aggregate_id,
        tags
    FROM host_events
    WHERE tags IS NOT NULL
    ORDER BY aggregate_id, event_version DESC
),
-- Get last non-null aliases
aliases_values AS (
    SELECT DISTINCT ON (aggregate_id)
        aggregate_id,
        aliases
    FROM host_events
    WHERE aliases IS NOT NULL
    ORDER BY aggregate_id, event_version DESC
)
SELECT
    le.aggregate_id as id,
    ip.ip_address,
    hn.hostname,
    cv.comment,
    tv.tags,
    av.aliases,
    fe.created_at,
    le.updated_at,
    le.event_version
FROM latest_events le
LEFT JOIN first_events fe ON fe.aggregate_id = le.aggregate_id
LEFT JOIN ip_values ip ON ip.aggregate_id = le.aggregate_id
LEFT JOIN hostname_values hn ON hn.aggregate_id = le.aggregate_id
LEFT JOIN comment_values cv ON cv.aggregate_id = le.aggregate_id
LEFT JOIN tags_values tv ON tv.aggregate_id = le.aggregate_id
LEFT JOIN aliases_values av ON av.aggregate_id = le.aggregate_id
WHERE le.latest_event_type != 'HostDeleted';

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
ORDER BY aggregate_id, event_version;

-- Snapshots table for /etc/hosts versioning
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hosts_content TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    trigger TEXT NOT NULL,
    name TEXT,
    event_log_position BIGINT
);

-- Index for snapshot queries by time
CREATE INDEX IF NOT EXISTS idx_snapshots_created ON snapshots(created_at DESC);
