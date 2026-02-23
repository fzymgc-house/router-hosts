-- Events table (append-only event store)
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_data TEXT NOT NULL,
    event_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_aggregate ON events(aggregate_id, event_version);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

-- Snapshots table
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    hosts_content TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    trigger_type TEXT NOT NULL,
    name TEXT,
    event_log_position INTEGER
);

CREATE INDEX IF NOT EXISTS idx_snapshots_created_at ON snapshots(created_at);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_version (version, applied_at)
VALUES (1, datetime('now'));
