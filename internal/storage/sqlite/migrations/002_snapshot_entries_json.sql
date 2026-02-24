-- Add entries_json column to store structured snapshot entries separately
-- from the formatted hosts-file text in hosts_content.
ALTER TABLE snapshots ADD COLUMN entries_json TEXT;

INSERT OR IGNORE INTO schema_version (version, applied_at)
VALUES (2, datetime('now'));
