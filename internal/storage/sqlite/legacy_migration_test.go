package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sqlib "zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// createRustSchema creates the Rust-era database schema (host_events + snapshots)
// without any Go tables.
func createRustSchema(t *testing.T, conn *sqlib.Conn) {
	t.Helper()
	ddl := `
		CREATE TABLE host_events (
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
		CREATE INDEX idx_events_aggregate ON host_events(aggregate_id, event_version);
		CREATE INDEX idx_events_time ON host_events(created_at);
		CREATE INDEX idx_events_ip_hostname ON host_events(ip_address, hostname);

		CREATE VIEW host_entries_current AS
		SELECT aggregate_id AS id FROM host_events LIMIT 0;

		CREATE VIEW host_entries_history AS
		SELECT event_id FROM host_events LIMIT 0;

		CREATE TABLE snapshots (
			snapshot_id TEXT PRIMARY KEY,
			created_at INTEGER NOT NULL,
			hosts_content TEXT NOT NULL,
			entry_count INTEGER NOT NULL,
			trigger TEXT NOT NULL,
			name TEXT,
			event_log_position INTEGER
		);
		CREATE INDEX idx_snapshots_created ON snapshots(created_at DESC);

		CREATE TABLE _sqlx_migrations (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			installed_on TEXT NOT NULL,
			success INTEGER NOT NULL
		);
		INSERT INTO _sqlx_migrations VALUES (20251223000000, 'initial_schema', '2025-12-23', 1);
	`
	require.NoError(t, sqlitex.ExecuteScript(conn, ddl, nil))
}

// insertRustEvent inserts an event in the Rust host_events format.
func insertRustEvent(t *testing.T, conn *sqlib.Conn, eventID, aggregateID, eventType, eventVersion string, ip, hostname, comment, tags, aliases *string, eventTimestampMicros, createdAtMicros int64, metadata string, createdBy *string) {
	t.Helper()
	require.NoError(t, sqlitex.Execute(conn,
		`INSERT INTO host_events (event_id, aggregate_id, event_type, event_version,
		    ip_address, hostname, comment, tags, aliases,
		    event_timestamp, metadata, created_at, created_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		&sqlitex.ExecOptions{
			Args: []any{
				eventID, aggregateID, eventType, eventVersion,
				ptrToAny(ip), ptrToAny(hostname), ptrToAny(comment), ptrToAny(tags), ptrToAny(aliases),
				eventTimestampMicros, metadata, createdAtMicros, ptrToAny(createdBy),
			},
		}))
}

func insertRustSnapshot(t *testing.T, conn *sqlib.Conn, snapshotID string, createdAtMicros int64, hostsContent string, entryCount int64, trigger string, name *string) {
	t.Helper()
	require.NoError(t, sqlitex.Execute(conn,
		`INSERT INTO snapshots (snapshot_id, created_at, hosts_content, entry_count, trigger, name)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		&sqlitex.ExecOptions{
			Args: []any{snapshotID, createdAtMicros, hostsContent, entryCount, trigger, ptrToAny(name)},
		}))
}

func strPtr(s string) *string { return &s }

// newLegacyTestStore creates a Storage backed by an in-memory SQLite database
// with the Rust schema pre-populated, then applies Go migrations (which
// creates the empty Go tables alongside the Rust tables).
func newLegacyTestStore(t *testing.T) (*Storage, *sqlib.Conn) {
	t.Helper()

	pool, err := sqlitex.NewPool("file::memory:?mode=memory&cache=shared", sqlitex.PoolOptions{PoolSize: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })

	store := &Storage{pool: pool, log: slog.Default()}

	// Take connection and create the Rust schema BEFORE Go migrations.
	conn, err := pool.Take(context.Background())
	require.NoError(t, err)

	createRustSchema(t, conn)

	// Now apply Go SQL migrations (001 + 002) on top.
	// 001: CREATE TABLE IF NOT EXISTS events/snapshots/schema_version → events is new, snapshots is no-op.
	// 002: ALTER TABLE snapshots ADD COLUMN entries_json.
	for _, m := range migrationFiles {
		sql, readErr := migrations.ReadFile(m.path)
		require.NoError(t, readErr)
		require.NoError(t, sqlitex.ExecuteScript(conn, string(sql), nil))
	}

	return store, conn
}

func TestLegacyMigration_HostCreated(t *testing.T) {
	store, conn := newLegacyTestStore(t)
	defer store.pool.Put(conn)

	aggID := ulid.Make()
	ts := time.Date(2025, 12, 1, 10, 0, 0, 0, time.UTC)
	tsMicros := ts.UnixMicro()
	tags := `["infra","k8s"]`
	aliases := `["router","gw"]`
	comment := "main gateway"
	meta := `{"comment":"main gateway","tags":["infra","k8s"],"aliases":["router","gw"]}`

	insertRustEvent(t, conn, ulid.Make().String(), aggID.String(), "HostCreated",
		ulid.Make().String(), strPtr("192.168.1.1"), strPtr("gateway.local"),
		&comment, &tags, &aliases, tsMicros, tsMicros, meta, nil)

	// Run migration.
	require.NoError(t, migrateLegacyRustData(conn, slog.Default()))

	// Verify: events table should have 1 row.
	var count int64
	require.NoError(t, sqlitex.Execute(conn, `SELECT COUNT(*) FROM events`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlib.Stmt) error { count = stmt.ColumnInt64(0); return nil },
	}))
	assert.Equal(t, int64(1), count)

	// Verify event_data is valid JSON with correct fields.
	var eventData string
	require.NoError(t, sqlitex.Execute(conn, `SELECT event_data FROM events`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlib.Stmt) error { eventData = stmt.ColumnText(0); return nil },
	}))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(eventData), &parsed))
	assert.Equal(t, "HostCreated", parsed["type"])
	assert.Equal(t, "192.168.1.1", parsed["ip_address"])
	assert.Equal(t, "gateway.local", parsed["hostname"])

	// Verify version is 1 (sequential).
	var version int64
	require.NoError(t, sqlitex.Execute(conn, `SELECT event_version FROM events`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlib.Stmt) error { version = stmt.ColumnInt64(0); return nil },
	}))
	assert.Equal(t, int64(1), version)

	// Verify legacy tables dropped.
	assert.False(t, tableExists(conn, "host_events"))
	assert.False(t, tableExists(conn, "_sqlx_migrations"))
}

func TestLegacyMigration_IPAddressChanged(t *testing.T) {
	store, conn := newLegacyTestStore(t)
	defer store.pool.Put(conn)

	aggID := ulid.Make().String()
	ts := time.Date(2025, 12, 1, 10, 0, 0, 0, time.UTC)

	// HostCreated first.
	insertRustEvent(t, conn, ulid.Make().String(), aggID, "HostCreated",
		ulid.Make().String(), strPtr("10.0.0.1"), strPtr("web.local"),
		nil, strPtr("[]"), strPtr("[]"), ts.UnixMicro(), ts.UnixMicro(),
		`{}`, nil)

	// Then IP change with previous_ip in metadata.
	ts2 := ts.Add(time.Hour)
	insertRustEvent(t, conn, ulid.Make().String(), aggID, "IpAddressChanged",
		ulid.Make().String(), strPtr("10.0.0.2"), nil,
		nil, nil, nil, ts2.UnixMicro(), ts2.UnixMicro(),
		`{"previous_ip":"10.0.0.1"}`, nil)

	require.NoError(t, migrateLegacyRustData(conn, slog.Default()))

	// Should have 2 events with sequential versions.
	var versions []int64
	require.NoError(t, sqlitex.Execute(conn,
		`SELECT event_version FROM events WHERE aggregate_id = ? ORDER BY event_version`,
		&sqlitex.ExecOptions{
			Args: []any{aggID},
			ResultFunc: func(stmt *sqlib.Stmt) error {
				versions = append(versions, stmt.ColumnInt64(0))
				return nil
			},
		}))
	assert.Equal(t, []int64{1, 2}, versions)

	// Verify IP change event_data has old_ip from metadata.
	var eventData string
	require.NoError(t, sqlitex.Execute(conn,
		`SELECT event_data FROM events WHERE event_type = 'IpAddressChanged'`,
		&sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlib.Stmt) error { eventData = stmt.ColumnText(0); return nil },
		}))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(eventData), &parsed))
	assert.Equal(t, "10.0.0.1", parsed["old_ip"])
	assert.Equal(t, "10.0.0.2", parsed["new_ip"])
}

func TestLegacyMigration_HostDeleted(t *testing.T) {
	store, conn := newLegacyTestStore(t)
	defer store.pool.Put(conn)

	aggID := ulid.Make().String()
	ts := time.Date(2025, 12, 1, 10, 0, 0, 0, time.UTC)
	reason := "decommissioned"

	insertRustEvent(t, conn, ulid.Make().String(), aggID, "HostCreated",
		ulid.Make().String(), strPtr("10.0.0.1"), strPtr("old.local"),
		nil, strPtr("[]"), strPtr("[]"), ts.UnixMicro(), ts.UnixMicro(),
		`{}`, nil)

	ts2 := ts.Add(24 * time.Hour)
	insertRustEvent(t, conn, ulid.Make().String(), aggID, "HostDeleted",
		ulid.Make().String(), strPtr("10.0.0.1"), strPtr("old.local"),
		nil, nil, nil, ts2.UnixMicro(), ts2.UnixMicro(),
		fmt.Sprintf(`{"deleted_reason":"%s"}`, reason), nil)

	require.NoError(t, migrateLegacyRustData(conn, slog.Default()))

	var eventData string
	require.NoError(t, sqlitex.Execute(conn,
		`SELECT event_data FROM events WHERE event_type = 'HostDeleted'`,
		&sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlib.Stmt) error { eventData = stmt.ColumnText(0); return nil },
		}))

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(eventData), &parsed))
	assert.Equal(t, "HostDeleted", parsed["type"])
	assert.Equal(t, "decommissioned", parsed["reason"])
}

func TestLegacyMigration_Snapshots(t *testing.T) {
	store, conn := newLegacyTestStore(t)
	defer store.pool.Put(conn)

	snapID := ulid.Make().String()
	ts := time.Date(2025, 12, 15, 12, 0, 0, 0, time.UTC)
	snapName := "pre-upgrade"

	insertRustSnapshot(t, conn, snapID, ts.UnixMicro(),
		"192.168.1.1 gateway.local\n", 1, "manual", &snapName)

	require.NoError(t, migrateLegacyRustData(conn, slog.Default()))

	// Verify snapshots table has trigger_type (not trigger).
	assert.True(t, columnExists(conn, "snapshots", "trigger_type"))
	assert.False(t, columnExists(conn, "snapshots", "trigger"))

	// Verify snapshot data migrated correctly.
	var triggerType, createdAt string
	require.NoError(t, sqlitex.Execute(conn,
		`SELECT trigger_type, created_at FROM snapshots WHERE snapshot_id = ?`,
		&sqlitex.ExecOptions{
			Args: []any{snapID},
			ResultFunc: func(stmt *sqlib.Stmt) error {
				triggerType = stmt.ColumnText(0)
				createdAt = stmt.ColumnText(1)
				return nil
			},
		}))
	assert.Equal(t, "manual", triggerType)
	// created_at should now be RFC3339-ish text, not integer.
	assert.Contains(t, createdAt, "2025-12-15")
}

func TestLegacyMigration_NoLegacyDB_IsNoop(t *testing.T) {
	// Fresh Go database — no host_events table.
	store, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	require.NoError(t, store.Initialize(context.Background()))

	// Verify migration version 3 was recorded (ran as no-op).
	var applied bool
	err = store.withConn(context.Background(), func(conn *sqlib.Conn) error {
		applied = isMigrationApplied(conn, legacyMigrationVersion)
		return nil
	})
	require.NoError(t, err)
	assert.True(t, applied)
}

func TestLegacyMigration_IdempotentWhenEventsExist(t *testing.T) {
	store, conn := newLegacyTestStore(t)
	defer store.pool.Put(conn)

	aggID := ulid.Make().String()
	ts := time.Date(2025, 12, 1, 10, 0, 0, 0, time.UTC)

	insertRustEvent(t, conn, ulid.Make().String(), aggID, "HostCreated",
		ulid.Make().String(), strPtr("10.0.0.1"), strPtr("test.local"),
		nil, strPtr("[]"), strPtr("[]"), ts.UnixMicro(), ts.UnixMicro(),
		`{}`, nil)

	// Run migration once.
	require.NoError(t, migrateLegacyRustData(conn, slog.Default()))

	var count int64
	require.NoError(t, sqlitex.Execute(conn, `SELECT COUNT(*) FROM events`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlib.Stmt) error { count = stmt.ColumnInt64(0); return nil },
	}))
	assert.Equal(t, int64(1), count)

	// host_events is gone, so a second call should be a no-op.
	require.NoError(t, migrateLegacyRustData(conn, slog.Default()))

	// Count should still be 1.
	require.NoError(t, sqlitex.Execute(conn, `SELECT COUNT(*) FROM events`, &sqlitex.ExecOptions{
		ResultFunc: func(stmt *sqlib.Stmt) error { count = stmt.ColumnInt64(0); return nil },
	}))
	assert.Equal(t, int64(1), count)
}

func TestLegacyMigration_FullRoundTrip_ViaInitialize(t *testing.T) {
	// Create a pool with Rust schema, then call Initialize which should
	// run SQL migrations + legacy Go migration end-to-end.
	pool, err := sqlitex.NewPool("file::memory:?mode=memory&cache=shared", sqlitex.PoolOptions{PoolSize: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })

	conn, err := pool.Take(context.Background())
	require.NoError(t, err)
	createRustSchema(t, conn)

	aggID := ulid.Make().String()
	ts := time.Date(2025, 12, 1, 10, 0, 0, 0, time.UTC)
	insertRustEvent(t, conn, ulid.Make().String(), aggID, "HostCreated",
		ulid.Make().String(), strPtr("10.0.0.5"), strPtr("full-test.local"),
		nil, strPtr(`["infra"]`), strPtr(`["ft"]`), ts.UnixMicro(), ts.UnixMicro(),
		`{"tags":["infra"],"aliases":["ft"]}`, nil)
	pool.Put(conn)

	store := &Storage{pool: pool, log: slog.Default()}
	require.NoError(t, store.Initialize(context.Background()))

	// Now use the normal Go API to read.
	ctx := context.Background()
	entries, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "10.0.0.5", entries[0].IP)
	assert.Equal(t, "full-test.local", entries[0].Hostname)
	assert.Equal(t, []string{"ft"}, entries[0].Aliases)
	assert.Equal(t, []string{"infra"}, entries[0].Tags)
}
