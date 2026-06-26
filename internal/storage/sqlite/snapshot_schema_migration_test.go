package sqlite

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sqlib "zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// newGoPoolWithConn creates a pool + returns a held connection (caller must Put it back).
// The pool is registered for cleanup. The connection is NOT put back until the
// test calls pool.Put — callers that need to return the conn before calling
// store methods should do so explicitly.
func newGoPoolWithConn(t *testing.T) (*sqlitex.Pool, *sqlib.Conn) {
	t.Helper()
	pool, err := sqlitex.NewPool("file::memory:?mode=memory&cache=shared", sqlitex.PoolOptions{PoolSize: 1})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })

	conn, err := pool.Take(context.Background())
	require.NoError(t, err)
	return pool, conn
}

// createGoTablesWithoutTriggerType creates the Go events/schema_version tables and a
// snapshots table that deliberately omits trigger_type (and trigger). This
// reproduces the #331 production case: the DB was created by a Go-era deploy
// whose migration 001 no-oped because snapshots already existed from a prior
// run that lacked trigger_type.
func createGoTablesWithoutTriggerType(t *testing.T, conn *sqlib.Conn) {
	t.Helper()
	ddl := `
		CREATE TABLE events (
			event_id TEXT PRIMARY KEY,
			aggregate_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			event_data TEXT NOT NULL,
			event_version INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			created_by TEXT
		);
		CREATE INDEX idx_events_aggregate ON events(aggregate_id, event_version);
		CREATE INDEX idx_events_created_at ON events(created_at);

		CREATE TABLE snapshots (
			snapshot_id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			hosts_content TEXT NOT NULL,
			entry_count INTEGER NOT NULL,
			name TEXT,
			event_log_position INTEGER,
			entries_json TEXT
		);
		CREATE INDEX idx_snapshots_created_at ON snapshots(created_at);

		CREATE TABLE schema_version (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		);
		INSERT INTO schema_version (version, applied_at) VALUES (1, datetime('now'));
		INSERT INTO schema_version (version, applied_at) VALUES (2, datetime('now'));
		INSERT INTO schema_version (version, applied_at) VALUES (3, datetime('now'));
	`
	require.NoError(t, sqlitex.ExecuteScript(conn, ddl, nil))
}

// TestGH331_GoEraDBMissingTriggerType is the primary regression test for #331.
// It reproduces a Go-era database where snapshots was created without trigger_type
// (no host_events table, so the legacy path is a no-op) and verifies Initialize
// repairs the schema and a full round-trip works.
func TestGH331_GoEraDBMissingTriggerType(t *testing.T) {
	pool, conn := newGoPoolWithConn(t)
	createGoTablesWithoutTriggerType(t, conn)
	pool.Put(conn)

	store := &Storage{pool: pool, log: slog.Default()}
	ctx := context.Background()

	// This MUST succeed after the fix; it fails against unpatched code because
	// repairSnapshotTriggerType / version-4 migration don't exist yet.
	require.NoError(t, store.Initialize(ctx))

	// Verify trigger_type column was added.
	err := store.withConn(ctx, func(c *sqlib.Conn) error {
		assert.True(t, columnExists(c, "snapshots", "trigger_type"),
			"trigger_type column must exist after Initialize")
		return nil
	})
	require.NoError(t, err)

	// Full round-trip: SaveSnapshot then ListSnapshots must not error.
	snap := domain.NewSnapshot(ulid.Make(), "127.0.0.1 localhost\n", "manual", nil, nil)
	snap.CreatedAt = time.Now().UTC()
	require.NoError(t, store.SaveSnapshot(ctx, *snap))

	metas, err := store.ListSnapshots(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, snap.SnapshotID, metas[0].SnapshotID)
	assert.Equal(t, "manual", metas[0].Trigger)
}

// TestGH331_LegacyPath_NeitherColumn verifies Part 2: when the legacy migration
// runs on a DB that has host_events AND a snapshots table missing both trigger
// and trigger_type, Initialize adds trigger_type.
func TestGH331_LegacyPath_NeitherColumn(t *testing.T) {
	pool, conn := newGoPoolWithConn(t)

	// Build a schema with host_events AND a snapshots table missing both columns.
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
			created_by TEXT
		);
		CREATE TABLE snapshots (
			snapshot_id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			hosts_content TEXT NOT NULL,
			entry_count INTEGER NOT NULL,
			name TEXT,
			event_log_position INTEGER
		);
		CREATE TABLE _sqlx_migrations (version INTEGER PRIMARY KEY, description TEXT NOT NULL, installed_on TEXT NOT NULL, success INTEGER NOT NULL);
	`
	require.NoError(t, sqlitex.ExecuteScript(conn, ddl, nil))

	// Run migration SQL files (creates events + schema_version alongside existing tables).
	for _, m := range migrationFiles {
		sql, readErr := migrations.ReadFile(m.path)
		require.NoError(t, readErr)
		require.NoError(t, sqlitex.ExecuteScript(conn, string(sql), nil))
	}
	pool.Put(conn)

	store := &Storage{pool: pool, log: slog.Default()}
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))

	err := store.withConn(ctx, func(c *sqlib.Conn) error {
		assert.True(t, columnExists(c, "snapshots", "trigger_type"),
			"trigger_type must exist after legacy path handles neither-column case")
		return nil
	})
	require.NoError(t, err)

	// The schema can be structurally complete yet still misbehave at the data
	// layer, so exercise the real create/list path the way #331 broke it.
	snap := domain.NewSnapshot(ulid.Make(), "127.0.0.1 localhost\n", "manual", nil, nil)
	snap.CreatedAt = time.Now().UTC()
	require.NoError(t, store.SaveSnapshot(ctx, *snap))

	metas, err := store.ListSnapshots(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, "manual", metas[0].Trigger)
}

// TestAssertSnapshotsSchema_MissingTriggerType verifies Part 3 directly: calling
// assertSnapshotsSchema on a snapshots table that lacks trigger_type returns a
// descriptive error (the repair path does not mask it here).
func TestAssertSnapshotsSchema_MissingTriggerType(t *testing.T) {
	pool, conn := newGoPoolWithConn(t)
	defer pool.Put(conn)

	// Create snapshots without trigger_type.
	require.NoError(t, sqlitex.ExecuteScript(conn, `
		CREATE TABLE snapshots (
			snapshot_id TEXT PRIMARY KEY,
			created_at TEXT NOT NULL,
			hosts_content TEXT NOT NULL,
			entry_count INTEGER NOT NULL,
			name TEXT,
			event_log_position INTEGER
		);
	`, nil))

	err := assertSnapshotsSchema(conn)
	require.Error(t, err, "assertSnapshotsSchema must fail when trigger_type is missing")
	assert.Contains(t, err.Error(), "trigger_type")
}

// TestAssertSnapshotsSchema_MissingTable verifies Part 3: missing snapshots table
// is also an assertion failure.
func TestAssertSnapshotsSchema_MissingTable(t *testing.T) {
	pool, conn := newGoPoolWithConn(t)
	defer pool.Put(conn)

	err := assertSnapshotsSchema(conn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "snapshots")
}

// TestInitialize_HealthyDB_Idempotent verifies no regression: a fresh healthy DB
// survives Initialize called twice with no errors.
func TestInitialize_HealthyDB_Idempotent(t *testing.T) {
	store, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx), "first Initialize")
	require.NoError(t, store.Initialize(ctx), "second Initialize must be idempotent")

	// Confirm trigger_type exists on a clean DB.
	err = store.withConn(ctx, func(c *sqlib.Conn) error {
		assert.True(t, columnExists(c, "snapshots", "trigger_type"))
		return nil
	})
	require.NoError(t, err)
}

// TestInitialize_Version4_Recorded verifies the repair migration version (4) is
// recorded in schema_version after Initialize on a repaired DB.
func TestInitialize_Version4_Recorded(t *testing.T) {
	pool, conn := newGoPoolWithConn(t)
	createGoTablesWithoutTriggerType(t, conn)
	pool.Put(conn)

	store := &Storage{pool: pool, log: slog.Default()}
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))

	err := store.withConn(ctx, func(c *sqlib.Conn) error {
		assert.True(t, isMigrationApplied(c, snapshotTriggerRepairVersion),
			"version 4 must be recorded after repair")
		return nil
	})
	require.NoError(t, err)
}
