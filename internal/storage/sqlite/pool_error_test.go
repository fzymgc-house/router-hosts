package sqlite

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"
	sqlib "zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// errTakePool is a ConnPool whose Take always returns an error.
// Used to exercise the pool.Take error branches in EventStore and SnapshotStore.
type errTakePool struct {
	err error
}

func (p *errTakePool) Take(_ context.Context) (*sqlib.Conn, error) {
	return nil, p.err
}

func (p *errTakePool) Put(_ *sqlib.Conn) {}

func (p *errTakePool) Close() error { return nil }

// lockedConnPool is a ConnPool whose Take returns a real SQLite connection
// that is already inside an IMMEDIATE transaction, causing a second call to
// sqlitex.ImmediateTransaction to fail (SQLite does not allow nested
// IMMEDIATE transactions on the same connection).
type lockedConnPool struct {
	conn  *sqlib.Conn
	endFn func(*error)
}

func newLockedConnPool(t *testing.T) *lockedConnPool {
	t.Helper()
	conn, err := sqlib.OpenConn("file::memory:?mode=memory&cache=shared", sqlib.OpenReadWrite, sqlib.OpenCreate, sqlib.OpenURI)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	endFn, err := sqlitex.ImmediateTransaction(conn)
	require.NoError(t, err, "setup: begin initial transaction")

	return &lockedConnPool{conn: conn, endFn: endFn}
}

func (p *lockedConnPool) Take(_ context.Context) (*sqlib.Conn, error) {
	return p.conn, nil
}

func (p *lockedConnPool) Put(_ *sqlib.Conn) {}

func (p *lockedConnPool) Close() error {
	var err error
	p.endFn(&err)
	return err
}

// newStorageWithPool creates a Storage using the supplied pool without running
// migrations. Tests that inject a mock pool must set up any required state
// themselves (or not need it — these tests only verify error propagation).
func newStorageWithPool(pool ConnPool) *Storage {
	return &Storage{pool: pool, log: slog.Default()}
}

// ---------- EventStore: pool.Take error branches ----------

func TestAppendEvent_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	aggID := ulid.Make()
	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "x.local",
		Aliases: []string{}, Tags: []string{},
		CreatedAt: time.Now().UTC(),
	}, 1, time.Now().UTC())
	err := s.AppendEvent(context.Background(), aggID, env, 0)
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

func TestAppendEvents_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	aggID := ulid.Make()
	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "x.local",
		Aliases: []string{}, Tags: []string{},
		CreatedAt: time.Now().UTC(),
	}, 1, time.Now().UTC())
	err := s.AppendEvents(context.Background(), aggID, []domain.EventEnvelope{env}, 0)
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

func TestAppendEventsBatch_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	aggID := ulid.Make()
	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "x.local",
		Aliases: []string{}, Tags: []string{},
		CreatedAt: time.Now().UTC(),
	}, 1, time.Now().UTC())
	batch := []storage.AggregateEvents{
		{AggregateID: aggID, Events: []domain.EventEnvelope{env}, ExpectedVersion: 0},
	}
	err := s.AppendEventsBatch(context.Background(), batch)
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

// withConn funnels through pool.Take, so a single errTakePool covers all
// read methods.

func TestLoadEvents_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	_, err := s.LoadEvents(context.Background(), ulid.Make())
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

func TestGetCurrentVersion_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	_, err := s.GetCurrentVersion(context.Background(), ulid.Make())
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

func TestCountEvents_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	_, err := s.CountEvents(context.Background(), ulid.Make())
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

// ---------- EventStore: ImmediateTransaction error branches ----------

func TestAppendEvent_TransactionError(t *testing.T) {
	p := newLockedConnPool(t)
	t.Cleanup(func() { _ = p.Close() })
	s := newStorageWithPool(p)

	aggID := ulid.Make()
	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "x.local",
		Aliases: []string{}, Tags: []string{},
		CreatedAt: time.Now().UTC(),
	}, 1, time.Now().UTC())
	err := s.AppendEvent(context.Background(), aggID, env, 0)
	require.Error(t, err)
	require.ErrorContains(t, err, "begin transaction")
}

func TestAppendEvents_TransactionError(t *testing.T) {
	p := newLockedConnPool(t)
	t.Cleanup(func() { _ = p.Close() })
	s := newStorageWithPool(p)

	aggID := ulid.Make()
	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "x.local",
		Aliases: []string{}, Tags: []string{},
		CreatedAt: time.Now().UTC(),
	}, 1, time.Now().UTC())
	err := s.AppendEvents(context.Background(), aggID, []domain.EventEnvelope{env}, 0)
	require.Error(t, err)
	require.ErrorContains(t, err, "begin transaction")
}

func TestAppendEventsBatch_TransactionError(t *testing.T) {
	p := newLockedConnPool(t)
	t.Cleanup(func() { _ = p.Close() })
	s := newStorageWithPool(p)

	aggID := ulid.Make()
	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "x.local",
		Aliases: []string{}, Tags: []string{},
		CreatedAt: time.Now().UTC(),
	}, 1, time.Now().UTC())
	batch := []storage.AggregateEvents{
		{AggregateID: aggID, Events: []domain.EventEnvelope{env}, ExpectedVersion: 0},
	}
	err := s.AppendEventsBatch(context.Background(), batch)
	require.Error(t, err)
	require.ErrorContains(t, err, "begin transaction")
}

// ---------- SnapshotStore: pool.Take error branches ----------

func TestSaveSnapshot_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	snap := domain.Snapshot{
		SnapshotID:   ulid.Make(),
		CreatedAt:    time.Now().UTC(),
		HostsContent: "",
		EntryCount:   0,
		Trigger:      "manual",
	}
	err := s.SaveSnapshot(context.Background(), snap)
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

func TestGetSnapshot_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	_, err := s.GetSnapshot(context.Background(), ulid.Make())
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

func TestListSnapshots_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	_, err := s.ListSnapshots(context.Background(), nil, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

func TestDeleteSnapshot_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	err := s.DeleteSnapshot(context.Background(), ulid.Make())
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

func TestApplyRetentionPolicy_TakeError(t *testing.T) {
	s := newStorageWithPool(&errTakePool{err: errors.New("pool exhausted")})
	maxCount := 5
	_, err := s.ApplyRetentionPolicy(context.Background(), &maxCount, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "take connection")
}

// ---------- SnapshotStore: ImmediateTransaction error branch ----------

func TestApplyRetentionPolicy_TransactionError(t *testing.T) {
	p := newLockedConnPool(t)
	t.Cleanup(func() { _ = p.Close() })
	s := newStorageWithPool(p)

	maxCount := 5
	_, err := s.ApplyRetentionPolicy(context.Background(), &maxCount, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, "begin transaction")
}
