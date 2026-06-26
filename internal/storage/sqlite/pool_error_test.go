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

// ---------- EventStore: context cancelled mid-flight (#330) ----------
//
// noInterruptPool wraps a real ConnPool and, on each successful Take:
//  1. Strips the SQLite interrupt from the connection (SetInterrupt(nil)).
//  2. Calls onTake (if non-nil), which the test uses to cancel the context.
//
// This reproduces the production failure window: zombiezen's pool wires the
// context's Done channel to sqlite3_interrupt, so the interrupt only fires on
// the *next* SQLite call. If the context deadline expires in the tiny gap
// between the last successful INSERT and the `return nil`, no new SQLite call
// is made, so the interrupt never fires and the deferred endFn commits with
// err==nil. By stripping the interrupt first we make that window observable
// and deterministic: all SQL succeeds, then we cancel the context, then the
// pre-commit guard is the only thing that can catch it.
type noInterruptPool struct {
	inner  ConnPool
	onTake func() // called after stripping interrupt, e.g. to cancel testCtx
}

func (p *noInterruptPool) Take(ctx context.Context) (*sqlib.Conn, error) {
	conn, err := p.inner.Take(ctx)
	if err != nil {
		return nil, err
	}
	conn.SetInterrupt(nil) // strip interrupt so ctx cancellation won't abort SQL
	if p.onTake != nil {
		p.onTake() // simulate deadline expiry in the last-write→return nil window
	}
	return conn, nil
}

func (p *noInterruptPool) Put(conn *sqlib.Conn) { p.inner.Put(conn) }
func (p *noInterruptPool) Close() error         { return p.inner.Close() }

// newNoInterruptStore builds a Storage that strips the connection interrupt and
// runs onTake after each successful Take, plus a read-only Storage on the same
// pool for count assertions.
func newNoInterruptStore(t *testing.T, onTake func()) (write *Storage, read *Storage) {
	t.Helper()
	real, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, real.Initialize(context.Background()))
	t.Cleanup(func() { _ = real.pool.Close() })

	write = &Storage{pool: &noInterruptPool{inner: real.pool, onTake: onTake}, log: slog.Default()}
	read = real
	return write, read
}

// TestAppendEvent_ContextExpiredBeforeCommit verifies that AppendEvent rolls
// back and returns an error when the request context expires in the window
// between the final INSERT and the deferred commit (pre-commit guard — #330).
//
// Without the guard, the deferred endFn sees err==nil and commits; the data
// is persisted even though the caller already received a deadline/cancel error.
func TestAppendEvent_ContextExpiredBeforeCommit(t *testing.T) {
	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, real := newNoInterruptStore(t, cancel)

	aggID := ulid.Make()
	now := time.Now().UTC()
	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "precommit-single.local",
		Aliases: []string{}, Tags: []string{}, CreatedAt: now,
	}, 1, now)

	err := s.AppendEvent(testCtx, aggID, env, 0)
	require.Error(t, err, "AppendEvent must return error when ctx expires before commit (#330)")

	count, countErr := real.CountEvents(context.Background(), aggID)
	require.NoError(t, countErr)
	require.Equal(t, int64(0), count, "AppendEvent must not commit data when ctx expires before commit (#330)")
}

// TestAppendEvents_ContextExpiredBeforeCommit is the multi-event variant of
// TestAppendEvent_ContextExpiredBeforeCommit.
func TestAppendEvents_ContextExpiredBeforeCommit(t *testing.T) {
	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, real := newNoInterruptStore(t, cancel)

	aggID := ulid.Make()
	now := time.Now().UTC()
	env1 := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "precommit-multi-a.local",
		Aliases: []string{}, Tags: []string{}, CreatedAt: now,
	}, 1, now)
	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP: "10.0.0.1", NewIP: "10.0.0.2", ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))

	err := s.AppendEvents(testCtx, aggID, []domain.EventEnvelope{env1, env2}, 0)
	require.Error(t, err, "AppendEvents must return error when ctx expires before commit (#330)")

	count, countErr := real.CountEvents(context.Background(), aggID)
	require.NoError(t, countErr)
	require.Equal(t, int64(0), count, "AppendEvents must not commit data when ctx expires before commit (#330)")
}

// TestAppendEventsBatch_ContextExpiredBeforeCommit is the batch variant of
// TestAppendEvent_ContextExpiredBeforeCommit.
func TestAppendEventsBatch_ContextExpiredBeforeCommit(t *testing.T) {
	testCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, real := newNoInterruptStore(t, cancel)

	aggID := ulid.Make()
	now := time.Now().UTC()
	env := makeEnvelope(aggID, domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: "precommit-batch.local",
		Aliases: []string{}, Tags: []string{}, CreatedAt: now,
	}, 1, now)
	batch := []storage.AggregateEvents{
		{AggregateID: aggID, Events: []domain.EventEnvelope{env}, ExpectedVersion: 0},
	}

	err := s.AppendEventsBatch(testCtx, batch)
	require.Error(t, err, "AppendEventsBatch must return error when ctx expires before commit (#330)")

	count, countErr := real.CountEvents(context.Background(), aggID)
	require.NoError(t, countErr)
	require.Equal(t, int64(0), count, "AppendEventsBatch must not commit data when ctx expires before commit (#330)")
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
