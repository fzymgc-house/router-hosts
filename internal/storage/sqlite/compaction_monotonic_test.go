package sqlite

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/eventid"
)

// maxEventIDForTest reads MAX(event_id) directly, ahead of Task 2's
// LatestEventID method existing on the public interface. A NULL result (an
// empty events table) is reported as the zero ULID.
func maxEventIDForTest(t *testing.T, ctx context.Context, s *Storage) ulid.ULID {
	t.Helper()
	var max ulid.ULID
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		return sqlitex.Execute(conn,
			`SELECT MAX(event_id) FROM events`,
			&sqlitex.ExecOptions{
				ResultFunc: func(stmt *sqlite.Stmt) error {
					if stmt.ColumnType(0) == sqlite.TypeNull {
						return nil
					}
					parsed, parseErr := ulid.Parse(stmt.ColumnText(0))
					if parseErr != nil {
						return parseErr
					}
					max = parsed
					return nil
				},
			})
	})
	require.NoError(t, err)
	return max
}

// envelopeViaEventID builds an envelope like makeEnvelope, but mints its
// EventID through the shared internal/eventid generator instead of the bare
// package-level ulid.Make(). This mirrors production's
// CommandHandler.newID(), which mints through the same generator — a
// DIFFERENT entropy source than ulid.Make()'s process-global default. That
// distinction matters for these tests: the pre-fix compaction bug (a bare
// ulid.Make() seed at the compaction site) can only regress against events
// minted from a genuinely independent entropy source. If the pre-existing
// events here were minted with ulid.Make() too, they would share the same
// underlying monotonic entropy stream as the bug's own ulid.Make() call and
// could never be observed sorting out of order, making the RED verification
// this test claims to have passed impossible to actually observe.
func envelopeViaEventID(aggregateID ulid.ULID, event any, version int64, createdAt time.Time) domain.EventEnvelope {
	env := makeEnvelope(aggregateID, event, version, createdAt)
	env.EventID = eventid.New()
	return env
}

// monotonicTestStoreOnce/-Store back monotonicTestStorage: one Storage shared
// by every test in this file across every -count repeat.
var (
	monotonicTestStoreOnce sync.Once
	monotonicTestStore     *Storage
)

// monotonicTestStorage returns a package-shared, already-warmed-up Storage
// for the compaction regression tests in this file.
//
// These tests exist to observe a genuine same-millisecond race between two
// independent monotonic-entropy sources (see envelopeViaEventID). That race
// requires the whole append-then-compact sequence to complete inside the
// same 1ms window it started in. A freshly constructed Storage pays for
// embedded migration file reads, several schema_version checks and a fresh
// connection pool — measured at several milliseconds on a cold cache under
// -race — which alone guarantees the compaction always lands in a later
// millisecond than the append it followed, so the race this file exists to
// catch could never be observed. `go test -count=N` re-invokes a test
// function N times inside one process, so a package-level store, built once
// and reused, lets later repeats run warm; each repeat still creates its own
// aggregate (a fresh ulid.Make() ID), so there is no cross-repeat data
// coupling from sharing it.
//
// The DSN deliberately uses a NAMED in-memory database
// ("file:eventid_guard_monotonic_shared"), not the bare "file::memory:" DSN
// every other test in this package uses. SQLite's cache=shared mode makes an
// anonymous "file::memory:" identity process-wide: every connection that
// opens that exact DSN with cache=shared attaches to the SAME underlying
// database for as long as any one connection to it stays open anywhere in
// the process. This store's pool is intentionally never closed (it lives for
// the rest of the test binary), so reusing the generic anonymous DSN here
// would keep that shared anonymous database alive process-wide and leak this
// file's already-migrated schema into every other test in this package that
// opens "file::memory:?mode=memory&cache=shared" expecting a fresh database
// — which is exactly what happened during development here (a later test
// failed with "index idx_events_aggregate already exists"). A distinctly
// named DSN gives this store its own shared-cache identity, isolated from
// every other test's anonymous one.
func monotonicTestStorage(t *testing.T) *Storage {
	t.Helper()
	monotonicTestStoreOnce.Do(func() {
		store, err := New("file:eventid_guard_monotonic_shared?mode=memory&cache=shared", slog.Default())
		if err != nil {
			t.Fatalf("create shared monotonic-test store: %v", err)
		}
		if err := store.Initialize(context.Background()); err != nil {
			t.Fatalf("initialize shared monotonic-test store: %v", err)
		}
		monotonicTestStore = store
	})
	return monotonicTestStore
}

// TestCompactAggregate_AdvancesLatestEventID is the direct regression test
// for review round-2 H2 / round-3's compaction case: compacting an aggregate
// must leave the log's maximum event ID strictly greater than it was before
// the compaction, never pinned and never regressed.
//
// This test was verified RED against the pre-fix code (EventID: ulid.Make()
// at the compaction seed site instead of eventid.New()): reverting that one
// line and running
// `task test -- -count=50 -run TestCompactAggregate_Advances ./internal/storage/sqlite/`
// failed 10 of 50 runs of this test (11 of 50 for its sibling below, 21 of
// 100 total) — two same-millisecond ULIDs minted from independent entropy
// sources sort in a random order, so a single run of the broken code passes
// about half the time it actually lands in the same millisecond. That
// observed count is recorded in the SUMMARY rather than "failed at least
// once", per review L3.
func TestCompactAggregate_AdvancesLatestEventID(t *testing.T) {
	store := monotonicTestStorage(t)
	ctx := context.Background()

	id := ulid.Make()
	now := time.Now().UTC()
	env := envelopeViaEventID(id, domain.HostCreated{
		IPAddress: "10.9.0.1",
		Hostname:  "compact-advance.local",
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: now,
	}, 1, now)
	require.NoError(t, store.AppendEvent(ctx, id, env, 0))
	up := envelopeViaEventID(id, domain.IPAddressChanged{
		OldIP:     "10.9.0.1",
		NewIP:     "10.9.0.2",
		ChangedAt: now,
	}, 2, now)
	require.NoError(t, store.AppendEvent(ctx, id, up, 1))

	before := maxEventIDForTest(t, ctx, store)

	_, err := store.CompactAggregate(ctx, id)
	require.NoError(t, err)

	after := maxEventIDForTest(t, ctx, store)
	require.Positive(t, after.Compare(before), "compaction must leave the log maximum strictly greater than before")
}

// TestCompactAggregate_AdvancesWhenAggregateHeldTheMaximum seeds a second
// aggregate first so the compacted aggregate demonstrably holds the global
// maximum before compaction — the exact case a bare ulid.Make() breaks,
// because CompactAggregate deletes the aggregate's rows before inserting the
// replacement seed (eventstore.go: deleteEventsForAggregate runs before
// insertEvent), so the in-transaction MAX(event_id) read at insert time
// cannot see the value that was just deleted. What covers that gap is the
// eventid generator's floor, seeded from the persisted maximum and already
// raised past the deleted value by every prior mint — not the in-transaction
// guard, which by then can no longer see the deleted maximum. Without this
// note this test looks like a duplicate of
// TestCompactAggregate_AdvancesLatestEventID and is a candidate for deletion
// by a future reader; it is not a duplicate, because that test alone can
// pass without exercising this case.
func TestCompactAggregate_AdvancesWhenAggregateHeldTheMaximum(t *testing.T) {
	store := monotonicTestStorage(t)
	ctx := context.Background()

	now := time.Now().UTC()

	// Seed a second aggregate first so its events sort below the aggregate
	// under test, guaranteeing the compacted aggregate holds the global max.
	other := ulid.Make()
	otherEnv := envelopeViaEventID(other, domain.HostCreated{
		IPAddress: "10.9.1.1",
		Hostname:  "other-aggregate.local",
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: now,
	}, 1, now)
	require.NoError(t, store.AppendEvent(ctx, other, otherEnv, 0))

	id := ulid.Make()
	env := envelopeViaEventID(id, domain.HostCreated{
		IPAddress: "10.9.0.1",
		Hostname:  "compact-holds-max.local",
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: now,
	}, 1, now)
	require.NoError(t, store.AppendEvent(ctx, id, env, 0))
	up := envelopeViaEventID(id, domain.IPAddressChanged{
		OldIP:     "10.9.0.1",
		NewIP:     "10.9.0.2",
		ChangedAt: now,
	}, 2, now)
	require.NoError(t, store.AppendEvent(ctx, id, up, 1))

	before := maxEventIDForTest(t, ctx, store)

	// Confirm the setup actually holds the property this test claims: the
	// aggregate under test's own last-appended event must be the log max.
	events, err := store.LoadEvents(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before, events[len(events)-1].EventID, "test setup must make the compacted aggregate hold the global maximum")

	_, err = store.CompactAggregate(ctx, id)
	require.NoError(t, err)

	after := maxEventIDForTest(t, ctx, store)
	require.Positive(t, after.Compare(before), "compaction must advance the log maximum even when the compacted aggregate held it")
}
