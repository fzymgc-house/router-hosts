// Package storagetest provides a reusable compliance test suite that any
// storage.Storage implementation must pass. Embed these functions into a
// backend-specific _test.go file and call them with a freshly initialised store.
package storagetest

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/eventid"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// helpers

func makeEnvelope(aggregateID ulid.ULID, event any, version int64, createdAt time.Time) domain.EventEnvelope {
	he, err := domain.NewHostEvent(event)
	if err != nil {
		panic(fmt.Sprintf("storagetest.makeEnvelope: NewHostEvent: %v", err))
	}
	// Minted through the shared generator so the store never has cause to
	// replace it: callers of this helper assert env.EventID == the
	// read-back ID, which only holds unconditionally when the proposed ID
	// already sorts above the log's maximum.
	return domain.EventEnvelope{
		EventID:     eventid.New(),
		AggregateID: aggregateID,
		Event:       he,
		Version:     version,
		CreatedAt:   createdAt,
	}
}

func hostCreatedEnvelope(aggID ulid.ULID, ip, hostname string, t time.Time) domain.EventEnvelope {
	return makeEnvelope(aggID, domain.HostCreated{
		IPAddress: ip,
		Hostname:  hostname,
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: t,
	}, 1, t)
}

func ptr[T any](v T) *T { return &v }

func mustAppendCreated(t *testing.T, store storage.EventStore, id ulid.ULID, ip, hostname string) {
	t.Helper()
	ctx := context.Background()
	env := hostCreatedEnvelope(id, ip, hostname, time.Now().UTC().Truncate(time.Millisecond))
	require.NoError(t, store.AppendEvent(ctx, id, env, 0))
}

// ---------- EventStore compliance ----------

// TestEventStoreAppendAndLoad verifies that a single event can be written and
// read back with all fields preserved.
func TestEventStoreAppendAndLoad(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := hostCreatedEnvelope(aggID, "10.1.0.1", "compliance.local", now)
	require.NoError(t, store.AppendEvent(ctx, aggID, env, 0))

	events, err := store.LoadEvents(ctx, aggID)
	require.NoError(t, err)
	require.Len(t, events, 1)

	got := events[0]
	require.Equal(t, env.EventID, got.EventID)
	require.Equal(t, aggID, got.AggregateID)
	require.Equal(t, int64(1), got.Version)
	require.Equal(t, domain.EventTypeHostCreated, got.Event.Type)

	decoded, err := got.Event.Decode()
	require.NoError(t, err)
	hc, ok := decoded.(domain.HostCreated)
	require.True(t, ok, "decoded event must be HostCreated")
	require.Equal(t, "10.1.0.1", hc.IPAddress)
	require.Equal(t, "compliance.local", hc.Hostname)
}

// TestEventStoreVersionConflict verifies that appending with an incorrect
// expectedVersion returns an error containing "version conflict".
func TestEventStoreVersionConflict(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env := hostCreatedEnvelope(aggID, "10.1.0.2", "conflict.local", now)
	require.NoError(t, store.AppendEvent(ctx, aggID, env, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "10.1.0.2",
		NewIP:     "10.1.0.3",
		ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))

	// Pass wrong expected version — must fail.
	err := store.AppendEvent(ctx, aggID, env2, 999)
	require.Error(t, err)
	require.Contains(t, err.Error(), "version conflict")
}

// TestEventStoreEmptyLoad verifies that loading events for an unknown aggregate
// returns an empty slice without an error.
func TestEventStoreEmptyLoad(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	events, err := store.LoadEvents(ctx, ulid.Make())
	require.NoError(t, err)
	require.Empty(t, events)
}

// TestEventStoreGetCurrentVersion verifies that version tracking is correct
// after sequential appends and returns zero for a new aggregate.
func TestEventStoreGetCurrentVersion(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()

	// New aggregate — expect version 0.
	zeroVer, err := store.GetCurrentVersion(ctx, ulid.Make())
	require.NoError(t, err)
	require.Equal(t, int64(0), zeroVer)

	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	env1 := hostCreatedEnvelope(aggID, "10.1.0.4", "version.local", now)
	require.NoError(t, store.AppendEvent(ctx, aggID, env1, 0))

	env2 := makeEnvelope(aggID, domain.IPAddressChanged{
		OldIP:     "10.1.0.4",
		NewIP:     "10.1.0.5",
		ChangedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	require.NoError(t, store.AppendEvent(ctx, aggID, env2, 1))

	ver, err := store.GetCurrentVersion(ctx, aggID)
	require.NoError(t, err)
	require.Equal(t, int64(2), ver)
}

// TestEventStoreMultipleAggregatesIsolated verifies that events for distinct
// aggregates do not bleed into each other's load results.
func TestEventStoreMultipleAggregatesIsolated(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, agg1, hostCreatedEnvelope(agg1, "10.2.0.1", "agg1.local", now), 0))
	require.NoError(t, store.AppendEvent(ctx, agg2, hostCreatedEnvelope(agg2, "10.2.0.2", "agg2.local", now), 0))

	events1, err := store.LoadEvents(ctx, agg1)
	require.NoError(t, err)
	require.Len(t, events1, 1)

	events2, err := store.LoadEvents(ctx, agg2)
	require.NoError(t, err)
	require.Len(t, events2, 1)

	require.Equal(t, agg1, events1[0].AggregateID)
	require.Equal(t, agg2, events2[0].AggregateID)
}

// TestEventStoreBatchAppend verifies that AppendEventsBatch writes events for
// multiple aggregates atomically.
func TestEventStoreBatchAppend(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	batch := []storage.AggregateEvents{
		{
			AggregateID:     agg1,
			Events:          []domain.EventEnvelope{hostCreatedEnvelope(agg1, "10.3.0.1", "batch1.local", now)},
			ExpectedVersion: 0,
		},
		{
			AggregateID:     agg2,
			Events:          []domain.EventEnvelope{hostCreatedEnvelope(agg2, "10.3.0.2", "batch2.local", now)},
			ExpectedVersion: 0,
		},
	}
	require.NoError(t, store.AppendEventsBatch(ctx, batch))

	for _, aggID := range []ulid.ULID{agg1, agg2} {
		events, err := store.LoadEvents(ctx, aggID)
		require.NoError(t, err)
		require.Len(t, events, 1, "aggregate %s should have exactly one event", aggID)
	}
}

// TestEventStoreBatchAppendRollback verifies that AppendEventsBatch rolls back
// all writes when a version conflict occurs mid-batch. The first aggregate's
// events MUST NOT be persisted if the second aggregate's expectedVersion is
// wrong.
func TestEventStoreBatchAppendRollback(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	// Pre-seed agg2 with one event so its current version is 1.
	require.NoError(t, store.AppendEvent(ctx, agg2, hostCreatedEnvelope(agg2, "10.10.0.2", "rollback-agg2.local", now), 0))

	// Build a batch where agg1 is fresh (expectedVersion=0, correct) but agg2
	// uses expectedVersion=0 instead of the correct 1 — this must trigger a
	// version conflict.
	batch := []storage.AggregateEvents{
		{
			AggregateID:     agg1,
			Events:          []domain.EventEnvelope{hostCreatedEnvelope(agg1, "10.10.0.1", "rollback-agg1.local", now)},
			ExpectedVersion: 0,
		},
		{
			AggregateID:     agg2,
			Events:          []domain.EventEnvelope{makeEnvelope(agg2, domain.IPAddressChanged{OldIP: "10.10.0.2", NewIP: "10.10.0.3", ChangedAt: now.Add(time.Second)}, 2, now.Add(time.Second))},
			ExpectedVersion: 0, // wrong: current version is 1
		},
	}

	err := store.AppendEventsBatch(ctx, batch)
	require.Error(t, err, "batch with a version conflict must return an error")

	// agg1 must have no events — the transaction was rolled back.
	events1, loadErr := store.LoadEvents(ctx, agg1)
	require.NoError(t, loadErr)
	require.Empty(t, events1, "agg1 events must be rolled back on batch failure")

	// agg2 must still have only its original single event.
	events2, loadErr := store.LoadEvents(ctx, agg2)
	require.NoError(t, loadErr)
	require.Len(t, events2, 1, "agg2 must retain only its pre-existing event")
}

// TestEventStoreListAggregateIDs verifies all aggregate IDs (incl. deleted) are returned.
func TestEventStoreListAggregateIDs(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	id1, id2 := ulid.Make(), ulid.Make()
	mustAppendCreated(t, store, id1, "10.0.0.1", "a.example.com")
	mustAppendCreated(t, store, id2, "10.0.0.2", "b.example.com")

	ids, err := store.ListAggregateIDs(ctx)
	require.NoError(t, err)
	got := map[string]bool{}
	for _, id := range ids {
		got[id.String()] = true
	}
	require.True(t, got[id1.String()])
	require.True(t, got[id2.String()])

	// Deleting an aggregate must NOT remove it from ListAggregateIDs: the method
	// reads the raw event log (distinct aggregate_id), not the projection, so a
	// deleted aggregate's ID remains visible. This is the defining contract.
	now := time.Now().UTC().Truncate(time.Millisecond)
	del := makeEnvelope(id1, domain.HostDeleted{
		IPAddress: "10.0.0.1",
		Hostname:  "a.example.com",
		DeletedAt: now,
	}, 2, now)
	require.NoError(t, store.AppendEvent(ctx, id1, del, 1))

	ids2, err := store.ListAggregateIDs(ctx)
	require.NoError(t, err)
	got2 := map[string]bool{}
	for _, id := range ids2 {
		got2[id.String()] = true
	}
	require.True(t, got2[id1.String()], "deleted aggregate ID must still appear in ListAggregateIDs")
}

// TestEventStoreCompactAggregate is the #330/#323 regression: a bloated aggregate
// compacts to one event with its version and folded state preserved.
func TestEventStoreCompactAggregate(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	id := ulid.Make()

	// Bloat: 1 create + 20 IP changes => 21 events, version 21.
	mustAppendCreated(t, store, id, "10.0.0.1", "h.example.com")
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+2)
		ev, _ := domain.NewHostEvent(domain.IPAddressChanged{NewIP: ip, ChangedAt: time.Now().UTC()})
		env := domain.EventEnvelope{EventID: eventid.New(), AggregateID: id, Event: ev, Version: int64(i + 2), CreatedAt: time.Now().UTC()}
		require.NoError(t, store.AppendEvent(ctx, id, env, int64(i+1)))
	}
	before, err := store.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(21), before.Version)

	res, err := store.CompactAggregate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(21), res.EventsBefore)
	require.Equal(t, int64(1), res.EventsAfter)
	require.Equal(t, int64(21), res.Version)

	// Event count is now 1; current version preserved.
	cnt, err := store.CountEvents(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(1), cnt)
	v, err := store.GetCurrentVersion(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(21), v)

	// Folded state is byte-identical (same Version means OCC unbroken).
	after, err := store.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

// TestEventStoreCompactAggregateNoop verifies that compacting an aggregate with
// <=1 event is a no-op that leaves the log untouched.
func TestEventStoreCompactAggregateNoop(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	id := ulid.Make()
	mustAppendCreated(t, store, id, "10.0.0.1", "h.example.com")
	res, err := store.CompactAggregate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(1), res.EventsBefore)
	require.Equal(t, int64(1), res.EventsAfter)
	cnt, _ := store.CountEvents(ctx, id)
	require.Equal(t, int64(1), cnt)
}

// TestEventStoreCompactAggregateDeleted verifies a deleted aggregate compacts to
// a single HostCompacted{Deleted:true} seed: live and deleted aggregates compact
// uniformly, and the seed preserves the high-water version.
func TestEventStoreCompactAggregateDeleted(t *testing.T, store storage.EventStore) {
	t.Helper()
	ctx := context.Background()
	id := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	mustAppendCreated(t, store, id, "10.0.0.1", "gone.example.com")
	del := makeEnvelope(id, domain.HostDeleted{
		IPAddress: "10.0.0.1",
		Hostname:  "gone.example.com",
		DeletedAt: now,
	}, 2, now)
	require.NoError(t, store.AppendEvent(ctx, id, del, 1))

	res, err := store.CompactAggregate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(2), res.EventsBefore)
	require.Equal(t, int64(1), res.EventsAfter)
	require.Equal(t, int64(2), res.Version)

	// The single remaining event is a HostCompacted seed carrying Deleted=true at
	// the preserved high-water version.
	events, err := store.LoadEvents(ctx, id)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, int64(2), events[0].Version)
	decoded, err := events[0].Event.Decode()
	require.NoError(t, err)
	seed, ok := decoded.(domain.HostCompacted)
	require.True(t, ok, "compacted seed must be HostCompacted")
	require.True(t, seed.Deleted, "deleted aggregate must compact to a Deleted=true seed")
	require.Equal(t, "10.0.0.1", seed.IPAddress)
	require.Equal(t, "gone.example.com", seed.Hostname)
	require.Equal(t, int64(2), seed.FoldedEventCount)
}

// ---------- EventStore change-ID compliance ----------

// TestEventStoreLatestEventID verifies the storage-level change-ID contract
// (TMPL-08, D-18): an empty log reports the zero ULID with no error, the
// returned value equals the greatest appended EventID, and a further append
// advances it.
func TestEventStoreLatestEventID(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	empty, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Equal(t, ulid.ULID{}, empty, "an empty log must report the zero ULID, never an error")

	id := ulid.Make()
	env := hostCreatedEnvelope(id, "10.5.0.1", "latest-id.example.com", time.Now().UTC().Truncate(time.Millisecond))
	require.NoError(t, store.AppendEvent(ctx, id, env, 0))

	max, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Equal(t, env.EventID, max, "LatestEventID must equal the greatest appended EventID")

	update := makeEnvelope(id, domain.IPAddressChanged{
		OldIP:     "10.5.0.1",
		NewIP:     "10.5.0.2",
		ChangedAt: time.Now().UTC(),
	}, 2, time.Now().UTC())
	require.NoError(t, store.AppendEvent(ctx, id, update, 1))

	after, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Equal(t, update.EventID, after, "a further append must advance LatestEventID to its own EventID")
	require.Positive(t, after.Compare(max), "LatestEventID must strictly advance across a real append")
}

// TestEventStoreCompactionAdvancesLatestEventID is the storage-level mirror
// of the sqlite package's own compaction regression test (T-1-38), lifted to
// the level every EventStore backend must satisfy: compacting an aggregate
// must leave LatestEventID strictly greater than it was before, never
// pinned and never regressed.
func TestEventStoreCompactionAdvancesLatestEventID(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	id := ulid.Make()

	mustAppendCreated(t, store, id, "10.5.1.1", "compact-latest.example.com")
	for i := 0; i < 3; i++ {
		ev, _ := domain.NewHostEvent(domain.IPAddressChanged{NewIP: fmt.Sprintf("10.5.1.%d", i+2), ChangedAt: time.Now().UTC()})
		env := domain.EventEnvelope{EventID: eventid.New(), AggregateID: id, Event: ev, Version: int64(i + 2), CreatedAt: time.Now().UTC()}
		require.NoError(t, store.AppendEvent(ctx, id, env, int64(i+1)))
	}

	before, err := store.LatestEventID(ctx)
	require.NoError(t, err)

	_, err = store.CompactAggregate(ctx, id)
	require.NoError(t, err)

	after, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Positive(t, after.Compare(before), "compaction must leave LatestEventID strictly greater than before, never pinned or regressed")
}

// TestEventStoreAppendNeverLowersLatestEventID pins the in-transaction
// ordering guard (T-1-33, T-1-51, T-1-55) at the level every EventStore
// backend must satisfy: no commit may ever leave LatestEventID at or below
// its pre-append value.
//
// A caller-supplied EventID that sorts below the current maximum admits
// exactly two acceptable outcomes, not one — the append returned an error
// and LatestEventID is unchanged, or the append succeeded and LatestEventID
// is strictly greater than the recorded value. sqlite re-mints (the second
// branch); a future backend may legitimately choose to reject instead (the
// first branch). Neither may leave a committed event below the maximum,
// which is the one thing this case actually asserts.
//
// The zero-ID-into-empty-store sub-case (review round-4 H1) runs FIRST, on
// the store exactly as RunAll's factory hands it in — genuinely empty,
// having appended nothing yet. Appending a zero-value EventID into a store
// that has never held an event must not leave LatestEventID at the zero
// ULID. A backend that stored the zero ID verbatim would make LatestEventID
// indistinguishable from storage.ZeroChangeID, reporting an empty log while
// actually holding one committed event. No production path mints a zero
// EventID — the interface's caller-constructed envelopes
// (storage.go AppendEvent doc comment) are the only way a zero ID reaches an
// implementation, which is exactly why this compliance case, not a
// production code path, is where a future backend meets this the first time
// someone forgets to mint one. The lower-caller-supplied-ID sub-case runs
// SECOND, reusing the same store — by then it holds the zero-ID sub-case's
// event, which is exactly the non-empty precondition that sub-case needs,
// so this one function needs only the one store RunAll already constructs.
func TestEventStoreAppendNeverLowersLatestEventID(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	// Sub-case 1 (review round-4 H1): a zero EventID into a store that has
	// never held any event — a zero-value domain.EventEnvelope carries a
	// zero EventID, so this is exactly what a caller-constructed envelope
	// looks like when nobody minted one. Must run before anything else
	// appends, since the property under test ("never held an event") is
	// process-wide over the whole events table, not per-aggregate.
	beforeEmpty, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Equal(t, ulid.ULID{}, beforeEmpty, "the store handed to this compliance case must start genuinely empty")

	zeroHostEvent, err := domain.NewHostEvent(domain.HostCreated{
		IPAddress: "10.5.2.9",
		Hostname:  "zero-id.example.com",
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	zeroAggID := ulid.Make()
	zeroEnv := domain.EventEnvelope{
		EventID:     ulid.ULID{}, // zero value, deliberately not minted
		AggregateID: zeroAggID,
		Event:       zeroHostEvent,
		Version:     1,
		CreatedAt:   time.Now().UTC(),
	}
	zeroAppendErr := store.AppendEvent(ctx, zeroAggID, zeroEnv, 0)
	if zeroAppendErr != nil {
		afterZero, latestErr := store.LatestEventID(ctx)
		require.NoError(t, latestErr)
		require.Equal(t, ulid.ULID{}, afterZero, "a rejected zero-ID append must leave the store empty")
	} else {
		afterZero, latestErr := store.LatestEventID(ctx)
		require.NoError(t, latestErr)
		require.NotEqual(t, ulid.ULID{}, afterZero, "an accepted zero-ID append must not leave LatestEventID at the zero ULID")
		require.NotEqual(t, storage.ZeroChangeID, afterZero.String(),
			"LatestEventID must not collide with storage.ZeroChangeID after accepting a real event")
	}

	// Sub-case 2: a caller-supplied ID that sorts below the current maximum.
	// The store is non-empty by now (sub-case 1 above), satisfying this
	// sub-case's own precondition for free.
	id := ulid.Make()
	mustAppendCreated(t, store, id, "10.5.2.1", "never-lowers.example.com")
	recorded, err := store.LatestEventID(ctx)
	require.NoError(t, err)

	lowerHostEvent, err := domain.NewHostEvent(domain.IPAddressChanged{
		OldIP: "10.5.2.1", NewIP: "10.5.2.2", ChangedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	pastID := ulid.MustNew(ulid.Timestamp(time.Now().Add(-time.Hour)), nil)
	lowerEnv := domain.EventEnvelope{
		EventID:     pastID,
		AggregateID: id,
		Event:       lowerHostEvent,
		Version:     2,
		CreatedAt:   time.Now().UTC(),
	}
	appendErr := store.AppendEvent(ctx, id, lowerEnv, 1)
	if appendErr != nil {
		after, latestErr := store.LatestEventID(ctx)
		require.NoError(t, latestErr)
		require.Equal(t, recorded, after, "a rejected lower-ID append must leave LatestEventID unchanged")
	} else {
		after, latestErr := store.LatestEventID(ctx)
		require.NoError(t, latestErr)
		require.Positive(t, after.Compare(recorded), "an accepted lower-ID append must still advance LatestEventID")
	}
}

// ---------- HostProjection compliance ----------

// TestHostProjectionListAll verifies that creating hosts via events causes them
// to appear in ListAll.
func TestHostProjectionListAll(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	// Empty store returns empty slice, not an error.
	entries, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Empty(t, entries)

	agg1 := ulid.Make()
	agg2 := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, agg1, hostCreatedEnvelope(agg1, "10.4.0.1", "list1.local", now), 0))
	require.NoError(t, store.AppendEvent(ctx, agg2, hostCreatedEnvelope(agg2, "10.4.0.2", "list2.local", now), 0))

	entries, err = store.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	ips := make(map[string]bool)
	for _, e := range entries {
		ips[e.IP] = true
	}
	require.True(t, ips["10.4.0.1"])
	require.True(t, ips["10.4.0.2"])
}

// TestHostProjectionGetByID verifies point lookup by aggregate ID.
func TestHostProjectionGetByID(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, aggID, hostCreatedEnvelope(aggID, "10.5.0.1", "byid.local", now), 0))

	entry, err := store.GetByID(ctx, aggID)
	require.NoError(t, err)
	require.Equal(t, aggID, entry.ID)
	require.Equal(t, "10.5.0.1", entry.IP)
	require.Equal(t, "byid.local", entry.Hostname)

	// Unknown ID must return a "not found" error.
	_, err = store.GetByID(ctx, ulid.Make())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestHostProjectionDeletedExcludedFromListAll verifies that a HostDeleted event
// removes the entry from ListAll.
func TestHostProjectionDeletedExcludedFromListAll(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, aggID, hostCreatedEnvelope(aggID, "10.6.0.1", "todelete.local", now), 0))

	del := makeEnvelope(aggID, domain.HostDeleted{
		IPAddress: "10.6.0.1",
		Hostname:  "todelete.local",
		DeletedAt: now.Add(time.Second),
	}, 2, now.Add(time.Second))
	require.NoError(t, store.AppendEvent(ctx, aggID, del, 1))

	entries, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// TestHostProjectionSearchByQuery verifies that Search with a text Query
// returns matching hosts and returns an empty slice for a non-matching query.
func TestHostProjectionSearchByQuery(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, aggID, hostCreatedEnvelope(aggID, "10.8.0.1", "search-target.local", now), 0))

	// Matching query — host must be returned.
	results, err := store.Search(ctx, domain.SearchFilter{Query: ptr("search-target")})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, aggID, results[0].ID)
	require.Equal(t, "10.8.0.1", results[0].IP)
	require.Equal(t, "search-target.local", results[0].Hostname)

	// Non-matching query — must return empty, not an error.
	results, err = store.Search(ctx, domain.SearchFilter{Query: ptr("no-such-host-xyzzy")})
	require.NoError(t, err)
	require.Empty(t, results)
}

// TestHostProjectionFindByIPAndHostname verifies point lookup by IP + hostname
// pair and nil-return for an unknown pair.
func TestHostProjectionFindByIPAndHostname(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	aggID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	require.NoError(t, store.AppendEvent(ctx, aggID, hostCreatedEnvelope(aggID, "10.9.0.1", "findpair.local", now), 0))

	// Matching pair — must return the entry.
	entry, err := store.FindByIPAndHostname(ctx, "10.9.0.1", "findpair.local")
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, aggID, entry.ID)
	require.Equal(t, "10.9.0.1", entry.IP)
	require.Equal(t, "findpair.local", entry.Hostname)

	// Non-existent pair — must return a "not found" error.
	entry, err = store.FindByIPAndHostname(ctx, "10.9.0.1", "does-not-exist.local")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
	require.Nil(t, entry)
}

// currentMaxAggregateID returns the greatest aggregate ID currently in
// store (the zero ULID if the store is empty), then sleeps past a
// millisecond boundary. A subtest that captures this value BEFORE seeding
// its own fixtures gets a cursor strictly less than every aggregate it is
// about to create — including on a store already populated by earlier
// subtests within the same TestHostProjectionListPage run — without relying
// on ulid.Make() being monotonic across separate calls (it is only
// monotonic in expectation at millisecond granularity; ties within the same
// millisecond break on unordered random entropy). The sleep is what turns
// "very likely ordered" into "deterministically ordered".
func currentMaxAggregateID(t *testing.T, ctx context.Context, store storage.Storage) ulid.ULID {
	t.Helper()
	entries, err := store.ListAll(ctx)
	require.NoError(t, err)
	var maxID ulid.ULID
	for _, e := range entries {
		if e.ID.Compare(maxID) > 0 {
			maxID = e.ID
		}
	}
	time.Sleep(2 * time.Millisecond)
	return maxID
}

// idsOf extracts each entry's aggregate ID, in order, for compact
// order/membership assertions against a ListPage result.
func idsOf(entries []domain.HostEntry) []ulid.ULID {
	ids := make([]ulid.ULID, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	return ids
}

// TestHostProjectionListPage exercises storage.HostProjection.ListPage's
// keyset contract (D-05..D-10): empty/singleton pages, the exact-boundary
// cursor exclusion, exactly-once coverage across varying page sizes,
// cross-page ascending order, idempotency, D-08's fill-to-N loop over
// deleted aggregates, drain equivalence with ListAll, and concurrent full
// drains. Every subtest after "empty store" isolates itself from prior
// subtests' fixtures via currentMaxAggregateID, so subtests may run in any
// relative order without polluting each other's exact-count assertions.
func TestHostProjectionListPage(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	t.Run("empty store", func(t *testing.T) {
		entries, next, done, err := store.ListPage(ctx, ulid.ULID{}, 10)
		require.NoError(t, err)
		require.Empty(t, entries)
		require.True(t, done)
		require.Equal(t, ulid.ULID{}, next)
	})

	t.Run("single aggregate", func(t *testing.T) {
		baseline := currentMaxAggregateID(t, ctx, store)
		aggID := ulid.Make()
		now := time.Now().UTC().Truncate(time.Millisecond)
		require.NoError(t, store.AppendEvent(ctx, aggID, hostCreatedEnvelope(aggID, "10.20.0.1", "page-single.local", now), 0))

		entries, next, done, err := store.ListPage(ctx, baseline, 10)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, aggID, entries[0].ID)
		require.True(t, done)
		require.Equal(t, aggID, next)
	})

	t.Run("exact-boundary cursor separates rather than merges", func(t *testing.T) {
		baseline := currentMaxAggregateID(t, ctx, store)
		now := time.Now().UTC().Truncate(time.Millisecond)
		ids := make([]ulid.ULID, 3)
		for i := range ids {
			ids[i] = ulid.Make()
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].Compare(ids[j]) < 0 })
		for i, id := range ids {
			require.NoError(t, store.AppendEvent(ctx, id, hostCreatedEnvelope(id, "10.20.1.1", fmt.Sprintf("page-boundary%d.local", i), now), 0))
		}

		// Sanity: from baseline, exactly these 3 fixtures exist — confirms
		// the isolation baseline is doing its job before testing the
		// boundary itself.
		full, _, fullDone, err := store.ListPage(ctx, baseline, 10)
		require.NoError(t, err)
		require.True(t, fullDone)
		require.Equal(t, ids, idsOf(full))

		page, next, done, err := store.ListPage(ctx, ids[1], 10)
		require.NoError(t, err)
		require.True(t, done)
		require.Len(t, page, 1, "the cursor's own aggregate (ids[1]) must be excluded, and nothing beyond ids[2] exists yet")
		require.Equal(t, ids[2], page[0].ID)
		require.Equal(t, ids[2], next)
	})

	t.Run("exactly-once across pages of varying size", func(t *testing.T) {
		baseline := currentMaxAggregateID(t, ctx, store)
		now := time.Now().UTC().Truncate(time.Millisecond)
		const n = 9
		ids := make([]ulid.ULID, n)
		for i := range ids {
			ids[i] = ulid.Make()
			require.NoError(t, store.AppendEvent(ctx, ids[i], hostCreatedEnvelope(ids[i], "10.20.2.1", fmt.Sprintf("page-exact%d.local", i), now), 0))
		}
		want := make(map[ulid.ULID]struct{}, n)
		for _, id := range ids {
			want[id] = struct{}{}
		}

		for _, pageSize := range []int{1, 2, n} {
			t.Run(fmt.Sprintf("pageSize=%d", pageSize), func(t *testing.T) {
				got := make(map[ulid.ULID]struct{}, n)
				cursor := baseline
				for {
					page, next, done, err := store.ListPage(ctx, cursor, pageSize)
					require.NoError(t, err)
					for _, e := range page {
						_, dup := got[e.ID]
						require.False(t, dup, "aggregate %s returned more than once", e.ID)
						got[e.ID] = struct{}{}
					}
					if done {
						break
					}
					cursor = next
				}
				require.Equal(t, want, got, "drain with page size %d must yield the identical complete set", pageSize)
			})
		}
	})

	t.Run("ascending order across page boundaries", func(t *testing.T) {
		// No isolation baseline here — this asserts a property (strict
		// ascending order and total-count agreement with ListAll) that holds
		// regardless of how much fixture data prior subtests contributed.
		want, err := store.ListAll(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, want, "prior subtests must have seeded at least one aggregate by this point")

		var drained []domain.HostEntry
		var cursor ulid.ULID
		for {
			page, next, done, pageErr := store.ListPage(ctx, cursor, 3)
			require.NoError(t, pageErr)
			for i := 1; i < len(page); i++ {
				require.Positivef(t, page[i].ID.Compare(page[i-1].ID), "within-page order must be strictly ascending")
			}
			if len(drained) > 0 && len(page) > 0 {
				require.Positivef(t, page[0].ID.Compare(drained[len(drained)-1].ID), "order must remain strictly ascending across a page boundary")
			}
			drained = append(drained, page...)
			if done {
				break
			}
			cursor = next
		}
		require.Len(t, drained, len(want), "draining ListPage must visit every aggregate ListAll sees")
	})

	t.Run("idempotency", func(t *testing.T) {
		page1, next1, done1, err := store.ListPage(ctx, ulid.ULID{}, 5)
		require.NoError(t, err)
		page2, next2, done2, err := store.ListPage(ctx, ulid.ULID{}, 5)
		require.NoError(t, err)

		require.Equal(t, page1, page2, "two identical ListPage calls against an unchanged store must return equal slices")
		require.Equal(t, next1, next2)
		require.Equal(t, done1, done2)
	})

	t.Run("fill-to-N with deleted aggregates", func(t *testing.T) {
		baseline := currentMaxAggregateID(t, ctx, store)
		now := time.Now().UTC().Truncate(time.Millisecond)

		const deletedCount = 5
		const liveCount = 4
		ids := make([]ulid.ULID, 0, deletedCount+liveCount)
		for range deletedCount + liveCount {
			ids = append(ids, ulid.Make())
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].Compare(ids[j]) < 0 })

		for i, id := range ids {
			hostname := fmt.Sprintf("page-fill%02d.local", i)
			require.NoError(t, store.AppendEvent(ctx, id, hostCreatedEnvelope(id, "10.20.3.1", hostname, now), 0))
			if i < deletedCount {
				del := makeEnvelope(id, domain.HostDeleted{
					IPAddress: "10.20.3.1",
					Hostname:  hostname,
					DeletedAt: now.Add(time.Second),
				}, 2, now.Add(time.Second))
				require.NoError(t, store.AppendEvent(ctx, id, del, 1))
			}
		}

		// Requesting 3 live entries must skip all 5 deleted aggregates
		// internally and return a FULL page of 3, not a short page — even
		// though 8 of these 9 fixture aggregates had to be scanned to find
		// them, and even though the aggregate-ID space is not yet exhausted.
		page, next, done, err := store.ListPage(ctx, baseline, 3)
		require.NoError(t, err)
		require.False(t, done, "one live aggregate remains beyond this page, so it must not be done")
		require.Len(t, page, 3)

		// Draining the remainder must yield exactly the one remaining live
		// entry, and THIS page — the one that actually exhausts the
		// aggregate-ID space — is where done becomes true.
		page2, _, done2, err := store.ListPage(ctx, next, 3)
		require.NoError(t, err)
		require.True(t, done2)
		require.Len(t, page2, 1)
	})

	t.Run("drain equivalence with ListAll", func(t *testing.T) {
		want, err := store.ListAll(ctx)
		require.NoError(t, err)

		var drained []domain.HostEntry
		var cursor ulid.ULID
		for {
			page, next, done, pageErr := store.ListPage(ctx, cursor, 4)
			require.NoError(t, pageErr)
			drained = append(drained, page...)
			if done {
				break
			}
			cursor = next
		}
		require.Equal(t, want, drained, "draining ListPage must equal ListAll element-for-element")
	})

	t.Run("concurrent full drains observe the same complete set", func(t *testing.T) {
		const goroutines = 5
		results := make([][]ulid.ULID, goroutines)
		var wg sync.WaitGroup
		wg.Add(goroutines)
		for g := range goroutines {
			go func(idx int) {
				defer wg.Done()
				var ids []ulid.ULID
				var cursor ulid.ULID
				for {
					page, next, done, err := store.ListPage(ctx, cursor, 3)
					if err != nil {
						return // asserted against below via a nil check on results[idx]
					}
					for _, e := range page {
						ids = append(ids, e.ID)
					}
					if done {
						break
					}
					cursor = next
				}
				results[idx] = ids
			}(g)
		}
		wg.Wait()

		toSet := func(ids []ulid.ULID) map[ulid.ULID]struct{} {
			set := make(map[ulid.ULID]struct{}, len(ids))
			for _, id := range ids {
				set[id] = struct{}{}
			}
			return set
		}
		require.NotEmpty(t, results[0], "concurrent drain must not have failed silently")
		want := toSet(results[0])
		for i := 1; i < goroutines; i++ {
			require.Equal(t, want, toSet(results[i]), "goroutine %d must observe the same complete entry set as goroutine 0", i)
		}
	})
}

// ---------- SnapshotStore compliance ----------

// TestSnapshotStoreRoundTrip verifies that a snapshot saved via SaveSnapshot can
// be retrieved intact via GetSnapshot with all fields preserved.
func TestSnapshotStoreRoundTrip(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	snapID := ulid.Make()
	now := time.Now().UTC().Truncate(time.Millisecond)

	snap := domain.Snapshot{
		SnapshotID:   snapID,
		CreatedAt:    now,
		HostsContent: "",
		Entries: []domain.HostEntry{
			{
				ID:        ulid.Make(),
				IP:        "10.7.0.1",
				Hostname:  "snap.local",
				Tags:      []string{"compliance"},
				Aliases:   []string{},
				Version:   1,
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		EntryCount: 1,
		Trigger:    "compliance-test",
		Name:       ptr("compliance snapshot"),
	}

	require.NoError(t, store.SaveSnapshot(ctx, snap))

	got, err := store.GetSnapshot(ctx, snapID)
	require.NoError(t, err)
	require.Equal(t, snapID, got.SnapshotID)
	require.Equal(t, int32(1), got.EntryCount)
	require.Equal(t, "compliance-test", got.Trigger)
	require.NotNil(t, got.Name)
	require.Equal(t, "compliance snapshot", *got.Name)
	require.Len(t, got.Entries, 1)
	require.Equal(t, "10.7.0.1", got.Entries[0].IP)
}

// TestSnapshotStoreNotFound verifies that GetSnapshot for an unknown ID returns
// an error containing "not found".
func TestSnapshotStoreNotFound(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	_, err := store.GetSnapshot(ctx, ulid.Make())
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestSnapshotStoreDelete verifies that DeleteSnapshot removes the snapshot and
// subsequent retrieval returns "not found".
func TestSnapshotStoreDelete(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	snapID := ulid.Make()

	require.NoError(t, store.SaveSnapshot(ctx, domain.Snapshot{
		SnapshotID:   snapID,
		CreatedAt:    time.Now().UTC(),
		HostsContent: "",
		EntryCount:   0,
		Trigger:      "manual",
	}))

	require.NoError(t, store.DeleteSnapshot(ctx, snapID))

	_, err := store.GetSnapshot(ctx, snapID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

// TestSnapshotStoreListOrdering verifies that ListSnapshots returns results
// ordered by CreatedAt descending (newest first).
func TestSnapshotStoreListOrdering(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	early := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	late := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	oldID := ulid.Make()
	newID := ulid.Make()

	require.NoError(t, store.SaveSnapshot(ctx, domain.Snapshot{
		SnapshotID: oldID, CreatedAt: early, HostsContent: "", EntryCount: 0, Trigger: "auto",
	}))
	require.NoError(t, store.SaveSnapshot(ctx, domain.Snapshot{
		SnapshotID: newID, CreatedAt: late, HostsContent: "", EntryCount: 0, Trigger: "auto",
	}))

	metas, err := store.ListSnapshots(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, metas, 2)
	require.Equal(t, newID, metas[0].SnapshotID, "newest snapshot must be first")
	require.Equal(t, oldID, metas[1].SnapshotID)
}

// TestSnapshotStoreRetentionByCount verifies that ApplyRetentionPolicy removes
// older snapshots when the count exceeds maxCount.
func TestSnapshotStoreRetentionByCount(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()

	for i := range 5 {
		require.NoError(t, store.SaveSnapshot(ctx, domain.Snapshot{
			SnapshotID:   ulid.Make(),
			CreatedAt:    time.Now().UTC().Add(time.Duration(i) * time.Minute),
			HostsContent: "",
			EntryCount:   0,
			Trigger:      "auto",
		}))
	}

	maxCount := 2
	deleted, err := store.ApplyRetentionPolicy(ctx, &maxCount, nil)
	require.NoError(t, err)
	require.Equal(t, 3, deleted)

	metas, err := store.ListSnapshots(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, metas, 2)
}

// ---------- Storage lifecycle compliance ----------

// TestStorageInitializeIdempotent verifies that calling Initialize multiple
// times does not return an error.
func TestStorageInitializeIdempotent(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))
}

// TestStorageHealthCheck verifies that HealthCheck returns nil for a live store.
func TestStorageHealthCheck(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, store.HealthCheck(ctx))
}

// RunAll executes every compliance test against the provided store. Callers
// pass a factory function that returns a fresh, initialised store for each
// sub-test, keeping tests hermetic.
//
// Usage in a backend test file:
//
//	func TestCompliance(t *testing.T) {
//	    storagetest.RunAll(t, func(t *testing.T) storage.Storage {
//	        s, err := mybackend.New(...)
//	        require.NoError(t, err)
//	        require.NoError(t, s.Initialize(context.Background()))
//	        t.Cleanup(func() { _ = s.Close() })
//	        return s
//	    })
//	}
func RunAll(t *testing.T, factory func(t *testing.T) storage.Storage) {
	t.Helper()

	// EventStore
	t.Run("EventStoreAppendAndLoad", func(t *testing.T) {
		TestEventStoreAppendAndLoad(t, factory(t))
	})
	t.Run("EventStoreVersionConflict", func(t *testing.T) {
		TestEventStoreVersionConflict(t, factory(t))
	})
	t.Run("EventStoreEmptyLoad", func(t *testing.T) {
		TestEventStoreEmptyLoad(t, factory(t))
	})
	t.Run("EventStoreGetCurrentVersion", func(t *testing.T) {
		TestEventStoreGetCurrentVersion(t, factory(t))
	})
	t.Run("EventStoreMultipleAggregatesIsolated", func(t *testing.T) {
		TestEventStoreMultipleAggregatesIsolated(t, factory(t))
	})
	t.Run("EventStoreBatchAppend", func(t *testing.T) {
		TestEventStoreBatchAppend(t, factory(t))
	})
	t.Run("EventStoreBatchAppendRollback", func(t *testing.T) {
		TestEventStoreBatchAppendRollback(t, factory(t))
	})
	t.Run("EventStoreListAggregateIDs", func(t *testing.T) {
		TestEventStoreListAggregateIDs(t, factory(t))
	})
	t.Run("EventStoreCompactAggregate", func(t *testing.T) {
		TestEventStoreCompactAggregate(t, factory(t))
	})
	t.Run("EventStoreCompactAggregateNoop", func(t *testing.T) {
		TestEventStoreCompactAggregateNoop(t, factory(t))
	})
	t.Run("EventStoreCompactAggregateDeleted", func(t *testing.T) {
		TestEventStoreCompactAggregateDeleted(t, factory(t))
	})
	t.Run("EventStoreLatestEventID", func(t *testing.T) {
		TestEventStoreLatestEventID(t, factory(t))
	})
	t.Run("EventStoreCompactionAdvancesLatestEventID", func(t *testing.T) {
		TestEventStoreCompactionAdvancesLatestEventID(t, factory(t))
	})
	t.Run("EventStoreAppendNeverLowersLatestEventID", func(t *testing.T) {
		TestEventStoreAppendNeverLowersLatestEventID(t, factory(t))
	})

	// HostProjection
	t.Run("HostProjectionListAll", func(t *testing.T) {
		TestHostProjectionListAll(t, factory(t))
	})
	t.Run("HostProjectionListPage", func(t *testing.T) {
		TestHostProjectionListPage(t, factory(t))
	})
	t.Run("HostProjectionGetByID", func(t *testing.T) {
		TestHostProjectionGetByID(t, factory(t))
	})
	t.Run("HostProjectionDeletedExcludedFromListAll", func(t *testing.T) {
		TestHostProjectionDeletedExcludedFromListAll(t, factory(t))
	})
	t.Run("HostProjectionSearchByQuery", func(t *testing.T) {
		TestHostProjectionSearchByQuery(t, factory(t))
	})
	t.Run("HostProjectionFindByIPAndHostname", func(t *testing.T) {
		TestHostProjectionFindByIPAndHostname(t, factory(t))
	})

	// SnapshotStore
	t.Run("SnapshotStoreRoundTrip", func(t *testing.T) {
		TestSnapshotStoreRoundTrip(t, factory(t))
	})
	t.Run("SnapshotStoreNotFound", func(t *testing.T) {
		TestSnapshotStoreNotFound(t, factory(t))
	})
	t.Run("SnapshotStoreDelete", func(t *testing.T) {
		TestSnapshotStoreDelete(t, factory(t))
	})
	t.Run("SnapshotStoreListOrdering", func(t *testing.T) {
		TestSnapshotStoreListOrdering(t, factory(t))
	})
	t.Run("SnapshotStoreRetentionByCount", func(t *testing.T) {
		TestSnapshotStoreRetentionByCount(t, factory(t))
	})

	// Lifecycle
	t.Run("StorageInitializeIdempotent", func(t *testing.T) {
		TestStorageInitializeIdempotent(t, factory(t))
	})
	t.Run("StorageHealthCheck", func(t *testing.T) {
		TestStorageHealthCheck(t, factory(t))
	})
}
