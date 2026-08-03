package sqlite

import (
	"context"
	"log/slog"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"
	"zombiezen.com/go/sqlite"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// seededAggregate tracks a test-seeded aggregate's identity and current
// version, so later sub-cases (delete, compact) can append a well-formed
// next event without re-deriving the version from storage.
type seededAggregate struct {
	id      ulid.ULID
	version int64
}

// seedRandomizedAggregates creates n aggregates with real ULIDs, appends
// them to store in a SHUFFLED order (never insertion/generation order), and
// gives each a randomized 1-3 event depth so the index scan this test
// exercises is not trivially sequential. Returns the seeded aggregates
// keyed by their final version, for later mutation by the delete/compact
// sub-case.
func seedRandomizedAggregates(t *testing.T, ctx context.Context, store *Storage, n int) map[ulid.ULID]*seededAggregate {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)

	ids := make([]ulid.ULID, n)
	for i := range ids {
		ids[i] = ulid.Make()
	}

	// Shuffle a copy of the generation order before appending, so insertion
	// order cannot coincide with ascending ULID order by construction.
	insertOrder := make([]int, n)
	for i := range insertOrder {
		insertOrder[i] = i
	}
	rnd := rand.New(rand.NewSource(20260803)) // deterministic seed: reproducible shuffle across runs
	rnd.Shuffle(n, func(i, j int) { insertOrder[i], insertOrder[j] = insertOrder[j], insertOrder[i] })

	seeded := make(map[ulid.ULID]*seededAggregate, n)
	for idx, i := range insertOrder {
		id := ids[i]
		ip := "10.0.0.1"
		hostname := ulid.Make().String() + ".local"

		env := makeEnvelope(id, domain.HostCreated{
			IPAddress: ip,
			Hostname:  hostname,
			Aliases:   []string{},
			Tags:      []string{},
			CreatedAt: now,
		}, 1, now)
		require.NoError(t, store.AppendEvent(ctx, id, env, 0))

		// Vary depth 1-3 events per aggregate (deterministic by position,
		// not random, so the fixture's total event count is stable).
		depth := 1 + idx%3
		version := int64(1)
		for extra := 0; extra < depth-1; extra++ {
			version++
			ev := makeEnvelope(id, domain.CommentUpdated{
				NewComment: ptr("seed comment"),
				UpdatedAt:  now.Add(time.Duration(extra+1) * time.Second),
			}, version, now.Add(time.Duration(extra+1)*time.Second))
			require.NoError(t, store.AppendEvent(ctx, id, ev, version-1))
		}

		seeded[id] = &seededAggregate{id: id, version: version}
	}

	return seeded
}

// distinctAggregateIDs drives the real getDistinctAggregateIDs against store
// through zombiezen.com/go/sqlite, the production driver.
func distinctAggregateIDs(t *testing.T, ctx context.Context, store *Storage) []ulid.ULID {
	t.Helper()
	var ids []ulid.ULID
	err := store.withConn(ctx, func(conn *sqlite.Conn) error {
		var innerErr error
		ids, innerErr = getDistinctAggregateIDs(conn)
		return innerErr
	})
	require.NoError(t, err)
	return ids
}

// assertStrictlyAscendingAndComplete asserts got is strictly ascending by
// ulid.ULID.Compare (not merely sortedness-after-sorting, and not merely a
// prefix of the seeded set) and that its element set equals wantSet exactly,
// so a truncated result cannot pass.
func assertStrictlyAscendingAndComplete(t *testing.T, got []ulid.ULID, wantSet map[ulid.ULID]*seededAggregate) {
	t.Helper()

	require.Len(t, got, len(wantSet), "returned count must equal the seeded aggregate count")

	for i := 1; i < len(got); i++ {
		require.Positivef(t, got[i].Compare(got[i-1]), "element %d (%s) must sort strictly after element %d (%s)", i, got[i], i-1, got[i-1])
	}

	gotSet := make(map[ulid.ULID]struct{}, len(got))
	for _, id := range got {
		gotSet[id] = struct{}{}
	}
	for id := range wantSet {
		_, ok := gotSet[id]
		require.Truef(t, ok, "seeded aggregate %s missing from returned order", id)
	}
}

// TestGetDistinctAggregateIDs_OrderMatchesDeFacto pins, by EXECUTION against
// the real zombiezen.com/go/sqlite driver (not by reading the query), that
// today's bare `SELECT DISTINCT aggregate_id FROM events` (no ORDER BY)
// already returns ascending ULID-TEXT order. This closes RESEARCH.md
// Assumption A1 and Open Question Q-01: that session's proof used the
// sqlite3 CLI and Python's sqlite3 module, not the production driver.
// D-10's later explicit `ORDER BY aggregate_id` must be a documented no-op
// against this same behavior.
func TestGetDistinctAggregateIDs_OrderMatchesDeFacto(t *testing.T) {
	ctx := context.Background()
	store, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	// At least 200 aggregates, randomized insertion order, varying event
	// depth per aggregate (Q-01, memory b9gbp3bp20).
	const n = 250
	seeded := seedRandomizedAggregates(t, ctx, store, n)

	t.Run("baseline: ascending order, complete set", func(t *testing.T) {
		got := distinctAggregateIDs(t, ctx, store)
		assertStrictlyAscendingAndComplete(t, got, seeded)
	})

	// Pick two distinct seeded aggregates for the delete/compact sub-case:
	// one is tombstoned (HostDeleted appended), the other is compacted.
	// Both operations retain the aggregate_id row in `events` (compaction
	// reuses the same aggregate_id with a freshly minted event_id per
	// RESEARCH.md Pitfall 5; a delete is itself just another event on the
	// same aggregate), so the seeded set's cardinality is unchanged by
	// either operation.
	orderedSeeded := make([]ulid.ULID, 0, len(seeded))
	for id := range seeded {
		orderedSeeded = append(orderedSeeded, id)
	}
	sort.Slice(orderedSeeded, func(i, j int) bool { return orderedSeeded[i].Compare(orderedSeeded[j]) < 0 })
	require.GreaterOrEqual(t, len(orderedSeeded), 2)
	deleteTarget := orderedSeeded[0]
	compactTarget := orderedSeeded[len(orderedSeeded)/2]

	// Capture the compacted aggregate's index in keyset order BEFORE any
	// mutation, so the post-compaction assertion has a baseline.
	before := distinctAggregateIDs(t, ctx, store)
	indexBefore := -1
	for i, id := range before {
		if id == compactTarget {
			indexBefore = i
			break
		}
	}
	require.GreaterOrEqualf(t, indexBefore, 0, "compaction target %s must appear in the pre-mutation order", compactTarget)

	t.Run("after a tombstone delete", func(t *testing.T) {
		now := time.Now().UTC()
		del := seeded[deleteTarget]
		env := makeEnvelope(deleteTarget, domain.HostDeleted{
			IPAddress: "10.0.0.1",
			Hostname:  "deleted.local",
			DeletedAt: now,
		}, del.version+1, now)
		require.NoError(t, store.AppendEvent(ctx, deleteTarget, env, del.version))
		del.version++

		got := distinctAggregateIDs(t, ctx, store)
		assertStrictlyAscendingAndComplete(t, got, seeded)
	})

	t.Run("after CompactAggregate on one aggregate", func(t *testing.T) {
		_, err := store.CompactAggregate(ctx, compactTarget)
		require.NoError(t, err)

		got := distinctAggregateIDs(t, ctx, store)
		assertStrictlyAscendingAndComplete(t, got, seeded)

		indexAfter := -1
		for i, id := range got {
			if id == compactTarget {
				indexAfter = i
				break
			}
		}
		require.GreaterOrEqualf(t, indexAfter, 0, "compaction target %s must still appear in the post-compaction order", compactTarget)
		require.Equalf(t, indexBefore, indexAfter,
			"compaction reuses the same aggregate_id (RESEARCH.md Pitfall 5); the aggregate's keyset position must not move")
	})
}
