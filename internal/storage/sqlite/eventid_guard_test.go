package sqlite

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/eventid"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// newGuardTestStore creates a fresh, file-backed Storage under t.TempDir().
// A real file (rather than the shared anonymous ":memory:" DSN other tests
// in this package use) is deliberate: TestInitialize_SeedsGeneratorFromPersistedLog
// below needs to reopen the SAME database from a second Storage instance,
// which the anonymous in-memory DSN cannot do once the first instance closes.
func newGuardTestStore(t *testing.T, dbPath string) *Storage {
	t.Helper()
	store, err := New(dbPath, slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(context.Background()))
	return store
}

// pastULID builds a ULID whose embedded timestamp is `before` earlier than
// now, with zero entropy bytes. Used to construct a caller-supplied EventID
// that is guaranteed to sort below anything minted "now" or later,
// regardless of entropy, since the timestamp prefix dominates ULID
// comparison.
func pastULID(t *testing.T, before time.Duration) ulid.ULID {
	t.Helper()
	id, err := ulid.New(ulid.Timestamp(time.Now().Add(-before)), nil)
	require.NoError(t, err)
	return id
}

// hostCreatedEnvelopeWithID builds a HostCreated envelope carrying the given
// EventID verbatim (no minting), so tests can supply an explicit,
// controlled ID.
func hostCreatedEnvelopeWithID(t *testing.T, id, aggID ulid.ULID, ip, hostname string) domain.EventEnvelope {
	t.Helper()
	he, err := domain.NewHostEvent(domain.HostCreated{
		IPAddress: ip,
		Hostname:  hostname,
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	return domain.EventEnvelope{
		EventID:     id,
		AggregateID: aggID,
		Event:       he,
		Version:     1,
		CreatedAt:   time.Now().UTC(),
	}
}

// TestInsertEvent_LowerCallerSuppliedIDStillAdvancesMax is the direct
// regression test for review round-3 H4 / T-1-53: a caller-constructed
// envelope carrying an EventID that sorts below the log's current maximum
// must still leave LatestEventID strictly greater than it was before the
// append, because insertEvent's guard re-mints it rather than inserting it
// verbatim.
func TestInsertEvent_LowerCallerSuppliedIDStillAdvancesMax(t *testing.T) {
	store := newGuardTestStore(t, filepath.Join(t.TempDir(), "guard.db"))
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	id := ulid.Make()
	require.NoError(t, store.AppendEvent(ctx, id, hostCreatedEnvelopeWithID(t, eventid.New(), id, "10.6.0.1", "lower-caller-id.example.com"), 0))

	recorded, err := store.LatestEventID(ctx)
	require.NoError(t, err)

	lowerID := pastULID(t, time.Hour)
	lowerEnv := hostCreatedEnvelopeWithID(t, lowerID, id, "10.6.0.1", "lower-caller-id.example.com")
	lowerHe, err := domain.NewHostEvent(domain.IPAddressChanged{OldIP: "10.6.0.1", NewIP: "10.6.0.2", ChangedAt: time.Now().UTC()})
	require.NoError(t, err)
	lowerEnv.Event = lowerHe
	lowerEnv.Version = 2

	require.NoError(t, store.AppendEvent(ctx, id, lowerEnv, 1))

	after, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Positive(t, after.Compare(recorded), "a lower caller-supplied EventID must still leave LatestEventID strictly greater than before")
}

// TestInsertEvent_ZeroIDIntoEmptyStoreRemints is the direct regression test
// for review round-4 H1: a caller-supplied zero EventID appended into a
// store that has never held an event must be re-minted, not inserted
// verbatim, because a zero committed event ID would make LatestEventID
// indistinguishable from storage.ZeroChangeID.
//
// This test was verified RED against a guard carrying the round-3 revision's
// "when the log is non-empty" emptiness branch: gating the comparison on
// non-emptiness skips it entirely on an empty store, so the zero ID inserts
// verbatim and LatestEventID afterwards equals the zero ULID — this
// assertion then fails. Verified by temporarily reintroducing that gate
// around the comparison in insertEvent and re-running this test, then
// reverting.
func TestInsertEvent_ZeroIDIntoEmptyStoreRemints(t *testing.T) {
	store := newGuardTestStore(t, filepath.Join(t.TempDir(), "guard.db"))
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	id := ulid.Make()
	env := hostCreatedEnvelopeWithID(t, ulid.ULID{}, id, "10.6.1.1", "zero-empty.example.com")

	require.NoError(t, store.AppendEvent(ctx, id, env, 0))

	after, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.NotEqual(t, ulid.ULID{}, after, "LatestEventID must not be the zero ULID after accepting a zero-ID append")
	require.NotEqual(t, storage.ZeroChangeID, after.String(), "LatestEventID must not collide with the empty-store sentinel")

	events, err := store.LoadEvents(ctx, id)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.NotEqual(t, ulid.ULID{}, events[0].EventID, "the persisted event must carry the re-minted ID, not the zero ID that was proposed")
}

// TestInsertEvent_ZeroIDIntoNonEmptyStoreRemints covers the same zero-ID
// input as TestInsertEvent_ZeroIDIntoEmptyStoreRemints, but against a
// populated store — pinning both halves of "the comparison always runs,
// with no emptiness branch" (review round-4 H1).
func TestInsertEvent_ZeroIDIntoNonEmptyStoreRemints(t *testing.T) {
	store := newGuardTestStore(t, filepath.Join(t.TempDir(), "guard.db"))
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	first := ulid.Make()
	require.NoError(t, store.AppendEvent(ctx, first, hostCreatedEnvelopeWithID(t, eventid.New(), first, "10.6.2.1", "zero-nonempty-seed.example.com"), 0))
	before, err := store.LatestEventID(ctx)
	require.NoError(t, err)

	second := ulid.Make()
	zeroEnv := hostCreatedEnvelopeWithID(t, ulid.ULID{}, second, "10.6.2.2", "zero-nonempty.example.com")
	require.NoError(t, store.AppendEvent(ctx, second, zeroEnv, 0))

	after, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Positive(t, after.Compare(before), "a zero-ID append into a non-empty store must still advance LatestEventID")
	require.NotEqual(t, ulid.ULID{}, after, "LatestEventID must not be the zero ULID after accepting a zero-ID append")

	events, err := store.LoadEvents(ctx, second)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.NotEqual(t, ulid.ULID{}, events[0].EventID, "the persisted event must carry the re-minted ID, not the zero ID that was proposed")
}

// TestAppendEventsBatch_AllLowerIDsStillAdvanceMax covers the bulk append
// path (T-1-54's naming of AppendEventsBatch as both the import and
// RollbackToSnapshot path): a batch of events that ALL carry
// caller-supplied IDs below the pre-existing maximum must still leave
// LatestEventID strictly greater afterward, and every event must land in
// the log (row count grows by the full batch size), proving the guard
// applies per-insert inside the batch's single transaction rather than only
// to the first or last row.
func TestAppendEventsBatch_AllLowerIDsStillAdvanceMax(t *testing.T) {
	store := newGuardTestStore(t, filepath.Join(t.TempDir(), "guard.db"))
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	seed := ulid.Make()
	require.NoError(t, store.AppendEvent(ctx, seed, hostCreatedEnvelopeWithID(t, eventid.New(), seed, "10.6.3.1", "batch-seed.example.com"), 0))
	before, err := store.LatestEventID(ctx)
	require.NoError(t, err)

	aggID := ulid.Make()
	batch := []storage.AggregateEvents{
		{
			AggregateID: aggID,
			Events: []domain.EventEnvelope{
				hostCreatedEnvelopeWithID(t, pastULID(t, 3*time.Hour), aggID, "10.6.3.2", "batch-1.example.com"),
			},
			ExpectedVersion: 0,
		},
	}
	up1, err := domain.NewHostEvent(domain.IPAddressChanged{OldIP: "10.6.3.2", NewIP: "10.6.3.3", ChangedAt: time.Now().UTC()})
	require.NoError(t, err)
	batch[0].Events = append(batch[0].Events, domain.EventEnvelope{
		EventID: pastULID(t, 2*time.Hour), AggregateID: aggID, Event: up1, Version: 2, CreatedAt: time.Now().UTC(),
	})
	up2, err := domain.NewHostEvent(domain.IPAddressChanged{OldIP: "10.6.3.3", NewIP: "10.6.3.4", ChangedAt: time.Now().UTC()})
	require.NoError(t, err)
	batch[0].Events = append(batch[0].Events, domain.EventEnvelope{
		EventID: pastULID(t, 1*time.Hour), AggregateID: aggID, Event: up2, Version: 3, CreatedAt: time.Now().UTC(),
	})

	require.NoError(t, store.AppendEventsBatch(ctx, batch))

	after, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Positive(t, after.Compare(before), "a batch of all-lower caller-supplied IDs must still advance LatestEventID")

	countAfter, err := store.CountEvents(ctx, aggID)
	require.NoError(t, err)
	require.Equal(t, int64(3), countAfter, "all three batch events must land in the log despite every one carrying a lower caller-supplied ID")
}

// TestInsertEvent_ConcurrentReverseCommitOrderAdvancesMax is the direct
// regression test for review round-3 H2 / T-1-51: event IDs are minted
// outside the write-queue lock in production (CommandHandler.newID() runs
// before submitWrite), so mint order need not equal commit order. Two
// sequential AppendEvent calls with deliberately inverted IDs (mint A, mint
// B > A, commit B first, commit A second) reproduce that race
// deterministically without needing goroutine scheduling luck.
//
// This test was verified RED with the in-transaction guard removed from
// insertEvent (temporarily commenting out the re-mint): A's commit, landing
// after B's with a lower ID, left LatestEventID at B's ID instead of
// advancing past it — reverted after observing the failure.
func TestInsertEvent_ConcurrentReverseCommitOrderAdvancesMax(t *testing.T) {
	store := newGuardTestStore(t, filepath.Join(t.TempDir(), "guard.db"))
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()

	idA := eventid.New()
	idB := eventid.New()
	require.Positive(t, idB.Compare(idA), "test setup requires idB to sort strictly greater than idA")

	aggA := ulid.Make()
	aggB := ulid.Make()

	// B commits first, despite A having been minted first.
	require.NoError(t, store.AppendEvent(ctx, aggB, hostCreatedEnvelopeWithID(t, idB, aggB, "10.6.4.2", "reverse-b.example.com"), 0))
	afterB, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Equal(t, idB, afterB, "after B's commit, LatestEventID must equal B's ID")

	// A commits second, carrying an ID that sorts BELOW the log's current
	// maximum (B's ID) — the exact shape of the H2 race.
	require.NoError(t, store.AppendEvent(ctx, aggA, hostCreatedEnvelopeWithID(t, idA, aggA, "10.6.4.1", "reverse-a.example.com"), 0))
	afterA, err := store.LatestEventID(ctx)
	require.NoError(t, err)
	require.Positive(t, afterA.Compare(afterB), "A's commit, though it carries an ID sorting below B's, must still leave LatestEventID strictly greater than it was after B's commit")
}

// TestInitialize_SeedsGeneratorFromPersistedLog is the direct regression
// test for review round-3 H3 (a process restart minting inside the same
// millisecond as the last pre-restart append can sort below it), redesigned
// per review round-4 M2 to be independently discriminating: the
// internal/eventid floor is process-wide, so a prior test in the same
// binary (or a second -count iteration of this very test) could raise it
// before this test runs, leaving a "fresh" generator not fresh; and if the
// test read the ID back from storage, the in-transaction guard would repair
// an unseeded proposal and mask a deleted seeding call. Both are closed
// here: eventid.SwapDefault installs a generator with a provably zero
// floor, and the discriminating assertion runs on eventid.New() directly,
// BEFORE any append, so the append guard is not in the picture at all.
//
// This test was verified RED with sqlite.Storage.Initialize's eventid.Seed
// call removed: the swapped-in zero-floor generator's first New() sorted
// BELOW the persisted hour-ahead maximum, failing the discriminating
// assertion — reverted after observing the failure. It was also verified
// green under -count=3 with the seeding in place; without SwapDefault
// isolating each iteration's floor, the second iteration would pass
// spuriously because the first iteration's seeding would have already
// raised the process floor.
func TestInitialize_SeedsGeneratorFromPersistedLog(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "restart.db")

	// Persist one event whose ID is constructed literally with a
	// FUTURE timestamp, NOT via eventid.New(), so the package-level floor is
	// left completely untouched by this setup.
	first := newGuardTestStore(t, dbPath)
	futureID, err := ulid.New(ulid.Timestamp(time.Now().Add(time.Hour)), nil)
	require.NoError(t, err)
	aggID := ulid.Make()
	require.NoError(t, first.AppendEvent(context.Background(), aggID, hostCreatedEnvelopeWithID(t, futureID, aggID, "10.6.5.1", "restart-seed.example.com"), 0))
	require.NoError(t, first.Close())

	// Install a generator with a provably zero floor. This is the only way
	// to get a known starting floor, since the floor is monotonic by design
	// and therefore cannot be lowered. Not run parallel: SwapDefault mutates
	// process-wide state.
	restore := eventid.SwapDefault(eventid.NewGenerator())
	t.Cleanup(restore)

	// Open a SECOND Storage over the same path and Initialize it.
	second, err := New(dbPath, slog.Default())
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })
	require.NoError(t, second.Initialize(context.Background()))

	// The load-bearing assertion: BEFORE anything else touches the store,
	// the freshly-seeded generator's next mint must already sort above the
	// persisted future-timestamped maximum. Nothing has appended since
	// Initialize, so only the seeding call could have raised the floor —
	// the append guard is not in the picture at all and cannot mask its
	// absence.
	minted := eventid.New()
	require.Positive(t, minted.Compare(futureID), "eventid.New() immediately after Initialize must sort strictly above the persisted maximum")

	// Secondary end-to-end check, clearly commented as such: appending
	// through the store lands above the maximum too. This is NOT the
	// discriminating assertion above — do not mistake it for one.
	newAggID := ulid.Make()
	require.NoError(t, second.AppendEvent(context.Background(), newAggID, hostCreatedEnvelopeWithID(t, eventid.New(), newAggID, "10.6.5.2", "restart-post.example.com"), 0))
	after, err := second.LatestEventID(context.Background())
	require.NoError(t, err)
	require.Positive(t, after.Compare(futureID), "an append through the restarted store must also land above the persisted maximum")
}
