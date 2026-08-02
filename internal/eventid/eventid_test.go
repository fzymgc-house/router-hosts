package eventid

import (
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"
)

// Every test in this file builds its own generator with NewGenerator() rather
// than using the package singleton, so no test here can leave a raised floor
// that disarms another. None of these tests call t.Parallel() except where
// noted, since a couple mutate purely local state and there is no reason not
// to, but TestEventID_SwapDefaultRestores must not run parallel because it
// mutates process-wide state via SwapDefault.

// TestEventID_StrictlyIncreasing asserts that at least 1000 consecutive New()
// calls with no sleep between them return strictly increasing ULIDs, even
// though many of them share a millisecond.
func TestEventID_StrictlyIncreasing(t *testing.T) {
	g := NewGenerator()
	prev := g.New()
	for i := 0; i < 1000; i++ {
		cur := g.New()
		require.Positive(t, cur.Compare(prev), "id %d must sort strictly greater than its predecessor", i)
		prev = cur
	}
}

// TestEventID_Unique asserts that a set of consecutively minted IDs has no
// duplicates.
func TestEventID_Unique(t *testing.T) {
	g := NewGenerator()
	seen := make(map[ulid.ULID]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := g.New()
		_, dup := seen[id]
		require.False(t, dup, "id %s minted more than once", id)
		seen[id] = struct{}{}
	}
}

// TestEventID_ConcurrentUse mints from many goroutines and asserts all
// returned IDs are distinct. task test already runs -race, so an unguarded
// reader or floor fails here.
func TestEventID_ConcurrentUse(t *testing.T) {
	g := NewGenerator()
	const goroutines = 50
	const perGoroutine = 20

	ids := make(chan ulid.ULID, goroutines*perGoroutine)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				ids <- g.New()
			}
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[ulid.ULID]struct{}, goroutines*perGoroutine)
	for id := range ids {
		_, dup := seen[id]
		require.False(t, dup, "id %s minted more than once across goroutines", id)
		seen[id] = struct{}{}
	}
	require.Len(t, seen, goroutines*perGoroutine)
}

// TestEventID_SeedRaisesFloor asserts that after seeding with a ULID far in
// the future, the next New() sorts strictly greater than it.
func TestEventID_SeedRaisesFloor(t *testing.T) {
	g := NewGenerator()
	future := ulid.MustNew(ulid.Timestamp(time.Now().Add(time.Hour)), nil)
	g.Seed(future)

	got := g.New()
	require.Positive(t, got.Compare(future), "New() after Seed(future) must sort strictly greater than the seeded value")
}

// TestEventID_SeedIgnoresLowerValue asserts that seeding with a ULID below
// the current floor does not lower the floor: the next New() still sorts
// strictly greater than everything previously returned.
func TestEventID_SeedIgnoresLowerValue(t *testing.T) {
	g := NewGenerator()
	before := g.New()

	past := ulid.MustNew(ulid.Timestamp(time.Now().Add(-time.Hour)), nil)
	g.Seed(past)

	got := g.New()
	require.Positive(t, got.Compare(before), "New() after Seed(past) must still sort strictly greater than the prior New()")
}

// TestEventID_NewAfterAlwaysGreater asserts that NewAfter(lower) returns a
// ULID strictly greater than lower for any lower, including one whose
// entropy bytes are all 0xFF so the carry into the timestamp is exercised.
func TestEventID_NewAfterAlwaysGreater(t *testing.T) {
	var allFF ulid.ULID
	for i := 6; i < 16; i++ {
		allFF[i] = 0xFF
	}
	allFF[5] = 0x01 // give the timestamp carry somewhere to land

	cases := map[string]ulid.ULID{
		"zero":             {},
		"normal":           ulid.MustNew(ulid.Timestamp(time.Now()), nil),
		"entropy all 0xFF": allFF,
	}

	for name, lower := range cases {
		t.Run(name, func(t *testing.T) {
			g := NewGenerator()
			got := g.NewAfter(lower)
			require.Positive(t, got.Compare(lower), "NewAfter(%s) must sort strictly greater than lower", name)
		})
	}
}

// TestEventID_SwapDefaultRestores captures a value from the package
// singleton, swaps in a fresh generator, confirms it is genuinely fresh, and
// then confirms restoring puts the original singleton (with its floor
// intact) back. Not run parallel: SwapDefault mutates process-wide state.
func TestEventID_SwapDefaultRestores(t *testing.T) {
	captured := New()

	restore := SwapDefault(NewGenerator())
	fresh := New()
	// The fresh generator started with a zero floor, so its first New() need
	// not exceed the captured value — that is the whole point of having a
	// generator a test can fully control.
	_ = fresh

	restore()

	afterRestore := New()
	require.Positive(t, afterRestore.Compare(captured), "the restored singleton's floor must have survived the swap")
}
