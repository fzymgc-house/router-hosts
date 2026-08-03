package sqlite

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// hostCreatedEnv is the ListPage tests' equivalent of storagetest's
// hostCreatedEnvelope helper — this file lives in package sqlite (white-box)
// rather than storagetest, so it cannot import that helper directly.
func hostCreatedEnv(aggID ulid.ULID, ip, hostname string, t time.Time) domain.EventEnvelope {
	return makeEnvelope(aggID, domain.HostCreated{
		IPAddress: ip,
		Hostname:  hostname,
		Aliases:   []string{},
		Tags:      []string{},
		CreatedAt: t,
	}, 1, t)
}

// TestListPage_RejectsNonPositiveLimit pins the boundary-validation half of
// RESEARCH.md Security Domain V5: a zero or negative limit must error rather
// than loop forever or make zero progress.
func TestListPage_RejectsNonPositiveLimit(t *testing.T) {
	ctx := context.Background()
	store, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	for _, limit := range []int{0, -1} {
		t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
			entries, next, done, pageErr := store.ListPage(ctx, ulid.ULID{}, limit)
			require.Error(t, pageErr)
			require.Empty(t, entries)
			require.False(t, done)
			require.Equal(t, ulid.ULID{}, next)
		})
	}
}

// TestListPage_CancelledContext asserts a cancelled context returns a
// non-nil error and no partially populated page, rather than hanging or
// silently returning whatever had been scanned so far.
func TestListPage_CancelledContext(t *testing.T) {
	ctx := context.Background()
	store, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	entries, _, _, pageErr := store.ListPage(cancelCtx, ulid.ULID{}, 10)
	require.Error(t, pageErr)
	require.Empty(t, entries)
}

// TestListPage_ExactBoundaryCursorExcludesMatch pins the keyset boundary: a
// cursor exactly equal to an existing aggregate's ID excludes that aggregate
// and starts at the next one — no duplicate, no skip.
func TestListPage_ExactBoundaryCursorExcludesMatch(t *testing.T) {
	ctx := context.Background()
	store, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC().Truncate(time.Millisecond)
	ids := make([]ulid.ULID, 3)
	for i := range ids {
		ids[i] = ulid.Make()
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Compare(ids[j]) < 0 })

	for i, id := range ids {
		hostname := fmt.Sprintf("boundary%d.local", i)
		require.NoError(t, store.AppendEvent(ctx, id, hostCreatedEnv(id, "10.9.0.1", hostname, now), 0))
	}

	page, next, done, pageErr := store.ListPage(ctx, ids[1], 10)
	require.NoError(t, pageErr)
	require.True(t, done)
	require.Len(t, page, 1)
	require.Equal(t, ids[2], page[0].ID)
	require.Equal(t, ids[2], next)
}

// TestListPage_FillToNWithDeletedAggregates pins D-08: a page fills to N
// LIVE entries, skipping deleted aggregates internally, and a short page
// means done only at the aggregate-ID space's true exhaustion — not at the
// first empty-looking batch.
func TestListPage_FillToNWithDeletedAggregates(t *testing.T) {
	ctx := context.Background()
	store, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC().Truncate(time.Millisecond)

	const deletedCount = 5
	const liveCount = 4
	ids := make([]ulid.ULID, 0, deletedCount+liveCount)
	for range deletedCount + liveCount {
		ids = append(ids, ulid.Make())
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Compare(ids[j]) < 0 })

	for i, id := range ids {
		hostname := fmt.Sprintf("fill%02d.local", i)
		env := hostCreatedEnv(id, "10.9.1.1", hostname, now)
		require.NoError(t, store.AppendEvent(ctx, id, env, 0))
		if i < deletedCount {
			del := makeEnvelope(id, domain.HostDeleted{
				IPAddress: "10.9.1.1",
				Hostname:  hostname,
				DeletedAt: now.Add(time.Second),
			}, 2, now.Add(time.Second))
			require.NoError(t, store.AppendEvent(ctx, id, del, 1))
		}
	}

	// Requesting 3 live entries must skip all 5 deleted aggregates
	// internally and return a FULL page of 3, not a short page — even
	// though 8 of the 9 seeded aggregates had to be scanned to find them.
	page, next, done, pageErr := store.ListPage(ctx, ulid.ULID{}, 3)
	require.NoError(t, pageErr)
	require.False(t, done, "one live aggregate remains beyond this page, so it must not be done")
	require.Len(t, page, 3)

	// Draining the remainder must yield exactly the one remaining live
	// entry, and THIS page — the one that actually exhausts the
	// aggregate-ID space — is where done becomes true.
	page2, _, done2, pageErr := store.ListPage(ctx, next, 3)
	require.NoError(t, pageErr)
	require.True(t, done2)
	require.Len(t, page2, 1)
}

// TestListPage_DrainEquivalentToListAll pins D-07: draining ListPage from
// the zero cursor produces exactly the slice ListAll returns, element for
// element, regardless of the page size used to drain it.
func TestListPage_DrainEquivalentToListAll(t *testing.T) {
	ctx := context.Background()
	store, err := New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now().UTC().Truncate(time.Millisecond)
	const n = 12
	for i := range n {
		id := ulid.Make()
		hostname := fmt.Sprintf("drain%02d.local", i)
		require.NoError(t, store.AppendEvent(ctx, id, hostCreatedEnv(id, "10.9.2.1", hostname, now), 0))
	}

	all, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, all, n)

	var drained []domain.HostEntry
	var cursor ulid.ULID
	for {
		page, next, done, pageErr := store.ListPage(ctx, cursor, 5)
		require.NoError(t, pageErr)
		drained = append(drained, page...)
		if done {
			break
		}
		cursor = next
	}

	require.Equal(t, all, drained, "draining ListPage must equal ListAll element-for-element")
}
