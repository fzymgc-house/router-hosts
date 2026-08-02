package server

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// waitBound is the bound every test in this file uses for a wake it expects
// to observe. It must be long enough to never flake under CI load, and short
// enough that a genuine regression fails the suite instead of hanging it.
const waitBound = 2 * time.Second

// settleBound is the bound used to observe the ABSENCE of a wake: long
// enough that a wake which was going to happen already would have, short
// enough to keep the suite fast.
const settleBound = 100 * time.Millisecond

func TestChangeNotifier_ReleasesSubscriber(t *testing.T) {
	n := newChangeNotifier()
	ch := n.Subscribe()

	n.Notify()

	select {
	case <-ch:
	case <-time.After(waitBound):
		t.Fatal("subscriber was not released by Notify")
	}
}

func TestChangeNotifier_ReleasesAllSubscribers(t *testing.T) {
	n := newChangeNotifier()
	const numSubs = 10

	var wg sync.WaitGroup
	released := make([]bool, numSubs)
	for i := range numSubs {
		ch := n.Subscribe()
		wg.Add(1)
		go func(idx int, ch <-chan struct{}) {
			defer wg.Done()
			select {
			case <-ch:
				released[idx] = true
			case <-time.After(waitBound):
			}
		}(i, ch)
	}

	n.Notify()
	wg.Wait()

	for i, r := range released {
		assert.True(t, r, "subscriber %d was not released by a single Notify", i)
	}
}

func TestChangeNotifier_SubscriptionAfterNotifyStillWaits(t *testing.T) {
	n := newChangeNotifier()

	n.Notify()
	ch := n.Subscribe()

	select {
	case <-ch:
		t.Fatal("a subscription taken after Notify must not already be released")
	case <-time.After(settleBound):
	}
}

func TestChangeNotifier_NotifyWithNoSubscribers(t *testing.T) {
	n := newChangeNotifier()

	done := make(chan struct{})
	go func() {
		n.Notify()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(waitBound):
		t.Fatal("Notify blocked or panicked with zero subscribers")
	}
}

// TestChangeNotifier_CoalescesBurst controls its own timing: the subscriber
// is held busy by the test itself (it simply does not read its channel until
// after the burst), never by the scheduler, which is what makes this the
// deterministic home for the coalescing proof (review M2). The stream-level
// test in watch_test.go asserts convergence instead, not a wake count.
func TestChangeNotifier_CoalescesBurst(t *testing.T) {
	n := newChangeNotifier()

	// Take a subscription and deliberately do not read it yet — this is the
	// "busy subscriber" the burst lands on.
	busy := n.Subscribe()

	for range 5 {
		n.Notify()
	}

	// The busy subscriber must be released — at least one notify in the
	// burst reaches it — but released exactly once: reading it a second time
	// must not also succeed without a further Notify.
	select {
	case <-busy:
	case <-time.After(waitBound):
		t.Fatal("busy subscriber was never released by the burst")
	}

	// Resubscribing after the burst must NOT already be released: the burst
	// produced at most one additional wake, already consumed above, not one
	// per notification.
	next := n.Subscribe()
	select {
	case <-next:
		t.Fatal("resubscription after the burst was already released; burst produced more than one wake")
	case <-time.After(settleBound):
	}

	// A further, single notify still wakes it.
	n.Notify()
	select {
	case <-next:
	case <-time.After(waitBound):
		t.Fatal("subscriber was not released by a notify following the burst")
	}
}

func TestChangeNotifier_ConcurrentUse(t *testing.T) {
	n := newChangeNotifier()
	stop := make(chan struct{})

	var notifyWG sync.WaitGroup
	notifyWG.Add(1)
	go func() {
		defer notifyWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				n.Notify()
			}
		}
	}()

	var subWG sync.WaitGroup
	for range 20 {
		subWG.Add(1)
		go func() {
			defer subWG.Done()
			for range 20 {
				ch := n.Subscribe()
				select {
				case <-ch:
				case <-time.After(waitBound):
					return
				}
			}
		}()
	}

	subWG.Wait()
	close(stop)
	notifyWG.Wait()
}

// TestService_RegenerateOutputs_NotifiesWithoutGenerators lives here rather
// than in service_test.go to avoid churning that file. It constructs a
// service with no generator and no hook executor configured and asserts that
// RegenerateOutputs (the exported startup entry point) still notifies —
// coverage for a deployment configuration where the pre-review code path
// would have returned before reaching any notify site.
func TestService_RegenerateOutputs_NotifiesWithoutGenerators(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	svc := NewHostsServiceImpl(handler, store)

	ch := svc.changes.Subscribe()
	svc.RegenerateOutputs(ctx)

	select {
	case <-ch:
	case <-time.After(waitBound):
		t.Fatal("RegenerateOutputs did not notify watchers with no generator or hook configured")
	}
}

// newCompactNotifyTestService builds a bare service (no generators, no
// gRPC/bufconn plumbing) directly over a fresh in-memory store, since
// CompactAggregates is a unary method callable without a stream.
func newCompactNotifyTestService(t *testing.T) (*HostsServiceImpl, context.Context) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })

	handler := NewCommandHandler(store)
	svc := NewHostsServiceImpl(handler, store)
	return svc, ctx
}

// TestService_CompactAggregates_Notifies pins review round-3 H1: compaction
// never calls regenerateOutputs, so without its own notify call the change
// ID would move with no watcher told. Before this test was accepted, the
// compaction notify call was temporarily removed and this test was observed
// FAIL (see SUMMARY.md for the recorded failure) — a notification test never
// observed failing is indistinguishable from one that cannot fail.
func TestService_CompactAggregates_Notifies(t *testing.T) {
	svc, ctx := newCompactNotifyTestService(t)
	id := seedBloated(t, ctx, svc.store, 10)

	ch := svc.changes.Subscribe()

	_, err := svc.CompactAggregates(ctx, &hostsv1.CompactAggregatesRequest{
		Target: &hostsv1.CompactAggregatesRequest_AggregateId{AggregateId: id.String()},
	})
	require.NoError(t, err)

	select {
	case <-ch:
	case <-time.After(waitBound):
		t.Fatal("a successful non-dry-run compaction did not notify watchers")
	}
}

func TestService_CompactAggregates_DryRunDoesNotNotify(t *testing.T) {
	svc, ctx := newCompactNotifyTestService(t)
	id := seedBloated(t, ctx, svc.store, 10)

	ch := svc.changes.Subscribe()

	_, err := svc.CompactAggregates(ctx, &hostsv1.CompactAggregatesRequest{
		Target: &hostsv1.CompactAggregatesRequest_AggregateId{AggregateId: id.String()},
		DryRun: true,
	})
	require.NoError(t, err)

	select {
	case <-ch:
		t.Fatal("a dry-run compaction must not notify watchers; it mutates nothing")
	case <-time.After(settleBound):
	}
}

func TestService_CompactAggregates_NoOpDoesNotNotify(t *testing.T) {
	svc, ctx := newCompactNotifyTestService(t)
	// A single-event aggregate: compaction is a no-op (EventsBefore == EventsAfter).
	id := seedBloated(t, ctx, svc.store, 1)

	ch := svc.changes.Subscribe()

	_, err := svc.CompactAggregates(ctx, &hostsv1.CompactAggregatesRequest{
		Target: &hostsv1.CompactAggregatesRequest_AggregateId{AggregateId: id.String()},
	})
	require.NoError(t, err)

	select {
	case <-ch:
		t.Fatal("a no-op compaction (<=1 event) must not notify watchers")
	case <-time.After(settleBound):
	}
}
