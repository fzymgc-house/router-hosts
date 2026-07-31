// BACKSTOP (T-09-02 finish-instant edge, 09-VALIDATION.md §Determinism
// Contract, 09-04-PLAN.md must_haves): a Trigger arriving at the exact
// instant a batch finishes must either start a new batch or increment the
// coalesced counter — it must never vanish. The conservation law is
// asserted deterministically by TestHookRunner_CoalescesSupersededRuns and
// sampled under the race detector by TestHookRunner_ConcurrentTriggersConserve.
// The precise interleaving at the finish instant itself — Trigger's
// mutex-guarded pending-overwrite racing runPending's mutex-guarded
// pending-take at the exact moment a batch returns — is not reproducible on
// demand. It is covered by argument (the shared mutex totally orders the two
// operations: either the Trigger's request becomes the next pending batch,
// or runPending has already cleared pending and the Trigger starts a fresh
// one; there is no interleaving in which the request is dropped by neither
// path) rather than by a targeted test. This is a known, intentional
// verification limit, not an untested behavior.

package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/fzymgc-house/router-hosts/internal/config"
)

// blockingSentinelHook returns a HookDefinition whose command polls for
// unblockPath to exist before touching markerPath. Used to prove ordering
// (the caller returned before the hook could finish) without any wall-clock
// comparison — the sanctioned technique per 09-VALIDATION.md.
func blockingSentinelHook(name, unblockPath, markerPath string) config.HookDefinition {
	return config.HookDefinition{
		Name:    name,
		Command: fmt.Sprintf(`while [ ! -f %q ]; do sleep 0.05; done; touch %q`, unblockPath, markerPath),
	}
}

// router-hosts HOOK-02: regenerateOutputs must return before a triggered hook
// completes — proven by filesystem-sentinel ordering, never wall-clock timing.
func TestRegenerateOutputs_DetachesFromHooks(t *testing.T) {
	ctx := context.Background()
	store := hookWiringStore(t)
	handler := NewCommandHandler(store)
	seedHosts(t, handler, 2)

	dir := t.TempDir()
	unblock := filepath.Join(dir, "unblock")
	marker := filepath.Join(dir, "marker")

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingSentinelHook("block-until-unblocked", unblock, marker)},
		nil,
		5*time.Second,
		slog.Default(),
	)
	hooks.Start()

	gen := NewHostsFileGenerator(filepath.Join(dir, "hosts"))
	svc := NewHostsServiceImpl(handler, store, WithHostsGenerator(gen), WithHookExecutor(hooks))

	svc.RegenerateOutputs(ctx)

	// The write path returned while the hook is still polling for unblock —
	// its completion marker cannot exist yet.
	assert.NoFileExists(t, marker)

	f, err := os.Create(unblock)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	hooks.Stop(context.Background())
	assert.FileExists(t, marker)
}

// router-hosts HOOK-02: a hook with an explicit Timeout keeps it; a hook
// with the zero value inherits the constructor's defaultTimeout.
func TestHookExecutor_ResolvesPerHookTimeout(t *testing.T) {
	onSuccess := []config.HookDefinition{
		{Name: "custom-timeout", Command: "true", Timeout: 50 * time.Millisecond},
		{Name: "inherits-default", Command: "true"},
	}

	executor := NewHookExecutor(onSuccess, nil, 5*time.Second, slog.Default())

	require.Len(t, executor.onSuccess, 2)
	assert.Equal(t, 50*time.Millisecond, executor.onSuccess[0].Timeout)
	assert.Equal(t, 5*time.Second, executor.onSuccess[1].Timeout)
}

// router-hosts HOOK-01: a successful hook records exactly one execution
// counter datapoint and one duration observation with the expected labels.
func TestHookExecutor_RecordsSuccessMetric(t *testing.T) {
	m, reader := newTestMetrics(t)

	executor := NewHookExecutor(
		[]config.HookDefinition{{Name: "touch-marker", Command: "true"}},
		nil,
		5*time.Second,
		slog.Default(),
		WithMetrics(m),
	)

	executor.RunSuccess(context.Background(), 1)

	rm := collectMetrics(t, reader)

	counter := findMetric(rm, "router_hosts_hook_executions_total")
	require.NotNil(t, counter, "hook_executions_total metric not found")
	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok, "expected Sum[int64] data type")
	require.Len(t, sum.DataPoints, 1)

	attrs := extractAttrs(sum.DataPoints[0])
	assert.Equal(t, "touch-marker", attrs["name"])
	assert.Equal(t, "success", attrs["type"])
	assert.Equal(t, "success", attrs["status"])

	histogram := findMetric(rm, "router_hosts_hook_duration_seconds")
	require.NotNil(t, histogram, "hook_duration_seconds metric not found")
	histData, ok := histogram.Data.(metricdata.Histogram[float64])
	require.True(t, ok, "expected Histogram[float64] data type")
	require.Len(t, histData.DataPoints, 1)
}

// router-hosts HOOK-02 (Pitfall 2 regression): cancelling the context that
// was passed into the write path must not kill an already-detached hook —
// the runner always dispatches against its own server-lifecycle context.
func TestHookRunner_SurvivesRPCContextCancellation(t *testing.T) {
	store := hookWiringStore(t)
	handler := NewCommandHandler(store)
	seedHosts(t, handler, 1)

	dir := t.TempDir()
	unblock := filepath.Join(dir, "unblock")
	marker := filepath.Join(dir, "marker")

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingSentinelHook("block-until-unblocked", unblock, marker)},
		nil,
		5*time.Second,
		slog.Default(),
	)
	hooks.Start()

	gen := NewHostsFileGenerator(filepath.Join(dir, "hosts"))
	svc := NewHostsServiceImpl(handler, store, WithHostsGenerator(gen), WithHookExecutor(hooks))

	rpcCtx, cancel := context.WithCancel(context.Background())
	svc.RegenerateOutputs(rpcCtx)
	cancel() // simulate a disconnected/timed-out RPC client

	// Hook is still blocked polling for unblock; cancelling rpcCtx above must
	// not have reached it.
	assert.NoFileExists(t, marker)

	f, err := os.Create(unblock)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	hooks.Stop(context.Background())
	assert.FileExists(t, marker)
}

// router-hosts HOOK-01: a service with no hook executor at all must emit
// zero hook datapoints on regeneration — a no-op, not a zero-valued point.
func TestRegenerateOutputs_NoHooksEmitsNoMetrics(t *testing.T) {
	ctx := context.Background()
	store := hookWiringStore(t)
	handler := NewCommandHandler(store)
	seedHosts(t, handler, 2)

	dir := t.TempDir()
	gen := NewHostsFileGenerator(filepath.Join(dir, "hosts"))

	_, reader := newTestMetrics(t)
	// Constructed WITHOUT WithHookExecutor: s.hooks stays nil.
	svc := NewHostsServiceImpl(handler, store, WithHostsGenerator(gen))

	svc.RegenerateOutputs(ctx)

	rm := collectMetrics(t, reader)
	assert.Nil(t, findMetric(rm, "router_hosts_hook_executions_total"))
}

// waitForFile polls until path exists, failing the test if it never appears
// within a generous bound. This is a synchronization primitive for crossing
// the Go/subprocess boundary — never used to assert timing.
func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to appear", path)
}

// blockingRunsLogHook returns a HookDefinition whose command appends
// $ROUTER_HOSTS_ENTRY_COUNT as one line to runsLogPath, touches startedPath
// on every invocation, then blocks polling for unblockPath to exist before
// returning — the coalescing/ordering-test analogue of blockingSentinelHook,
// additionally recording which payloads actually ran and in what order.
func blockingRunsLogHook(name, runsLogPath, startedPath, unblockPath string) config.HookDefinition {
	return config.HookDefinition{
		Name: name,
		Command: fmt.Sprintf(
			`echo "$ROUTER_HOSTS_ENTRY_COUNT" >> %q; touch %q; while [ ! -f %q ]; do sleep 0.05; done`,
			runsLogPath, startedPath, unblockPath,
		),
	}
}

// router-hosts HOOK-02 (T-09-02): a Trigger arriving while a request is
// already pending overwrites it (latest-wins) rather than queuing, and every
// overwrite is counted on router_hosts_hook_runs_coalesced_total exactly
// once. Conservation holds: executed batches + coalesced == triggers issued.
// Samples the finish-instant BACKSTOP recorded at the top of this file.
func TestHookRunner_CoalescesSupersededRuns(t *testing.T) {
	dir := t.TempDir()
	runsLog := filepath.Join(dir, "runs.log")
	started := filepath.Join(dir, "started")
	unblock := filepath.Join(dir, "unblock")

	m, reader := newTestMetrics(t)

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingRunsLogHook("record", runsLog, started, unblock)},
		nil,
		5*time.Second,
		slog.Default(),
		WithMetrics(m),
	)
	hooks.Start()

	hooks.TriggerSuccess(1) // A — starts immediately, pending was nil
	waitForFile(t, started)

	hooks.TriggerSuccess(2) // B — pending was nil (A already taken), no coalesce
	hooks.TriggerSuccess(3) // C — pending was B, exactly one coalesce, B dropped

	f, err := os.Create(unblock)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	hooks.Stop(context.Background())

	logBytes, err := os.ReadFile(runsLog)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	require.Equal(t, []string{"1", "3"}, lines, "payload 2 must never execute — latest-wins")

	rm := collectMetrics(t, reader)
	counter := findMetric(rm, "router_hosts_hook_runs_coalesced_total")
	require.NotNil(t, counter, "coalesced counter metric not found")
	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok, "expected Sum[int64] data type")
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1), sum.DataPoints[0].Value)
	assert.Equal(t, "success", extractAttrs(sum.DataPoints[0])["type"])

	// Conservation: 2 executed batches + 1 coalesced == 3 triggers.
	assert.Len(t, lines, 2)
}

// router-hosts HOOK-02 (T-09-02): under 50 concurrent Trigger calls, the
// conservation law holds under the race detector — no trigger is silently
// dropped, only ever coalesced or executed.
func TestHookRunner_ConcurrentTriggersConserve(t *testing.T) {
	dir := t.TempDir()
	runsLog := filepath.Join(dir, "runs.log")
	started := filepath.Join(dir, "started")
	unblock := filepath.Join(dir, "unblock")

	m, reader := newTestMetrics(t)

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingRunsLogHook("record", runsLog, started, unblock)},
		nil,
		5*time.Second,
		slog.Default(),
		WithMetrics(m),
	)
	hooks.Start()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			hooks.TriggerSuccess(n)
		}(i)
	}
	wg.Wait()

	waitForFile(t, started)

	f, err := os.Create(unblock)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	hooks.Stop(context.Background())

	logBytes, err := os.ReadFile(runsLog)
	require.NoError(t, err)
	trimmed := strings.TrimSpace(string(logBytes))
	var executed int64
	if trimmed != "" {
		executed = int64(len(strings.Split(trimmed, "\n")))
	}

	rm := collectMetrics(t, reader)
	var coalesced int64
	if counter := findMetric(rm, "router_hosts_hook_runs_coalesced_total"); counter != nil {
		sum, ok := counter.Data.(metricdata.Sum[int64])
		require.True(t, ok)
		for _, dp := range sum.DataPoints {
			coalesced += dp.Value
		}
	}

	assert.Equal(t, int64(50), executed+coalesced, "no trigger may vanish: executed + coalesced must equal triggers issued")
}

// blockingStartedSentinelHook returns a HookDefinition whose command touches
// startedPath, blocks polling for unblockPath to exist, then touches
// markerPath — the shutdown-test analogue of blockingSentinelHook that also
// signals when it has begun, needed to know a batch is in-flight before
// calling Stop.
func blockingStartedSentinelHook(name, startedPath, unblockPath, markerPath string) config.HookDefinition {
	return config.HookDefinition{
		Name: name,
		Command: fmt.Sprintf(
			`touch %q; while [ ! -f %q ]; do sleep 0.05; done; touch %q`,
			startedPath, unblockPath, markerPath,
		),
	}
}

// router-hosts HOOK-02 (T-09-03): Stop(ctx) with no deadline waits for the
// in-flight batch to finish before returning.
func TestHookRunner_StopDrainsInFlightBatch(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	unblock := filepath.Join(dir, "unblock")
	marker := filepath.Join(dir, "marker")

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingStartedSentinelHook("drain-in-flight", started, unblock, marker)},
		nil,
		5*time.Second,
		slog.Default(),
	)
	hooks.Start()

	hooks.TriggerSuccess(1)
	waitForFile(t, started)

	f, err := os.Create(unblock)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	hooks.Stop(context.Background())

	assert.FileExists(t, marker, "Stop must wait for the in-flight batch's completion")
}

// router-hosts HOOK-02 (T-09-03): Stop(ctx) drains the single still-pending
// request before exiting, mirroring WriteQueue.process's drain-buffer step.
func TestHookRunner_StopDrainsPendingRequest(t *testing.T) {
	dir := t.TempDir()
	runsLog := filepath.Join(dir, "runs.log")
	started := filepath.Join(dir, "started")
	unblock := filepath.Join(dir, "unblock")

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingRunsLogHook("drain-pending", runsLog, started, unblock)},
		nil,
		5*time.Second,
		slog.Default(),
	)
	hooks.Start()

	hooks.TriggerSuccess(1) // A — starts immediately
	waitForFile(t, started)

	hooks.TriggerSuccess(2) // B — pending, never started before Stop

	f, err := os.Create(unblock)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	hooks.Stop(context.Background())

	logBytes, err := os.ReadFile(runsLog)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	assert.Equal(t, []string{"1", "2"}, lines, "the single pending request must be drained before Stop returns")
}

// router-hosts HOOK-02 (T-09-03): Stop's deadline expiring while a hook is
// still running must still return, having cancelled the runner's base
// context and thereby killed the hook subprocess. Never asserts wall-clock
// duration — a safety timeout only guards against the test hanging forever
// if Stop fails to terminate, which is itself the failure signal.
func TestHookRunner_StopDrainsThenCancels(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	unblock := filepath.Join(dir, "unblock") // deliberately never created
	marker := filepath.Join(dir, "marker")

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingStartedSentinelHook("never-unblocked", started, unblock, marker)},
		nil,
		30*time.Second, // the hook's own timeout must not be what ends this run
		slog.Default(),
	)
	hooks.Start()

	hooks.TriggerSuccess(1)
	waitForFile(t, started)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	stopReturned := make(chan struct{})
	go func() {
		hooks.Stop(ctx)
		close(stopReturned)
	}()

	select {
	case <-stopReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after its deadline expired — base context was not cancelled")
	}

	assert.NoFileExists(t, marker, "the hook subprocess must have been killed by the cancelled base context, never completing")
}

// router-hosts HOOK-02 (T-09-12): a Trigger after Stop is a no-op — it must
// not panic, must not execute a hook, and must not record a coalesce.
func TestHookRunner_TriggerAfterStopIsNoOp(t *testing.T) {
	dir := t.TempDir()
	runsLog := filepath.Join(dir, "runs.log")
	started := filepath.Join(dir, "started")
	unblock := filepath.Join(dir, "unblock")

	m, reader := newTestMetrics(t)

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingRunsLogHook("idle", runsLog, started, unblock)},
		nil,
		5*time.Second,
		slog.Default(),
		WithMetrics(m),
	)
	hooks.Start()
	hooks.Stop(context.Background()) // idle runner, nothing ever triggered

	require.NotPanics(t, func() {
		hooks.TriggerSuccess(1)
	})

	_, err := os.Stat(runsLog)
	assert.True(t, os.IsNotExist(err), "no hook may execute after Stop")

	rm := collectMetrics(t, reader)
	assert.Nil(t, findMetric(rm, "router_hosts_hook_runs_coalesced_total"), "no coalesce may be recorded after Stop")
}

// router-hosts HOOK-02 (T-09-12): calling Stop twice must not panic or block.
func TestHookRunner_StopIsIdempotent(t *testing.T) {
	hooks := NewHookExecutor(nil, nil, 5*time.Second, slog.Default())
	hooks.Start()

	require.NotPanics(t, func() {
		hooks.Stop(context.Background())
		hooks.Stop(context.Background())
	})
}

// WR-01 regression: Stop on a runner whose Start was never called must
// return promptly and honor ctx's deadline, not block forever on <-r.done
// (there is no loop() goroutine to ever close it). Uses a short deadline as
// a liveness bound proving Stop returns, not as a timing-equality
// assertion — the outer watchdog is the actual failure signal.
func TestHookRunner_StopBeforeStartReturnsPromptly(t *testing.T) {
	hooks := NewHookExecutor(nil, nil, 5*time.Second, slog.Default())
	// Start deliberately never called.

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	stopReturned := make(chan struct{})
	go func() {
		hooks.Stop(ctx)
		close(stopReturned)
	}()

	select {
	case <-stopReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop before Start did not return — it ignored ctx's deadline and blocked forever")
	}
}

// WR-02 regression: calling Start twice must not launch a second loop()
// goroutine that races the first to close r.done — the second Start call is
// a no-op, and the subsequent Stop must not panic.
func TestHookRunner_StartIsIdempotent(t *testing.T) {
	hooks := NewHookExecutor(nil, nil, 5*time.Second, slog.Default())

	require.NotPanics(t, func() {
		hooks.Start()
		hooks.Start() // second call — must be a no-op, not a second loop() goroutine
		hooks.Stop(context.Background())
	})
}

// router-hosts HOOK-02: three hooks in one batch execute and record output
// in declaration order — through the runner's detached background loop, not
// just via a direct RunSuccess call.
func TestHookRunner_BatchOrderIsDeclarationOrder(t *testing.T) {
	dir := t.TempDir()
	orderLog := filepath.Join(dir, "order.log")

	appendNameHook := func(name string) config.HookDefinition {
		return config.HookDefinition{
			Name:    name,
			Command: fmt.Sprintf(`echo %q >> %q`, name, orderLog),
		}
	}

	hooks := NewHookExecutor(
		[]config.HookDefinition{
			appendNameHook("first"),
			appendNameHook("second"),
			appendNameHook("third"),
		},
		nil,
		5*time.Second,
		slog.Default(),
	)
	hooks.Start()

	hooks.TriggerSuccess(1)
	hooks.Stop(context.Background())

	logBytes, err := os.ReadFile(orderLog)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")
	assert.Equal(t, []string{"first", "second", "third"}, lines,
		"detachment to a background goroutine must not reorder in-batch hook execution")
}

// router-hosts HOOK-02 (T-09-02): the across-batch ordering contract stated
// as an ordering property rather than a count — a superseded request's
// payload never appears in the runs-log at any position, not merely "never
// after" the superseding request's payload.
func TestHookRunner_SupersededNeverRunsAfterSuperseder(t *testing.T) {
	dir := t.TempDir()
	runsLog := filepath.Join(dir, "runs.log")
	started := filepath.Join(dir, "started")
	unblock := filepath.Join(dir, "unblock")

	hooks := NewHookExecutor(
		[]config.HookDefinition{blockingRunsLogHook("ordering", runsLog, started, unblock)},
		nil,
		5*time.Second,
		slog.Default(),
	)
	hooks.Start()

	hooks.TriggerSuccess(1) // A — starts immediately, in flight
	waitForFile(t, started)

	hooks.TriggerSuccess(2) // B — pending, not yet superseded
	hooks.TriggerSuccess(3) // C — supersedes B; B must never execute at any position

	f, err := os.Create(unblock)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	hooks.Stop(context.Background())

	logBytes, err := os.ReadFile(runsLog)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(logBytes)), "\n")

	assert.NotContains(t, lines, "2", "a superseded request's payload must never appear in the runs-log at any position")
	require.Len(t, lines, 2)
	assert.Equal(t, "1", lines[0], "the batch already in flight when the supersede happened must run first")
	assert.Equal(t, "3", lines[1], "the superseding request must run — and never before the in-flight batch it did not supersede")
}
