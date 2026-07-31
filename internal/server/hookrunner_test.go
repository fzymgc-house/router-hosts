package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
