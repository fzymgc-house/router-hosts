package commands

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/storage/sqlite"
)

// wiringTestStore returns an isolated in-memory store scoped by t.Name() so
// parallel tests don't share a cache.
func wiringTestStore(t *testing.T) *sqlite.Storage {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.New("file:"+t.Name()+"?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func oneHookConfig() config.HooksConfig {
	return config.HooksConfig{
		OnSuccess: []config.HookDefinition{
			{Name: "noop", Command: "true"},
		},
		DefaultTimeout: 5 * time.Second,
	}
}

// router-hosts HOOK-01 regression (WR-03): configureMetricsAndHooks must
// construct metrics BEFORE the hook executor, so WithMetrics receives the
// real recorder. If a future edit reorders the two blocks inside
// configureMetricsAndHooks back to the pre-fix order (hook executor first),
// hookExec.MetricsEnabled() flips to false here and this test fails —
// exactly the silent regression the review flagged as uncaught.
func TestConfigureMetricsAndHooks_HookExecutorGetsRealMetrics(t *testing.T) {
	store := wiringTestStore(t)
	logger := slog.Default()

	cfg := &config.Config{
		Hooks: oneHookConfig(),
		Metrics: &config.MetricsConfig{
			OTel: &config.OTelConfig{
				Endpoint: "localhost:4317",
				Insecure: true,
			},
		},
	}

	wired, err := configureMetricsAndHooks(cfg, store, logger)
	require.NoError(t, err)
	require.NotNil(t, wired.cleanup)
	defer wired.cleanup()

	require.NotNil(t, wired.metrics, "OTel is configured — metrics must be constructed")
	require.NotNil(t, wired.hookExec, "hooks are configured — executor must be constructed")
	assert.True(t, wired.hookExec.MetricsEnabled(),
		"hook executor must be wired to the real metrics recorder, not DisabledMetrics()")
}

// router-hosts HOOK-01: with OTel unconfigured, the hook executor must still
// be constructed (hooks work standalone) but keeps the default
// DisabledMetrics() — WithMetrics(nil) is documented as a no-op.
func TestConfigureMetricsAndHooks_NoOTelLeavesHookExecutorMetricsDisabled(t *testing.T) {
	store := wiringTestStore(t)
	logger := slog.Default()

	cfg := &config.Config{
		Hooks: oneHookConfig(),
		// Metrics left nil — OTel unconfigured.
	}

	wired, err := configureMetricsAndHooks(cfg, store, logger)
	require.NoError(t, err)
	require.NotNil(t, wired.cleanup)
	defer wired.cleanup()

	assert.Nil(t, wired.metrics, "no OTel config — metrics must not be constructed")
	require.NotNil(t, wired.hookExec, "hooks are configured — executor must be constructed")
	assert.False(t, wired.hookExec.MetricsEnabled(),
		"hook executor must fall back to DisabledMetrics() when OTel is unconfigured")
}

// No hooks configured — the executor must stay nil regardless of metrics
// configuration, matching runServe's pre-extraction behavior.
func TestConfigureMetricsAndHooks_NoHooksConfigured(t *testing.T) {
	store := wiringTestStore(t)
	logger := slog.Default()

	cfg := &config.Config{}

	wired, err := configureMetricsAndHooks(cfg, store, logger)
	require.NoError(t, err)
	require.NotNil(t, wired.cleanup)
	defer wired.cleanup()

	assert.Nil(t, wired.hookExec)
}

// A server configured with OTel metrics gets a sink health registry and its
// sink gauges registered (registration failure would surface as a non-nil
// err here, per RegisterSinkGauges's error-wrapping shape).
func TestConfigureMetricsAndHooks_SinkHealthWithMetrics(t *testing.T) {
	store := wiringTestStore(t)
	logger := slog.Default()

	cfg := &config.Config{
		Metrics: &config.MetricsConfig{
			OTel: &config.OTelConfig{
				Endpoint: "localhost:4317",
				Insecure: true,
			},
		},
	}

	wired, err := configureMetricsAndHooks(cfg, store, logger)
	require.NoError(t, err)
	require.NotNil(t, wired.cleanup)
	defer wired.cleanup()

	require.NotNil(t, wired.metrics, "OTel is configured — metrics must be constructed")
	require.NotNil(t, wired.sinkHealth, "sink health registry must always be constructed")
}

// A server configured WITHOUT OTel metrics still gets a sink health
// registry, so status reporting works even though gauge export is absent.
func TestConfigureMetricsAndHooks_SinkHealthWithoutMetrics(t *testing.T) {
	store := wiringTestStore(t)
	logger := slog.Default()

	cfg := &config.Config{
		// Metrics left nil — OTel unconfigured.
	}

	wired, err := configureMetricsAndHooks(cfg, store, logger)
	require.NoError(t, err)
	require.NotNil(t, wired.cleanup)
	defer wired.cleanup()

	assert.Nil(t, wired.metrics, "no OTel config — metrics must not be constructed")
	require.NotNil(t, wired.sinkHealth, "sink health registry must be constructed even without OTel")
}

// WithSinkHealth must be appended to svcOpts unconditionally — even with no
// hooks and no metrics configured, the service still gets the option so a
// deployment without OTel still benefits from status recording.
func TestConfigureMetricsAndHooks_SinkOptionAlwaysPresent(t *testing.T) {
	store := wiringTestStore(t)
	logger := slog.Default()

	cfg := &config.Config{} // no hooks, no metrics

	wired, err := configureMetricsAndHooks(cfg, store, logger)
	require.NoError(t, err)
	require.NotNil(t, wired.cleanup)
	defer wired.cleanup()

	require.NotNil(t, wired.sinkHealth)
	assert.Len(t, wired.svcOpts, 1,
		"WithSinkHealth must be appended to svcOpts even with no hooks and no metrics configured")
}
