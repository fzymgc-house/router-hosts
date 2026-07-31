package commands

import (
	"context"
	"log/slog"
	"time"

	"github.com/samber/oops"
	"google.golang.org/grpc"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/server"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// hooksAndMetrics bundles what runServe needs from the metrics + hook
// executor wiring step: the constructed metrics recorder (nil if OTel is
// unconfigured), the optional hook executor, the server/service options
// each contributes, and a cleanup func the caller must defer.
type hooksAndMetrics struct {
	metrics    *server.Metrics
	hookExec   *server.HookExecutor
	serverOpts []server.Option
	svcOpts    []server.ServiceOption
	cleanup    func()
}

// configureMetricsAndHooks wires OTel metrics (if cfg.Metrics.OTel is set)
// and the hook executor (if any hooks are configured), IN THAT ORDER. This
// order is the HOOK-01 fix: the hook executor must be constructed AFTER
// metrics exists, or WithMetrics silently receives a nil *server.Metrics (a
// no-op) and hook execution metrics stay dead forever. Extracted out of
// runServe specifically so this ordering is unit-testable in isolation —
// reordering the two blocks below regresses HOOK-01 with no compiler
// warning; see TestConfigureMetricsAndHooks_HookExecutorGetsRealMetrics in
// serve_wiring_test.go, which fails if that happens.
func configureMetricsAndHooks(cfg *config.Config, store storage.EventStore, logger *slog.Logger) (hooksAndMetrics, error) {
	var result hooksAndMetrics
	var cleanups []func()

	if cfg.Metrics != nil && cfg.Metrics.OTel != nil {
		metrics, err := server.NewMetricsFromConfig(cfg.Metrics.OTel)
		if err != nil {
			return hooksAndMetrics{}, oops.Wrapf(err, "setup metrics")
		}
		result.metrics = metrics
		cleanups = append(cleanups, func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if serr := metrics.Shutdown(shutCtx); serr != nil {
				logger.Error("metrics shutdown failed", "error", serr)
			}
		})

		result.serverOpts = append(result.serverOpts, server.WithGRPCOptions(
			grpc.ChainUnaryInterceptor(server.UnaryMetricsInterceptor(metrics)),
			grpc.ChainStreamInterceptor(server.StreamMetricsInterceptor(metrics)),
		))

		if rerr := metrics.RegisterAggregateEventGauges(store, server.DefaultAggregateEventsWarnThreshold); rerr != nil {
			return hooksAndMetrics{}, oops.Wrapf(rerr, "register aggregate-event gauges")
		}
	}

	// Hook executor (optional) — constructed AFTER the metrics block above,
	// not before, so WithMetrics receives the real *server.Metrics (or nil,
	// tolerated as a no-op, when OTel is unconfigured).
	if len(cfg.Hooks.OnSuccess) > 0 || len(cfg.Hooks.OnFailure) > 0 {
		hookExec := server.NewHookExecutor(
			cfg.Hooks.OnSuccess,
			cfg.Hooks.OnFailure,
			cfg.Hooks.DefaultTimeout,
			logger,
			server.WithMetrics(result.metrics),
		)
		hookExec.Start()
		result.hookExec = hookExec
		result.svcOpts = append(result.svcOpts, server.WithHookExecutor(hookExec))
	}
	cleanups = append(cleanups, func() {
		if result.hookExec == nil {
			return
		}
		shutCtx, cancel := context.WithTimeout(context.Background(), server.GracefulShutdownTimeout)
		defer cancel()
		result.hookExec.Stop(shutCtx)
	})

	result.cleanup = func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	return result, nil
}
