package server

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/samber/oops"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/domain"
)

// Hook execution outcome status values recorded on
// router_hosts_hook_executions_total. timeout is a first-class outcome,
// distinct from failure, so a deadline kill is never misreported as a
// self-inflicted non-zero exit.
const (
	hookStatusSuccess = "success"
	hookStatusFailure = "failure"
	hookStatusTimeout = "timeout"
)

// HookExecutor runs post-edit shell hooks sequentially, either synchronously
// (RunSuccess/RunFailure) or detached on a background runner
// (TriggerSuccess/TriggerFailure).
type HookExecutor struct {
	onSuccess []config.HookDefinition
	onFailure []config.HookDefinition
	log       *slog.Logger
	metrics   *Metrics
	runner    *hookRunner
}

// HookExecutorOption configures optional dependencies on HookExecutor.
type HookExecutorOption func(*HookExecutor)

// WithMetrics sets the metrics recorder used for hook execution telemetry.
// A nil argument is a no-op — the executor keeps its default DisabledMetrics(),
// which serve.go relies on when OTel is unconfigured.
func WithMetrics(m *Metrics) HookExecutorOption {
	return func(h *HookExecutor) {
		if m != nil {
			h.metrics = m
		}
	}
}

// NewHookExecutor creates an executor with the given hook definitions. Any
// hook whose Timeout is unset (zero) inherits defaultTimeout at construction
// time; this is the only place a default is consulted — every hook
// definition held by the executor carries its own already-resolved timeout,
// and no execution-time code path reads a global default.
func NewHookExecutor(onSuccess, onFailure []config.HookDefinition, defaultTimeout time.Duration, logger *slog.Logger, opts ...HookExecutorOption) *HookExecutor {
	resolvedSuccess := make([]config.HookDefinition, len(onSuccess))
	copy(resolvedSuccess, onSuccess)
	for i := range resolvedSuccess {
		if resolvedSuccess[i].Timeout == 0 {
			resolvedSuccess[i].Timeout = defaultTimeout
		}
	}

	resolvedFailure := make([]config.HookDefinition, len(onFailure))
	copy(resolvedFailure, onFailure)
	for i := range resolvedFailure {
		if resolvedFailure[i].Timeout == 0 {
			resolvedFailure[i].Timeout = defaultTimeout
		}
	}

	h := &HookExecutor{
		onSuccess: resolvedSuccess,
		onFailure: resolvedFailure,
		log:       logger,
		metrics:   DisabledMetrics(),
	}
	for _, opt := range opts {
		opt(h)
	}
	h.runner = newHookRunner(h, logger)
	return h
}

// Start launches the background hook runner's processing goroutine.
func (h *HookExecutor) Start() {
	h.runner.Start()
}

// Stop drains the background runner: it waits for any in-flight or pending
// hook batch to complete up to ctx's deadline, then cancels the runner's
// base context (killing a still-running hook subprocess) and waits for the
// goroutine to exit. Safe to call more than once.
func (h *HookExecutor) Stop(ctx context.Context) {
	h.runner.Stop(ctx)
}

// TriggerSuccess enqueues an on-success hook batch on the background runner,
// coalescing with any not-yet-started pending batch. Never blocks; safe to
// call from the RPC goroutine.
func (h *HookExecutor) TriggerSuccess(entryCount int) {
	h.runner.Trigger(hookRunRequest{event: "success", entryCount: entryCount})
}

// TriggerFailure enqueues an on-failure hook batch on the background runner,
// coalescing with any not-yet-started pending batch. Never blocks; safe to
// call from the RPC goroutine.
func (h *HookExecutor) TriggerFailure(entryCount int, errMsg string) {
	h.runner.Trigger(hookRunRequest{event: "failure", entryCount: entryCount, errMsg: errMsg})
}

// RunSuccess executes on-success hooks sequentially. Hook failures are logged
// but not propagated to the caller. This is the synchronous core the
// background runner calls; tests may also call it directly.
func (h *HookExecutor) RunSuccess(ctx context.Context, entryCount int) {
	h.runHooks(ctx, h.onSuccess, "success", entryCount, "")
}

// RunFailure executes on-failure hooks sequentially. Hook failures are logged
// but not propagated to the caller. This is the synchronous core the
// background runner calls; tests may also call it directly.
func (h *HookExecutor) RunFailure(ctx context.Context, entryCount int, errMsg string) {
	h.runHooks(ctx, h.onFailure, "failure", entryCount, errMsg)
}

// HookNames returns the names of all configured hooks (success + failure).
func (h *HookExecutor) HookNames() []string {
	names := make([]string, 0, len(h.onSuccess)+len(h.onFailure))
	for _, hook := range h.onSuccess {
		names = append(names, hook.Name)
	}
	for _, hook := range h.onFailure {
		names = append(names, hook.Name)
	}
	return names
}

// HookCount returns the total number of configured hooks.
func (h *HookExecutor) HookCount() int {
	return len(h.onSuccess) + len(h.onFailure)
}

// runHooks executes hooks sequentially, logging failures without propagating.
func (h *HookExecutor) runHooks(ctx context.Context, hooks []config.HookDefinition, event string, entryCount int, errMsg string) {
	for _, hook := range hooks {
		if err := h.executeHook(ctx, hook, event, entryCount, errMsg); err != nil {
			h.log.Error("hook failed",
				"hook", hook.Name,
				"event", event,
				"error", err,
			)
		} else {
			h.log.Info("hook completed",
				"hook", hook.Name,
				"event", event,
			)
		}
	}
}

// executeHook runs a single hook command against its own resolved timeout
// and environment variables, then records an execution metric. ctx is the
// caller's context (the runner's server-lifecycle context in production,
// never an RPC context) — executeHook derives the hook's deadline from it
// via hook.Timeout, not from any executor-level default.
func (h *HookExecutor) executeHook(ctx context.Context, hook config.HookDefinition, event string, entryCount int, errMsg string) error {
	start := time.Now()
	hookCtx, cancel := context.WithTimeout(ctx, hook.Timeout)
	defer cancel()

	sanitizedErrMsg := strings.ReplaceAll(errMsg, "\r\n", " ")
	sanitizedErrMsg = strings.ReplaceAll(sanitizedErrMsg, "\n", " ")
	sanitizedErrMsg = strings.ReplaceAll(sanitizedErrMsg, "\r", " ")
	sanitizedErrMsg = strings.ReplaceAll(sanitizedErrMsg, "\x00", "")

	cmd := exec.CommandContext(hookCtx, "sh", "-c", hook.Command)
	cmd.Env = append(cmd.Environ(),
		"ROUTER_HOSTS_EVENT="+event,
		"ROUTER_HOSTS_ENTRY_COUNT="+strconv.Itoa(entryCount),
		"ROUTER_HOSTS_ERROR="+sanitizedErrMsg,
	)

	output, err := cmd.CombinedOutput()

	// Classify the outcome by inspecting the hook's own context FIRST. When
	// context.WithTimeout kills the subprocess, exec.CommandContext reports
	// an ordinary *exec.ExitError indistinguishable from a hook that failed
	// on its own merits — checking hookCtx.Err() before the process error is
	// the only reliable way to tell a deadline kill from a self-inflicted
	// non-zero exit.
	var status string
	switch {
	case errors.Is(hookCtx.Err(), context.DeadlineExceeded):
		status = hookStatusTimeout
	case err != nil:
		status = hookStatusFailure
	default:
		status = hookStatusSuccess
	}
	h.metrics.RecordHookExecution(ctx, hook.Name, event, status, time.Since(start))

	if err != nil {
		return oops.Code(domain.CodeInternal).Wrapf(err, "hook %q (output: %s)", hook.Name, string(output))
	}
	return nil
}
