# Phase 9: Hook Reliability & Metrics - Pattern Map

**Mapped:** 2026-07-31
**Files analyzed:** 9 (3 new, 6 modified)
**Analogs found:** 9 / 9

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `internal/server/hookrunner.go` (NEW) | service (background worker) | event-driven | `internal/server/writequeue.go` | role-match (queueing vs. coalescing differ, lifecycle identical) |
| `internal/server/hookrunner_test.go` (NEW) | test | event-driven | `internal/server/writequeue_test.go` | role-match |
| `internal/server/hooks.go` (MODIFY) | service | request-response | itself (existing) + `internal/server/service.go` `ServiceOption` | exact (option pattern), self (executor core) |
| `internal/server/metrics.go` (MODIFY) | service (instrumentation) | event-driven | itself (existing `hookExecsTotal`/`RecordHookExecution`) | exact — template already in file |
| `internal/server/service.go` (MODIFY) | service | request-response | itself (`regenerateOutputs`) | exact |
| `internal/client/commands/serve.go` (MODIFY) | config/wiring | request-response | itself (`writeQueue.Start()`/`defer writeQueue.Stop()`, metrics wiring block) | exact |
| `internal/config/server.go` (MODIFY) | config | CRUD (config load/validate) | itself (`RetentionConfig.Validate`, `HookDefinition.validate`, zero-value-default pattern) | exact |
| `internal/server/hooks_test.go` (MODIFY) | test | request-response | itself (`TestHookExecutor_Timeout`) | exact |
| `internal/server/metrics_test.go` (MODIFY) | test | event-driven | itself (`TestNewMetrics`, `TestDisabledMetrics`, `newTestMetrics`/`collectMetrics`/`findMetric`/`extractAttrs` helpers) | exact |
| `internal/config/server_test.go` (MODIFY) | test | CRUD | itself (`TestLoadServerConfig_WithHooks`, `TestHookDefinition_Validate`) | exact |

## Pattern Assignments

### `internal/server/hookrunner.go` (NEW — service, event-driven)

**Analog:** `internal/server/writequeue.go` (full file, 135 lines — read in one pass, no re-read needed)

**Struct + constructor shape** (writequeue.go:21-40):

```go
type WriteQueue struct {
	ch   chan writeCommand
	quit chan struct{} // closed by Stop to tell process() to drain and exit
	done chan struct{} // closed by process() when it has fully exited
	log  *slog.Logger

	mu      sync.Mutex
	stopped bool
}

func NewWriteQueue(bufferSize int, logger *slog.Logger) *WriteQueue {
	return &WriteQueue{
		ch:   make(chan writeCommand, bufferSize),
		quit: make(chan struct{}),
		done: make(chan struct{}),
		log:  logger,
	}
}
```

Copy this shape verbatim for `hookRunner`, but replace `ch chan writeCommand` (unbounded-buffer queue) with a `mu`-guarded `pending *hookRunRequest` slot + a capacity-1 `trigger chan struct{}` (per RESEARCH.md Pattern 1) — this is the one structural divergence CONTEXT.md mandates (coalescing vs. queuing).

**Start/Stop lifecycle** (writequeue.go:42-58):

```go
func (q *WriteQueue) Start() {
	go q.process()
}

func (q *WriteQueue) Stop() {
	q.mu.Lock()
	if !q.stopped {
		q.stopped = true
		close(q.quit)
	}
	q.mu.Unlock()
	<-q.done
}
```

Copy `Start`/the `stopped`-guarded `close(quit)` idiom verbatim. `hookRunner.Stop` must extend this with the CONTEXT.md-mandated bounded drain: take a `context.Context` deadline, and if `<-r.done` doesn't fire before `ctx.Done()`, call `r.cancel()` (cancelling the runner's own base context, killing any in-flight `exec.Cmd`) and then still wait on `<-r.done`. RESEARCH.md gives the exact shape:

```go
func (r *hookRunner) Stop(ctx context.Context) {
	close(r.quit)
	select {
	case <-r.done:
	case <-ctx.Done():
		r.cancel()
		<-r.done
	}
}
```

**Processing loop** (writequeue.go:112-134):

```go
func (q *WriteQueue) process() {
	defer close(q.done)
	for {
		select {
		case cmd := <-q.ch:
			err := cmd.fn()
			cmd.result <- err
		case <-q.quit:
			// Drain any commands already buffered before exiting.
			for {
				select {
				case cmd := <-q.ch:
					err := cmd.fn()
					cmd.result <- err
				default:
					return
				}
			}
		}
	}
}
```

Copy the `defer close(q.done)` + `select { case work: ...; case <-quit: drain-then-return }` skeleton. `hookRunner.loop()` differs only in what "work" means: pop `r.pending` (mutex-guarded) instead of reading off a channel, and there is no drain-buffer step on `<-quit` since there's at most one pending request (already captured by `Stop`'s bounded-wait, not a drain loop).

**Coalescing trigger — NEW pattern, not in writequeue.go** (from RESEARCH.md Pattern 1, cite as the shape to implement):

```go
func (r *hookRunner) Trigger(req hookRunRequest) {
	r.mu.Lock()
	coalesced := r.pending != nil
	r.pending = &req
	r.mu.Unlock()

	if coalesced {
		r.metrics.RecordHookRunCoalesced(context.Background())
	}

	select {
	case r.trigger <- struct{}{}:
	default: // a wakeup is already pending; loop() will pick up the latest req
	}
}
```

**Deterministic test technique (no `time.Sleep`)** — `writequeue_test.go` doesn't need signal channels for its Stop test because `Submit` is synchronous (`wg.Wait()` before `q.Stop()`, writequeue_test.go:144-165). `hookRunner`'s tests need a different determinism technique because hook bodies run in a subprocess (`sh -c`), not a Go closure — RESEARCH.md's Pitfall/Determinism-note prescribes a **filesystem sentinel inside `t.TempDir()`**: block the hook on `while [ ! -f "$UNBLOCK" ]; do sleep 0.05; done`, call the triggering method, assert it returned, THEN create the sentinel file, THEN assert completion. This proves ordering without wall-clock comparison. Do not port `writequeue_test.go`'s `wg.Wait()`-then-assert shape directly — it assumes in-process synchronous work, which hooks are not.

---

### `internal/server/hooks.go` (MODIFY — service, request-response)

**Current constructor is POSITIONAL, not options** (hooks.go:26-33):

```go
func NewHookExecutor(onSuccess, onFailure []config.HookDefinition, timeout time.Duration, logger *slog.Logger) *HookExecutor {
	return &HookExecutor{
		onSuccess: onSuccess,
		onFailure: onFailure,
		timeout:   timeout,
		log:       logger,
	}
}
```

**Every call site that breaks if this becomes variadic-options** (grep before editing — do not assume RESEARCH.md's enumeration is complete):

- `internal/client/commands/serve.go:102-107` — `server.NewHookExecutor(cfg.Hooks.OnSuccess, cfg.Hooks.OnFailure, defaultHookTimeout, logger)`
- `internal/server/hooks_test.go` — multiple `NewHookExecutor([]config.HookDefinition{...}, nil, timeout, logger)` calls (e.g. line 59-69 quoted in RESEARCH.md); grep `NewHookExecutor(` across `internal/server/*_test.go` before touching the signature.

**Recommended non-breaking approach:** keep the existing 4 positional params (name/command/timeout/logger are the load-bearing arguments every caller already supplies) and add `opts ...HookExecutorOption` as a trailing variadic parameter, mirroring `ServiceOption`'s shape below — this avoids rewriting every existing call site's argument order while still supporting `WithMetrics`.

**Functional-option pattern to copy** (`internal/server/service.go:59-72`, plus constructor loop at :95-97):

```go
type ServiceOption func(*HostsServiceImpl)

func WithHookExecutor(hooks *HookExecutor) ServiceOption {
	return func(s *HostsServiceImpl) { s.hooks = hooks }
}

func WithVersion(version, buildInfo string) ServiceOption {
	return func(s *HostsServiceImpl) {
		s.version = version
		s.buildInfo = buildInfo
	}
}

func NewHostsServiceImpl(handler *CommandHandler, store storage.Storage, opts ...ServiceOption) *HostsServiceImpl {
	svc := &HostsServiceImpl{ /* defaults */ }
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}
```

Copy this exact shape for `HookExecutorOption`/`WithMetrics(m *Metrics) HookExecutorOption`, defaulting `h.metrics = DisabledMetrics()` before applying opts (per CONTEXT.md: "always holds a non-nil `*Metrics`").

**Per-hook timeout resolution** — new logic, no direct analog; place it where `executeHook` currently derives `hookCtx` (hooks.go:83-85):

```go
hookCtx, cancel := context.WithTimeout(ctx, h.timeout)
defer cancel()
```

Replace `h.timeout` with a per-hook resolved value: `hook.Timeout` if non-zero, else the executor's configured default (which itself is `HooksConfig.DefaultTimeout` if non-zero, else `config.DefaultHookTimeout` = 30s — resolved once at config-load time per Pitfall 1, not at hook-execution time). Also replace `ctx` (today the RPC ctx) with the runner's own base context per RESEARCH.md Pattern 2 — this parameter itself must change from "RPC ctx" to "runner ctx" as part of HOOK-02.

**Status classification (success/failure/timeout)** — no existing analog (this is new logic); implement per RESEARCH.md Pitfall 3: check `hookCtx.Err()` FIRST — `errors.Is(hookCtx.Err(), context.DeadlineExceeded)` → `status="timeout"`; else `err != nil` → `status="failure"`; else `status="success"`. Existing exit-code handling (hooks.go:99-103) stays as the wrapped-error return path; only the status *string* passed to `RecordHookExecution` needs this ordering.

**Error handling (existing, unchanged):**

```go
output, err := cmd.CombinedOutput()
if err != nil {
	return oops.Code(domain.CodeInternal).Wrapf(err, "hook %q (output: %s)", hook.Name, string(output))
}
```

---

### `internal/server/metrics.go` (MODIFY — service/instrumentation, event-driven)

**8 sites to touch** (verified against real file — RESEARCH.md's enumeration matches; line numbers below are current, re-verify after HOOK-01's own edits shift them):

1. Struct field (metrics.go:33-43):

```go
type Metrics struct {
	requestsTotal    otelmetric.Int64Counter
	requestDuration  otelmetric.Float64Histogram
	storageOpsTotal  otelmetric.Int64Counter
	storageDuration  otelmetric.Float64Histogram
	hookExecsTotal   otelmetric.Int64Counter
	hookDuration     otelmetric.Float64Histogram
	hostEntriesGauge otelmetric.Int64Gauge

	meterProvider *metric.MeterProvider
}
```

Add `hookRunsCoalescedTotal otelmetric.Int64Counter`.

2. `NewMetrics` instrument creation (metrics.go:81-86, the exact template to copy):

```go
hookExecsTotal, err := meter.Int64Counter("router_hosts_hook_executions_total",
	otelmetric.WithDescription("Total number of hook executions"),
)
if err != nil {
	return nil, oops.Wrapf(err, "create hook_executions_total counter")
}
```

Copy for `hookRunsCoalescedTotal` with name `router_hosts_hook_runs_coalesced_total`.

3. `NewMetrics` return struct literal (metrics.go:104-113) — add the field.

4. `DisabledMetrics` noop creation (metrics.go:198, the exact template):

```go
hookExecsTotal, _ := noopMeter.Int64Counter("router_hosts_hook_executions_total")
```

Copy for the coalesced counter.

5. `DisabledMetrics` return struct literal (metrics.go:202-210) — add the field.

6. New recording method — copy `RecordHookExecution`'s shape (metrics.go:241-257):

```go
func (m *Metrics) RecordHookExecution(ctx context.Context, name, hookType, status string, duration time.Duration) {
	counterAttrs := otelmetric.WithAttributes(
		attribute.String("name", name),
		attribute.String("type", hookType),
		attribute.String("status", status),
	)
	m.hookExecsTotal.Add(ctx, 1, counterAttrs)
	m.hookDuration.Record(ctx, duration.Seconds(),
		otelmetric.WithAttributes(
			attribute.String("name", name),
			attribute.String("type", hookType),
		),
	)
}
```

`RecordHookRunCoalesced(ctx context.Context, hookType string)` should follow the same `otelmetric.WithAttributes(attribute.String("type", hookType))` + single `.Add(ctx, 1, attrs)` shape (RESEARCH.md Assumption A1 recommends matching the `type` label for dashboard consistency).

7/8. Test sites — see `metrics_test.go` pattern assignment below.

**Metric duration-histogram convention** (metrics.go:241-243 doc comment) — preserve: "duration histogram intentionally omits the status label to match the Rust implementation." Apply the same doc-comment convention to any new doc comments this phase adds.

---

### `internal/server/service.go` (MODIFY — service, request-response)

**Current synchronous hook fire site** (service.go:150-169):

```go
if s.hooks == nil || !ran {
	return
}

entryCount := 0
if entries, err := s.store.ListAll(ctx); err != nil {
	slog.Error("hook entry count unavailable", "op", op, "error", err)
} else {
	entryCount = len(entries)
}

if len(errMsgs) == 0 {
	s.hooks.RunSuccess(ctx, entryCount)
} else {
	s.hooks.RunFailure(ctx, entryCount, strings.Join(errMsgs, "; "))
}
```

Replace the final `if len(errMsgs) == 0 { s.hooks.RunSuccess... } else { s.hooks.RunFailure... }` block with `s.hookRunner.Trigger(hookRunRequest{event: ..., entryCount: entryCount, errMsg: ...})` — **do not pass `ctx`** (RESEARCH.md Pitfall 2: `hookRunRequest` must carry no `context.Context` field). The `s.hooks == nil` guard becomes `s.hookRunner == nil` (or keep `s.hooks` as the field the runner wraps — Claude's Discretion per CONTEXT.md on internal naming — but the RPC-facing behavior must still no-op when no hooks are configured, exactly as today).

**`ServiceOption` wiring point** — reuse the exact `WithHookExecutor` pattern (service.go:64-67) shown above under `hooks.go`; likely need a parallel `WithHookRunner(r *hookRunner) ServiceOption` (or fold the runner construction inside `WithHookExecutor` — Claude's Discretion, not mandated by CONTEXT.md).

---

### `internal/client/commands/serve.go` (MODIFY — config/wiring, request-response)

**Existing `writeQueue` Start/defer-Stop shape to mirror** (serve.go:71-76):

```go
writeQueue := server.NewWriteQueue(64, logger)
writeQueue.Start()
defer writeQueue.Stop()
```

Copy this exact `construct → Start() → defer Stop()` shape for the hook runner's lifecycle in `runServe`.

**Existing bounded-deadline defer shape to mirror** (serve.go:137-143, the `metrics.Shutdown` block):

```go
defer func() {
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if serr := metrics.Shutdown(shutCtx); serr != nil {
		logger.Error("metrics shutdown failed", "error", serr)
	}
}()
```

Copy this shape for `hookRunner.Stop(ctx)`, but use `server.GracefulShutdownTimeout` (server.go:26, `30*time.Second`) as the deadline per CONTEXT.md/RESEARCH.md ("bounded drain... tied to the existing `GracefulShutdownTimeout`"), not the 5s used for metrics.

**Hardcoded timeout + hook executor construction to replace** (serve.go:19-20, 100-109):

```go
const defaultHookTimeout = 30 * time.Second
...
if len(cfg.Hooks.OnSuccess) > 0 || len(cfg.Hooks.OnFailure) > 0 {
	hookExec := server.NewHookExecutor(
		cfg.Hooks.OnSuccess,
		cfg.Hooks.OnFailure,
		defaultHookTimeout,
		logger,
	)
	svcOpts = append(svcOpts, server.WithHookExecutor(hookExec))
}
```

Remove the local `defaultHookTimeout` const (moves to `internal/config/server.go` as `DefaultHookTimeout`, alongside `DefaultMaxSnapshots`/`DefaultRenewalDays`). Pass `metrics` into the executor via the new `WithMetrics` option — this is the literal HOOK-01 wiring gap RESEARCH.md identifies (`metrics` is constructed later at serve.go:129-133, but the executor is built earlier at :100-109 with no metrics reference at all today) — so this construction must move to *after* the metrics block, or `metrics` must be forward-declared/passed by pointer before assignment. Verify ordering carefully when planning this file's diff.

**Existing metrics construction block (unchanged shape, just needs the hook executor to consume its output)** (serve.go:129-148) — read for full context when sequencing the reordering above.

---

### `internal/config/server.go` (MODIFY — config, CRUD)

**Current schema to extend** (server.go:151-161):

```go
type HookDefinition struct {
	Name    string `toml:"name"`
	Command string `toml:"command"`
}

type HooksConfig struct {
	OnSuccess []HookDefinition `toml:"on_success"`
	OnFailure []HookDefinition `toml:"on_failure"`
}
```

Add `Timeout time.Duration `toml:"timeout"`` to `HookDefinition` and `DefaultTimeout time.Duration `toml:"default_timeout"`` to `HooksConfig` — BurntSushi/toml v1.6.0 decodes these natively from `"10s"`-style strings, no custom type (RESEARCH.md, confirmed via Context7).

**Zero-value-means-inherit-default pattern to copy** (server.go:242-243, the `RetentionConfig` precedent):

```go
if cfg.Retention.MaxSnapshots == 0 {
	cfg.Retention.MaxSnapshots = DefaultMaxSnapshots
}
```

Apply identically for hook timeouts inside `LoadServerConfig`, after decode and before `cfg.validate()`: `if cfg.Hooks.DefaultTimeout == 0 { cfg.Hooks.DefaultTimeout = DefaultHookTimeout }`, then per-hook `if hook.Timeout == 0 { hook.Timeout = cfg.Hooks.DefaultTimeout }` (or resolve per-hook lazily in `hooks.go` instead — either satisfies CONTEXT.md, but the zero-value defaulting step itself must exist somewhere before validation, per Pitfall 1).

**`DefaultXxx` constant block to extend** (server.go:22-34 region, cited via `DefaultMaxSnapshots = 50` / `DefaultRenewalDays = 30`) — add `DefaultHookTimeout = 30 * time.Second` alongside these, replacing the const currently duplicated in `serve.go:19-20`.

**Validation pattern to copy** (server.go:369-384, `HookDefinition.validate()`):

```go
func (h *HookDefinition) validate() error {
	if h.Name == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: hook name must be non-empty")
	}
	if len(h.Name) > MaxHookNameLength {
		return oops.Code(domain.CodeValidation).Errorf("config: hook name %q exceeds %d character limit", h.Name, MaxHookNameLength)
	}
	if !isValidKebabCase(h.Name) {
		return oops.Code(domain.CodeValidation).Errorf("config: hook name %q is invalid (must be kebab-case: lowercase letters, numbers, and hyphens)", h.Name)
	}
	if strings.TrimSpace(h.Command) == "" {
		return oops.Code(domain.CodeValidation).Errorf("config: hook %q has empty or whitespace-only command", h.Name)
	}
	return nil
}
```

Append `if h.Timeout < 0 { return oops.Code(domain.CodeValidation).Errorf("config: hook %q timeout must be non-negative (got %s)", h.Name, h.Timeout) }` in the same style. Add the equivalent check to `HooksConfig.validate()` (server.go:342-367) for `DefaultTimeout`.

---

## Shared Patterns

### Errors — `samber/oops` with `oops.Code(domain.CodeValidation)` / `oops.Code(domain.CodeInternal).Wrapf`

**Source:** `internal/config/server.go:369-384` (validation), `internal/server/hooks.go:100-102` (runtime)
**Apply to:** All new validation logic in `config/server.go`, all new runtime error paths in `hookrunner.go`/`hooks.go`.

### Logging — `log/slog` key/value pairs

**Source:** `internal/server/hooks.go:68-78`

```go
h.log.Error("hook failed", "hook", hook.Name, "event", event, "error", err)
h.log.Info("hook completed", "hook", hook.Name, "event", event)
```

**Apply to:** Any new log lines in `hookrunner.go` (e.g. coalesce events, drain-timeout events) — keep the `"hook"`/`"event"` key convention.

### Goroutine lifecycle — `quit`/`done` channel pair, `sync.Mutex`-guarded stop flag

**Source:** `internal/server/writequeue.go:24-25, 50-58, 114-134` (full pattern, see hookrunner.go pattern assignment above for the complete excerpt)
**Apply to:** `hookrunner.go` — this is the mandatory skeleton per CONTEXT.md/RESEARCH.md; only the "what is work" step (channel-read vs. mutex-guarded-slot-read) and the `Stop` bounded-deadline extension differ from `WriteQueue`.

### Functional options

**Source:** `internal/server/service.go:44-84` (full `ServiceOption` block)
**Apply to:** `HookExecutorOption`/`WithMetrics` in `hooks.go`; keep the `for _, opt := range opts { opt(x) }` application loop identical to `NewHostsServiceImpl` (service.go:95-97).

### OTel instrument registration — dual real/noop constructor parity

**Source:** `internal/server/metrics.go` (`NewMetrics` vs `DisabledMetrics`, full enumeration in the `metrics.go` pattern assignment above)
**Apply to:** Any new instrument — the 8-site checklist above is mandatory; a missed site either fails to compile (constructor/struct-literal sites) or silently under-tests (test-assertion sites).

### Config zero-value-inherits-default

**Source:** `internal/config/server.go:242-243` (`RetentionConfig.MaxSnapshots`), `:277-279` (`OTel.ExportIntervalSec`)
**Apply to:** `HooksConfig.DefaultTimeout` and `HookDefinition.Timeout` defaulting logic inside `LoadServerConfig`.

## No Analog Found

| File/Concern | Role | Data Flow | Reason |
|---|---|---|---|
| Coalescing trigger channel (`pending` slot + cap-1 channel) | concurrency primitive | event-driven | No coalescing precedent exists in this codebase; `WriteQueue` queues unboundedly rather than coalescing. RESEARCH.md Pattern 1 supplies the reference shape (standard Go idiom, not an in-repo file) — use that, not a codebase analog. |
| `status="timeout"` vs `status="failure"` classification via `hookCtx.Err()` ordering | logic (not file-level) | request-response | New logic; no existing status-classification code in the repo to copy from. RESEARCH.md Pitfall 3 is the authoritative reference. |

## Metadata

**Analog search scope:** `internal/server/`, `internal/config/`, `internal/client/commands/`
**Files scanned:** `writequeue.go`, `writequeue_test.go`, `hooks.go`, `hooks_test.go`, `metrics.go`, `metrics_test.go`, `service.go`, `serve.go`, `config/server.go`, `config/server_test.go`
**Pattern extraction date:** 2026-07-31
