# Phase 9: Hook Reliability & Metrics - Research

**Researched:** 2026-07-31
**Domain:** Go concurrency (detached background runner), OTel metrics wiring, TOML config duration parsing
**Confidence:** HIGH

## Summary

This phase closes two defects in an already-working hook mechanism: dead metrics
(HOOK-01) and an unbounded/fixed-timeout synchronous hook path that can stall
writes (HOOK-02). Neither defect requires new external dependencies — everything
needed (OTel instruments, `time.Duration` TOML decoding, `context.WithTimeout`,
channels) is already imported or already in `go.mod`. The two changes are best
implemented together because they touch the same seam: `HookExecutor` gains a
`WithMetrics` option and a background runner; `regenerateOutputs` stops calling
hooks inline and instead hands a request to that runner.

The single highest-value finding from this research: **`github.com/BurntSushi/toml`
v1.6.0 (the version already pinned in `go.mod`) decodes `time.Duration` struct
fields natively** from both TOML strings (`"10s"`) and bare integers (nanoseconds)
— confirmed via Context7 official docs, not assumed. No custom `UnmarshalText`
type and no `string`-then-`ParseDuration`-in-`validate()` detour is needed; a
plain `Timeout time.Duration \`toml:"timeout"\`` field on `HookDefinition` decodes
directly. This eliminates the single biggest risk area flagged in the research
brief.

For the detached runner, the codebase already contains an idiomatic in-house
precedent to follow rather than invent: `internal/server/writequeue.go`
(`WriteQueue`) is a single-goroutine background processor with `quit`/`done`
channel lifecycle, `sync.Mutex`-guarded stop flag, and deterministic
(non-`time.Sleep`) tests using signal channels. The hook runner's shape differs
from `WriteQueue` in one respect — `WriteQueue` queues unboundedly (bounded by
buffer + blocking `Submit`), while the hook runner must coalesce (queue depth 1,
latest-wins) — but the channel-lifecycle skeleton (`quit`, `done`, `Start`/`Stop`)
should be reused verbatim for consistency and reviewer familiarity.

**Primary recommendation:** Add a `hookRunner` type (new file `internal/server/hookrunner.go`,
sibling to `hooks.go`) that owns a server-lifecycle `context.Context` (created
in `serve.go`, cancelled after a bounded drain tied to `GracefulShutdownTimeout`),
a `sync.Mutex`-guarded "latest pending request" slot, and a capacity-1 trigger
channel using the standard Go non-blocking-send-with-`default` coalescing idiom.
`regenerateOutputs` calls `hookRunner.Trigger(req)` and returns immediately;
`HookExecutor.executeHook` derives its per-hook timeout from `hookCtx :=
context.WithTimeout(runnerCtx, resolvedTimeout)`, never from the RPC `ctx`.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Hook execution (shell command run) | API / Backend (`internal/server`) | — | Hooks are a server-side side effect of write processing; no client or storage involvement |
| Hook scheduling / coalescing | API / Backend (`internal/server`, new `hookrunner.go`) | — | Purely in-process goroutine + channel state; not persisted, not client-visible |
| Timeout configuration | Database / Storage tier N/A — Config/File | — | TOML config file, parsed at server startup (`internal/config`) |
| Metrics emission | API / Backend (`internal/server/metrics.go`) | — | OTel instruments live in the server process; already registered, only need callers |
| Server lifecycle / shutdown draining | API / Backend (`internal/server/server.go`, `internal/client/commands/serve.go`) | — | `GracefulShutdownTimeout` and signal handling already live here |

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| HOOK-01 | Server emits execution metrics (count, duration, outcome) for `on_success` / `on_failure` hooks | `RecordHookExecution` is fully implemented ([VERIFIED: internal/server/metrics.go:244-257]); this research documents exactly where to call it (executor, post-exec) and how to add the `WithMetrics` functional option and the timeout-vs-failure status distinction (§ "Wiring metrics into the executor") |
| HOOK-02 | Configurable per-hook timeout + bounded execution so a slow hook cannot block the write path | This research documents the TOML `time.Duration` decoding mechanism (§ "Timeout configuration"), the detached-runner design with coalescing (§ "Architecture Patterns"), and the shutdown-drain integration point (§ "Common Pitfalls") |

</phase_requirements>

## Standard Stack

No new dependencies. Every mechanism required by this phase is already present:

### Core (already in go.mod — no version change needed)

| Library | Version (go.mod) | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `github.com/BurntSushi/toml` | v1.6.0 [VERIFIED: go.mod:6] | TOML config decode, incl. native `time.Duration` field support | Already chosen for `MetaData.Undecoded()` strict-key checking (documented in `internal/config/server.go:12-15`); no reason to add a second TOML lib |
| `go.opentelemetry.io/otel/metric` | v1.44.0 [VERIFIED: go.mod:18] | Metric instrument types (`Int64Counter`, `Float64Histogram`) | Already used for every other instrument in `metrics.go` |
| `go.opentelemetry.io/otel/sdk/metric` | v1.44.0 [VERIFIED: go.mod:20] | `metric.NewManualReader` for tests | Already the test pattern in `metrics_test.go:26-33` |
| `github.com/samber/oops` | v1.23.0 [VERIFIED: go.mod:13] | Structured errors for timeout validation | Repo-wide convention (CLAUDE.md, `internal/config/server.go:369-383`) |
| stdlib `context`, `time`, `sync` | go 1.26.5 [VERIFIED: go.mod:3] | Runner goroutine, coalescing channel, `context.WithTimeout` | No third-party concurrency primitive needed for this shape |

### Explicitly NOT added

| Considered | Verdict | Why not |
|------------|---------|---------|
| `go.uber.org/goleak` | Not added | **Confirmed absent from go.mod** [VERIFIED: go.mod — grepped, no match]. `writequeue_test.go` (the closest existing precedent for a goroutine-owning type) does not use it either; it verifies clean shutdown via the `done`-channel-closes contract instead. Adding a new test-only dependency for one phase is disproportionate — follow the existing repo pattern (§ Testing Strategy) instead of introducing a new tool. |
| `golang.org/x/sync/singleflight` | Not added as direct dep | Present only as an *indirect* transitive dependency [VERIFIED: go.mod:106, `// indirect`]. `singleflight.Group.Do` collapses **concurrent identical calls** into one execution and returns the *same result* to all callers — semantically wrong here: coalescing must mean "the supersede-and-drop of an already-queued-but-not-yet-started run," not "share a result across callers." A manual mutex-guarded "latest pending" slot + capacity-1 trigger channel is both simpler and semantically correct. |

**Version verification performed:**

```bash
$ grep 'BurntSushi/toml' go.mod
	github.com/BurntSushi/toml v1.6.0
```

Confirmed current: BurntSushi/toml is the actively maintained TOML library; the `time.Duration` field support is documented in its README/`_autodocs` (fetched via Context7 `/burntsushi/toml`, high source reputation).

**Installation:** None required — no `go get` needed for this phase.

## Package Legitimacy Audit

**Not applicable.** This phase adds zero new external packages. All work uses
libraries already present in `go.mod` (BurntSushi/toml, OTel SDK, samber/oops,
stdlib). Skip the Package Legitimacy Gate protocol.

## Architecture Patterns

### System Architecture Diagram

```text
                     ┌─────────────────────────────────────────────┐
                     │              gRPC write RPC                 │
                     │   AddHost / UpdateHost / DeleteHost /        │
                     │   ImportHosts / RollbackToSnapshot           │
                     └───────────────────┬───────────────────────────┘
                                          │ (RPC ctx — short-lived)
                                          ▼
                     ┌─────────────────────────────────────────────┐
                     │   regenerateOutputs(rpcCtx, op)              │
                     │   1. run generators (hosts/dnsmasq/unbound)  │
                     │   2. build hookRunRequest{event,count,err}   │
                     │   3. hookRunner.Trigger(req)  ── NON-BLOCKING│
                     │   4. return to RPC caller immediately        │
                     └───────────────────┬───────────────────────────┘
                                          │ Trigger() only touches a
                                          │ mutex + a cap-1 channel;
                                          │ never blocks on hook I/O
                                          ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  hookRunner (owns runnerCtx — server-lifecycle, NOT rpcCtx)     │
     │                                                                  │
     │   loop:                                                         │
     │     select {                                                    │
     │     case <-trigger:                                             │
     │         req := takeLatestPending()   // may itself be req N,    │
     │                                       // req 2..N-1 were         │
     │                                       // coalesced/dropped here  │
     │         runBatch(runnerCtx, req)      // sequential hooks        │
     │     case <-runnerCtx.Done():                                    │
     │         return                                                  │
     │     }                                                            │
     └───────────────────────────┬──────────────────────────────────────┘
                                  │ per hook: hookCtx =
                                  │ context.WithTimeout(runnerCtx, resolved)
                                  ▼
                    ┌───────────────────────────────┐
                    │ executeHook (unchanged core)   │
                    │ exec.CommandContext(hookCtx,…) │──── metrics.RecordHookExecution(
                    └───────────────────────────────┘        name, type, status, dur)
                                                                      │
                                                                      ▼
                                                     router_hosts_hook_executions_total
                                                     router_hosts_hook_duration_seconds
                                                     router_hosts_hook_runs_coalesced_total (new)

     Shutdown path: serve.go defer → hookRunner.Stop(ctx-with-GracefulShutdownTimeout)
                    → signals quit, waits up to timeout for in-flight batch, then
                      cancels runnerCtx (kills any still-running exec.Cmd)
```

### Recommended Project Structure

```text
internal/server/
├── hooks.go              # HookExecutor: unchanged executeHook core, gains
│                          # WithMetrics option + timeout resolution per hook
├── hookrunner.go          # NEW: hookRunner — background goroutine, coalescing
│                          # trigger, Start/Stop lifecycle (mirrors writequeue.go)
├── hookrunner_test.go     # NEW: deterministic (non-sleep) coalescing + drain tests
├── service.go             # regenerateOutputs calls hookRunner.Trigger(req)
│                          # instead of s.hooks.RunSuccess/RunFailure directly
├── metrics.go             # + hookRunsCoalescedTotal instrument (NewMetrics,
│                          # DisabledMetrics, struct field — 3 sites)
internal/config/
├── server.go              # HookDefinition.Timeout time.Duration; HooksConfig.
│                          # DefaultTimeout time.Duration; validate() timeout checks
internal/client/commands/
├── serve.go                # constructs hookRunner with server-lifecycle ctx,
│                           # passes metrics via WithMetrics, defers bounded Stop
```

### Pattern 1: Coalescing trigger channel (capacity-1 + non-blocking send)

**What:** A cheap, well-known Go idiom for "wake a background worker, but never
queue more than one pending wakeup" — the "debounce"/"coalesce" channel pattern.
**When to use:** Exactly the CONTEXT.md "queue depth 1 with coalescing,
latest-wins" requirement.
**Example (shape, not exact final code — Claude's Discretion on naming per CONTEXT.md):**

```go
// Source: standard Go concurrency idiom (Rob Pike "Go Concurrency Patterns";
// same shape used by client-go workqueue and controller-runtime internally)
type hookRunner struct {
	mu      sync.Mutex
	pending *hookRunRequest // latest not-yet-started request; nil = none

	trigger chan struct{} // capacity 1
	ctx     context.Context
	cancel  context.CancelFunc
	quit    chan struct{}
	done    chan struct{}

	exec    *HookExecutor
	metrics *Metrics
}

// Trigger enqueues req, coalescing with any not-yet-started pending request.
// Never blocks; safe to call from the RPC goroutine.
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

func (r *hookRunner) loop() {
	defer close(r.done)
	for {
		select {
		case <-r.trigger:
			r.mu.Lock()
			req := r.pending
			r.pending = nil
			r.mu.Unlock()
			if req != nil {
				r.exec.runBatch(r.ctx, *req) // uses r.ctx, NOT any RPC ctx
			}
		case <-r.quit:
			return
		}
	}
}
```

This is the same structural family as `internal/server/writequeue.go`'s
`process()` loop (`quit`/`done` channel pair, `sync.Mutex`-guarded stop flag) —
reuse that lifecycle shape for reviewer familiarity, but note `WriteQueue` does
**not** coalesce (it queues every command up to buffer size and blocks
`Submit` when full); the hook runner's `pending`-slot-plus-`trigger` combo is
the piece that is new here.

### Pattern 2: Detaching from the RPC context

**What:** The runner must execute hooks against a context that survives RPC
cancellation.
**When to use:** Always, for this phase — this is the core of HOOK-02.
**Why the current code is wrong:** `executeHook(ctx, ...)` receives the RPC's
`ctx` directly today [VERIFIED: internal/server/hooks.go:83-84, `hookCtx, cancel
:= context.WithTimeout(ctx, h.timeout)`] and `runHooks` is called synchronously
from `regenerateOutputs(ctx, op)` [VERIFIED: internal/server/service.go:122,166,168]
with the same RPC `ctx` that `AddHost` etc. received [VERIFIED:
internal/server/service.go:207,211 — `func (s *HostsServiceImpl) AddHost(ctx
context.Context, ...)` then `s.regenerateOutputs(ctx, "AddHost")`]. If a client
disconnects or the RPC deadline fires, that same `ctx` cancels the hook's
`context.WithTimeout` derivation too — today this doesn't matter because hooks
already run synchronously and their result isn't observed by the RPC. Once
detached, this same cancellation must NOT reach the hook, or a fast client
timeout would silently prevent hooks from ever running to completion.
**Fix shape:** `hookRunner` owns its own base `context.Context` created once at
server startup (in `serve.go`, e.g., `hookRunnerCtx, hookRunnerCancel :=
context.WithCancel(context.Background())`), independent of any RPC. Every
`hookCtx := context.WithTimeout(hookRunner.ctx, resolvedTimeout)` derives from
that base, not from the RPC's `ctx`. `regenerateOutputs` no longer passes its
own `ctx` into anything hook-related — only `hookRunRequest{event, entryCount,
errMsg}` (plain data) crosses the RPC→runner boundary.

### Anti-Patterns to Avoid

- **Passing the RPC `ctx` into `Trigger()` or storing it on `hookRunRequest`:**
  defeats the entire point of detaching — even if `Trigger` itself doesn't
  block, a stored RPC `ctx` used later inside `runBatch` would still get
  cancelled when the RPC completes (gRPC contexts are cancelled after the
  handler returns), racing the just-detached hook run.
- **Using `sync/singleflight` for coalescing:** see Alternatives table —
  `singleflight` shares one *result* across N *concurrent* callers; it does not
  express "drop requests 2..N-1, keep only N" for callers that are not
  concurrently blocked waiting on a return value (nobody here waits on a
  return value at all, by design).
- **Unbounded buffered channel "for safety":** CONTEXT.md is explicit — queue
  depth 1 with coalescing, not a bigger buffer. A buffer > 1 would let stale
  regeneration requests queue and run after being superseded, which the
  CONTEXT.md rationale explicitly says is pointless (hooks react to
  output-file state, and only the latest state matters).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Duration parsing from TOML strings | A custom `type Duration string` + manual `time.ParseDuration` call site in `validate()` | Plain `time.Duration` struct field, decoded natively by BurntSushi/toml v1.6.0 | [CITED: github.com/burntsushi/toml README / `_autodocs/type-conversions.md` via Context7] — confirmed the library has first-class support; a hand-rolled string-then-parse path is strictly more code for identical behavior and a needless divergence from the library's native mechanism |
| OTel instrument creation boilerplate | A new counter helper function | Reuse the existing `meter.Int64Counter(...)` call shape already used 3x in `NewMetrics` and mirrored in `DisabledMetrics` | Instrument creation in this codebase already has an established two-constructor pattern (real + noop); a new helper would only add indirection for one more instrument |
| Goroutine lifecycle / graceful drain | A custom `WaitGroup`-plus-timer pattern from scratch | The `quit`/`done` channel pair already used in `WriteQueue` (`internal/server/writequeue.go:24-25,50-58,114-134`) | Proven, already-reviewed pattern in this exact package; reusing it means the plan-checker and code-reviewer see a familiar shape instead of a novel one |

**Key insight:** every mechanism this phase needs (duration decode, background
goroutine lifecycle, OTel instrument registration) already has a working
precedent either in the standard library, in the already-pinned dependency, or
in this exact package. The temptation to build something bespoke (a custom
duration string type, a `sync.Cond`-based signaling scheme, a new metrics
helper abstraction) should be resisted — none of it is justified by anything
specific to hooks.

## Common Pitfalls

### Pitfall 1: `time.Duration` zero value is indistinguishable from "not set"

**What goes wrong:** A `time.Duration` field decoded from TOML defaults to `0`
whether the key was absent from the file or the user wrote `timeout = "0s"`
explicitly (BurntSushi/toml has no `Undecoded()`-style per-field presence check
that's convenient to use here, and the repo's own `MetaData.Undecoded()` usage
[VERIFIED: internal/config/server.go:233-239, quoted: `if keys :=
meta.Undecoded(); len(keys) > 0 {`] only tracks *unknown* keys, not "known key
present with zero value" vs "known key absent").
**Why it happens:** This is a Go zero-value ambiguity, not a TOML library bug.
**How to avoid:** Treat `0` uniformly as "inherit the default," exactly as the
codebase already does for `Retention.MaxSnapshots`/`MaxAgeDays` [VERIFIED:
internal/config/server.go:242-247, quoted: `if cfg.Retention.MaxSnapshots == 0
{ cfg.Retention.MaxSnapshots = DefaultMaxSnapshots }`] and for
`OTel.ExportIntervalSec` [VERIFIED: internal/config/server.go:277-279, quoted:
`if otel.ExportIntervalSec == 0 { otel.ExportIntervalSec =
DefaultExportIntervalSecs }`]. Apply the same `if X.Timeout == 0 { X.Timeout =
resolvedDefault }` defaulting pass inside `LoadServerConfig`, after decode and
before `cfg.validate()`. Validation itself then only needs to reject
**negative** durations (a TOML string like `timeout = "-5s"` parses to a
negative `time.Duration` without error) — `if h.Timeout < 0 { return
oops.Code(domain.CodeValidation).Errorf(...) }` in `HookDefinition.validate()`
[existing method: internal/config/server.go:370-384] and the equivalent check
for `HooksConfig.DefaultTimeout`.
**Warning signs:** A test that writes `timeout = "0s"` and asserts it behaves
identically to omitting `timeout` entirely is the correct regression test for
this; a test that expects `0s` to be rejected would contradict CONTEXT.md's
"absent inherits default" rule and should not be written.

### Pitfall 2: RPC `ctx` cancellation silently killing detached hooks

**What goes wrong:** If any code path in the new runner accidentally threads
the RPC's `ctx` through to `context.WithTimeout` for the hook's `exec.Cmd`
(easy to do by accident if `hookRunRequest` is built to carry a `context.Context`
field "for convenience"), a client that disconnects or hits its own gRPC
deadline will silently kill an in-flight hook that the whole point of this
phase was to detach from that exact failure mode.
**Why it happens:** `hookRunRequest` is data that crosses a goroutine boundary;
it's tempting to also stash a context on it, especially since the *current*
`executeHook(ctx, ...)` signature already takes one.
**How to avoid:** `hookRunRequest` should carry no `context.Context` field at
all — only plain values (`event string`, `entryCount int`, `errMsg string`).
The runner's own `runnerCtx` (server-lifecycle, created once) is the only
context ever passed to `executeHook`/`exec.CommandContext`.
**Warning signs:** A grep for `context.Context` inside any `hookRunRequest`-like
struct, or a call to `context.WithTimeout(ctx, ...)` inside the runner's
`loop()`/`runBatch` where `ctx` traces back to an RPC handler parameter rather
than `r.ctx`/`runnerCtx`.

### Pitfall 3: Distinguishing `status="timeout"` from a generic non-zero exit is a real race, not just an `errors.Is` call

**What goes wrong:** `cmd.CombinedOutput()` (used today [VERIFIED:
internal/server/hooks.go:99, quoted: `output, err := cmd.CombinedOutput()`])
returns an `*exec.ExitError` when the killed process exits with a non-zero
code — which is *always* what happens when `exec.CommandContext`'s context
deadline fires (the stdlib kills the process, and a killed process typically
reports a non-zero exit status or a signal-terminated status, not directly
`context.DeadlineExceeded`). A naive `errors.As(err, &exitErr)` check alone
cannot tell "hook exited 1 because its own logic failed" from "hook was killed
because the timeout fired."
**Why it happens:** `os/exec`'s documented behavior: when `CommandContext`'s
context is done, it calls `cmd.Cancel` (kill by default) and *then* the
running `Wait`/`CombinedOutput` returns whatever the OS reports for that killed
process — the error value itself does not reliably say "killed by our
timeout" versus "process's own exit code."
**How to avoid:** Check the *context*, not just the error: after
`cmd.CombinedOutput()` returns, inspect `hookCtx.Err()` (the context passed to
`CommandContext`) — if `errors.Is(hookCtx.Err(), context.DeadlineExceeded)`,
classify as `status="timeout"` regardless of what the process-level error
looked like; only fall through to `status="failure"` when `hookCtx.Err()` is
`nil` (i.e., the context was never cancelled/expired) and `err != nil`. This
ordering (context-error-first) is the reliable way to detect this race —
checking `err`'s type first and `hookCtx.Err()` second can misclassify a hook
that happened to exit with a real error in the exact instant the timeout also
fired.
**Warning signs:** A flaky test where a hook command like `sleep 10` with a
100ms timeout sometimes reports `status="failure"` instead of
`status="timeout"` — that's this race manifesting; `TestHookExecutor_Timeout`
[VERIFIED: internal/server/hooks_test.go:59-69, quoted: `executor :=
NewHookExecutor([]config.HookDefinition{{Name: "slow-hook", Command: "sleep
10"}}, nil, 100*time.Millisecond, slog.Default())`] already exercises this
exact shape and is the right base to extend with a status assertion once
metrics are wired.

### Pitfall 4: Forgetting a site when adding the coalesced-runs instrument

**What goes wrong:** A new OTel instrument in this codebase must be added in
**every** one of these places, or `DisabledMetrics()`/`NewMetrics()` will
diverge and a nil-pointer panic or missing-metric bug ships silently (no
compiler error catches a missing field in one of two structurally-identical
constructors).
**Enumerated sites (verified by reading the existing `hookExecsTotal` pattern
end-to-end):**

1. `Metrics` struct field — [VERIFIED: internal/server/metrics.go:33-43, quoted
   struct includes `hookExecsTotal   otelmetric.Int64Counter`] → add
   `hookRunsCoalescedTotal otelmetric.Int64Counter`
2. `NewMetrics` constructor — instrument creation + error wrap [VERIFIED:
   internal/server/metrics.go:81-86, quoted: `hookExecsTotal, err :=
   meter.Int64Counter("router_hosts_hook_executions_total", ...)`] → same shape
   for the new counter, new name e.g. `router_hosts_hook_runs_coalesced_total`
3. `NewMetrics` return struct literal — [VERIFIED: internal/server/metrics.go:104-113]
   → add the new field to the literal
4. `DisabledMetrics` — noop instrument creation [VERIFIED:
   internal/server/metrics.go:198, quoted: `hookExecsTotal, _ :=
   noopMeter.Int64Counter("router_hosts_hook_executions_total")`] → same for
   the new counter
5. `DisabledMetrics` return struct literal — [VERIFIED: internal/server/metrics.go:202-210]
   → add the new field
6. A new `RecordHookRunCoalesced(ctx context.Context)` method, mirroring
   `RecordHookExecution`'s shape [VERIFIED: internal/server/metrics.go:244-257]
   but with no labels beyond what's needed (CONTEXT.md doesn't specify labels
   for this counter — Claude's Discretion; a bare counter with no attributes,
   or `name`+`type` attributes matching the executions counter, are both
   defensible; the latter is more useful for per-hook-type dashboards and
   costs nothing extra since the runner already has the hook batch's event
   type in scope)
7. `metrics_test.go`'s `TestNewMetrics` assertion list [VERIFIED:
   internal/server/metrics_test.go:65-82, quoted: `assert.NotNil(t,
   m.hookExecsTotal)` among others] → add `assert.NotNil(t,
   m.hookRunsCoalescedTotal)`
8. `metrics_test.go`'s `TestDisabledMetrics` recording-methods-don't-panic list
   [VERIFIED: internal/server/metrics_test.go:84-98] → add a call to the new
   recording method

That is 8 sites across 1 non-test file + its test — miss any one and either the
struct literal fails to compile (constructors 2/3/4/5) or the test coverage
silently doesn't verify the new instrument exists (7/8).

## Code Examples

### Existing `RecordHookExecution` — the call this phase must wire in

```go
// Source: internal/server/metrics.go:244-257 (already implemented, zero callers today)
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

`hookType` here is the label the CONTEXT.md calls `type` — in the current
codebase this is the `event` string (`"success"` / `"failure"`) already passed
through `runHooks(ctx, hooks, event string, ...)` [VERIFIED:
internal/server/hooks.go:65]. The executor's post-exec call site should be:
`m.RecordHookExecution(runnerCtx, hook.Name, event, status, time.Since(start))`
where `status` is resolved per Pitfall 3 above.

### TOML `time.Duration` decode — confirmed native support

```go
// Source: BurntSushi/toml README / _autodocs/type-conversions.md (via Context7,
// library ID /burntsushi/toml, high source reputation)
type Config struct {
	Timeout      time.Duration
	RetryWait    time.Duration
}

// tomlData:
//   timeout = "30s"
//   retry_wait = "1m30s"
// decodes directly into cfg.Timeout == 30*time.Second, no custom type needed.
```

Applied to this phase's schema:

```go
// internal/config/server.go — proposed field additions (not yet in repo)
type HookDefinition struct {
	Name    string        `toml:"name"`
	Command string        `toml:"command"`
	Timeout time.Duration `toml:"timeout"` // 0 = inherit HooksConfig.DefaultTimeout
}

type HooksConfig struct {
	OnSuccess      []HookDefinition `toml:"on_success"`
	OnFailure      []HookDefinition `toml:"on_failure"`
	DefaultTimeout time.Duration    `toml:"default_timeout"` // 0 = DefaultHookTimeout (30s)
}
```

### `WriteQueue` shutdown lifecycle — the pattern to mirror for `hookRunner`

```go
// Source: internal/server/writequeue.go:50-58 (existing, working pattern)
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

The hook runner's `Stop` differs in one respect required by CONTEXT.md
("bounded drain... then their context is cancelled"): it must take a deadline
and cancel `runnerCtx` if `<-q.done` doesn't fire in time, e.g.
`Stop(ctx context.Context) { close(r.quit); select { case <-r.done: case
<-ctx.Done(): r.cancel() ; <-r.done } }` — the caller in `serve.go` supplies
`ctx` derived from `server.GracefulShutdownTimeout` [VERIFIED:
internal/server/server.go:26, quoted: `const GracefulShutdownTimeout = 30 *
time.Second`], mirroring how `metrics.Shutdown` is already given a `5*time.Second`
timeout at the same call site [VERIFIED: internal/client/commands/serve.go:138,
quoted: `shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)`].

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Hooks run synchronously inline in `regenerateOutputs`, blocking the RPC caller for up to N × 30s | Hooks detached to a background runner; RPC returns as soon as generators finish writing | This phase | Write RPCs no longer have hook latency in their tail; `AddHost`/`UpdateHost`/`DeleteHost`/`ImportHosts`/`RollbackToSnapshot` all benefit since they all funnel through `regenerateOutputs` |
| Fixed 30s hook timeout (`defaultHookTimeout` const in `serve.go`) | Per-hook configurable timeout, `HooksConfig.DefaultTimeout` server-level fallback, both default to 30s | This phase | Existing configs are byte-identical in behavior (CONTEXT.md explicit no-migration guarantee); new configs can tune slow hooks (webhook POST) vs fast ones (`systemctl reload`) independently |
| `RecordHookExecution` implemented but never called | Called from the executor after every hook run | This phase | Closes router-hosts-0ed; `router_hosts_hook_executions_total`/`_duration_seconds` become populated in dashboards for the first time |

**Deprecated/outdated:** `defaultHookTimeout` const in
`internal/client/commands/serve.go:19-20` — should move to
`internal/config/server.go` as `DefaultHookTimeout` (alongside the existing
`DefaultMaxSnapshots`/`DefaultRenewalDays` block [VERIFIED:
internal/config/server.go:22-41]) so config-loading defaults and the CLI's
hardcoded const don't diverge over time.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The coalesced-runs counter should use `attribute.String("type", event)` labels (mirroring `hookExecsTotal`) rather than being label-free | Common Pitfalls > Pitfall 4, item 6 | Low — CONTEXT.md leaves the exact shape to Claude's Discretion ("Naming... and the exact name of the coalesced counter"); either shape satisfies HOOK-01/02. If the planner picks label-free, no rework needed elsewhere since this is a leaf instrument with one call site. |
| A2 | `hookRunner` should live in a new file `hookrunner.go` rather than inside `hooks.go` | Architecture Patterns > Recommended Project Structure | None — CONTEXT.md explicitly delegates this ("Whether the runner lives in hooks.go or a sibling file") to Claude's Discretion; stated here only as a recommendation for file-size hygiene (hooks.go would roughly double in size otherwise) |
| A3 | `runBatch`/`Trigger` naming and the exact `hookRunRequest` field set are illustrative, not mandated | Architecture Patterns > Pattern 1 code example | None — CONTEXT.md explicitly delegates "Naming of the background runner type, its internal channel/goroutine structure" to Claude's Discretion |

**If this table is empty:** N/A — see above; all three entries are
low/no-risk because they map directly onto areas CONTEXT.md already marked as
Claude's Discretion, not areas where a wrong guess would require rework.

## Open Questions

1. **Should the coalesced counter carry the `event` (success/failure) label or be bare?**
   - What we know: CONTEXT.md mandates a *dedicated* instrument, name unspecified beyond an example (`router_hosts_hook_runs_coalesced_total`), and explicitly delegates naming/shape to Claude's Discretion.
   - What's unclear: whether an operator dashboard would want to distinguish "success-batch coalesced" from "failure-batch coalesced" — plausible but not required by either HOOK-01 or HOOK-02's stated success criteria.
   - Recommendation: default to matching the `type` label already used on `hookExecsTotal`/`hookDuration` for consistency (Assumption A1); trivial to simplify to label-free in review if the planner disagrees.

2. **Where exactly does `hookRunner.Stop(ctx)` get invoked relative to `srv.Run(ctx)` returning?**
   - What we know: `serve.go` already has a `defer writeQueue.Stop()` pattern [VERIFIED: internal/client/commands/serve.go:73-74, quoted: `writeQueue.Start()` / `defer writeQueue.Stop()`] and a `defer metrics.Shutdown(...)` pattern with its own timeout [VERIFIED: internal/client/commands/serve.go:137-143]; the hook runner should follow the same `defer`-after-construction shape.
   - What's unclear: whether `Server.gracefulStop()` (inside `server.go`) should own draining the hook runner too, vs. `serve.go` doing it after `srv.Run(ctx)` returns. `Server` currently has no reference to `HookExecutor`/the runner [VERIFIED: internal/server/server.go:29-42, `Server` struct fields do not include hooks], so threading it through would be a bigger structural change than needed.
   - Recommendation: keep it in `serve.go` as a `defer` after `srv.Run(ctx)` returns (i.e., runs after gRPC's own `GracefulStop`/`GracefulShutdownTimeout` window), reusing `server.GracefulShutdownTimeout` as the deadline for the hook drain. This keeps `Server` unchanged and matches the existing `writeQueue`/`metrics` shutdown ordering already in `serve.go`.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` + `testify` (`require`/`assert`) [VERIFIED: go.mod:15, `github.com/stretchr/testify v1.11.1`] |
| Config file | none — no separate test config; `go test` flags only |
| Quick run command | `task test -- -run '<AnchoredPattern>' ./internal/server/... ./internal/config/...` (per Taskfile's own documented usage [VERIFIED: Taskfile.yml:22, quoted: `desc: Run all unit and integration tests. Pass extra go test args after "--" (e.g. \`task test -- -run TestFoo ./internal/operator/\`).`]) |
| Full suite command | `task test` (all packages) or `task ci` (full pipeline: lint + test + build + buf) |

**`-run` is an unanchored regex — proven, not assumed, per this repo's own
prior VALIDATION.md docs** [VERIFIED: `.planning/phases/08-kubernetes-service-controller/08-VALIDATION.md`
and `.planning/quick/260728-ude-fix-wr-01-and-wr-02-from-08-review-md-ag/260728-ude-PLAN.md`,
both state this exact gotcha for this repo]. Any scoped verify command in the
plan MUST enumerate `rg '^func Test' internal/server/*_test.go
internal/config/*_test.go` first and match the `--- PASS` count against that
enumeration — never infer scope from a shared name prefix (e.g. `TestHook`
would silently also match `TestHookExecutor_*` *and* any future
`TestHookRunner*`, which is probably desired, but `TestHookExecutor` would
**not** match a sibling `TestHookRunnerCoalesces` — verify, don't assume).

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| HOOK-01 | `RecordHookExecution` called with correct `name`/`type`/`status` after a successful hook | unit | `task test -- -run '^TestHookExecutor_RecordsSuccessMetric$' ./internal/server/` | ❌ Wave 0 |
| HOOK-01 | `RecordHookExecution` called with `status="timeout"` distinct from `status="failure"` (Pitfall 3) | unit | `task test -- -run '^TestHookExecutor_RecordsTimeoutStatus$' ./internal/server/` | ❌ Wave 0 |
| HOOK-01 | `WithMetrics` defaults to `DisabledMetrics()` when not supplied (no nil-panic) | unit | `task test -- -run '^TestNewHookExecutor_DefaultsToDisabledMetrics$' ./internal/server/` | ❌ Wave 0 |
| HOOK-01 | New `router_hosts_hook_runs_coalesced_total` instrument exists in both `NewMetrics` and `DisabledMetrics` (Pitfall 4) | unit | `task test -- -run '^TestNewMetrics$|^TestDisabledMetrics$' ./internal/server/` | ✅ existing tests extended, not new files |
| HOOK-02 | Per-hook `timeout` TOML string decodes to the correct `time.Duration`, absent inherits `default_timeout`, absent-absent inherits 30s | unit | `task test -- -run '^TestLoadServerConfig_HookTimeout' ./internal/config/` | ❌ Wave 0 |
| HOOK-02 | Negative `timeout` string is rejected at `validate()` | unit | `task test -- -run '^TestHookDefinition_Validate$'` (extend existing table) | ✅ existing, extend table |
| HOOK-02 | Write RPC (`regenerateOutputs`/`AddHost`) returns before a slow hook completes — **deterministic**, not timing-flake | integration | `task test -- -run '^TestRegenerateOutputs_DetachesFromHooks$' ./internal/server/` | ❌ Wave 0 |
| HOOK-02 | A second trigger while a batch is running coalesces (only the latest request's hooks actually execute) | integration | `task test -- -run '^TestHookRunner_CoalescesSupersededRuns$' ./internal/server/` | ❌ Wave 0 |
| HOOK-02 | `Stop(ctx)` drains an in-flight batch within the deadline, then cancels a still-running hook past the deadline | integration | `task test -- -run '^TestHookRunner_StopDrainsThenCancels$' ./internal/server/` | ❌ Wave 0 |
| HOOK-02 | RPC-context cancellation does not kill an already-detached hook (Pitfall 2 regression test) | integration | `task test -- -run '^TestHookRunner_SurvivesRPCContextCancellation$' ./internal/server/` | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** the specific `task test -- -run '<pattern>' <pkg>` scoped to the file(s) touched by that task
- **Per wave merge:** `task test ./internal/server/... ./internal/config/...`
- **Phase gate:** `task ci` (full pipeline) green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `internal/server/hookrunner_test.go` — new file, covers coalescing/drain/detachment behaviors listed above
- [ ] Extend `internal/server/hooks_test.go` — metrics-recording assertions (status classification, `WithMetrics` default)
- [ ] Extend `internal/server/metrics_test.go` — new instrument assertions in `TestNewMetrics`/`TestDisabledMetrics`, new `TestRecordHookRunCoalesced`
- [ ] Extend `internal/config/server_test.go` — timeout decode/default/validation table cases
- [ ] No new framework install needed — testify + stdlib `testing` already cover everything; no fixtures beyond `t.TempDir()` (already the established pattern in `hooks_test.go`/`hooks_wiring_test.go`)

**Determinism note (research_focus item 5b/5a):** The write-path-doesn't-block
assertion must NOT rely on wall-clock timing comparison (e.g. "returned in
< Nms while hook sleeps 10s" — flaky under CI load). Instead: use a hook
command that blocks on a filesystem sentinel inside `t.TempDir()` (e.g. `while
[ ! -f "$UNBLOCK" ]; do sleep 0.05; done`), call `regenerateOutputs`/the
service method, assert it returned (trivially true — it's a synchronous Go
call that either returned or the test would already be hung), THEN create the
unblock sentinel, THEN assert the hook's own completion marker appears — this
proves ordering (write returned *before* the hook could possibly have
completed, since the hook was still polling for a file that didn't exist yet)
without measuring time at all. This differs from `writequeue_test.go`'s
signal-channel technique only because a hook body executes in a *subprocess*
(`sh -c ...`), which cannot receive a Go channel signal directly — a
filesystem sentinel inside `t.TempDir()` is the closest process-boundary-safe
analog and does not violate the "MUST NOT write to real filesystem" rule
(`t.TempDir()` is the sanctioned mechanism).

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | No | Out of scope — this phase touches no auth surface |
| V3 Session Management | No | Out of scope |
| V4 Access Control | No | Hook config is server-operator-controlled TOML, same trust boundary as today |
| V5 Input Validation | Yes | Reject negative `time.Duration` timeout values at config-validation time via existing `oops.Code(domain.CodeValidation)` pattern [VERIFIED: internal/config/server.go:370-384] — same validation tier already used for hook `Name`/`Command` |
| V6 Cryptography | No | No crypto surface touched |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Resource exhaustion via an unbounded backlog of pending hook runs under rapid write churn | Denial of Service | Already addressed by design: queue depth 1 with coalescing (CONTEXT.md decision) bounds pending work to exactly one in-flight batch + one pending request, regardless of write RPC rate |
| A hook with `timeout = "876000h"` (no upper cap, per CONTEXT.md) tying up the runner goroutine indefinitely | Denial of Service | CONTEXT.md explicitly accepts this trade-off ("No upper cap... a long-running hook no longer stalls writes") since detachment already isolates the RPC path from hook duration; the *coalescing* mechanism (not a timeout cap) is what prevents backlog growth — a stuck hook simply means the next trigger's request waits as the single `pending` slot until the stuck one finishes or the shutdown drain cancels it |
| Shell command injection via hook env vars (`ROUTER_HOSTS_ERROR`, etc.) | Tampering | Already mitigated, out of scope for this phase — existing sanitization strips CR/LF/NUL [VERIFIED: internal/server/hooks.go:87-91] and is covered by `TestHookExecutor_ErrorMessageSanitization*` [VERIFIED: internal/server/hooks_test.go:135-220]; this phase does not change the env var contract (CONTEXT.md: "the hook environment-variable contract" is explicitly out of scope) |

## Sources

### Primary (HIGH confidence)

- `/burntsushi/toml` (Context7) — "Duration Fields", "Map TOML values to
  time.Duration", "Unmarshal time.Duration from TOML" — confirmed native
  `time.Duration` struct-field decoding in the exact version pinned in
  `go.mod` (v1.6.0)
- Direct source reads (`Read` tool, this session) of: `internal/server/hooks.go`,
  `internal/server/metrics.go`, `internal/server/service.go` (lines 1-230,
  580-599, 840-852), `internal/server/server.go` (lines 1-180),
  `internal/server/writequeue.go`, `internal/config/server.go` (lines 1-100,
  100-400), `internal/client/commands/serve.go`, `go.mod`,
  `internal/server/hooks_test.go`, `internal/server/hooks_wiring_test.go`,
  `internal/server/metrics_test.go`, `internal/server/writequeue_test.go`,
  `internal/config/server_test.go` (partial), `docs/guides/operations.md`
  (lines 1-60), `docs/reference/configuration.md` ([hooks] section),
  `.planning/phases/09-hook-reliability-metrics/09-CONTEXT.md`,
  `.planning/REQUIREMENTS.md`, `.planning/STATE.md`

### Secondary (MEDIUM confidence)

- None required for this phase — no external web claims were needed beyond
  the Context7-sourced TOML library behavior, which is Primary/HIGH.

### Tertiary (LOW confidence)

- None.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — zero new dependencies; all mechanisms verified either
  by direct source read or official docs via Context7
- Architecture: HIGH — the detached-runner shape follows an existing,
  already-reviewed in-repo pattern (`WriteQueue`) with one well-understood
  standard-library modification (coalescing via cap-1 channel), not a novel
  design
- Pitfalls: HIGH — all four documented pitfalls are grounded in either a
  verified source-code quote (zero-value ambiguity, RPC ctx threading, metrics
  constructor-site enumeration) or a well-documented `os/exec`/`context`
  standard-library race (timeout-vs-exit-code classification)

**Research date:** 2026-07-31
**Valid until:** 2026-08-30 (30 days — stable Go stdlib + already-pinned
dependency versions; no fast-moving external API surface in this phase)
