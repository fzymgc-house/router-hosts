---
phase: 09-hook-reliability-metrics
reviewed: 2026-07-31T16:27:58Z
depth: standard
files_reviewed: 11
files_reviewed_list:
  - internal/server/hookrunner.go
  - internal/server/hookrunner_test.go
  - internal/server/hooks.go
  - internal/server/hooks_test.go
  - internal/server/hooks_wiring_test.go
  - internal/server/metrics.go
  - internal/server/metrics_test.go
  - internal/server/service.go
  - internal/config/server.go
  - internal/config/server_test.go
  - internal/client/commands/serve.go
findings:
  critical: 0
  warning: 3
  info: 3
  total: 6
status: issues_found
fixed_at: 2026-07-31T16:45:00Z
fix_status: partial
fixed_count: 4
skipped_count: 2
---

# Phase 09: Code Review Report

**Reviewed:** 2026-07-31T16:27:58Z
**Depth:** standard
**Files Reviewed:** 11
**Status:** issues_found

## Summary

The core conservation-law logic in `hookrunner.go` (Trigger/coalesce/drain) is
correct and well-proven — I traced every interleaving named in the review brief
(lost wakeups, double-counted coalesces, Trigger-vs-Stop races, the
finish-instant window) and could not find a way to lose or double-count a
trigger. I also wrote and ran three adversarial standalone tests against the
actual code (not committed, cleaned up after use) to pressure-test the parts
static reading alone couldn't settle:

1. `Stop()` called before `Start()` — **hangs forever, ignoring the caller's
   context deadline** (proved empirically). See CR-adjacent finding WR-01.
2. `Start()` called twice — **panics with "close of closed channel"** on the
   next `Stop()` (proved empirically). See WR-02.
3. `Stop()` called concurrently from 8 goroutines after a single `Start()` —
   safe, no race, no panic (confirms the documented idempotency claim holds
   for the case it's actually exercised in production).

Neither WR-01 nor WR-02 is reachable through the current production call
graph (`serve.go` always pairs `Start()` immediately after construction and
guards `Stop()` behind the same `hookExec != nil` check), so I classified both
as Warnings rather than Blockers — but they are real, provoked, and violate
the bounded-shutdown guarantee that is the entire point of this phase's
`Stop()` contract ("waits ... up to ctx's deadline"). A future caller (a new
test, a refactor that conditionally skips `Start()`, or a second server
instance sharing a `HookExecutor`) hits either one with no compiler or runtime
warning until it's already hung a shutdown or crashed a process.

Timeout-vs-failure classification, the `ROUTER_HOSTS_ERROR` sanitization, the
timeout config resolution chain (`resolveTimeouts`), the RPC-context isolation
guarantee, and the `serve.go` wiring order (metrics before hook executor) are
all correct and match the phase's locked decisions — verified against the
actual line order and, where feasible, with an empirical probe rather than by
reading alone.

## Warnings

### WR-01: `Stop()` before `Start()` deadlocks forever, ignoring the passed context's deadline

**File:** `internal/server/hookrunner.go:92-110`
**Issue:** `Stop()` unconditionally blocks on `<-r.done`. `r.done` is only ever
closed by `loop()`'s `defer close(r.done)` — and `loop()` only runs if
`Start()` was called. If `Stop(ctx)` is invoked on a `hookRunner` whose
`Start()` was never called, the `select` in `Stop()` will take the
`ctx.Done()` branch, call `r.cancel()` (a no-op here, since nothing is
running), and then block forever on `<-r.done` — the second, unconditional
receive after the deadline branch. The caller's context deadline is
completely ignored; `Stop()` never returns.

I reproduced this directly:

```go
hooks := NewHookExecutor(nil, nil, 5*time.Second, slog.Default())
// Start() deliberately never called
ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
defer cancel()
hooks.Stop(ctx) // never returns — proved with a 2s outer watchdog that fired
```

This is not reachable today because `internal/client/commands/serve.go:145-163`
always pairs `hookExec.Start()` with the `hookExec != nil` guard used for
`Stop()`, and every test that calls `Stop()` also calls `Start()` first. But
`HookExecutor.Start()` / `HookExecutor.Stop()` (`hooks.go:88-99`) are both
exported with no documented precondition tying them together, and `Stop()`'s
own doc comment promises bounded behavior unconditionally ("waits for the
goroutine to fully exit, up to ctx's deadline"). Any future caller —
including a test — that calls `Stop()` without `Start()` hangs indefinitely
(in a test, until the Go test binary's default 10-minute timeout, silently
consuming CI time with no useful signal).

**Fix:** Track whether the loop is actually running and make `Stop()`
short-circuit if it isn't, e.g.:

```go
type hookRunner struct {
    ...
    started bool // set true in Start(), guarded by mu
}

func (r *hookRunner) Start() {
    r.mu.Lock()
    if r.started {
        r.mu.Unlock()
        return
    }
    r.started = true
    r.mu.Unlock()
    go r.loop()
}

func (r *hookRunner) Stop(ctx context.Context) {
    r.mu.Lock()
    if !r.started {
        r.stopped = true
        r.mu.Unlock()
        r.cancel()
        return
    }
    if !r.stopped {
        r.stopped = true
        close(r.quit)
    }
    r.mu.Unlock()
    ...
}
```

### WR-02: `Start()` is not idempotent — a second call causes a panic on the next `Stop()`

**File:** `internal/server/hookrunner.go:52-55`
**Issue:** `Start()` unconditionally launches a new `go r.loop()` with no guard
against being called more than once. Two concurrently running `loop()`
goroutines both observe the same `r.quit` close (channel close broadcasts to
all receivers), both call `runPending()` (safe — mutex-protected), and both
then `return`, each running its own `defer close(r.done)`. The second `close`
on an already-closed channel panics.

Reproduced directly:

```go
hooks := NewHookExecutor(nil, nil, 5*time.Second, slog.Default())
hooks.Start()
hooks.Start() // second call — no guard
hooks.Stop(context.Background())
// panic: close of closed channel
//   at hookrunner.go:125 (loop) via hookrunner.go:54 (Start's second goroutine)
```

Same reachability caveat as WR-01: `serve.go` calls `Start()` exactly once
per `HookExecutor`, so this isn't hit today. But nothing in the type prevents
it, and the fix in WR-01 (a `started` guard under `mu`) also closes this gap
for free — implement them together.

**Fix:** Same `started`-flag guard shown in WR-01 makes `Start()` a safe
no-op on a second call.

### WR-03: `serve.go`'s hook-executor wiring order has no regression test

**File:** `internal/client/commands/serve.go:112-163`
**Issue:** The bug this phase fixes for HOOK-01 (`WithMetrics` receiving
`DisabledMetrics()` forever because the hook executor was constructed before
metrics existed) was a pure ordering bug in `runServe()`. The fix — moving
hook-executor construction after the metrics block and passing
`server.WithMetrics(metrics)` — is correct today (verified by reading the
actual line order: metrics block at `serve.go:119-140`, hook executor block
at `serve.go:145-155`). But `serve_test.go` only tests flag parsing
(`TestNewServeCmd_Exists`, `_HasConfigFlag`, `_ConfigFlagRequired`,
`_RegisteredInRoot`); `runServe()` itself is never exercised by a unit test,
and no e2e test under `e2e/` references hooks at all (`rg -rl hook e2e/`
returns nothing). Nothing in CI would catch a regression where a future edit
reorders these two blocks back to the pre-fix order — the exact defect this
phase exists to close would silently return.

**Fix:** Add a narrow regression test — either a unit test that extracts the
wiring logic into a testable helper (e.g. a function taking `*config.Config`
and returning the constructed `*server.HookExecutor` plus which `*Metrics` it
was built with), or an e2e test that configures both `[metrics.otel]` and a
hook, then asserts the hook's execution actually produces an OTel counter
datapoint through the real `serve` path.

## Info

### IN-01: `NewHookExecutor` silently produces a zero-timeout (always-expired) hook if given a non-positive `defaultTimeout`

**File:** `internal/server/hooks.go:58-73`
**Issue:** `NewHookExecutor`'s own per-hook default-resolution (`if
resolvedSuccess[i].Timeout == 0 { ... = defaultTimeout }`) does not validate
that `defaultTimeout > 0`. If called with `defaultTimeout <= 0` (e.g., a
future caller that doesn't route through `config.LoadServerConfig`, which is
the only place that currently enforces positivity via `resolveTimeouts()`),
any hook whose own `Timeout` is zero keeps `Timeout == 0` forever, and
`context.WithTimeout(ctx, 0)` in `executeHook` (`hooks.go:171`) produces an
already-expired context — every such hook would be classified `timeout` on
its very first run. Not reachable via the current production path (`serve.go`
always passes the already-`resolveTimeouts()`-validated
`cfg.Hooks.DefaultTimeout`), but the constructor's own doc comment
("Idiomatic ... self-documenting") makes no mention of this precondition,
and duplicating `config.HooksConfig.resolveTimeouts()`'s defaulting logic
here (rather than requiring already-resolved input) invites drift between
the two copies.
**Fix:** Either document the precondition explicitly (`defaultTimeout must be
> 0; callers not going through config.LoadServerConfig must validate this
themselves`) or add a defensive `if defaultTimeout <= 0 { defaultTimeout =
config.DefaultHookTimeout }` fallback so the constructor can never produce a
guaranteed-to-timeout hook.

### IN-02: A hook killed by `Stop`'s shutdown-cancel is recorded as `status="failure"`, indistinguishable from a genuine hook bug

**File:** `internal/server/hooks.go:194-202`
**Issue:** Confirmed empirically: when `Stop(ctx)`'s deadline expires while a
hook is still running and the base context is cancelled to kill it, the
classifier (`errors.Is(hookCtx.Err(), context.DeadlineExceeded)`) does _not_
match, because `hookCtx.Err()` propagates the parent's cancellation cause
(`context.Canceled`), not `DeadlineExceeded` — so the outcome falls through
to `status="failure"`. This is the closest available value given the
decisions doc's fixed `{success, failure, timeout}` enum, and it correctly
avoids mislabeling a shutdown-kill as a per-hook `timeout` (which would be
actively misleading — the hook's own budget was never exhausted). But it
means every rolling restart that catches a hook mid-run will emit a
`hook_executions_total{status="failure"}` datapoint that looks identical to
a real hook bug, which could produce false-positive alerts correlated with
deploys.
**Fix:** No code change required if this tradeoff is accepted (it's a
reasonable one within the locked 3-value status enum) — but worth a one-line
callout in `docs/guides/operations.md`'s hooks section: "a hook interrupted by
server shutdown is recorded as `status=failure`, not a distinct outcome;
expect a `failure` blip correlated with deploys that use `hookExec.Stop`."

### IN-03: Several metadata commits use plan-ID scopes instead of domain scopes

**File:** git history, `feat/hook-reliability-metrics` branch
**Issue:** Per `CLAUDE.md`, commit scopes should be domain scopes
(`proto`, `server`, `client`, `storage`, `validation`, `config`, `ci`, `deps`,
`docs`, `operator`, `acme`, `e2e`). Several commits on this branch use a plan
ID as the scope instead, e.g. `docs(09-04): complete hook runner coalescing
and shutdown plan`, `docs(09-02): complete hook timeout configuration chain
plan`, and multiple `docs(09): ...` commits during the discuss/research
phase. `docs` is itself a valid domain scope — these should have been
`docs(docs): ...` or simply omitted the plan ID from the scope position.
**Fix:** None required — per review instructions, history must not be
rewritten to fix this. Noted for awareness only.

---

## Fix Disposition

Applied by the gsd-code-fixer agent against branch `feat/hook-reliability-metrics`
in an isolated worktree, fast-forwarded back after `task ci` passed
(lint + buf lint/format + manifests + full `go test -race ./...`, coverage
85.8% repo-wide, holding the ≥80% gate).

### WR-01: `Stop()` before `Start()` deadlocks forever — **fixed**

**Commit:** `9029a5a` — `fix(server): make hookRunner Start/Stop safe out of order`
**Files:** `internal/server/hookrunner.go`, `internal/server/hookrunner_test.go`

Added a `started bool` field guarded by `hookRunner.mu`. `Stop()` now checks
`!r.started` first and returns immediately (after marking `stopped` and
calling `r.cancel()`) instead of blocking on `<-r.done`, which nothing would
ever close. Regression test `TestHookRunner_StopBeforeStartReturnsPromptly`
calls `Stop()` with a 200ms-deadline context on a never-started runner from a
goroutine and asserts it returns within a 2s watchdog.

### WR-02: `Start()` not idempotent — second call panics on next `Stop()` — **fixed**

**Commit:** `9029a5a` (same commit as WR-01 — the `started` guard fixes both)
**Files:** `internal/server/hookrunner.go`, `internal/server/hookrunner_test.go`

`Start()` now short-circuits to a no-op if `r.started` is already true,
preventing a second `loop()` goroutine from racing the first to
`close(r.done)`. Regression test `TestHookRunner_StartIsIdempotent` calls
`Start()` twice then `Stop()` and asserts no panic.

### WR-03: no regression coverage for the HOOK-01 wiring-order fix — **fixed**

**Commits:** `b44c3a0` — `test(client): guard HOOK-01 metrics-before-hooks wiring order`,
followed by `3362aaa` — `fix(client): satisfy prealloc lint in runServe wiring`
**Files:** `internal/client/commands/serve.go`, `internal/client/commands/serve_wiring.go` (new),
`internal/client/commands/serve_wiring_test.go` (new), `internal/server/hooks.go`,
`internal/server/metrics.go`

Took the review's preferred behavioral-test path, not the source-order-assertion
fallback. Extracted the metrics + hook-executor construction out of `runServe`
into `configureMetricsAndHooks(cfg, store, logger) (hooksAndMetrics, error)` in
a new `serve_wiring.go`, preserving the exact statement order and defer/cleanup
semantics (cleanup closures are collected and returned for the caller to defer,
running in the same LIFO order as before). Added a minimal, purpose-built
`HookExecutor.MetricsEnabled() bool` accessor (backed by an unexported
`Metrics.enabled()` check on `meterProvider != nil`) so the constructed
executor's actual metrics state is observable from the `commands` package.

`TestConfigureMetricsAndHooks_HookExecutorGetsRealMetrics` builds a real
(non-disabled) `*server.Metrics` via the same `NewMetricsFromConfig` OTel path
`serve.go` uses in production, and asserts the resulting `HookExecutor`'s
`MetricsEnabled()` is `true`. If a future edit reorders the hook-executor
block back above the metrics block _inside_ `configureMetricsAndHooks`, this
assertion flips to `false` and the test fails — reproducing exactly the
silent regression the review flagged as uncaught. Companion tests cover the
OTel-unconfigured case (`MetricsEnabled() == false`, matching the documented
`WithMetrics(nil)`-is-a-no-op contract) and the no-hooks-configured case
(`hookExec == nil`).

The `3362aaa` follow-up commit fixes a `prealloc` lint finding
(`golangci-lint`) surfaced by `task ci` against the extracted wiring — no
behavior change.

### IN-01: `NewHookExecutor` silently produces a zero-timeout hook — **fixed**

**Commit:** `340c22b` — `fix(server): fall back on non-positive NewHookExecutor defaultTimeout`
**Files:** `internal/server/hooks.go`, `internal/server/hooks_test.go`

Added a guard at the top of `NewHookExecutor`: `if defaultTimeout <= 0 { defaultTimeout = config.DefaultHookTimeout }`,
matching the positivity `config.LoadServerConfig`'s `resolveTimeouts()` already
enforces on the production path. Regression test
`TestNewHookExecutor_NonPositiveDefaultTimeoutFallsBack` constructs an executor
with `defaultTimeout = 0` and an unset-`Timeout` hook, asserts the resolved
timeout falls back to `config.DefaultHookTimeout`, then runs the hook and
asserts it records `status="success"` rather than `status="timeout"`.

### IN-02: shutdown-killed hooks recorded as `status="failure"` — **skipped (consciously)**

Per fix-task instructions: this is a documented, defensible tradeoff, not a
code defect. Distinguishing a shutdown-cancel from a genuine per-hook
deadline-exceeded would require a design change to the classifier (currently
`errors.Is(hookCtx.Err(), context.DeadlineExceeded)` against the fixed
`{success, failure, timeout}` status enum) — out of scope for a fix pass. No
code change applied; the review's suggested documentation callout in
`docs/guides/operations.md` was likewise not applied in this pass and remains
open for a future phase or doc update.

### IN-03: plan-ID commit scopes on three metadata commits — **skipped (out of scope)**

Per fix-task instructions and the review's own **Fix:** entry: history must
not be rewritten. No action taken; noted for awareness only.

---

_Reviewed: 2026-07-31T16:27:58Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
_Fixed: 2026-07-31T16:45:00Z_
_Fixer: Claude (gsd-code-fixer)_
