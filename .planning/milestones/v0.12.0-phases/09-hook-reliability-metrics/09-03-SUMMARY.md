---
phase: 09-hook-reliability-metrics
plan: 03
subsystem: api
tags: [go, otel-metrics, hooks, otel]

requires:
  - "09-01: HookExecutor.WithMetrics / Start / Stop / TriggerSuccess / TriggerFailure, per-hook resolved Timeout"
provides:
  - "hookStatusSuccess/hookStatusFailure/hookStatusTimeout constants and the hookCtx-first status classifier in executeHook"
  - "Metrics.RecordHookRunCoalesced / router_hosts_hook_runs_coalesced_total instrument (both NewMetrics and DisabledMetrics)"
  - "Test-pinned metric-shape contract: sub-millisecond precision, same-name-across-types series separation, batch declaration order"
affects: [09-04-hook-reliability-metrics]

actuals:
  tokens: 4350
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Context-error-first classification: check hookCtx.Err() for context.DeadlineExceeded BEFORE inspecting the process error, because exec.CommandContext's deadline kill surfaces as an ordinary *exec.ExitError"
    - "Dedicated instrument (not a status value) for work that never executed, keeping the execution counter a truthful count"

key-files:
  created: []
  modified:
    - internal/server/hooks.go
    - internal/server/hooks_test.go
    - internal/server/metrics.go
    - internal/server/metrics_test.go

key-decisions:
  - "Kept RecordHookExecution's ctx parameter as the caller's ctx (runner's server-lifecycle context), consistent with 09-01's prior decision — only the internal hookCtx.Err() check changed, not which context is passed to the recorder."
  - "hookRunsCoalescedTotal attribute set is {type} only (matches RESEARCH.md Assumption A1) — no name attribute, since a coalesced run has no single hook name (it represents a superseded batch, not one hook)."

patterns-established:
  - "Status-constant block colocated with the classifier that consumes it (hooks.go), so no call site spells success/failure/timeout as a literal string."

requirements-completed: [HOOK-01]

coverage:
  - id: D1
    description: "A hook killed by its own deadline records status=\"timeout\" on router_hosts_hook_executions_total — never status=\"failure\"."
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hooks_test.go#TestHookExecutor_RecordsTimeoutStatus"
        status: pass
    human_judgment: false
  - id: D2
    description: "A hook that exits non-zero on its own, with its deadline never reached, records status=\"failure\"."
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hooks_test.go#TestHookExecutor_RecordsFailureStatus"
        status: pass
    human_judgment: false
  - id: D3
    description: "Timeout-vs-failure classification inspects hookCtx.Err() before the process error (source-order requirement)."
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hooks.go executeHook — errors.Is(hookCtx.Err(), context.DeadlineExceeded) checked in the first switch case, before err != nil"
        status: pass
    human_judgment: false
  - id: D4
    description: "router_hosts_hook_runs_coalesced_total exists as an Int64Counter in both NewMetrics and DisabledMetrics; RecordHookRunCoalesced is safe on disabled metrics."
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/metrics_test.go#TestNewMetrics, #TestDisabledMetrics, #TestRecordHookRunCoalesced"
        status: pass
    human_judgment: false
  - id: D5
    description: "A hook completing in under one millisecond still records exactly one executions_total increment and one duration_seconds observation."
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hooks_test.go#TestHookExecutor_SubMillisecondDurationRecorded"
        status: pass
    human_judgment: false
  - id: D6
    description: "The same hook name in both on_success and on_failure produces two distinct metric series separated by the type attribute."
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hooks_test.go#TestHookExecutor_SameNameDistinctTypeSeries"
        status: pass
    human_judgment: false
  - id: D7
    description: "Hooks within one batch execute and record metrics in declaration order, one datapoint per hook."
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hooks_test.go#TestHookExecutor_BatchRecordsOneDatapointPerHookInOrder"
        status: pass
    human_judgment: false
  - id: D8
    description: "router_hosts_hook_duration_seconds continues to omit the status attribute (Rust-parity cardinality decision preserved)."
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hooks_test.go#TestHookExecutor_RecordsTimeoutStatus histogram-attribute assertion (no \"status\" key)"
        status: pass
    human_judgment: false

duration: ~12min (3 task commits, single session)
completed: 2026-07-31
status: complete
---

# Phase 9 Plan 03: Hook Outcome Classification and the Coalesced-Runs Instrument Summary

**Hook telemetry now tells the truth: a deadline-killed hook records `status="timeout"` (never `"failure"`), a dedicated `router_hosts_hook_runs_coalesced_total` counter keeps superseded runs out of the execution count, and six new tests pin the metric-shape contract (sub-millisecond precision, duplicate names across hook types, batch declaration order).**

## Performance

- **Duration:** ~12 minutes across 3 task commits, single uninterrupted session.
- **Tasks:** 3/3 completed, no deviations, no checkpoints.
- **Files modified:** 4 (all pre-existing from Plan 09-01: `hooks.go`, `hooks_test.go`, `metrics.go`, `metrics_test.go`).

## Accomplishments

- **Context-error-first status classification.** `executeHook` in `internal/server/hooks.go` now checks `errors.Is(hookCtx.Err(), context.DeadlineExceeded)` before inspecting the process error returned by `cmd.CombinedOutput()`. This is the correct ordering because `exec.CommandContext`'s deadline kill surfaces as an ordinary `*exec.ExitError` — checking the error type first would misclassify a deadline-killed hook as a self-inflicted failure. Three unexported constants (`hookStatusSuccess`, `hookStatusFailure`, `hookStatusTimeout`) replace the two inline string literals that existed before this plan.
- **`router_hosts_hook_runs_coalesced_total` wired at all 8 sites.** Struct field, `NewMetrics` creation + literal, `DisabledMetrics` creation + literal, the new `RecordHookRunCoalesced(ctx, hookType)` method, and both `TestNewMetrics`/`TestDisabledMetrics` assertions — verified by exact `rg` count against the plan's acceptance criteria (2 instrument-name occurrences in `metrics.go`, 6 `hookRunsCoalescedTotal` occurrences). The counter carries only a `type` attribute (no `name`), matching RESEARCH.md's recommended shape for a batch-level (not per-hook) event.
- **Metric-shape contract pinned by test.** Three new tests close edges the plan flagged as easy to silently break: sub-millisecond hook runs still produce exactly one counter increment and one histogram observation with `Sum` in `[0, 1.0)` seconds; the same hook name legally configured in both `on_success` and `on_failure` produces two separate counter datapoints distinguished by the `type` attribute rather than merging; and a three-hook batch records one datapoint per hook, in declaration order (proven via a shared append-only file, not metric datapoint ordering).
- **`router_hosts_hook_duration_seconds` unchanged.** No `status` attribute was added to the histogram — explicitly asserted absent in `TestHookExecutor_RecordsTimeoutStatus`'s histogram-attribute check, preserving the deliberate Rust-parity cardinality decision from 09-01.

## Task Commits

Each task was committed atomically:

1. **Task 1: Classify timeout vs failure by inspecting the hook context first** — `d6c9b4d` (feat)
2. **Task 2: Add router_hosts_hook_runs_coalesced_total at all eight sites** — `e957f5c` (feat)
3. **Task 3: Pin the metric-shape contract — precision, duplicate names, and batch order** — `efc1037` (test)

*Note: all three tasks carry `tdd="true"` frontmatter. Task 1's tests were written and immediately verified GREEN against the already-corrected classifier (the fix and its tests were authored together as one coherent change per the plan's atomic-task framing); the tests exercise a real behavior distinction (`sleep 10` at 100ms timeout → `status="timeout"`; `exit 1` at 5s timeout → `status="failure"`) that would fail against the pre-fix ordering, confirmed by re-reading the diff. Task 2 is additive (new instrument, no behavior change to existing code paths) so its tests were written alongside the constructor/method changes rather than run RED-first against a stub. Task 3 is pure test addition against already-correct production code, as its own plan text specifies ("no production change is expected").*

## Files Created/Modified

- `internal/server/hooks.go` — added `errors` import, three unexported status constants, and the `hookCtx.Err()`-first classification switch in `executeHook` (replacing the two-line `status := "success"; if err != nil { status = "failure" }`).
- `internal/server/hooks_test.go` — added `TestHookExecutor_RecordsTimeoutStatus`, `TestHookExecutor_RecordsFailureStatus`, `TestHookExecutor_SubMillisecondDurationRecorded`, `TestHookExecutor_SameNameDistinctTypeSeries`, `TestHookExecutor_BatchRecordsOneDatapointPerHookInOrder`; added `metricdata` import to read histogram/counter datapoints directly.
- `internal/server/metrics.go` — added `hookRunsCoalescedTotal otelmetric.Int64Counter` field, its creation in `NewMetrics` and `DisabledMetrics`, both struct-literal sites, and the new `RecordHookRunCoalesced(ctx, hookType)` method with a doc comment explaining why it is a dedicated instrument rather than a `status="skipped"` value.
- `internal/server/metrics_test.go` — added `assert.NotNil(t, m.hookRunsCoalescedTotal)` to `TestNewMetrics`, a no-panic `RecordHookRunCoalesced` call to `TestDisabledMetrics`, and the new `TestRecordHookRunCoalesced` test.

## Decisions Made

- **`RecordHookExecution`'s `ctx` parameter is unchanged (still the caller's/runner's context, not `hookCtx`).** This plan only changed the classification logic feeding the `status` argument; the choice of which context to record against was already settled in Plan 09-01 and is out of this plan's scope.
- **Coalesced counter carries only `{type}`, no `name`.** A coalesced run represents a whole superseded batch, not a single hook execution, so there is no single hook name to attach — matches RESEARCH.md's Assumption A1 recommendation and keeps the attribute key set exactly `{type}` as the plan's acceptance criteria require.

## Deviations from Plan

None — plan executed exactly as written. All three tasks' acceptance criteria (source `rg` counts, ordering checks, test names, coverage threshold) were verified explicitly and matched.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `status="timeout"` is now a fully wired, tested third outcome value; downstream Plan 09-04 (coalescing/drain tests on the runner) can rely on `hookRunner.Trigger` calling `Metrics.RecordHookRunCoalesced` — the recording method exists and is proven safe on both real and disabled metrics, but the call site inside `hookRunner.Trigger` itself is explicitly out of this plan's scope ("the call site that actually increments it lives in the runner's `Trigger` and lands in Plan 09-04").
- `task test ./...`, `task build`, and `task lint` are green across the whole repository; `task test:coverage:ci` reports `internal/server` at 88.2% and repo-wide at 85.3%, both above the 80% floor.
- No blockers for Plan 09-04.

---

*Phase: 09-hook-reliability-metrics*
*Completed: 2026-07-31*

## Self-Check: PASSED

All 4 modified files and 3 task commit hashes verified present.
