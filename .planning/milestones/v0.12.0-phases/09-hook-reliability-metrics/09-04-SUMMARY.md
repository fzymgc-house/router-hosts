---
phase: 09-hook-reliability-metrics
plan: 04
subsystem: api
tags: [go, concurrency, otel-metrics, hooks, testing]

requires:
  - phase: 09-hook-reliability-metrics (Plan 01)
    provides: "hookRunner coalescing background runner with server-lifecycle context, Trigger/Stop/loop skeleton"
  - phase: 09-hook-reliability-metrics (Plan 03)
    provides: "Metrics.RecordHookRunCoalesced / router_hosts_hook_runs_coalesced_total instrument"
provides:
  - "hookRunner.Trigger records router_hosts_hook_runs_coalesced_total exactly once per superseded request, using context.Background() so the metric lands even after the base context is cancelled"
  - "hookRunner.Trigger rejects post-Stop calls under the stopped flag, closing a latent phantom-coalesce bug where a second post-Stop Trigger would otherwise find a never-drained pending request"
  - "hookRunner.Stop releases the base context unconditionally (idempotent r.cancel()) on the normal in-deadline path, not only the deadline-expired path"
  - "Nine new hookrunner_test.go tests proving conservation, latest-wins, bounded drain, deadline-cancel, post-Stop no-op, Stop idempotency, and in-batch declaration order — plus a documented finish-instant BACKSTOP"
affects: [09-05-hook-reliability-metrics]

actuals:
  tokens: 4012
  tasks: 3
  commits: 5

tech-stack:
  added: []
  patterns:
    - "blockingRunsLogHook / blockingStartedSentinelHook filesystem-sentinel hook generators, extending Plan 09-01's blockingSentinelHook technique to also record which payloads ran and in what order via a shared t.TempDir() log file"
    - "waitForFile poll helper — bounded existence poll crossing the Go/subprocess boundary, never a timing assertion"

key-files:
  created: []
  modified:
    - internal/server/hookrunner.go
    - internal/server/hookrunner_test.go

key-decisions:
  - "RecordHookRunCoalesced is called with the incoming (superseding) request's event, not the dropped request's event, matching the plan's literal action text (`req.event` is the Trigger parameter, i.e. the new request) — since the coalesced counter's `type` attribute has no per-request identity anyway (09-03 decision), this only matters when on_success/on_failure hooks could coalesce against each other, which they cannot: Trigger is always called with the caller's own event type."
  - "Verified Task 2's core shutdown behavior (drain in-flight, drain pending, deadline-cancel, idempotent Stop) was already correctly implemented by Plan 09-01 — all five Task 2 tests passed against the pre-Task-2 tree with zero behavior change needed. Recorded as already-satisfied per the plan's upstream_state guidance rather than rewritten."
  - "Still added the plan's mandated stopped-flag check in Trigger and the unconditional post-select r.cancel() in Stop, even though the existing single-call TriggerAfterStopIsNoOp test already passed without them — both are explicit source-level acceptance criteria in the plan, and the stopped-flag check closes a real latent bug: without it, a *second* post-Stop Trigger call finds the never-drained `pending` from the first non-nil and records a phantom coalesce despite nothing having actually been superseded."

patterns-established:
  - "Ordering-property test shape (TestHookRunner_SupersededNeverRunsAfterSuperseder) — assert a superseded payload is NotContains anywhere in the log, not just absent-in-position, distinguishing a true ordering guarantee from a coincidental count match."

requirements-completed: [HOOK-02]

coverage:
  - id: D1
    description: "Pending work is bounded at one; every superseded Trigger increments router_hosts_hook_runs_coalesced_total exactly once and never executes; conservation (executed + coalesced == triggered) holds deterministically and under 50 concurrent triggers with the race detector on"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_CoalescesSupersededRuns"
        status: pass
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_ConcurrentTriggersConserve"
        status: pass
    human_judgment: false
  - id: D2
    description: "Stop(ctx) with no deadline drains both the in-flight batch and the single pending request before returning"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_StopDrainsInFlightBatch"
        status: pass
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_StopDrainsPendingRequest"
        status: pass
    human_judgment: false
  - id: D3
    description: "Stop(ctx) whose deadline expires while a hook is still running returns anyway, having cancelled the base context and killed the hook subprocess"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_StopDrainsThenCancels"
        status: pass
    human_judgment: false
  - id: D4
    description: "Trigger after Stop is a no-op (no panic, no execution, no coalesce recorded); Stop is idempotent"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_TriggerAfterStopIsNoOp"
        status: pass
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_StopIsIdempotent"
        status: pass
    human_judgment: false
  - id: D5
    description: "Hooks within one batch run in declaration order through the detached runner; a superseded request's payload never appears in the runs-log at any position (latest-wins as an ordering property, not just a count)"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_BatchOrderIsDeclarationOrder"
        status: pass
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_SupersededNeverRunsAfterSuperseder"
        status: pass
    human_judgment: false

duration: ~6min (3 task waves, 5 commits, single session)
completed: 2026-07-31
status: complete
---

# Phase 9 Plan 04: Hook Runner Coalescing, Conservation, and Bounded Shutdown Summary

**`hookRunner.Trigger` now counts every superseded request on `router_hosts_hook_runs_coalesced_total`, rejects post-`Stop` calls, and nine new tests prove the conservation law, bounded drain-then-cancel shutdown, and in-batch declaration order — with Plan 09-01's existing shutdown implementation verified correct rather than rewritten.**

## Performance

- **Duration:** ~6 min across 5 commits (test→feat pairs for Tasks 1 and 2, a single test commit for Task 3), single uninterrupted session.
- **Tasks:** 3/3 completed, no checkpoints.
- **Files modified:** 2 (`internal/server/hookrunner.go`, `internal/server/hookrunner_test.go`).

## Accomplishments

- **Coalesce accounting closes the phase's only high-severity threat (T-09-02).** `Trigger` now captures whether a request was already pending before overwriting it and, when so, calls `RecordHookRunCoalesced(context.Background(), req.event)` exactly once — using `context.Background()` deliberately, since a metric record must still land during shutdown after the base context is cancelled. Verified by `rg -n 'RecordHookRunCoalesced'` showing exactly one call site, inside `Trigger`.
- **Conservation law proven deterministically and under concurrency.** `TestHookRunner_CoalescesSupersededRuns` proves `executed(2) + coalesced(1) == triggered(3)` with an exact ordering assertion (payload `2` never runs). `TestHookRunner_ConcurrentTriggersConserve` fires 50 concurrent `Trigger` calls under `-race` and proves `executed + coalesced == 50` regardless of goroutine-scheduling interleaving.
- **Plan 09-01's bounded-shutdown implementation verified correct, not rewritten.** All five Task 2 behavior tests (`StopDrainsInFlightBatch`, `StopDrainsPendingRequest`, `StopDrainsThenCancels`, `TriggerAfterStopIsNoOp`, `StopIsIdempotent`) passed against the pre-existing `Stop`/`loop` implementation with zero behavior change required — the mutex-guarded `stopped` flag, `close(quit)`, drain-then-return quit branch, and deadline-triggered `r.cancel()` were already correct.
- **Closed a latent phantom-coalesce bug anyway.** Added the plan's mandated `stopped`-flag check to `Trigger` (a hard source-level acceptance criterion) even though the existing single-call test already passed without it: without the check, a *second* post-`Stop` `Trigger` would find the first call's never-drained `pending` request still non-nil and incorrectly record a coalesce despite nothing having actually been superseded. Also added an unconditional `r.cancel()` after `Stop`'s select so the base context is released on the normal in-deadline path too (idempotent, per Go's `context.CancelFunc` contract), not only the deadline-expired path.
- **Batch order and latest-wins proven as properties, not just counts.** `TestHookRunner_BatchOrderIsDeclarationOrder` proves three hooks in one batch append their names in declaration order through the detached runner. `TestHookRunner_SupersededNeverRunsAfterSuperseder` asserts a superseded payload is absent from the runs-log at *any* position, distinguishing a true ordering guarantee from a coincidental count match.
- **Finish-instant BACKSTOP documented, not silently omitted.** A file-level comment in `hookrunner_test.go` records that the precise interleaving of a `Trigger` racing a batch's completion at the exact finish instant is not reproducible on demand and is covered by argument (the shared mutex totally orders pending-overwrite against pending-take) rather than a targeted test — naming the two tests that sample the conservation law instead.

## Task Commits

Each task was committed atomically as test→feat pairs (TDD):

1. **Task 1: Instrument coalescing and prove the conservation law**
   - RED: `843fdf3` (test) — `TestHookRunner_CoalescesSupersededRuns`, `TestHookRunner_ConcurrentTriggersConserve`, confirmed failing (coalesced counter was zero)
   - GREEN: `b46f56d` (feat) — coalesce detection + `RecordHookRunCoalesced` call in `Trigger`
2. **Task 2: Bounded shutdown — drain the pending batch, then cancel**
   - Tests: `56320b8` (test) — all five tests locked in behavior already correct in the upstream tree
   - Source-criteria fixes: `c5b9d1a` (feat) — `stopped`-flag check in `Trigger`; unconditional `r.cancel()` in `Stop`
3. **Task 3: Prove batch ordering through the runner and record the finish-instant backstop**
   - `c7eefd5` (test) — pure test additions plus the BACKSTOP documentation comment, no production change (as the plan anticipated)

## Files Created/Modified

- `internal/server/hookrunner.go` — `Trigger` gained coalesce detection + metric recording + a stopped-flag early return; `Stop` gained an unconditional post-select `r.cancel()`.
- `internal/server/hookrunner_test.go` — nine new tests (`TestHookRunner_CoalescesSupersededRuns`, `_ConcurrentTriggersConserve`, `_StopDrainsInFlightBatch`, `_StopDrainsPendingRequest`, `_StopDrainsThenCancels`, `_TriggerAfterStopIsNoOp`, `_StopIsIdempotent`, `_BatchOrderIsDeclarationOrder`, `_SupersededNeverRunsAfterSuperseder`); two new hook-command generators (`blockingRunsLogHook`, `blockingStartedSentinelHook`); the `waitForFile` poll helper; a file-level BACKSTOP documentation comment.

## Decisions Made

- `RecordHookRunCoalesced` records the incoming (superseding) request's `event`, per the plan's literal action text — matches since `on_success`/`on_failure` triggers never coalesce against each other in practice (each `Trigger*` method always supplies its own event type).
- Task 2's core shutdown semantics were verified as already-correct upstream work rather than rewritten, per the plan's `<upstream_state>` guidance — but the two source-level acceptance criteria (stopped-flag check, unconditional cancel) were still applied because they are explicit plan requirements and the stopped-flag check closes a real (if untested-by-the-plan's-own-spec) phantom-coalesce bug on repeated post-Stop triggers.

## Deviations from Plan

None — plan executed exactly as written. The Task 2 source-level changes (stopped-flag check, unconditional `r.cancel()`) were explicitly directed by the plan's own action text and acceptance criteria, not an unplanned addition; they are documented above under Decisions Made because the pre-existing behavior already passed the plan's own five Task 2 tests, which is worth calling out explicitly rather than silently.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `hookRunner`'s coalescing, conservation, and bounded-shutdown behavior is now fully instrumented and tested: `router_hosts_hook_runs_coalesced_total` has a real call site, the conservation law holds deterministically and under 50-way concurrency with `-race`, and `Stop` always terminates (draining in-flight/pending work within the caller's deadline, cancelling the base context past it).
- `task test ./internal/server/...` is green under `-race` with no race-detector report; `task lint` is 0 issues; `task test:coverage:ci` reports `internal/server` at 88.4% and repo-wide at 85.3%, both above the 80% floor.
- `.planning/phases/09-hook-reliability-metrics/09-VALIDATION.md` rows 09-04-T1/T2/T3 flipped to ✅ green with evidence.
- The phase's only `high`-severity threat (T-09-02, unbounded pending-work growth) is now fully mitigated and verified — queue depth stays exactly one (capacity-1 `trigger` channel, single `pending *hookRunRequest` field, confirmed via `rg`), and `router_hosts_hook_executions_total` is never incremented for a coalesced (never-executed) run.
- No blockers for Plan 09-05 (documentation).

---

*Phase: 09-hook-reliability-metrics*
*Completed: 2026-07-31*

## Self-Check: PASSED

All 2 modified files and 5 task commit hashes verified present via `git log --oneline --all` and filesystem checks.
