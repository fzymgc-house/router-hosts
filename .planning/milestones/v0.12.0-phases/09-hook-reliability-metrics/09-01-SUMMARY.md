---
phase: 09-hook-reliability-metrics
plan: 01
subsystem: api
tags: [go, grpc, otel-metrics, concurrency, toml]

requires: []
provides:
  - "hookRunner: coalescing (queue depth 1) background runner with server-lifecycle context, mirroring WriteQueue's quit/done lifecycle"
  - "HookExecutor.WithMetrics/Start/Stop/TriggerSuccess/TriggerFailure — the async surface later plans (09-02..09-05) build on"
  - "config.HookDefinition.Timeout + config.DefaultHookTimeout — per-hook timeout resolved once at config load"
  - "router_hosts_hook_executions_total / _duration_seconds now have a real caller (HOOK-01 closed for the success/failure path)"
affects: [09-02-hook-reliability-metrics, 09-03-hook-reliability-metrics, 09-04-hook-reliability-metrics]

actuals:
  tokens: 6468
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Coalescing trigger channel (capacity-1 + non-blocking send) for queue-depth-1 latest-wins background work"
    - "Server-lifecycle context.WithCancel(context.Background()) owned by a background runner, never derived from an RPC context"
    - "Functional-option HookExecutorOption / WithMetrics defaulting to DisabledMetrics(), matching the existing ServiceOption pattern"

key-files:
  created:
    - internal/server/hookrunner.go
    - internal/server/hookrunner_test.go
  modified:
    - internal/config/server.go
    - internal/server/hooks.go
    - internal/server/service.go
    - internal/server/hooks_wiring_test.go
    - internal/server/hooks_test.go
    - internal/client/commands/serve.go

key-decisions:
  - "Added HooksConfig.DefaultTimeout now (ahead of its documented 09-02 TOML wiring) because serve.go must already compile against cfg.Hooks.DefaultTimeout — the field carries no TOML/validation logic yet, only the struct slot."
  - "executeHook records the metric using the caller's ctx (the runner's base context), not the per-hook hookCtx that may already be Done() from a timeout — RESEARCH.md's runnerCtx recommendation."
  - "hookRunner.loop drains its single pending request on both the trigger and quit select branches identically, so Stop() is deterministic regardless of which branch the scheduler picks."

patterns-established:
  - "Filesystem-sentinel ordering test technique (poll-for-file hook body + t.TempDir()) for proving async-write-path detachment without wall-clock comparison — reusable by 09-04's coalescing/drain tests."

requirements-completed: [HOOK-01, HOOK-02]

coverage:
  - id: D1
    description: "regenerateOutputs returns before a triggered hook completes (write path detached from hook execution)"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestRegenerateOutputs_DetachesFromHooks"
        status: pass
    human_judgment: false
  - id: D2
    description: "Every hook execution records router_hosts_hook_executions_total and router_hosts_hook_duration_seconds with name/type/status attributes"
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookExecutor_RecordsSuccessMetric"
        status: pass
    human_judgment: false
  - id: D3
    description: "Each hook's timeout is resolved once at construction from its own config value or the constructor's defaultTimeout — no run-time global default lookup"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookExecutor_ResolvesPerHookTimeout"
        status: pass
    human_judgment: false
  - id: D4
    description: "Hook execution derives its context from the runner's server-lifecycle context; cancelling the RPC context does not kill an already-detached hook"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestHookRunner_SurvivesRPCContextCancellation"
        status: pass
    human_judgment: false
  - id: D5
    description: "A service with no hook executor emits zero hook metric datapoints (no-op, not a zero-valued point)"
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hookrunner_test.go#TestRegenerateOutputs_NoHooksEmitsNoMetrics"
        status: pass
    human_judgment: false
  - id: D6
    description: "NewHookExecutor without WithMetrics, and with WithMetrics(nil), both hold a non-nil DisabledMetrics() — no nil-check-required recording"
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/server/hooks_test.go#TestNewHookExecutor_DefaultsToDisabledMetrics"
        status: pass
    human_judgment: false
  - id: D7
    description: "serve.go constructs the hook executor AFTER metrics so WithMetrics receives a real *server.Metrics — the literal HOOK-01 wiring gap"
    requirement: "HOOK-01"
    verification:
      - kind: unit
        ref: "internal/client/commands/serve.go — line-ordering acceptance criteria (NewHookExecutor after NewMetricsFromConfig), verified via rg and task build"
        status: pass
    human_judgment: false

duration: 3min (across 3 commits; execution paused mid-plan for an unrelated git-commit-signing environment blocker, resumed by the coordinator)
completed: 2026-07-31
status: complete
---

# Phase 9 Plan 01: Tracer — Detached Hook Run with a Resolved Timeout and a Recorded Metric Summary

**Hooks now run on a detached background runner against a server-lifecycle context, with a per-hook TOML timeout resolved once at config load and a real `router_hosts_hook_executions_total`/`_duration_seconds` datapoint on every run.**

## Performance

- **Duration:** ~3 min of active commit-to-commit work (09:20–09:23 across three task commits); the run was paused mid-plan by a git-commit-signing (1Password SSH agent) environment blocker and resumed by the coordinator once unlocked — no code work occurred during the pause.
- **Tasks:** 3/3 completed
- **Files modified:** 8 (2 new, 6 modified)

## Accomplishments

- Detached hook execution from the RPC write path: `regenerateOutputs` now calls `TriggerSuccess`/`TriggerFailure` (plain data, no context) instead of running hooks synchronously on the RPC's context.
- New `internal/server/hookrunner.go`: a coalescing (queue-depth-1, latest-wins) background runner mirroring `WriteQueue`'s `quit`/`done` lifecycle, owning its own `context.WithCancel(context.Background())` so client disconnects can never kill an in-flight hook.
- `HookExecutor` gained `WithMetrics`/`Start`/`Stop`/`TriggerSuccess`/`TriggerFailure`, a per-hook resolved `Timeout` field replacing the old struct-level executor timeout, and a real call to `RecordHookExecution` after every hook run.
- Closed the literal HOOK-01 wiring gap in `serve.go`: hook-executor construction moved to *after* the OTel metrics block so `WithMetrics(metrics)` receives a real `*server.Metrics` instead of silently staying on `DisabledMetrics()` forever.
- Migrated the four pre-existing `TestRegenerateOutputs_*` lifecycle assertions in `hooks_wiring_test.go` to `Start()`/`Stop()` so they stay deterministic under detachment (no more racing a still-running background hook).
- Locked the tracer's two architectural claims with dedicated regression tests: RPC-context cancellation survival, and a no-hooks-configured no-op emitting zero metric datapoints.

## Task Commits

Each task was committed atomically:

1. **Task 1: End-to-end detached hook run with resolved timeout and recorded metric** — `6fee455` (feat)
2. **Task 2: Close the serve.go metrics-sequencing gap and remove the hardcoded timeout const** — `2e103ec` (feat)
3. **Task 3: Lock the two architectural claims the tracer makes** — `09cba18` (test)

*Note: Tasks 1 and 3 carry `tdd="true"` frontmatter; all new behavior for Task 1 was implemented and verified together in one commit (config + hooks.go + hookrunner.go + tests) since the tracer wires multiple layers as a single atomic slice per the plan's own framing ("Every layer the phase touches... is wired for keeps in one commit"). Task 3's three tests all passed on first run against the Task 1/2 implementation with zero production changes required — documented below under Issues Encountered rather than as a separate RED/GREEN pair.*

## Files Created/Modified

- `internal/config/server.go` — `DefaultHookTimeout` const, `HookDefinition.Timeout`, `HooksConfig.DefaultTimeout` field, per-hook timeout defaulting pass in `LoadServerConfig`
- `internal/server/hooks.go` — removed struct-level executor timeout; added `HookExecutorOption`/`WithMetrics`, async `Start`/`Stop`/`TriggerSuccess`/`TriggerFailure`, metric recording in `executeHook`
- `internal/server/hookrunner.go` (new) — `hookRunner`/`hookRunRequest`, coalescing trigger, server-lifecycle base context, bounded-drain `Stop`
- `internal/server/service.go` — `regenerateOutputs` now triggers hooks asynchronously instead of running them inline
- `internal/server/hooks_wiring_test.go` — four existing tests migrated to `hooks.Start()`/`hooks.Stop(context.Background())`
- `internal/server/hookrunner_test.go` (new) — detachment, per-hook timeout resolution, success-metric recording, RPC-context survival, no-hooks-no-metrics tests
- `internal/server/hooks_test.go` — `TestNewHookExecutor_DefaultsToDisabledMetrics`
- `internal/client/commands/serve.go` — hook-executor construction moved after the OTel metrics block, wired via `WithMetrics(metrics)`, started/stopped with a `server.GracefulShutdownTimeout`-bounded defer; removed the file-local `defaultHookTimeout` const

## Decisions Made

- **Added `HooksConfig.DefaultTimeout` ahead of schedule.** Task 2's `serve.go` reorder requires `cfg.Hooks.DefaultTimeout` to already exist as an addressable field (per the plan's own action text: "`cfg.Hooks.DefaultTimeout` is the zero value until Plan 09-02 adds that key"). Added the bare struct field with its documented `toml:"default_timeout"` tag now, with no defaulting/validation logic attached — that lands in 09-02 as originally scoped. See Deviations below.
- **Metric recording uses the caller's `ctx`, not `hookCtx`.** `executeHook` passes the outer (runner) context to `RecordHookExecution`, not the per-hook `context.WithTimeout` derivative — a timed-out `hookCtx` would already be `Done()` at the point of recording, and RESEARCH.md's code example explicitly calls out `runnerCtx` as the recording context.
- **`hookRunner.loop`'s trigger and quit branches drain identically.** Both branches take-and-clear `pending` and run it if non-nil, so `Stop()` is correct regardless of which `select` case the Go scheduler happens to pick when a trigger and a quit race — no special-casing needed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `HooksConfig.DefaultTimeout` field ahead of its documented Plan 09-02 introduction**

- **Found during:** Task 2 (`serve.go` reorder)
- **Issue:** The plan's Task 2 action text instructs constructing the hook executor as `server.NewHookExecutor(cfg.Hooks.OnSuccess, cfg.Hooks.OnFailure, cfg.Hooks.DefaultTimeout, logger, server.WithMetrics(metrics))`, but `HooksConfig` (as it stood after Task 1, matching Task 1's own scoped action list) had no `DefaultTimeout` field — the phase's `artifacts_this_phase_produces` table attributes that field to Plan 09-02. As literally written, Task 2 would not compile.
- **Fix:** Added `DefaultTimeout time.Duration \`toml:"default_timeout"\`` to `HooksConfig` in Task 1's config edits, matching the exact shape RESEARCH.md's own code example already proposed. No TOML-resolution or validation logic was attached — `LoadServerConfig`'s per-hook defaulting pass (Task 1) still hardcodes `config.DefaultHookTimeout`, ignoring this field entirely, exactly as the plan intended ("Plan 09-02 inserts the `[hooks] default_timeout` middle link into this same pass"). The field is a compile-time no-op until 09-02 wires it up.
- **Files modified:** `internal/config/server.go`
- **Verification:** `task build` and `task test -- ./internal/config/... ./internal/server/...` both pass; `rg -n 'DefaultTimeout' internal/config/server.go` shows the field exists with no defaulting logic referencing it in `LoadServerConfig`.
- **Committed in:** `6fee455` (Task 1 commit — the field was added alongside the rest of Task 1's config changes so Task 2 could compile without a follow-up config edit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Necessary for Task 2 to compile as specified; zero behavioral change until Plan 09-02 lands its TOML wiring. No scope creep — the field carries no logic, only a struct slot.

## Issues Encountered

- **Git commit signing (1Password SSH agent) failed mid-execution.** After Task 1's code was complete and staged, `git commit` failed at the `commit-msg` lefthook stage with `1Password: failed to fill whole buffer` — the SSH agent backing `gpg.ssh.program=op-ssh-sign` was not authenticated in this session. Per project rules (never bypass `--no-gpg-sign`, never touch `git config`), this was surfaced as a `checkpoint:human-action` rather than worked around. The coordinator confirmed the agent was unlocked; the retried commit succeeded immediately with no code changes needed. No further signing failures occurred for Tasks 2 or 3.
- **Task 3's tests all passed on first run.** As the plan anticipated ("no production change should be needed if Task 1 was implemented correctly; if a test fails, fix hookrunner.go/hooks.go, not the test"), all three Task 3 tests (`TestHookRunner_SurvivesRPCContextCancellation`, `TestRegenerateOutputs_NoHooksEmitsNoMetrics`, `TestNewHookExecutor_DefaultsToDisabledMetrics`) passed against the Task 1/2 implementation without any production code fixes.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- The tracer path is fully proven end to end: TOML `timeout` → resolved on the hook at construction → detached run on the runner's own context → recorded on `router_hosts_hook_executions_total`/`_duration_seconds`.
- `task test ./...`, `task build`, and `task lint` are all green with the race detector enabled across the whole repo (not just the touched packages).
- Plan 09-02 can now insert the `[hooks] default_timeout` TOML key and its validation/resolution logic into the already-structured defaulting pass in `LoadServerConfig`, and wire `HooksConfig.DefaultTimeout`'s zero-value-inherits-30s behavior — the struct field and its constructor call site already exist and compile.
- Plan 09-03 (status classification, coalesced-runs counter) and 09-04 (coalescing/drain tests) build directly on `hookRunner`'s `Trigger`/`loop`/`runBatch` shape and the filesystem-sentinel test technique established here.
- No blockers for downstream plans.

---

*Phase: 09-hook-reliability-metrics*
*Completed: 2026-07-31*

## Self-Check: PASSED

All 8 key files and 3 task commit hashes verified present.
