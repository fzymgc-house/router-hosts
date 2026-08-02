---
phase: 09-hook-reliability-metrics
plan: 02
subsystem: config
tags: [go, toml, config-validation]

requires:
  - "09-01: HookDefinition.Timeout, HooksConfig.DefaultTimeout struct fields, DefaultHookTimeout const (added early so serve.go could compile)"
provides:
  - "HooksConfig.resolveTimeouts() — the single function encoding the per-hook -> [hooks] default_timeout -> DefaultHookTimeout chain"
  - "Positivity invariant: after LoadServerConfig succeeds, every hook's resolved Timeout and HooksConfig.DefaultTimeout are strictly > 0"
  - "Negative-timeout rejection in HookDefinition.validate()/HooksConfig.validate() (backstop for hand-constructed configs)"
  - "Pinned TOML decode contract: quoted duration strings vs bare-integer-is-nanoseconds"
affects: [09-03-hook-reliability-metrics, 09-04-hook-reliability-metrics, 09-05-hook-reliability-metrics]

actuals:
  tokens: 9500
  tasks: 2
  commits: 4

tech-stack:
  added: []
  patterns:
    - "Single resolveTimeouts() method as the one place a multi-link config default chain is encoded, called from LoadServerConfig between the strict-key check and validate()"
    - "Zero-vs-negative split: zero means inherit (never rejected by validate()); resolveTimeouts() enforces the strict positivity invariant after resolution; validate() only rejects negative as a backstop for values that bypass resolveTimeouts()"

key-files:
  created: []
  modified:
    - internal/config/server.go
    - internal/config/server_test.go
    - .planning/phases/09-hook-reliability-metrics/09-VALIDATION.md

key-decisions:
  - "Did not re-add DefaultTimeout field, DefaultHookTimeout const, or the partial per-hook resolution loop — Wave 1 (09-01) already added them so serve.go could compile. Verified their presence first, then replaced the ad-hoc loop with resolveTimeouts() and closed the remaining gaps (default-link resolution, both-list coverage, positivity enforcement, negative rejection, encoding pin)."
  - "resolveTimeouts() enforces strict positivity as part of its own contract (step 3 of the plan's 3-step spec), not just as a side effect of validate(). This means LoadServerConfig already rejects a negative timeout before HookDefinition.validate()/HooksConfig.validate() are ever reached for that hook — the validate() checks added in Task 2 are a documented backstop for hand-constructed config.Config/HookDefinition values that never went through LoadServerConfig, not the primary enforcement path for the TOML-load case."
  - "DefaultTimeout's negative check in HooksConfig.validate() is placed before the OnSuccess/OnFailure loops, and resolveTimeouts() checks h.DefaultTimeout's positivity before touching either hook list, so a bad server-level default always reports itself by name rather than surfacing as a confusing per-hook error."

requirements-completed: [HOOK-02]

coverage:
  - id: D1
    description: "The effective timeout of every configured hook resolves through exactly one chain: per-hook timeout -> [hooks] default_timeout -> DefaultHookTimeout (30s)"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestLoadServerConfig_HookTimeoutResolution"
        status: pass
    human_judgment: false
  - id: D2
    description: "After LoadServerConfig returns without error, every hook in on_success and on_failure has Timeout > 0 for every set/unset combination"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestHooksConfig_ResolveTimeouts_Invariant"
        status: pass
    human_judgment: false
  - id: D3
    description: "A config with no timeout key anywhere yields exactly 30s per hook"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestLoadServerConfig_HookTimeoutResolution (both-absent case)"
        status: pass
    human_judgment: false
  - id: D4
    description: "A negative per-hook timeout is rejected at config-load time, naming the offending hook"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestLoadServerConfig_HookTimeoutRejectsNegative"
        status: pass
    human_judgment: false
  - id: D5
    description: "A negative [hooks] default_timeout is rejected naming default_timeout, not the downstream hook"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestLoadServerConfig_HookTimeoutRejectsNegative (negative default_timeout case)"
        status: pass
    human_judgment: false
  - id: D6
    description: "timeout = \"0s\" behaves identically to omitting the key (inherits the default)"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestLoadServerConfig_HookTimeoutExplicitZeroInherits"
        status: pass
    human_judgment: false
  - id: D7
    description: "TOML string duration decodes correctly; bare integer decodes as nanoseconds (accepted, positive) — pinned, not fixed"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestLoadServerConfig_HookTimeoutEncoding"
        status: pass
    human_judgment: false
  - id: D8
    description: "An empty [hooks] table with only default_timeout set loads without error"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestLoadServerConfig_EmptyHooksTable"
        status: pass
    human_judgment: false
  - id: D9
    description: "No existing hand-constructed config.Config value regresses because HookDefinition.validate gained a timeout check"
    requirement: "HOOK-02"
    verification:
      - kind: unit
        ref: "internal/config/server_test.go#TestHookDefinition_Validate, TestACMEConfig_Validation (both pass unchanged with new rows added)"
        status: pass
    human_judgment: false

duration: ~15min across 4 commits
completed: 2026-07-31
status: complete
---

# Phase 9 Plan 02: Hook Timeout Configuration Chain and Validation Summary

**`[hooks] default_timeout` inserted as the middle link of the timeout resolution chain via a single `resolveTimeouts()` method, closing the positivity invariant, negative-timeout rejection, and the TOML bare-integer-nanoseconds footgun with pinning tests.**

## Performance

- **Duration:** ~15 minutes of active work across 4 task commits (2 tasks, RED then GREEN each)
- **Tasks:** 2/2 completed
- **Files modified:** 2 source files (`internal/config/server.go`, `internal/config/server_test.go`) + 1 validation tracking doc

## Accomplishments

- Added `(*HooksConfig).resolveTimeouts() error` — the single function that encodes the full three-link chain (per-hook `timeout` → `[hooks] default_timeout` → `DefaultHookTimeout`) for both `OnSuccess` and `OnFailure`, replacing the partial ad-hoc per-hook loop Wave 1 left in `LoadServerConfig`.
- `resolveTimeouts()` enforces the promoted invariant directly: after it returns `nil`, `HooksConfig.DefaultTimeout` and every hook's `Timeout` in both lists are guaranteed strictly positive. The `DefaultTimeout` positivity check runs before either hook list is touched, so a bad server-level default reports itself by name.
- Added a negative-timeout backstop check to `HookDefinition.validate()` (rejects `< 0` only, never `0`) and `HooksConfig.validate()` (rejects a negative `DefaultTimeout`, checked before the `OnSuccess`/`OnFailure` loops) — for hand-constructed `config.Config`/`HookDefinition` values that bypass `LoadServerConfig`.
- Pinned the BurntSushi/toml decode contract by test: `"10s"` → 10s, `"2m"` → 2m, `"1m30s"` → 90s, and the bare-integer footgun `timeout = 10` → 10 **nanoseconds** (accepted, since it's positive — documented as an operator footgun for Plan 09-05, not "fixed").
- 8 new test functions covering resolution (4-combination table, both hook lists per case), explicit-zero-inherits, the resolution invariant directly (7 sub-cases including both-empty-lists), empty-`[hooks]`-table-with-default-only, negative rejection (per-hook and server-level, with a `NotContains` assertion proving the default-negative error never names the downstream hook), and TOML encoding. Extended the existing `TestHookDefinition_Validate` table with 2 rows.

## Task Commits

Each task followed RED (`test(config): ...`) then GREEN (`feat(config): ...`):

1. **Task 1: `[hooks] default_timeout` + `resolveTimeouts()`**
   - RED: `0e12e11` — `test(config): add failing tests for hook timeout resolution chain` (fails to compile: `resolveTimeouts` undefined)
   - GREEN: `db294cc` — `feat(config): resolve hook timeout chain via resolveTimeouts()`
2. **Task 2: Reject non-positive timeouts, pin TOML encoding**
   - RED: `cbdadd9` — `test(config): add failing test for HookDefinition negative-timeout rejection`
   - GREEN: `cce6941` — `feat(config): reject negative hook timeouts in validate()`

## Files Created/Modified

- `internal/config/server.go` — `(*HooksConfig).resolveTimeouts() error` (new); `LoadServerConfig`'s ad-hoc per-hook defaulting loop replaced with a single `cfg.Hooks.resolveTimeouts()` call, positioned after `meta.Undecoded()` and before `cfg.validate()`; `HooksConfig.DefaultTimeout` doc comment updated (no longer says "lands in Plan 09-02" since it now does); `Timeout < 0` check added to `HookDefinition.validate()`; `DefaultTimeout < 0` check added to `HooksConfig.validate()` before its `OnSuccess`/`OnFailure` loops
- `internal/config/server_test.go` — 8 new test functions + 2 new rows in `TestHookDefinition_Validate`; added `time` and `fmt` imports
- `.planning/phases/09-hook-reliability-metrics/09-VALIDATION.md` — flipped the 4 `09-02-T1`/`09-02-T2` rows from `⬜ pending` to `✅ green`

## Decisions Made

- **Did not re-add Wave 1's early additions.** Per the upstream deviation note, `internal/config/server.go` already carried `DefaultHookTimeout`, `HookDefinition.Timeout`, `HooksConfig.DefaultTimeout`, and a partial per-hook (but not default-link) resolution loop from Plan 09-01. Verified each was present via `Read` before touching anything, then implemented only the genuinely missing pieces: the default-link resolution, the single-function collapse, the positivity enforcement, the negative-timeout backstop checks, and the encoding pin tests.
- **`resolveTimeouts()` is the primary enforcement point for positivity, not `validate()`.** As specified by the plan's own 3-step description, `resolveTimeouts()` itself rejects a non-positive `DefaultTimeout` or hook `Timeout` after resolution. This means the `LoadServerConfig`-level negative-timeout tests (`TestLoadServerConfig_HookTimeoutRejectsNegative`) already passed once Task 1 landed — before Task 2's `validate()` changes existed. This was confirmed empirically during Task 2's RED step (see Issues Encountered) and is expected, not a bug: the plan explicitly frames the `validate()` checks as a backstop for hand-constructed values that skip `LoadServerConfig`, and Task 2's genuinely new behavior (`HookDefinition.validate()` called directly) was correctly RED before implementation.
- **Ordering guarantees which key gets named in the error.** Both `resolveTimeouts()` and `HooksConfig.validate()` check `DefaultTimeout`'s (non-)positivity/negativity before iterating either hook list, so a bad `default_timeout` always names itself rather than surfacing as a confusing per-hook error on whichever hook happened to inherit it.

## Deviations from Plan

None beyond the upstream Wave-1 pre-population already flagged and handled per the execution-context instructions — no new deviations introduced by this plan's own work.

## Issues Encountered

- **Task 2's `LoadServerConfig`-level negative-rejection and encoding tests were already green at RED-check time**, because Task 1's `resolveTimeouts()` already enforces positivity in the config-load path (by design — see Decisions above). This is not a TDD-discipline failure: the genuinely new production-code requirement in Task 2 — `HookDefinition.validate()` rejecting a negative `Timeout` when called directly (not through `LoadServerConfig`) — was confirmed RED (`TestHookDefinition_Validate/negative_timeout` failed with "An error is expected but got nil") before implementation, and GREEN after. Documented explicitly in the Task 2 RED commit message rather than silently proceeding.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `[hooks] default_timeout` is fully wired: TOML decode → `resolveTimeouts()` → guaranteed-positive `Timeout` on every hook → already consumed by `HookExecutor`/`hookRunner` from Plan 09-01.
- `task test`, `task lint`, `task build`, and `task test:coverage:ci` (85.3% overall, 88.3% `internal/config`) are all green.
- Plan 09-03 (status classification, coalesced-runs counter) and 09-04 (coalescing/drain tests) are unaffected by this plan's scope — no shared files.
- Plan 09-05 (docs) can now write the operator-facing timeout configuration reference, including the pinned bare-integer-nanoseconds footgun documented (not fixed) by `TestLoadServerConfig_HookTimeoutEncoding`.
- No blockers for downstream plans.

---

*Phase: 09-hook-reliability-metrics*
*Completed: 2026-07-31*

## Self-Check: PASSED

All source changes verified present via `rg`, all 4 task commit hashes verified in `git log`, full `task test`/`task lint`/`task build`/`task test:coverage:ci` green.
