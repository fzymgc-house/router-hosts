---
phase: 260728-ude
plan: 01
subsystem: operator
tags: [kubernetes, controller-runtime, validation, events, service-controller]

# Dependency graph
requires:
  - phase: 08-kubernetes-service-controller
    provides: ServiceReconciler, the D-12 operator-visible Event states, D-14 terminal-no-requeue rule
provides:
  - reasonInvalidConfiguration, a fifth Kubernetes Event reason distinct from MissingIPAddress
  - serviceIPOverride helper (single definition of "the ip-address override is present")
  - resolveServiceIP client-side ip-address format validation via validation.ValidateIPAddress
  - serviceAliasCandidates / serviceAliasesExceedCap helpers closing the WR-01 unreachable-cap gap
affects: [08-kubernetes-service-controller, future operator controllers reusing the InvalidConfiguration pattern]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "oops.AsOops + Code() inspection to detect a specific validation error class from a []error slice (mirrors internal/server/commands.go:145)"
    - "InvalidConfiguration Event reason: present-but-unusable annotation, distinct from a Missing* reason meaning absent; always terminal, always freezes (carries forward the tracked ID) rather than tearing down"

key-files:
  created: []
  modified:
    - internal/operator/service_controller.go
    - internal/operator/service_controller_test.go

key-decisions:
  - "InvalidConfiguration is a fifth Event reason, never a reuse of MissingIPAddress — collapsing absent vs. present-but-unusable would make a typo indistinguishable from an omission in kubectl describe service (locked in plan design decision 1)"
  - "InvalidConfiguration freezes: the previously tracked ID is carried forward into newIDs so the stale-cleanup pass never deletes a working, previously published entry over a cosmetic annotation typo (design decision 2)"
  - "Both new branches are terminal per D-14 — no RequeueAfter, no hadError — since the underlying alias count or IP value never changes on its own between reconciles"
  - "serviceAliasesExceedCap calls validation.ValidateAliases ONCE on the full candidate slice — the only way to reach validation.go's length-cap branch, since the per-alias loop in serviceDesiredAliases passes a one-element slice where that branch is structurally unreachable"
  - "serviceDesiredAliases does not truncate an over-cap list; truncation is not attempted since the caller's serviceAliasesExceedCap gate runs first and skips the sync entirely"

requirements-completed: [WR-01, WR-02]

coverage:
  - id: D1
    description: "WR-02: an ip-address override annotation that is present but unparseable is validated client-side with validation.ValidateIPAddress, never falls through to LoadBalancer status, and produces a terminal Warning InvalidConfiguration Event instead of an indefinite silent requeueDelayLong retry"
    requirement: "WR-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/nodeport_unparseable_override"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/loadbalancer_unparseable_override_does_not_fall_through"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_Events/InvalidConfiguration_ip_override"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_InvalidIPOverrideEmitsInvalidConfiguration"
        status: pass
    human_judgment: false
  - id: D2
    description: "WR-01: an aliases annotation whose candidate count exceeds validation.MaxAliasesPerEntry (50) is caught by one aggregate ValidateAliases call (serviceAliasesExceedCap) before AddHost/UpdateHost is ever attempted, reported as terminal Warning InvalidConfiguration, and publishes nothing"
    requirement: "WR-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_AliasCapExceededEmitsInvalidConfiguration"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestServiceDesiredAliases/sixty_aliases_returns_all_uncapped"
        status: pass
    human_judgment: false
  - id: D3
    description: "Neither new InvalidConfiguration branch tears down a previously published host entry — the tracked ID is carried forward and DeleteHost is never called for either failure mode"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_InvalidIPOverrideEmitsInvalidConfiguration"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_AliasCapExceededEmitsInvalidConfiguration"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-29
status: complete
---

# Quick 260728-ude: Make Two Silent Service Misconfigurations Visible Summary

**Client-side validation for the Service controller's `ip-address` and `aliases` annotations, surfaced through a new `InvalidConfiguration` Kubernetes Event reason instead of a silent, eventless, indefinite `requeueDelayLong` retry.**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-07-29T17:52:00Z
- **Completed:** 2026-07-29T18:00:00Z
- **Tasks:** 3 (2 code tasks + 1 verification-only task)
- **Files modified:** 2

## Accomplishments

- Closed WR-02: `resolveServiceIP` now trims and validates the `ip-address` override with `validation.ValidateIPAddress`; an unparseable value is never returned as an IP and never falls through to LoadBalancer status. `syncService` emits a terminal `Warning InvalidConfiguration` Event for it, distinct from `MissingIPAddress` (which still means the annotation is absent).
- Closed WR-01: extracted `serviceAliasCandidates` (comma-split/trim/non-nil parse) and added `serviceAliasesExceedCap`, which calls `validation.ValidateAliases` once on the *full* candidate slice — the only way to ever reach `validation.go`'s `len(aliases) > MaxAliasesPerEntry` branch, since the pre-existing per-alias loop structurally could not trip it. `syncService` gates on this before `AddHost`/`UpdateHost` and emits `Warning InvalidConfiguration` naming the observed count and the maximum.
- Both new terminal branches carry the previously tracked host ID forward into `newIDs`, so the stale-cleanup pass never deletes a working, previously published DNS entry over a cosmetic annotation typo (design decision 2) — verified directly by both new regression tests asserting the ID is retained.
- All ten pre-existing `TestResolveServiceIP` subtests and all nine pre-existing `TestServiceDesiredAliases` subtests pass with zero edits to their assertions.

## Task Commits

Each task was committed as a RED/GREEN pair (TDD):

1. **Task 1: Validate the ip-address override and surface it as InvalidConfiguration**
   - `24a844f` test(operator): add failing tests for ip-address validation
   - `79e78bc` fix(operator): validate ip-address annotation client-side
2. **Task 2: Make the aggregate alias cap reachable and event-visible**
   - `79a8275` test(operator): add failing tests for alias cap enforcement
   - `4403ad1` fix(operator): enforce alias cap client-side
3. **Task 3: Negative-control, inventory, and coverage gate** — verification-only, no code changes; see below.

**Plan metadata:** committed separately by the orchestrator (SUMMARY.md, STATE.md).

## Files Created/Modified

- `internal/operator/service_controller.go` — added `reasonInvalidConfiguration`, `serviceIPOverride`, `serviceAliasCandidates`, `serviceAliasesExceedCap`; updated `resolveServiceIP` and `syncService`'s inner switches; extended doc comments for the fifth D-12 state.
- `internal/operator/service_controller_test.go` — 3 new `TestResolveServiceIP` subtests, 1 new `TestSyncService_Events` subtest, 1 new `TestServiceDesiredAliases` subtest, 2 new top-level regression tests (`TestSyncService_InvalidIPOverrideEmitsInvalidConfiguration`, `TestSyncService_AliasCapExceededEmitsInvalidConfiguration`).

## Decisions Made

- Followed the plan's four locked design decisions exactly: `InvalidConfiguration` is a fifth reason (never a `MissingIPAddress` reuse); it freezes rather than tears down; both branches are terminal per D-14; `serviceDesiredAliases`/`resolveServiceIP` signatures are unchanged.
- Used `oops.AsOops(err)` + `.Code() == "too_many_aliases"` for cap detection rather than a bare `len(candidates) > validation.MaxAliasesPerEntry` comparison, per the plan's explicit instruction to keep the controller and `internal/validation` agreeing on one definition of the cap through code inspection rather than a duplicated magic number check.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Lint] Preallocated two test slices flagged by golangci-lint's `prealloc`**

- **Found during:** Task 2 verification (`task lint`)
- **Issue:** `var segments, want []string` (60-alias pinning subtest) and `var segments []string` (alias-cap regression test) were built via repeated `append` in a fixed-size loop without a capacity hint.
- **Fix:** Changed both to `make([]string, 0, N)` with the known final length.
- **Files modified:** `internal/operator/service_controller_test.go`
- **Verification:** `task lint` reports 0 issues; tests still pass.
- **Committed in:** `79a8275` (Task 2 test commit)

---

**Total deviations:** 1 auto-fixed (1 lint).
**Impact on plan:** Cosmetic only — no scope creep, no behavior change.

## Issues Encountered

None.

## Negative Control Results (Task 3)

Both new regression tests were proven to fail against un-fixed code, then restored and re-verified green, per the plan's negative-control requirement:

1. **Alias cap gate reverted** (checked out `internal/operator/service_controller.go` from commit `79a8275`, the last commit before the alias-cap fix, then restored to HEAD via `git checkout HEAD --`): `TestSyncService_AliasCapExceededEmitsInvalidConfiguration` failed with:

   ```text
   service_controller_test.go:737: UpdateHost must not be called when the alias cap is exceeded
   ```

   Restored and re-verified `PASS`.

2. **Override validation reverted** (manually removed the `validation.ValidateIPAddress` call inside `resolveServiceIP`'s override branch, keeping the alias-cap fix intact — no single commit represents this combination — then restored the exact committed file content via `git show HEAD:... > snapshot` / copy-back, confirmed byte-identical with `diff`): `TestSyncService_InvalidIPOverrideEmitsInvalidConfiguration` failed with:

   ```text
   service_controller_test.go:700: expected an event
   ```

   (the unparseable `"not-an-ip"` override flowed straight into `UpdateHost` unchecked, producing an `INFO host entry updated` log line instead of a Warning Event.) Restored and re-verified `PASS`.

## Inventory and Coverage Gate

- `rg -c '^func Test' internal/operator/service_controller_test.go` → **20**
- `rg -c '^func Test.*Service' internal/operator/*_test.go` summed → **20** (all in `service_controller_test.go`)
- `task test -- -v -run 'Service' ./internal/operator/` top-level `--- PASS` count → **20**
- All three numbers agree, matching the plan's expected post-change inventory (18 pre-existing + 2 new regression tests).
- `task test` — green repo-wide.
- `task lint` — 0 issues (golangci-lint + buf lint + buf format + manifests verify).
- `task test:coverage:ci` — **85.2%** (baseline 85.1%, threshold 80%).
- `git diff --stat 0e953f0..HEAD` — exactly `internal/operator/service_controller.go` and `internal/operator/service_controller_test.go`.
- `git diff --stat -- go.mod go.sum` — empty (zero new dependencies).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- WR-01 and WR-02 from `08-REVIEW.md` are both closed; the Service controller's fifth Event reason (`InvalidConfiguration`) is available for any future annotation-validation gap that needs the same "present but unusable" signal.
- No blockers. `internal/validation`, `internal/server`, `go.mod`, and `go.sum` are untouched, so the server-side bounding control this plan relied on (WR-01/WR-02 were visibility fixes, not correctness fixes — the server already rejected both cases) is unchanged.

---

*Phase: 260728-ude*
*Completed: 2026-07-29*

## Self-Check: PASSED

- FOUND: internal/operator/service_controller.go
- FOUND: internal/operator/service_controller_test.go
- FOUND: SUMMARY.md (this file)
- FOUND commit: 24a844f (test: ip-address validation RED)
- FOUND commit: 79e78bc (fix: ip-address validation GREEN)
- FOUND commit: 79a8275 (test: alias cap RED)
- FOUND commit: 4403ad1 (fix: alias cap GREEN)
