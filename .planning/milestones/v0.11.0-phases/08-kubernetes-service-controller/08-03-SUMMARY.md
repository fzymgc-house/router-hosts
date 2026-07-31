---
phase: 08-kubernetes-service-controller
plan: 03
subsystem: infra
tags: [kubernetes, operator, controller-runtime, corev1, service, dns, validation, aliases]

# Dependency graph
requires:
  - phase: 08-kubernetes-service-controller (plan 02)
    provides: full resolveServiceIP type matrix, the four Kubernetes Events, and the events RBAC fix
provides:
  - "serviceDesiredHostname(log, svc) — trimmed, validation.ValidateHostname-checked hostname; invalid input is warned-and-dropped (treated as absent, MissingHostname), a dot-less hostname is warned-and-accepted (D-08)"
  - "serviceDesiredAliases(log, svc, canonicalHostname) — comma-split/trimmed/per-alias-validated/case-insensitively-deduped alias list, ALWAYS non-nil (Pitfall 2 guard)"
  - "(*ServiceReconciler).syncServiceHost — read-before-write fail-closed update path for an already-tracked hostname, mirroring IngressRouteReconciler.syncHost, with UpdateHost kept unconditional per D-19"
  - "syncService now threads the real (non-nil) alias slice through AddHost/UpdateHost instead of nil, and routes an already-tracked hostname through syncServiceHost instead of always calling addOrAdoptService"
affects: [08-kubernetes-service-controller (plan 04, which adds the desired-set diff, stale-cleanup pass, and provenance-gated adoption on top of this update path)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Per-alias validation.ValidateAliases([]string{alias}, canonicalHostname) call, with a locally-maintained case-insensitive seen-set for cross-alias dedup the per-alias call cannot see on its own"
    - "Alias slice always initialized via make([]string, 0, ...), never `var aliases []string`, so an empty result is a real empty slice and UpdateHost's `if aliases != nil` wire-attachment guard fires correctly on a cleared aliases annotation"

key-files:
  created: []
  modified:
    - internal/operator/service_controller.go
    - internal/operator/service_controller_test.go

key-decisions:
  - "TestSyncService_UpdatePath's four subtests call (*ServiceReconciler).syncServiceHost directly rather than routing through the full Reconcile/fake-client/annotation round trip. This is a test-structure choice within the plan's explicitly granted discretion (task ordering/test structure not fixed by CONTEXT.md) — it isolates the read-before-write branch logic (D-18/D-19) from the annotation-persistence plumbing already covered by TestSyncService_AliasesClearedSendsEmptySlice/TestSyncService_AliasesSentOnCreate (which DO run through full Reconcile, per their explicit behavior text)."
  - "syncService's error-handling shape for a syncServiceHost failure is unchanged from the tracer's addOrAdoptService failure shape: log.Error + ctrl.Result{RequeueAfter: requeueDelayLong} with a nil returned error (the established D-18 'swallow to requeue' pattern already used by IngressRoute's reconcileUpsert hadError branch). The previously-tracked ID is retained because the annotation is never touched on this branch."

patterns-established: []

requirements-completed: [SVC-01]

coverage:
  - id: D1
    description: "An invalid hostname annotation is logged at Warn and treated as absent (MissingHostname event), rather than becoming a bad DNS entry"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestServiceDesiredHostname/invalid_dropped"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_Events/MissingHostname_when_invalid"
        status: pass
    human_judgment: false
  - id: D2
    description: "A dot-less (non-FQDN) hostname is accepted and warned about, matching the other three controllers"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestServiceDesiredHostname/dotless_accepted_with_warning"
        status: pass
    human_judgment: false
  - id: D3
    description: "The aliases annotation is comma-split, trimmed, empty-segment-skipped, per-alias validated (IP rejection, canonical-hostname-match rejection, hostname validity), and case-insensitively deduped, each drop logged at Warn without failing the reconcile"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestServiceDesiredAliases (9 subtests)"
        status: pass
    human_judgment: false
  - id: D4
    description: "The alias slice handed to AddHost/UpdateHost is never nil — an absent or emptied aliases annotation yields a non-nil empty slice, so a cleared aliases annotation actually clears server-side aliases instead of leaving them untouched"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestServiceDesiredAliases/absent_annotation_returns_empty_non_nil"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_AliasesClearedSendsEmptySlice"
        status: pass
    human_judgment: false
  - id: D5
    description: "A tracked hostname is refreshed by reading the current entry first (supplying the optimistic-concurrency version to UpdateHost) and fails closed — no UpdateHost call — on any non-NotFound read error or an empty (nil, nil) read result, retaining the previously tracked ID"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_UpdatePath/passes_version_from_get"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_UpdatePath/fails_closed_on_read_error"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_UpdatePath/fails_closed_on_empty_entry"
        status: pass
    human_judgment: false
  - id: D6
    description: "A tracked ID the server reports as not found (on the pre-update read, or on the update itself) is recreated via addOrAdoptService rather than retained as a dead ID"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_UpdatePath/recreates_when_get_reports_not_found"
        status: pass
    human_judgment: false
  - id: D7
    description: "A fresh Service's aliases annotation is threaded through to AddHost in order on create"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_AliasesSentOnCreate"
        status: pass
    human_judgment: false

# Metrics
duration: ~50min
completed: 2026-07-26
status: complete
---

# Phase 8 Plan 03: Hostname Validation, Aliases, and the Per-Host Sync Path Summary

**Validated hostname extraction with the project-consistent non-FQDN warning, a comma-separated aliases parser that always returns a non-nil slice (closing the nil-vs-empty UpdateHost leak), and a read-before-write fail-closed `syncServiceHost` update path modelled on IngressRoute's `syncHost`.**

## Performance

- **Duration:** ~50 min
- **Completed:** 2026-07-26
- **Tasks:** 3 (all `tdd="true"`, each RED-then-GREEN)
- **Files modified:** 2

## Accomplishments

- `serviceDesiredHostname` now takes a `*slog.Logger`, trims the annotation, validates it with `internal/validation.ValidateHostname`, and returns the empty string on failure (logged at Warn) — the caller's existing `MissingHostname` branch is the operator-visible signal, matching `extractHostnames`/`extractHosts` in the Gateway and IngressRoute controllers. A dot-less hostname is accepted and warned about (D-08), not rejected.
- `serviceDesiredAliases` splits the `aliases` annotation on commas, trims each segment, skips empty segments, validates each surviving alias individually with `validation.ValidateAliases([]string{alias}, canonicalHostname)` (catching IP-address aliases, canonical-hostname collisions, and invalid hostnames), and deduplicates case-insensitively across the accumulated result — the per-alias call can't see the others, so dedup is done locally. The result is **always non-nil** (`make([]string, 0, ...)`, never `var aliases []string`), closing the Pitfall 2 leak where `grpcHostClient.UpdateHost` silently no-ops a nil alias slice.
- `(*ServiceReconciler).syncServiceHost` adds the read-before-write fail-closed update path: a non-empty `prevID` triggers `GetHost` first, and its result decides the branch — success updates unconditionally (D-19, no "already in sync" skip) using the read's version for optimistic concurrency; `ErrHostNotFound` on either the read or the write recreates via `addOrAdoptService`; any other read error or an empty `(nil, nil)` read fails closed, returning the retained `prevID` and a wrapped error so the caller neither loses the ID nor issues a blind, event-re-appending update (#338).
- `syncService` now computes `aliases := serviceDesiredAliases(log, svc, hostname)` and routes the create-or-update decision through `syncServiceHost(ctx, log, existingIDs[hostname], ip, hostname, comment, aliases, tags)` instead of always calling `addOrAdoptService` with a hardcoded `nil` for aliases.
- Coverage rose from 84.7% to 84.8% (`task test:coverage:ci`); zero `go.mod`/`go.sum` changes.

## Task Commits

Each task was TDD-split into a RED (test, build-fails-until-implemented) commit and a GREEN (feat) commit:

1. **Task 1: Validate the hostname annotation with the project-consistent non-FQDN warning**
   - RED: `a595e03` (test) — `TestServiceDesiredHostname`'s 2-arg call didn't compile against the 1-arg tracer signature; build failure confirmed as the "must fail" gate
   - GREEN: `a637be3` (feat)
2. **Task 2: Parse and validate the comma-separated aliases annotation into a never-nil slice**
   - RED: `7fdb1a6` (test) — `serviceDesiredAliases` undefined; build failure
   - GREEN: `ba1312f` (feat) — also updates the pre-existing `TestReconcileService_LoadBalancerCreatesHost` assertion from `assert.Nil(aliases)` to `assert.NotNil` + `assert.Empty` (see Deviations)
3. **Task 3: Thread aliases through a fail-closed per-host sync path**
   - RED: `4c26fbd` (test) — `r.syncServiceHost` undefined; build failure
   - GREEN: `452141b` (feat)

**Plan metadata:** (this commit)

## Files Created/Modified

- `internal/operator/service_controller.go` — `serviceDesiredHostname` gained a `*slog.Logger` parameter and `validation.ValidateHostname` wiring; new `serviceDesiredAliases` function; new `(*ServiceReconciler).syncServiceHost` method; `syncService` now computes and passes the real alias slice and routes through `syncServiceHost`
- `internal/operator/service_controller_test.go` — added `TestServiceDesiredHostname` (6 subtests), `TestServiceDesiredAliases` (9 subtests), a `MissingHostname_when_invalid` subtest on `TestSyncService_Events`, `TestSyncService_AliasesClearedSendsEmptySlice`, `TestSyncService_AliasesSentOnCreate`, and `TestSyncService_UpdatePath` (4 subtests); updated one pre-existing assertion (see Deviations)

## Decisions Made

- `TestSyncService_UpdatePath`'s four subtests call `syncServiceHost` directly rather than through a full `Reconcile` + fake-client + annotation round trip. This isolates the read-before-write branch logic (D-18/D-19) as a focused unit test; the annotation-persistence half of the contract ("the new ID lands in the host-ids annotation") is separately proven by `TestSyncService_AliasesClearedSendsEmptySlice` and `TestSyncService_AliasesSentOnCreate`, which do run the full `Reconcile` path. This is within the plan's granted test-structure discretion, not a deviation from a specified behavior.
- `syncServiceHost`'s fail-closed branches return to `syncService`, which handles the error exactly like the tracer's pre-existing `addOrAdoptService` failure handling: `log.Error` + `ctrl.Result{RequeueAfter: requeueDelayLong}` with a nil returned error. The previously-tracked ID survives because the annotation write is skipped entirely on this branch — no special-case logic was needed.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Updated a pre-existing test assertion that the plan's own behavior change invalidated**

- **Found during:** Task 2, after wiring the real alias slice into `syncService`'s create-path call to `addOrAdoptService`
- **Issue:** `TestReconcileService_LoadBalancerCreatesHost` (written in plan 01, unrelated to this plan's task list) asserted `assert.Nil(t, aliases)` inside its `addHostFn` mock, because the tracer always passed a literal `nil`. Task 2's action explicitly requires `syncService`'s create path to pass the real (non-nil) alias slice from `serviceDesiredAliases`, which correctly turns "no aliases annotation" into a non-nil empty slice rather than nil — exactly the Pitfall 2 contract this plan exists to establish. The old assertion was now testing the bug this plan fixes.
- **Fix:** Changed the assertion to `assert.NotNil(t, aliases)` + `assert.Empty(t, aliases)`, matching the same non-nil-empty-slice contract this plan's own `TestServiceDesiredAliases/absent_annotation_returns_empty_non_nil` and `TestSyncService_AliasesClearedSendsEmptySlice` tests assert elsewhere.
- **Files modified:** `internal/operator/service_controller_test.go`
- **Verification:** `TestReconcileService_LoadBalancerCreatesHost` passes; full `Service`-scoped suite green (11/11 top-level `--- PASS`, 0 `--- FAIL`).
- **Committed in:** `ba1312f` (Task 2 GREEN commit)

---

**Total deviations:** 1 auto-fixed (bug — a pre-existing test asserted the exact nil-vs-empty-slice bug this plan closes)
**Impact on plan:** No behavior beyond what the plan specified; the fixed assertion is a direct consequence of implementing task 2 correctly. No scope creep.

## Issues Encountered

None beyond the deviation above. Every `<verify>` and acceptance-criteria command from the plan was run exactly as written and produced the exact expected counts:

- `TestServiceDesiredHostname`: 6/6 `--- PASS` subtests (`dotless_accepted_with_warning` and `invalid_dropped` both individually confirmed)
- `TestSyncService_Events/MissingHostname_when_invalid`: 1/1 `--- PASS`
- `TestServiceDesiredAliases`: 9/9 `--- PASS` subtests (`absent_annotation_returns_empty_non_nil` and `invalid_alias_dropped` both individually confirmed)
- `TestSyncService_AliasesClearedSendsEmptySlice`: 1/1 `--- PASS`, body asserts both `assert.NotNil` and `assert.Empty` on the captured `UpdateHost` aliases argument
- `TestSyncService_UpdatePath`: 4/4 `--- PASS` subtests (`fails_closed_on_read_error` individually confirmed)
- `grep -c 'var aliases \[\]string' internal/operator/service_controller.go` = 0
- `grep -c 'router-hosts.fzymgc.house/tags' internal/operator/service_controller.go` = 0
- `grep -c 'UpdateHost(ctx, prevID, ip, hostname, comment, nil,' internal/operator/service_controller.go` = 0
- `grep -c 'type recordingHandler' internal/operator/service_controller_test.go` = 0 (the existing package-level handler is reused, not redeclared)
- `task lint` exits 0 (0 issues), `task build` exits 0
- `task test:coverage:ci` exits 0, coverage 84.8% (≥80% threshold)
- `git diff --exit-code -- go.mod go.sum` exits 0 (zero new dependencies)
- Full `Service`-scoped suite: 11/11 top-level test functions `--- PASS`, 0 `--- FAIL` (`task test -- -v -run 'Service' ./internal/operator/`)

**Scoped-pattern verification (per 08-VALIDATION.md's `-run` pattern trap):** the test-function inventory in `internal/operator/service_controller_test.go` after this plan is 11 top-level `func Test...` declarations (`rg '^func Test' internal/operator/service_controller_test.go`), all containing the literal substring `Service`. `task test -- -v -run 'Service' ./internal/operator/` produced exactly 11 top-level `--- PASS` lines and 0 `--- FAIL` lines — the scoping pattern covers the full inventory, matching 08-CONTEXT's prescribed `-run 'Service'` pattern (not the `-run 'TestService'` pattern that silently missed `TestReconcileService_*`/`TestResolveServiceIP` in 08-01).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `serviceDesiredHostname`, `serviceDesiredAliases`, and `syncServiceHost` are complete per this plan's must-haves; plan 04 can build the desired-set diff, stale-cleanup pass, and provenance-gated adoption on top without touching hostname/alias validation or the single-host update semantics.
- `syncService`'s early-return branches (unsupported type, missing hostname, missing IP) remain provisional exactly as plan 02's summary flagged: plan 04 restructures them to fall through to the stale-cleanup diff pass (D-17) instead of returning early, while still emitting the same events.
- `addOrAdoptService`'s `ErrHostAlreadyExists` branch is still a hard error (no adoption) — plan 04's provenance-gated adoption (D-21, `hasServiceProvenance`) lands there, mirroring `addOrAdopt`/`hasIngressProvenance`.
- No blockers.

---

*Phase: 08-kubernetes-service-controller*
*Completed: 2026-07-26*

## Self-Check: PASSED

- FOUND: internal/operator/service_controller.go
- FOUND: internal/operator/service_controller_test.go
- FOUND: .planning/phases/08-kubernetes-service-controller/08-03-SUMMARY.md
- FOUND: commit a595e03 in git log
- FOUND: commit a637be3 in git log
- FOUND: commit 7fdb1a6 in git log
- FOUND: commit ba1312f in git log
- FOUND: commit 4c26fbd in git log
- FOUND: commit 452141b in git log
