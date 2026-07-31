---
phase: 07-gateway-api-support
plan: 04
subsystem: infra
tags: [kubernetes, gateway-api, controller-runtime, operator, k8s]

requires:
  - phase: 07-gateway-api-support
    provides: "GatewayRouteReconciler, gatewayRouteKinds(), resolveIP (complete D-15/D-16 matrix), syncRoute's tracer create path, extractHostnames (plans 07-01/07-02/07-03)"
provides:
  - "syncRoute: complete create/update/delete diff against the host-ids annotation — unconditional UpdateHost for tracked hostnames (D-13), stale-cleanup DeleteHost pass sourced only from the object's own annotation (D-14, threat T-07-02), per-host error retention with requeueDelayLong, corrupt-annotation fail-closed with requeueDelayShort"
  - "reconcileDelete: full cleanup-then-finalizer-release lifecycle — deletes every tracked entry before releasing gatewayCleanupFinalizer, partial-delete retry (persist remaining IDs, keep finalizer, requeue short), corrupt-annotation fail-closed"
affects: ["07-gateway-api-support (plan 05 adds the parentRefIndexKey field index and Gateway watch on top of this)"]

tech-stack:
  added: []
  patterns:
    - "syncRoute's update path deliberately does NOT port ingressroute_controller.go's syncHost GetHost-before-Update idempotency guard — UpdateHost is unconditional for every tracked hostname per D-13, so a changed Gateway IP propagates without the controller keeping any 'last known IP' state"
    - "Every DeleteHost target in both syncRoute's stale-cleanup pass and reconcileDelete comes only from the reconciled object's own host-ids annotation — never a hostname/IP lookup — so no cross-owner deletion is possible even when two routes share a hostname"
    - "A corrupt host-ids annotation is the one failure that aborts immediately (return error, requeueDelayShort, touch nothing); every other per-host failure degrades to requeueDelayLong (sync) or requeueDelayShort (delete) with a retained/undeleted ID instead of returning an error"

key-files:
  created: []
  modified:
    - internal/operator/gateway_controller.go
    - internal/operator/gateway_controller_test.go

key-decisions:
  - "Removed syncRoute's pre-existing `if len(hostnames) == 0 { return }` early bail (from plan 07-01's tracer). It predated the delete diff and, left in place, would have skipped the stale-cleanup pass whenever a route's hostnames were edited down to zero without deleting the route itself — orphaning every previously-tracked entry. The general create/update/delete diff already handles the zero-hostname case correctly (empty create loop, full stale-cleanup pass, maps.Equal(nil, map[string]string{}) == true so no spurious Update), so removing the guard is strictly more correct and needed no special-case code. Verified via TestSyncRoute_NeverDeletesUntrackedID and TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete, both of which drive a route to zero hostnames."
  - "Confirmed empirically (not assumed) that the fake controller-runtime client deletes an object outright once its finalizer list becomes empty while a DeletionTimestamp is set, mirroring the real API server. The two full-success delete tests (TestReconcile_HTTPRoute_DeletesHostsOnFinalize, TestReconcile_Route_DeleteAllThreeKinds) assert apierrors.IsNotFound on the post-Reconcile Get rather than asserting the finalizer's absence on a fetched object, since that object no longer exists to fetch."
  - "GW-01 marked complete in REQUIREMENTS.md: the third success criterion ('deleting or editing a route updates/removes the corresponding DNS entries') is now satisfied by this plan's syncRoute diff and reconcileDelete implementation, closing the gap plans 01-03 deliberately left open."

requirements-completed: [GW-01]

coverage:
  - id: D1
    description: "Editing a route's hostnames converges the router: newly added hostnames are created, retained hostnames are updated, and hostnames removed from the spec have their entries deleted and dropped from the host-ids annotation"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_CreatesNewHostnames"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_UpdatesTrackedHostnames"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_DeletesRemovedHostnames"
        status: pass
    human_judgment: false
  - id: D2
    description: "UpdateHost is issued for every already-tracked hostname on every reconcile that reaches syncRoute, even when the resolved IP is unchanged — the intentional D-13 mechanism that propagates a changed Gateway IP without extra state"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_UpdatesEvenWhenIPUnchanged"
        status: pass
    human_judgment: false
  - id: D3
    description: "The object Update is skipped when the recomputed host-ids map equals the stored one and the finalizer is already present"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_SkipsUpdateWhenNothingChanged"
        status: pass
    human_judgment: false
  - id: D4
    description: "Deleting a route deletes every host entry recorded in its host-ids annotation and only then removes the gateway-cleanup finalizer"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestReconcile_HTTPRoute_DeletesHostsOnFinalize"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestReconcile_Route_DeleteAllThreeKinds"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestReconcile_Route_DeleteWithoutFinalizerIsNoOp"
        status: pass
    human_judgment: false
  - id: D5
    description: "A partial delete or per-host sync failure never orphans an entry: still-undeleted/still-retained IDs are persisted back to the annotation, the finalizer (on delete) is kept, and the reconcile requeues instead of aborting the batch"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestReconcile_Route_PartialDeleteKeepsFinalizerAndRequeues"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_PerHostErrorDoesNotAbortBatch"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_RetainsPriorIDOnUpdateFailure"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_RetainsIDOnStaleDeleteFailure"
        status: pass
    human_judgment: false
  - id: D6
    description: "A corrupt host-ids annotation returns an error and requeues rather than proceeding on a partial view and deleting entries it can no longer see, in both syncRoute and reconcileDelete"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_CorruptAnnotationRequeuesWithoutWriting"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestReconcile_Route_DeleteCorruptAnnotationRequeues"
        status: pass
    human_judgment: false
  - id: D7
    description: "DeleteHost is only ever invoked with host IDs read from the reconciled object's own host-ids annotation — a hostname shared with another route never causes cross-owner deletion (threat T-07-02)"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_NeverDeletesUntrackedID"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete"
        status: pass
    human_judgment: false
  - id: D8
    description: "task build, task lint (0 issues, manifests verified up to date), and task test:coverage:ci (>=80%) all green"
    requirement: null
    verification:
      - kind: unit
        ref: "task build && task lint && task test:coverage:ci -> Coverage: 85.0%"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-07-26
status: complete
---

# Phase 7 Plan 04: Route Lifecycle — Update, Delete, and Fail-Closed Safety Summary

**`syncRoute` now runs the full create/update/delete diff against the host-ids annotation and `reconcileDelete` performs real cleanup-then-finalizer-release, closing GW-01's edit/delete convergence gap left open by plans 01-03**

## Performance

- **Duration:** ~25 min of active execution
- **Started:** 2026-07-26T16:44Z
- **Completed:** 2026-07-26T16:54Z
- **Tasks:** 2 (RED/GREEN TDD cycle per task)
- **Files modified:** 2

## Accomplishments

- Completed `syncRoute`'s update path: an already-tracked hostname now gets
  an unconditional `UpdateHost` call (id, resolved IP, hostname, comment,
  `nil` aliases, tags, empty version) on every reconcile, deliberately not
  porting `ingressroute_controller.go`'s `syncHost` GetHost-before-Update
  idempotency guard, per D-13.
- Added the stale-cleanup delete pass: every `existingIDs` entry with no
  corresponding `newIDs` entry gets `DeleteHost`'d and dropped from the
  persisted annotation. Every deletion target is sourced only from the
  reconciled object's own annotation, never a hostname or IP lookup —
  verified directly by `TestSyncRoute_NeverDeletesUntrackedID` and
  `TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete` (threat
  T-07-02).
- Per-host failures (create, update, or stale-delete) no longer abort the
  batch: the failing hostname is logged and skipped for its own operation,
  a known ID is retained where one exists so the stale-cleanup pass can't
  mistake it for removed, and the result requeues after `requeueDelayLong`
  with a nil error instead of returning an error.
- A corrupt `host-ids` annotation is the one failure that aborts
  immediately: `syncRoute` returns the error and `requeueDelayShort`
  without touching `HostClient` or the annotation at all (D-14).
- Removed the pre-existing `len(hostnames) == 0` early return from
  `syncRoute` (see Decisions below) — the general diff now handles the
  all-hostnames-removed case correctly without a special case.
- Implemented `reconcileDelete` for real: no-op when the finalizer isn't
  present, fail-closed on a corrupt annotation, delete every tracked entry
  and only then `RemoveFinalizer` + `Update`, and on partial failure
  persist the remaining IDs, keep the finalizer, and requeue after
  `requeueDelayShort` — mirroring `ingressroute_controller.go`'s
  `reconcileDelete` structure exactly. Verified identical across HTTPRoute,
  GRPCRoute, and TLSRoute reconciler instances.
- Marked **GW-01** complete in REQUIREMENTS.md — its third success
  criterion ("deleting or editing a route updates/removes the
  corresponding DNS entries") is now satisfied.

## Task Commits

1. **Task 1 + Task 2 (RED):** `d85d271` (test) — added the full behavior
   matrix for both `syncRoute`'s diff and `reconcileDelete`'s lifecycle: 16
   new test functions plus two fixture helpers
   (`newHTTPRouteTracking`/`hostnamesToGateway` for sync tests,
   `newDeletingHTTPRoute` for delete tests). All new tests failed against
   the pre-existing stub/tracer implementation, confirming they exercised
   genuinely unwritten behavior.
2. **Task 1 + Task 2 (GREEN):** `145aeac` (feat) — rewrote `syncRoute` with
   the unconditional-update branch and stale-cleanup pass, and implemented
   `reconcileDelete` in full. All 16 new tests plus the full existing
   suite pass; `task build`, `task lint` (0 issues), and
   `task test:coverage:ci` (85.0%, operator package 87.6%) all green.

Both tasks share `tdd="true"` and were executed as one RED → GREEN cycle
per this file's `type: tdd` frontmatter (Task 1's syncRoute tests and Task
2's reconcileDelete tests were both written before any implementation
change, then both implementations landed together) — TDD Gate Compliance:
`test(...)` commit (`d85d271`) precedes `feat(...)` commit (`145aeac`).

## Files Created/Modified

- `internal/operator/gateway_controller.go` — `syncRoute` rewritten with
  the unconditional-UpdateHost branch (D-13), the stale-cleanup DeleteHost
  pass, per-host error retention, and removal of the now-redundant
  zero-hostnames early return; `reconcileDelete` implemented in full
  (previously an underscored-parameter stub)
- `internal/operator/gateway_controller_test.go` — 16 new test functions
  covering the full syncRoute diff matrix and reconcileDelete lifecycle,
  plus `hostnamesToGateway`, `newHTTPRouteTracking`, and
  `newDeletingHTTPRoute` fixture helpers; new imports `encoding/json`,
  `errors`, `fmt`, `apierrors "k8s.io/apimachinery/pkg/api/errors"`

## Decisions Made

- **Removed `syncRoute`'s `len(hostnames) == 0` early return:** this guard
  predated the delete diff (added by plan 07-01's tracer, when `syncRoute`
  only created entries). Left in place after this plan's rewrite, it would
  have silently skipped stale-entry cleanup whenever a route's hostnames
  were edited down to zero without the route itself being deleted —
  orphaning every previously-tracked entry, directly contradicting GW-01's
  "hostnames removed from the spec have their entries deleted" contract.
  The general create/update/delete diff already handles zero hostnames
  correctly with no special case (empty create loop, full stale-cleanup
  pass, `maps.Equal(nil, map[string]string{})` evaluates true so no
  spurious `Update`), so removing the guard is strictly more correct and
  adds no complexity. This is a Rule 1 (bug fix) deviation: in-scope,
  discovered while rewriting the exact function the plan targets, and
  directly required by the plan's own stated truths.
- **Delete-success assertions use `apierrors.IsNotFound` on a post-Reconcile
  Get, not a finalizer-absence check on a fetched object:** confirmed
  empirically that the fake controller-runtime client deletes an object
  outright once its finalizer list becomes empty while `DeletionTimestamp`
  is set (mirroring the real API server, not a test artifact). The two
  full-success delete tests were written to assert `NotFound` accordingly.
- **`TestReconcile_Route_DeleteWithoutFinalizerIsNoOp` seeds an unrelated
  finalizer** (`other.example/finalizer`) rather than none: the fake client
  refuses to build a store containing an object with a `DeletionTimestamp`
  and zero finalizers at all (again mirroring real apiserver semantics —
  such an object would already be gone). Seeding a finalizer this
  reconciler doesn't own still genuinely exercises the
  `!ContainsFinalizer(gatewayCleanupFinalizer)` no-op branch.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed the stale zero-hostnames early return in `syncRoute`**

- **Found during:** Task 1 (syncRoute diff implementation)
- **Issue:** The tracer-era `if len(hostnames) == 0 { return }` guard would
  have prevented the new stale-cleanup pass from ever running when a route's
  hostnames are all removed without deleting the route object — orphaning
  every previously-created entry, contrary to GW-01.
- **Fix:** Removed the guard; the general diff algorithm already produces
  correct behavior for the zero-hostnames case with no special-casing.
- **Files modified:** `internal/operator/gateway_controller.go`
- **Verification:** `TestSyncRoute_NeverDeletesUntrackedID` and
  `TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete` both drive
  a route to zero hostnames and assert every previously-tracked entry is
  correctly deleted (and only entries this object ever held).
- **Committed in:** `145aeac` (Task 1/2 GREEN commit)

---

**Total deviations:** 1 auto-fixed (1 bug fix)
**Impact on plan:** Necessary for GW-01 correctness; no scope creep — the
change is entirely within `syncRoute`, the function this plan's Task 1
targets, and is validated by tests the plan itself specifies.

## Issues Encountered

None beyond the fake-client deletion semantics discovered while writing the
`reconcileDelete` tests (documented above under Decisions, not a bug — the
tests were adjusted to assert the correct, real API-server-mirroring
behavior).

## Known Stubs

None. `syncRoute` and `reconcileDelete` are both now complete, real
implementations with no underscored parameters or placeholder returns.

## User Setup Required

None.

## Next Phase Readiness

- **Plan 05** adds the `parentRefIndexKey` field index and the CRD-gated
  Gateway watch in `SetupWithManager`, so a Gateway status change
  re-triggers reconciliation of its child routes. Nothing in this plan
  blocks that work — `resolveIP`, `syncRoute`, and `reconcileDelete` are
  all complete and stable inputs.
- GW-01 is now fully satisfied; no further syncRoute/reconcileDelete work
  is anticipated for this phase.

No blockers.

---

*Phase: 07-gateway-api-support*
*Completed: 2026-07-26*

## Self-Check: PASSED

All modified files present on disk; both task commits (`d85d271`,
`145aeac`) verified present in `git log --oneline --all`. REQUIREMENTS.md
GW-01 checkbox and traceability row confirmed marked Complete.
