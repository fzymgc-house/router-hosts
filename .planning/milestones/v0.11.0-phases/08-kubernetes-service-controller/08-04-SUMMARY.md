---
phase: 08-kubernetes-service-controller
plan: 04
subsystem: infra
tags: [kubernetes, operator, controller-runtime, corev1, service, dns, provenance, finalizer]

# Dependency graph
requires:
  - phase: 08-kubernetes-service-controller (plan 03)
    provides: validated hostname/aliases extraction and the read-before-write syncServiceHost update path
provides:
  - "syncService with no early return: a desired-set diff against the host-ids annotation, with an unconditional stale-cleanup pass, so every D-17 stop-managing transition (opt-out, unsupported type change, hostname change, opt-out via annotation removal) deletes the previously tracked entry through one code path"
  - "addOrAdoptService with the dual-provenance adoption gate (existing.Comment == k8s-service:<ns>/<name> AND hasServiceProvenance(existing.Tags)), refusing a foreign entry on ErrHostAlreadyExists rather than adopting it"
  - "hasServiceProvenance(tags []string) bool — the Service-controller ownership check, mirroring hasIngressProvenance/hasGatewayProvenance"
  - "a full reconcileDelete: deletes every tracked host entry before releasing the service-cleanup finalizer, retaining remaining IDs and requeuing on partial failure, and never releasing the finalizer while the host-ids annotation is unreadable"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Desired-set diff with unconditional stale-cleanup pass (the 07-04 fix): syncService computes newIDs via a switch over opted-out/unsupported-type/missing-hostname/waiting/sync branches with NO early return, then always runs a for-range over existingIDs deleting anything absent from newIDs"
    - "Reconcile's finalizer-add branch gates on serviceEnabled(svc) || annotations[hostIDsAnnotation] != \"\", not on serviceEnabled(svc) alone, so a Service that opts out while still tracking an entry still gets (or keeps) the finalizer needed to clean it up"

key-files:
  created: []
  modified:
    - internal/operator/service_controller.go
    - internal/operator/service_controller_test.go

key-decisions:
  - "syncService's switch/case desired-set computation replaces the tracer's four sequential early returns with a single fallthrough-to-cleanup structure, matching gateway_controller.go's syncRoute shape rather than reproducing ingressroute_controller.go's pre-07-04 len(hosts)==0 early return."
  - "The waiting (PendingLoadBalancer) branch is the one case that carries an already-tracked ID forward into newIDs instead of leaving it for stale-cleanup, so a provisioning LoadBalancer's entry survives while its IP resolves."
  - "TestSyncService_AdoptionRefused and TestHasServiceProvenance reuse gateway_controller_test.go's fakeHostStore/newFakeHostStore rather than a bare mockHostClient literal, per 08-VALIDATION.md's fixture-trap warning: a mock that hands out a fresh ID per AddHost models a server that accepts duplicate (ip, hostname) pairs, which internal/server/commands.go rejects, so it would never reach the adoption branch."
  - "newDeletingSvc seeds a foreign finalizer (not none) for the no-finalizer-is-a-noop case, because the fake client refuses to construct an object with a DeletionTimestamp and zero finalizers at all — mirroring the real API server, which would already have removed such an object. Same pattern as gateway_controller_test.go's TestReconcile_Route_DeleteWithoutFinalizerIsNoOp."

patterns-established: []

requirements-completed: [SVC-01, SVC-02]

coverage:
  - id: D1
    description: "All four D-17 stop-managing transitions (enabled flipped false, type changed to ClusterIP, hostname annotation changed, enabled annotation removed) delete the previously tracked host entry through the single desired-set diff, with the unconditional stale-cleanup pass running even when the desired set is empty"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_StopManaging (4 subtests)"
        status: pass
    human_judgment: false
  - id: D2
    description: "A corrupt host-ids annotation stops syncService before any HostClient call and requeues after requeueDelayShort with a non-nil error"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_CorruptAnnotationRequeues"
        status: pass
    human_judgment: false
  - id: D3
    description: "A per-host delete failure during the stale-cleanup pass retains the failing entry's ID in the annotation alongside any newly created entry, and requeues after requeueDelayLong"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_PartialFailureRetainsIDs"
        status: pass
    human_judgment: false
  - id: D4
    description: "A reconcile with an unchanged desired set issues no object Update (no ResourceVersion bump), even though UpdateHost may still run"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_SkipsUpdateWhenUnchanged"
        status: pass
    human_judgment: false
  - id: D5
    description: "Adoption on ErrHostAlreadyExists is refused unless BOTH the existing entry's comment equals k8s-service:<namespace>/<name> AND its tags contain \"service\"; a foreign entry (wrong comment OR wrong tags) is left untouched, never entering the Service's annotation, and never deleted"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_AdoptionRefused (foreign_comment, foreign_tags, own_entry_adopted)"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestHasServiceProvenance (5 subtests)"
        status: pass
    human_judgment: false
  - id: D6
    description: "Deleting a Service deletes every host entry tracked in its annotation and only then removes the service-cleanup finalizer; a failed delete retains the remaining IDs, requeues, and keeps the finalizer; an unreadable annotation never releases the finalizer; a Service without the finalizer is a no-op"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestReconcileService_DeleteRemovesHostsAndFinalizer (4 subtests)"
        status: pass
    human_judgment: false

# Metrics
duration: ~70min (across a signing-outage pause and resumption)
completed: 2026-07-27
status: complete
---

# Phase 8 Plan 04: Desired-Set Diff, Provenance-Gated Adoption, and Cleanup Summary

**One diff handles every "stop managing this" Service transition, adoption is refused unless both comment and tags prove ownership, and reconcileDelete removes every tracked entry before releasing the finalizer.**

## Performance

- **Duration:** ~70 min (includes a git-signing outage pause between the RED commit for Task 1 and its resumption)
- **Completed:** 2026-07-27
- **Tasks:** 3 (all `tdd="true"`, each RED-then-GREEN)
- **Files modified:** 2

## Accomplishments

- `syncService` was restructured around a `switch`-computed desired set (opted-out -> unsupported type -> missing hostname -> waiting/missing-IP/sync) with **no early return**, followed by an unconditional stale-cleanup pass over `existingIDs`. All four D-17 stop-managing transitions — `enabled` flipped to `"false"`, `Spec.Type` changed to `ClusterIP`, the `hostname` annotation changed to a new value, and the `enabled` annotation removed entirely — now delete the previously tracked entry through this single code path instead of the tracer's four separate early returns.
- The `waiting` (provisioning LoadBalancer) branch is the one exception: it carries the already-tracked ID forward into `newIDs` rather than letting the stale-cleanup pass delete it, so a `PendingLoadBalancer` Service does not lose its entry while its IP resolves.
- `Reconcile`'s finalizer-add branch now gates on `serviceEnabled(svc) || annotations[hostIDsAnnotation] != ""`, replacing the tracer's opted-out early return — a Service that opts out while still tracking an entry keeps (or gains) the finalizer it needs for `reconcileDelete` to ever run.
- `addOrAdoptService` now adopts a conflicting `FindHost` result only when `existing.Comment == "k8s-service:<namespace>/<name>"` **and** `hasServiceProvenance(existing.Tags)` — refusing an entry that matches on only one half, mirroring `addOrAdopt`/`hasIngressProvenance` in `ingressroute_controller.go`. `hasServiceProvenance(tags []string) bool` checks only the `service` tag, since `kubernetes` comes from the shared `DefaultTags`.
- `reconcileDelete` now iterates the `host-ids` annotation, deletes every tracked entry, and releases `serviceCleanupFinalizer` only on full success — a per-host delete failure retains the remaining IDs and requeues with the finalizer intact; an unreadable annotation requeues without ever touching the finalizer.
- Coverage: 85.1% (`task test:coverage:ci`, up from 84.8% at the end of plan 03); zero `go.mod`/`go.sum` changes.

## Task Commits

Each task was TDD-split into a RED (test) and a GREEN (feat) commit. Task 1's RED commit was written by a prior executor that hit a git-signing outage before it could commit; this executor verified the staged tests, re-confirmed the RED signature, then committed once signing was restored.

1. **Task 1: Desired-set diff with no early return, covering all four stop-managing transitions**
   - RED: `8fc4c37` (test) — `TestSyncService_StopManaging` (4 subtests), `TestSyncService_SkipsUpdateWhenUnchanged`, `TestSyncService_CorruptAnnotationRequeues`, `TestSyncService_PartialFailureRetainsIDs`; re-confirmed the exact expected RED signature (4 `StopManaging` subtests + `PartialFailureRetainsIDs` failing; `SkipsUpdateWhenUnchanged` and `CorruptAnnotationRequeues` already passing against pre-existing behavior) before committing
   - GREEN: `68fa76d` (feat)
2. **Task 2: Gate adoption on both halves of provenance**
   - RED: `4b15eb1` (test) — `TestSyncService_AdoptionRefused` undefined-symbol build failure (`hasServiceProvenance`)
   - GREEN: `3945224` (feat)
3. **Task 3: Delete every tracked entry before releasing the cleanup finalizer**
   - RED: `a346603` (test) — 3 of 4 `TestReconcileService_DeleteRemovesHostsAndFinalizer` subtests failed against the tracer's finalizer-only stub, confirming the RED signature
   - GREEN: `0c8733a` (feat)

**Plan metadata:** (this commit)

## Files Created/Modified

- `internal/operator/service_controller.go` — `syncService` restructured around a no-early-return desired-set diff with unconditional stale-cleanup; `Reconcile`'s finalizer-add branch now gates on opt-in OR existing annotation; `addOrAdoptService` gained the dual-provenance adoption gate; new `hasServiceProvenance`; `reconcileDelete` replaced with the full tracked-entry cleanup, mirroring `ingressroute_controller.go`
- `internal/operator/service_controller_test.go` — added `TestSyncService_StopManaging` (4 subtests), `TestSyncService_SkipsUpdateWhenUnchanged`, `TestSyncService_CorruptAnnotationRequeues`, `TestSyncService_PartialFailureRetainsIDs`, `TestSyncService_AdoptionRefused` (3 subtests), `TestHasServiceProvenance` (5 subtests), `TestReconcileService_DeleteRemovesHostsAndFinalizer` (4 subtests), plus helpers `newDeletingSvc`

## Decisions Made

- `syncService`'s desired-set computation is a `switch`/`case` chain (opted-out -> unsupported type -> missing hostname -> waiting/missing-IP/sync) rather than four sequential `if` early returns, mirroring the shape `gateway_controller.go`'s `syncRoute` uses for the same "compute desired state, never return early" property. This is a within-plan test/implementation-structure choice, not a deviation.
- `newDeletingSvc`'s `no_finalizer_is_a_noop` fixture seeds a foreign finalizer (`"other.example/finalizer"`) rather than none, because the fake client under test rejects an object seeded with a `DeletionTimestamp` and zero finalizers at all (it mirrors the real API server, which would already have garbage-collected such an object). This exact pattern already exists in `gateway_controller_test.go`'s `TestReconcile_Route_DeleteWithoutFinalizerIsNoOp`; it was reused here rather than re-derived.

## Deviations from Plan

None — plan executed exactly as written. The one adjustment (the `newDeletingSvc` foreign-finalizer fixture) was a test-construction necessity forced by the fake client's own validation, not a change to plan-specified behavior; it is documented above as a Decision, not a deviation, because it does not alter what is being tested.

## Issues Encountered

- **Git-signing outage mid-Task-1 (pre-existing, resolved before this session).** A prior executor wrote and staged Task 1's RED tests but could not commit before `op-ssh-sign` failed. This executor verified the staged diff against `git status --short`/`git diff --cached --stat`, reviewed the tests line-by-line against the plan's `<behavior>` spec (found sound, no defects), re-ran them to independently reconfirm the exact RED signature described in the resumption brief, and committed once signing was confirmed working — see Task 1's RED commit `8fc4c37`.

**Scoped-pattern verification (08-VALIDATION.md's `-run` pattern trap):** the test-function inventory in `internal/operator/service_controller_test.go` after this plan is 18 top-level `func Test...` declarations (`rg '^func Test' internal/operator/service_controller_test.go`), all containing the literal substring `Service`. `task test -- -v -run 'Service' ./internal/operator/` produced exactly 18 top-level `--- PASS`/`--- FAIL` lines (18 PASS, 0 FAIL) — the `-run 'Service'` scoping pattern (not the narrower `-run 'TestService'` pattern that silently missed `TestReconcileService_*`/`TestResolveServiceIP` in 08-01) covers the full inventory.

All plan `<verify>` and acceptance-criteria commands were run exactly as written and produced the exact expected counts:

- `TestSyncService_StopManaging`: 4/4 `--- PASS` subtests (`enabled_annotation_removed` and `hostname_annotation_changed` both individually confirmed)
- `TestSyncService_CorruptAnnotationRequeues`, `TestSyncService_SkipsUpdateWhenUnchanged`, `TestSyncService_PartialFailureRetainsIDs`: 1/1 top-level `--- PASS` each
- `grep -c 'maps.Equal(existingIDs, newIDs)' internal/operator/service_controller.go` >= 1
- `TestSyncService_AdoptionRefused`: 3/3 `--- PASS` subtests (`foreign_tags` and `foreign_comment` both individually confirmed)
- `TestHasServiceProvenance`: 1/1 top-level `--- PASS` (5/5 subtests)
- `grep -c 'func hasServiceProvenance(tags \[\]string) bool' internal/operator/service_controller.go` = 1
- `grep -c 'k8s-service:%s/%s' internal/operator/service_controller.go` >= 1
- `grep -c 'newFakeHostStore()' internal/operator/service_controller_test.go` >= 1 and `grep -c 'type fakeHostStore' internal/operator/service_controller_test.go` = 0 (reused, not redeclared)
- `TestReconcileService_DeleteRemovesHostsAndFinalizer`: 4/4 `--- PASS` subtests (`retains_ids_and_requeues_on_delete_failure` and `corrupt_annotation_requeues_without_deleting` both individually confirmed)
- `grep -c 'controllerutil.RemoveFinalizer(' internal/operator/service_controller.go` >= 1 and `grep -c 'serviceCleanupFinalizer' internal/operator/service_controller.go` >= 1
- `task test -- -v -run 'TestService|TestSyncService|TestReconcileService|TestResolveServiceIP|TestHasServiceProvenance' ./internal/operator/ 2>&1 | grep -c '^--- FAIL'` = 0
- `task build` exits 0, `task lint` exits 0 (0 issues, buf lint/format clean, generated manifests up to date)
- `task test:coverage:ci` exits 0, coverage 85.1% (>= 80% threshold)
- `git diff --exit-code -- go.mod go.sum` exits 0 (zero new dependencies)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 8's Service controller is now feature-complete per its plans: opt-in via annotation, the full type/IP resolution matrix, hostname/alias validation, the fail-closed per-host update path, the no-early-return desired-set diff with stale-cleanup, provenance-gated adoption, and full delete-time cleanup.
- This is the final plan of phase 08-kubernetes-service-controller. The orchestrator will next run phase-level code-review, regression, and goal-verification gates across all of phase 8's plans (01-04).
- No blockers.

---

*Phase: 08-kubernetes-service-controller*
*Completed: 2026-07-27*

## Self-Check: PASSED

- FOUND: internal/operator/service_controller.go
- FOUND: internal/operator/service_controller_test.go
- FOUND: .planning/phases/08-kubernetes-service-controller/08-04-SUMMARY.md
- FOUND: commit 8fc4c37 in git log
- FOUND: commit 68fa76d in git log
- FOUND: commit 4b15eb1 in git log
- FOUND: commit 3945224 in git log
- FOUND: commit a346603 in git log
- FOUND: commit 0c8733a in git log
