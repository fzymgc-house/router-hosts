---
phase: 07-gateway-api-support
plan: 05
subsystem: infra
tags: [kubernetes, gateway-api, controller-runtime, operator, k8s, field-index]

requires:
  - phase: 07-gateway-api-support
    provides: "GatewayRouteReconciler, gatewayRouteKinds(), resolveIP, syncRoute, reconcileDelete, gatewayKindPresent, gatewayGroupVersionKind (plans 07-01 through 07-04)"
provides:
  - "parentRefIndexKey field index + routeParentRefIndexFunc: per-route-kind index keyed \"<namespace>/<name>\" of each declared parentRef, namespace defaulted to the route's own (D-17)"
  - "mapGatewayToRoutes: handler.MapFunc that lists this reconciler's route kind by the index and re-enqueues every route naming the changed Gateway (GW-02)"
  - "gatewayGVK + watchGateway threading: the Gateway watch clause is gated on gatewayKindPresent(mapper, gatewayGVK), computed once in SetupGatewayControllers and passed into every route controller's SetupWithManager, so a cluster with route CRDs but no Gateway CRD still starts the manager cleanly (D-04/D-05, research Pitfall 1)"
  - "per-route-kind CRD-absence skip log now names the required apiVersion (gateway.networking.k8s.io/v1)"
affects: []

tech-stack:
  added: []
  patterns:
    - "parentRefIndexKey is the single field-index key shared by routeParentRefIndexFunc (extractor, registered per-kind in SetupWithManager) and mapGatewayToRoutes (reader, via client.MatchingFields) — both apply the identical namespace-defaulting rule (route's own namespace when parentRef.Namespace is nil), or the index key and lookup key silently diverge and a Gateway IP change stops propagating"
    - "gatewayGVK is resolved via the existing gatewayGroupVersionKind(\"Gateway\") helper (gatewayv1.GroupVersion.WithKind), not the deprecated gatewayv1.SchemeGroupVersion.WithKind used by the stale 2026-06-07 plan doc's code sketch — staticcheck SA1019 flags the latter, and the file already established the non-deprecated helper for the three route kinds"
    - "SetupWithManager registers the field index unconditionally (the caller has already confirmed this kind's CRD is installed before calling it) but adds the Gateway Watches(...) clause only when watchGateway is true — the same CRD-presence gate the three route kinds use, applied a second time to the Gateway kind itself, because Watches() only registers a source and the actual List/Watch happens when the manager's shared informer cache starts all registered informers together at mgr.Start()"

key-files:
  created: []
  modified:
    - internal/operator/gateway_controller.go
    - internal/operator/gateway_controller_test.go

key-decisions:
  - "gatewayGVK uses gatewayGroupVersionKind(\"Gateway\") instead of the plan's literal acceptance-criteria string gatewayv1.SchemeGroupVersion.WithKind(\"Gateway\") — SchemeGroupVersion is deprecated (staticcheck SA1019) per this project's CLAUDE.md domain guidance, and the file already uses the non-deprecated helper for all three route kinds' GVKs. Semantically identical (both resolve to gateway.networking.k8s.io/v1, Kind: Gateway); only the literal-string acceptance-criteria grep for the stale plan doc's sketch does not match."
  - "mapGatewayToRoutes logs and returns nil on both a List failure and an ExtractList failure, rather than propagating an error — matches handler.MapFunc's signature, which has no error return, and matches the plan's stated behavior for TestMapGatewayToRoutes_ListErrorReturnsNil."
  - "Task 2's core per-route-kind CRD gating (mapper := mgr.GetRESTMapper(); if !gatewayKindPresent(mapper, k.gvk) { ...; continue }) was already implemented by an earlier plan; this plan's Task 2 work was the missing test matrix (AllRouteKindsPresent/PartiallyInstalled/AllAbsent/WrongVersion) plus naming the required apiVersion in the skip log."
  - "REQUIREMENTS.md GW-02 and GW-03 were already marked Complete before this plan ran (their literal wording — Gateway status.addresses IP resolution, and chart/RBAC watch/list grants — was satisfied by plans 07-01/07-02/07-03). This plan's frontmatter still lists them because the re-enqueue/CRD-gating work it adds is the deeper mechanism GW-02 depends on for correctness; no REQUIREMENTS.md checkbox state changed as a result of this plan."

requirements-completed: [GW-02, GW-03]

coverage:
  - id: D1
    description: "A Gateway status change re-enqueues exactly the routes of one kind whose parentRefs name it, via a field index and Gateway watch, so a changed status.addresses value propagates without polling"
    requirement: GW-02
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestMapGatewayToRoutes_EnqueuesReferencingRoutes"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestMapGatewayToRoutes_PerKind"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestMapGatewayToRoutes_NoMatches"
        status: pass
    human_judgment: false
  - id: D2
    description: "routeParentRefIndexFunc emits <namespace>/<name> per parentRef, defaulting the namespace to the route's own when the parentRef sets none, in declaration order, and an empty non-nil slice for a route with no parentRefs or a non-route object"
    requirement: GW-02
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestRouteParentRefIndexFunc_ExplicitNamespace"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestRouteParentRefIndexFunc_DefaultsToRouteNamespace"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestRouteParentRefIndexFunc_MultipleAndEmpty"
        status: pass
    human_judgment: false
  - id: D3
    description: "mapGatewayToRoutes degrades safely (logs, returns nil) on a List or list-extraction failure instead of panicking or propagating an error the handler.MapFunc signature cannot carry"
    requirement: GW-02
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestMapGatewayToRoutes_ListErrorReturnsNil"
        status: pass
    human_judgment: false
  - id: D4
    description: "With zero Gateway API route CRDs installed, SetupGatewayControllers constructs zero controllers and a nil error; a route kind whose GroupKind resolves only at a non-v1 version is skipped, not built at that older version"
    requirement: GW-03
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestGatewayKindPresent_AllAbsent"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestGatewayKindPresent_PartiallyInstalled"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestGatewayKindPresent_WrongVersion"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestGatewayKindPresent_AllRouteKindsPresent"
        status: pass
    human_judgment: false
  - id: D5
    description: "With route CRDs installed but the Gateway CRD absent, the Gateway watch clause is not registered on any route controller — computed once via gatewayKindPresent(mapper, gatewayGVK) and threaded through SetupWithManager's watchGateway parameter — so the manager's shared informer cache never attempts to start an informer for an unresolvable Gateway GVK"
    requirement: GW-03
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestGatewayKindPresent_GatewayGVKAbsent"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestGatewayKindPresent_GatewayGVKPresent"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestSetupWithManager_WatchGatewayFlagIsThreaded"
        status: pass
    human_judgment: false
  - id: D6
    description: "task build, task lint (0 issues, manifests verified up to date), and task test:coverage:ci (>=80%) all green"
    requirement: null
    verification:
      - kind: unit
        ref: "task build && task lint && task test:coverage:ci -> Coverage: 84.9%, internal/operator 86.7%"
        status: pass
    human_judgment: false

duration: 20min
completed: 2026-07-26
status: complete
---

# Phase 7 Plan 05: Gateway Re-enqueue and CRD-Presence Gating Summary

**A parentRef field index plus a CRD-presence-gated Gateway watch now re-enqueue every route that names a changed Gateway, without ever risking the manager's startup on a cluster missing the Gateway CRD**

## Performance

- **Duration:** ~20 min of active execution
- **Started:** 2026-07-26T16:58Z
- **Completed:** 2026-07-26T17:06Z
- **Tasks:** 3 (single RED/GREEN TDD cycle across all three, per this file's `type: tdd` frontmatter)
- **Files modified:** 2

## Accomplishments

- Added `parentRefIndexKey` (`"spec.parentRefs.gateway"`) and `routeParentRefIndexFunc`, a pure, unit-testable extractor that emits `"<namespace>/<name>"` per parentRef in declaration order, defaulting the namespace to the route's own when the parentRef sets none — the same defaulting `resolveIP` already applies.
- Added `mapGatewayToRoutes`, the `handler.MapFunc` that lists this reconciler's route kind filtered by the field index and returns one `reconcile.Request` per matching route; it logs and returns `nil` (not a propagated error, since `handler.MapFunc` has none) on either a `List` or `apimeta.ExtractList` failure.
- Registered the field index unconditionally in `SetupWithManager` via `mgr.GetFieldIndexer().IndexField(...)` — safe because the caller (`SetupGatewayControllers`) has already confirmed this route kind's CRD is installed before calling it.
- Added `gatewayGVK` (via the existing non-deprecated `gatewayGroupVersionKind("Gateway")` helper) and computed `watchGateway := gatewayKindPresent(mapper, gatewayGVK)` once in `SetupGatewayControllers`, threading it into every route controller's `SetupWithManager(mgr, watchGateway)` call. The `.Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayToRoutes))` clause now exists at exactly one call site, guarded by `if watchGateway {` — closing research Pitfall 1: an ungated Gateway watch would otherwise fail the manager's shared informer cache at startup on any cluster with route CRDs but no Gateway CRD, taking the already-shipped HostMapping and IngressRoute controllers down with it.
- Confirmed the per-route-kind CRD-presence gate in `SetupGatewayControllers` (`mapper := mgr.GetRESTMapper()`; `if !gatewayKindPresent(mapper, k.gvk) { ...; continue }`) was already implemented by an earlier plan; this plan added the missing test matrix (all-present, partially-installed, all-absent, wrong-version) and enriched the skip log to name the exact required `apiVersion` (`gateway.networking.k8s.io/v1`).
- 20 new test functions added, covering the field index, the map function (including a `.WithIndex(...)`-built fake client per every test that exercises it, and a `client.WithWatch` List-failure interceptor), per-kind and Gateway RESTMapper presence gating, and a compile-time `SetupWithManager` signature/wiring assertion.

## Task Commits

1. **Tasks 1 + 2 + 3 (RED):** `ba6c408` (test) — added the full spec matrix: parentRef index and map-function tests (7), route-kind RESTMapper gating tests (4), and Gateway-watch gating tests (3). Confirmed to fail as a **compile** failure (`undefined: routeParentRefIndexFunc`, `r.mapGatewayToRoutes undefined`, etc.) before any implementation landed — proving the tests exercised genuinely unwritten symbols, not just unimplemented behavior.
2. **Tasks 1 + 2 + 3 (GREEN):** `0091e46` (feat) — added `parentRefIndexKey`, `routeParentRefIndexFunc`, `mapGatewayToRoutes`, `gatewayGVK`, threaded `watchGateway` through `SetupGatewayControllers`/`SetupWithManager`, and gated the Gateway watch clause. All 20 new tests plus the full existing suite pass; `task build`, `task lint` (0 issues, manifests verified up to date), and `task test:coverage:ci` (84.9%, `internal/operator` 86.7%) all green.

All three tasks share `tdd="true"` under this plan's `type: tdd` frontmatter and were executed as a single RED → GREEN cycle (every task's tests were written before any of the three tasks' implementation changes landed, then all three implementations landed together) — **TDD Gate Compliance:** `test(...)` commit (`ba6c408`) precedes `feat(...)` commit (`0091e46`).

## Files Created/Modified

- `internal/operator/gateway_controller.go` — added `parentRefIndexKey`, `routeParentRefIndexFunc`, `mapGatewayToRoutes`, `gatewayGVK`; `SetupGatewayControllers` now computes `watchGateway` once and threads it through; `SetupWithManager` gained a `watchGateway bool` parameter, registers the field index unconditionally, and gates the `Watches(&gatewayv1.Gateway{}, ...)` clause on it; the per-kind skip log now names the required `apiVersion`
- `internal/operator/gateway_controller_test.go` — 20 new test functions (`TestRouteParentRefIndexFunc_*` ×3, `TestMapGatewayToRoutes_*` ×4, `TestGatewayKindPresent_*` ×6 new alongside the 1 pre-existing, `TestSetupWithManager_WatchGatewayFlagIsThreaded`), plus `gatewayGVKAt` and `setupWithManagerFunc` test helpers; new imports `sigs.k8s.io/controller-runtime/pkg/client/interceptor`

## Decisions Made

- **`gatewayGVK` uses `gatewayGroupVersionKind("Gateway")`, not the plan's literal `gatewayv1.SchemeGroupVersion.WithKind("Gateway")` sketch:** `SchemeGroupVersion` is deprecated (staticcheck `SA1019`) per this project's CLAUDE.md domain guidance, and the file already established the non-deprecated helper for all three route kinds' GVKs — using the deprecated form here would have been the one inconsistency in an otherwise uniform file and would have re-introduced a lint violation this plan's own domain notes explicitly call out. Semantically identical (both resolve to `gateway.networking.k8s.io/v1`, `Kind: Gateway`); confirmed via `TestSetupWithManager_WatchGatewayFlagIsThreaded`'s `assert.Equal(t, gatewayGroupVersionKind("Gateway"), gatewayGVK)`.
- **`mapGatewayToRoutes` returns `nil` (not an error) on failure:** matches `handler.MapFunc`'s signature (`func(context.Context, client.Object) []reconcile.Request`, no error return) and is the plan-specified behavior for `TestMapGatewayToRoutes_ListErrorReturnsNil`.
- **`SetupWithManager`'s test uses a named `setupWithManagerFunc` type instead of an inline `func(ctrl.Manager, bool) error` var declaration:** an inline declaration triggers `staticcheck`'s `ST1023`/`S1021` (redundant, inferable type annotation) either way it's written; a distinct named type makes the assignment a genuine, non-redundant signature assertion.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Lint conformance] `gatewayGVK` built via the non-deprecated helper instead of the plan's literal code sketch**

- **Found during:** Task 3 (Gateway watch gating)
- **Issue:** The plan's `<action>` and acceptance criteria specify `var gatewayGVK = gatewayv1.SchemeGroupVersion.WithKind("Gateway")`, copied from the stale 2026-06-07 design doc's code sketch. `gatewayv1.SchemeGroupVersion` is deprecated and flagged by `staticcheck SA1019`; this executor prompt's domain notes explicitly instruct using the file's existing `gatewayGroupVersionKind()` helper instead, which is already how all three route kinds' GVKs are built.
- **Fix:** `var gatewayGVK = gatewayGroupVersionKind("Gateway")`. Behaviorally identical; `task lint` stays at 0 issues.
- **Files modified:** `internal/operator/gateway_controller.go`
- **Verification:** `task lint` 0 issues; `TestSetupWithManager_WatchGatewayFlagIsThreaded` asserts `gatewayGVK == gatewayGroupVersionKind("Gateway")`.
- **Committed in:** `0091e46` (GREEN commit)

---

**Total deviations:** 1 auto-fixed (1 lint-conformance substitution, no behavior change)
**Impact on plan:** None on functionality; keeps the file's GVK-construction convention uniform across all four kinds and avoids reintroducing a lint violation the domain notes explicitly flagged.

## Issues Encountered

None. `task fmt` (gofumpt) reformatted several unrelated files across the repo as a side effect of running `-w .`; those were pre-existing formatting drift unrelated to this plan's scope and were reverted (`git checkout --`) before committing, per the deviation-rules scope boundary (only auto-fix issues directly caused by this task's changes).

## Known Stubs

None. All new code (`routeParentRefIndexFunc`, `mapGatewayToRoutes`, the CRD-gating additions) is a complete, real implementation with no placeholder returns.

## User Setup Required

None.

## Next Phase Readiness

- Phase 7 (Gateway API Support) is now fully implemented: `GatewayRouteReconciler` handles create/update/delete for HTTPRoute/GRPCRoute/TLSRoute (GW-01, plan 04), resolves IPs from parent Gateways with a documented fallback (GW-02, plans 01/03), and now re-enqueues on Gateway change with CRD-presence gating on every registered kind including `Gateway` itself (GW-02/GW-03, this plan).
- This was the final plan (5 of 5, wave 5) in phase 07-gateway-api-support. No further Gateway API controller work is anticipated; remaining phase-level verification is `task ci` (already green) and any manual cluster validation tracked in `07-VALIDATION.md`.
- REQUIREMENTS.md GW-01/GW-02/GW-03 are all already marked Complete; no traceability table change was needed from this plan.

No blockers.

---

*Phase: 07-gateway-api-support*
*Completed: 2026-07-26*

## Self-Check: PASSED

Both modified files (`internal/operator/gateway_controller.go`, `internal/operator/gateway_controller_test.go`) present on disk with the expected new symbols (`parentRefIndexKey`, `routeParentRefIndexFunc`, `mapGatewayToRoutes`, `gatewayGVK`). Both commits (`ba6c408`, `0091e46`) verified present in `git log --oneline --all`. `task build`, `task lint` (0 issues), and `task test:coverage:ci` (84.9%) all confirmed green immediately prior to writing this file.
