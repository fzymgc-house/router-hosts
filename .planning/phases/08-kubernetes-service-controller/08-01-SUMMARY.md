---
phase: 08-kubernetes-service-controller
plan: 01
subsystem: infra
tags: [kubernetes, operator, controller-runtime, corev1, service, dns]

# Dependency graph
requires:
  - phase: 07-gateway-api-support
    provides: hostIDsAnnotation/getHostIDsAnnotation/setHostIDsAnnotation widened to client.Object, requeueDelayShort/Long constants, the finalizer+annotation lifecycle pattern, and the provenance-gated adoption pattern this plan's tracer intentionally stubs out
provides:
  - ServiceReconciler watching v1/Service, gated by --enable-service (default false) and a per-Service router-hosts.fzymgc.house/enabled="true" annotation
  - serviceEnabledPredicate, hand-rolled and update-symmetric so an opt-out edit (annotation removed) still reaches Reconcile (D-05)
  - resolveServiceIP: LoadBalancer status.loadBalancer.ingress[].IP walk with an ip-address annotation override, never falling back to --default-ingress-ip (D-11)
  - the service-cleanup finalizer and host-ids annotation lifecycle for a single-hostname Service, matching IngressRoute/Gateway conventions
affects: [08-kubernetes-service-controller (plans 02-05, which expand the type matrix, events, aliases, update/diff path, and adoption)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Hand-rolled predicate.Funcs{} for annotation-gated watches, never predicate.NewPredicateFuncs (new-object-only) or GenerationChangedPredicate (annotation writes don't bump generation)"
    - "Typed controller-runtime builder (For(&corev1.Service{}, ...)) for core API kinds, reserving WatchesRawSource/unstructured for CRDs that aren't cleanly importable"

key-files:
  created:
    - internal/operator/service_controller.go
    - internal/operator/service_controller_test.go
  modified:
    - cmd/operator/main.go

key-decisions:
  - "Checkpoint resolved: kept the service-cleanup finalizer string exactly as CONTEXT.md D-16 locked it (router-hosts.fzymgc.house/service-cleanup) — the fourth in the one-finalizer-per-source-kind series, deliberately distinct from host-cleanup/ingressroute-cleanup/gateway-cleanup."
  - "syncService always calls addOrAdoptService for the resolved hostname rather than checking existingIDs for a prevID short-circuit — the read-before-write update path and per-host error accumulation are explicitly deferred to plan 04 per the plan's action text."
  - "addOrAdoptService returns a hard error on ErrHostAlreadyExists instead of approximating adoption; the provenance-gated D-21 adoption branch is plan 04's job."

patterns-established:
  - "Local per-controller const block for annotation keys/finalizer (not folded into the shared ingressroute_controller.go block), per RESEARCH Open Question 1"

requirements-completed: [SVC-01, SVC-02]

coverage:
  - id: D1
    description: "An opted-in LoadBalancer Service with one non-empty ingress IP produces one AddHost call with that IP, hostname, comment k8s-service:<ns>/<name>, and tags kubernetes+service"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestReconcileService_LoadBalancerCreatesHost"
        status: pass
    human_judgment: false
  - id: D2
    description: "After that reconcile the Service carries the service-cleanup finalizer and a host-ids annotation mapping hostname to the returned host ID"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestReconcileService_LoadBalancerCreatesHost"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestReconcileService_AddsFinalizerAndReturns"
        status: pass
    human_judgment: false
  - id: D3
    description: "The watch predicate admits an Update where the enabled annotation was present on the old object and absent on the new object (D-05 opt-out hazard)"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestServiceEnabledPredicate/update_annotation_removed"
        status: pass
    human_judgment: false
  - id: D4
    description: "The watch predicate refuses Create/Update-both-disabled for a Service with no enabled annotation, and admits Create/Delete for an enabled one (D-03)"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestServiceEnabledPredicate"
        status: pass
    human_judgment: false
  - id: D5
    description: "The operator registers no Service controller unless --enable-service was passed (defaults to false), wired with a Recorder"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "cmd/operator/main.go (grep-verified: enable-service flag defaults false, ServiceReconciler registration gated on it)"
        status: pass
    human_judgment: false
  - id: D6
    description: "go.mod/go.sum unchanged and defaultIngressIPWarning's two return strings unchanged — corev1.Service needed no new module, no scheme install, and the Service controller doesn't consume --default-ingress-ip"
    verification:
      - kind: other
        ref: "git diff --exit-code -- go.mod go.sum; grep -c on both defaultIngressIPWarning return strings"
        status: pass
    human_judgment: false
  - id: D7
    description: "LoadBalancer IP resolution walks status.loadBalancer.ingress[] for the first non-empty .IP (never inferring from .Hostname), with an ip-address annotation override"
    requirement: "SVC-02"
    verification: []
    human_judgment: true
    rationale: "resolveServiceIP is exercised indirectly via TestReconcileService_LoadBalancerCreatesHost (single-entry case) but has no direct unit test for multi-entry ordering, hostname-only-entry skip, or the annotation-override precedence in this plan — those are explicitly plan 02/03 scope per the plan's task list. Flagging for reviewer awareness rather than silently claiming coverage."

# Metrics
duration: ~20min (resumed from a checkpoint; excludes the prior agent's pre-checkpoint session)
completed: 2026-07-26
status: complete
---

# Phase 8 Plan 01: Tracer — One LoadBalancer Service Becomes One Router DNS Entry Summary

**ServiceReconciler tracer: an annotated LoadBalancer Service with a resolved ingress IP becomes one router-hosts DNS entry, behind `--enable-service`, with an update-symmetric opt-in/opt-out predicate and the finalizer/host-ids lifecycle already in place.**

## Performance

- **Duration:** ~20 min (this continuation session; resumed from a resolved `checkpoint:decision`)
- **Completed:** 2026-07-26T18:07:13-07:00
- **Tasks:** 2 (Task 1: checkpoint decision, resolved before this session started; Task 2: tracer implementation)
- **Files modified:** 3 (2 created, 1 modified)

## Accomplishments

- `ServiceReconciler` reconciles a single opted-in `LoadBalancer` Service end-to-end: resolve hostname + IP → `AddHost` → persist `host-ids` annotation, with the `service-cleanup` finalizer added on first reconcile
- `serviceEnabledPredicate` is hand-rolled and update-symmetric: an Update event is admitted when *either* the old or the new object carries `enabled: "true"`, so removing the annotation (opting out) still reaches `Reconcile` — the D-05 hazard the plan flagged as this phase's silent-failure risk
- `resolveServiceIP` implements the LoadBalancer arm plus the `ip-address` annotation override, testing `.IP` directly and never inferring emptiness from `.Hostname` (D-09)
- `cmd/operator/main.go` wires the reconciler behind `--enable-service` (default `false`), with a dedicated `mgr.GetEventRecorder("service-controller")`
- Zero `go.mod`/`go.sum` changes; `defaultIngressIPWarning`'s two return strings are byte-identical to their pre-phase form

## Task Commits

1. **Task 1: Confirm the Service cleanup finalizer string** — checkpoint decision, resolved out-of-band before this session (decision: `confirm-service-cleanup`, kept `router-hosts.fzymgc.house/service-cleanup` per locked CONTEXT D-16). No code commit for this task; the decision is recorded here and in this plan's checkpoint history.
2. **Task 2: Tracer — one annotated LoadBalancer Service becomes one router DNS entry, end to end** - `144ad56` (feat)

**Plan metadata:** (this commit)

## Files Created/Modified

- `internal/operator/service_controller.go` - `ServiceReconciler`, the four annotation-key constants, `serviceCleanupFinalizer`, `serviceEnabledPredicate`, `resolveServiceIP`, `serviceDesiredHostname`, `Reconcile`, `syncService`, `addOrAdoptService`, `reconcileDelete` (stub), `SetupWithManager` (typed `For(&corev1.Service{}, ...)`)
- `internal/operator/service_controller_test.go` - `TestServiceEnabledPredicate` (7 subtests), `TestReconcileService_AddsFinalizerAndReturns`, `TestReconcileService_LoadBalancerCreatesHost`, plus `newServiceReconciler`/`newTrackedService` test helpers; reuses the package-level `mockHostClient` and `testScheme(t)` from `hostmapping_controller_test.go`
- `cmd/operator/main.go` - `enableService` flag (`--enable-service`, default `false`) and a guarded `ServiceReconciler` registration block after the Gateway API block

## Decisions Made

- **Task 1 checkpoint resolved:** kept `router-hosts.fzymgc.house/service-cleanup` exactly as CONTEXT D-16 locked it. Rationale on record: it is the fourth in the established one-finalizer-per-source-kind series (`.../host-cleanup`, `.../ingressroute-cleanup`, `.../gateway-cleanup`), deliberately distinct from all three so the four controllers never contend, and the shared-finalizer alternative was rejected because it would break the three shipped finalizers and require an out-of-scope migration.
- `syncService` always calls `addOrAdoptService` for the resolved hostname rather than short-circuiting on a `prevID` found in `existingIDs` — the plan's action text scopes the read-before-write update path, per-host error accumulation, and stale-cleanup diffing to plan 04. This tracer's `syncService` is correct for the single-Reconcile "first sync" case the plan's tests assert; a *second* reconcile of an already-tracked Service would currently re-call `AddHost` and hit the `addOrAdoptService` hard-error path rather than being a no-op — expected and explicitly deferred, not a bug in this plan's scope.
- `addOrAdoptService` treats `ErrHostAlreadyExists` as a hard error (not an adoption), per the plan's explicit instruction not to approximate D-21's provenance-gated adoption here.

## Deviations from Plan

None - plan executed exactly as written, including the resolved checkpoint decision.

## Issues Encountered

None. All verification commands from the plan's `<verify>` block were run exactly as written and produced the exact expected counts:

- 3 top-level `--- PASS` lines for the three named test functions
- `TestServiceEnabledPredicate/update_annotation_removed` present and passing
- `git diff --exit-code -- go.mod go.sum` exits 0
- `task build` and `task lint` both exit 0 (0 lint issues, manifests up to date)
- `task test -- ./internal/operator/` green (full existing suite unaffected)
- All acceptance-criteria `grep -c` checks (finalizer string, four annotation constants, absence of `WatchesRawSource`/`unstructured`/`NewPredicateFuncs`/`GenerationChangedPredicate`, absence of redeclared shared constants, single `mockHostClient`, `--enable-service` wiring, byte-identical warning strings) returned exactly the counts the plan specified

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- The tracer proves both architectural risks called out in the plan's objective: the update-symmetric opt-in/opt-out predicate (D-05) and the typed `corev1.Service` reconcile path reading `status` and writing metadata back.
- Plan 02 can now expand `resolveServiceIP` into the full type matrix (NodePort, ClusterIP, ExternalName) and the four Kubernetes Events without re-deriving the finalizer/annotation lifecycle.
- Plan 04's scope is now concretely bounded by this tracer's deliberate stubs: the read-before-write update/no-op-skip path in `syncService`, per-host error accumulation, the desired-set/stale-cleanup diff (D-17), and the provenance-gated `hasServiceProvenance` adoption check (D-21) in `addOrAdoptService`.
- No blockers.

---

*Phase: 08-kubernetes-service-controller*
*Completed: 2026-07-26*

## Self-Check: PASSED

- FOUND: internal/operator/service_controller.go
- FOUND: internal/operator/service_controller_test.go
- FOUND: cmd/operator/main.go
- FOUND: .planning/phases/08-kubernetes-service-controller/08-01-SUMMARY.md
- FOUND: commit 144ad56 in git log
