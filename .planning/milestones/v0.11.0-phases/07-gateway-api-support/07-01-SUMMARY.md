---
phase: 07-gateway-api-support
plan: 01
subsystem: infra
tags: [kubernetes, gateway-api, controller-runtime, operator, k8s]

requires:
  - phase: 06-hostmapping-ingressroute
    provides: HostClient interface, requeueDelay constants, host-ids annotation lifecycle pattern (IngressRoute controller)
provides:
  - "sigs.k8s.io/gateway-api v1.6.1 pinned as a direct dependency, k8s.io/*/controller-runtime pins unchanged"
  - "genuinely scoped `task test -- -run <pattern> <package>` (previously silently ran the whole suite)"
  - "getHostIDsAnnotation/setHostIDsAnnotation widened to client.Object, shared by IngressRoute and Gateway controllers"
  - "GatewayRouteReconciler with a working HTTPRoute happy path: finalizer, host-ids annotation, resolveIP from parent Gateway status, AddHost per untracked hostname"
  - "cmd/operator --enable-gateway flag wiring gatewayv1 scheme install + SetupGatewayControllers, off by default"
affects: [07-gateway-api-support (plans 02-06)]

tech-stack:
  added: [sigs.k8s.io/gateway-api@v1.6.1]
  patterns:
    - "gatewayRouteKind{name, gvk, newObject, newList} table + gatewayKindPresent(RESTMapper) CRD-presence gate, extended per route kind in later plans"
    - "GatewayRouteReconciler mirrors IngressRouteReconciler's finalizer/annotation lifecycle shape but with typed Get (one kind per reconciler instance) instead of unstructured GVK fallback"

key-files:
  created:
    - internal/operator/gateway_controller.go
    - internal/operator/gateway_controller_test.go
  modified:
    - go.mod
    - go.sum
    - Taskfile.yml
    - internal/operator/ingressroute_controller.go
    - cmd/operator/main.go

key-decisions:
  - "D-09 confirmed at plan checkpoint: single gatewayCleanupFinalizer = router-hosts.fzymgc.house/gateway-cleanup shared across all three route kinds, not per-kind finalizers"
  - "Task 4 scope deliberately excludes UpdateHost/delete-diff logic, the Gateway watch, and the parentRefs field index — those land in plans 02, 04, and 05 respectively; syncRoute only creates untracked hostnames for the tracer"
  - "gatewayv1.SchemeGroupVersion.WithKind(...) from PATTERNS.md/RESEARCH.md is staticcheck SA1019 (deprecated); replaced with a small gatewayGroupVersionKind() helper built from the non-deprecated gatewayv1.GroupVersion"

requirements-completed: []

coverage:
  - id: D1
    description: "gateway-api v1.6.1 pinned with no k8s.io/*/controller-runtime movement; task test -- -run is genuinely scoped"
    requirement: null
    verification:
      - kind: unit
        ref: "go list -m sigs.k8s.io/gateway-api k8s.io/api k8s.io/apimachinery k8s.io/client-go sigs.k8s.io/controller-runtime"
        status: pass
      - kind: integration
        ref: "task test -- -run 'ZZZNoSuchTestPattern' ./internal/validation/"
        status: pass
    human_judgment: false
  - id: D2
    description: "getHostIDsAnnotation/setHostIDsAnnotation widened to client.Object; existing IngressRoute suite unaffected"
    requirement: null
    verification:
      - kind: unit
        ref: "internal/operator/ingressroute_controller_test.go#TestReconcile_IngressRoute_*"
        status: pass
    human_judgment: false
  - id: D3
    description: "One HTTPRoute + one IP-bearing parent Gateway produces exactly one AddHost with the resolved IP, gateway-cleanup finalizer, and host-ids annotation written"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestReconcile_HTTPRoute_CreatesHost"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestReconcile_HTTPRoute_AddsFinalizerAndReturns"
        status: pass
    human_judgment: false
  - id: D4
    description: "resolveIP walks parentRefs to the parent Gateway's status.addresses and returns the first IPAddress-typed value"
    requirement: GW-02
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestResolveIP_FromParentGateway"
        status: pass
    human_judgment: false
  - id: D5
    description: "cmd/operator installs the gateway scheme and registers Gateway API controllers only when --enable-gateway is passed"
    requirement: null
    verification:
      - kind: unit
        ref: "task build && task lint (0 issues)"
        status: pass
    human_judgment: true
    rationale: "The --enable-gateway opt-in gate has no live-cluster integration test in this plan; confirmed by code inspection and build/lint, not an automated end-to-end run against a real manager."

duration: 40min
completed: 2026-07-26
status: complete
---

# Phase 7 Plan 01: Tracer — HTTPRoute Hostname to Router DNS Entry Summary

**GatewayRouteReconciler's HTTPRoute happy path resolves one hostname to one router DNS entry via the parent Gateway's status.addresses, with gateway-api v1.6.1 pinned and the operator gated behind `--enable-gateway`**

## Performance

- **Duration:** ~40 min of active execution (plus a checkpoint pause for the D-09 finalizer-string decision)
- **Started:** 2026-07-26T15:33:24Z (Task 1 commit)
- **Completed:** 2026-07-26T16:13:10Z (Task 4 commit)
- **Tasks:** 4 (2 auto, 1 checkpoint:decision, 1 tracer/tdd)
- **Files modified:** 6

## Accomplishments

- Pinned `sigs.k8s.io/gateway-api v1.6.1` with zero `k8s.io/*`/`controller-runtime` version movement, and fixed `Taskfile.yml`'s `test` task so `task test -- -run <pattern> <package>` genuinely scopes runs instead of silently discarding the filter
- Widened `getHostIDsAnnotation`/`setHostIDsAnnotation` from `*unstructured.Unstructured` to `client.Object` (signature-only, behavior-neutral) so the IngressRoute and Gateway controllers share one annotation mechanism
- Confirmed the one-way-door finalizer decision at the plan's blocking checkpoint: `router-hosts.fzymgc.house/gateway-cleanup`, one finalizer for all three route kinds
- Built `GatewayRouteReconciler` with a working HTTPRoute happy path (RED→GREEN TDD): typed `Get`, finalizer add/return, `resolveIP` walking `parentRefs` to the parent Gateway's `status.addresses`, and `syncRoute` creating one host entry per untracked hostname with comment `k8s-gateway:<ns>/<name>` and tags `kubernetes`+`gateway`+`httproute`
- Wired `cmd/operator/main.go`: `gatewayv1.Install(scheme)`, new `--enable-gateway` flag, `SetupGatewayControllers` called only when the flag is set, widened `--default-ingress-ip` help text and empty-IP warning to name both controllers

## Task Commits

Each task was committed atomically:

1. **Task 1: Pin gateway-api v1.6.1 and make scoped test runs actually scoped** - `6860560` (build)
2. **Task 2: Widen the shared host-ids annotation helpers to client.Object** - `5ec135e` (refactor)
3. **Task 3: Checkpoint — confirm Gateway route cleanup finalizer string** - no commit (decision gate; user selected `confirm-gateway-cleanup`)
4. **Task 4: Tracer — one HTTPRoute hostname becomes one router DNS entry, end to end** (TDD):
   - RED: `95e6b42` (test) — 5 failing tests, fails to compile
   - GREEN: `807a9e8` (feat) — `GatewayRouteReconciler` implemented, all 5 tests pass
   - REFACTOR: none needed

**Plan metadata:** (this commit)

## Files Created/Modified

- `internal/operator/gateway_controller.go` - `GatewayRouteReconciler`, `hostnamesOf`/`parentRefsOf`/`extractHostnames` (HTTPRoute-only for now), `resolveIP`, `syncRoute`, `gatewayKindPresent`, `SetupGatewayControllers`/`SetupWithManager`
- `internal/operator/gateway_controller_test.go` - `gatewayScheme` helper, 5 unit/integration tests reusing `mockHostClient` from `hostmapping_controller_test.go`
- `internal/operator/ingressroute_controller.go` - `getHostIDsAnnotation`/`setHostIDsAnnotation` parameter type widened to `client.Object` (D-11)
- `cmd/operator/main.go` - gateway scheme install, `--enable-gateway` flag, gated `SetupGatewayControllers` call, widened help/warning text
- `go.mod` / `go.sum` - `sigs.k8s.io/gateway-api v1.6.1` (direct after `go mod tidy` once the import landed)
- `Taskfile.yml` - `test` task now honors `TEST_ARGS: '{{.CLI_ARGS | default "./..."}}'`

## Decisions Made

- **D-09 confirmed at checkpoint:** single `gatewayCleanupFinalizer = router-hosts.fzymgc.house/gateway-cleanup` for all three route kinds (not per-kind finalizers). Locked, one-way door — this string is now safe to write to live cluster objects.
- **Task 4 scope boundary:** `syncRoute` only creates entries for untracked hostnames (no `UpdateHost`, no stale-delete diff) per the plan's explicit tracer-scope text; that logic is deferred to plan 04. `SetupWithManager` has no `Watches` clause and no field index yet — those land in plan 05.
- **Deprecated API avoided:** `gatewayv1.SchemeGroupVersion.WithKind(...)` (used verbatim in `07-PATTERNS.md`/`07-RESEARCH.md`'s code sketches) trips staticcheck SA1019. Replaced with a local `gatewayGroupVersionKind()` helper built from the non-deprecated `gatewayv1.GroupVersion` (a `metav1.GroupVersion`, which has no `WithKind` method — hence the small wrapper rather than a one-line substitution).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Deprecated `gatewayv1.SchemeGroupVersion.WithKind` trips staticcheck SA1019**

- **Found during:** Task 4, `task lint`
- **Issue:** The plan's own pattern/research docs specify `gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute")` for `gatewayRouteKinds()`, but `SchemeGroupVersion` is marked `Deprecated: use GroupVersion instead` in v1.6.1, and this repo's `.golangci.yml` includes `staticcheck` in its standard linter set, so `task lint` failed with `SA1019`.
- **Fix:** Added `gatewayGroupVersionKind(kind string) schema.GroupVersionKind`, built from `gatewayv1.GroupVersion.Group`/`.Version` (the non-deprecated `metav1.GroupVersion`, which lacks a `WithKind` method), and used it in `gatewayRouteKinds()`.
- **Files modified:** `internal/operator/gateway_controller.go`
- **Verification:** `task lint` → `0 issues`; `task build` and the full scoped test run both still pass.
- **Committed in:** `807a9e8` (part of Task 4's GREEN commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — lint-blocking bug)
**Impact on plan:** Purely a lint-compliance substitution with identical runtime behavior (`gatewayGroupVersionKind("HTTPRoute")` produces the same `schema.GroupVersionKind` value `SchemeGroupVersion.WithKind("HTTPRoute")` would have). No scope creep.

## Issues Encountered

Lefthook's pre-commit hook order (`lint-markdown`/`gofumpt` before `fmt-markdown`) meant the Task 4 GREEN commit initially failed because gofumpt reformatted `cmd/operator/main.go`'s multi-arg `logger.Info(...)` call (an existing line, reformatted due to the new lines added nearby pushing it over gofumpt's wrapping threshold); re-running the identical commit after the auto-fix succeeded, per the known repo quirk.

## User Setup Required

None - no external service configuration required. `--enable-gateway` is off by default; enabling it in a live cluster requires Gateway API CRDs to be installed, which is unchanged infrastructure setup outside this plan's scope.

## Next Phase Readiness

Plans 02-06 build directly on this tracer:

- **Plan 02** adds GRPCRoute/TLSRoute to `gatewayRouteKinds()`, `hostnamesOf`/`parentRefsOf` arms, and `extractHostnames` validation/wildcard filtering.
- **Plan 03** expands `resolveIP`'s error/fallback matrix (GW-02).
- **Plan 04** adds the update/delete diff and per-host error accumulation to `syncRoute`, and fills in `reconcileDelete` (currently a stub).
- **Plan 05** adds the `parentRefIndexKey` field index and the CRD-gated Gateway watch in `SetupWithManager`.
- **Plan 06** — GW-03 (Helm chart / RBAC).

No blockers. `requirements-completed` is intentionally left empty in this SUMMARY's frontmatter: GW-01 and GW-02 are each split across multiple plans in `.planning/REQUIREMENTS.md`'s traceability table (GW-01 also in plan 02/04; GW-02 also in plan 03/05), and this plan only delivers the HTTPRoute happy path — marking either requirement complete now would be premature. They should be marked complete once their full plan sets land.

---

*Phase: 07-gateway-api-support*
*Completed: 2026-07-26*

## Self-Check: PASSED

All created/modified files present on disk; all four task commits (`6860560`, `5ec135e`, `95e6b42`, `807a9e8`) verified present in `git log --oneline --all`.
