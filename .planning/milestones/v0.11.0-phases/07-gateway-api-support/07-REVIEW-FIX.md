---
phase: 07-gateway-api-support
fixed_at: 2026-07-26T21:49:23Z
review_path: .planning/phases/07-gateway-api-support/07-REVIEW.md
iteration: 1
findings_in_scope: 6
fixed: 6
skipped: 0
status: all_fixed
---

# Phase 07: Code Review Fix Report

**Fixed at:** 2026-07-26T21:49:23Z
**Source review:** .planning/phases/07-gateway-api-support/07-REVIEW.md
**Iteration:** 1

**Summary:**

- Findings in scope: 6 (4 critical, 2 warning — IN-01 out of scope per fix_scope)
- Fixed: 6
- Skipped: 0

## Fixed Issues

### CR-01: `syncRoute`'s no-IP early return skips stale-entry cleanup indefinitely

**Files modified:** `internal/operator/gateway_controller.go`, `internal/operator/gateway_controller_test.go`
**Commit:** `986546b`
**Applied fix:** Restructured `syncRoute` so `resolveIP`/`getHostIDsAnnotation` are always read and the stale-cleanup pass always runs; only the create/update loop is now gated on `ip != ""`. When no IP resolves, every hostname still declared in the spec is carried into `newIDs` unchanged (so it isn't mistaken for removed), while hostnames actually dropped from the spec are still deleted from the router. Preserved the existing `requeueDelayShort` result for the no-IP case (matching prior behavior/tests) versus `requeueDelayLong` for other per-host failures. Added `TestSyncRoute_NoIPStillPrunesStaleEntries`, which fails against the pre-fix code and asserts `DeleteHost` is called for a hostname removed from the spec even when the route's IP is unresolvable.

### CR-02: Orphaned, un-adoptable host entry when `AddHost` succeeds but the annotation persist fails

**Files modified:** `internal/operator/gateway_controller.go`, `internal/operator/gateway_controller_test.go`
**Commit:** `e56f80d`
**Applied fix:** Added `addOrAdoptGatewayHost`, ported from `ingressroute_controller.go`'s `addOrAdopt`: on `AddHost` returning `ErrHostAlreadyExists`, it calls `FindHost` and adopts the existing entry's ID instead of treating the reply as a fatal, non-recoverable create failure. Wired this into `syncRoute`'s create branch. Added `TestSyncRoute_AdoptsExistingHostOnAlreadyExists` (direct unit coverage of the adoption path) and `TestSyncRoute_RecoversFromCreateSucceedsThenAnnotationUpdateFails` (end-to-end: `AddHost` succeeds, the annotation `r.Update` is made to fail via `interceptor.Funcs`, and the next reconcile's retried `AddHost` returns `AlreadyExists` — asserting the originally-created ID is adopted, not orphaned).

### CR-03: `DeleteHost` `NotFound` treated as a real failure in `reconcileDelete`

**Files modified:** `internal/operator/gateway_controller.go`, `internal/operator/gateway_controller_test.go`
**Commit:** `0aa0e65`
**Applied fix:** `reconcileDelete`'s delete loop now special-cases `errors.Is(err, ErrHostNotFound)`: it logs and `continue`s rather than adding the ID to `remainingIDs`/setting `hadDeleteError`, so an already-gone entry no longer wedges the finalizer forever. Added `TestReconcile_Route_DeleteTreatsNotFoundAsSuccess`, asserting the finalizer is removed and the object becomes `NotFound` (via the fake client, mirroring the real API server) after a full `Reconcile` where `DeleteHost` always returns `ErrHostNotFound`.

**Note (out of scope per review):** `ingressroute_controller.go`'s `reconcileDelete` has the identical gap, pre-existing and unmodified in this phase. Not fixed here per the review's explicit scope note — flagged below as a recommended follow-up.

### CR-04: `DeleteHost`/`UpdateHost` `NotFound` mishandling in `syncRoute`

**Files modified:** `internal/operator/gateway_controller.go`, `internal/operator/gateway_controller_test.go`
**Commit:** `7771ea9`
**Applied fix:** Two changes to `syncRoute`, both gated on `errors.Is(err, ErrHostNotFound)`: (1) the stale-cleanup pass's `DeleteHost` NotFound case now logs and drops the hostname entirely rather than retaining it in `newIDs` — retaining it made `newIDs` equal `existingIDs` again on the next reconcile, permanently skipping the annotation write via the `!maps.Equal` guard; (2) the update branch's `UpdateHost` NotFound case now recreates the entry via `addOrAdoptGatewayHost` (mirroring `ingressroute_controller.go`'s `syncHost` self-heal) instead of retaining a dead ID that could never successfully update again. The unconditional-update design (D-13) is preserved — only the NotFound branch was added, no idempotency guard was introduced. Added `TestSyncRoute_StaleDeleteNotFoundDropsFromAnnotation` and `TestSyncRoute_UpdateNotFoundRecreatesEntry`, covering each half independently.

### WR-01: `--default-ingress-ip` empty-string warning names Gateway API controllers even when disabled

**Files modified:** `cmd/operator/main.go`, `cmd/operator/main_test.go` (new)
**Commit:** `21582cd`
**Applied fix:** Extracted the warning-message logic into a pure `defaultIngressIPWarning(enableGateway bool) string` helper that only names the Gateway API controllers when `enableGateway` is true, and switched the call site in `run()` to use it. Added `cmd/operator/main_test.go` (previously no test file existed for this package) with `TestDefaultIngressIPWarning_NamesOnlyRegisteredControllers`, covering both the `enableGateway=false` and `enableGateway=true` message variants.

### WR-02: `parentRefsOf`/`routeParentRefIndexFunc`/`resolveIP` do not filter on `ParentReference.Kind`

**Files modified:** `internal/operator/gateway_controller.go`, `internal/operator/gateway_controller_test.go`
**Commit:** `745df3f`
**Applied fix:** Added an `isGatewayKindRef` helper (`ref.Kind == nil || string(*ref.Kind) == "Gateway"`, matching the Gateway API spec's `+kubebuilder:default=Gateway` on `ParentReference.Kind`) and applied it identically in both `routeParentRefIndexFunc` and `resolveIP`'s loop, skipping any parentRef naming a non-Gateway kind (e.g. a GAMMA-style Service mesh parent) before it reaches the field index or a wasted `Get` call. Added `TestRouteParentRefIndexFunc_SkipsNonGatewayKind` and `TestResolveIP_SkipsNonGatewayKindParentRef`.

## Recommended Follow-up (not fixed, out of scope)

- **`ingressroute_controller.go`'s `reconcileDelete`** has the same `DeleteHost` `NotFound`-as-failure gap CR-03 fixed in `gateway_controller.go`. It predates this phase and was explicitly called out in the review as out of scope for this fix pass. Recommend either porting the identical `errors.Is(err, ErrHostNotFound)` fix there, or extracting the two controllers' near-identical delete loops into one shared helper so future route kinds cannot reintroduce the gap.

## Verification

All three required checks were run against the fully fixed tree and passed:

- `task build` — both binaries build cleanly.
- `task lint` — `golangci-lint run ./...` reports 0 issues; `buf lint`/`buf format --diff` clean; `manifests:verify` confirms generated CRDs/deepcopy are up to date.
- `task test:coverage:ci` — all `internal/...` packages pass under `-race`; overall coverage **84.9%** (unchanged from the pre-fix baseline stated for this phase, well above the 80% threshold).
- `task test` (full `./...`, including `cmd/operator`, not covered by the `internal/...`-scoped coverage target) — all packages pass under `-race`.

---

_Fixed: 2026-07-26T21:49:23Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
