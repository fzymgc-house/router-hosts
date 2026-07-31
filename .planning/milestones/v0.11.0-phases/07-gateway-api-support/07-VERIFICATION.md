---
phase: 07-gateway-api-support
verified: 2026-07-26T21:54:32Z
status: passed
score: 16/16 must-haves verified
behavior_unverified: 0
overrides_applied: 0
---

# Phase 7: Gateway API Support Verification Report

**Phase Goal:** Gateway API routes auto-populate router DNS, closing the largest operator-parity gap toward the north star.
**Verified:** 2026-07-26T21:54:32Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Creating an HTTPRoute, GRPCRoute, or TLSRoute results in router DNS entries for each of its hostnames | ✓ VERIFIED | `gatewayRouteKinds()` (gateway_controller.go:60-81) lists all three kinds sharing one `GatewayRouteReconciler`; `hostnamesOf`/`parentRefsOf` (lines 85-122) switch on all three concrete types; `extractHostnames` (lines 214-238) filters wildcards/dupes/invalid names before any `HostClient` call; `syncRoute` create branch calls `addOrAdoptGatewayHost`→`AddHost`. Verified via `TestReconcile_HTTPRoute_CreatesHost`, `TestHostnamesOf_AllThreeKinds` (line ~408), `TestReconcile_Route_DeleteAllThreeKinds` — all pass (`go test ./internal/operator/...` green). |
| 2 | Route entry IPs are resolved from the parent Gateway's `status.addresses` | ✓ VERIFIED | `resolveIP` (lines 379-404) walks `parentRefsOf` in order, `r.Get`s each Gateway, and returns the first `IPAddressType` address; falls back to `r.DefaultIP`. Directly wired as the sole IP source for `AddHost`/`UpdateHost` in `syncRoute`. Confirmed by passing tests `TestResolveIP_*` (ordering, namespace defaulting, Hostname-type skip, NotFound-skip-continue, fallback). |
| 3a | Deleting or editing a route updates/removes the corresponding DNS entries | ✓ VERIFIED | `syncRoute`'s diff loop (create/update/stale-delete, lines 431-568) and `reconcileDelete` (lines 313-360, deletes-before-finalizer-removal). Confirmed by `TestSyncRoute_UpdatesTrackedHostnames`, `TestSyncRoute_DeletesRemovedHostnames`, `TestReconcile_HTTPRoute_DeletesHostsOnFinalize`, `TestReconcile_Route_PartialDeleteKeepsFinalizerAndRequeues`, `TestReconcile_Route_DeleteCorruptAnnotationRequeues`, `TestReconcile_Route_DeleteAllThreeKinds` — all pass. |
| 3b | The shipped Helm chart + RBAC grant the operator watch/list access to Gateway API resources | ✓ VERIFIED | `charts/router-hosts-operator/templates/clusterrole.yaml` grants `get,list,watch,update,patch` on `httproutes;grpcroutes;tlsroutes` and `get,list,watch` on `gateways`, matching the `+kubebuilder:rbac` markers at gateway_controller.go:264-265 exactly. `deployment.yaml` renders `--enable-gateway` only when `.Values.gateway.enabled`; `values.yaml` defaults `gateway.enabled: false`. Confirmed live with `helm template`: `gateway.enabled=true` → flag present; default → flag absent; `rbac.create=false` → zero ClusterRole objects rendered (0 matches for all three checks, run directly against the chart in this verification session). |

**Score:** 4/4 roadmap success criteria verified (5 sub-criteria counted; SC3 has two independently-verified clauses).

### Must-Have Truths (PLAN frontmatter, merged across all 6 plans)

| # | Truth (abbreviated) | Status | Evidence |
|---|------|--------|----------|
| 1 | Single-hostname HTTPRoute + status IP → one AddHost with correct comment/tags (D-12) | ✓ VERIFIED | `TestReconcile_HTTPRoute_CreatesHost` passes; comment format `k8s-gateway:<ns>/<name>` and tags `DefaultTags + "gateway" + KindName` at lines 440-445. |
| 2 | Finalizer `router-hosts.fzymgc.house/gateway-cleanup` + host-ids annotation after reconcile (D-09/D-10) | ✓ VERIFIED | Constant at line 32 matches 07-CONTEXT.md D-09 verbatim (one-way-door string confirmed unchanged from user-approved decision). `TestReconcile_HTTPRoute_AddsFinalizerAndReturns` passes. |
| 3 | No-op reconcile issues no Update; interrupted batch persists partial IDs (D-13/D-14) | ✓ VERIFIED | `maps.Equal` guard at line 553; `TestSyncRoute_SkipsUpdateWhenNothingChanged`, `TestSyncRoute_RetainsPriorIDOnUpdateFailure` pass. |
| 4 | go.mod pins gateway-api v1.6.1, k8s.io/* stay v0.36.1 (D-01/D-03) | ✓ VERIFIED | `go.mod` lines 24-26, 29 confirmed directly. |
| 5 | `task test -- -run <pattern> <pkg>` restricts run scope | ✓ VERIFIED | `Taskfile.yml` `TEST_ARGS: '{{.CLI_ARGS | default "./..."}}'`, confirmed correct per 07-REVIEW.md's independent check against Task's `CLI_ARGS` semantics. |
| 6 | All Gateway tests in one file, reusing `mockHostClient`, coverage ≥80% (D-20) | ✓ VERIFIED | `gateway_controller_test.go` is the sole test file; `task test:coverage:ci` run live in this session → 84.9%. |
| 7 | All 3 kinds share one reconciler; `gatewayRouteKinds()` lists exactly 3 (D-02) | ✓ VERIFIED | Code + `TestGatewayRouteKinds_*` (line ~450) confirm HTTPRoute/GRPCRoute/TLSRoute in order. |
| 8 | Wildcard hostname skipped (D-18) | ✓ VERIFIED | `extractHostnames` line 218-220; tested. |
| 9 | Invalid hostname logged+skipped, not fatal (D-18) | ✓ VERIFIED | Lines 226-229; tested. |
| 10 | Duplicate hostnames → one entry (D-18) | ✓ VERIFIED | `seen` map lines 215, 221-224; tested. |
| 11 | Dot-less hostname warned + accepted (D-19) | ✓ VERIFIED | Lines 231-233; tested. |
| 12 | All-skipped route → no entries, zero Result, nil error | ✓ VERIFIED | Empty `hostnames` produces empty `newIDs`/no-op path; covered by extractHostnames edge tests. |
| 13 | resolveIP: declaration-order first-IP-wins; Hostname-type skipped; namespace default/explicit; Gateway NotFound skip-continue, non-NotFound logged-continue; empty→DefaultIP→requeue-short (D-15/D-16) | ✓ VERIFIED | Lines 379-404 implement exactly this; full `TestResolveIP_*` suite passes. |
| 14 | Edit converges (add/update/delete); unconditional UpdateHost (D-13); skip-Update-when-equal; delete-before-finalizer-drop; partial-delete persists+requeues (D-14); corrupt annotation fails closed (D-14); deletion only from own annotation (adjacency); cross-route hostname collision handled per-host (backstop) | ✓ VERIFIED | All confirmed in code (lines 431-568, 313-360) and by the full `TestSyncRoute_*`/`TestReconcile_Route_*` suite, including `TestSyncRoute_NeverDeletesUntrackedID` and `TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete`, both passing. |
| 15 | Gateway change re-enqueues referencing routes only (D-17); zero-CRD → zero controllers, nil error (GW-03/D-04); non-v1 version skipped (D-05); route-CRD-only cluster starts cleanly without Gateway watch (Pitfall 1); Gateway status change re-enqueues, no self-concurrency, stale Update returns conflict→requeue | ✓ VERIFIED (concurrency clause: presence + standard error-propagation, not a custom invariant) | `routeParentRefIndexFunc`, `mapGatewayToRoutes`, `gatewayKindPresent`, `watchGateway` threading (lines 130-200, 604-680) confirmed; `TestMapGatewayToRoutes_*`, `TestGatewayKindPresent_*`, `TestSetupWithManager_WatchGatewayFlagIsThreaded` all pass. The "never reconciled concurrently with itself" / "conflict error requeues" clause rests on controller-runtime's own per-key serialization and this code's existing generic `r.Update` error → `oops.Wrapf` → returned-error → controller-runtime-requeues path (already exercised by `TestSyncRoute_RecoversFromCreateSucceedsThenAnnotationUpdateFails`'s induced `r.Update` failure), not a phase-specific state machine — no additional custom invariant exists here to leave unverified. |
| 16 | Helm/RBAC: route verbs, Gateway read-only verbs, conditional `--enable-gateway`, `gateway.enabled: false` default + CRD-prerequisite doc, README coverage, `rbac.create=false` → no ClusterRole | ✓ VERIFIED | `clusterrole.yaml`, `deployment.yaml`, `values.yaml` all confirmed by direct read + live `helm template` runs (three scenarios, all correct). `README.md` documents the CRD prerequisite, `gateway.enabled`, RBAC rules, and Gateway-derived host tags (lines 16-17, 119-155, 206-234, 302-305). |

**Score:** 16/16 must-haves verified (0 present-but-behavior-unverified).

### Code Review Findings — Fix Verification

The phase's own code review (`07-REVIEW.md`) found 4 Critical + 2 Warning issues in un-happy-path `ErrHostNotFound`/`ErrHostAlreadyExists` handling — exactly the class of bug the verification brief flagged as likely to be missed by self-reported executor gates. Each was independently re-verified against the current source (not just the SUMMARY/REVIEW-FIX narrative) and confirmed fixed:

| Finding | Fix confirmed in source | Regression test | Result |
|---------|--------------------------|------------------|--------|
| CR-01 (no-IP skips stale cleanup) | Lines 447-460: stale-cleanup pass now runs unconditionally; only create/update gated on `ip != ""` | `TestSyncRoute_NoIPStillPrunesStaleEntries` | PASS |
| CR-02 (AddHost success + annotation persist fail → orphan) | `addOrAdoptGatewayHost` (lines 581-602) adopts on `ErrHostAlreadyExists` via `FindHost` | `TestSyncRoute_AdoptsExistingHostOnAlreadyExists`, `TestSyncRoute_RecoversFromCreateSucceedsThenAnnotationUpdateFails` | PASS |
| CR-03 (DeleteHost NotFound wedges finalizer) | Lines 327-341: `errors.Is(err, ErrHostNotFound)` → `continue`, not folded into `remainingIDs`/`hadDeleteError` | `TestReconcile_Route_DeleteTreatsNotFoundAsSuccess` | PASS |
| CR-04 (Delete/Update NotFound wedges annotation) | Lines 474-501 (update self-heals via recreate), 531-546 (stale-delete drops rather than retains) | `TestSyncRoute_StaleDeleteNotFoundDropsFromAnnotation`, `TestSyncRoute_UpdateNotFoundRecreatesEntry` | PASS |
| WR-01 (misleading warning when Gateway disabled) | `defaultIngressIPWarning(enableGateway bool)` (main.go:167-172) | `TestDefaultIngressIPWarning_NamesOnlyRegisteredControllers` (cmd/operator/main_test.go) | PASS (main.go tests not re-run individually but `task test` full-suite green) |
| WR-02 (no Kind filter on parentRef) | `isGatewayKindRef` (lines 160-165) applied in both `routeParentRefIndexFunc` and `resolveIP` | `TestRouteParentRefIndexFunc_SkipsNonGatewayKind`, `TestResolveIP_SkipsNonGatewayKindParentRef` | PASS |

All 8 named regression tests were executed directly in this verification session (`go test ./internal/operator/... -run '...' -v`) — every one passed, with log output confirming the expected adoption/self-heal/prune/skip behavior actually fired (not just that the test function returned green).

**IN-01** (unconditional `remainingIDs` allocation): confirmed still present at line 323 — correctly left unfixed per its Info severity and explicit fix-scope exclusion. Cosmetic only; does not affect goal achievement.

**Pre-existing, out-of-phase gap**: `ingressroute_controller.go`'s `reconcileDelete` has the identical `ErrHostNotFound` gap CR-03 fixed in the new controller. Confirmed still present and unmodified — correctly recorded as a follow-up in `07-REVIEW-FIX.md`, not introduced by this phase, and does not block this phase's goal (`ingressroute_controller.go` is out of this phase's file scope).

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/operator/gateway_controller.go` | Full reconciler for 3 route kinds | ✓ VERIFIED | 680 lines, no stubs, no debt markers (`rg` scan for TBD/FIXME/XXX/TODO/HACK/PLACEHOLDER — zero hits) |
| `internal/operator/gateway_controller_test.go` | Full test coverage | ✓ VERIFIED | 60+ test functions, all pass |
| `cmd/operator/main.go` | Scheme install + opt-in wiring | ✓ VERIFIED | `gatewayv1.Install`, `--enable-gateway` flag, gated `SetupGatewayControllers` call |
| `charts/router-hosts-operator/templates/clusterrole.yaml` | Route + Gateway RBAC | ✓ VERIFIED | Verbs match kubebuilder markers exactly |
| `charts/router-hosts-operator/templates/deployment.yaml` | Conditional `--enable-gateway` | ✓ VERIFIED | `{{- if .Values.gateway.enabled }}` |
| `charts/router-hosts-operator/values.yaml` | `gateway.enabled: false` default | ✓ VERIFIED | Line 55-56 |
| `charts/router-hosts-operator/README.md` | Prerequisite + value + RBAC + tags docs | ✓ VERIFIED | All four topics present |
| `go.mod` | gateway-api v1.6.1, k8s.io/* v0.36.1 | ✓ VERIFIED | Confirmed directly |

### Key Link Verification

| From | To | Via | Status |
|------|-----|-----|--------|
| `cmd/operator/main.go` | `operator.SetupGatewayControllers` | `if enableGateway { ... }` (line 128) | WIRED |
| `values.yaml gateway.enabled` | `deployment.yaml --enable-gateway` | Helm `if` conditional | WIRED (confirmed via `helm template`) |
| `extractHostnames` | every route kind's `HostClient` call | Sole filter before `syncRoute`'s loop (line 291) | WIRED |
| `gatewayRouteKinds()` | `SetupGatewayControllers` loop | Single source of truth for per-kind controller construction | WIRED |
| `parentRefIndexKey` | `routeParentRefIndexFunc` (writer) / `mapGatewayToRoutes` (reader) | `mgr.GetFieldIndexer().IndexField` / `client.MatchingFields` | WIRED |
| `getHostIDsAnnotation`/`setHostIDsAnnotation` | `syncRoute` and `reconcileDelete` | Shared `client.Object`-typed helpers (D-11) | WIRED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Build both binaries | `task build` | Both `bin/router-hosts` and `bin/operator` built cleanly | ✓ PASS |
| Lint | `golangci-lint run ./internal/operator/... ./cmd/operator/...` | 0 issues | ✓ PASS |
| 8 named regression tests (review-fix verification) | `go test ./internal/operator/... -run '<8-name-pattern>' -v` | All 8 PASS with correct log output | ✓ PASS |
| Full operator + cmd/operator suite | `go test ./internal/operator/... ./cmd/operator/... -race -count=1` | `ok` both packages | ✓ PASS |
| Coverage threshold | `task test:coverage:ci` | 84.9% (≥80%) | ✓ PASS |
| Helm render: gateway.enabled=true | `helm template ... --set gateway.enabled=true` | `--enable-gateway` present in container args | ✓ PASS |
| Helm render: default values | `helm template ...` | `--enable-gateway` absent | ✓ PASS |
| Helm render: rbac.create=false | `helm template ... --set rbac.create=false` | Zero `ClusterRole` objects rendered | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| GW-01 | 07-01, 07-02, 07-04 | Operator reconciles HTTPRoute/GRPCRoute/TLSRoute hostnames into router DNS entries | ✓ SATISFIED | `gatewayRouteKinds()`, `syncRoute`, full lifecycle test suite |
| GW-02 | 07-01, 07-03, 07-05 | Operator resolves route IPs from parent Gateway's `status.addresses` | ✓ SATISFIED | `resolveIP`, `mapGatewayToRoutes`, field index |
| GW-03 | 07-05, 07-06 | Helm chart and RBAC grant watch/list access to Gateway API route resources | ✓ SATISFIED | `clusterrole.yaml`, `values.yaml`, `deployment.yaml`, CRD-presence gating |

REQUIREMENTS.md correctly marks all three as Complete (lines 48-51, 119-121). No orphaned requirement IDs found for Phase 7 — every ID declared across the 6 plans' frontmatter (`[GW-01, GW-02]`, `[GW-01]` ×2, `[GW-02]`, `[GW-02, GW-03]`, `[GW-03]`) accounts for all three IDs listed against Phase 7 in REQUIREMENTS.md's traceability table.

### Anti-Patterns Found

None. Scanned `gateway_controller.go`, `gateway_controller_test.go`, `main.go`, and all four modified chart files for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER` — zero hits. No debt markers, no stub returns, no hardcoded-empty data flowing to output.

### Human Verification Required

None. All must-haves resolved to VERIFIED via direct code inspection, live command execution (build/lint/test/coverage/helm template), and passing named regression tests — no items required deferral to human judgment.

### Gaps Summary

No gaps. All 4 Critical and 2 Warning code-review findings were independently confirmed fixed in the current source, with their regression tests re-executed live in this session and passing (not merely trusted from REVIEW-FIX.md's narrative). All 3 ROADMAP success criteria and all 16 merged PLAN must-have truths are verified. The one Info-level finding (IN-01) and one pre-existing out-of-phase gap (`ingressroute_controller.go`'s identical `ErrHostNotFound` issue) are correctly left unfixed per explicit, documented scope decisions and do not block the phase goal.

---

_Verified: 2026-07-26T21:54:32Z_
_Verifier: Claude (gsd-verifier)_
