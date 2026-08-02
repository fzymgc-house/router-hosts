---
phase: 07-gateway-api-support
plan: 02
subsystem: infra
tags: [kubernetes, gateway-api, controller-runtime, operator, k8s]

requires:
  - phase: 07-gateway-api-support
    provides: "GatewayRouteReconciler HTTPRoute tracer, gatewayRouteKinds() table shape, extractHostnames stub (plan 07-01)"
provides:
  - "gatewayRouteKinds() covering httproute, grpcroute, tlsroute — all sourced from sigs.k8s.io/gateway-api/apis/v1"
  - "hostnamesOf/parentRefsOf type switches with arms for HTTPRoute, GRPCRoute, and TLSRoute"
  - "extractHostnames enforcing D-18 (wildcard skip, de-dup, validation.ValidateHostname) and D-19 (dot-less warn-and-accept)"
affects: ["07-gateway-api-support (plans 03-05 build directly on this)"]

tech-stack:
  added: []
  patterns:
    - "hostnamesFrom([]gatewayv1.Hostname) []string helper shared by all three hostnamesOf arms, since HTTPRouteSpec/GRPCRouteSpec/TLSRouteSpec declare an identically shaped Hostnames field"
    - "extractHostnames filter order: wildcard skip -> de-dup (seen map, first-appearance order) -> validation.ValidateHostname -> dot-less Warn-and-accept"

key-files:
  created: []
  modified:
    - internal/operator/gateway_controller.go
    - internal/operator/gateway_controller_test.go

key-decisions:
  - "GW-01 NOT marked complete in REQUIREMENTS.md: this plan delivers the three-kind reconcile surface and hostname filtering, but syncRoute's update/delete diff (the rest of GW-01's lifecycle) lands in plan 04, per 07-01-SUMMARY's explicit note not to mark GW-01 complete until its full plan set lands."
  - "extractHostnames marks a hostname 'seen' immediately after the wildcard check, before validation — so a repeated invalid hostname produces exactly one Warn log instead of one per repetition. Not specified by the plan either way; chosen for cleaner log output without changing observable de-dup behavior."

requirements-completed: []

coverage:
  - id: T1
    description: "gatewayRouteKinds() has 3 entries (httproute, grpcroute, tlsroute), all at gateway.networking.k8s.io/v1, with matching newObject/newList factories"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestGatewayRouteKinds_CoversThreeKinds"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestGatewayScheme_InstallsAllRouteKinds"
        status: pass
    human_judgment: false
  - id: T2
    description: "hostnamesOf and parentRefsOf return the same shapes for HTTPRoute, GRPCRoute, and TLSRoute, and nil for a non-route object (Gateway)"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestHostnamesOf_AllKinds"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestParentRefsOf_AllKinds"
        status: pass
    human_judgment: false
  - id: T3
    description: "A wildcard hostname is skipped and never becomes a router DNS entry (D-18)"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestExtractHostnames_SkipsWildcards"
        status: pass
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestExtractHostnames_AllSkipped"
        status: pass
    human_judgment: false
  - id: T4
    description: "A hostname that fails validation.ValidateHostname is logged and skipped without aborting the batch (D-18)"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestExtractHostnames_SkipsInvalid"
        status: pass
    human_judgment: false
  - id: T5
    description: "Duplicate hostnames within one route produce exactly one host entry, first-appearance order"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestExtractHostnames_DeDuplicates"
        status: pass
    human_judgment: false
  - id: T6
    description: "A dot-less hostname is warned about and accepted (D-19)"
    requirement: GW-01
    verification:
      - kind: unit
        ref: "internal/operator/gateway_controller_test.go#TestExtractHostnames_AcceptsDotlessWithWarning"
        status: pass
    human_judgment: false
  - id: T7
    description: "No deprecated apis/v1alpha* Gateway API package is imported anywhere in the operator; task build/lint/coverage all green"
    requirement: null
    verification:
      - kind: unit
        ref: "grep -v '^\\s*//' internal/operator/gateway_controller.go | grep -c 'gateway-api/apis/v1alpha' -> 0; task build && task lint && task test:coverage:ci"
        status: pass
    human_judgment: false

duration: 35min
completed: 2026-07-26
status: complete
---

# Phase 7 Plan 02: All Three Route Kinds and Hostname Filtering Summary

**`gatewayRouteKinds()`, `hostnamesOf`, and `parentRefsOf` now cover HTTPRoute, GRPCRoute, and TLSRoute uniformly from `apis/v1`, and `extractHostnames` is the single filter (wildcard skip, de-dup, `ValidateHostname`, dot-less warn) every hostname passes through before any `HostClient` call**

## Performance

- **Duration:** ~35 min of active execution
- **Started:** 2026-07-26T09:20Z (Task 1 RED commit `e6f92c2`)
- **Completed:** 2026-07-26T09:35Z (Task 2 GREEN commit `32e0c55`)
- **Tasks:** 2 (both TDD: RED -> GREEN)
- **Files modified:** 2

## Accomplishments

- Extended `gatewayRouteKinds()` from the plan 01 tracer's single HTTPRoute
  entry to all three kinds (`httproute`, `grpcroute`, `tlsroute`), each backed
  by typed `newObject`/`newList` factories and `gatewayGroupVersionKind(...)`
  (the plan 01 non-deprecated GVK helper) — no second scheme install, no
  second import, no `apis/v1alpha*` reference anywhere in the file
- Added `*gatewayv1.GRPCRoute` and `*gatewayv1.TLSRoute` arms to `hostnamesOf`
  and `parentRefsOf`, factored through a shared `hostnamesFrom([]gatewayv1.Hostname) []string`
  helper since all three route specs declare an identically shaped
  `Hostnames` field via `CommonRouteSpec`
- Completed `extractHostnames`: skips `*`-prefixed wildcards, de-duplicates
  in first-appearance order, validates every remaining name with
  `internal/validation.ValidateHostname` (logging and skipping failures
  without aborting the batch), and accepts dot-less (non-FQDN) names with a
  `log.Warn` per D-19 — matching the project's documented, deliberately
  unenforced footgun (ADR `router-hosts-bzg`)
- `syncRoute`'s existing "empty hostname slice -> zero `ctrl.Result`, nil
  error, no `HostClient` call" path confirmed to still hold after filtering

## Task Commits

Each task followed a RED -> GREEN TDD cycle, committed atomically:

1. **Task 1: Extend the kinds table and type switches to GRPCRoute and TLSRoute**
   - RED: `e6f92c2` (test) — 4 failing tests (`TestHostnamesOf_AllKinds`,
     `TestParentRefsOf_AllKinds`, `TestGatewayRouteKinds_CoversThreeKinds`,
     `TestGatewayScheme_InstallsAllRouteKinds`)
   - GREEN: `53cd641` (feat) — kinds table + type switches extended, all 4 pass
2. **Task 2: Filter hostnames — wildcard skip, de-duplication, validation, dot-less warning**
   - RED: `9bff5c6` (test) — 5 failing/partially-failing tests
     (`TestExtractHostnames_SkipsWildcards`, `_SkipsInvalid`,
     `_DeDuplicates` [already passed — de-dup pre-existed from plan 01],
     `_AcceptsDotlessWithWarning`, `_AllSkipped`)
   - GREEN: `32e0c55` (feat) — full filter chain implemented, all 5 pass

## Files Created/Modified

- `internal/operator/gateway_controller.go` — `gatewayRouteKinds()` (3
  entries), `hostnamesOf`/`parentRefsOf` (3 typed arms + shared
  `hostnamesFrom` helper), `extractHostnames` (wildcard/dedup/validate/warn
  chain); new imports `strings` and
  `github.com/fzymgc-house/router-hosts/internal/validation`
- `internal/operator/gateway_controller_test.go` — `recordingHandler` (a
  minimal `slog.Handler` capturing records for the dot-less-warning
  assertion, reused nowhere else), 4 new kinds/hostnamesOf/parentRefsOf
  tests, 5 new `extractHostnames` tests

## Decisions Made

- **GW-01 left incomplete in `REQUIREMENTS.md`:** this plan finishes the
  three-kind reconcile surface and the full hostname-filtering contract, but
  `syncRoute`'s update/delete diff (the remainder of GW-01's lifecycle) is
  explicitly deferred to plan 04 per 07-01-SUMMARY's "Next Phase Readiness"
  note. Marking GW-01 complete now would be premature.
- **`seen` map marks a hostname before validation, not after:** so a
  hostname repeated N times that also happens to be invalid produces one
  `log.Warn`, not N. The plan's four-step order (wildcard -> dedup ->
  validate -> dot-less-warn) doesn't specify whether dedup happens before or
  after validation failures are recorded; this ordering was chosen for
  cleaner log output and does not change the returned hostname set.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None. Lefthook's known pre-commit markdown-lint/gofumpt reordering quirk
(noted in 07-01-SUMMARY) did not surface this run — no commit needed a retry.

## User Setup Required

None.

## Next Phase Readiness

Plans 03-05 build directly on this:

- **Plan 03** expands `resolveIP`'s error/fallback matrix (GW-02) — untouched
  by this plan.
- **Plan 04** adds the update/delete diff and per-host error accumulation to
  `syncRoute`, and fills in `reconcileDelete` (still a stub) — this is what
  completes GW-01.
- **Plan 05** adds the `parentRefIndexKey` field index and the CRD-gated
  Gateway watch in `SetupWithManager`.

No blockers.

---

*Phase: 07-gateway-api-support*
*Completed: 2026-07-26*

## Self-Check: PASSED

All created/modified files present on disk; all four task commits
(`e6f92c2`, `53cd641`, `9bff5c6`, `32e0c55`) verified present in
`git log --oneline --all`.
