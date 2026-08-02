---
phase: 7
slug: gateway-api-support
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-25
audited: 2026-07-26
---

# Phase 7 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Seeded from `07-RESEARCH.md` § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go standard `testing` + `testify` (assert/require) + controller-runtime `pkg/client/fake` |
| **Config file** | none — plain `go test`, wrapped by `Taskfile.yml` |
| **Quick run command** | See "Approval" below — the seeded pattern predated waves 3–5 and the security remediation, so it missed `TestSyncRoute_*`, `TestReconcile_Route_*`, and the provenance tests. The corrected pattern executes 91 tests |
| **Chart command** | `task test:chart` (added 2026-07-26; `helm lint` + four rendered-output assertions) |
| **Full suite command** | `task test:coverage:ci` (enforces ≥80% over `./internal/...`) |
| **Estimated runtime** | ~2 s scoped to `./internal/operator/`; ~60–90 s for the full coverage run; ~1 s for the chart check |

Package baseline before this phase: `internal/operator` at 87.9% coverage. No new
test framework or fixture install is needed — `testify` and the fake client are
already dependencies used identically by the two existing controller test files.

---

## Sampling Rate

- **After every task commit:** Run the quick command scoped to that task's `TestXxx` pattern
- **After every plan wave:** Run `task test:coverage:ci`
- **Before `/gsd-verify-work`:** `task ci` (lint + test + build + buf) must be green
- **Max feedback latency:** 10 seconds for the scoped run

Chart verification was manual when this file was seeded. It is now automated as
`task test:chart` (added by this audit), which runs `helm lint` and then asserts the
rendered output in four ways: `--enable-gateway` absent by default, present under
`gateway.enabled=true`, `gateways/status` never granted, and zero ClusterRole objects
under `rbac.create=false`. It self-skips with exit 0 when `helm` is not installed, so
it is safe to chain. It is **not** yet wired into `task ci` — chaining it there would
make CI depend on a `helm` binary that the CI image does not currently install; that
is a deliberate follow-up, not an oversight.

---

## Per-Task Verification Map

Task IDs are assigned by the planner; rows below are seeded at requirement level
and are refined to `{phase}-{plan}-{task}` granularity during execution.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 07-02-02 | 07-02 | 2 | GW-01 | T-07-07, T-07-10, T-07-11 | Wildcard and invalid hostnames are skipped, never registered; duplicates collapse to one entry | unit | `task test -- -run 'TestHostnamesOf_AllKinds\|TestExtractHostnames' ./internal/operator/` | ✅ | ✅ green (6) |
| 07-04-01 | 07-04 | 4 | GW-01 | T-07-02 | `DeleteHost` only ever targets IDs this object recorded in its own `host-ids` annotation | unit | `task test -- -run 'TestReconcile_HTTPRoute\|TestSyncRoute_NeverDeletesUntrackedID\|TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete' ./internal/operator/` | ✅ | ✅ green (5) |
| 07-03-01 | 07-03 | 3 | GW-02 | T-07-12 | No IP-less entry is ever created; unresolvable IP requeues instead | unit | `task test -- -run 'TestResolveIP' ./internal/operator/` | ✅ | ✅ green (13) |
| 07-05-01 | 07-05 | 5 | GW-02 | T-07-15 | A changed Gateway re-enqueues exactly its referencing routes | unit | `task test -- -run 'TestRouteParentRefIndexFunc\|TestMapGatewayToRoutes' ./internal/operator/` | ✅ | ✅ green (8) |
| 07-05-03 | 07-05 | 5 | GW-03 | T-07-01, T-07-14 | Absent CRDs (route kinds **and** Gateway) skip controller construction rather than crashing the manager | unit | `task test -- -run 'TestGatewayKind' ./internal/operator/` | ✅ | ✅ green (7) |
| 07-06-01 | 07-06 | 1 | GW-03 | T-07-03, T-07-16, T-07-17 | ClusterRole grants least privilege: write verbs on routes, read-only on gateways, no `gateways/status`, no ClusterRole at all under `rbac.create=false`; `--enable-gateway` absent by default and present only when opted in | chart | `task test:chart` | ✅ | ✅ green |
| 07-04-02 | 07-04 | 4 | GW-01 | T-07-04 | A corrupt `host-ids` annotation errors and requeues; never proceeds on a partial view | unit | `task test -- -run 'TestSyncRoute_CorruptAnnotation\|TestReconcile_Route_DeleteCorruptAnnotation' ./internal/operator/` | ✅ | ✅ green (2) |
| SEC-02 | (post-phase) | — | GW-01 | T-07-02 (part 2) | Adoption on `AlreadyExists` is refused unless the entry's comment (and, where operator-derived, tags) prove this object created it — so no controller can adopt then delete another owner's entry | unit | `task test -- -run 'TestAddOrAdopt_\|TestHasGatewayProvenance\|TestReconcile_AlreadyExists_RefusesForeignEntry\|TestReconcile_IngressRoute_RefusesForeignEntryAdoption' ./internal/operator/` | ✅ | ✅ green (5) |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky · `(n)` = passing tests the command actually executes*

**Row commands are asserted to reach their stated behavior, not merely to exit 0.**
Each `(n)` above was measured by running the command with `-v` and counting `--- PASS`
lines. Two rows failed that check on this audit and were corrected — see the audit
trail below.

---

## Wave 0 Requirements

- [x] `internal/operator/gateway_controller.go` — created in 07-01, extended through 07-05
- [x] `internal/operator/gateway_controller_test.go` — created in 07-01; reuses `mockHostClient` from `hostmapping_controller_test.go` as required (no second mock was declared)
- [x] `go.mod` / `go.sum` — `sigs.k8s.io/gateway-api v1.6.1` present in the direct require block; `go mod tidy` is a no-op and `task build` is green (CONTEXT D-03 build gate satisfied in 07-01 task 1)

No framework installation was required.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| End-to-end: an HTTPRoute in a live cluster produces a router DNS entry at the parent Gateway's address | GW-01, GW-02 | Requires a real cluster with Gateway API CRDs, a Gateway controller assigning `status.addresses`, and a reachable router-hosts server over mTLS. Genuinely unautomatable at unit level — the fake client cannot assign status addresses the way a real Gateway controller does | Deferred to `/gsd-verify-work` UAT; not gated in CI |

*The chart-rendering row previously listed here was automated by this audit as
`task test:chart` and moved into the Per-Task Verification Map. Its "why manual"
rationale — no chart-test infrastructure existed — was an infrastructure gap rather
than an inherent limit, so it was closed rather than accepted.*

---

## Validation Audit 2026-07-26

| Metric | Count |
|--------|-------|
| Rows audited | 8 (7 seeded + 1 added) |
| Gaps found | 4 |
| Resolved | 4 |
| Escalated to manual-only | 0 |
| Manual-only rows remaining | 1 (live-cluster E2E — genuinely unautomatable) |
| Go tests generated | 0 — every behavior already had passing tests |
| Automation added | 1 — `task test:chart` |

**Gaps found and how they were resolved.** Three were mapping defects rather than
missing coverage, so no auditor test-generation pass was needed; the fourth was an
infrastructure gap that was closed rather than accepted.

| # | Gap | Type | Resolution |
|---|-----|------|------------|
| 1 | Row for T-07-02 (`DeleteHost` targets only own IDs) ran `TestReconcile_HTTPRoute`, which matches `_CreatesHost`, `_AddsFinalizerAndReturns`, `_DeletesHostsOnFinalize` — none of them the ownership proof. The real proofs (`TestSyncRoute_NeverDeletesUntrackedID`, `TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete`) were never executed by the row's command | PARTIAL — miswired command, tests existed | Command widened to include both proof tests; now executes 5 |
| 2 | Row for T-07-04 (corrupt annotation) ran the same `TestReconcile_HTTPRoute` pattern; the actual tests are `TestSyncRoute_CorruptAnnotationRequeuesWithoutWriting` and `TestReconcile_Route_DeleteCorruptAnnotationRequeues` | PARTIAL — miswired command, tests existed | Command repointed at the two corrupt-annotation tests; now executes 2 |
| 3 | Adoption-provenance behavior (T-07-02 part 2), added by the post-phase security remediation in `c65c8a2` / `4f81538`, had five passing tests but no row in this map | MISSING row — tests existed | Row `SEC-02` added; executes 5 |
| 4 | The GW-03 chart row was marked manual-only because "`helm` is not wired into `Taskfile.yml`" — an infrastructure gap, not an inherent limit, leaving three threat mitigations (T-07-03, T-07-16, T-07-17) with no automated gate | MISSING automation | Added `task test:chart`: `helm lint` plus four rendered-output assertions. Mutation-tested — flipping the `gateway.enabled` default to `true` makes it fail with `--enable-gateway rendered with default values`. Row promoted from manual to automated |

**Method note.** Both defects in rows 1–2 are the *vacuous-verification* pattern this
phase hit repeatedly: a command that exits 0 without touching the behavior it names.
Detected by running every row's command with `-v` and counting `--- PASS` lines rather
than trusting exit status — the same discriminating check the `task test` CLI_ARGS fix
required. Row counts are now recorded in the map so a future audit can spot drift.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references — all three Wave 0 items satisfied
- [x] No watch-mode flags — `go test` is one-shot; `task test` forwards `{{.CLI_ARGS}}` with a `./...` default
- [x] Feedback latency < 10s — scoped `./internal/operator/` runs complete in ~2s
- [x] `nyquist_compliant: true` set in frontmatter
- [x] Every row's command verified to execute its stated behavior's tests (not merely exit 0)

**Approval:** validated 2026-07-26 — **all 8 map rows have automated verification.**
One behavior remains manual-only and is deliberately outside the map: live-cluster
E2E (GW-01, GW-02), which needs a real Gateway controller assigning
`status.addresses` and a reachable router-hosts server over mTLS. It is deferred to
`/gsd-verify-work` UAT.

Quick-run command for the whole phase's automated surface:

```text
task test -- -run 'TestHostnamesOf\|TestExtractHostnames\|TestResolveIP\|TestReconcile_HTTPRoute\|TestSyncRoute_\|TestReconcile_Route_\|TestRouteParentRefIndexFunc\|TestMapGatewayToRoutes\|TestGatewayKind\|TestAddOrAdopt_\|TestHasGatewayProvenance\|TestReconcile_AlreadyExists_\|TestReconcile_IngressRoute_' ./internal/operator/
task test:chart
```
