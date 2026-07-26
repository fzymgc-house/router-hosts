---
phase: 7
slug: gateway-api-support
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-25
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
| **Quick run command** | `task test -- -run 'TestHostnamesOf\|TestExtractHostnames\|TestResolveIP\|TestReconcile_HTTPRoute\|TestRouteParentRefIndexFunc\|TestMapGatewayToRoutes\|TestGatewayKind' ./internal/operator/` |
| **Full suite command** | `task test:coverage:ci` (enforces ≥80% over `./internal/...`) |
| **Estimated runtime** | ~5 s scoped to `./internal/operator/`; ~60–90 s for the full coverage run |

Package baseline before this phase: `internal/operator` at 87.9% coverage. No new
test framework or fixture install is needed — `testify` and the fake client are
already dependencies used identically by the two existing controller test files.

---

## Sampling Rate

- **After every task commit:** Run the quick command scoped to that task's `TestXxx` pattern
- **After every plan wave:** Run `task test:coverage:ci`
- **Before `/gsd-verify-work`:** `task ci` (lint + test + build + buf) must be green
- **Max feedback latency:** 10 seconds for the scoped run

Chart verification (`helm lint` / `helm template`) is **not** part of `task ci` —
`helm` v4.2.3 is available locally but is not wired into `Taskfile.yml`. Treat it
as a manual step, not an automated gate.

---

## Per-Task Verification Map

Task IDs are assigned by the planner; rows below are seeded at requirement level
and are refined to `{phase}-{plan}-{task}` granularity during execution.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | TBD | 1 | GW-01 | — | Wildcard and invalid hostnames are skipped, never registered | unit | `task test -- -run 'TestHostnamesOf_AllKinds\|TestExtractHostnames' ./internal/operator/` | ❌ W0 | ⬜ pending |
| TBD | TBD | 1 | GW-01 | T-07-02 | `DeleteHost` only ever targets IDs this object recorded in its own `host-ids` annotation | unit | `task test -- -run 'TestReconcile_HTTPRoute' ./internal/operator/` | ❌ W0 | ⬜ pending |
| TBD | TBD | 1 | GW-02 | — | No IP-less entry is ever created; unresolvable IP requeues instead | unit | `task test -- -run 'TestResolveIP' ./internal/operator/` | ❌ W0 | ⬜ pending |
| TBD | TBD | 1 | GW-02 | — | A changed Gateway re-enqueues exactly its referencing routes | unit | `task test -- -run 'TestRouteParentRefIndexFunc\|TestMapGatewayToRoutes' ./internal/operator/` | ❌ W0 | ⬜ pending |
| TBD | TBD | 1 | GW-03 | T-07-01 | Absent CRDs (route kinds **and** Gateway) skip controller construction rather than crashing the manager | unit | `task test -- -run 'TestGatewayKind' ./internal/operator/` | ❌ W0 | ⬜ pending |
| TBD | TBD | 2 | GW-03 | T-07-03 | ClusterRole grants least privilege: write verbs on routes, read-only on gateways | manual | `helm lint charts/router-hosts-operator && helm template charts/router-hosts-operator --set gateway.enabled=true \| rg -- '--enable-gateway'` | ❌ W0 | ⬜ pending |
| TBD | TBD | 1 | GW-01 | T-07-04 | A corrupt `host-ids` annotation errors and requeues; never proceeds on a partial view | unit | `task test -- -run 'TestReconcile_HTTPRoute' ./internal/operator/` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/operator/gateway_controller.go` — does not exist; all reconciler and helper code for this phase
- [ ] `internal/operator/gateway_controller_test.go` — does not exist; all unit tests, **reusing `mockHostClient` from `hostmapping_controller_test.go`** (same package — do not add a second mock)
- [ ] `go.mod` / `go.sum` — `sigs.k8s.io/gateway-api v1.6.1` must be present and `task build` green before any controller code is written (CONTEXT D-03 build gate)

No framework installation required.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| ClusterRole grants the Gateway API verbs, and `--enable-gateway` is templated only when `gateway.enabled=true` | GW-03 | No automated Helm chart test infrastructure exists in this repo; `helm` is not wired into `Taskfile.yml` | `helm lint charts/router-hosts-operator`; then `helm template charts/router-hosts-operator --set gateway.enabled=true` and confirm `--enable-gateway` is present plus the two `gateway.networking.k8s.io` rule blocks; re-run without `--set` and confirm the arg is absent |
| End-to-end: an HTTPRoute in a live cluster produces a router DNS entry at the parent Gateway's address | GW-01, GW-02 | Requires a real cluster with Gateway API CRDs, a Gateway controller assigning `status.addresses`, and a reachable router-hosts server over mTLS | Deferred to `/gsd-verify-work` UAT; not gated in CI |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
