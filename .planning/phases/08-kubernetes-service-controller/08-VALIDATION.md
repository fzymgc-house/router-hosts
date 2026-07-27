---
phase: 8
slug: kubernetes-service-controller
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-26
---

# Phase 8 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Seeded by plan-phase from `08-RESEARCH.md` § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go `testing` + `stretchr/testify` (`assert`/`require`) — matches `hostmapping_controller_test.go` / `gateway_controller_test.go` |
| **Config file** | none — plain `go test`, invoked only via `task test` per CLAUDE.md |
| **Quick run command** | `task test -- -v -run 'Service' ./internal/operator/` (see the pattern warning below) |
| **Full suite command** | `task test:coverage:ci` (enforces the ≥80% threshold) |
| **Chart command** | `task test:chart` (helm present in this environment — it will actually run, not self-skip) |
| **Estimated runtime** | ~15s scoped / ~120s full suite |

---

## Sampling Rate

- **After every task commit:** `task test -- -v -run 'Service' ./internal/operator/`
- **After every plan wave:** `task test:coverage:ci`
- **Before `/gsd-verify-work`:** `task test:coverage:ci` green **AND** `task test:chart` green
- **Max feedback latency:** ~15 seconds (scoped run)

---

## Command Discipline (MANDATORY — Phase 7 regression)

Every command recorded in this file MUST assert on a **discriminating signal**, never on exit
status alone. Phase 7 seeded 7 rows here; **3 were wrong and still exited 0**:

- Two pointed at `TestReconcile_HTTPRoute`, which matches `_CreatesHost` / `_AddsFinalizerAndReturns` /
  `_DeletesHostsOnFinalize` — *not* the ownership or corrupt-annotation proofs they claimed to cover.
- In an alternation `A|B`, one branch can satisfy the pattern while the other names a test that does
  not exist. A bare `-run 'A|B'` exits 0 either way.
- The header's quick-run pattern missed every test added after planning.

**Therefore:** run each row with `-v` and **count `--- PASS` lines**, recording the count in the row.
Where a specific subtest is the point of the row, grep for its **name string**, not just a count.

### The `-run` pattern trap (caught live on 2026-07-26, plan 08-01)

This file originally specified `-run 'TestService'` as the quick-run command. Go's `-run` is an
**unanchored regex over the test-function name**, and `TestService` does **not** match
`TestReconcileService_AddsFinalizerAndReturns` or `TestReconcileService_LoadBalancerCreatesHost` —
the literal substring `TestService` does not occur in `TestReconcileService…`. Measured after
08-01 landed:

| pattern | top-level `--- PASS` | verdict |
|---|---|---|
| `-run 'TestService'` | 1 of 3 | silently blind, exits 0 |
| `-run 'Service'` | 3 of 3 | correct |

This is the Phase 7 regression reproducing inside the very file written to prevent it. The lesson
generalizes: a `Test<Noun>` prefix pattern misses every `Test<Verb><Noun>` sibling. **Prove a
scoping pattern by counting what it runs against the test-function inventory
(`rg '^func Test' <pkg>/*_test.go`) — never assume it covers a family by prefix.**

The `helm template … | grep -q` idiom inherited from Phase 7's `test:chart` is itself an
exit-status-only assertion — **do not copy it forward** for the new D-25 rows. Assert on rendered
content (e.g. capture the `verbs:` line under the `events` rule and check it contains both `create`
and `patch`).

---

## Per-Task Verification Map

**Deliberately unseeded.** Plans do not exist yet at the time this file is written, so any task IDs
or test names entered here would be invented rather than observed — which is precisely how Phase 7
shipped three rows that named nonexistent tests while exiting 0.

`/gsd-validate-phase 8` MUST populate this table **after** execution, from the actual `*-PLAN.md`
task IDs and the actual `func Test…` names on disk, recording a verified `--- PASS` count per row.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | PASS count | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-----------|-------------|--------|
| *(populate from plans + disk)* | | | | | | | | | | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

### Requirement → behavior coverage owed (source: `08-RESEARCH.md` § Validation Architecture)

The authoritative behavior list lives in RESEARCH.md and is not duplicated here. Summary of what the
populated table must end up covering:

- **SVC-01** — opt-in predicate (incl. the D-05 annotation-**removal** update); required-`hostname`
  missing → `MissingHostname` event, terminal; alias parsing with an invalid alias dropped; aliases
  cleared sends `[]string{}` not `nil` (research Pitfall 2).
- **SVC-02** — LoadBalancer IP resolution (first non-empty `.IP`, hostname-only skipped, multi-entry
  ordering, empty status → requeue short); NodePort with and without `ip-address`; `ip-address`
  overriding LB status; finalizer add and cleanup-on-delete; the four D-17 "stop managing"
  transitions.
- **Both** — adoption refused on foreign comment and on foreign tags (D-21, via the existing
  `fakeHostStore`); corrupt `host-ids` annotation errors and requeues; each of the four Kubernetes
  Events fires with the right reason and type.
- **D-13 / D-25 (chart)** — cluster-scoped `events` `create`+`patch` rendered; `--enable-service`
  absent by default and present under `serviceController.enabled=true`; `services` write verbs exact;
  zero ClusterRole under `rbac.create=false`.

---

## Wave 0 Requirements

- [ ] `internal/operator/service_controller.go` — does not exist; the reconciler itself
- [ ] `internal/operator/service_controller_test.go` — does not exist; covers SVC-01 / SVC-02
- [ ] `charts/router-hosts-operator/templates/clusterrole.yaml` — needs the cluster-scoped `events`
      rule (D-13) before any `Eventf` call can succeed in a live cluster
- [x] Framework install: none needed — `testify` and `sigs.k8s.io/controller-runtime/pkg/client/fake`
      are already dependencies used by the existing controller tests
- [x] Mock infrastructure: none needed — `mockHostClient` (`hostmapping_controller_test.go`) and
      `fakeHostStore` (`gateway_controller_test.go:1339-1384`) are both package-scoped and reusable

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Events visible on a real Service | D-12 / D-13 | The fake recorder proves the call is made; it cannot prove RBAC permits it in a live cluster. The gap being fixed is exactly one that is invisible to unit tests. | On a cluster: `kubectl auth can-i create events --as=system:serviceaccount:<ns>:<operator-sa>` → `yes`; then annotate a ClusterIP Service and confirm `kubectl describe svc` shows `InvalidServiceType`. |
| Informer cache footprint under many Services | D-04 | Measuring resident memory against a large Service population is an environment property, not a unit-testable one. | Optional: compare operator RSS before/after enabling `--enable-service` on the target cluster. |

---

## Validation Sign-Off

- [ ] Per-Task Verification Map populated from real plan task IDs and real test names
- [ ] Every row carries a recorded `--- PASS` count from an actual `-v` run
- [ ] No row asserts on exit status alone; no `A|B` alternation hiding a nonexistent branch
- [ ] New `test:chart` assertions check rendered content, not `grep -q`
- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
</content>
