---
phase: 8
slug: kubernetes-service-controller
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-07-26
validated: 2026-07-27
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

**Populated 2026-07-27 from disk, post-execution.** Every row below names a test that was observed
running, with its `--- PASS` count measured — not inferred from a plan. Tasks are positional within
each plan (plans carry no explicit task ids), so `Task ID` is `{plan}-{ordinal}`.

Measured totals for `task test -- -v -run 'Service' ./internal/operator/`:
**18 top-level `--- PASS`, 65 subtest `--- PASS`, 0 `--- FAIL`**, against an inventory of
18 `func Test…` in `service_controller_test.go` — pattern coverage is exact (18 == 18).

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | PASS | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|------|--------|
| 08-01-01 | 01 | 1 | SVC-01/02 | T-08-19 (D-16) | one-way finalizer string confirmed before it reaches live objects | checkpoint | n/a — `checkpoint:decision`, resolved `confirm-service-cleanup` | — | ✅ |
| 08-01-02 | 01 | 1 | SVC-01, SVC-02 | T-08-02, T-08-08, T-08-SC | opt-in predicate + typed watch; one LB Service → one DNS entry | unit (tracer) | `task test -- -v -run 'TestServiceEnabledPredicate' ./internal/operator/` | 1 top / 8 sub | ✅ |
| 08-02-01 | 02 | 2 | SVC-01/02 | **T-08-04**, T-08-05 | cluster-scoped `events` + `services` RBAC, least-privilege | integration (helm render) | `task test:chart` → `Chart verification passed.` | exit 0 | ✅ |
| 08-02-02 | 02 | 2 | SVC-02 | **T-08-13** | full IP matrix; `.IP`/`.Hostname` independently optional | unit (tdd) | `task test -- -v -run 'TestResolveServiceIP' ./internal/operator/` | 1 top / 10 sub | ✅ |
| 08-02-03 | 02 | 2 | SVC-01 | T-08-12 | four failure/waiting Events, no success-path event | unit (tdd) | `task test -- -v -run 'TestSyncService_Events\|TestSyncService_TerminalConditionsDoNotRequeue' ./internal/operator/` | 2 top / 11 sub | ✅ |
| 08-03-01 | 03 | 3 | SVC-01 | T-08-07 | hostname required + validated; dot-less warned, accepted | unit (tdd) | `task test -- -v -run 'TestServiceDesiredHostname' ./internal/operator/` | 1 top / 6 sub | ✅ |
| 08-03-02 | 03 | 3 | SVC-01 | T-08-14 (partial) | alias parse/validate/dedupe; IP + self-alias dropped | unit (tdd) | `task test -- -v -run 'TestServiceDesiredAliases' ./internal/operator/` | 1 top / 9 sub | ✅ |
| 08-03-03 | 03 | 3 | SVC-01 | **T-08-15**, T-08-16 | aliases cleared send `[]string{}` not `nil`; read-before-write OCC, fail-closed | unit (tdd) | `task test -- -v -run 'TestSyncService_AliasesClearedSendsEmptySlice\|TestSyncService_AliasesSentOnCreate\|TestSyncService_UpdatePath' ./internal/operator/` | 3 top / 4 sub | ✅ |
| 08-04-01 | 04 | 4 | SVC-02 | **T-08-18**, T-08-06 | desired-set diff, no early return; all four stop-managing transitions | unit (tdd) | `task test -- -v -run 'TestSyncService_StopManaging\|TestSyncService_SkipsUpdateWhenUnchanged\|TestSyncService_CorruptAnnotationRequeues\|TestSyncService_PartialFailureRetainsIDs' ./internal/operator/` | 4 top / 4 sub | ✅ |
| 08-04-02 | 04 | 4 | SVC-01/02 | **T-08-01**, T-08-03, T-08-17 | adoption refused on foreign comment AND foreign tags | unit (tdd) | `task test -- -v -run 'TestSyncService_AdoptionRefused\|TestHasServiceProvenance' ./internal/operator/` | 2 top / 8 sub | ✅ |
| 08-04-03 | 04 | 4 | SVC-02 | **T-08-19** | finalizer released only after all deletes succeed-or-NotFound | unit (tdd) | `task test -- -v -run 'TestReconcileService_DeleteRemovesHostsAndFinalizer\|TestReconcileService_AddsFinalizerAndReturns' ./internal/operator/` | 2 top / 5 sub | ✅ |
| 08-05-01 | 05 | 3 | SVC-01/02 | T-08-08, T-08-21 | `serviceController.enabled` toggle; key does not collide with Helm `service:` | integration (helm render) | `task test:chart` | exit 0 | ✅ |
| 08-05-02 | 05 | 3 | SVC-01/02 | **T-08-20** | chart assertions compare rendered content, not `grep -q` exit status | integration (helm render) | `task test:chart`; negative controls run manually in 08-05 and proven to fail | exit 0 | ✅ |
| 08-05-03 | 05 | 3 | SVC-01 | — | annotation contract documented in chart README | docs | `rg -c 'router-hosts.fzymgc.house/(enabled\|hostname\|aliases\|ip-address)' charts/router-hosts-operator/README.md` | ≥4 | ✅ |
| CR-01 | review | post | SVC-02 | **T-08-19** | deletion event admitted for an opted-out-but-finalized Service | unit (regression) | `task test -- -v -run 'TestServiceEnabledPredicate/update_deletion_of_opted_out_but_finalized' ./internal/operator/` | named subtest | ✅ |
| CR-02 | review | post | SVC-02 | **T-08-19** | `ErrHostNotFound` during cleanup releases the finalizer | unit (regression) | `task test -- -v -run 'TestReconcileService_DeleteRemovesHostsAndFinalizer/host_not_found_during_cleanup_releases_finalizer' ./internal/operator/` | named subtest | ✅ |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*
*Bold threat refs are high-severity (the `block_on` set). All verified closed in `08-SECURITY.md`.*

### Requirement coverage verdict

**SVC-01 — COVERED.** Opt-in predicate including the D-05 annotation-removal update; required
`hostname` missing → `MissingHostname` event, terminal (no requeue); alias parsing with invalid
aliases dropped; aliases cleared send `[]string{}` not `nil`.

**SVC-02 — COVERED.** LoadBalancer IP resolution (first non-empty `.IP`, hostname-only skipped,
multi-entry ordering, both-fields entry, empty status → requeue short); NodePort with and without
`ip-address`; annotation overriding LB status; finalizer add and cleanup-on-delete; all four D-17
stop-managing transitions.

**Cross-cutting — COVERED.** Adoption refused on foreign comment and on foreign tags via
`fakeHostStore` (mutation-proven load-bearing in `08-SECURITY.md`); corrupt `host-ids` annotation
requeues on both the sync and delete paths; all four Kubernetes Events fire with the correct reason.

**Chart (D-13 / D-25) — COVERED** by `task test:chart`, which runs (helm present) rather than
self-skipping.

### Known uncovered behaviors (not requirement gaps)

Two behaviors have no automated test. Neither is owed by SVC-01/SVC-02 — both were surfaced by code
review as robustness findings, and both are blocked on a code change rather than a missing test.
Recording them here so `nyquist_compliant: true` cannot be read as "everything is tested".

| Behavior | Origin | Why untested |
|----------|--------|--------------|
| Alias list exceeding the aggregate 50-alias cap is rejected client-side | WR-01 → T-08-14 | The code **cannot** enforce it — `ValidateAliases` is called per-alias with a one-element slice, so `len(aliases) > MaxAliasesPerEntry` is structurally unreachable. A test would be RED with no GREEN available. Bounded by server-side enforcement, so an over-long list is rejected, never published. Fix the code first, then add the test. |
| Malformed `ip-address` produces a visible terminal failure | WR-02 (unregistered threat half) | Currently produces an unbounded `requeueDelayLong` retry with **no** Event — `reasonMissingIPAddress` fires only when the annotation is absent, not when it is malformed. Testing the current behavior would pin the defect. Register the threat and decide the intended behavior first. |

---

## Wave 0 Requirements

- [x] `internal/operator/service_controller.go` — created (`144ad56`), now ~600 lines
- [x] `internal/operator/service_controller_test.go` — created; 18 `func Test…`, 65 subtests, all green
- [x] `charts/router-hosts-operator/templates/clusterrole.yaml` — cluster-scoped `events` rule added
      (`ad0d38c`, D-13). **Artifact only — the deployed cluster still denies it; see `08-SECURITY.md`
      § Deployment Caveat**
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

- [x] Per-Task Verification Map populated from real plan task IDs and real test names
- [x] Every row carries a recorded `--- PASS` count from an actual `-v` run
- [x] No row asserts on exit status alone; no `A|B` alternation hiding a nonexistent branch
- [x] New `test:chart` assertions check rendered content, not `grep -q`
- [x] All tasks have automated verify or a documented manual-only entry
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references — all three Wave 0 items now exist
- [x] No watch-mode flags
- [x] `nyquist_compliant: true` set in frontmatter
- [x] Known uncovered behaviors recorded explicitly so compliance is not overstated

---

## Validation Audit 2026-07-27

| Metric | Count |
|--------|-------|
| Requirement-owed behaviors | 14 |
| Covered | 14 |
| Gaps found | 0 |
| Resolved | 0 (none needed) |
| Escalated | 0 |
| Known uncovered non-requirement behaviors | 2 (WR-01 → T-08-14, WR-02) |
| Manual-only | 2 (live-cluster events RBAC, informer RSS) |

Measured: 18 top-level `--- PASS`, 65 subtest `--- PASS`, 0 `--- FAIL`; inventory 18 `func Test…`
(pattern coverage exact). Coverage 85.1% overall, 87.4% for `internal/operator`.
No `gsd-nyquist-auditor` spawn was required — gap analysis found zero requirement-level gaps.

**Approval:** validated 2026-07-27
