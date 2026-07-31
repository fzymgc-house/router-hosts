---
phase: 08-kubernetes-service-controller
verified: 2026-07-27T22:05:00Z
status: passed
score: 2/2 must-haves verified
behavior_unverified: 0
overrides_applied: 1
overrides:
  - item: "D11 — operator ServiceAccount can create Kubernetes Events in a live cluster"
    original_status: human_needed
    overridden_by: user
    date: 2026-07-30
    measured_result: "FAILS as of 2026-07-30 — `kubectl auth can-i create events --as=system:serviceaccount:router-hosts-operator:router-hosts-operator` returns `no`; the deployed ClusterRole (chart 0.10.11) contains zero `events` rules and zero `services` rules."
    rationale: "Circular gate, resolved in the correct order. D11 measures a DEPLOYMENT, not the code. The mitigation exists in the chart artifact and is regression-gated in `task test:chart`, but it cannot become effective until the chart ships — and the chart cannot ship until this PR merges. Overriding unblocks the merge; the item is then closed honestly by re-running /gsd-verify-work 8 against the deployed chart."
    residual_risk: "T-08-04 remains LIVE IN PRODUCTION until v0.11.0 is released and the ArgoCD pin is bumped from 0.10.11. HostMapping Events have been silently dropped since 2025-12-31. Tracked in 08-SECURITY.md § Deployment Caveat."
    closes_when: "Post-deploy: `kubectl auth can-i create events --as=<operator-sa>` returns `yes`, then re-run /gsd-verify-work 8."
human_verification:
  - test: "Confirm the operator ServiceAccount can actually create/patch Kubernetes Events in a live cluster (D-13)"
    expected: "`kubectl auth can-i create events --as=system:serviceaccount:<ns>:<operator-sa>` returns `yes`; annotating a ClusterIP Service with `router-hosts.fzymgc.house/enabled: \"true\"` and `.../hostname` produces an `InvalidServiceType` Warning event visible via `kubectl describe svc`"
    why_human: "A fake recorder (used in all unit tests) proves the `Eventf` call is made; it cannot prove the cluster-scoped `events` RBAC rule the chart now renders is actually bound and effective at runtime. This is exactly the class of gap (RBAC works on paper, not in a live API server) that a unit test structurally cannot see. 08-VALIDATION.md lists this as Manual-Only."
  - test: "Optional: measure operator RSS before/after enabling `--enable-service` against a cluster with a large Service population (D-04)"
    expected: "Memory growth is bounded and acceptable for the target homelab-scale cluster; the shared informer caching every Service (not just annotated ones) is a documented, deliberate trade-off, not a leak"
    why_human: "Resident-memory footprint under a real Service population is an environment property, not something a fake client / unit test can measure. 08-VALIDATION.md lists this as optional Manual-Only."
---

# Phase 8: Kubernetes Service Controller Verification Report

**Phase Goal:** Externally-reachable Services register their DNS automatically, completing "Gateway API + Ingress + Services" parity.
**Verified:** 2026-07-27
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth (Roadmap Success Criterion) | Status | Evidence |
|---|---|---|---|
| 1 | A LoadBalancer or NodePort Service with the configured annotations produces router DNS entries | ✓ VERIFIED | `internal/operator/service_controller.go:323-433` (`syncService`) computes IP + hostname + aliases from the four annotations and calls `AddHost`/`UpdateHost` via `syncServiceHost`/`addOrAdoptService`. Exercised end-to-end by `TestReconcileService_LoadBalancerCreatesHost`, `TestSyncService_AliasesSentOnCreate`, `TestResolveServiceIP/nodeport_with_annotation`, and the four `TestSyncService_Events` subtests, all passing (`task test -- -v -run 'Service' ./internal/operator/` → 18/18 top-level `--- PASS`, 0 FAIL, ran directly by this verifier). Chart-level opt-in gate (`serviceController.enabled` → `--enable-service`) confirmed rendered/absent correctly by `task test:chart` → "Chart verification passed." |
| 2 | Service IPs are resolved per the IP-resolution rules, and entries are removed when the Service is deleted | ✓ VERIFIED | `resolveServiceIP` (`:154-170`) implements the full D-09/D-10/D-11 matrix (LB first-non-empty-IP, hostname-only-entries-skipped, NodePort-annotation-only, annotation-overrides-LB-status, unsupported types rejected) — every branch has a passing `TestResolveServiceIP` subtest. Deletion path traced end-to-end: predicate admits the delete/deletion-timestamp event (`serviceEnabledPredicate` + `serviceOwnsState`, `:82-132`, regression test `TestServiceEnabledPredicate/update_deletion_of_opted_out_but_finalized` — this is the exact CR-01 scenario, now passing) → `Reconcile` routes to `reconcileDelete` on `DeletionTimestamp != nil` (`:268-269`) → all tracked entries deleted, a `NotFound` treated as success (CR-02 fix, `:569-577`, regression test `TestReconcileService_DeleteRemovesHostsAndFinalizer/host_not_found_during_cleanup_releases_finalizer`, passing) → finalizer released only on full success (`:583-601`), confirmed NOT released on a genuine delete error by `TestReconcileService_DeleteRemovesHostsAndFinalizer/retains_ids_and_requeues_on_delete_failure` (asserts finalizer retained + `RequeueAfter` set), passing. All four D-17 "stop managing" transitions (opt-out, type change, hostname change, annotation removal) also delete the stale entry, verified by `TestSyncService_StopManaging`'s 4 passing subtests. |

**Score:** 2/2 truths verified (0 present-but-behavior-unverified)

Both roadmap-level truths are *cleanup/lifecycle invariants* (Step 3, "behavior-dependent truths" category) — presence and wiring alone would not have been sufficient. Both are upgraded to VERIFIED specifically because the two BLOCKERs the code review found in exactly this territory (CR-01: opt-out-then-delete wedges the finalizer via a predicate gap; CR-02: `DeleteHost` NotFound misclassified as failure) are each covered by a **named regression test that fails against the pre-fix code and passes against the current code** (confirmed by reading both the diff and the test; re-run directly by this verifier, not taken from SUMMARY.md).

### Required Artifacts

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `internal/operator/service_controller.go` | Reconciler: predicate, IP resolution, hostname/alias parsing, sync/diff, adoption, delete | ✓ VERIFIED | 618 lines, substantive, wired into `cmd/operator/main.go` |
| `internal/operator/service_controller_test.go` | Full behavior coverage per D-27/D-28 | ✓ VERIFIED | 1311 lines, 18 top-level `func Test*`, all passing |
| `cmd/operator/main.go` | `--enable-service` flag + gated `ServiceReconciler` registration | ✓ VERIFIED | `:48` flag (default `false`), `:130-141` gated registration with `Recorder: mgr.GetEventRecorder("service-controller")` |
| `charts/router-hosts-operator/templates/clusterrole.yaml` | `services` write verbs + cluster-scoped `events` create/patch | ✓ VERIFIED | Both rules present with explanatory comments referencing D-13/D-24 |
| `charts/router-hosts-operator/values.yaml` + `templates/deployment.yaml` | `serviceController.enabled` toggle | ✓ VERIFIED | `values.yaml:72` `serviceController:`, `deployment.yaml:55` gated `--enable-service` arg |
| `charts/router-hosts-operator/README.md` | Documents all 4 annotations, IP rules, no-default-IP divergence, `serviceController` naming asymmetry, cache footprint | ✓ VERIFIED | Lines 126-330 cover every item; matches code exactly (annotation table, event reasons, dot-less-hostname behavior) |
| `Taskfile.yml` `test:chart` | D-25 content-assertions, not exit-status-only | ✓ VERIFIED | Lines 89-131 capture rendered content into variables and compare/count; ran directly, "Chart verification passed." |

### Key Link Verification

| From | To | Via | Status | Details |
|---|---|---|---|---|
| `cmd/operator/main.go` | `ServiceReconciler.SetupWithManager` | `enableService` flag gate | WIRED | `if enableService { ... SetupWithManager(mgr) ... }` |
| `serviceEnabledPredicate` | `Reconcile` | controller-runtime `builder.WithPredicates` | WIRED | `SetupWithManager:612-617`; predicate correctly admits create/update/delete/generic per D-05 + CR-01 fix |
| `syncService` | `HostClient.AddHost`/`UpdateHost`/`DeleteHost` | `syncServiceHost` / stale-cleanup loop | WIRED | Confirmed via passing tests with `mockHostClient`/`fakeHostStore` |
| `reconcileDelete` | finalizer release | ordering: delete-all-then-release | WIRED | `:551-601`; confirmed a partial failure retains the finalizer (test above) |
| `charts/.../clusterrole.yaml` | `ServiceReconciler.Recorder.Eventf` | cluster-scoped `events` RBAC rule | WIRED (rendered) / UNVERIFIED (runtime) — see Human Verification | Rendered content confirmed by `task test:chart`; runtime RBAC effect requires a live cluster |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Scoped Service test suite | `task test -- -v -run 'Service' ./internal/operator/` | 18/18 top-level `--- PASS`, 0 FAIL | ✓ PASS |
| Named CR-01 regression | subtest `TestServiceEnabledPredicate/update_deletion_of_opted_out_but_finalized` | PASS | ✓ PASS |
| Named CR-02 regression | subtest `TestReconcileService_DeleteRemovesHostsAndFinalizer/host_not_found_during_cleanup_releases_finalizer` | PASS | ✓ PASS |
| Genuine delete failure does not release finalizer | subtest `TestReconcileService_DeleteRemovesHostsAndFinalizer/retains_ids_and_requeues_on_delete_failure` | PASS (finalizer retained, requeue set) | ✓ PASS |
| Full workspace test suite | `task test:coverage:ci` | 12 packages ok, 0 FAIL, coverage 85.1% (`internal/operator` 87.4%) | ✓ PASS |
| Chart render/RBAC content assertions | `task test:chart` | "Chart verification passed." | ✓ PASS |
| Build | `task build` | both binaries built | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|---|---|---|---|---|
| SVC-01 | 08-01, 08-02, 08-03, 08-04, 08-05 | Operator creates router DNS entries for LoadBalancer/NodePort Services from configured annotations | ✓ SATISFIED | `syncService` + `resolveServiceIP` + `serviceDesiredHostname`/`Aliases`, tested end-to-end |
| SVC-02 | 08-02, 08-04 | Operator resolves Service IPs and removes entries when the Service is deleted | ✓ SATISFIED | `resolveServiceIP` matrix + `reconcileDelete` with both BLOCKERs fixed and regression-tested |

No orphaned requirements — REQUIREMENTS.md maps only SVC-01/SVC-02 to Phase 8 and both are claimed and satisfied.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|---|---|---|---|---|
| `internal/operator/service_controller.go` | 191-218 (`serviceDesiredAliases`) | WR-01 (from 08-REVIEW.md, still open): per-alias validation cannot enforce the aggregate 50-alias cap, so >50 aliases silently pass client-side and then fail server-side on every reconcile with no Kubernetes Event | ⚠️ WARNING | Only reachable when a Service's `aliases` annotation lists >50 entries — an edge case, not the documented/common path. Degrades to an indefinite, eventless `requeueDelayLong` retry loop rather than corrupting state or blocking the roadmap Success Criteria for a normal Service. Not a BLOCKER for this phase's goal, but should not ship silently past this verification without a decision. |
| `internal/operator/service_controller.go` | 127-143 (`resolveServiceIP`) | WR-02 (from 08-REVIEW.md, still open): `ip-address` override annotation is used verbatim with no `net.ParseIP`/format check, so a malformed value fails server-side with no distinguishing Kubernetes Event (looks identical to a healthy Service from `kubectl describe service`) | ⚠️ WARNING | Same failure shape as WR-01: indefinite eventless retry on a misconfigured (not absent) annotation. Does not corrupt data and does not block the documented happy path. |

Both warnings were identified and left open by 08-REVIEW.md as deliberate, tracked deviations — not silently missed by this verification. Neither is covered by an `overrides:` entry in this file's frontmatter, nor by any must-have `prohibition` in the five PLAN.md files (the prohibitions cover "no entry with empty IP," "no silent orphaning," "no adoption of foreign entries," etc. — not aggregate-alias-cap enforcement or IP-format validation). They are recorded here as non-blocking findings for a human decision on whether to open follow-up work (see WR-01/WR-02 fix suggestions in 08-REVIEW.md), consistent with the orchestrator's instruction to judge rather than silently pass or silently fail them.

No debt markers (`TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER`) found in any file touched by this phase.

### Human Verification Required

1. **Live-cluster RBAC effect for Kubernetes Events (D-12/D-13)**
   **Test:** `kubectl auth can-i create events --as=system:serviceaccount:<ns>:<operator-sa>`, then annotate a `ClusterIP` Service with the opt-in + hostname annotations and confirm `kubectl describe svc` shows `InvalidServiceType`.
   **Expected:** `can-i` returns `yes`; the event appears.
   **Why human:** The unit test suite uses a fake `events.EventRecorder` that proves the `Eventf` call site is reached with the right reason/type — it cannot prove the newly-added cluster-scoped `events` RBAC rule is actually bound and effective against a real API server. This is precisely the class of RBAC gap the phase's own D-13 finding describes (a pre-existing, structurally-identical gap for `HostMappingReconciler` went undetected until this phase's audit). 08-VALIDATION.md lists this as Manual-Only.

2. **Informer cache footprint under a large Service population (D-04)** — optional
   **Test:** Compare operator RSS before/after enabling `--enable-service` on a cluster with many Services.
   **Expected:** Bounded, acceptable growth for a homelab-scale deployment (the design deliberately caches every Service, not only annotated ones).
   **Why human:** Resident-memory behavior under real cluster load is an environment property no fake client can measure. 08-VALIDATION.md lists this as optional Manual-Only.

### Gaps Summary

No BLOCKER-level gaps. Both roadmap Success Criteria are backed by passing code and named regression tests covering the exact failure modes (CR-01, CR-02) the code review previously found and that are now fixed. Two WARNING-level, pre-existing-and-tracked code-review findings (WR-01, WR-02) remain open by deliberate choice of the executor pass — they degrade gracefully (eventless retry, not data corruption) and do not falsify either Success Criterion for the documented/common annotation usage, but are surfaced here rather than silently absorbed into a clean pass. Two items require a live Kubernetes cluster to confirm (RBAC effect, cache footprint) and cannot be honestly marked VERIFIED from static analysis or unit tests alone — routing this report to `human_needed` per the decision tree rather than `passed`.

---

*Verified: 2026-07-27*
*Verifier: Claude (gsd-verifier)*
