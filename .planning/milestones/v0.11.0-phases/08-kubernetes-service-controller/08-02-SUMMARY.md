---
phase: 08-kubernetes-service-controller
plan: 02
subsystem: infra
tags: [kubernetes, operator, controller-runtime, corev1, service, dns, rbac, events]

# Dependency graph
requires:
  - phase: 08-kubernetes-service-controller (plan 01)
    provides: ServiceReconciler tracer (LoadBalancer-only resolveServiceIP, finalizer/host-ids lifecycle, --enable-service wiring)
provides:
  - "resolveServiceIP covering the full locked type matrix: LoadBalancer ordering, hostname-only-entry skip, NodePort annotation-only resolution, ip-address override precedence, unsupported-type rejection"
  - "Four Kubernetes Event reasons (InvalidServiceType, MissingHostname, MissingIPAddress, PendingLoadBalancer) wired into syncService with terminal-vs-requeue semantics"
  - "emitEvent helper (nil-guarded, tools/events recorder) as the Service controller's only event path"
  - "Cluster-scoped events RBAC rule (create, patch) plus services RBAC rule (get/list/watch/update/patch) in the Helm chart's ClusterRole, with matching kubebuilder markers"
affects: [08-kubernetes-service-controller (plans 03-05, which add aliases/validation, the update/diff path, and adoption)]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "emitEvent(svc, eventtype, reason, note, args...) nil-guarded wrapper over events.EventRecorder.Eventf, action always the literal \"Reconcile\""
    - "Terminal-for-now failure states (D-14): emit event, log, return ctrl.Result{} with nil error — no timed requeue; only the waiting state (PendingLoadBalancer) sets RequeueAfter"

key-files:
  created: []
  modified:
    - internal/operator/service_controller.go
    - internal/operator/service_controller_test.go
    - charts/router-hosts-operator/templates/clusterrole.yaml

key-decisions:
  - "D-13 gap confirmed empirically before fixing it: the rendered ClusterRole contained zero events rules pre-change, and the namespace-scoped leader-election Role does not render under default chart values either (replicaCount=1, leaderElection.enabled unset) — recorded per the task's explicit instruction not to fix a bug that is not there."
  - "Reworded two pre-existing comments (from plan 01) that contained the literal substrings the plan's acceptance criteria grep for at count 0 — 'services/status' and 'DefaultIP' — without changing their meaning, since the comments predate this plan but their exact wording tripped this plan's own discipline checks."
  - "syncService's type/hostname/IP-resolution checks run in that fixed order (type first, so ip-address cannot resurrect an unsupported type; then hostname; then IP) — matching the plan's explicit ordering instruction, distinct from resolveServiceIP's own internal evaluation order."

patterns-established: []

requirements-completed: [SVC-01, SVC-02]

coverage:
  - id: D1
    description: "resolveServiceIP walks status.loadBalancer.ingress[] in declaration order and returns the first entry whose .ip is non-empty, skipping hostname-only entries including when the hostname-only entry comes first"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/loadbalancer_first_ip"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/loadbalancer_hostname_only_skipped"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/loadbalancer_hostname_then_ip"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/loadbalancer_entry_with_both_fields"
        status: pass
    human_judgment: false
  - id: D2
    description: "A LoadBalancer Service with no resolvable ingress IP creates nothing, emits Normal PendingLoadBalancer, and requeues after requeueDelayShort"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/loadbalancer_empty_status"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_Events/PendingLoadBalancer"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_TerminalConditionsDoNotRequeue/pending_load_balancer_requeues_short"
        status: pass
    human_judgment: false
  - id: D3
    description: "A NodePort Service resolves its IP only from the ip-address annotation; without it, creates nothing and emits Warning MissingIPAddress"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/nodeport_with_annotation"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/nodeport_without_annotation"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_Events/MissingIPAddress"
        status: pass
    human_judgment: false
  - id: D4
    description: "The ip-address annotation overrides LoadBalancer status when both are present"
    requirement: "SVC-02"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/annotation_overrides_loadbalancer_status"
        status: pass
    human_judgment: false
  - id: D5
    description: "A ClusterIP or ExternalName Service that opted in creates nothing and emits Warning InvalidServiceType; the annotation override does not rescue an unsupported type"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/clusterip_unsupported"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestResolveServiceIP/externalname_unsupported"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_Events/InvalidServiceType"
        status: pass
    human_judgment: false
  - id: D6
    description: "An opted-in Service with no hostname annotation creates nothing and emits Warning MissingHostname"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_Events/MissingHostname"
        status: pass
    human_judgment: false
  - id: D7
    description: "InvalidServiceType, MissingHostname, and MissingIPAddress each return without a timed requeue; only PendingLoadBalancer sets RequeueAfter"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_TerminalConditionsDoNotRequeue"
        status: pass
    human_judgment: false
  - id: D8
    description: "No success-path event is emitted on create — the event stream carries only the four failure/waiting reasons"
    requirement: "SVC-01"
    verification:
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_Events/no_success_event_on_create"
        status: pass
      - kind: unit
        ref: "internal/operator/service_controller_test.go#TestSyncService_Events/nil_recorder_is_safe"
        status: pass
    human_judgment: false
  - id: D9
    description: "The rendered ClusterRole grants apiGroups [\"\"] resources [\"services\"] with exactly get, list, watch, update, patch"
    requirement: "SVC-01"
    verification:
      - kind: other
        ref: "helm template charts/router-hosts-operator --show-only templates/clusterrole.yaml | awk matching the services rule's verbs line, asserted equal to the exact five-verb string"
        status: pass
    human_judgment: false
  - id: D10
    description: "The rendered ClusterRole grants apiGroups [\"\"] resources [\"events\"] with create and patch, cluster-scoped, and the pre-change gap (zero events rules) is empirically confirmed"
    requirement: "SVC-02"
    verification:
      - kind: other
        ref: "helm template charts/router-hosts-operator --show-only templates/clusterrole.yaml | grep -c 'resources: [\"events\"]' (pre-change: 0, post-change: 1, verbs contain create+patch)"
        status: pass
    human_judgment: false
  - id: D11
    description: "In a live cluster the operator's ServiceAccount can actually create Events, so the four reasons reach kubectl describe service rather than failing silently"
    verification: []
    human_judgment: true
    rationale: "The fake recorder proves the Eventf call is made and RBAC rules render with the right verbs; neither proves a live cluster's RBAC binding actually grants the permission end-to-end. Backstop verification per 08-VALIDATION.md's Manual-Only Verifications table: kubectl auth can-i create events --as=system:serviceaccount:<ns>:<operator-sa>, then annotate a ClusterIP Service and confirm kubectl describe svc shows InvalidServiceType."

# Metrics
duration: ~45min
completed: 2026-07-26
status: complete
---

# Phase 8 Plan 02: IP Resolution Matrix, Failure Events, and the Events RBAC Fix Summary

**Full LoadBalancer/NodePort/override/unsupported-type IP resolution matrix, four nil-guarded Kubernetes Event reasons with terminal-vs-requeue semantics, and the cluster-scoped `events` RBAC grant that makes those events actually deliverable.**

## Performance

- **Duration:** ~45 min
- **Completed:** 2026-07-26
- **Tasks:** 3 (RBAC confirm-and-grant; resolveServiceIP matrix, TDD; four Events, TDD)
- **Files modified:** 3

## Accomplishments

- Confirmed the D-13 `events` RBAC gap empirically (0 events rules in the pre-change rendered ClusterRole; the namespace-scoped leader-election Role doesn't even render under default chart values) before adding the fix — per the task's explicit "verify, don't assume" instruction
- `resolveServiceIP` now implements the complete locked type matrix: unsupported types (ClusterIP/ExternalName) are rejected before the `ip-address` annotation can rescue them; NodePort resolves only from the annotation; LoadBalancer walks `status.loadBalancer.ingress[]` for the first non-empty `.IP`, correctly skipping hostname-only entries wherever they appear in the list, including ahead of the resolving entry
- All four Kubernetes Event reasons (`InvalidServiceType`, `MissingHostname`, `MissingIPAddress`, `PendingLoadBalancer`) fire through a single nil-guarded `emitEvent` helper; the first three are terminal-for-now (no timed requeue), only `PendingLoadBalancer` requeues after `requeueDelayShort`
- No success-path event fires on create — verified directly by a test that drains the fake recorder's channel after a successful reconcile and asserts it's empty
- The rendered ClusterRole now grants `services` (get/list/watch/update/patch, no delete, no status subresource) and cluster-scoped `events` (create/patch), fixing `HostMappingReconciler`'s pre-existing silent event-recording gap outside the operator's own namespace as a documented side effect
- Coverage held at 84.7% (`task test:coverage:ci`), zero `go.mod`/`go.sum` changes

## Task Commits

Each task was committed atomically, with tasks 2 and 3 (both `tdd="true"`) split into RED (test) then GREEN (feat) commits:

1. **Task 1: Confirm the events RBAC gap, then grant services and cluster-scoped events** - `ad0d38c` (feat)
2. **Task 2: Complete resolveServiceIP across the full Service type matrix**
   - RED: `a9a8e54` (test) — `clusterip_unsupported` failed against the pre-task implementation (annotation override applied before the type check), the other 9 subtests already passed
   - GREEN: `a1efba7` (feat)
3. **Task 3: Emit the four Kubernetes Events with terminal-vs-requeue semantics**
   - RED: `957a1de` (test) — 4 of 6 `TestSyncService_Events` subtests failed (no event wiring existed yet); `no_success_event_on_create` and `nil_recorder_is_safe` already passed vacuously
   - GREEN: `af417bb` (feat)

**Plan metadata:** (this commit)

## Files Created/Modified

- `charts/router-hosts-operator/templates/clusterrole.yaml` - added the `services` (get/list/watch/update/patch) and cluster-scoped `events` (create/patch) rules inside the existing `rbac.create` gate, unconditional on `serviceController.enabled`
- `internal/operator/service_controller.go` - kubebuilder RBAC markers; rewrote `resolveServiceIP` for the full type matrix; added the four `reason*` constants and `(*ServiceReconciler).emitEvent`; restructured `syncService`'s early-return checks into type → hostname → IP-resolution order, each emitting its event
- `internal/operator/service_controller_test.go` - added `TestResolveServiceIP` (10 subtests), `TestSyncService_Events` (6 subtests), `TestSyncService_TerminalConditionsDoNotRequeue` (4 subtests), plus the `newReadySvc`/`noAddHostMock` test helpers

## Decisions Made

- Confirmed the D-13 gap empirically per the task's instruction before writing the fix: pre-change, the rendered ClusterRole contained **zero** `events` rules, and rendering with default values (`replicaCount: 1`, `leaderElection.enabled` unset) confirmed the namespace-scoped `role-leader-election.yaml` events rule doesn't even render in the default case — so the gap was real and unconditional, not something the default leader-election path happened to cover.
- Reworded two pre-existing comments carried forward from plan 01 (`internal/operator/service_controller.go`) that contained the literal substrings this plan's own acceptance criteria grep for at an expected count of 0 — `services/status` (in a new RBAC comment I wrote for task 1) and `DefaultIP` (in plan 01's `ServiceReconciler.DefaultTags` doc comment). Both were prose explaining an absence, not actual grants or fields; reworded to keep the same meaning (`status subresource`, `default-IP field`) without matching the substring.
- `syncService`'s three early-return checks run in a fixed order — unsupported type first (so the `ip-address` override cannot resurrect it), then missing hostname, then IP resolution — exactly as the plan's action text specifies, which is a different (and narrower) ordering concern than `resolveServiceIP`'s own internal type-then-override-then-walk evaluation order.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Reworded self-inflicted acceptance-criteria false positives**

- **Found during:** Task 1 (after writing the RBAC comment) and Task 2 (running the full acceptance-criteria grep sweep)
- **Issue:** This plan's own acceptance criteria assert `grep -c 'services/status'` and `grep -c 'DefaultIP'` are both 0 against `internal/operator/service_controller.go`. The task-1 RBAC comment I wrote said "no Service status subresource," and plan 01's pre-existing `DefaultTags` doc comment said "there is deliberately no DefaultIP field" — both literal substrings, both true prose, both tripped the discipline check.
- **Fix:** Reworded both comments to preserve their exact meaning without the literal substrings (`services/status` → "status subresource"; `DefaultIP` → "default-IP field").
- **Files modified:** `charts/router-hosts-operator/templates/clusterrole.yaml`, `internal/operator/service_controller.go`
- **Verification:** Both `grep -c` counts confirmed 0 after the reword; `helm lint` and `task lint` still green.
- **Committed in:** `ad0d38c` (Task 1 commit) and `a1efba7` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (blocking, self-inflicted discipline-check false positive)
**Impact on plan:** No behavior change; comment wording only. No scope creep.

## Issues Encountered

None beyond the deviation above. Every `<verify>` and acceptance-criteria command from the plan was run exactly as written and produced the exact expected counts:

- `helm lint charts/router-hosts-operator` exits 0
- Pre-change `events` rule count: 0 (empirically confirmed per D-13); post-change: exactly 1, verbs `create`+`patch`
- `services` rule verbs line matches the exact five-verb string byte-for-byte
- `helm template ... --set rbac.create=false` renders zero `ClusterRole`
- `TestResolveServiceIP`: 10/10 `--- PASS` subtests
- `TestSyncService_Events`: 6/6 `--- PASS` subtests
- `TestSyncService_TerminalConditionsDoNotRequeue`: 4/4 `--- PASS` subtests
- `task build`, `task lint`, `task test:coverage:ci` (84.7%) all green
- `git diff --exit-code -- go.mod go.sum` exits 0 (zero new dependencies)

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `resolveServiceIP` and the four Event reasons are now complete per the locked D-09/D-10/D-11/D-12/D-14 matrix; plan 03 can build hostname validation and alias parsing on top without touching IP resolution or event semantics.
- The early-return branches in `syncService` are explicitly provisional per the plan's own note: plan 04 restructures them to fall through to the stale-cleanup diff pass (D-17) instead of returning early, while still emitting the same events.
- The cluster-scoped `events` RBAC grant also fixes `HostMappingReconciler`'s pre-existing silent-failure gap outside the operator namespace — no action needed by future phases, but worth knowing if a HostMapping event that "was already broken" starts appearing after this ships.
- D11 (live-cluster Events RBAC + `kubectl describe service` visibility) remains a manual/backstop verification per `08-VALIDATION.md` — not exercised in this session (no live cluster available); flagged for `/gsd-verify-work` or a future in-cluster smoke test.
- No blockers.

---

*Phase: 08-kubernetes-service-controller*
*Completed: 2026-07-26*

## Self-Check: PASSED

- FOUND: internal/operator/service_controller.go
- FOUND: internal/operator/service_controller_test.go
- FOUND: charts/router-hosts-operator/templates/clusterrole.yaml
- FOUND: .planning/phases/08-kubernetes-service-controller/08-02-SUMMARY.md
- FOUND: commit ad0d38c in git log
- FOUND: commit a9a8e54 in git log
- FOUND: commit a1efba7 in git log
- FOUND: commit 957a1de in git log
- FOUND: commit af417bb in git log
