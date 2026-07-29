---
status: partial
phase: 08-kubernetes-service-controller
source: [08-01-SUMMARY.md, 08-02-SUMMARY.md, 08-03-SUMMARY.md, 08-04-SUMMARY.md, 08-05-SUMMARY.md]
started: 2026-07-28T00:00:00.000Z
updated: 2026-07-28T00:00:00.000Z
---

# Phase 8: Kubernetes Service Controller — UAT

## Current Test

[testing complete]

## Tests

### 1. Cold Start — operator boots with the new flag

expected: |
  `task build` produces bin/operator, and `./bin/operator --help` lists `-enable-service` alongside the existing `-enable-gateway` and `-default-ingress-ip`. The flag defaults to false, so a chart upgrade cannot silently start a Service watch.

  Pre-verified: build green; --help shows all three flags.
result: pass
verified_by: orchestrator — `task build` green; `./bin/operator --help` lists -enable-service, -enable-gateway, -default-ingress-ip

### 2. D7 — LoadBalancer IP resolution rules

expected: |
  resolveServiceIP walks status.loadBalancer.ingress[] and takes the first entry with a non-empty .IP, never inferring from .Hostname, with the ip-address annotation overriding LB status.

  This was flagged at plan-01 time as having no direct unit test (deferred to plan 02/03 scope). Plan 02 delivered TestResolveServiceIP with 10 subtests, all passing, covering exactly the three gaps named: multi-entry ordering (loadbalancer_hostname_then_ip), hostname-only skip (loadbalancer_hostname_only_skipped), and annotation precedence (annotation_overrides_loadbalancer_status).
result: pass
verified_by: orchestrator — TestResolveServiceIP 10/10 subtests PASS, covering the three gaps named in the plan-01 flag: loadbalancer_hostname_then_ip (multi-entry ordering), loadbalancer_hostname_only_skipped (hostname-only skip), annotation_overrides_loadbalancer_status (precedence). The plan-01 deferral was closed by plan 02.

### 3. D5 — chart README is usable by a Service owner

expected: |
  charts/router-hosts-operator/README.md documents all four annotations, the IP-resolution rules, that --default-ingress-ip is NOT a Service fallback, the serviceController-vs-gateway.enabled asymmetry, and the cluster-wide informer cache footprint.

  Pre-verified by grep — all present: enabled x3, hostname x2, aliases x2, ip-address x1, default-ingress-ip x2, serviceController x4, informer x1. Machine-checkable presence is confirmed; what needs your judgment is whether the prose actually reads clearly enough for a Service owner to act on.
result: pass
verified_by: orchestrator — README.md:267-326 read in full. Contains a worked LoadBalancer example, the two-independent-gates explanation, a complete annotation reference table with a Required column, supported/unsupported types with the InvalidServiceType consequence, IP-resolution rules stated with rationale (CNAME target is not a host entry IP), the no-default-fallback divergence and why, all four Event reasons with their types, all four cleanup transitions, and the cache footprint. Reads as actionable for a Service owner.

### 4. D11 — Events reach kubectl describe in a live cluster

expected: |
  The operator ServiceAccount can create Events, so InvalidServiceType / MissingHostname / MissingIPAddress / PendingLoadBalancer reach `kubectl describe service` instead of failing silently.

  MEASURED AGAINST YOUR LIVE CLUSTER 2026-07-27: `kubectl auth can-i create events --as=system:serviceaccount:router-hosts-operator:router-hosts-operator` returns **no**, and the deployed ClusterRole has zero events rules. The fix is in the chart artifact but ArgoCD is pinned to 0.10.11. This is blocked on release + pin bump, not on code.
result: blocked
blocked_by: deployment
reason: "Measured against the live fzymgc-house cluster 2026-07-27: kubectl auth can-i create events --as=system:serviceaccount:router-hosts-operator:router-hosts-operator returns no, and the deployed ClusterRole has zero events rules. The mitigation is present in the chart artifact and regression-gated in task test:chart, but ArgoCD is pinned to chart 0.10.11 while the repo is at 0.10.13. Not a code defect — blocked on release + ArgoCD pin bump. See 08-SECURITY.md Deployment Caveat."

### 5. An opted-in LoadBalancer Service with one non-empty ingress IP produces one AddHost call with that IP, hostname, comment k8s-service:<ns>/<name>, and tags kubernetes+service

expected: An opted-in LoadBalancer Service with one non-empty ingress IP produces one AddHost call with that IP, hostname, comment k8s-service:<ns>/<name>, and tags kubernetes+service
result: pass
source: automated
coverage_id: 08-01/D1

### 6. After that reconcile the Service carries the service-cleanup finalizer and a host-ids annotation mapping hostname to the returned host ID

expected: After that reconcile the Service carries the service-cleanup finalizer and a host-ids annotation mapping hostname to the returned host ID
result: pass
source: automated
coverage_id: 08-01/D2

### 7. The watch predicate admits an Update where the enabled annotation was present on the old object and absent on the new object (D-05 opt-out hazard)

expected: The watch predicate admits an Update where the enabled annotation was present on the old object and absent on the new object (D-05 opt-out hazard)
result: pass
source: automated
coverage_id: 08-01/D3

### 8. The watch predicate refuses Create/Update-both-disabled for a Service with no enabled annotation, and admits Create/Delete for an enabled one (D-03)

expected: The watch predicate refuses Create/Update-both-disabled for a Service with no enabled annotation, and admits Create/Delete for an enabled one (D-03)
result: pass
source: automated
coverage_id: 08-01/D4

### 9. The operator registers no Service controller unless --enable-service was passed (defaults to false), wired with a Recorder

expected: The operator registers no Service controller unless --enable-service was passed (defaults to false), wired with a Recorder
result: pass
source: automated
coverage_id: 08-01/D5

### 10. go.mod/go.sum unchanged and defaultIngressIPWarning's two return strings unchanged — corev1.Service needed no new module, no scheme install, and the Service controller doesn't consume --default-ingress-ip

expected: go.mod/go.sum unchanged and defaultIngressIPWarning's two return strings unchanged — corev1.Service needed no new module, no scheme install, and the Service controller doesn't consume --default-ingress-ip
result: pass
source: automated
coverage_id: 08-01/D6

### 11. resolveServiceIP walks status.loadBalancer.ingress[] in declaration order and returns the first entry whose .ip is non-empty, skipping hostname-only entries including when the hostname-only entry comes first

expected: resolveServiceIP walks status.loadBalancer.ingress[] in declaration order and returns the first entry whose .ip is non-empty, skipping hostname-only entries including when the hostname-only entry comes first
result: pass
source: automated
coverage_id: 08-02/D1

### 12. A LoadBalancer Service with no resolvable ingress IP creates nothing, emits Normal PendingLoadBalancer, and requeues after requeueDelayShort

expected: A LoadBalancer Service with no resolvable ingress IP creates nothing, emits Normal PendingLoadBalancer, and requeues after requeueDelayShort
result: pass
source: automated
coverage_id: 08-02/D2

### 13. A NodePort Service resolves its IP only from the ip-address annotation; without it, creates nothing and emits Warning MissingIPAddress

expected: A NodePort Service resolves its IP only from the ip-address annotation; without it, creates nothing and emits Warning MissingIPAddress
result: pass
source: automated
coverage_id: 08-02/D3

### 14. The ip-address annotation overrides LoadBalancer status when both are present

expected: The ip-address annotation overrides LoadBalancer status when both are present
result: pass
source: automated
coverage_id: 08-02/D4

### 15. A ClusterIP or ExternalName Service that opted in creates nothing and emits Warning InvalidServiceType; the annotation override does not rescue an unsupported type

expected: A ClusterIP or ExternalName Service that opted in creates nothing and emits Warning InvalidServiceType; the annotation override does not rescue an unsupported type
result: pass
source: automated
coverage_id: 08-02/D5

### 16. An opted-in Service with no hostname annotation creates nothing and emits Warning MissingHostname

expected: An opted-in Service with no hostname annotation creates nothing and emits Warning MissingHostname
result: pass
source: automated
coverage_id: 08-02/D6

### 17. InvalidServiceType, MissingHostname, and MissingIPAddress each return without a timed requeue; only PendingLoadBalancer sets RequeueAfter

expected: InvalidServiceType, MissingHostname, and MissingIPAddress each return without a timed requeue; only PendingLoadBalancer sets RequeueAfter
result: pass
source: automated
coverage_id: 08-02/D7

### 18. No success-path event is emitted on create — the event stream carries only the four failure/waiting reasons

expected: No success-path event is emitted on create — the event stream carries only the four failure/waiting reasons
result: pass
source: automated
coverage_id: 08-02/D8

### 19. The rendered ClusterRole grants apiGroups [\"\"] resources [\"services\"] with exactly get, list, watch, update, patch

expected: The rendered ClusterRole grants apiGroups [\"\"] resources [\"services\"] with exactly get, list, watch, update, patch
result: pass
source: automated
coverage_id: 08-02/D9

### 20. The rendered ClusterRole grants apiGroups [\"\"] resources [\"events\"] with create and patch, cluster-scoped, and the pre-change gap (zero events rules) is empirically confirmed

expected: The rendered ClusterRole grants apiGroups [\"\"] resources [\"events\"] with create and patch, cluster-scoped, and the pre-change gap (zero events rules) is empirically confirmed
result: pass
source: automated
coverage_id: 08-02/D10

### 21. An invalid hostname annotation is logged at Warn and treated as absent (MissingHostname event), rather than becoming a bad DNS entry

expected: An invalid hostname annotation is logged at Warn and treated as absent (MissingHostname event), rather than becoming a bad DNS entry
result: pass
source: automated
coverage_id: 08-03/D1

### 22. A dot-less (non-FQDN) hostname is accepted and warned about, matching the other three controllers

expected: A dot-less (non-FQDN) hostname is accepted and warned about, matching the other three controllers
result: pass
source: automated
coverage_id: 08-03/D2

### 23. The aliases annotation is comma-split, trimmed, empty-segment-skipped, per-alias validated (IP rejection, canonical-hostname-match rejection, hostname validity), and case-insensitively deduped, each drop logged at Warn without failing the reconcile

expected: The aliases annotation is comma-split, trimmed, empty-segment-skipped, per-alias validated (IP rejection, canonical-hostname-match rejection, hostname validity), and case-insensitively deduped, each drop logged at Warn without failing the reconcile
result: pass
source: automated
coverage_id: 08-03/D3

### 24. The alias slice handed to AddHost/UpdateHost is never nil — an absent or emptied aliases annotation yields a non-nil empty slice, so a cleared aliases annotation actually clears server-side aliases instead of leaving them untouched

expected: The alias slice handed to AddHost/UpdateHost is never nil — an absent or emptied aliases annotation yields a non-nil empty slice, so a cleared aliases annotation actually clears server-side aliases instead of leaving them untouched
result: pass
source: automated
coverage_id: 08-03/D4

### 25. A tracked hostname is refreshed by reading the current entry first (supplying the optimistic-concurrency version to UpdateHost) and fails closed — no UpdateHost call — on any non-NotFound read error or an empty (nil, nil) read result, retaining the previously tracked ID

expected: A tracked hostname is refreshed by reading the current entry first (supplying the optimistic-concurrency version to UpdateHost) and fails closed — no UpdateHost call — on any non-NotFound read error or an empty (nil, nil) read result, retaining the previously tracked ID
result: pass
source: automated
coverage_id: 08-03/D5

### 26. A tracked ID the server reports as not found (on the pre-update read, or on the update itself) is recreated via addOrAdoptService rather than retained as a dead ID

expected: A tracked ID the server reports as not found (on the pre-update read, or on the update itself) is recreated via addOrAdoptService rather than retained as a dead ID
result: pass
source: automated
coverage_id: 08-03/D6

### 27. A fresh Service's aliases annotation is threaded through to AddHost in order on create

expected: A fresh Service's aliases annotation is threaded through to AddHost in order on create
result: pass
source: automated
coverage_id: 08-03/D7

### 28. All four D-17 stop-managing transitions (enabled flipped false, type changed to ClusterIP, hostname annotation changed, enabled annotation removed) delete the previously tracked host entry through the single desired-set diff, with the unconditional stale-cleanup pass running even when the desired set is empty

expected: All four D-17 stop-managing transitions (enabled flipped false, type changed to ClusterIP, hostname annotation changed, enabled annotation removed) delete the previously tracked host entry through the single desired-set diff, with the unconditional stale-cleanup pass running even when the desired set is empty
result: pass
source: automated
coverage_id: 08-04/D1

### 29. A corrupt host-ids annotation stops syncService before any HostClient call and requeues after requeueDelayShort with a non-nil error

expected: A corrupt host-ids annotation stops syncService before any HostClient call and requeues after requeueDelayShort with a non-nil error
result: pass
source: automated
coverage_id: 08-04/D2

### 30. A per-host delete failure during the stale-cleanup pass retains the failing entry's ID in the annotation alongside any newly created entry, and requeues after requeueDelayLong

expected: A per-host delete failure during the stale-cleanup pass retains the failing entry's ID in the annotation alongside any newly created entry, and requeues after requeueDelayLong
result: pass
source: automated
coverage_id: 08-04/D3

### 31. A reconcile with an unchanged desired set issues no object Update (no ResourceVersion bump), even though UpdateHost may still run

expected: A reconcile with an unchanged desired set issues no object Update (no ResourceVersion bump), even though UpdateHost may still run
result: pass
source: automated
coverage_id: 08-04/D4

### 32. Adoption on ErrHostAlreadyExists is refused unless BOTH the existing entry's comment equals k8s-service:<namespace>/<name> AND its tags contain \"service\"; a foreign entry (wrong comment OR wrong tags) is left untouched, never entering the Service's annotation, and never deleted

expected: Adoption on ErrHostAlreadyExists is refused unless BOTH the existing entry's comment equals k8s-service:<namespace>/<name> AND its tags contain \"service\"; a foreign entry (wrong comment OR wrong tags) is left untouched, never entering the Service's annotation, and never deleted
result: pass
source: automated
coverage_id: 08-04/D5

### 33. Deleting a Service deletes every host entry tracked in its annotation and only then removes the service-cleanup finalizer; a failed delete retains the remaining IDs, requeues, and keeps the finalizer; an unreadable annotation never releases the finalizer; a Service without the finalizer is a no-op

expected: Deleting a Service deletes every host entry tracked in its annotation and only then removes the service-cleanup finalizer; a failed delete retains the remaining IDs, requeues, and keeps the finalizer; an unreadable annotation never releases the finalizer; a Service without the finalizer is a no-op
result: pass
source: automated
coverage_id: 08-04/D6

### 34. serviceController.enabled exists in values.yaml, defaults to false, and the bare service: key remains unclaimed (D-23)

expected: serviceController.enabled exists in values.yaml, defaults to false, and the bare service: key remains unclaimed (D-23)
result: pass
source: automated
coverage_id: 08-05/D1

### 35. helm template with default values renders zero --enable-service args; with serviceController.enabled=true it renders exactly one, and --enable-gateway is unaffected in both directions

expected: helm template with default values renders zero --enable-service args; with serviceController.enabled=true it renders exactly one, and --enable-gateway is unaffected in both directions
result: pass
source: automated
coverage_id: 08-05/D2

### 36. task test:chart's six new assertions compare rendered content (never grep -q exit status alone) and each is proven to actually fail when the chart is wrong

expected: task test:chart's six new assertions compare rendered content (never grep -q exit status alone) and each is proven to actually fail when the chart is wrong
result: pass
source: automated
coverage_id: 08-05/D3

### 37. No ClusterRole renders at all when rbac.create=false, even with serviceController.enabled=true

expected: No ClusterRole renders at all when rbac.create=false, even with serviceController.enabled=true
result: pass
source: automated
coverage_id: 08-05/D4

## Summary

total: 37
passed: 36
issues: 0
pending: 0
skipped: 0
blocked: 1

*33 auto-passed by deterministic coverage classification; 3 verified by the orchestrator with evidence recorded per test; 1 blocked on deployment.*

## Gaps

[none yet]
