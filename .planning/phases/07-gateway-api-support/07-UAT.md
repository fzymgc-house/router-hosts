---
status: partial
phase: 07-gateway-api-support
source: [07-01-SUMMARY.md, 07-02-SUMMARY.md, 07-03-SUMMARY.md, 07-04-SUMMARY.md, 07-05-SUMMARY.md, 07-06-SUMMARY.md]
started: 2026-07-26
updated: 2026-07-26
---

# Phase 07 — UAT

> Conversational verification of what Phase 7 built. 34 of 37 deliverables were
> auto-covered by passing tests and recorded without being presented; the 3 human
> tests all share one live-cluster prerequisite.

## Current Test

[testing complete]

## Tests

### 1. Cold Start — operator boots with Gateway support OFF (default)

expected: Fresh build, started with no `--enable-gateway`. Boots clean; only HostMapping and IngressRoute controllers register; no Gateway API controller log lines; manager does not crash-loop.
result: blocked
blocked_by: other
reason: "User: I'm not going to deploy just to test this bit, but help verified, so it's partial"
partial_verification: |
  `./bin/operator --help` confirmed independently by the orchestrator: the flag is
  present and reads `-enable-gateway  Enable Gateway API HTTPRoute/GRPCRoute/TLSRoute
  controllers`. Go's flag package emits `(default ...)` only for non-zero defaults, and
  none is printed here — so the flag defaults to false, i.e. Gateway support is off
  unless explicitly enabled.
  NOT verified: runtime boot behavior against a live cluster (which controllers actually
  register, and that the manager does not crash-loop).

### 2. Opt-in gate — `--enable-gateway` registers Gateway controllers

expected: Same binary started WITH `--enable-gateway`. Logs one "Gateway API controller registered" line per route kind whose CRD is installed, each naming `watchesGateway`. Any route kind whose CRD is absent logs "Gateway API CRD not installed; skipping controller" naming the kind and `gateway.networking.k8s.io/v1` — and the manager still boots rather than crash-looping.
result: blocked
blocked_by: other
reason: "Same live-cluster prerequisite the user declined on test 1; not re-asked."
coverage_id: D5
source: human_judgment
partial_verification: |
  Registration and CRD-gating logic is unit-covered (`TestGatewayKindPresent_*`, 7 tests,
  including `_PartiallyInstalled`, `_AllAbsent`, `_WrongVersion`, `_GatewayGVKAbsent`), and
  the flag's existence/default is confirmed above. What remains unverified is the same
  thing 07-01's own coverage block flagged as needing human judgment: that a real manager
  boots with these controllers attached.

### 3. End-to-end — an HTTPRoute becomes a router DNS entry

expected: With `--enable-gateway` running, create an HTTPRoute with one hostname whose parent Gateway reports an `IPAddress`-typed `status.addresses` entry. Within a reconcile the router gains one DNS entry for that hostname at the Gateway's IP, tagged `kubernetes`/`gateway`/`httproute` with comment `k8s-gateway:<ns>/<name>`. The HTTPRoute gains the `router-hosts.fzymgc.house/gateway-cleanup` finalizer and a `host-ids` annotation. Deleting the HTTPRoute removes the entry and the finalizer.
result: blocked
blocked_by: other
reason: "Same live-cluster prerequisite the user declined on test 1; not re-asked."
partial_verification: |
  This is the item 07-VALIDATION.md classifies as genuinely unautomatable — it needs a real
  Gateway controller assigning `status.addresses` and a router-hosts server reachable over
  mTLS. The reconcile logic behind it is unit-covered end to end against a fake client
  (creation, finalizer, annotation, IP resolution, edit/delete convergence), but no test
  exercises the real gRPC + cluster path.

### 4. gateway-api v1.6.1 pinned; scoped `task test` genuinely scoped

expected: gateway-api v1.6.1 pinned with no k8s.io/*/controller-runtime movement; task test -- -run is genuinely scoped
result: pass
source: automated
coverage_id: 07-01/D1

### 5. Annotation helpers widened to client.Object

expected: getHostIDsAnnotation/setHostIDsAnnotation widened to client.Object; existing IngressRoute suite unaffected
result: pass
source: automated
coverage_id: 07-01/D2

### 6. One HTTPRoute + IP-bearing Gateway produces one AddHost

expected: One HTTPRoute + one IP-bearing parent Gateway produces exactly one AddHost with the resolved IP, gateway-cleanup finalizer, and host-ids annotation written
result: pass
source: automated
coverage_id: 07-01/D3

### 7. resolveIP walks parentRefs to status.addresses

expected: resolveIP walks parentRefs to the parent Gateway's status.addresses and returns the first IPAddress-typed value
result: pass
source: automated
coverage_id: 07-01/D4

### 8. Three route kinds registered at v1

expected: gatewayRouteKinds() has 3 entries (httproute, grpcroute, tlsroute), all at gateway.networking.k8s.io/v1, with matching newObject/newList factories
result: pass
source: automated
coverage_id: 07-02/T1

### 9. hostnamesOf/parentRefsOf uniform across kinds

expected: hostnamesOf and parentRefsOf return the same shapes for HTTPRoute, GRPCRoute, and TLSRoute, and nil for a non-route object (Gateway)
result: pass
source: automated
coverage_id: 07-02/T2

### 10. Wildcard hostname skipped

expected: A wildcard hostname is skipped and never becomes a router DNS entry (D-18)
result: pass
source: automated
coverage_id: 07-02/T3

### 11. Invalid hostname skipped without aborting batch

expected: A hostname that fails validation.ValidateHostname is logged and skipped without aborting the batch (D-18)
result: pass
source: automated
coverage_id: 07-02/T4

### 12. Duplicate hostnames collapse to one entry

expected: Duplicate hostnames within one route produce exactly one host entry, first-appearance order
result: pass
source: automated
coverage_id: 07-02/T5

### 13. Dot-less hostname warned and accepted

expected: A dot-less hostname is warned about and accepted (D-19)
result: pass
source: automated
coverage_id: 07-02/T6

### 14. No deprecated v1alpha* package imported

expected: No deprecated apis/v1alpha* Gateway API package is imported anywhere in the operator; task build/lint/coverage all green
result: pass
source: automated
coverage_id: 07-02/T7

### 15. parentRefs walked in declaration order, deterministically

expected: resolveIP walks parentRefs in declaration order and returns the first IPAddress-typed address from the first parent that has one, deterministically across repeated calls (D-15 ordering edge)
result: pass
source: automated
coverage_id: 07-03/T1

### 16. Hostname-typed/empty address never used as IP

expected: A Hostname-typed or empty-valued status address is never used as an entry IP, even when it is the only address a parent reports (D-15)
result: pass
source: automated
coverage_id: 07-03/T2

### 17. parentRef namespace defaulting

expected: A parentRef with no explicit namespace resolves against the route's own namespace; an explicit namespace is honored verbatim (D-15)
result: pass
source: automated
coverage_id: 07-03/T3

### 18. Fallback to --default-ingress-ip, else requeue

expected: A route with zero parentRefs or no resolvable parent IP falls back to --default-ingress-ip; when that is also empty, syncRoute requeues after requeueDelayShort and creates nothing (D-16)
result: pass
source: automated
coverage_id: 07-03/T4

### 19. NotFound Gateway skipped; walk continues

expected: A NotFound parent Gateway Get is skipped silently and the walk continues; a non-NotFound failure is logged and the walk still continues (D-16)
result: pass
source: automated
coverage_id: 07-03/T5

### 20. Wave 3 gates green

expected: task build, task lint (0 issues, manifests verified up to date), and task test:coverage:ci (>=80%) all green
result: pass
source: automated
coverage_id: 07-03/T6

### 21. Editing hostnames converges the router

expected: Editing a route's hostnames converges the router: newly added hostnames are created, retained hostnames are updated, and hostnames removed from the spec have their entries deleted and dropped from the host-ids annotation
result: pass
source: automated
coverage_id: 07-04/D1

### 22. UpdateHost issued unconditionally (D-13)

expected: UpdateHost is issued for every already-tracked hostname on every reconcile that reaches syncRoute, even when the resolved IP is unchanged — the intentional D-13 mechanism that propagates a changed Gateway IP without extra state
result: pass
source: automated
coverage_id: 07-04/D2

### 23. No-op annotation write skipped

expected: The object Update is skipped when the recomputed host-ids map equals the stored one and the finalizer is already present
result: pass
source: automated
coverage_id: 07-04/D3

### 24. Delete removes entries then finalizer

expected: Deleting a route deletes every host entry recorded in its host-ids annotation and only then removes the gateway-cleanup finalizer
result: pass
source: automated
coverage_id: 07-04/D4

### 25. Partial failure never orphans an entry

expected: A partial delete or per-host sync failure never orphans an entry: still-undeleted/still-retained IDs are persisted back to the annotation, the finalizer (on delete) is kept, and the reconcile requeues instead of aborting the batch
result: pass
source: automated
coverage_id: 07-04/D5

### 26. Corrupt annotation fails closed

expected: A corrupt host-ids annotation returns an error and requeues rather than proceeding on a partial view and deleting entries it can no longer see, in both syncRoute and reconcileDelete
result: pass
source: automated
coverage_id: 07-04/D6

### 27. No cross-owner deletion (T-07-02)

expected: DeleteHost is only ever invoked with host IDs read from the reconciled object's own host-ids annotation — a hostname shared with another route never causes cross-owner deletion (threat T-07-02)
result: pass
source: automated
coverage_id: 07-04/D7

### 28. Wave 4 gates green

expected: task build, task lint (0 issues, manifests verified up to date), and task test:coverage:ci (>=80%) all green
result: pass
source: automated
coverage_id: 07-04/D8

### 29. Gateway change re-enqueues referencing routes

expected: A Gateway status change re-enqueues exactly the routes of one kind whose parentRefs name it, via a field index and Gateway watch, so a changed status.addresses value propagates without polling
result: pass
source: automated
coverage_id: 07-05/D1

### 30. Index key format and namespace defaulting

expected: routeParentRefIndexFunc emits <namespace>/<name> per parentRef, defaulting the namespace to the route's own when the parentRef sets none, in declaration order, and an empty non-nil slice for a route with no parentRefs or a non-route object
result: pass
source: automated
coverage_id: 07-05/D2

### 31. mapGatewayToRoutes degrades safely

expected: mapGatewayToRoutes degrades safely (logs, returns nil) on a List or list-extraction failure instead of panicking or propagating an error the handler.MapFunc signature cannot carry
result: pass
source: automated
coverage_id: 07-05/D3

### 32. Zero route CRDs builds zero controllers

expected: With zero Gateway API route CRDs installed, SetupGatewayControllers constructs zero controllers and a nil error; a route kind whose GroupKind resolves only at a non-v1 version is skipped, not built at that older version
result: pass
source: automated
coverage_id: 07-05/D4

### 33. Gateway CRD absent → watch not registered

expected: With route CRDs installed but the Gateway CRD absent, the Gateway watch clause is not registered on any route controller — computed once via gatewayKindPresent(mapper, gatewayGVK) and threaded through SetupWithManager's watchGateway parameter — so the manager's shared informer cache never attempts to start an informer for an unresolvable Gateway GVK
result: pass
source: automated
coverage_id: 07-05/D5

### 34. Wave 5 gates green

expected: task build, task lint (0 issues, manifests verified up to date), and task test:coverage:ci (>=80%) all green
result: pass
source: automated
coverage_id: 07-05/D6

### 35. ClusterRole least privilege

expected: ClusterRole grants get/list/watch/update/patch on httproutes, grpcroutes, tlsroutes and get/list/watch on gateways, nothing more, inside the existing rbac.create guard
result: pass
source: automated
coverage_id: 07-06/D1

### 36. gateway.enabled defaults false and gates the arg

expected: gateway.enabled defaults to false and gates the --enable-gateway deployment arg
result: pass
source: automated
coverage_id: 07-06/D2

### 37. README documents the CRD prerequisite

expected: README documents the Gateway API CRD cluster prerequisite, gateway.enabled value, RBAC, entry provenance, IP-resolution rule, and troubleshooting paths
result: pass
source: automated
coverage_id: 07-06/D3

## Summary

total: 37
passed: 34
issues: 0
pending: 0
skipped: 0
blocked: 3

## Gaps

[none — no defects were reported]

Blocked tests are prerequisite gates, not code issues, so they are deliberately not
recorded as gaps and do not spawn fix plans. All three share one prerequisite: a live
Kubernetes cluster with Gateway API CRDs, a Gateway controller assigning
`status.addresses`, and a reachable router-hosts server over mTLS.

## Unblocking

To close tests 1–3 later, deploy the chart with Gateway support on and re-run
`/gsd-verify-work 7` — it will resume at the first blocked test:

```text
helm upgrade --install router-hosts-operator charts/router-hosts-operator \
  --set gateway.enabled=true
kubectl logs -l app.kubernetes.io/name=router-hosts-operator | grep -i gateway
```

Expect one `Gateway API controller registered` line per installed route kind, and
`Gateway API CRD not installed; skipping controller` for any absent kind.
