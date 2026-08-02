# Phase 8: Kubernetes Service Controller - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-26
**Phase:** 8-kubernetes-service-controller
**Mode:** `--all --auto --chain` — all gray areas auto-selected, every question
auto-resolved to the recommended option, no interactive prompts.
**Areas discussed:** Enablement & watch scope, Hostname & alias source, IP
resolution, Unsupported types & failure signalling, Lifecycle & cleanup,
Provenance & adoption, Chart / RBAC surface

---

## Enablement & Watch Scope

Every cluster has hundreds of Services, most of them ClusterIP noise — the
opposite of HTTPRoutes and IngressRoutes, which are rare and intrinsically
hostname-bearing. This is the defining constraint of the phase.

| Option | Description | Selected |
|--------|-------------|----------|
| Flag + per-object annotation + predicate | `--enable-service` (default false) *and* `router-hosts.fzymgc.house/enabled: "true"`; predicate filters the reconcile queue | ✓ |
| Per-object annotation only | Skip the operator flag; rely on the annotation alone | |
| Flag only, reconcile every Service | Mirror IngressRoute, which reconciles all objects of its kind | |
| Label-based opt-in + scoped informer cache | Use a label so `cache.ByObject` can filter server-side | |

**Choice:** flag + annotation + predicate (D-03, D-04).
**Notes:** Both gates are independent and neither substitutes for the other —
the flag stops a chart upgrade from silently starting a Service watch (the
T-07-17 threat class); the annotation stops the controller acting on a Service
its owner did not mark. The label variant was rejected for now because
annotations cannot drive a cache selector, so adopting it would change the
opt-in contract; it is recorded as a deferred idea with the memory trade-off
noted. The predicate filters *events*, not the informer cache — the manager
still caches every Service. Accepted at homelab scale, documented in the chart
README. Sub-decision D-05: the predicate must admit update events where the
annotation is being *removed*, or opting out becomes invisible.

---

## Hostname & Alias Source

| Option | Description | Selected |
|--------|-------------|----------|
| Required `hostname` annotation + optional `aliases` → native Aliases field | One host entry, N names; single-key `host-ids` map | ✓ |
| Required `hostname` annotation only | Drop aliases from scope | |
| `aliases` as N separate host entries | One entry per name, N-key `host-ids` map | |
| Derive hostname from `<name>.<namespace>` convention | No annotation needed | |

**Choice:** required `hostname`, optional comma-separated `aliases` mapped to the
entry's native `Aliases` field (D-06, D-07).
**Notes:** A Service has no hostname in its spec — the structural difference from
every other source in this operator — so explicit registration is the feature,
not a workaround. `HostClient.AddHost`/`UpdateHost` have carried an `aliases`
parameter since Phase 1 that both existing controllers pass `nil` for; ALIAS-01
is shipped. Using it keeps the `host-ids` annotation a single-key map, which
keeps the diff logic trivial. Convention-derived hostnames were rejected: they
would register entries for Services whose owners never asked. Dot-less hostnames
stay warn-but-accept (D-08), consistent with Phase 7 D-19.

---

## IP Resolution

| Option | Description | Selected |
|--------|-------------|----------|
| LB: first ingress with non-empty `.ip`; NodePort: annotation required; annotation overrides LB; **no** `--default-ingress-ip` fallback | Service resolves its own IP or produces nothing | ✓ |
| Same, but fall back to `--default-ingress-ip` | Consistent with IngressRoute and Gateway controllers | |
| Resolve hostname-typed LB ingress via DNS lookup | Support AWS-ELB-style CNAME targets | |
| Register every IP in `status.loadBalancer.ingress[]` | Dual-stack / multi-IP support | |

**Choice:** no shared-default fallback; skip hostname-only ingress entries; first
`.ip`-bearing entry wins; requeue short while pending (D-09, D-10, D-11).
**Notes:** The fallback was rejected on two grounds. A Service's IP is knowable
from the object itself, so a default is a guess rather than a fallback. More
concretely, the T-07-02 comment at `gateway_controller.go:610-613` names the
shared `--default-ingress-ip` as exactly what makes cross-controller
`(ip, hostname)` collisions "arise in ordinary use" — a third consumer widens the
adoption-collision surface for no benefit. This is a deliberate divergence from
the other two controllers and is called out as such. Consequence recorded in
D-26: `defaultIngressIPWarning` must *not* grow a Service clause, since naming a
controller that does not use the flag is the WR-01 mistake that function exists
to prevent. Skipping hostname-typed ingress mirrors Phase 7 D-15 verbatim.

---

## Unsupported Types & Failure Signalling

| Option | Description | Selected |
|--------|-------------|----------|
| Kubernetes Warning/Normal Events for the 4 failure/waiting states + logs | `kubectl describe service` shows why nothing happened | ✓ |
| Structured logs only | No Recorder, no new RBAC | |
| All 6 events from the Rust design incl. success events | Full parity with historical intent | |
| Service status write-back | Conditions on the object | |

**Choice:** four events — `InvalidServiceType`, `MissingHostname`,
`MissingIPAddress` (Warning) and `PendingLoadBalancer` (Normal); success events
dropped (D-12).
**Notes:** A Service's owner is usually not the cluster operator and will not
read operator logs. Success events were dropped because they fire on every
reconcile and would flood the event stream; the existing `log.Info` covers them.
This choice carries a real cost, recorded as D-13: the chart grants **no
`events` permission at all** — the only `events` rule is namespace-scoped in
`role-leader-election.yaml` — so `HostMappingReconciler.Recorder` is very likely
failing silently today for any HostMapping outside the operator namespace.
Adopting events means adding cluster-scoped `events: create,patch`, which fixes
HostMapping as a side effect. D-13 requires verifying the gap empirically before
writing the fix. Status write-back was rejected: Services have no
extension-friendly status subresource.

---

## Lifecycle, Mutation & Cleanup

| Option | Description | Selected |
|--------|-------------|----------|
| Desired-set vs annotation diff, **no early return** on empty desired set | One code path handles all four "stop managing" transitions | ✓ |
| Early-return when the Service is no longer managed | Simpler reconcile head | |
| Grace-period annotation + deletion scheduler | Rust design parity | |

**Choice:** desired-set diff with no early return; finalizer
`router-hosts.fzymgc.house/service-cleanup`; reuse `hostIDsAnnotation`
(D-15, D-16, D-17, D-18, D-19).
**Notes:** This is the Phase 7 07-04 bug fix carried forward — the stale-cleanup
delete pass must run even when the desired set is empty, which is what makes
`enabled: "false"`, a LoadBalancer→ClusterIP type change, a renamed `hostname`
annotation, and annotation removal all work through one path instead of four
special cases. `getHostIDsAnnotation`/`setHostIDsAnnotation` already take
`client.Object` after Phase 7's D-11 widening, so `*corev1.Service` needs no
further signature change. Grace periods were deferred: the Go operator never
ported `DeletionScheduler`, and a grace period that does not survive an operator
restart is not a real feature.

---

## Provenance & Adoption

| Option | Description | Selected |
|--------|-------------|----------|
| Comment `k8s-service:<ns>/<name>` + tags `["kubernetes","service"]`, both checked on adopt | Mirrors `hasIngressProvenance` | ✓ |
| Comment check only | One kind, so tags add little | |
| Also accept a user-supplied `tags` annotation | Rust design parity | |

**Choice:** both halves checked; no user `tags` annotation this phase
(D-20, D-21, D-22).
**Notes:** `FindHost` matches on `(ip, hostname)` alone, which is not proof of
ownership — adopting a foreign entry writes a foreign ID into this Service's
annotation, after which stale-cleanup and delete legitimately destroy another
owner's live DNS entry. D-11 makes the collision less likely here but does not
make the check optional. `k8s-service:` is prefix-disjoint from `k8s:`,
`k8s-ingress:`, and `k8s-gateway:`. Only one kind, so a single
`hasServiceProvenance(tags)` helper — no `KindName` parameter like the Gateway
reconciler needs. User tags were deferred because provenance tags are
load-bearing for ownership, and mixing user-controlled values into that field
reintroduces the HostMapping asymmetry `gateway_controller.go:620-626` warns
about.

---

## Chart / RBAC Surface

| Option | Description | Selected |
|--------|-------------|----------|
| `serviceController.enabled` values key | Avoids the Helm `service:` convention | ✓ |
| `service.enabled` | Symmetric with the existing `gateway.enabled` | |

**Choice:** `serviceController.enabled` (D-23), plus `services` write verbs, the
`events` rule, kubebuilder markers, and extended `task test:chart`
(D-24, D-25).
**Notes:** `service:` is a near-universal Helm convention for *the chart's own
Service resource*; claiming it would be a permanent source of confusion and
would block ever adding a real Service to this chart. This deliberately breaks
symmetry with `gateway.enabled` (`values.yaml:55`), so the chart README must say
the asymmetry is intentional — flagged in CONTEXT.md § Specific Ideas as the
decision most likely to be "corrected" back to the wrong answer by an agent
pattern-matching on the Gateway work. Extending `task test:chart` is a standing
instruction recorded when that task was built: extend it whenever a phase adds
chart surface.

---

## Claude's Discretion

Auto-resolved under `--auto`; every question took the recommended option. The
planner retains latitude on: task ordering and granularity (there is no
dependency build-gate this phase — see D-01); file layout for the reconciler;
whether IP resolution is one function with a type switch or two; log and event
message wording; where the annotation-key constants are declared; how the alias
list is split. None of these change observable behavior.

## Deferred Ideas

Recorded in full in `08-CONTEXT.md` § Deferred Ideas: user-supplied `tags`
annotation, deletion grace period, label-based opt-in with a scoped informer
cache, multi-IP / dual-stack entries, hostname-typed (CNAME) LoadBalancer
ingress, `ExternalName` and headless Services, Service status write-back,
project-wide FQDN enforcement, and refreshing the two 2026-01-02 Rust-era docs
in place.
