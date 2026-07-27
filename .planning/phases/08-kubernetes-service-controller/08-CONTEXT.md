# Phase 8: Kubernetes Service Controller - Context

**Gathered:** 2026-07-26
**Status:** Ready for planning

<domain>

## Phase Boundary

Add a Kubernetes `v1/Service` controller to the router-hosts operator
(`cmd/operator`, `internal/operator`): watch Services, and for each Service that
explicitly opts in via annotation and is of type `LoadBalancer` or `NodePort`,
resolve its IP and sync its annotated hostname (plus optional aliases) to the
router-hosts gRPC server as a host entry — with the same `host-ids` annotation +
cleanup-finalizer lifecycle the IngressRoute and Gateway API controllers use.
Ships with RBAC (ClusterRole + kubebuilder markers), Helm chart wiring, and an
extension of `task test:chart`.

Delivers REQUIREMENTS.md **SVC-01** (create entries for LoadBalancer/NodePort
Services from configured annotations) and **SVC-02** (resolve Service IPs;
remove entries on Service deletion).

**Not in this phase:** `ClusterIP` / `ExternalName` / headless Service support,
multi-IP or dual-stack (AAAA) entries, deletion grace periods, a user-supplied
`tags` annotation, label-selector-based cache scoping, Service `status`
write-back, hook reliability/metrics (Phase 9), consumer-rendered output
(Phase 10).

**Note on the historical design:** `docs/plans/2026-01-02-service-controller-design.md`
is a Rust-era document (kube-rs, `service.rs`, `DeletionScheduler`,
`RetryTracker`). Its *behavioral contract* — supported types, IP-resolution
table, annotation names, the reconcile flow — is the intent of record and is
carried forward here. Its *implementation sections* (file paths, crate
structure, reused Rust components) are superseded by the Go operator's existing
controller shape. Every supersession is recorded as a numbered decision below.

</domain>

<decisions>

## Implementation Decisions

Auto-resolved under `--auto` — every question took the recommended option.
Rationale is recorded per decision so a reviewer can dissent with evidence.

### Dependency & Scheme Surface

- **D-01:** **No new module dependency and no new scheme install.**
  `corev1.Service` is already registered through `clientgoscheme.AddToScheme(scheme)`
  (`cmd/operator/main.go:60`) and `corev1` is already imported by
  `internal/operator/hostmapping_controller.go`. Unlike Phase 7, there is **no
  build-gate task** — planning should not budget one. If `go.mod` changes at all
  during this phase, that is a signal something is wrong.
- **D-02:** **No CRD-presence / RESTMapper gating.** `v1/Service` is core
  Kubernetes and cannot be absent. The Phase 7 `gatewayKindPresent` machinery
  (D-04/D-05) has no analogue here and must not be copied.

### Enablement & Watch Scope

- **D-03:** **Two independent gates, both required.**
  (a) An operator-level `--enable-service` flag on `cmd/operator`, defaulting to
  `false`, mirroring `--enable-gateway` (`main.go:48`). (b) A per-Service opt-in
  annotation `router-hosts.fzymgc.house/enabled: "true"`, taken verbatim from the
  Rust design. Rationale: the flag keeps a chart upgrade from silently starting a
  Service watch at all (the same threat class as T-07-17); the annotation keeps
  the controller from ever acting on a Service its owner did not mark. Neither
  gate substitutes for the other. — **Reversibility:** costly — once
  `router-hosts.fzymgc.house/enabled` ships, live Services in user clusters carry
  it; renaming the key silently de-registers every managed Service on the next
  reconcile and orphans their DNS entries.
- **D-04:** **Filter with a controller-runtime predicate, not a scoped cache.**
  Register `For(&corev1.Service{}, builder.WithPredicates(...))` where the
  predicate admits only Services carrying `enabled: "true"`. Accept that the
  manager's shared informer still **caches every Service in the cluster** — this
  is a homelab-scale router control plane, and the alternative (a
  `cache.ByObject` field/label selector) cannot filter on an annotation, only on
  a label, which would mean changing the opt-in contract. Document the memory
  characteristic in the chart README; see Deferred Ideas for the label variant.
- **D-05:** Predicate must admit **update events where the annotation is being
  removed** (old object had it, new object does not), otherwise opting a Service
  out becomes invisible to the controller and its DNS entry is orphaned. A naive
  `newObject`-only predicate is the bug here; write the test for it.

### Hostname & Alias Source

- **D-06:** **`router-hosts.fzymgc.house/hostname` is required** and carries
  exactly one hostname. A Service has no hostname in its spec — this is the
  structural difference from every other source in this operator — so
  registration stays explicit. A Service that opts in without this annotation is
  a configuration error (see D-12), not a silent skip.
- **D-07:** **Optional `router-hosts.fzymgc.house/aliases`, comma-separated,
  mapped to the host entry's native `Aliases` field** — not to N separate host
  entries. `HostClient.AddHost`/`UpdateHost` already take an `aliases []string`
  parameter (`internal/operator/hostclient.go:24,29`) that the IngressRoute and
  Gateway controllers pass `nil` for; ALIAS-01 is a shipped Phase 1 capability.
  Consequence: the `host-ids` annotation stays a **single-key** map for a
  Service, which keeps the diff logic trivial. Each alias is validated with
  `internal/validation`; an invalid alias is logged and dropped, never fatal.
- **D-08:** Validate the hostname with `internal/validation.ValidateHostname`.
  Dot-less (non-FQDN) names are **warned about but accepted**, matching Phase 7
  D-19 and the existing controllers. Under locked ADR `router-hosts-bzg` a bare
  name makes unbound authoritative for a whole pseudo-TLD; enforcing it in only
  this controller would make the operator inconsistent with itself.

### IP Resolution

- **D-09:** **LoadBalancer:** walk `status.loadBalancer.ingress[]` in order and
  take the first entry with a **non-empty `.ip`**. Entries carrying only
  `.hostname` (AWS ELB style) are **skipped, not resolved** — this mirrors Phase 7
  D-15 verbatim ("a CNAME target is not a host entry IP"). If no entry yields an
  IP, the load balancer is still provisioning: **requeue after
  `requeueDelayShort` and create nothing.** Never write an IP-less entry.
- **D-10:** **NodePort:** the IP comes only from
  `router-hosts.fzymgc.house/ip-address`. NodePort exposes on every node, so
  which IP to publish is topology-dependent and cannot be inferred. A NodePort
  Service without this annotation is a configuration error (D-12).
- **D-11:** **`ip-address` overrides LoadBalancer status when both are present**
  (per the Rust design's "optional override for LoadBalancer"), and
  **`--default-ingress-ip` is NOT a fallback for Services** — this is a
  deliberate divergence from the IngressRoute and Gateway controllers. Two
  reasons: (1) a Service's IP is knowable from the object itself, so a default is
  a guess, not a fallback; (2) the shared `--default-ingress-ip` is precisely
  what makes cross-controller `(ip, hostname)` collisions "arise in ordinary use"
  per the T-07-02 comment at `gateway_controller.go:610-613` — adding a third
  consumer widens the adoption-collision surface for no benefit. A Service that
  cannot resolve its own IP produces no entry.

### Unsupported Types & Failure Signalling

- **D-12:** **Emit Kubernetes Events, not just logs**, for the four operator-
  visible failure/waiting states, carrying the Rust design's reason strings
  forward: `InvalidServiceType` (Warning — ClusterIP/ExternalName annotated),
  `MissingHostname` (Warning), `MissingIPAddress` (Warning — NodePort without
  `ip-address`), `PendingLoadBalancer` (Normal). Rationale: a Service is a
  resource whose owner is usually not the cluster operator, and `kubectl describe
  service` is where they will look. Wire a `Recorder events.EventRecorder` field
  the same way `HostMappingReconciler` does (`hostmapping_controller.go:43`,
  `main.go:109`). Success-path events (`HostRegistered` / `HostDeleted`) are
  **dropped** — they fire on every reconcile and would flood the event stream;
  the existing `log.Info("host entry created from …")` line covers them.
- **D-13:** **Adopting D-12 requires fixing a pre-existing RBAC gap.**
  `charts/router-hosts-operator/templates/clusterrole.yaml` grants **no `events`
  permission at all**; the only `events` rule is namespace-scoped in
  `role-leader-election.yaml` (the operator's own namespace). Today's
  `HostMappingReconciler.Recorder` is therefore almost certainly failing silently
  in-cluster for any HostMapping outside the operator namespace. This phase adds
  a cluster-scoped `apiGroups: [""] resources: ["events"] verbs: ["create","patch"]`
  rule (plus the matching kubebuilder marker), which fixes HostMapping's recorder
  as a side effect. **Verify the existing gap before writing the fix** — if it
  turns out events already work through some path not visible in the chart, drop
  this and say so.
- **D-14:** An unsupported type or a missing required annotation is a
  **terminal-for-now** condition: emit the event, log, and return without
  requeueing on a timer. The next Service update re-triggers reconcile naturally.
  Only `PendingLoadBalancer` requeues (D-09).

### Lifecycle, Mutation & Cleanup

- **D-15:** **Reuse the `hostIDsAnnotation`** (`router-hosts.fzymgc.house/host-ids`,
  `ingressroute_controller.go:31`) as the `hostname → hostID` map, shared with the
  IngressRoute and Gateway controllers. Safe because a given object is only ever
  one kind. `getHostIDsAnnotation`/`setHostIDsAnnotation` already take
  `client.Object` after Phase 7's D-11 widening, so `*corev1.Service` works with
  no further signature change. — **Reversibility:** costly — changing the key
  later orphans host IDs recorded on live Services.
- **D-16:** **Finalizer is `router-hosts.fzymgc.house/service-cleanup`**, a fourth
  distinct finalizer alongside `host-cleanup`, `ingressroute-cleanup`, and
  `gateway-cleanup`. — **Reversibility:** one-way — once deployed, live Services
  carry this exact string; renaming it strands finalizers and blocks Service
  deletion until an operator patches every affected object.
- **D-17:** **Compute a desired set and diff it against the annotation — never
  early-return on an empty desired set.** This is the Phase 7 07-04 bug fix
  carried forward: the stale-cleanup delete pass must run even when the desired
  set is empty. It is what makes all four "stop managing this" transitions work
  through one code path: `enabled` flipped to `"false"`, type changed
  LoadBalancer→ClusterIP, `hostname` annotation edited to a new name, or the
  annotation removed entirely. Each produces a desired set that no longer
  contains the old hostname, and the diff deletes its entry.
- **D-18:** Preserve the established error semantics verbatim: per-host errors do
  not abort the batch, partial IDs are **always** persisted to the annotation, a
  corrupt `host-ids` annotation returns an error and requeues (never proceeds on
  a partial view), all fallible calls wrapped with `oops.Wrapf`, requeue via the
  existing `requeueDelayShort`/`requeueDelayLong` constants, no
  `log.Fatal`/`os.Exit`.
- **D-19:** **Skip the object `Update` when nothing changed** (Phase 7 D-13):
  if the recomputed `host-ids` map equals the existing annotation and the
  finalizer is already present, do not issue the write. `UpdateHost` for an
  already-tracked hostname stays **unconditional**, so a changed LoadBalancer IP
  propagates without extra state. Guard the update with the same
  read-before-write / fail-closed rule the IngressRoute controller uses
  (`ingressroute_controller.go:245-250`) so a blind `UpdateHost` cannot re-append
  events (#338).

### Provenance & Adoption Safety

- **D-20:** Entry provenance: comment **`k8s-service:<namespace>/<name>`**; tags
  **`DefaultTags + ["service"]`** (i.e. `["kubernetes", "service"]`). The comment
  prefix is disjoint from `k8s:` (HostMapping), `k8s-ingress:` (IngressRoute), and
  `k8s-gateway:` (Gateway routes).
- **D-21:** **Gate adoption on provenance — both halves.** Mirror
  `addOrAdopt` + `hasIngressProvenance` (`ingressroute_controller.go:260-309`):
  on `ErrHostAlreadyExists`, `FindHost`, then refuse to adopt unless
  `existing.Comment == comment` **and** `slices.Contains(existing.Tags, "service")`.
  `FindHost` matches on `(ip, hostname)` alone, which is not proof of ownership —
  adopting a foreign entry writes a foreign ID into this Service's annotation, and
  the stale-cleanup and delete passes then legitimately `DeleteHost` another
  owner's live DNS entry. Unlike the Gateway controller there is only one kind, so
  no `KindName` parameter is needed — a single `hasServiceProvenance(tags)`
  helper. Note that D-11 (no shared `--default-ingress-ip`) makes the collision
  *less* likely here, but does not make the check optional.
- **D-22:** **No user-supplied `tags` annotation in this phase.** The Rust design
  listed one; it is deferred. Provenance tags are load-bearing for ownership
  (D-21), and mixing user-controlled values into the same field reintroduces the
  HostMapping asymmetry that `gateway_controller.go:620-626` explicitly warns
  about. Adding it later is a small, additive change that should come with its own
  ownership analysis. See Deferred Ideas.

### Chart, RBAC & Verification Surface

- **D-23:** **Helm values key is `serviceController.enabled`, NOT `service.enabled`.**
  `service:` is a near-universal Helm convention for *the chart's own Service
  resource*; claiming that key would be a permanent source of confusion and would
  block ever adding a real Service to this chart. This deliberately breaks
  symmetry with the existing `gateway.enabled` key (`values.yaml:55`) — call that
  out in the chart README so the asymmetry reads as intentional.
- **D-24:** ClusterRole additions: `apiGroups: [""] resources: ["services"]
  verbs: ["get","list","watch","update","patch"]` — write verbs are required
  because the controller writes the finalizer and the `host-ids` annotation back
  onto the Service. Plus the `events` rule from D-13. Mirror both in kubebuilder
  markers on the reconciler, exactly as the other three controllers do.
- **D-25:** **Extend `task test:chart`** (`Taskfile.yml:55`) with the parallel
  assertions the Gateway work added: `--enable-service` absent under default
  values, present under `--set serviceController.enabled=true`, `services` granted
  write verbs while nothing unexpected is, and zero ClusterRole under
  `rbac.create=false`. This is an explicit standing instruction recorded when that
  task was built: extend it whenever a phase adds chart surface.
- **D-26:** Update `defaultIngressIPWarning` (`main.go:167`) **only if needed** —
  under D-11 the Service controller does not consume `--default-ingress-ip`, so
  the warning text must **not** grow a Service clause. Naming a controller that
  does not use the flag is the exact WR-01 mistake that function exists to avoid.

### Testing

- **D-27:** `internal/operator/service_controller_test.go`, fake client on the
  existing scheme (no gateway-api scheme needed), reusing the package-level
  `mockHostClient` from `hostmapping_controller_test.go` — do **not** write a
  second mock. Coverage must hold ≥80% (`task test:coverage:ci`). Required cases:
  opt-in predicate incl. the **annotation-removal update** (D-05); type matrix
  (LoadBalancer / NodePort / ClusterIP / ExternalName); LB IP resolution incl.
  hostname-only ingress skipped, multiple ingress entries, empty status →
  requeue; NodePort with and without `ip-address`; `ip-address` overriding LB
  status; aliases parsing incl. an invalid alias dropped; each of the four
  Kubernetes Events emitted with the right reason and type; finalizer add and
  cleanup-on-delete; the four "stop managing" transitions of D-17; adoption
  refused on foreign comment and on foreign tags (D-21); corrupt `host-ids`
  annotation returns an error rather than proceeding.
- **D-28:** Assert Events using a **fake recorder**, and assert on the reason
  string, not the message text — reason strings are the contract users script
  against, messages are not.

### Claude's Discretion

Auto-resolved under `--auto`. The planner has latitude on: task ordering and
granularity; whether the reconciler lives in a new `service_controller.go` or
shares a file; whether IP resolution is one function with a type switch or two;
exact log and event message wording; whether the annotation-key constants are
grouped into one `const` block with the existing ones or declared locally; how
the alias list is split (`strings.Split` + `TrimSpace` vs a helper). None of
these change observable behavior.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase design (behavioral contract of record)

- `docs/plans/2026-01-02-service-controller-design.md` — the Rust-era design,
  **Status: Approved**. Authoritative for: the supported-type table and its
  IP-resolution rules, the annotation names, the reconcile flow, and the
  Kubernetes Event reason strings. **Superseded sections that MUST NOT be
  followed as written:** the entire *Implementation* section (`service.rs`,
  `controllers/mod.rs`, `main.rs`, `is_enabled()`/`extract_hostname()`/… — Rust
  file and function layout), *Reused Components* (`DeletionScheduler`,
  `RetryTracker`, `config.rs` — none exist in the Go operator), the
  `grace-period` annotation (→ D-16, finalizer-based immediate cleanup), the
  `tags` annotation (→ D-22, deferred), and the `HostRegistered`/`HostDeleted`
  success events (→ D-12, dropped).
- `docs/plans/2026-01-02-service-controller-impl.md` — the Rust-era task-by-task
  implementation plan (33 KB). **Reference only; do not execute.** Same
  Rust-stack staleness as the design doc, at greater length. The GSD planner
  writes its own PLAN.md.
- `.planning/phases/07-gateway-api-support/07-CONTEXT.md` — the immediately
  preceding controller build. Its D-09 through D-14 (finalizer, annotation reuse,
  provenance, no-op update skip, error semantics) are the pattern this phase
  follows; read them before re-deriving anything.

### Project constraints (locked)

- `.planning/PROJECT.md` § Locked Decisions — ADR `router-hosts-bzg` (unbound
  per-name `static` zones) is what makes D-08's dot-less-hostname warning matter.
  ADRs `router-hosts-v5b` / `-vl8` / `-4w2` govern compaction and do not
  constrain this phase.
- `.planning/PROJECT.md` § Constraints — `CGO_ENABLED=0`, SQLite-only,
  single-goroutine `WriteQueue` (new write paths must be retry-safe/idempotent),
  mTLS-only with no `InsecureSkipVerify`, `samber/oops` errors, ≥80% coverage via
  `task test` (never raw `go test`).
- `.planning/REQUIREMENTS.md` § Kubernetes Service Controller — SVC-01, SVC-02.
- `CLAUDE.md` — Conventional Commits with scope `operator`, `task`-first
  build/test commands, native-git workflow (no `jj`).

### Existing implementation to mirror

- `internal/operator/ingressroute_controller.go` — the closest analogue and the
  primary template: `hostIDsAnnotation` (`:31`), finalizer handling,
  `syncHost` read-before-write fail-closed guard (`:245`), `addOrAdopt` (`:260`),
  `hasIngressProvenance` (`:307`), `reconcileDelete` (`:312`),
  `getHostIDsAnnotation` (`:419`), `setHostIDsAnnotation` (`:439`).
- `internal/operator/gateway_controller.go` — the T-07-02 adoption-gating
  rationale in full (`:601-644`), the desired-set/stale-cleanup diff, and the
  `DefaultTags` copy-don't-mutate pattern (`:443-445`).
- `internal/operator/hostmapping_controller.go` — `requeueDelayShort`/`Long`
  (`:28-29`), the `Recorder events.EventRecorder` field and its use (`:43`,
  `:328-329`), the predicate pattern (`:433`).
- `internal/operator/hostclient.go` — the `HostClient` interface, including the
  `aliases []string` parameter this phase is the first controller to use (`:24`,
  `:29`) and `FindHost` (`:39`).
- `cmd/operator/main.go` — flag block (`:40-49`), controller wiring (`:104-134`),
  `defaultIngressIPWarning` (`:167`, see D-26).
- `charts/router-hosts-operator/templates/clusterrole.yaml` — RBAC shape and the
  **absent `events` rule** (D-13).
- `charts/router-hosts-operator/values.yaml:55` — the `gateway.enabled` toggle
  whose shape (but not whose key name — D-23) this phase mirrors.
- `Taskfile.yml:55` — `task test:chart`, to be extended per D-25.

### Upstream API

- `k8s.io/api/core/v1` — `Service`, `ServiceSpec.Type`, `ServiceTypeLoadBalancer`
  / `ServiceTypeNodePort` / `ServiceTypeClusterIP` / `ServiceTypeExternalName`,
  `ServiceStatus.LoadBalancer`, `LoadBalancerIngress{IP, Hostname}`. Already in
  the scheme; no new dependency (D-01).

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **`getHostIDsAnnotation` / `setHostIDsAnnotation`** — already widened to
  `client.Object` by Phase 7's D-11, so `*corev1.Service` works with **no
  signature change**. Phase 7 paid this cost; Phase 8 collects the refund.
- **`requeueDelayShort` (5s) / `requeueDelayLong` (30s)** — package-level,
  already in scope.
- **`hostIDsAnnotation`** const — shared annotation key (D-15).
- **`mockHostClient`** with `addHostFn`/`updateHostFn`/`deleteHostFn`/`getHostFn`/
  `findHostFn` (`hostmapping_controller_test.go`) — same package, reuse directly.
- **`HostClient.AddHost`/`UpdateHost` `aliases` parameter** — present since
  Phase 1, passed `nil` by both existing controllers. This phase is its first
  operator-side consumer (D-07).
- **`internal/validation.ValidateHostname`** — the hostname and alias validator.
- **`events.EventRecorder` wiring** — `HostMappingReconciler` shows the field,
  the `mgr.GetEventRecorder(...)` call site, and the `Eventf` signature.

### Established Patterns

- **Annotation + cleanup-finalizer lifecycle** — all three existing controllers
  track created entries on the watched object and delete them in a finalizer.
- **Desired-set diff with no early return** — established by the Phase 7 07-04
  fix; the delete pass must run even when the desired set is empty (D-17).
- **Provenance-gated adoption** — established across all controllers by Phase 7
  commit `4f81538`; comment *and* tags are both checked, and both are
  load-bearing (D-21).
- **Per-controller finalizer, one per source kind** — `host-cleanup`,
  `ingressroute-cleanup`, `gateway-cleanup`, now `service-cleanup`.
- **Typed client for importable APIs** — `unstructured` is used *only* for
  Traefik CRDs. `corev1.Service` is typed, like the Gateway API kinds.

### Integration Points

- `cmd/operator/main.go` — add the `--enable-service` flag and a
  `ServiceReconciler{...}.SetupWithManager(mgr)` call guarded by it, alongside
  the three existing registrations. No scheme change (D-01).
- `charts/router-hosts-operator/templates/clusterrole.yaml` — `services` rule +
  the `events` rule (D-13, D-24).
- `charts/router-hosts-operator/values.yaml` + `templates/deployment.yaml` —
  `serviceController.enabled` toggle templating `--enable-service` (D-23).
- `charts/router-hosts-operator/README.md` — annotation reference for Service
  users, the RBAC list, and the cache-footprint note from D-04.
- `Taskfile.yml` `test:chart` — new assertions (D-25).

### Verified Against the Working Tree (2026-07-26)

| Rust-era design assumption | Actual (Go operator) |
|---|---|
| New file `crates/.../controllers/service.rs` | `internal/operator/service_controller.go` |
| Reuse `DeletionScheduler` for grace periods | Does not exist in Go; finalizers only (D-16) |
| Reuse `RetryTracker` for backoff | Does not exist; `requeueDelayShort/Long` + controller-runtime backoff |
| Annotation constants live in `config.rs` | Live as consts in each `*_controller.go` |
| Emits 6 Kubernetes Events | Only `HostMappingReconciler` has a Recorder today, and **no `events` RBAC is granted** (D-13) |
| `~200-300 lines of new code` | Plausible for the reconciler; the Gateway analogue is 722 LOC with a 2000-LOC test file |

</code_context>

<specifics>

## Specific Ideas

- **The `events` RBAC gap is a finding, not an assumption.**
  `charts/router-hosts-operator/templates/clusterrole.yaml` contains no `events`
  rule; the only one is namespace-scoped in `role-leader-election.yaml`. If D-12
  is adopted, confirm the gap empirically first (a `kubectl auth can-i create
  events` against the operator's ServiceAccount, or a rendered-chart grep), then
  fix it — do not fix a bug that is not there.
- **The `service.enabled` naming trap (D-23) is the one thing most likely to be
  "corrected" back to the wrong answer** by an agent pattern-matching on
  `gateway.enabled`. The asymmetry is deliberate; the README must say so.
- **The D-05 predicate case (annotation removal) is the silent-failure of this
  phase**, structurally identical to Phase 7's `.WithIndex(...)` trap: a
  predicate that only inspects the new object passes every naive test while
  making opt-out impossible. Write that test deliberately.
- Phase 7's plan-time VALIDATION.md rows went stale while still exiting 0. When
  this phase writes validation commands, run each with `-v` and record the count
  of `--- PASS` lines — exit status alone proves nothing.

</specifics>

<deferred>

## Deferred Ideas

- **User-supplied `tags` annotation** (`router-hosts.fzymgc.house/tags`). In the
  Rust design; deferred per D-22 because provenance tags are load-bearing for
  ownership. Additive and small once the ownership question is answered.
- **Deletion grace period** (`router-hosts.fzymgc.house/grace-period`). Requires
  a scheduler abstraction the Go operator never ported. Would need to survive
  operator restarts to be meaningful, which makes it a real feature, not a flag.
- **Label-based opt-in for server-side cache scoping.** A label (unlike an
  annotation) can drive a `cache.ByObject` selector, so the informer would cache
  only managed Services. Worth revisiting if the operator ever runs against a
  cluster with thousands of Services. Would be a breaking change to the opt-in
  contract.
- **Multi-IP / dual-stack (AAAA) entries.** `status.loadBalancer.ingress[]` can
  carry both an IPv4 and an IPv6 address; the host model is one IP per hostname.
  Cross-cutting — it touches the domain model, not just this controller.
- **Hostname-typed LoadBalancer ingress (CNAME targets).** Skipped by D-09,
  consistent with Phase 7 D-15. Supporting it would mean either a CNAME concept
  in the host model or a DNS lookup in the reconcile loop.
- **`ExternalName` and headless Services.** Explicitly out of scope in the
  original design; no single IP to register.
- **Service `status` write-back / conditions.** Would make the operator
  observable from `kubectl describe service`, but Services have no
  extension-friendly status subresource — the Kubernetes Events of D-12 are the
  idiomatic substitute.
- **Enforce FQDN-only hostnames project-wide.** Carried forward unchanged from
  Phase 7's deferred list — D-08 keeps this controller consistent with the others
  rather than fixing it in one place.
- **Refreshing the two 2026-01-02 Rust-era docs in place.** They stay as the
  historical design of record; this CONTEXT records the supersessions rather than
  rewriting them.

</deferred>

---

*Phase: 8-Kubernetes Service Controller*
*Context gathered: 2026-07-26*
</content>
</invoke>
