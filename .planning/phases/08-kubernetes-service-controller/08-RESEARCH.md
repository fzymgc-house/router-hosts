# Phase 8: Kubernetes Service Controller - Research

**Researched:** 2026-07-26
**Domain:** Kubernetes controller-runtime (corev1.Service watch/reconcile), Go operator patterns already established by Phase 7
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

All 28 decisions (D-01 through D-28) in `.planning/phases/08-kubernetes-service-controller/08-CONTEXT.md` are **LOCKED** under `--auto` and are the behavioral contract for this phase. Do not re-derive or propose alternatives to any of them. Highlights the planner must anchor tasks on:

- **D-01/D-02:** No new module dependency, no new scheme install, no CRD-presence/RESTMapper gating (`corev1.Service` is core K8s and already registered via `clientgoscheme.AddToScheme`).
- **D-03/D-04/D-05:** Two independent gates — `--enable-service` flag (default `false`) AND per-Service annotation `router-hosts.fzymgc.house/enabled: "true"`. Filter via controller-runtime predicate (not a scoped cache). The predicate MUST admit Update events where the annotation is being **removed** (old had it, new doesn't) — a naive new-object-only predicate is the bug to avoid.
- **D-06/D-07/D-08:** `router-hosts.fzymgc.house/hostname` required (single hostname); optional `router-hosts.fzymgc.house/aliases` (comma-separated) maps to the host entry's native `Aliases` field; hostname validated with `internal/validation.ValidateHostname`, dot-less names warned-not-rejected.
- **D-09/D-10/D-11:** LoadBalancer — first `status.loadBalancer.ingress[]` entry with non-empty `.IP` wins; hostname-only entries skipped; no IP yet → requeue short, create nothing. NodePort — IP comes ONLY from `router-hosts.fzymgc.house/ip-address`. `ip-address` overrides LB status when both present; `--default-ingress-ip` is explicitly NOT a fallback for Services.
- **D-12/D-13/D-14:** Emit K8s Events (not just logs) for `InvalidServiceType`, `MissingHostname`, `MissingIPAddress` (all Warning), `PendingLoadBalancer` (Normal). Success events dropped. Fix the pre-existing RBAC gap (no `events` rule in `clusterrole.yaml`) as part of adopting this — but verify the gap first, don't fix a bug that isn't there. Unsupported type / missing annotation is terminal-for-now (no timed requeue); only `PendingLoadBalancer` requeues.
- **D-15 through D-19:** Reuse `hostIDsAnnotation` as hostname→hostID map. New finalizer `router-hosts.fzymgc.house/service-cleanup`. Desired-set diff with **no early return** on empty desired set (Phase 7's 07-04 bug fix, carried forward). Preserve existing error semantics (per-host errors don't abort batch, partial IDs always persisted, corrupt annotation fails closed, `oops.Wrapf` everywhere, `requeueDelayShort`/`Long`). Skip the object `Update` call when nothing changed; `UpdateHost` itself stays unconditional; guard with the read-before-write fail-closed pattern.
- **D-20/D-21/D-22:** Comment `k8s-service:<namespace>/<name>`; tags `DefaultTags + ["service"]` (i.e. `["kubernetes","service"]`). Adoption gated on BOTH comment match AND `slices.Contains(tags, "service")`. No user-supplied `tags` annotation this phase.
- **D-23 through D-26:** Helm key is `serviceController.enabled` (deliberately asymmetric with `gateway.enabled` — do not "fix" this). ClusterRole: `services` get/list/watch/update/patch, plus the `events` create/patch rule. Extend `task test:chart` with the same style of assertions Phase 7 added. Do NOT add a Service clause to `defaultIngressIPWarning` — the controller does not consume `--default-ingress-ip`.
- **D-27/D-28:** New `internal/operator/service_controller_test.go`, fake client, reuse package-level `mockHostClient`. Coverage must hold ≥80%. Assert Events via a fake recorder, asserting on the **reason string**, not the message.

### Claude's Discretion

Auto-resolved under `--auto`. The planner has latitude on: task ordering and granularity; whether the reconciler lives in a new `service_controller.go` or shares a file; whether IP resolution is one function with a type switch or two; exact log and event message wording; whether the annotation-key constants are grouped into one `const` block with the existing ones or declared locally; how the alias list is split (`strings.Split` + `TrimSpace` vs a helper). None of these change observable behavior.

### Deferred Ideas (OUT OF SCOPE)

- User-supplied `tags` annotation (`router-hosts.fzymgc.house/tags`) — deferred per D-22.
- Deletion grace period (`router-hosts.fzymgc.house/grace-period`) — requires a scheduler abstraction the Go operator never ported.
- Label-based opt-in for server-side cache scoping (`cache.ByObject`) — would be a breaking change to the opt-in contract.
- Multi-IP / dual-stack (AAAA) entries.
- Hostname-typed LoadBalancer ingress (CNAME targets) — skipped per D-09.
- `ExternalName` and headless Services.
- Service `status` write-back / conditions.
- Enforcing FQDN-only hostnames project-wide.
- Refreshing the two 2026-01-02 Rust-era docs in place.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SVC-01 | Operator creates router DNS entries for LoadBalancer and NodePort Services from configured annotations | Architecture Patterns (reconcile flow), Code Examples (predicate, annotation constants), D-03/D-04/D-05/D-06/D-07/D-08 mechanics verified below |
| SVC-02 | Operator resolves Service IPs and removes entries when the Service is deleted | Code Examples (IP resolution), Common Pitfalls (LB ingress semantics), reconcileDelete pattern mirrored from `ingressroute_controller.go`/`gateway_controller.go` |

</phase_requirements>

## Summary

This phase is almost entirely a "port the pattern" exercise, not a discovery exercise: Phase 7 (`ingressroute_controller.go`, `gateway_controller.go`) already established every mechanic this controller needs — annotation + finalizer lifecycle, desired-set diff with no early return, provenance-gated adoption, `getHostIDsAnnotation`/`setHostIDsAnnotation` (already `client.Object`-typed), `requeueDelayShort`/`Long`. The two genuinely new pieces are (1) a `corev1.Service`-specific predicate that correctly detects annotation-based opt-out on Update (verified below: this is NOT what `predicate.NewPredicateFuncs` or `GenerationChangedPredicate` give you for free — both are traps), and (2) the operator's first real use of `events.EventRecorder` beyond `HostMappingReconciler`, which surfaces a genuine, empirically-confirmed RBAC gap (D-13) that must be fixed in the same PR.

`corev1.Service` requires no new Go module and no new scheme registration — `clientgoscheme.AddToScheme(scheme)` at `cmd/operator/main.go:60` already covers it, confirmed by inspecting `k8s.io/api@v0.36.1/core/v1/types.go` directly (the version pinned in `go.mod`). The `Service.Status.LoadBalancer.Ingress[]` entries carry an `IP` field and a `Hostname` field that are independently optional (neither implies the other is empty), which is exactly why D-09's "skip hostname-only, walk in order for first non-empty IP" rule is necessary and not a simplification of something the API already guarantees.

The alias plumbing (D-07) has one hazard research surfaced that is not obvious from reading the controller pattern alone: `grpcHostClient.UpdateHost` (`internal/operator/grpc_hostclient.go:119-136`) only sets the wire-level `AliasesUpdate` field when the Go `aliases` parameter is **non-nil** — an empty slice `[]string{}` clears server-side aliases, but `nil` means "leave aliases untouched." Every existing controller passes `nil` and never triggers this branch. This phase is the first to pass real alias data, so a Service whose `aliases` annotation is edited down to zero aliases (or removed) must send `[]string{}`, not `nil`, or the stale aliases silently persist on the server.

**Primary recommendation:** Build `internal/operator/service_controller.go` as a close structural mirror of `ingressroute_controller.go` (single-kind, typed client, no CRD-gating), reusing its finalizer/annotation/adoption machinery verbatim where the shapes match, and spend the actual design effort on: the D-05 predicate (write it as a hand-rolled `predicate.Funcs`, not `predicate.NewPredicateFuncs`), the IP-resolution type switch (LoadBalancer vs NodePort vs unsupported), the four Kubernetes Events plus their RBAC fix, and the nil-vs-empty-slice alias semantics on update.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Service watch + annotation-gated filtering | API / Backend (K8s operator/controller) | — | controller-runtime manager process; the operator is itself a control-plane backend service, not client- or CDN-tier |
| IP resolution (LB status / NodePort annotation) | API / Backend | — | Pure reconcile-loop logic reading `Service.Status`/`Annotations`, no external call |
| Host entry create/update/delete | API / Backend | Database / Storage (router-hosts server + SQLite event store) | Operator is the client; router-hosts gRPC server + its SQLite event-sourced store is the actual persistence tier the entry lands in |
| DNS output (hosts/dnsmasq/unbound) | Database / Storage (router-hosts server) | — | Out of scope for this phase — server-side generation already consumes `Aliases` unconditionally; no operator-side change needed |
| RBAC / Helm chart wiring | API / Backend (cluster control plane) | — | ClusterRole and Deployment args are cluster-admission-time configuration, not application logic |
| Kubernetes Events | API / Backend | — | `events.EventRecorder` writes to the `events` API on behalf of the operator's ServiceAccount; consumed by `kubectl describe service`, a client-tier view, but produced entirely in the backend controller |

No browser/frontend-server/CDN tier is implicated — this phase is entirely within the Kubernetes operator process and the router-hosts gRPC server it talks to.

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `k8s.io/api/core/v1` | v0.36.1 (pinned in `go.mod`, already a transitive dep) | `Service`, `ServiceSpec.Type`, `ServiceStatus`, `LoadBalancerIngress` types | Already imported elsewhere in `internal/operator`; core Kubernetes API group, cannot be absent from any cluster (D-02) |
| `sigs.k8s.io/controller-runtime` | v0.24.1 (pinned in `go.mod`) | `predicate.Funcs`, `builder.WithPredicates`, `ctrl.NewControllerManagedBy` | Already the operator's controller framework; no version bump needed |
| `k8s.io/client-go/tools/events` | v0.36.1 (pinned in `go.mod`) | `events.EventRecorder`, `mgr.GetEventRecorderFor`, `FakeRecorder` (tests) | Already used by `HostMappingReconciler`; the non-deprecated recorder API (see State of the Art) |

### Supporting

No supporting/new libraries. **This phase adds zero entries to `go.mod`** — D-01 is explicit that any `go.mod` diff is a signal something is wrong, and this research confirms it: `corev1` is already imported by `internal/operator/hostmapping_controller.go:12` and `internal/operator/gateway_controller.go` transitively pulls the same `k8s.io/api` module.

### Alternatives Considered

None — CONTEXT.md's D-01/D-02 already foreclose the only two design axes (module choice, scheme/CRD gating) that would normally need alternatives research.

**Installation:** None required.

**Version verification:**

```bash
$ grep -n 'k8s.io/api \|k8s.io/client-go \|controller-runtime ' go.mod
k8s.io/api v0.36.1
k8s.io/client-go v0.36.1
sigs.k8s.io/controller-runtime v0.24.1
```

`[VERIFIED: go.mod inspection]` — all three are already present at these exact pinned versions; no `go get` is needed for this phase.

## Package Legitimacy Audit

**Not applicable.** This phase installs zero new external packages (D-01, confirmed above). The Package Legitimacy Gate is skipped because there is nothing to check.

**Packages removed due to [SLOP] verdict:** none — no new packages proposed.
**Packages flagged as suspicious [SUS]:** none.

## Architecture Patterns

### System Architecture Diagram

```text
Kubernetes API Server
        │
        │  watch corev1.Service (cluster-wide, cached by shared informer — D-04)
        ▼
┌───────────────────────────────────────────────────────────────┐
│ ServiceReconciler (internal/operator/service_controller.go)   │
│                                                                 │
│  predicate.Funcs (D-05): admits Create/Delete/Generic always;  │
│  Update admitted iff OLD.annotations["...enabled"]=="true"     │
│  OR NEW.annotations["...enabled"]=="true"                      │
│        │                                                        │
│        ▼                                                        │
│  Reconcile(req)                                                 │
│    ├─ Get Service (NotFound → ignore, already deleted)          │
│    ├─ DeletionTimestamp set? → reconcileDelete (finalizer path) │
│    ├─ finalizer absent? → add "service-cleanup", return         │
│    └─ reconcileUpsert:                                          │
│         ├─ enabled annotation == "true"? (opt-out state can     │
│         │    still reach here via Update predicate — must be    │
│         │    rechecked inside Reconcile, not just at watch time)│
│         ├─ resolve desired hostname+aliases from annotations    │
│         │    (D-06/D-07/D-08, internal/validation)               │
│         ├─ resolve IP by Spec.Type:                              │
│         │    LoadBalancer → walk Status.LoadBalancer.Ingress[]   │
│         │      for first non-empty .IP (D-09)                    │
│         │    NodePort → annotation "...ip-address" only (D-10)   │
│         │    ip-address annotation overrides LB status (D-11)    │
│         │    ClusterIP/ExternalName → InvalidServiceType event   │
│         ├─ build desired-set {hostname: aliases}; diff against   │
│         │    hostIDsAnnotation (no early return — D-17)          │
│         ├─ per-host: addOrAdopt / syncHost via HostClient         │
│         │    (mirrors ingressroute_controller.go addOrAdopt)      │
│         ├─ stale-cleanup pass: DeleteHost for hostnames dropped   │
│         │    from desired set                                     │
│         ├─ emit Events: InvalidServiceType/MissingHostname/       │
│         │    MissingIPAddress (Warning), PendingLoadBalancer      │
│         │    (Normal) — via Recorder.Eventf                        │
│         └─ persist hostIDsAnnotation only if changed (D-19)        │
└───────────────────────────────────────────────────────────────┘
        │                                                    │
        │ gRPC (mTLS) via HostClient.AddHost/UpdateHost/       │ Kubernetes Events API
        │ DeleteHost/GetHost/FindHost                          │ (RBAC: apiGroups [""],
        ▼                                                       resources ["events"],
┌─────────────────────────────┐                                verbs create/patch)
│ router-hosts gRPC server     │                                       │
│ (event-sourced SQLite store) │                                       ▼
│  → hosts(5) / dnsmasq /       │                          kubectl describe service
│    unbound config generation  │                          (operator-visible failures)
└─────────────────────────────┘
```

### Recommended Project Structure

No new directories. This phase adds:

```text
internal/operator/
├── service_controller.go          # new — ServiceReconciler, predicate, IP resolution, event emission
├── service_controller_test.go     # new — D-27 test matrix, reuses mockHostClient + fakeHostStore
cmd/operator/
└── main.go                        # edit — --enable-service flag, ServiceReconciler wiring
charts/router-hosts-operator/
├── templates/clusterrole.yaml     # edit — services rule + events rule (D-13/D-24)
├── templates/deployment.yaml      # edit — --enable-service arg gated on serviceController.enabled
├── values.yaml                    # edit — serviceController.enabled key (D-23)
└── README.md                      # edit — annotation reference, cache-footprint note (D-04)
Taskfile.yml                       # edit — test:chart new assertions (D-25)
```

### Pattern 1: Update-Symmetric Opt-In/Opt-Out Predicate (D-05)

**What:** A `predicate.Funcs` whose `UpdateFunc` inspects BOTH `e.ObjectOld` and `e.ObjectNew`, admitting the event if either carries the enabled annotation as `"true"`.

**When to use:** Any watch gated by an annotation (not a label, not generation) where removal of the annotation must still reach `Reconcile` so the controller can clean up.

**Why `predicate.NewPredicateFuncs` and `GenerationChangedPredicate` are both wrong here (verified against the pinned controller-runtime source, `sigs.k8s.io/controller-runtime@v0.24.1/pkg/predicate/predicate.go`):**

- `predicate.NewPredicateFuncs(filter)` (`predicate.go:118-131`) builds its `UpdateFunc` as `func(e event.UpdateEvent) bool { return filter(e.ObjectNew) }` — literally only the new object. Removing the annotation makes `filter(new)` return `false`, so the Update event is dropped and `Reconcile` never runs. This is the exact "D-05 is the bug" case CONTEXT.md warns about.
- `predicate.GenerationChangedPredicate` (`predicate.go:196-224`) filters on `metadata.generation`. For a built-in resource with a status subresource (Service has one), `metadata.generation` increments **only on writes to `.spec`** — an annotation-only edit does not touch `.spec` and does not bump `.generation`. `[CITED: Kubernetes API conventions — generation is "set by the system and monotonically increasing, per-resource" for desired-state (spec) changes; status-subresource resources exclude metadata/status writes from bumping it]`. Chaining `GenerationChangedPredicate` in front of (or instead of) a custom filter would silently swallow every annotation-only Update — including both the opt-in and the opt-out edit.

**Example (shape to implement, not copy-paste — `enabled` is the annotation key from D-03):**

```go
// Source: sigs.k8s.io/controller-runtime@v0.24.1/pkg/predicate/predicate.go (Funcs/TypedFuncs shape),
// verified as the fix for the D-05 hazard against the pinned module version.
func serviceEnabledPredicate() predicate.Predicate {
	isEnabled := func(obj client.Object) bool {
		return obj.GetAnnotations()[serviceEnabledAnnotation] == "true"
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return isEnabled(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return isEnabled(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return isEnabled(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			// D-05: admit when EITHER side carries the annotation — old-only
			// covers opt-out (annotation removed), new-only covers opt-in.
			return isEnabled(e.ObjectOld) || isEnabled(e.ObjectNew)
		},
	}
}
```

Register with `builder.WithPredicates(serviceEnabledPredicate())` on `For(&corev1.Service{}, ...)`, exactly as `hostmapping_controller.go:475` registers `statusWriteFilter()`.

**One additional correctness note verified from source:** because the predicate only gates which events reach the work queue, `Reconcile` itself must still re-check the annotation value on the freshly-`Get`'d object (not trust the event) — the object may have changed again between enqueue and processing. This mirrors how `Reconcile` in every existing controller re-derives its desired state from a fresh `Get`, never from event payloads.

### Pattern 2: IP Resolution by Service Type (D-09/D-10/D-11)

**What:** A function (or type-switch branch, planner's discretion) that returns `(ip string, ok bool, reason string)` given `*corev1.Service`.

**Example (verified against `k8s.io/api@v0.36.1/core/v1/types.go`):**

```go
// Source: k8s.io/api/core/v1 types (LoadBalancerIngress at types.go:5908-5933,
// ServiceType constants at types.go:5777-5796) — both fields on
// LoadBalancerIngress are independently `,omitempty`; neither implies the
// other is unset, which is why "first non-empty .IP, skip .Hostname-only" is
// a real filtering rule and not a redundant check.
func resolveServiceIP(svc *corev1.Service) (ip string, waiting bool) {
	// D-11: ip-address annotation overrides LB status when both present, and
	// is the ONLY source for NodePort. Check it first regardless of Spec.Type.
	if override := svc.Annotations[serviceIPAddressAnnotation]; override != "" {
		return override, false
	}
	switch svc.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		for _, ing := range svc.Status.LoadBalancer.Ingress {
			if ing.IP != "" { // D-09: skip Hostname-only entries (AWS ELB style)
				return ing.IP, false
			}
		}
		return "", true // still provisioning — requeue short, D-09
	case corev1.ServiceTypeNodePort:
		return "", false // D-10: no ip-address annotation = MissingIPAddress event
	default:
		return "", false // ClusterIP/ExternalName = InvalidServiceType event
	}
}
```

Note this sketch separates "no IP yet, keep waiting" (`waiting=true`, LoadBalancer only) from "no IP and never will be" (NodePort without annotation, or unsupported type) — the caller uses this to decide between `PendingLoadBalancer` (requeue) and `MissingIPAddress`/`InvalidServiceType` (terminal, D-14).

### Anti-Patterns to Avoid

- **Filtering the Service watch with a scoped `cache.ByObject` selector.** D-04 explicitly rejects this — annotations cannot drive `cache.ByObject`, only labels can, and changing the opt-in contract to a label is a deferred idea, not this phase's job.
- **Using `predicate.NewPredicateFuncs` for the enabled-annotation gate.** Verified above: it structurally cannot see the old object, so it cannot detect opt-out.
- **Passing `nil` for aliases on every `UpdateHost` call "to match the other controllers."** The other controllers never manage aliases at all (they always pass `nil`, meaning "don't touch"). This controller manages a real alias set and must pass `[]string{}` (not `nil`) when the desired alias set is empty, or a Service that had aliases and then has them removed will leak stale aliases server-side forever. See Common Pitfalls.
- **Checking only `existing.Comment` on adoption.** D-21 requires checking `existing.Comment == comment` AND `slices.Contains(existing.Tags, "service")` — comment alone is what HostMapping's adoption check does (its tags are user-supplied and unusable for provenance), but Service's tags are operator-derived like IngressRoute's and Gateway's, so both must be checked here, mirroring `hasIngressProvenance`/`hasGatewayProvenance`, not `HostMappingReconciler.adoptExistingHost`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Detecting annotation add/remove on Update | A manual diff of two annotation maps as a bespoke helper | `predicate.Funcs{UpdateFunc: ...}` inspecting `e.ObjectOld`/`e.ObjectNew` directly (Pattern 1) | controller-runtime already threads both objects into every `UpdateEvent`; no need for a stored "last seen" cache or a custom map-diff utility |
| hostname↔hostID tracking storage | A new CRD, ConfigMap, or separate annotation scheme | Reuse `hostIDsAnnotation` + `getHostIDsAnnotation`/`setHostIDsAnnotation` (`ingressroute_controller.go:31,419,439`) | Already `client.Object`-typed since Phase 7's D-11 widening; zero signature changes needed for `*corev1.Service` |
| Ownership/adoption safety on `(ip, hostname)` collision | A new locking or reservation mechanism | The established `addOrAdopt` + provenance-tag pattern (`hasIngressProvenance`/`hasGatewayProvenance` shape) | The server enforces `(ip, hostname)` uniqueness itself (`internal/server/commands.go` `AddHost`); the operator-side pattern for surviving `AlreadyExists` safely is already solved and battle-tested across two controllers |
| Kubernetes Event emission plumbing | A custom event-writing client over the raw `events.v1` API | `events.EventRecorder` via `mgr.GetEventRecorderFor(name)` | `HostMappingReconciler` already establishes the exact call site and `Eventf` signature; duplicating it would just be a second, divergent implementation |

**Key insight:** Every piece of machinery this phase needs except the predicate and the IP-resolution switch already exists in the codebase, proven correct by Phase 7's test suite and the two production controllers built on it. The temptation to be "clean" and write something bespoke for Service (which structurally looks different — no CRD, no Traefik unstructured client, a real corev1 status) is the highest-risk move available; the annotation/finalizer/adoption layer is identical regardless of the resource kind underneath it.

## Common Pitfalls

### Pitfall 1: The D-05 predicate is easy to get subtly wrong even when "aware" of it

**What goes wrong:** A predicate that checks `new.Annotations[key] == "true" || old.Annotations[key] == "true"` looks correct and passes a naive "enable it, see it reconcile" test, but a developer under time pressure reaches for `predicate.NewPredicateFuncs(isEnabled)` because it's the idiomatic-looking one-liner everywhere else in the ecosystem, and it silently regresses the exact bug D-05 exists to prevent.

**Why it happens:** `NewPredicateFuncs` is the "blessed" convenience constructor in controller-runtime's own docs and is correct for the overwhelmingly common case (a filter that only cares about current state, e.g. "is this Pod ready"). It is wrong specifically for opt-out detection, which requires comparing two points in time, and that distinction is not obvious from the function's name or its one-line doc comment.

**How to avoid:** Write the predicate as an explicit `predicate.Funcs{}` literal (Pattern 1 above), never `NewPredicateFuncs`, for any annotation-gated watch where removal must be observable.

**Warning signs:** A test suite that only covers "annotation added → Service reconciled" and "annotation absent → Service ignored" without a dedicated "annotation removed on Update → still reconciled, entry deleted" case (exactly the case D-05/D-27 calls out) will pass with the buggy version.

### Pitfall 2: `nil` vs `[]string{}` for aliases on `UpdateHost`

**What goes wrong:** A Service's `aliases` annotation is edited from `"a.example.com,b.example.com"` down to nothing (annotation removed or emptied). The reconciler computes an empty desired alias slice and calls `UpdateHost(ctx, id, ip, hostname, comment, aliasesVar, tags, version)`. If `aliasesVar` is left as its Go zero value (`nil`, e.g. because it was built with `var aliases []string` and never appended to), `grpcHostClient.UpdateHost` (`internal/operator/grpc_hostclient.go:131-133`) skips setting `req.Aliases` entirely (`if aliases != nil { req.Aliases = ... }`), so the server-side `AliasesUpdate` field is never sent and the stale aliases persist forever — a silent, hard-to-notice leak, not a hard error.

**Why it happens:** `UpdateHost`'s double-pointer-style semantics ("nil means don't touch, empty means clear") are exactly analogous to the `comment **string` semantics already documented at `internal/server/commands.go:169-170`, but this is the first controller-side caller that needs to distinguish "no change" from "change to empty" for aliases, so the existing IngressRoute/Gateway code has never exercised this branch.

**How to avoid:** When building the aliases parameter for `UpdateHost` (and `AddHost`, though `AddHost` treats `nil` and `[]string{}` identically per `commands.go:109-111`), always initialize it as `aliases := make([]string, 0, ...)` or explicitly `[]string{}` rather than `var aliases []string`, so an empty result is a real empty slice, not `nil`. Add a dedicated test case: Service previously tracked with aliases, aliases annotation removed, `UpdateHost` call asserted to receive a non-nil empty slice.

**Warning signs:** A test that only checks `mockHostClient.updateHostFn` was called with the *new* aliases present, never a test where aliases go from populated to empty and asserts the aliases parameter is `[]string{}` (`assert.NotNil` + `assert.Empty`, not just `assert.Empty` which passes for both nil and empty).

### Pitfall 3: `LoadBalancerIngress.IP` and `.Hostname` are independently optional — don't assume mutual exclusivity

**What goes wrong:** Code that does `if ing.Hostname != "" { skip } else { use ing.IP }` looks equivalent to "first non-empty IP" but is not: per `k8s.io/api/core/v1` (`types.go:5908-5933`), both fields are separately `,omitempty`, so an entry could theoretically carry both (or, in a broken/malicious cluster, neither). D-09's rule is specifically "walk in order, take the first entry with non-empty `.IP`," which is NOT the same as "take the first entry, and use IP unless Hostname is set."

**Why it happens:** Real-world cloud LB controllers (GCE/OpenStack: IP-only; AWS ELB: Hostname-only) make the fields look mutually exclusive in practice, but nothing in the type or the API server enforces that, and a multi-ingress-entry status (e.g. dual-stack or multi-LB-implementation setups) can mix both across entries.

**How to avoid:** Loop and check `ing.IP != ""` directly (Pattern 2 sketch above), never branch on `ing.Hostname` to infer `ing.IP`'s emptiness.

**Warning signs:** A test with only a single-entry `Status.LoadBalancer.Ingress` fixture per case will not catch this; D-27 explicitly requires a "multiple ingress entries" test case — make sure at least one fixture has entry 0 = hostname-only, entry 1 = IP-set, and asserts entry 1's IP is used.

### Pitfall 4: `events` RBAC gap is real today, not a hypothetical (D-13)

**What goes wrong:** Adding `Recorder events.EventRecorder` and calling `Eventf` without also fixing `charts/router-hosts-operator/templates/clusterrole.yaml` means the calls fail silently in-cluster (the `EventRecorder` swallows write errors internally by design — it logs, it does not propagate the error to the caller), so the four new Events for this phase — and `HostMappingReconciler`'s pre-existing `Recorded` event — never actually appear via `kubectl describe`, and nobody notices because nothing crashes.

**Why it happens:** `k8s.io/client-go/tools/events.EventRecorder.Eventf` has no error return; a failed event write is invisible unless you go looking at the operator's own logs at a very specific log level, which most operators of this project will never do.

**How to avoid:** This research empirically confirmed the gap: `charts/router-hosts-operator/templates/clusterrole.yaml` contains rules for `traefik.io`, `gateway.networking.k8s.io`, and `router-hosts.fzymgc.house` resources only — **no `apiGroups: [""] resources: ["events"]` rule anywhere in it**. The only `events` rule in the chart is in `templates/role-leader-election.yaml:19-22`, which is a namespace-scoped `Role` bound only in the operator's own release namespace (for leader-election lifecycle events), not a `ClusterRole` covering Services (and HostMappings) that may live in other namespaces. D-13 must be implemented: add `apiGroups: [""] resources: ["events"] verbs: ["create","patch"]` to `clusterrole.yaml`, plus the matching `+kubebuilder:rbac` marker on the new reconciler.

**Warning signs:** `task test:chart` passing is not sufficient evidence this is fixed — write an explicit assertion (see Validation Architecture) that greps the rendered ClusterRole for the `events` rule.

## Code Examples

### Kubernetes Event emission (mirrors `HostMappingReconciler`, verified against pinned `client-go` v0.36.1)

```go
// Source: k8s.io/client-go@v0.36.1/tools/events/event_recorder.go — Eventf signature
// confirmed as: Eventf(regarding, related runtime.Object, eventtype, reason, action, note string, args ...interface{})
// Existing call site: internal/operator/hostmapping_controller.go:328-330
if r.Recorder != nil {
	r.Recorder.Eventf(svc, nil, corev1.EventTypeWarning, "MissingHostname", "Reconcile",
		"Service %s/%s opted in but is missing required annotation %q", svc.Namespace, svc.Name, serviceHostnameAnnotation)
}
```

`corev1.EventTypeWarning` / `corev1.EventTypeNormal` are plain string constants (`"Warning"`, `"Normal"`) already imported via `corev1` — no separate import needed.

### Field-based RBAC marker (mirrors the three existing controllers)

```go
// Source: pattern from internal/operator/ingressroute_controller.go:79-80 and
// gateway_controller.go:265-266, extended with the D-13 events rule.
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
```

### FakeRecorder usage for D-28 event assertions

```go
// Source: k8s.io/client-go@v0.36.1/tools/events/fake.go — FakeRecorder.Events is
// chan string, and Eventf formats as: eventtype + " " + reason + " " + note (printf-args applied).
rec := events.NewFakeRecorder(10)
r := &ServiceReconciler{ /* ... */ Recorder: rec}
// ... trigger reconcile that should emit MissingHostname ...
select {
case msg := <-rec.Events:
	assert.Contains(t, msg, "Warning MissingHostname ") // D-28: assert reason, not message text
default:
	t.Fatal("expected an event")
}
```

Note the FakeRecorder concatenates `eventtype`, `reason`, and `note` into ONE string separated by single spaces (`fmt.Sprintf(eventtype+" "+reason+" "+note, args...)`), so `assert.Contains(msg, "Warning MissingHostname ")` (reason bracketed by spaces) is the discriminating assertion the D-28 instruction calls for — plain `strings.Contains(msg, "MissingHostname")` would also match a hypothetical future reason like `"NotMissingHostnameButSimilar"`, so anchor on the surrounding spaces or `strings.Fields(msg)[1] == "MissingHostname"`.

### Reusable `fakeHostStore` for adoption tests (D-27's "don't write a second mock")

`internal/operator/gateway_controller_test.go:1339-1384` already defines a package-level `fakeHostStore` (not just `mockHostClient`) that models the server's real `(ip, hostname)` uniqueness constraint — `AddHost` returns `ErrHostAlreadyExists` for a duplicate pair and `FindHost` then serves the conflicting entry, exactly matching `internal/server/commands.go`'s actual behavior. Both `fakeHostStore` (adoption-collision tests) and the plain `mockHostClient` (single-controller-flow tests) are already package-scoped in `internal/operator` and importable by `service_controller_test.go` with no new mock code:

```go
// Source: internal/operator/gateway_controller_test.go:1339-1384 (package operator, already visible)
store := newFakeHostStore()
store.seed("foreign-id", "10.0.0.5", "shared.example.com", "k8s-ingress:default/other", []string{"traefik", "ingress"})
r := &ServiceReconciler{HostClient: store.client(), /* ... */}
// AddHost for the same (ip, hostname) will hit ErrHostAlreadyExists; FindHost will
// return the "foreign" entry, whose comment/tags do NOT match this controller's
// k8s-service:.../"service" provenance — adoption must be refused (D-21).
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| `record.EventRecorder` / `mgr.GetEventRecorderFor` (client-go `tools/record`) | `events.EventRecorder` / `mgr.GetEventRecorder` (client-go `tools/events`, `events.k8s.io/v1` backed) | Already the status quo in this repo (`hostmapping_controller.go:43`) | The deprecated `record` package trips `staticcheck SA1019` and fails `task lint`; this phase must use the same `events.EventRecorder` field type and `Eventf` signature `HostMappingReconciler` already uses — there is no migration to do, only consistency to maintain |
| Rust `kube-rs` + `DeletionScheduler`/`RetryTracker` (2026-01-02 design doc) | Go `controller-runtime` finalizers + `requeueDelayShort`/`Long` constants | 2026-02-22 Go migration (project-wide) | No scheduler abstraction exists or is needed; immediate finalizer-based cleanup replaces grace-period scheduling (D-16) |

**Deprecated/outdated:** The two `docs/plans/2026-01-02-service-controller-*.md` documents' *implementation* sections (Rust file layout, `service.rs`, `config.rs`) are historical only — CONTEXT.md's canonical_refs section already enumerates every superseded piece; nothing further to add here.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `metadata.generation` on a built-in resource with a status subresource (Service) increments only on `.spec` writes, never on annotation-only writes | Pattern 1 (D-05 predicate rationale) | If wrong, `GenerationChangedPredicate` might occasionally pass an annotation-only update, which would be a false negative for the "this predicate is a trap" warning — but would not break the recommended hand-rolled predicate, so the risk is confined to the explanatory rationale, not the implementation |

No other claims in this research are `[ASSUMED]` — the package/API surface, RBAC gap, `Eventf` signature, `FakeRecorder` shape, `LoadBalancerIngress` field semantics, and `grpcHostClient` alias nil/empty behavior were all verified directly against the pinned module source under `$GOPATH/pkg/mod` and the working tree.

## Open Questions

1. **Exact annotation-key constant naming and grouping**
   - What we know: D-03/D-06/D-07/D-10 fix the annotation *values* (`router-hosts.fzymgc.house/enabled`, `/hostname`, `/aliases`, `/ip-address`) but CONTEXT.md's Claude's Discretion explicitly leaves Go constant naming/grouping open.
   - What's unclear: Whether to add these to the existing `const ( hostIDsAnnotation = ... )` block in `ingressroute_controller.go:29-32` or declare a local block in `service_controller.go`.
   - Recommendation: Declare locally in `service_controller.go` — the existing block's constants (`ingressRouteCleanupFinalizer`, `hostIDsAnnotation`) are either IngressRoute-specific or genuinely shared; mixing four Service-only annotation keys into that block would make it a dumping ground. `hostIDsAnnotation` itself is still referenced (shared, D-15); the new keys are not.

2. **Whether the `enabled` re-check inside `Reconcile` (not just at the predicate) needs its own dedicated test, or is covered incidentally**
   - What we know: The predicate is an admission gate on the watch, not authoritative for what `Reconcile` does with the freshly-fetched object; Pattern 1 already calls this out.
   - What's unclear: D-27's test list doesn't explicitly separate "predicate admits an opt-out Update" from "Reconcile, given an opted-out Service (annotation absent), runs the cleanup/delete path via the D-17 desired-set diff" — these are two different code paths that both need coverage.
   - Recommendation: Cover both explicitly. The predicate test proves the event reaches the queue; a separate `reconcileUpsert`/`syncService`-level test (constructing a Service object with a currently-empty `enabled` annotation but a populated `hostIdsAnnotation` from a prior reconcile) proves the D-17 stale-cleanup path actually deletes the tracked entries. This is exactly the "four stop-managing transitions" D-17/D-27 call for; the annotation-removed transition is the one closest to being conflated with the predicate test and deserves its own assertion.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Go | `task build`, `task test`, `task lint` | ✓ | go1.26.5 darwin/arm64 | — |
| helm | `task test:chart` (D-25 extension) | ✓ | v4.2.3+g43e8b7f | — |
| kubectl | manual verification against a live cluster (not required by any `task` target) | ✓ | v1.36.3 (client) | — |
| golangci-lint | `task lint` | ✓ | v2.12.2 | — |
| k8s.io/api, controller-runtime, client-go/tools/events | Go module dependencies | ✓ (already in `go.mod` at v0.36.1 / v0.24.1) | see Standard Stack | — |

**Missing dependencies with no fallback:** none.
**Missing dependencies with fallback:** none — every tool this phase's `task` targets need is present, so `task test:chart` will actually execute (not self-skip) when the planner writes VALIDATION.md commands against it.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go `testing` + `stretchr/testify` (`assert`/`require`), consistent with `hostmapping_controller_test.go`/`gateway_controller_test.go` |
| Config file | none — plain `go test`, invoked only via `task test` per CLAUDE.md |
| Quick run command | `task test -- -run 'TestService' ./internal/operator/` (verified pattern: `task test -- -run 'TestX' ./pkg/` genuinely scopes as of commit 6860560, per known-gotchas) |
| Full suite command | `task test:coverage:ci` (enforces ≥80% threshold, matches CLAUDE.md's hard requirement) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SVC-01 | Opt-in predicate admits Create/enabled-Update/Delete; refuses disabled Create | unit | `task test -- -run 'TestServiceEnabledPredicate' ./internal/operator/` — assert on count of `--- PASS:` lines in `-v` output, e.g. `task test -- -v -run 'TestServiceEnabledPredicate' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` equals the number of subtests written | ❌ Wave 0 — `service_controller_test.go` does not exist yet |
| SVC-01 | Opt-in predicate admits Update where annotation is REMOVED (D-05 hazard) | unit | `task test -- -v -run 'TestServiceEnabledPredicate/annotation_removed' ./internal/operator/ 2>&1 \| grep -c '^--- PASS: TestServiceEnabledPredicate'` (must be ≥1, and the subtest name string itself must appear — a renamed/deleted subtest silently drops out of a bare count) | ❌ Wave 0 |
| SVC-01 | Hostname/aliases extraction: required hostname missing → `MissingHostname` event, terminal (no requeue) | unit | `task test -- -v -run 'TestSyncService.*MissingHostname' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` | ❌ Wave 0 |
| SVC-01 | Aliases: invalid alias logged and dropped, valid ones kept | unit | `task test -- -v -run 'TestSyncService.*Alias' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` | ❌ Wave 0 |
| SVC-01 | `UpdateHost` receives `[]string{}` (not `nil`) when aliases drop to zero (Pitfall 2) | unit | `task test -- -v -run 'TestSyncService.*AliasesCleared' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` | ❌ Wave 0 |
| SVC-02 | LoadBalancer IP resolution: first non-empty `.IP`, hostname-only skipped, multi-entry ordering, empty status → requeue short | unit | `task test -- -v -run 'TestResolveServiceIP' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` | ❌ Wave 0 |
| SVC-02 | NodePort with/without `ip-address`; `ip-address` overrides LB status | unit | `task test -- -v -run 'TestResolveServiceIP.*NodePort\|TestResolveServiceIP.*Override' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` | ❌ Wave 0 |
| SVC-02 | Finalizer add on first reconcile; cleanup-on-delete removes all tracked entries and the finalizer | unit | `task test -- -v -run 'TestServiceReconcile.*Delete' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` | ❌ Wave 0 |
| SVC-02 | Four "stop managing" transitions (D-17): disabled, type change, hostname change, annotation removed — each deletes the stale entry via the no-early-return diff | unit | `task test -- -v -run 'TestSyncService.*StopManaging' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` (expect exactly 4 subtests) | ❌ Wave 0 |
| SVC-01/02 | Adoption refused on foreign comment / foreign tags (D-21), using `fakeHostStore` | unit | `task test -- -v -run 'TestSyncService.*Adopt' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` | ❌ Wave 0 — reuses existing `fakeHostStore` from `gateway_controller_test.go`, no new mock file |
| SVC-01/02 | Corrupt `host-ids` annotation → error + requeue, never proceeds on partial view | unit | `task test -- -v -run 'TestSyncService.*Corrupt' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` | ❌ Wave 0 |
| SVC-01/02 | Each of the 4 Kubernetes Events fires with correct reason+type via `FakeRecorder` | unit | `task test -- -v -run 'TestSyncService.*Event' ./internal/operator/ 2>&1 \| grep -c '^--- PASS'` (expect 4 subtests, one per reason) | ❌ Wave 0 |
| D-13 | ClusterRole grants `events` create/patch cluster-wide (RBAC fix) | integration (helm render) | `helm template charts/router-hosts-operator --set serviceController.enabled=true \| awk '/resources: \["events"\]/{f=1} f && /verbs:/{print; exit}'` then assert output contains both `create` and `patch` — do NOT assert on `grep -q` alone (exit-status-only assertions go stale silently per known gotcha) | ❌ Wave 0 — `clusterrole.yaml` has no `events` rule today (confirmed) |
| D-25 | `--enable-service` absent by default, present under `serviceController.enabled=true` | integration (helm render) | extend `task test:chart` per the existing `--enable-gateway` assertion pair at `Taskfile.yml:64-72` | ❌ Wave 0 — new `test:chart` block |
| D-25 | `services` granted exact write verbs, zero unexpected extras; zero ClusterRole under `rbac.create=false` | integration (helm render) | extend `task test:chart` per the existing RBAC assertion block at `Taskfile.yml:74-87` | ❌ Wave 0 |

**Staleness discipline (per known gotchas):** every command above uses `-v` plus a `grep -c '^--- PASS'` (or an explicit named-subtest grep) rather than bare exit status, and rather than an `A|B` alternation where one branch could match a renamed/nonexistent test while the other reports the real result. The `helm template | grep -q` pattern from the Phase 7 `test:chart` task IS exit-status-based and DID go stale in that phase per the specifics note — the planner should upgrade the new D-25 assertions to the same explicit-count style shown for the `events` rule above, not blindly copy the Phase 7 `grep -q` idiom forward.

### Sampling Rate

- **Per task commit:** `task test -- -run 'TestService' ./internal/operator/` (Service-controller-scoped subset)
- **Per wave merge:** `task test:coverage:ci` (full suite, enforces ≥80%)
- **Phase gate:** `task test:coverage:ci` green AND `task test:chart` green (helm is available in this environment, confirmed above — it will actually run, not self-skip) before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `internal/operator/service_controller.go` — does not exist; the reconciler itself
- [ ] `internal/operator/service_controller_test.go` — does not exist; covers REQ SVC-01/SVC-02 per the map above
- [ ] `charts/router-hosts-operator/templates/clusterrole.yaml` — needs the `events` rule (D-13) before any `Eventf` call can succeed in a live cluster
- [ ] Framework install: none — `testify` and `controller-runtime`'s fake client (`sigs.k8s.io/controller-runtime/pkg/client/fake`) are already dependencies used by `gateway_controller_test.go`/`ingressroute_controller_test.go`

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | no | This phase adds no new authentication surface; the operator↔server mTLS channel is unchanged (established Phase 1/3) |
| V3 Session Management | no | N/A — stateless reconcile loop |
| V4 Access Control | yes | Kubernetes RBAC (`ClusterRole`) is the access-control boundary: `services` get/list/watch/update/patch and `events` create/patch, least-privilege, no `services/status` write (Services carry no extension status this phase touches) — mirrors the existing least-privilege pattern audited by `task test:chart`'s RBAC assertions |
| V5 Input Validation | yes | `internal/validation.ValidateHostname` (hostname + each alias) and `net.ParseIP` rejection inside `ValidateAliases` (aliases can't be raw IPs) — both already implemented, reused not rebuilt (D-08) |
| V6 Cryptography | no | No new crypto surface; existing mTLS client (`internal/operator/grpc_hostclient.go`) unchanged |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|----------------------|
| A namespaced user annotates a Service they own to register an arbitrary hostname pointed at an arbitrary IP (via the `ip-address` override annotation, D-11) | Spoofing / Tampering (DNS entry ownership) | Same threat class as `--default-ingress-ip` sharing across IngressRoute/Gateway controllers (T-07-02, `gateway_controller.go:610-613`); D-11's design NOTE explicitly accepts this shape of risk as inherent to "a Service's IP is knowable from the object itself" and mitigates the *cross-controller collision* half via provenance-gated adoption (D-21) — it does NOT (and is not scoped to) prevent a single malicious Service owner from claiming a hostname nobody else has registered. This is consistent with the project's existing trust model: any actor who can annotate a Service in the watched namespaces is already trusted to publish DNS for their own workload, exactly as `HostMapping` CRD authors are. No new mitigation needed beyond what D-21 already specifies. |
| Adopting a foreign `(ip, hostname)` entry via `AlreadyExists` race and later `DeleteHost`-ing another owner's live DNS entry | Tampering / Elevation of Privilege | D-21's dual-check adoption gate (comment AND `service` tag) — implemented exactly as `hasIngressProvenance`/`hasGatewayProvenance`, both halves load-bearing per the `gateway_controller.go:601-644` rationale this phase inherits |
| `events.EventRecorder.Eventf` silently no-ops without the RBAC `events` rule, masking operator-visible failure signals from the Service owner | Repudiation (failure state becomes unobservable) | D-13's RBAC fix — verified as a real, present gap in this research, not hypothetical |
| Corrupt `host-ids` annotation tampered with (or corrupted by an unrelated controller/webhook) causing the operator to lose track of live entries and orphan them, or worse, delete an entry it shouldn't | Tampering / Denial of Service (DNS leak or wrongful deletion) | D-18's fail-closed rule: a corrupt annotation returns an error and requeues, never proceeds on a partial view — inherited unchanged from Phase 7 |
| A Service granted cluster-wide `update`/`patch` RBAC on `services` (needed to write the finalizer + `host-ids` annotation) is a broad write grant across every namespace | Elevation of Privilege (RBAC over-grant) | Inherent to the annotation-tracking design (same shape as IngressRoute/Gateway's write grants on their resources); least-privilege is enforced by scoping verbs (no `delete`, no `services/status`), verified via `task test:chart`'s RBAC assertions (D-25) |

## Sources

### Primary (HIGH confidence)

- `k8s.io/api@v0.36.1/core/v1/types.go` (local module cache, pinned version matching `go.mod`) — `ServiceType` constants, `LoadBalancerIngress`, `ServiceStatus` field semantics
- `sigs.k8s.io/controller-runtime@v0.24.1/pkg/predicate/predicate.go` (local module cache, pinned version matching `go.mod`) — `predicate.Funcs`, `NewPredicateFuncs`, `GenerationChangedPredicate`, `AnnotationChangedPredicate` behavior
- `k8s.io/client-go@v0.36.1/tools/events/{interfaces,event_recorder,fake}.go` (local module cache, pinned version matching `go.mod`) — `EventRecorder`/`Eventf` signature, `FakeRecorder` shape
- Working-tree source: `internal/operator/{ingressroute_controller,gateway_controller,hostmapping_controller,hostclient,grpc_hostclient}.go`, `internal/server/commands.go`, `internal/validation/validation.go`, `cmd/operator/main.go`, `charts/router-hosts-operator/{values.yaml,templates/clusterrole.yaml,templates/role-leader-election.yaml,templates/deployment.yaml}`, `Taskfile.yml` — all read directly, not summarized from memory
- `.planning/phases/08-kubernetes-service-controller/08-CONTEXT.md` — the 28 locked decisions

### Secondary (MEDIUM confidence)

- Kubernetes API conventions on `metadata.generation` semantics (WebSearch, cross-referenced against controller-runtime's own `GenerationChangedPredicate` doc comment caveats) — see Assumptions Log A1

### Tertiary (LOW confidence)

None used for load-bearing claims in this research.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — zero new dependencies, all versions confirmed directly against `go.mod` and local module cache
- Architecture: HIGH — every pattern is either directly copy-adaptable from Phase 7's shipped, tested controllers, or (predicate, IP resolution) verified against the pinned controller-runtime/k8s.io/api source
- Pitfalls: HIGH — all four pitfalls (predicate trap, alias nil/empty, LB ingress field independence, events RBAC gap) were empirically confirmed against source, not inferred

**Research date:** 2026-07-26
**Valid until:** 30 days (stable, pinned-dependency codebase; re-verify if `go.mod` bumps `k8s.io/api`, `client-go`, or `controller-runtime` before this phase executes)
