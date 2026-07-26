# Phase 7: Gateway API Support - Research

**Researched:** 2026-07-25
**Domain:** Kubernetes Gateway API controller (controller-runtime) integrated into an existing Go operator
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Pin `sigs.k8s.io/gateway-api` at **v1.6.1**, not the v1.5.1 named in the 2026-06-07 design doc. v1.6.1's `go.mod` requires `k8s.io/api`, `k8s.io/apimachinery`, and `k8s.io/client-go` at **v0.36.1** — an exact match for this repo's current pins — and `go 1.26.0` (repo is on 1.26.5). v1.5.1 requires v0.35.1 and would force a downgrade of the k8s libraries. **D-01 supersedes** the design doc's Dependency section.
- **D-02:** Import **`sigs.k8s.io/gateway-api/apis/v1` only**. In v1.6.1 `TLSRoute` has graduated to `apis/v1` (`+kubebuilder:storageversion`); `apis/v1alpha2.TLSRoute` carries `+kubebuilder:deprecatedversion`. All three route kinds plus `Gateway` come from one package: one `gatewayv1.Install(scheme)` call, one import, no v1alpha2/v1alpha3 surface. **D-02 supersedes** the design doc's "TLSRoute is experimental-channel v1alpha2" premise. Reversibility: costly.
- **D-03:** Build-gate-first sequencing: task 1 is `go get sigs.k8s.io/gateway-api@v1.6.1 && go mod tidy && task build`, green before any controller code. If `go mod tidy` proposes moving any `k8s.io/*` off v0.36.1, STOP and re-derive the pin.
- **D-04:** Gate each route-kind controller on the exact GVK the operator imports (`gateway.networking.k8s.io/v1`, kind `HTTPRoute`/`GRPCRoute`/`TLSRoute`) via `mgr.GetRESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)`. A kind whose mapping does not resolve gets no controller constructed.
- **D-05:** When a route kind's GroupKind resolves but not at `v1` (older cluster serving `TLSRoute` only at `v1alpha2`), skip that kind and log an actionable `Info` naming the required version — do not build a second v1alpha2 controller.
- **D-06:** Keep Gateway support opt-in: `--enable-gateway` flag on `cmd/operator` defaulting to `false`, surfaced as `gateway.enabled: false` in `charts/router-hosts-operator/values.yaml`, templated into deployment args. Per-kind RESTMapper gating (D-04) runs inside the enabled path, not instead of the flag.
- **D-07:** Reuse the existing `--default-ingress-ip` flag as the IP fallback rather than adding a gateway-specific one; update its help text (currently "Default IP for hosts extracted from IngressRoutes", `cmd/operator/main.go:44`).
- **D-08:** Document in `values.yaml` and the README that Gateway API CRDs are a cluster prerequisite — the chart does not bundle them.
- **D-09:** Finalizer is `router-hosts.fzymgc.house/gateway-cleanup`, distinct from `ingressroute-cleanup` and `host-cleanup`. Ownership is keyed on the route, never the Gateway. Reversibility: one-way (strands live finalizers if renamed).
- **D-10:** Reuse the existing `hostIDsAnnotation` (`router-hosts.fzymgc.house/host-ids`) as the `hostname → hostID` tracking map, shared with IngressRoute. Reversibility: costly.
- **D-11:** Widen `getHostIDsAnnotation`/`setHostIDsAnnotation` (`ingressroute_controller.go:390`, `:410`) from `*unstructured.Unstructured` to `client.Object` so both controllers share them. Signature-only change; `*unstructured.Unstructured` still satisfies `client.Object`.
- **D-12:** Entry provenance: comment `k8s-gateway:<namespace>/<name>`; tags `DefaultTags + ["gateway", "<kindname>"]`.
- **D-13:** Skip the object `Update` when nothing changed (recomputed `host-ids` map equals existing annotation and finalizer already present) — efficiency guard only. `UpdateHost` for already-tracked hostnames stays **unconditional**, because that is what propagates a changed Gateway IP without keeping extra state.
- **D-14:** Preserve the design's error semantics verbatim: per-host errors don't abort the batch, partial IDs always persisted, corrupt `host-ids` annotation returns an error and requeues, all fallible calls wrapped with `oops.Wrapf`, requeue via existing `requeueDelayShort`/`requeueDelayLong`, no `log.Fatal`/`os.Exit`.
- **D-15:** `resolveIP` walks `spec.parentRefs` in declaration order, `Get`s each referenced `Gateway` (parent namespace defaults to route's namespace), returns the first `IPAddress`-typed `status.addresses[]` value found. `Hostname`-typed addresses skipped. One IP per hostname.
- **D-16:** If no parent yields an IP, fall back to `--default-ingress-ip`. If that's also empty, requeue short and create nothing. A `Get` failure that is not `NotFound` is logged and the walk continues to the next parentRef.
- **D-17:** Re-resolution on Gateway change uses a per-kind field index `spec.parentRefs.gateway` emitting `"<parentNamespace>/<parentName>"`, plus `Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(...))` on each route-kind builder. Tests for the map function MUST build the fake client with `.WithIndex(...)`.
- **D-18:** Skip `*`-prefixed wildcard hostnames, de-duplicate, validate each remaining name with `internal/validation.ValidateHostname`. Invalid names logged and skipped — never fatal.
- **D-19:** Non-FQDN (dot-less) hostnames are warned about but accepted, matching current HostMapping/IngressRoute behavior (ADR `router-hosts-bzg`).
- **D-20:** `internal/operator/gateway_controller_test.go` with a fake client on the gateway-api scheme. Reuse the existing `mockHostClient`. Coverage must hold ≥80%. Required cases: hostname extraction (wildcard/invalid/dup skips), IP resolution (parent hit, Hostname-type skipped, multiple parents, missing Gateway → fallback, no IP → requeue), finalizer add and cleanup-on-delete, create/update/delete diff, parentRef index keys incl. namespace defaulting, Gateway → route map function (with `.WithIndex`), per-kind RESTMapper gating incl. all-absent case.

### Claude's Discretion

Auto-resolved under `--auto`; every question took the recommended option. The planner has latitude on: task ordering and granularity beyond the D-03 build gate; whether `hostnamesOf`/`parentRefsOf` stay two type-switches or collapse into one helper returning both; exact log message wording; whether the kinds table is a package-level func or a var. None of these change observable behavior.

### Deferred Ideas (OUT OF SCOPE)

- Enforce FQDN-only hostnames project-wide (cross-cutting, not this controller).
- `Gateway.spec.listeners[].hostname` as an entry source.
- `ReferenceGrant` enforcement for cross-namespace `parentRefs`.
- Writing route `status` conditions back to the cluster.
- `TCPRoute`/`UDPRoute` (L4, no hostnames).
- Refreshing the two 2026-06-07 docs in place (this CONTEXT records supersessions instead).

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| GW-01 | Operator reconciles Gateway API HTTPRoute/GRPCRoute/TLSRoute hostnames into router DNS entries | Confirmed `apis/v1` type shapes for all three route kinds (uniform `CommonRouteSpec` embedding); confirmed `hostnamesOf`/`extractHostnames`/`syncRoute` design from the stale plan doc compiles unchanged against v1.6.1 since the type shapes did not change between v1.5.1 and v1.6.1 for HTTPRoute/GRPCRoute — only TLSRoute's package moved. See "Verified v1.6.1 API Surface" below. |
| GW-02 | Operator resolves route IPs from the parent Gateway's `status.addresses` | Confirmed `GatewayStatusAddress{Type *AddressType, Value string}` and `IPAddressType`/`HostnameAddressType` consts unchanged from the design doc's assumptions. See "Verified v1.6.1 API Surface". |
| GW-03 | Helm chart and RBAC grant the operator watch/list access to Gateway API route resources | Read the actual `clusterrole.yaml`/`deployment.yaml`/`values.yaml`; confirmed insertion points, confirmed RBAC generation is NOT automated in this repo (chart is hand-maintained), confirmed `helm` CLI is available locally but not wired into `Taskfile.yml`. See "RBAC / Helm Wiring Specifics" below. |

</phase_requirements>

## Summary

The 2026-06-07 design doc (`docs/plans/2026-06-07-gateway-api-support-design.md`) is a genuine architecture spec, not a sketch, and CONTEXT.md has already corrected its two stale assumptions (dependency pin, TLSRoute package). This research verified every remaining Go-identifier-level claim the stale plan doc's "Grounded facts" table makes against the actual `sigs.k8s.io/gateway-api@v1.6.1` module source and the actual `controller-runtime@v0.24.1` module source (both read from local module cache / extracted tarball, not training data). **Every identifier checked out unchanged** — `HTTPRouteSpec`, `GRPCRouteSpec`, and `TLSRouteSpec` all embed `CommonRouteSpec` identically; `ParentReference.Name`/`.Namespace` types are unchanged; `GatewayStatusAddress`/`AddressType` consts are unchanged; `controllerutil` finalizer helpers, `handler.EnqueueRequestsFromMapFunc`'s `MapFunc` signature, `apimeta.ExtractList`, `RESTMapper.RESTMapping`, and the fake client's `WithIndex`/`WithObjects` behavior are all unchanged between controller-runtime v0.23.1 and v0.24.1 (only line numbers shifted). This means the stale plan doc's **code sketches are safe to reuse verbatim for HTTPRoute/GRPCRoute**, and safe for TLSRoute **after** changing its import from `gatewayv1alpha2` to `gatewayv1` (D-02) and dropping the `gatewayv1alpha2.Install(scheme)` call.

One finding is **not** covered by any locked CONTEXT.md decision and is a genuine gap in the stale plan doc's code: **the `Watches(&gatewayv1.Gateway{}, ...)` clause in `SetupWithManager` is never gated on Gateway CRD presence**, unlike the three route kinds (D-04/D-05). If a cluster has route CRDs installed but no Gateway CRD (a valid, if unusual, configuration), the informer cache will fail to start for the `Gateway` GVK when the manager starts — and because controller-runtime's cache is shared across all controllers in a manager, this **crashes the entire operator process**, not just the Gateway-support feature, taking down the already-shipped HostMapping and IngressRoute controllers too. The design's Decision 4 prose claims "if Gateways are absent the route controllers still run with `--default-ingress-ip` as the sole IP source" — true in principle, but the code sketch that would make it true is missing. The plan MUST add a Gateway-presence check (reusing `gatewayKindPresent`) and conditionally add the `.Watches(...)` clause per instance. This is the single most important correction this research contributes beyond what CONTEXT.md already locked in.

A second, smaller finding: this repo's `task manifests`/`task lint` pipeline only regenerates CRDs and deepcopy code (`controller-gen crd`/`object` scoped to `api/operator/...`) — there is no `controller-gen rbac` step and no `helm lint` step anywhere in `Taskfile.yml`. The kubebuilder `+kubebuilder:rbac` markers the stale plan doc adds are therefore documentation-only in this codebase; `charts/router-hosts-operator/templates/clusterrole.yaml` must be hand-edited, same as the existing IngressRoute/HostMapping rules already are. `helm` (v4.2.3) is available on the machine for manual verification (`helm template ... | grep`) but is not part of CI.

**Primary recommendation:** Follow the stale plan doc's task sequence and code almost verbatim, with four concrete changes: (1) swap `apis/v1alpha2` → `apis/v1` for TLSRoute and drop the second `Install` call, per D-02; (2) pin `v1.6.1` everywhere the doc says `v1.5.1`; (3) add a Gateway-presence gate around each route controller's `.Watches(&gatewayv1.Gateway{}, ...)` clause — do not construct it unconditionally; (4) replace every `jj commit` step with `git commit` (native git only, per CLAUDE.md).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Route hostname extraction (HTTPRoute/GRPCRoute/TLSRoute) | API/Backend (operator controller) | — | Controller-runtime reconciler reading `spec.hostnames` from the Kubernetes API server via the informer cache; no client or storage tier involved. |
| Gateway IP resolution (`status.addresses`) | API/Backend (operator controller) | Database/Storage (etcd, via API server) | The operator reads `Gateway.status`, which the Gateway controller (not this operator) writes; this phase is a read-only consumer of that status. |
| Host entry sync (create/update/delete) | API/Backend (operator → router-hosts gRPC server) | Database/Storage (SQLite event store) | The operator's `HostClient` is the sole write path into the router-hosts server; the server's event store is the actual persistence tier and is untouched by this phase. |
| RBAC / CRD watch permissions | Database/Storage (Kubernetes API server authorization) | — | Enforced entirely by the `ClusterRole` the chart ships; not application logic. |
| Cluster prerequisite (Gateway API CRDs) | CDN/Static-equivalent: cluster infrastructure | — | Installed independently of this chart; the operator only consumes CRDs it does not own or install. |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `sigs.k8s.io/gateway-api` | v1.6.1 | Typed Gateway API client types (`HTTPRoute`, `GRPCRoute`, `TLSRoute`, `Gateway`) | Official Kubernetes SIGs module, the canonical Go types for the Gateway API `gateway.networking.k8s.io` group. `[VERIFIED: proxy.golang.org]` — `@latest` resolves to v1.6.1 (published 2026-07-16, tag `v1.6.1` on `github.com/kubernetes-sigs/gateway-api`), and its `go.mod` requires `k8s.io/apimachinery`/`k8s.io/client-go` at exactly v0.36.1 and `go 1.26.0`, matching this repo's pins exactly. |
| `sigs.k8s.io/controller-runtime` | v0.24.1 (already in go.mod) | Reconciler framework, fake client, field indexer, RESTMapper | Already the operator's framework; no new dependency. `[VERIFIED: local module cache]` — read directly from `/Users/sean/go/pkg/mod/sigs.k8s.io/controller-runtime@v0.24.1`. |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `k8s.io/apimachinery` | v0.36.1 (already in go.mod) | `meta.RESTMapper`, `meta.ExtractList`, `meta.NoKindMatchError`, `schema.GroupVersionKind` | Used for CRD-presence gating (D-04) and the Gateway→route map function's list extraction. |
| `github.com/samber/oops` | v1.22.0 (already in go.mod) | Structured error wrapping | Required by CLAUDE.md for all fallible operations; already used identically in `ingressroute_controller.go` and `hostmapping_controller.go`. |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Typed `sigs.k8s.io/gateway-api` client | `unstructured.Unstructured` (as IngressRoute does) | Rejected in the design (Decision 1) and reaffirmed by CONTEXT: `unstructured` exists only because Traefik's CRD types aren't a clean importable module — that constraint doesn't apply to Gateway API, a first-class versioned module. |
| One controller per route kind | Single reconciler with a GVK type-switch on every request | Rejected in the design (Decision 2): a `ctrl.Request` carries no type, so a single reconciler would need a GVK try-fallback per request (the exact pattern IngressRoute already uses out of necessity for `unstructured`, and which Gateway API's typed client is meant to avoid). |

**Installation:**

```bash
go get sigs.k8s.io/gateway-api@v1.6.1
go mod tidy
task build
```

**Version verification:** `[VERIFIED: proxy.golang.org]` — confirmed 2026-07-25 via `curl https://proxy.golang.org/sigs.k8s.io/gateway-api/@latest` → `{"Version":"v1.6.1","Time":"2026-07-16T14:37:26Z", ...}` and `curl https://proxy.golang.org/sigs.k8s.io/gateway-api/@v/v1.6.1.mod` (read via the extracted module at the path given below) showing `go 1.26.0` and the exact `k8s.io/{api,apimachinery,client-go} v0.36.1` requirement. No newer stable version exists as of the research date.

## Package Legitimacy Audit

> The `gsd-tools query package-legitimacy check` seam only supports `npm`/`pypi`/`crates` ecosystems; it does not support Go modules, so it was **not run** for `sigs.k8s.io/gateway-api`. This is not a gap in verification effort — Go-module legitimacy was independently established below.

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|--------------|---------|-------------|
| `sigs.k8s.io/gateway-api` | Go module proxy (proxy.golang.org) | First tagged release 2020; v1.6.1 published 2026-07-16 | N/A (Go modules have no download-count metric) | `github.com/kubernetes-sigs/gateway-api` — the official Kubernetes SIGs organization, the same org that publishes `k8s.io/*` and `sigs.k8s.io/controller-runtime` already in this repo's dependency tree | OK | Approved — `[VERIFIED: proxy.golang.org]`, module vendor path (`sigs.k8s.io`) matches the org already trusted for `controller-runtime`; no slopsquat risk (the vanity import path resolves through Kubernetes' own DNS-hosted module redirect, not a third-party registry name that could be typo-squatted). |

**Packages removed due to [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

## Verified v1.6.1 API Surface

All identifiers below were read directly from the extracted module source at `/private/tmp/claude-501/-Volumes-Code-github-com-fzymgc-house-router-hosts/91757d26-2f1a-47aa-b0b7-02c5ee26db82/scratchpad/gw/sigs.k8s.io/gateway-api@v1.6.1/`, not from training data. `[VERIFIED: sigs.k8s.io/gateway-api@v1.6.1 module source]` for every row.

| Identifier | v1.6.1 shape | Matches stale plan doc's "Grounded facts"? |
|------------|--------------|---------------------------------------------|
| `TLSRouteSpec` | `apis/v1/tlsroute_types.go` — embeds `CommonRouteSpec` inline, `Hostnames []Hostname`, `+kubebuilder:storageversion` on the `TLSRoute` type | **Differs**: doc says `apis/v1alpha2`, storage version confirms D-02's premise |
| `HTTPRouteSpec` | `apis/v1/httproute_types.go:59` — `CommonRouteSpec` inline, `Hostnames []Hostname` | Matches |
| `GRPCRouteSpec` | `apis/v1/grpcroute_types.go:87` — `CommonRouteSpec` inline, `Hostnames []Hostname` | Matches |
| `CommonRouteSpec.ParentRefs` | `apis/v1/shared_types.go:259` — `[]ParentReference` | Matches |
| `ParentReference.Name` | `apis/v1/shared_types.go:88` — `ObjectName` (defined as `type ObjectName string` at `:708`) | Matches |
| `ParentReference.Namespace` | `apis/v1/shared_types.go:82` — `*Namespace` (defined as `type Namespace string` at `:729`) | Matches |
| `Hostname` | `apis/v1/shared_types.go:628` — `type Hostname string` | Matches |
| `Gateway.Status.Addresses` | `apis/v1/gateway_types.go:974` — `[]GatewayStatusAddress` | Matches |
| `GatewayStatusAddress` | `apis/v1/gateway_types.go:940` — `Type *AddressType`, `Value string` | Matches |
| `AddressType` consts | `apis/v1/shared_types.go:866,893,901,911` — `type AddressType string`; `IPAddressType AddressType = "IPAddress"`; `HostnameAddressType AddressType = "Hostname"`; `NamedAddressType AddressType = "NamedAddress"` | Matches |
| `Install`/`AddToScheme`/`SchemeGroupVersion` | `apis/v1/zz_generated.register.go` — `Install = localSchemeBuilder.AddToScheme` (same function, two names); `SchemeGroupVersion` present (marked `Deprecated: use GroupVersion instead` but still exported and usable); new preferred `GroupVersion metav1.GroupVersion` also present | Matches (both names usable) |
| `…List` types | `zz_generated.register.go` registers `HTTPRouteList`, `GRPCRouteList`, `TLSRouteList`, `GatewayList` **all in the single `apis/v1` package** | Matches — confirms D-02's "one import" claim at the registration level, not just the type level |

**Net effect for the plan:** a single `gatewayv1.Install(scheme)` call (or `gatewayv1.AddToScheme(scheme)` — same function) in `cmd/operator/main.go` registers `HTTPRoute`, `GRPCRoute`, `TLSRoute`, and `Gateway` plus their List types. No `apis/v1alpha2` import is needed anywhere in this phase.

## Controller-Runtime v0.24.1 API Currency

`[VERIFIED: sigs.k8s.io/controller-runtime@v0.24.1 module source]`, diffed directly against the v0.23.1 module also present in the local module cache.

| API | v0.24.1 signature | Drift from v0.23.1? |
|-----|--------------------|-----------------------|
| `ctrl.NewControllerManagedBy(mgr).For(obj).Named(name).Watches(obj2, handler).Complete(r)` | `Builder = TypedBuilder[reconcile.Request]`; `For(object client.Object, opts ...ForOption) *TypedBuilder`; `Named(string) *TypedBuilder`; `Watches(object client.Object, eventHandler handler.TypedEventHandler[client.Object, request], opts ...WatchesOption) *TypedBuilder`; `Complete(r reconcile.TypedReconciler[request]) error` | **None** — identical method set and signatures; only internal line numbers shifted between versions. |
| `handler.EnqueueRequestsFromMapFunc(fn)` | `MapFunc = TypedMapFunc[client.Object, reconcile.Request]`; `TypedMapFunc[object any, request comparable] func(context.Context, object) []request`; i.e. `func(ctx context.Context, obj client.Object) []reconcile.Request` | **None** — the design's `mapGatewayToRoutes(ctx context.Context, gw client.Object) []reconcile.Request` signature matches exactly. |
| `mgr.GetFieldIndexer().IndexField(ctx, obj, key, fn)` | `client.FieldIndexer.IndexField(ctx context.Context, obj Object, field string, extractValue IndexerFunc) error` (`pkg/client/interfaces.go:209`); backed by `informerCache.IndexField` | **None** — must be called before the manager starts (before the target GVK's informer starts); no functional change between versions. |
| `fake.NewClientBuilder().WithScheme(...).WithObjects(...).WithIndex(obj, field, fn)` | `WithIndex(obj runtime.Object, field string, extractValue client.IndexerFunc) *ClientBuilder` | **None** — same signature both versions. |
| `controllerutil.ContainsFinalizer/AddFinalizer/RemoveFinalizer` | `pkg/controller/controllerutil/controllerutil.go:502,513,530` — same three functions, same signatures (`(o client.Object, finalizer string) bool` / `(finalizersUpdated bool)`) | **None**. |
| `apimeta.RESTMapper.RESTMapping` + `meta.NoKindMatchError` | `k8s.io/apimachinery@v0.36.1`: `DefaultRESTMapper.RESTMapping(gk schema.GroupKind, versions ...string) (*RESTMapping, error)` (`pkg/api/meta/restmapper.go:450`); `NoKindMatchError` struct present at `pkg/api/meta/errors.go:99` | **None** relative to what the design assumes — `gatewayKindPresent` only needs `err == nil`, no type assertion on the error required. |
| `apimeta.ExtractList` | `k8s.io/apimachinery@v0.36.1/pkg/api/meta/help.go:202` — `func ExtractList(obj runtime.Object) ([]runtime.Object, error)` (an `ExtractListWithAlloc` variant also exists at `:210` but is not needed here) | **None**. |

**Conclusion:** none of the controller-runtime/apimachinery code sketches in the stale plan doc need adjustment for the v0.23.1→v0.24.1 jump. The only required changes are the gateway-api package path (D-02) and version pin (D-01).

## Architecture Patterns

### System Architecture Diagram

```text
   HTTPRoute  ──▶ informer/watch ─▶ Reconciler(HTTPRoute)  ─┐
   GRPCRoute  ──▶ informer/watch ─▶ Reconciler(GRPCRoute)  ─┼─▶ shared syncRoute(ctx, obj, hostnames)
   TLSRoute   ──▶ informer/watch ─▶ Reconciler(TLSRoute)   ─┘        │
                                        ▲                            │  resolveIP(obj) walks parentRefs,
   Gateway ───────────────────────────┘  (Watches + parentRefs      │  Get()s each Gateway, reads
   (status.addresses changes)             field-index re-enqueues   │  status.addresses[IPAddress]
                                           the owning routes)        ▼
                                                          AddHost / UpdateHost / DeleteHost
                                                                     │
                                                                     ▼
                                                    router-hosts gRPC server (mTLS) ──▶ SQLite event store
                                                                                    ──▶ hosts(5) / dnsmasq / unbound output

   SetupGatewayControllers(mgr) ── RESTMapper.RESTMapping() gate per route kind ──▶ constructs 0..3 controllers
                                └─ MUST ALSO gate the Gateway-kind Watches() clause per controller (see Risks below) ──▶ currently missing in the stale plan doc
```

A reader can trace the primary use case (a new `HTTPRoute` appears → a DNS entry appears on the router) by following: route created → informer delivers Create event → `Reconcile` adds finalizer → next reconcile calls `extractHostnames` + `resolveIP` (which does a live `Get` against the referenced `Gateway`, itself populated by the cluster's Gateway controller, out of band) → `syncRoute` diffs against the `host-ids` annotation → `HostClient.AddHost` over mTLS → server persists an event and regenerates output files.

### Recommended Project Structure

No new directories — this phase adds one file pair to the existing flat `internal/operator` package, matching the existing `ingressroute_controller.go`/`hostmapping_controller.go` layout:

```text
internal/operator/
├── gateway_controller.go       # new: GatewayRouteReconciler, syncRoute, resolveIP,
│                                 hostnamesOf/parentRefsOf, SetupGatewayControllers
├── gateway_controller_test.go  # new: unit tests, reuses mockHostClient
├── ingressroute_controller.go  # modified: widen getHostIDsAnnotation/setHostIDsAnnotation
│                                 params from *unstructured.Unstructured to client.Object (D-11)
└── hostmapping_controller.go   # unchanged (source of requeueDelayShort/Long constants)
```

### Pattern 1: Per-route-kind reconciler sharing one core (Decision 2)

**What:** One `GatewayRouteReconciler` struct instantiated three times (once per enabled route kind), each carrying a `newObject func() client.Object` / `newList func() client.ObjectList` factory pair so `Reconcile` does a single unambiguous typed `Get` per request — no GVK try-fallback.
**When to use:** Whenever a manager must watch several distinct typed kinds that share reconcile logic but have no common concrete Go type (only a common structural shape via `client.Object` + a type-switch helper).
**Example (verified compiles against v1.6.1 once the TLSRoute import is `apis/v1`):**

```go
// Source: docs/plans/2026-06-07-gateway-api-support-plan.md Task 7,
// verified against sigs.k8s.io/gateway-api@v1.6.1 module source (2026-07-25).
type gatewayRouteKind struct {
    name      string
    gvk       schema.GroupVersionKind
    newObject func() client.Object
    newList   func() client.ObjectList
}

func gatewayRouteKinds() []gatewayRouteKind {
    return []gatewayRouteKind{
        {
            name:      "httproute",
            gvk:       gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute"),
            newObject: func() client.Object { return &gatewayv1.HTTPRoute{} },
            newList:   func() client.ObjectList { return &gatewayv1.HTTPRouteList{} },
        },
        {
            name:      "grpcroute",
            gvk:       gatewayv1.SchemeGroupVersion.WithKind("GRPCRoute"),
            newObject: func() client.Object { return &gatewayv1.GRPCRoute{} },
            newList:   func() client.ObjectList { return &gatewayv1.GRPCRouteList{} },
        },
        {
            // NOTE: gatewayv1, not gatewayv1alpha2 — TLSRoute graduated (D-02).
            name:      "tlsroute",
            gvk:       gatewayv1.SchemeGroupVersion.WithKind("TLSRoute"),
            newObject: func() client.Object { return &gatewayv1.TLSRoute{} },
            newList:   func() client.ObjectList { return &gatewayv1.TLSRouteList{} },
        },
    }
}
```

### Pattern 2: parentRefs field index + Gateway map-func re-enqueue (Decision 2a / D-17)

**What:** A field index keyed `"spec.parentRefs.gateway"` on each route kind, emitting `"<parentNamespace>/<parentName>"` per parentRef (namespace defaulted to the route's own namespace). A `Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(mapFn))` clause on each route builder, where `mapFn` lists that controller's route kind filtered by the index.
**When to use:** Whenever a secondary object (here, `Gateway`) can invalidate previously-computed state (here, the resolved IP) without itself being the reconciled object.
**Example:** see the stale plan doc's Task 6 code — verified unchanged against v0.24.1 (`apimeta.ExtractList`, `handler.EnqueueRequestsFromMapFunc`, `client.MatchingFields` all confirmed above).

### Anti-Patterns to Avoid

- **Unconditionally watching a kind that might not exist in the cluster:** the design correctly avoids this for the three route kinds (D-04/D-05) but the stale plan doc's code sketch does **not** apply the same gate to the `Gateway` watch inside each route controller. See "Risks the Planner Must Design Around" below — this is the most important thing to fix relative to the stale doc.
- **Re-adding `apis/v1alpha2` "just for TLSRoute":** unnecessary after v1.6.1's graduation (D-02) and doubles the scheme-install/RBAC/type-switch surface for no benefit.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| CRD-presence detection | A custom "does this GVK exist" probe via raw discovery client calls | `mgr.GetRESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)` returning `meta.NoKindMatchError` on miss | Already the controller-runtime-idiomatic mechanism; verified unchanged in v0.24.1/apimachinery v0.36.1. |
| Gateway→route re-enqueue | Polling Gateways on a timer | Field indexer + `Watches(...)` + `EnqueueRequestsFromMapFunc` | Standard controller-runtime pattern for cross-object invalidation; avoids poll latency and matches the codebase's existing idioms (none exist yet in this repo, but it's the documented CR pattern). |
| Hostname validation | A new regex/validator specific to Gateway API hostnames | `internal/validation.ValidateHostname` (already used by IngressRoute) | Same validation semantics must apply across all three controllers per D-18/D-19; a second validator would silently diverge. |

**Key insight:** every piece of non-trivial machinery this phase needs (CRD gating, field indexing, cross-object re-enqueue, annotation-based ID tracking, finalizer lifecycle) already has a first-class idiom in controller-runtime or a working precedent in this same package. There is no part of this phase that legitimately needs a hand-rolled solution.

## Common Pitfalls

### Pitfall 1: Gateway watch not gated on Gateway CRD presence (new finding, not in CONTEXT.md)

**What goes wrong:** `SetupWithManager` (per the stale plan doc's Task 7) unconditionally does:

```go
return ctrl.NewControllerManagedBy(mgr).
    For(r.newObject()).
    Named("gateway-" + r.KindName).
    Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayToRoutes)).
    Complete(r)
```

If a cluster has (say) `HTTPRoute` CRDs installed but not `Gateway` CRDs — an unusual but valid configuration, and exactly the scenario D-04/D-05 are designed to tolerate for route kinds — the manager's shared informer cache will attempt to start an informer for the `Gateway` GVK when `mgr.Start()` runs. That List/Watch against the API server 404s, the cache's `Start()` returns an error, and **the entire manager process fails to start** — taking down the already-shipped HostMapping and IngressRoute controllers along with the new Gateway-route controllers, not just the Gateway feature.
**Why it happens:** `Watches()` only *registers* a source; the actual List/Watch call happens when the manager's shared cache starts *all* registered informers together, not per-controller. GVK resolvability is not checked at `Watches()`-call time.
**How to avoid:** In `SetupGatewayControllers`, resolve the Gateway GVK's presence once via the same `gatewayKindPresent(mapper, gatewayGVK)` helper used for route kinds, and pass the boolean into each `GatewayRouteReconciler`/`SetupWithManager` call so the `.Watches(...)` clause is only added when Gateway CRDs are present:

```go
gatewayGVK := gatewayv1.SchemeGroupVersion.WithKind("Gateway")
watchGateway := gatewayKindPresent(mapper, gatewayGVK)
// ... per route kind:
bldr := ctrl.NewControllerManagedBy(mgr).For(r.newObject()).Named("gateway-" + r.KindName)
if watchGateway {
    bldr = bldr.Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayToRoutes))
}
return bldr.Complete(r)
```

When Gateway CRDs are absent, routes still get reconciled and IP falls back to `--default-ingress-ip` (D-16) — the controller just won't get an event-driven kick when a Gateway's `status.addresses` changes later (acceptable: Gateway CRDs absent means there's no Gateway object to change anyway).
**Warning signs:** Manager crash-loops on startup with a `no matches for kind "Gateway" in version "gateway.networking.k8s.io/v1"` (or similar `NoKindMatchError`/404-from-discovery) error, and the crash log shows it originating from cache/informer startup rather than from `SetupGatewayControllers` itself (because the RESTMapper check the design *does* apply to route kinds passes fine — Gateway CRDs being absent is a separate, ungated failure).

### Pitfall 2: Fake client `WithObjects` + `DeletionTimestamp` — already solved in this repo, reuse the pattern

**What goes wrong (in general, other codebases):** Some believe a fake client rejects or silently drops an object seeded with a `DeletionTimestamp` but no finalizer, or that `Create()`-style deletion-timestamp stripping applies to test fixtures too.
**Why it doesn't apply here:** `[VERIFIED: controller-runtime@v0.24.1 module source]` — `fake.ClientBuilder.Build()` seeds `WithObjects(...)` fixtures via `tracker.Add(obj)` directly (`pkg/client/fake/client.go:305-311`), which bypasses the deletion-timestamp-stripping logic that lives specifically in `(*fakeClient).Create()` (`:641-645`, guarding only the live `Create` RPC path). This repo's own `ingressroute_controller_test.go` (`TestReconcile_IngressRoute_Delete`, line ~201) already proves the working pattern in this exact controller-runtime version:

```go
obj.SetFinalizers([]string{ingressRouteCleanupFinalizer})  // finalizer FIRST
obj.SetDeletionTimestamp(&now)                              // then DeletionTimestamp
k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(obj).Build()
```

**How to avoid:** Reuse this exact ordering for the Gateway delete-path test (this is what the stale plan doc's Task 5 test already does — `route.Finalizers = [...]` then `route.DeletionTimestamp = &now` then `WithObjects(route)` — so no change is needed there). Do not "fix" this into a `.Create()` + `.Delete()` two-step; that changes the resourceVersion semantics and is unnecessary.
**Warning signs:** none expected — this is a non-issue in v0.24.1 as long as the finalizer-then-timestamp ordering from the existing tests is followed.

### Pitfall 3: `SetupWithManager`/`SetupGatewayControllers` will show 0% direct unit-test coverage — this is already the accepted pattern in this package

**What goes wrong:** A plan author might feel obligated to unit-test `SetupWithManager`/`SetupGatewayControllers` directly (they need a real `ctrl.Manager`, which is expensive/awkward to fake) and either skip coverage entirely (risking the 80% gate) or over-engineer a manager mock.
**Why it happens:** These functions are thin wiring around `mgr.GetFieldIndexer()`/`mgr.GetRESTMapper()`/`ctrl.NewControllerManagedBy` — there is little branching logic to actually test once the pure helper functions (`gatewayKindPresent`, `routeParentRefIndexFunc`) are extracted and separately tested.
**How to avoid:** `[VERIFIED: go test -coverprofile, this repo, 2026-07-25]` — `IngressRouteReconciler.SetupWithManager` and `HostMappingReconciler.SetupWithManager` both already sit at **0.0% coverage** in the current, accepted, ≥80%-passing baseline (package total: 87.9%). This is precedent, not a gap to fix. Follow the same split: extract `gatewayKindPresent` and `routeParentRefIndexFunc` as pure functions taking a `meta.RESTMapper`/`client.Object` respectively (no manager needed) and unit-test those directly (as D-20 already requires); leave `SetupWithManager`/`SetupGatewayControllers` uncovered by direct unit tests, same as the existing two controllers.
**Warning signs:** N/A — this is expected and matches the codebase's existing coverage shape.

### Pitfall 4: Unconditional `UpdateHost` (D-13) will append a server-side event on every periodic informer resync — accepted tradeoff, not a bug to fix

**What goes wrong (if unaware):** A reviewer familiar with the IngressRoute controller's `syncHost` (which added a GetHost-before-Update idempotency check specifically to fix the event-bloat hot-loop, GH #338/#339/#341) might expect the same guard here and flag its absence as a regression.
**Why it's intentional:** D-13 explicitly locks this in: "`UpdateHost` for already-tracked hostnames stays unconditional, because that is what propagates a changed Gateway IP without keeping extra state." This means every reconcile that reaches `syncRoute` after the finalizer exists — including the informer's periodic resync delivery (default resync interval, not just real spec changes) — will call `UpdateHost` for every tracked hostname, and (per the server's own semantics, documented in `ingressroute_controller.go`'s `syncHost` comment) "the server appends an event for any presented comment/tags field without comparing its value" — so this is a slow, resync-interval-cadence version of the event-bloat pattern IngressRoute deliberately fixed, re-accepted here as a locked, explicit tradeoff.
**How to avoid (not "fix" — this is not to be changed):** Mirror IngressRoute's practice of a clear code comment on `syncRoute` explaining why `UpdateHost` is unconditional here (pointing at D-13's rationale) so a future maintainer doesn't "fix" it into an inconsistency with the rest of the file without re-deriving the tradeoff. Ensure D-20's test matrix includes an explicit assertion that `UpdateHost` **is called** even when the resolved IP is unchanged (proving the intentional behavior, not just the finalizer/create/delete paths).
**Warning signs:** N/A for this phase — flagging for awareness only; do not add an idempotency check without a new CONTEXT decision authorizing it.

## Code Examples

### Gateway-presence-gated `SetupWithManager` (corrects the stale plan doc's Task 7 gap)

```go
// Source: this research, correcting docs/plans/2026-06-07-gateway-api-support-plan.md Task 7
// (verified against controller-runtime@v0.24.1 and gateway-api@v1.6.1 module source, 2026-07-25).
var gatewayGVK = gatewayv1.SchemeGroupVersion.WithKind("Gateway")

func SetupGatewayControllers(mgr ctrl.Manager, log *slog.Logger, hc HostClient, defaultIP string, defaultTags []string) error {
    mapper := mgr.GetRESTMapper()
    watchGateway := gatewayKindPresent(mapper, gatewayGVK)
    for _, k := range gatewayRouteKinds() {
        if !gatewayKindPresent(mapper, k.gvk) {
            log.Info("Gateway API CRD not installed; skipping controller", "kind", k.name)
            continue
        }
        rec := &GatewayRouteReconciler{
            Client:      mgr.GetClient(),
            HostClient:  hc,
            Log:         log.With("controller", "gateway-"+k.name),
            KindName:    k.name,
            newObject:   k.newObject,
            newList:     k.newList,
            DefaultIP:   defaultIP,
            DefaultTags: defaultTags,
        }
        if err := rec.SetupWithManager(mgr, watchGateway); err != nil {
            return oops.Wrapf(err, "setting up gateway controller for %s", k.name)
        }
        log.Info("Gateway API controller registered", "kind", k.name, "watchesGateway", watchGateway)
    }
    return nil
}

func (r *GatewayRouteReconciler) SetupWithManager(mgr ctrl.Manager, watchGateway bool) error {
    if err := mgr.GetFieldIndexer().IndexField(context.Background(), r.newObject(), parentRefIndexKey, routeParentRefIndexFunc); err != nil {
        return oops.Wrapf(err, "indexing %s parentRefs", r.KindName)
    }
    bldr := ctrl.NewControllerManagedBy(mgr).
        For(r.newObject()).
        Named("gateway-" + r.KindName)
    if watchGateway {
        bldr = bldr.Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayToRoutes))
    }
    return bldr.Complete(r)
}
```

### `gatewayKindPresent` test pattern (unit-testable without a manager)

```go
// Source: docs/plans/2026-06-07-gateway-api-support-plan.md Task 7 Step 1,
// verified compiling against k8s.io/apimachinery@v0.36.1's DefaultRESTMapper.
func TestGatewayKindPresent_UsesRESTMapper(t *testing.T) {
    present := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
    mapper := apimeta.NewDefaultRESTMapper(nil)
    mapper.Add(present, apimeta.RESTScopeNamespace)

    httpGVK := gatewayRouteKinds()[0].gvk
    tlsGVK := gatewayRouteKinds()[2].gvk
    assert.True(t, gatewayKindPresent(mapper, httpGVK))
    assert.False(t, gatewayKindPresent(mapper, tlsGVK))
}
```

## RBAC / Helm Wiring Specifics

`[VERIFIED: repo source, read 2026-07-25]`

### `charts/router-hosts-operator/templates/clusterrole.yaml`

Entire file is 29 lines, guarded by `{{- if .Values.rbac.create -}}` / `{{- end }}`. Insert the new Gateway API rule block **between** the existing Traefik `ingressroutes`/`ingressroutetcps` rule (lines 9-14) and the `hostmappings` rule block (line 16 onward) — i.e. immediately after line 14/before line 16:

```yaml
  # Gateway API routes (gateway.networking.k8s.io). The controller writes a
  # finalizer + host-ids annotation, so update;patch are required.
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["httproutes", "grpcroutes", "tlsroutes"]
    verbs: ["get", "list", "watch", "update", "patch"]

  # Gateway resources are read-only (IP resolution from status.addresses).
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways"]
    verbs: ["get", "list", "watch"]
```

### `charts/router-hosts-operator/templates/deployment.yaml`

The `args:` list already has a working conditional-flag precedent to copy exactly — the `--default-ingress-ip` block at lines 49-51:

```yaml
            {{- with .Values.routerHosts.defaultIngressIP }}
            - --default-ingress-ip={{ . }}
            {{- end }}
```

Insert the new flag immediately after that block and before `--health-probe-bind-address` (line 52):

```yaml
            {{- if .Values.gateway.enabled }}
            - --enable-gateway
            {{- end }}
```

### `charts/router-hosts-operator/values.yaml`

No existing `gateway:` key. Add a new top-level block (the file has no strict ordering convention to preserve — `routerHosts` and `rbac` are both top-level siblings already):

```yaml
# Kubernetes Gateway API controllers. Disabled by default. The Gateway API CRDs
# (gateway.networking.k8s.io) MUST be installed in the cluster; this chart does
# not bundle them.
gateway:
  # Enable the HTTPRoute/GRPCRoute/TLSRoute controllers. Controllers are only
  # started for kinds whose CRD is actually installed (per-kind RESTMapper gating).
  enabled: false
```

Per D-07, **no new IP-fallback value is needed** — `routerHosts.defaultIngressIP` (already present, line 117) is reused as-is; only its inline comment needs updating to mention Gateway API routes alongside IngressRoutes.

### Is RBAC generation automated?

**No.** `[VERIFIED: Taskfile.yml, read 2026-07-25]` — `task manifests` runs exactly two `controller-gen` invocations, both scoped to `./api/operator/...`:

```yaml
manifests:
  cmds:
    - '{{.CONTROLLER_GEN}} crd paths=./api/operator/... output:crd:dir={{.CRD_DIR}}'
    - '{{.CONTROLLER_GEN}} object paths=./api/operator/...'
```

There is no `controller-gen rbac:...` invocation anywhere in `Taskfile.yml`, and `task lint`'s `manifests:verify` step only checks drift in `{{.CRD_DIR}}` (`charts/router-hosts-operator/crds`) and `api/operator` — **not** `clusterrole.yaml`. The `+kubebuilder:rbac` markers this phase adds to `gateway_controller.go` (mirroring the existing markers already present on `IngressRouteReconciler`/`HostMappingReconciler`) are therefore **documentation-only** in this codebase; they do not drive any generation step, and the ClusterRole YAML is, and remains, hand-maintained. This matches the existing precedent exactly — `ingressroute_controller.go`'s own `+kubebuilder:rbac` markers (lines 78-79) are equally decorative for the same reason.

### Is `helm` available as a lint step?

**Not in CI/Taskfile**, but the binary is present on this machine: `[VERIFIED: local shell, 2026-07-25]` `helm version --short` → `v4.2.3+g43e8b7f`. `Taskfile.yml` has no `helm lint`/`helm template` task at all — the stale plan doc's Task 9 Step 3 ("Run: `helm lint charts/router-hosts-operator` (or `task lint` if it covers charts)") is only half-right: `task lint` does **not** cover charts. The plan should add `helm lint charts/router-hosts-operator` and `helm template charts/router-hosts-operator --set gateway.enabled=true | grep -- '--enable-gateway'` as **manual verification steps** in the relevant task, not assume they run under any existing `task` target.

## Test-Scaffolding Reuse

`[VERIFIED: repo source, read 2026-07-25]`

### `mockHostClient` (defined in `hostmapping_controller_test.go`, same `operator` package — reuse directly, do not duplicate)

```go
type mockHostClient struct {
    addHostFn    func(ctx context.Context, ip, hostname, comment string, aliases, tags []string) (string, error)
    updateHostFn func(ctx context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error
    deleteHostFn func(ctx context.Context, id string) error
    getHostFn    func(ctx context.Context, id string) (*HostEntry, error)
    findHostFn   func(ctx context.Context, ip, hostname string) (*HostEntry, error)
}
```

Each method falls back to a sane default (e.g. `AddHost` → `"test-id-1", nil`; `GetHost` → a synthetic `HostEntry{ID: id, IP: "192.168.1.10", Hostname: "test.local", Version: "v1"}`) when the corresponding `*Fn` field is nil, so tests only need to set the fields they care about. `Close()` always returns nil. This exactly matches the `HostClient` interface (`AddHost`/`UpdateHost`/`DeleteHost`/`GetHost`/`FindHost`/`Close`) — no adaptation needed for the Gateway controller, which uses `AddHost`/`UpdateHost`/`DeleteHost` only (does not need `GetHost`/`FindHost`, per D-13's simpler unconditional-update design vs. IngressRoute's adoption logic).

### Scheme construction pattern (build a fresh helper, do not reuse `ingressRouteScheme`)

`ingressRouteScheme(t)` (in `ingressroute_controller_test.go:852`) registers `unstructured` types manually via `AddKnownTypeWithName` for the Traefik CRD GVKs — irrelevant to Gateway API, which has typed `Install`/`AddToScheme` functions. The Gateway test scheme should instead follow `hostmapping_controller_test.go`'s pattern (`clientgoscheme.AddToScheme(s)` + the specific API's `AddToScheme`), adapted to:

```go
func gatewayScheme(t *testing.T) *runtime.Scheme {
    t.Helper()
    s := runtime.NewScheme()
    require.NoError(t, gatewayv1.Install(s))
    return s
}
```

(Note: only `gatewayv1.Install`, no `gatewayv1alpha2.Install` — the stale plan doc's Task 4 test sketch includes a second `Install` call for v1alpha2 that must be dropped per D-02.)

### Deletion-timestamp test pattern (reuse verbatim — see Pitfall 2 above)

`ingressroute_controller_test.go`'s `TestReconcile_IngressRoute_Delete` (line ~201) sets `Finalizers` then `DeletionTimestamp` then builds the fake client with `WithObjects(obj)` — no `.Create()`/`.Delete()` round-trip needed. Reuse this exact ordering for `TestReconcile_HTTPRoute_DeletesHostsOnFinalize`.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-------------------|----------------|--------|
| `TLSRoute` lives in `gateway-api/apis/v1alpha2`, experimental channel | `TLSRoute` lives in `gateway-api/apis/v1`, marked `+kubebuilder:storageversion`; `v1alpha2.TLSRoute` marked `+kubebuilder:deprecatedversion` | Between gateway-api v1.5.x and v1.6.1 (exact minor-version boundary not independently pinpointed in this research; irrelevant to this phase since the pin is v1.6.1 regardless) | Simplifies this phase to a single package import/scheme-install (D-02); eliminates an entire duplicated code path the stale plan doc's Task 4/7 sketches would otherwise require. |

**Deprecated/outdated:**

- `sigs.k8s.io/gateway-api v1.5.1` pin from the 2026-06-07 design doc: superseded by D-01; would force a `k8s.io/*` downgrade to v0.35.1 if followed today.
- `apis/v1alpha2.TLSRoute` import: still present and functional in v1.6.1 (deprecated, not removed) but must not be used per D-02 — using it would require a second scheme install and duplicate every type-switch arm for no benefit.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| (none) | — | — | All claims in this research were verified directly against module source, repo source, or the Go module proxy (`proxy.golang.org`) during this session. No claim relies solely on training data or an unverified web search. |

**This table is empty:** all claims in this research were verified or cited — no user confirmation needed beyond what CONTEXT.md's own decisions already require (which are locked, not open).

## Open Questions

1. **Should the plan add a Gateway-presence gate as a new, un-decided design element, or treat it as an obvious bug-fix to the stale plan doc's code?**
   - What we know: CONTEXT.md's D-04/D-05 lock in RESTMapper-based gating for the three route kinds; the design doc's prose (Decision 4) asserts the same protection extends to the Gateway watch, but the actual code sketch does not implement it.
   - What's unclear: whether this rises to the level of a new locked decision requiring a discuss-phase note, or is simply a correctness fix within the existing D-04/D-05 intent (which already establishes "CRD-presence gating via RESTMapper" as the general mechanism, just not yet applied to this one watch clause).
   - Recommendation: treat it as a direct extension of D-04/D-05's existing intent (same mechanism, same rationale, just applied to the one spot the code sketch missed) rather than a new decision needing separate user sign-off — the "no manager panic on missing CRD" goal is already locked, this is closing a gap in achieving it, not a new tradeoff.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|--------------|-----------|---------|----------|
| Go toolchain | Build/test | ✓ | 1.26.5 | — |
| `sigs.k8s.io/gateway-api@v1.6.1` | Typed Gateway API client | ✓ (resolves from proxy.golang.org; not yet in `go.mod`) | v1.6.1 (latest) | — |
| `golangci-lint` | `task lint` | ✓ | 2.12.2 | — |
| `helm` CLI | Manual chart verification (`helm lint`/`helm template`) | ✓ | v4.2.3+g43e8b7f | Not wired into `task lint`/`task ci` — must be run manually per task, see "RBAC / Helm Wiring Specifics". |
| A real Kubernetes cluster with Gateway API CRDs installed | End-to-end manual verification of RESTMapper gating and IP resolution against a live Gateway | Not checked in this research (no cluster context available in this environment) | — | Unit tests with `fake.NewClientBuilder()` + a fake `RESTMapper` (per D-20) fully substitute for this at the phase-plan level; e2e verification against a real cluster is out of scope for `task test`/`task ci` and should be a manual UAT step, not a plan task. |

**Missing dependencies with no fallback:** none — the Gateway API dependency itself resolves cleanly from the public module proxy, verified above.

**Missing dependencies with fallback:** `helm` chart verification is not automated in CI; treat `helm lint`/`helm template` as manual verification commands within the relevant plan task rather than an automated gate.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go standard `testing` + `testify` (assert/require), controller-runtime `fake` client |
| Config file | none — plain `go test`, wrapped by `Taskfile.yml`'s `test`/`test:coverage:ci` tasks |
| Quick run command | `task test -- -run 'TestReconcile_HTTPRoute|TestResolveIP|TestHostnamesOf|TestExtractHostnames|TestRouteParentRefIndexFunc|TestMapGatewayToRoutes|TestGatewayKind' ./internal/operator/` |
| Full suite command | `task test:coverage:ci` (enforces ≥80% over `./internal/...`) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|--------------|
| GW-01 | Hostname extraction across HTTPRoute/GRPCRoute/TLSRoute, incl. wildcard/invalid/dup skip | unit | `task test -- -run 'TestHostnamesOf_AllKinds|TestExtractHostnames' ./internal/operator/` | ❌ Wave 0 — create `gateway_controller_test.go` |
| GW-01 | Create/update/delete diff against `host-ids` annotation; finalizer add/cleanup | unit | `task test -- -run 'TestReconcile_HTTPRoute' ./internal/operator/` | ❌ Wave 0 |
| GW-02 | IP resolution: parent hit, Hostname-type skipped, multiple parents, missing Gateway → fallback, no IP → requeue | unit | `task test -- -run 'TestResolveIP' ./internal/operator/` | ❌ Wave 0 |
| GW-02 | Gateway → route re-enqueue: parentRef index keys (incl. namespace defaulting), map function with `.WithIndex` | unit | `task test -- -run 'TestRouteParentRefIndexFunc|TestMapGatewayToRoutes' ./internal/operator/` | ❌ Wave 0 |
| GW-03 | Per-kind RESTMapper gating incl. all-absent case; Gateway-kind gating (new, per Pitfall 1) | unit | `task test -- -run 'TestGatewayKind' ./internal/operator/` | ❌ Wave 0 |
| GW-03 | RBAC/Helm rendering | manual | `helm lint charts/router-hosts-operator && helm template charts/router-hosts-operator --set gateway.enabled=true \| grep -- '--enable-gateway'` | manual-only — no automated chart test infra exists in this repo |

### Sampling Rate

- **Per task commit:** `task test -- -run '<relevant TestXxx pattern>' ./internal/operator/`
- **Per wave merge:** `task test:coverage:ci`
- **Phase gate:** `task ci` (lint + test) green before `/gsd-verify-work`; `helm lint`/`helm template` run manually since they are not part of `task ci`.

### Wave 0 Gaps

- [ ] `internal/operator/gateway_controller.go` — does not exist yet; all reconciler/helper code for this phase
- [ ] `internal/operator/gateway_controller_test.go` — does not exist yet; all unit tests for this phase, reusing `mockHostClient` from `hostmapping_controller_test.go` (same package)
- [ ] No new test framework/fixture installation needed — `testify` and `controller-runtime/pkg/client/fake` are already dependencies and already used identically by the two existing controller test files.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|-------------------|
| V2 Authentication | No | This phase adds no new authentication surface; the operator's existing mTLS gRPC client to the router-hosts server is unchanged. |
| V3 Session Management | No | N/A — no sessions involved. |
| V4 Access Control | Yes | Kubernetes RBAC (`ClusterRole`) is the access-control mechanism; this phase's RBAC grants `get;list;watch;update;patch` on route kinds and `get;list;watch` (read-only) on `gateways` — least-privilege for the finalizer/annotation write pattern, matching the existing IngressRoute rule shape exactly. |
| V5 Input Validation | Yes | `internal/validation.ValidateHostname` (existing) validates every extracted hostname before it becomes a DNS entry; wildcard hostnames are explicitly rejected (D-18) rather than passed through. |
| V6 Cryptography | No | No new cryptographic surface — the mTLS transport to the router-hosts server is unchanged and out of scope for this phase. |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|-----------------------|
| A route in namespace A references a `Gateway` in namespace B without a `ReferenceGrant`, and the operator's read-only `Get` on that Gateway leaks its `status.addresses` into a DNS entry the route's namespace didn't have a Gateway-mediated grant to see | Information Disclosure (mild) | Explicitly out of scope per CONTEXT.md's Deferred Ideas ("`ReferenceGrant` enforcement for cross-namespace `parentRefs`") — documented as a known, accepted simplification carried over unchanged from the design doc's Risks section. Not a regression introduced by this phase; do not add enforcement without a separate CONTEXT decision. |
| A malicious or misconfigured route sets a hostname that collides with an existing HostMapping/IngressRoute-derived entry, causing one controller's `DeleteHost` to remove another controller's entry | Tampering / Denial of Service | Prevented structurally: each entry's ownership is tracked per-object via the shared `host-ids` annotation on the object that created it (D-10); a Gateway-route controller only ever calls `DeleteHost` for IDs it itself recorded in its own object's annotation, never by hostname lookup across controllers. |
| A corrupt `host-ids` annotation (e.g. hand-edited by an operator) causes silent data loss (deleting live entries the annotation no longer references) | Tampering | D-14 requires: a corrupt annotation returns an error and requeues rather than proceeding with a partial/empty view — identical to the existing IngressRoute behavior (`getHostIDsAnnotation`'s `json.Unmarshal` error path). |

## Sources

### Primary (HIGH confidence)

- `sigs.k8s.io/gateway-api@v1.6.1` module source, read directly from the extracted tarball at `/private/tmp/claude-501/-Volumes-Code-github-com-fzymgc-house-router-hosts/91757d26-2f1a-47aa-b0b7-02c5ee26db82/scratchpad/gw/sigs.k8s.io/gateway-api@v1.6.1/` — `apis/v1/{tlsroute_types.go, httproute_types.go, grpcroute_types.go, shared_types.go, gateway_types.go, zz_generated.register.go}`, `apis/v1alpha2/tlsroute_types.go`, `go.mod`.
- `sigs.k8s.io/controller-runtime@v0.24.1` and `@v0.23.1` module source, read from `/Users/sean/go/pkg/mod/sigs.k8s.io/controller-runtime@{v0.24.1,v0.23.1}/` — `pkg/builder/controller.go`, `pkg/handler/enqueue_mapped.go`, `pkg/controller/controllerutil/controllerutil.go`, `pkg/client/fake/client.go`, `pkg/client/interfaces.go`.
- `k8s.io/apimachinery@v0.36.1` module source, read from `/Users/sean/go/pkg/mod/k8s.io/apimachinery@v0.36.1/` — `pkg/api/meta/{help.go, errors.go, restmapper.go}`.
- `proxy.golang.org/sigs.k8s.io/gateway-api/@latest` and `/@v/list` — HTTP responses fetched directly, 2026-07-25.
- This repository's own source: `internal/operator/{ingressroute_controller.go, hostmapping_controller.go, hostclient.go, ingressroute_controller_test.go, hostmapping_controller_test.go}`, `cmd/operator/main.go`, `charts/router-hosts-operator/{templates/clusterrole.yaml, templates/deployment.yaml, values.yaml}`, `Taskfile.yml`, `go.mod`.
- `.planning/phases/07-gateway-api-support/07-CONTEXT.md` (locked user decisions, D-01 through D-20).

### Secondary (MEDIUM confidence)

- `docs/plans/2026-06-07-gateway-api-support-design.md` — architecture of record; used as the baseline all findings above are diffed against.
- `docs/plans/2026-06-07-gateway-api-support-plan.md` — stale task-by-task plan; used only for its code sketches, cross-checked line-by-line against the current module sources above.

### Tertiary (LOW confidence)

- None — every non-trivial claim in this document was checked against a primary source during this session.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — dependency pin and API surface independently verified against the actual module source and the Go module proxy, not training data.
- Architecture: HIGH — reuses an already-shipped, already-tested pattern (IngressRoute controller) with one genuinely new mechanism (field indexer + Gateway watch), whose controller-runtime APIs were verified unchanged across the v0.23.1→v0.24.1 jump.
- Pitfalls: HIGH for the four cataloged here (each independently verified against source); MEDIUM for the possibility of an as-yet-undiscovered pitfall outside this research's explicit focus areas (e.g. multi-cluster/multi-namespace Gateway topologies were not stress-tested).

**Research date:** 2026-07-25
**Valid until:** 30 days (stable, GA Kubernetes API; the only fast-moving element — the gateway-api module's own release cadence — is pinned by D-01/D-03's build gate, which will surface any future drift immediately at `go get`/`go mod tidy` time).
