# Kubernetes Gateway API Support Design

**Status:** Draft
**Date:** 2026-06-07
**Bead:** rh-9uc
**Author:** Sean Brandt (with Claude)

## Summary

Add a third controller to the router-hosts operator (`cmd/operator`) that watches
Kubernetes Gateway API resources and syncs route hostnames to the router-hosts
gRPC server. It mirrors the established lifecycle used by the existing
`IngressRoute` controller — a `host-ids` annotation tracks `hostname → hostID`
mappings and a cleanup finalizer removes entries on deletion — while taking
advantage of Gateway API's typed client and its real assigned IP addresses
(`Gateway.status.addresses`).

## Motivation

The operator already automates DNS host registration for Traefik `IngressRoute`
and a custom `HostMapping` CRD. The Kubernetes Gateway API
(`gateway.networking.k8s.io`) is the vendor-neutral, GA successor to Ingress and
is increasingly the way services expose hostnames. Supporting it lets the
operator register host entries for any Gateway-API-conformant ingress
implementation without per-vendor parsing.

Gateway API also improves on the IngressRoute path in two concrete ways:

1. **Hostnames are structured.** Routes carry `spec.hostnames []string` directly,
   so there is no Traefik-style ``Host(`...`)`` match-rule regex parsing.
2. **Real IPs are available.** A `Gateway`'s `status.addresses[]` contains the
   actual assigned address(es), so entries can point at the true ingress IP
   instead of a statically configured guess.

## Scope

### In scope

- A `GatewayRouteReconciler` watching `HTTPRoute`, `GRPCRoute`, and `TLSRoute`
  as hostname sources.
- Watching `Gateway` as an **IP source only** (`status.addresses`), resolved per
  route via `spec.parentRefs`.
- Typed `sigs.k8s.io/gateway-api` client + scheme registration.
- CRD-presence gating so missing route kinds (notably the experimental
  `TLSRoute`) do not crash the manager.
- RBAC (`ClusterRole` + kubebuilder markers) and Helm chart wiring.
- Unit tests with ≥80% coverage.

### Out of scope

- **Gateway listener hostnames as entries.** `Gateway.spec.listeners[].hostname`
  is frequently a wildcard (`*.example.com`) or empty, which cannot become a
  concrete host entry. Gateways are consulted for IPs, not hostnames.
- `TCPRoute` / `UDPRoute` — L4, no hostnames.
- `ReferenceGrant` enforcement for cross-namespace `parentRefs` (see Risks).
- Writing route `status` conditions back to the cluster.

## Design Decisions

### 1. Typed client over unstructured

The `IngressRoute` controller uses `unstructured` specifically to avoid a typed
Traefik dependency — Traefik's CRD types are not a clean importable Go module.
That reasoning does **not** transfer to Gateway API: `sigs.k8s.io/gateway-api`
is a first-class, versioned module built to be imported. A typed client gives
`route.Spec.Hostnames` and `gw.Status.Addresses` with compile-time safety across
all the route kinds, which materially reduces error-prone `unstructured.Nested*`
navigation when juggling three route kinds plus Gateway.

### 2. One controller per route kind, sharing a reconcile core

Each enabled route kind (`HTTPRoute`, `GRPCRoute`, `TLSRoute`) gets its **own**
controller built with `For(&typedObject{})`, all sharing a single generic
`syncRoute` core. This is the idiomatic controller-runtime approach for watching
several distinct typed kinds, and it resolves two problems a single
"try-every-GVK" reconciler would create:

- **Unambiguous fetch.** A `ctrl.Request` carries only a `NamespacedName`, no
  type — but each controller instance is bound to **one** route kind, so the type
  is fixed per instance, not guessed per request. The struct carries a
  `newObject func() client.Object` factory; `Reconcile` allocates `r.newObject()`
  and does a single typed `Get`. There is no per-request type switching and no
  unstructured `SetGroupVersionKind` try-fallback (that pattern only existed for
  `IngressRoute`/`IngressRouteTCP` because it used `unstructured`). The one place
  a concrete type is examined is the small `hostnamesOf(client.Object)` helper,
  which type-switches over the three route types to read `Spec.Hostnames` (each
  is a distinct Go struct but all expose a `[]Hostname` field).
- **Clean CRD gating.** A kind whose CRD is absent simply has no controller
  constructed (Decision 4). If zero route CRDs exist, zero controllers are built
  — `NewControllerManagedBy` is never called with an empty watch set.

The shared core operates on `client.Object` (all route types embed
`metav1.ObjectMeta`, so finalizer helpers via `controllerutil` and
`GetAnnotations`/`SetAnnotations` work uniformly).

Ownership is keyed on **routes**, not Gateways: a route carries the finalizer and
the `host-ids` annotation, so there is a single owner per entry and no split-brain.

### 2a. Gateway → route re-enqueue mechanism

A `Gateway`'s `status.addresses` can change after a route is already reconciled,
so each route-kind controller must re-reconcile its routes when a referenced
Gateway changes. The mechanism (set up in `SetupWithManager`):

1. **Field indexer.** Register a field index per route kind on
   `mgr.GetFieldIndexer()` keyed `"spec.parentRefs.gateway"`, whose index func
   emits one value per `parentRef` formatted `"<parentNamespace>/<parentName>"`
   (parent namespace defaults to the route's namespace).
2. **Gateway watch.** Add
   `Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(mapFn))` to
   each route-kind builder. `mapFn` allocates the list via `r.newList()`, does a
   `List` of that controller's route kind filtered by the field selector
   `"spec.parentRefs.gateway" == "<gwNs>/<gwName>"`, and returns a
   `reconcile.Request` per matching route.

This keeps the Gateway purely a secondary trigger — it never owns entries; it
only causes the owning routes to recompute their IP.

### 3. IP resolution: parent Gateway, then flag fallback

`resolveIP(route)` walks `spec.parentRefs`, `Get`s each referenced `Gateway`
(namespace defaults to the route's namespace), and selects the first
`status.addresses[]` entry of type `IPAddress` from a parent. If no parent yields
an IP, it falls back to the `--default-ingress-ip` flag. If neither yields an IP,
the reconcile requeues (short) and logs, rather than creating IP-less entries.
One IP per hostname is selected (the host model is `hostname → hostID`).

### 4. CRD-presence gating via RESTMapper

`HTTPRoute`, `GRPCRoute`, and `Gateway` are standard-channel resources;
`TLSRoute` is experimental-channel and frequently absent. A typed informer for an
unregistered CRD crashes the manager at startup. Before constructing each
route-kind controller, `SetupGatewayControllers(mgr, ...)` queries the manager's
`RESTMapper` (`RESTMapping(gvk.GroupKind(), gvk.Version)`) for that kind; on
`meta.NoKindMatchError` the kind is skipped (logged at info), otherwise its
controller is built. The result:

- Each present route kind → one controller (per Decision 2).
- An absent kind → no controller, no panic.
- Zero route kinds present → zero controllers built; the manager starts with the
  other operator controllers unaffected. The Gateway watch lives *inside* each
  route-kind controller, so it too is absent when no routes exist (and a Gateway
  with no routes has nothing to enqueue anyway).

The Gateway kind itself is also RESTMapper-checked; if Gateways are absent the
route controllers still run with `--default-ingress-ip` as the sole IP source.

## Architecture

New file `internal/operator/gateway_controller.go` defining `GatewayRouteReconciler`
and a `SetupGatewayControllers` helper, registered in `cmd/operator/main.go`
alongside `HostMappingReconciler` and `IngressRouteReconciler`. The gateway-api
scheme is installed in `main.go`.

```text
   HTTPRoute  ─▶ controller(HTTPRoute) ─┐
   GRPCRoute  ─▶ controller(GRPCRoute) ─┼─▶ shared syncRoute core ─┐
   TLSRoute   ─▶ controller(TLSRoute)  ─┘   (resolveIP, diff, etc.) │
                      ▲                                             │
   Gateway ──────────┘  (Watches + parentRefs index re-enqueues     │
   (status.addresses)    the owning routes of a changed Gateway)    │
                                       AddHost/UpdateHost/DeleteHost │
                                                                     ▼
                                              router-hosts gRPC server (mTLS)
```

Each route kind has its own controller (Decision 2); all delegate to one
`syncRoute(ctx, obj client.Object, hostnames []string)` core. The struct:

```go
type GatewayRouteReconciler struct {
    client.Client
    HostClient  HostClient            // shared gRPC host client
    Log         *slog.Logger
    KindName    string                // "httproute" | "grpcroute" | "tlsroute" (logs/tags)
    newObject   func() client.Object  // allocates this instance's typed route
    newList     func() client.ObjectList // for the Gateway map-func List
    DefaultIP   string                // --default-ingress-ip fallback
    DefaultTags []string              // e.g. {"kubernetes"}
}
```

The struct is instantiated once per enabled route kind with the matching
`newObject`/`newList`/`KindName`; all instances share the same `Reconcile` and
`syncRoute` methods.

Annotation access **generalizes the two existing IngressRoute helpers** rather
than adding same-named duplicates (Go forbids two package-level funcs with one
name). Widen their `obj` parameter from `*unstructured.Unstructured` to
`client.Object`: the bodies only call `GetAnnotations`/`SetAnnotations`, which
`client.Object` already provides, and `*unstructured.Unstructured` still
satisfies `client.Object`, so the existing IngressRoute call sites compile
unchanged. This is a type-widening refactor with zero behavioral change — the
regression surface is a recompile, covered by the existing IngressRoute tests.

### Reconcile flow

1. **Fetch** — `obj := r.newObject()` then a single typed `Get`;
   `client.IgnoreNotFound` on miss. No GVK try-fallback.
2. **Deletion** (`DeletionTimestamp != nil`): delete all tracked host IDs, then
   remove the finalizer.
3. **Finalizer**: if absent, add `router-hosts.fzymgc.house/gateway-cleanup` and
   return (next reconcile sees the fresh object).
4. **Upsert**:
   - `extractHostnames(route)` — the validation wrapper: calls the raw
     `hostnamesOf(obj)` type-switch (Decision 2) to get `[]string`, then validates
     each via `internal/validation.ValidateHostname` and skips entries beginning
     with `*` (wildcards such as `*.example.com`) and invalids (logged, not
     fatal). `hostnamesOf` = raw read; `extractHostnames` = filtered result.
   - `resolveIP(route)` — per Decision 3.
   - Diff against the `host-ids` annotation (same algorithm as `IngressRoute`):
     create new hostnames, `UpdateHost` existing ones (so an IP change
     propagates), delete hostnames no longer present.
   - Comment: `k8s-gateway:<namespace>/<name>`.
   - Tags: `DefaultTags + ["gateway", "<routekind>"]`.
   - Persist the `host-ids` annotation (always, including partial IDs) and
     `Update` the route.

### Shared constants

Reuses `requeueDelayShort` / `requeueDelayLong` and the `hostIDsAnnotation`
constant already defined in the `operator` package. The annotation key
(`router-hosts.fzymgc.house/host-ids`) is shared with `IngressRoute`; since a
given object is only ever one kind, there is no collision.

## RBAC & Helm

- **`charts/router-hosts-operator/templates/clusterrole.yaml`**: add
  `gateway.networking.k8s.io` rules — `httproutes`, `grpcroutes`, `tlsroutes`
  with `get;list;watch;update;patch` (the finalizer + annotation require writes),
  and `gateways` with `get;list;watch`.
- **Kubebuilder markers** on `GatewayRouteReconciler` mirroring the ClusterRole.
- **`values.yaml`**: a `gateway.enabled` toggle (and optional per-kind list).
  Document that Gateway API CRDs are a cluster prerequisite, not bundled by this
  chart.
- **`cmd/operator/main.go`**: register the gateway-api scheme, add an
  `--enable-gateway` flag (default driven by the chart), reuse
  `--default-ingress-ip` as the IP fallback, and call `SetupGatewayControllers`.

#### Note: IngressRoute ClusterRole drift already resolved upstream

An earlier draft of this spec called for a separate commit to add `update;patch`
to the `ingressroutes`/`ingressroutetcps` ClusterRole rule (the controller's
finalizer/annotation writes need it). As of the v0.10.0 chart modernization
(PR #296, "migrate Helm chart from Rust to Go operator"), the ClusterRole already
grants `get;list;watch;update;patch` for those resources, so no fix is needed —
this item is **resolved** and is not part of the Gateway plan.

## Error Handling

Mirrors the `IngressRoute` controller:

- Per-host errors do not abort the batch; partial IDs are always persisted to the
  annotation so nothing is orphaned.
- Failures requeue with `requeueDelayShort` / `requeueDelayLong`.
- A corrupt `host-ids` annotation returns an error and requeues (never silently
  proceeds with an incomplete view).
- All fallible operations are wrapped with `oops.Wrapf`.
- No `log.Fatal` / `os.Exit` in the controller.

## Testing

`internal/operator/gateway_controller_test.go` using a fake client built on the
gateway-api scheme:

- Hostname extraction, including wildcard (`*`-prefixed) and invalid-hostname
  skips.
- IP resolution: parent Gateway `status.addresses` (type `IPAddress` chosen,
  `Hostname`-type skipped), multiple parents, missing Gateway → flag fallback,
  no IP available → requeue.
- Finalizer add and cleanup-on-delete.
- Create / update / delete diff against the annotation.
- **Gateway → route re-enqueue**: the parentRefs index func emits the expected
  `"<ns>/<name>"` keys (incl. default-namespace parentRefs); the Gateway map
  function returns a `reconcile.Request` for each route referencing a changed
  Gateway and none for unrelated Gateways. The map-func test MUST build its fake
  client with `fake.NewClientBuilder().WithIndex(obj, "spec.parentRefs.gateway",
  indexFn)` — a bare builder (as in `ingressroute_controller_test.go`) makes a
  field-selector `List` silently return zero results.
- **Per-kind gating**: `SetupGatewayControllers` with a fake `RESTMapper`
  constructs a controller only for kinds whose mapping resolves, and builds none
  (without error) when all route kinds are absent.

Coverage MUST stay ≥80% (`task test:coverage:ci`).

## Dependency

Pin **`sigs.k8s.io/gateway-api v1.5.1`**. Its `go.mod` requires
`k8s.io/apimachinery`, `k8s.io/api`, and `k8s.io/client-go` at **v0.35.1** —
an exact match with this repo's pinned versions — and `go 1.25` (repo is on
1.26). Verified read-only against the module proxy
(`proxy.golang.org/sigs.k8s.io/gateway-api/@v/v1.5.1.mod`); the plan phase
confirms with `go get sigs.k8s.io/gateway-api@v1.5.1` + `task build`. Typed
imports: `sigs.k8s.io/gateway-api/apis/v1` (HTTPRoute, GRPCRoute, Gateway) and
`.../apis/v1alpha2` (TLSRoute).

The implementation plan's **first task** is an explicit pass/fail gate:
`go get sigs.k8s.io/gateway-api@v1.5.1`, `go mod tidy`, `task build` — all green
before any controller code is written. If the version does not resolve cleanly
against the pinned k8s libs, stop and revisit before proceeding.

## Risks & Open Questions

- **Cross-namespace `parentRefs` without `ReferenceGrant`.** For IP resolution
  the controller reads the referenced Gateway directly (read-only `Get`). It does
  not enforce `ReferenceGrant`, since it is not acting as the Gateway controller.
  Documented as a known simplification.

## References

- Grounding traces recorded on bead `rh-9uc` (probe / context7 / chart).
- Existing pattern: `internal/operator/ingressroute_controller.go`.
- Gateway API: `sigs.k8s.io/gateway-api`, `gateway.networking.k8s.io`.
