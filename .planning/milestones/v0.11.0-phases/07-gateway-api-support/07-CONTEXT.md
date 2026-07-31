# Phase 7: Gateway API Support - Context

**Gathered:** 2026-07-25
**Status:** Ready for planning

<domain>

## Phase Boundary

Add Gateway API support to the router-hosts Kubernetes operator (`cmd/operator`,
`internal/operator`): watch `HTTPRoute`, `GRPCRoute`, and `TLSRoute` as hostname
sources, resolve each route's IP from its parent `Gateway.status.addresses`, and
sync those hostnames to the router-hosts gRPC server as host entries — with the
same annotation + finalizer lifecycle the existing `IngressRoute` controller uses.
Ships with RBAC (ClusterRole + kubebuilder markers) and Helm chart wiring.

Delivers REQUIREMENTS.md **GW-01** (reconcile route hostnames), **GW-02** (IPs
from parent `Gateway.status.addresses`), **GW-03** (Helm/RBAC watch+list access).

**Not in this phase:** Kubernetes `Service` controller (Phase 8), hook
reliability/metrics (Phase 9), `Gateway.spec.listeners[].hostname` as an entry
source, `TCPRoute`/`UDPRoute`, `ReferenceGrant` enforcement, writing route
`status` conditions back to the cluster.

</domain>

<decisions>

## Implementation Decisions

### Dependency & Typed API Surface

- **D-01:** Pin `sigs.k8s.io/gateway-api` at **v1.6.1**, not the v1.5.1 named in
  the 2026-06-07 design doc. Verified read-only against the module proxy today:
  v1.6.1's `go.mod` requires `k8s.io/api`, `k8s.io/apimachinery`, and
  `k8s.io/client-go` at **v0.36.1** — an exact match for this repo's current
  pins — and `go 1.26.0` (repo is on 1.26.5). v1.5.1 requires v0.35.1 and would
  force a downgrade of the k8s libraries. The design doc's Dependency section is
  stale; **D-01 supersedes it**.
- **D-02:** Import **`sigs.k8s.io/gateway-api/apis/v1` only**. In v1.6.1
  `TLSRoute` has graduated to `apis/v1` and is marked
  `+kubebuilder:storageversion`; `apis/v1alpha2.TLSRoute` carries
  `+kubebuilder:deprecatedversion`. All three route kinds plus `Gateway` therefore
  come from one package. Consequence: a single `gatewayv1.Install(scheme)` call,
  one import, and no `v1alpha2`/`v1alpha3` surface anywhere in the operator. The
  design doc's "TLSRoute is experimental-channel `v1alpha2`" premise is stale;
  **D-02 supersedes it.** — **Reversibility:** costly — re-adding v1alpha2 later
  means a second scheme install, a second controller registration, a second RBAC
  rule set, and duplicated type-switch arms across `hostnamesOf`/`parentRefsOf`.
- **D-03:** Keep the design's **build-gate-first** sequencing: task 1 of the plan
  is `go get sigs.k8s.io/gateway-api@v1.6.1 && go mod tidy && task build`, green
  before any controller code is written. If `go mod tidy` proposes moving any
  `k8s.io/*` off v0.36.1, STOP and re-derive the pin rather than accepting the
  upgrade.

### CRD-Presence Gating

- **D-04:** Gate each route-kind controller on the **exact GVK the operator
  imports** (`gateway.networking.k8s.io/v1`, kind `HTTPRoute` / `GRPCRoute` /
  `TLSRoute`) via `mgr.GetRESTMapper().RESTMapping(gvk.GroupKind(), gvk.Version)`,
  as Decision 4 of the design describes. A kind whose mapping does not resolve
  gets no controller constructed — no typed informer, no manager panic.
- **D-05:** When a route kind's **GroupKind resolves but not at `v1`** (an older
  cluster still serving `TLSRoute` only at `v1alpha2`), skip that kind and log an
  actionable `Info` naming the required version — do **not** build a second
  v1alpha2 controller for compatibility. Rationale: keeps exactly one controller
  per kind and one API surface (D-02); the cluster-side fix is a CRD channel
  upgrade, which is the operator's documented prerequisite anyway.

### Enablement & Rollout

- **D-06:** Keep Gateway support **opt-in**: `--enable-gateway` flag on
  `cmd/operator` defaulting to `false`, surfaced as `gateway.enabled: false` in
  `charts/router-hosts-operator/values.yaml` and templated into the deployment
  args. Rationale: merely having Gateway API CRDs installed must not silently
  start writing router DNS entries. Per-kind RESTMapper gating (D-04) runs
  *inside* the enabled path, not instead of the flag.
- **D-07:** Reuse the existing **`--default-ingress-ip`** flag as the IP fallback
  rather than adding a gateway-specific one; update its help text, which currently
  reads "Default IP for hosts extracted from IngressRoutes"
  (`cmd/operator/main.go:44`).
- **D-08:** Document in `values.yaml` and the README that Gateway API CRDs are a
  **cluster prerequisite** — the chart does not bundle them.

### Ownership, Lifecycle & Write-Loop Safety

- **D-09:** Finalizer is **`router-hosts.fzymgc.house/gateway-cleanup`**, distinct
  from `ingressroute-cleanup` (`ingressroute_controller.go:29`) and
  `host-cleanup` (`hostmapping_controller.go:27`). Ownership is keyed on the
  **route**, never the Gateway — the Gateway is a read-only IP source and a
  secondary trigger only. — **Reversibility:** one-way — once deployed, live
  routes in user clusters carry this exact finalizer string; renaming it strands
  those finalizers and blocks route deletion until an operator manually patches
  every affected object.
- **D-10:** Reuse the existing **`hostIDsAnnotation`**
  (`router-hosts.fzymgc.house/host-ids`) as the `hostname → hostID` tracking map,
  shared with the IngressRoute controller. Safe because a given object is only
  ever one kind. — **Reversibility:** costly — changing the key later orphans the
  host IDs recorded on live route objects; recovery needs a migration pass that
  reads the old key and rewrites the new one before any reconcile deletes entries
  it can no longer see.
- **D-11:** Widen `getHostIDsAnnotation` / `setHostIDsAnnotation`
  (`ingressroute_controller.go:390`, `:410`) from `*unstructured.Unstructured` to
  `client.Object` so both controllers share them. Signature-only change; the
  bodies already call just `GetAnnotations`/`SetAnnotations`, and
  `*unstructured.Unstructured` still satisfies `client.Object`, so IngressRoute
  call sites compile and behave identically. Existing IngressRoute tests are the
  regression guard.
- **D-12:** Entry provenance: comment **`k8s-gateway:<namespace>/<name>`**; tags
  **`DefaultTags + ["gateway", "<kindname>"]`** (e.g.
  `["kubernetes", "gateway", "httproute"]`). Distinct from the IngressRoute
  controller's provenance so entries are attributable per source.
- **D-13:** **Skip the object `Update` when nothing changed** — if the recomputed
  `host-ids` map equals the existing annotation and the finalizer is already
  present, do not issue the write. Avoids one API round-trip per reconcile.
  This is an efficiency guard only: `UpdateHost` for already-tracked hostnames
  stays **unconditional**, because that is what propagates a changed Gateway IP
  without keeping extra state.
- **D-14:** Preserve the design's error semantics verbatim: per-host errors do not
  abort the batch, partial IDs are **always** persisted to the annotation, a
  corrupt `host-ids` annotation returns an error and requeues (never proceeds on a
  partial view), all fallible calls wrapped with `oops.Wrapf`, requeue via the
  existing `requeueDelayShort` / `requeueDelayLong` constants, no
  `log.Fatal`/`os.Exit`.

### IP Resolution

- **D-15:** `resolveIP` walks `spec.parentRefs` in declaration order, `Get`s each
  referenced `Gateway` (parent namespace defaults to the route's namespace), and
  returns the **first `IPAddress`-typed** `status.addresses[]` value found.
  `Hostname`-typed addresses are skipped — a CNAME target is not a host entry IP.
  One IP per hostname (the host model is `hostname → hostID`).
- **D-16:** If no parent yields an IP, fall back to `--default-ingress-ip`. If that
  is also empty, **requeue short and create nothing** — never write an IP-less
  entry. A `Get` failure that is not `NotFound` is logged and the walk continues to
  the next parentRef.
- **D-17:** Re-resolution on Gateway change uses the design's Decision 2a
  mechanism: a per-kind field index `spec.parentRefs.gateway` emitting
  `"<parentNamespace>/<parentName>"`, plus
  `Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(...))` on each
  route-kind builder. Tests for the map function MUST build the fake client with
  `.WithIndex(...)` — a bare builder makes a field-selector `List` silently return
  zero results (this is called out in the design's Testing section and is the
  single easiest way to write a test that passes while proving nothing).

### Hostname Filtering

- **D-18:** Skip `*`-prefixed wildcard hostnames (`*.example.com` cannot be a
  concrete entry), de-duplicate, and validate each remaining name with
  `internal/validation.ValidateHostname`. Invalid names are logged and skipped —
  never fatal, never abort the batch.
- **D-19:** Non-FQDN (dot-less) hostnames are **warned about but accepted**,
  matching current HostMapping/IngressRoute behavior. Under locked ADR
  `router-hosts-bzg` a bare name becomes `local-zone: "<name>." static`, making
  unbound authoritative for a whole pseudo-TLD — a documented, project-wide
  footgun that PROJECT.md explicitly records as "not enforced". Enforcing it in
  only this one controller would make the operator inconsistent with itself; see
  Deferred Ideas for enforcing it project-wide.

### Testing

- **D-20:** `internal/operator/gateway_controller_test.go` with a fake client on
  the gateway-api scheme. Reuse the existing `mockHostClient`
  (`hostmapping_controller_test.go`, same package) rather than adding a second
  mock. Coverage must hold ≥80% (`task test:coverage:ci`). Required cases:
  hostname extraction incl. wildcard/invalid/dup skips; IP resolution
  (parent Gateway hit, `Hostname`-type skipped, multiple parents, missing Gateway
  → flag fallback, no IP → requeue); finalizer add and cleanup-on-delete;
  create/update/delete diff against the annotation; parentRef index keys incl.
  namespace defaulting; Gateway → route map function (with `.WithIndex`); and
  per-kind RESTMapper gating including the all-absent case.

### Claude's Discretion

Auto-resolved under `--auto`; every question took the recommended option. The
planner has latitude on: task ordering and granularity beyond the D-03 build gate;
whether `hostnamesOf`/`parentRefsOf` stay two type-switches or collapse into one
helper returning both; exact log message wording; whether the kinds table is a
package-level func or a var. None of these change observable behavior.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase design (authoritative for architecture)

- `docs/plans/2026-06-07-gateway-api-support-design.md` — the design of record:
  scope boundaries, Decision 1 (typed client over unstructured), Decision 2
  (one controller per route kind sharing a `syncRoute` core, `newObject` factory),
  Decision 2a (parentRefs field indexer + Gateway watch), Decision 3 (IP
  resolution), Decision 4 (RESTMapper CRD gating), reconcile flow, error handling,
  RBAC/Helm surface, testing matrix.
  **Two sections are superseded by this CONTEXT and MUST NOT be followed as
  written:** the *Dependency* section (v1.5.1 / `k8s.io/*` v0.35.1 → see D-01) and
  every reference to `TLSRoute` living in `apis/v1alpha2` (→ see D-02).
- `docs/plans/2026-06-07-gateway-api-support-plan.md` — the earlier task-by-task
  implementation plan. **Reference only, do not execute as-is.** Its code sketches
  and grounded-facts table are useful, but it is stale in three ways: it pins
  v1.5.1 and `k8s.io/*` v0.35.1 / controller-runtime v0.23.1 (repo is at v0.36.1 /
  v0.24.1), it imports `apis/v1alpha2` for TLSRoute, and every commit step uses
  `jj commit` — this repo is **native git only**. The GSD planner writes its own
  PLAN.md.

### Project constraints (locked)

- `.planning/PROJECT.md` § Locked Decisions — ADR `router-hosts-bzg` (unbound
  per-name `static` zones) is what makes D-19's dot-less-hostname warning matter;
  ADRs `router-hosts-v5b` / `-vl8` / `-4w2` govern compaction and do not constrain
  this phase.
- `.planning/PROJECT.md` § Constraints — `CGO_ENABLED=0`, SQLite-only,
  single-goroutine `WriteQueue` (new write paths must be retry-safe/idempotent),
  mTLS-only with no `InsecureSkipVerify`, `samber/oops` errors, ≥80% coverage via
  `task test` (never raw `go test`).
- `.planning/REQUIREMENTS.md` § Gateway API Support — GW-01, GW-02, GW-03.
- `CLAUDE.md` — commit conventions (Conventional Commits, scope `operator`),
  `task`-first build/test commands, native-git workflow.

### Existing implementation to mirror

- `internal/operator/ingressroute_controller.go` — the lifecycle being mirrored:
  `hostIDsAnnotation` const (`:29` area), finalizer handling (`:107`),
  `getHostIDsAnnotation` (`:390`), `setHostIDsAnnotation` (`:410`),
  `SetupWithManager` (`:445`).
- `internal/operator/hostmapping_controller.go` — source of the reusable
  `requeueDelayShort` / `requeueDelayLong` constants (`:28`, `:29`) and the
  predicate pattern at `:433`.
- `internal/operator/hostclient.go` — the `HostClient` interface the controller
  calls (`AddHost` / `UpdateHost` / `DeleteHost`).
- `cmd/operator/main.go` — scheme registration (`:56`, `:60`), flag block
  (`:37`–`:45`), controller wiring (`:102`, `:114`).
- `charts/router-hosts-operator/templates/clusterrole.yaml`,
  `.../templates/deployment.yaml`, `.../values.yaml` — the RBAC + chart surface.

### Upstream API

- `sigs.k8s.io/gateway-api@v1.6.1/apis/v1` — `HTTPRoute`, `GRPCRoute`, `TLSRoute`,
  `Gateway` (+ `…List`); `Install`/`AddToScheme` and `SchemeGroupVersion` in
  `zz_generated.register.go`; `GatewayStatusAddress` (`gateway_types.go`);
  `IPAddressType` / `HostnameAddressType` consts (`shared_types.go`).

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **`getHostIDsAnnotation` / `setHostIDsAnnotation`**
  (`ingressroute_controller.go:390`, `:410`) — the whole `hostname → hostID`
  tracking mechanism, reusable after the D-11 `client.Object` widening.
- **`requeueDelayShort` (5s) / `requeueDelayLong` (30s)**
  (`hostmapping_controller.go:28`) — package-level, already in scope.
- **`hostIDsAnnotation`** const — shared annotation key (D-10).
- **`mockHostClient`** with `addHostFn`/`updateHostFn`/`deleteHostFn`/`getHostFn`
  (`hostmapping_controller_test.go`) — same package, reuse directly; do not write
  a second mock.
- **`internal/validation.ValidateHostname`** — the hostname validator (D-18).
- **`HostClient` interface** (`hostclient.go`) — already the seam between
  controllers and the gRPC client, so the new controller needs no new plumbing.

### Established Patterns

- **Annotation + cleanup-finalizer lifecycle** — both existing controllers track
  created entries on the watched object and delete them in a finalizer. The new
  controller follows this exactly (D-09, D-10).
- **Per-host errors never abort the batch; partial IDs always persisted** —
  established in `IngressRoute`, carried forward (D-14).
- **`unstructured` is used *only* because Traefik's CRD types are not cleanly
  importable** — that constraint does not apply to `sigs.k8s.io/gateway-api`, which
  is a first-class versioned module. Hence typed client here (design Decision 1).
- **Existing `SetupWithManager` uses `WatchesRawSource` + `source.Kind`**
  (`ingressroute_controller.go:445`) because it watches unstructured objects. The
  Gateway controllers use the plain typed `For(...)` + `Watches(...)` builder
  instead — a deliberate divergence, not an inconsistency.
- **Three distinct finalizers, one per controller** — `host-cleanup`,
  `ingressroute-cleanup`, and now `gateway-cleanup`.

### Integration Points

- `cmd/operator/main.go` — add `gatewayv1.Install(scheme)`, the
  `--enable-gateway` flag, and a `SetupGatewayControllers(...)` call alongside the
  two existing `SetupWithManager` registrations.
- `charts/router-hosts-operator/templates/clusterrole.yaml` — new
  `gateway.networking.k8s.io` rules: `httproutes;grpcroutes;tlsroutes` with
  `get;list;watch;update;patch` (writes needed for the finalizer + annotation),
  `gateways` with `get;list;watch` (read-only IP source).
- `charts/router-hosts-operator/values.yaml` + `templates/deployment.yaml` —
  `gateway.enabled` toggle templating the `--enable-gateway` arg.
- Kubebuilder RBAC markers on the reconciler, mirroring the ClusterRole.

### Verified Drift From the Design Doc

Checked against the working tree and the module proxy on 2026-07-25:

| Design doc assumption | Actual |
|---|---|
| `k8s.io/*` v0.35.1, controller-runtime v0.23.1 | **v0.36.1**, **v0.24.1** (`go.mod:24-28`) |
| gateway-api v1.5.1 is the aligned pin | v1.5.1 requires k8s v0.35.1; **v1.6.1** requires v0.36.1 |
| `TLSRoute` is `apis/v1alpha2`, experimental-only | **`apis/v1`** + `storageversion` in v1.6.1; v1alpha2 deprecated |
| IngressRoute ClusterRole already has `update;patch` | Unchanged and still true — not a task |

</code_context>

<specifics>

## Specific Ideas

- The 2026-06-07 design doc is unusually complete — it is a genuine design of
  record, not a sketch. Planning should treat it as the architecture spec and
  spend its effort on the two superseded sections (D-01, D-02) and on the RBAC/
  chart/docs tail, not on re-deriving the controller shape.
- The `.WithIndex(...)` requirement for the Gateway map-function test is called out
  explicitly because the failure mode is silent: a bare fake-client builder makes a
  field-selector `List` return zero results, so the test passes while proving
  nothing.
- Bead reference for grounding traces: `rh-9uc`.

</specifics>

<deferred>

## Deferred Ideas

- **Enforce FQDN-only hostnames project-wide.** D-19 accepts dot-less hostnames
  with a warning for consistency with the existing controllers, but ADR
  `router-hosts-bzg` makes a bare name authoritative for a whole pseudo-TLD in
  unbound output. Enforcing (or at least gating behind a flag) belongs in a
  cross-cutting validation change, not in this controller.
- **`Gateway.spec.listeners[].hostname` as an entry source.** Explicitly out of
  scope in the design — usually a wildcard or empty. Revisit only if a concrete
  use case appears.
- **`ReferenceGrant` enforcement for cross-namespace `parentRefs`.** The controller
  reads referenced Gateways directly (read-only `Get`) and is not acting as the
  Gateway controller. Documented simplification; a security-hardening follow-up
  could revisit it.
- **Writing route `status` conditions back to the cluster.** Would make the
  operator observable from `kubectl describe httproute`; a separate UX phase.
- **`TCPRoute` / `UDPRoute`.** L4, no hostnames — nothing to register.
- **Refreshing the two 2026-06-07 docs in place.** They stay as the historical
  design of record; this CONTEXT records the supersessions rather than rewriting
  them.

</deferred>

---

*Phase: 7-Gateway API Support*
*Context gathered: 2026-07-25*
