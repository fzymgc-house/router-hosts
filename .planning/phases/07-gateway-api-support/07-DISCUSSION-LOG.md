# Phase 7: Gateway API Support - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-25
**Phase:** 7-gateway-api-support
**Mode:** `--auto` (all gray areas auto-selected; every question resolved to the recommended option, no user prompts)
**Areas discussed:** Dependency & typed API surface, CRD-presence gating, Enablement & rollout, Ownership & write-loop safety, IP resolution, Hostname filtering

---

## Dependency & Typed API Surface

| Option | Description | Selected |
|--------|-------------|----------|
| Pin v1.6.1, import `apis/v1` only | Matches repo's `k8s.io/*` v0.36.1 exactly; TLSRoute has graduated to `apis/v1` in v1.6.x, so one package covers all three route kinds + Gateway | ✓ |
| Pin v1.5.1 as the design doc says | Requires `k8s.io/*` v0.35.1 — would downgrade the repo's pinned k8s libraries | |
| Pin v1.6.1 but keep `apis/v1alpha2` TLSRoute | Preserves compatibility with clusters serving only the older experimental TLSRoute, at the cost of a second scheme install, import, and controller | |

**Selection:** Pin v1.6.1, import `apis/v1` only (recommended default).
**Notes:** Verified read-only against `proxy.golang.org` on 2026-07-25 — v1.6.1's `go.mod` requires `k8s.io/api`/`apimachinery`/`client-go` at v0.36.1 and `go 1.26.0`. Inspected the v1.6.1 module contents: `apis/v1/tlsroute_types.go` carries `+kubebuilder:storageversion`, `apis/v1alpha2/tlsroute_types.go` carries `+kubebuilder:deprecatedversion`. Both facts contradict the 2026-06-07 design doc, which was written against an older dependency floor. Recorded in CONTEXT.md as D-01/D-02 explicitly superseding those design sections.

---

## CRD-Presence Gating

| Option | Description | Selected |
|--------|-------------|----------|
| Gate on the exact imported GVK (`.../v1`) | RESTMapper check per kind; skip + log when the mapping does not resolve at v1 | ✓ |
| Gate on GroupKind at any version | Would build a v1 controller against a cluster serving only v1alpha2 — informer would fail at runtime | |
| Dual-version controllers per kind | Supports old and new clusters, doubles the controller and RBAC surface | |

**Selection:** Gate on the exact imported GVK; skip and log an actionable message otherwise.
**Notes:** Keeps exactly one controller per kind and one API surface. The cluster-side remedy (upgrade the Gateway API CRD channel) is already a documented prerequisite of the chart.

---

## Enablement & Rollout

| Option | Description | Selected |
|--------|-------------|----------|
| Opt-in `--enable-gateway` flag, default false | Chart exposes `gateway.enabled: false`; per-kind CRD gating runs inside the enabled path | ✓ |
| Auto-enable whenever Gateway API CRDs are detected | Zero-config, but a cluster that merely has the CRDs installed would start writing router DNS entries unannounced | |
| Always on, rely solely on CRD gating | Same surprise-writes problem, with no operator-side kill switch | |

**Selection:** Opt-in flag + chart toggle (matches the design doc).
**Notes:** Also reuses the existing `--default-ingress-ip` flag rather than adding a gateway-specific one; its help text needs updating since it currently names IngressRoutes only.

---

## Ownership & Write-Loop Safety

| Option | Description | Selected |
|--------|-------------|----------|
| Mirror IngressRoute lifecycle + skip no-op annotation writes | Route-keyed ownership, dedicated `gateway-cleanup` finalizer, shared `host-ids` annotation; skip the `Update` call when nothing changed | ✓ |
| Mirror IngressRoute exactly, unconditional `Update` | Simplest and proven in-tree, but issues an API write on every reconcile | |
| Track state in a separate ConfigMap instead of an annotation | Avoids writing to watched objects entirely, at the cost of a second source of truth and its own GC problem | |

**Selection:** Mirror the lifecycle, add the no-op write guard.
**Notes:** `UpdateHost` for already-tracked hostnames stays unconditional — that is the mechanism by which a changed Gateway IP propagates without extra stored state. The guard applies only to the Kubernetes object write. Finalizer naming flagged as a one-way decision: once deployed, live routes carry the string, and renaming it strands finalizers.

---

## IP Resolution

| Option | Description | Selected |
|--------|-------------|----------|
| First `IPAddress`-typed address across parentRefs, then flag fallback, else requeue | Design Decision 3 verbatim; never writes an IP-less entry | ✓ |
| Prefer a specific parentRef (e.g. same-namespace first) | More predictable with multi-parent routes, but invents policy the Gateway API does not define | |
| Accept `Hostname`-typed addresses too | A CNAME target is not usable as a host entry IP | |

**Selection:** Design Decision 3 as written.
**Notes:** Re-resolution on Gateway change uses the parentRefs field indexer + `Watches` map-func (design Decision 2a). Carried the design's warning forward: the map-func test must build its fake client with `.WithIndex(...)`, or the field-selector `List` silently returns zero results and the test proves nothing.

---

## Hostname Filtering

| Option | Description | Selected |
|--------|-------------|----------|
| Skip wildcards + invalid; warn-but-accept dot-less names | Consistent with HostMapping/IngressRoute behavior today | ✓ |
| Additionally reject dot-less (non-FQDN) hostnames | Closes the pseudo-TLD footgun from ADR `router-hosts-bzg`, but makes this one controller stricter than the other two | |
| Accept wildcards by stripping the `*.` prefix | Would silently register the apex as a concrete entry the user never asked for | |

**Selection:** Skip wildcards and invalid names; warn-but-accept non-FQDN.
**Notes:** PROJECT.md explicitly records the FQDN requirement as "documented footgun, not enforced". Enforcing it in a single controller would make the operator inconsistent with itself — routed to Deferred Ideas as a cross-cutting validation change.

---

## Claude's Discretion

Every area was auto-resolved under `--auto`, each taking the recommended option. Latitude explicitly left to the planner:

- Task ordering and granularity beyond the D-03 dependency build gate
- Whether `hostnamesOf` / `parentRefsOf` remain two type-switches or collapse into one helper
- Log message wording
- Whether the route-kinds table is a package-level func or a var

None of these change observable behavior.

## Deferred Ideas

- Enforce FQDN-only hostnames project-wide (cross-cutting validation change)
- `Gateway.spec.listeners[].hostname` as an entry source
- `ReferenceGrant` enforcement for cross-namespace `parentRefs`
- Writing route `status` conditions back to the cluster
- `TCPRoute` / `UDPRoute` (L4, no hostnames)
- Refreshing the two 2026-06-07 design/plan docs in place rather than recording supersessions here
