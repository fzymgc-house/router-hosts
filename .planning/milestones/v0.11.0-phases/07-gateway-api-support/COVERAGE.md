# API Coverage — Kubernetes Gateway API (`gateway.networking.k8s.io`, `sigs.k8s.io/gateway-api@v1.6.1`)

> Full coverage by default. Opt-outs are explicit, reasoned decisions.
> Produced at plan time for Phase 7 (detector: `api-coverage.cjs` → `detected: true`).

The capability surface below is the `apis/v1` type/field surface the operator
could consume, enumerated from the module source verified in `07-RESEARCH.md`
§ "Verified v1.6.1 API Surface".

| capability | decision | reason |
|---|---|---|
| `HTTPRoute` (`spec.hostnames`) | INTEGRATE | |
| `GRPCRoute` (`spec.hostnames`) | INTEGRATE | |
| `TLSRoute` (`spec.hostnames`) | INTEGRATE | |
| `CommonRouteSpec.parentRefs` (read, for IP resolution) | INTEGRATE | |
| `CommonRouteSpec.parentRefs` (field index + Gateway re-enqueue) | INTEGRATE | |
| `Gateway.status.addresses` — `IPAddressType` | INTEGRATE | |
| CRD presence discovery (RESTMapper gating per kind) | INTEGRATE | |
| Route finalizer + annotation write-back (`update`/`patch`) | INTEGRATE | |
| `Gateway.status.addresses` — `HostnameAddressType` | OPT-OUT | A CNAME target is not a host entry IP; D-15 skips it deliberately |
| `Gateway.status.addresses` — `NamedAddressType` | OPT-OUT | Implementation-specific opaque name; not resolvable to an A-record IP |
| `Gateway.spec.listeners[].hostname` as an entry source | OPT-OUT | Explicitly out of scope in the 2026-06-07 design and CONTEXT Deferred Ideas — usually wildcard or empty |
| `GatewayClass` | OPT-OUT | not needed — the operator consumes Gateway status, it is not a Gateway implementation |
| `TCPRoute` | OPT-OUT | L4, carries no hostnames — nothing to register (CONTEXT Deferred Ideas) |
| `UDPRoute` | OPT-OUT | L4, carries no hostnames — nothing to register (CONTEXT Deferred Ideas) |
| `ReferenceGrant` enforcement for cross-namespace `parentRefs` | OPT-OUT | Documented accepted simplification (CONTEXT Deferred Ideas); operator does a read-only `Get` and is not the Gateway controller |
| Route `status` conditions write-back (`RouteParentStatus`) | OPT-OUT | Separate UX phase (CONTEXT Deferred Ideas); would need `routes/status` RBAC not granted here |
| `spec.rules` (matches / filters / backendRefs) | OPT-OUT | Traffic-routing behavior, irrelevant to DNS entry creation |
| `BackendTLSPolicy` / policy attachment kinds | OPT-OUT | not a hostname source |
| `apis/v1alpha2` / `apis/v1alpha3` type surface | OPT-OUT | D-02 — all four consumed kinds graduated to `apis/v1` in v1.6.1; the alpha surface is deprecated |

**Opt-outs with no reason:** none.
**Second-integration check:** this is the first Gateway API integration in this
project; no prior integration's opt-outs were carried over.
