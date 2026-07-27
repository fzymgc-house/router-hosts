# API Coverage — Kubernetes core/v1 `Service` (`k8s.io/api/core/v1@v0.36.1`)

> Full coverage by default. Opt-outs are explicit, reasoned decisions.
> Produced at plan time for Phase 8 (detector: `api-coverage.cjs` → `detected: true`, signal: noun `api`).

The capability surface below is the core/v1 `Service` type/field surface — plus
the core `events` resource this phase newly writes to — that the operator could
consume. Enumerated from the module source verified in `08-RESEARCH.md`
§ "Standard Stack" and § "Pattern 2: IP Resolution by Service Type"
(`types.go:5777-5796` ServiceType constants, `types.go:5908-5933`
`LoadBalancerIngress`).

| capability | decision | reason |
|---|---|---|
| `Service` watch (`get`/`list`/`watch`, cluster-wide) | INTEGRATE | |
| `spec.type == LoadBalancer` as an entry source | INTEGRATE | |
| `spec.type == NodePort` as an entry source | INTEGRATE | |
| `status.loadBalancer.ingress[].ip` (walk in order, first non-empty) | INTEGRATE | |
| Annotation `router-hosts.fzymgc.house/enabled` (per-object opt-in gate) | INTEGRATE | |
| Annotation `router-hosts.fzymgc.house/hostname` (required entry hostname) | INTEGRATE | |
| Annotation `router-hosts.fzymgc.house/aliases` (native `Aliases` field) | INTEGRATE | |
| Annotation `router-hosts.fzymgc.house/ip-address` (NodePort source / LB override) | INTEGRATE | |
| Update-event symmetry on the opt-in annotation (opt-out must be observable) | INTEGRATE | |
| Finalizer + `host-ids` annotation write-back (`update`/`patch` on `services`) | INTEGRATE | |
| core `events` `create`/`patch` (operator-visible failure signalling) | INTEGRATE | |
| `status.loadBalancer.ingress[].hostname` (CNAME target) | OPT-OUT | A CNAME target is not a host entry IP; D-09 skips it deliberately, mirroring Phase 7 D-15 |
| `status.loadBalancer.ingress[].ports` (`PortStatus`) | OPT-OUT | Port-level LB status; a host entry carries no port |
| `spec.type == ClusterIP` | OPT-OUT | CONTEXT § Phase Boundary "Not in this phase" — no externally reachable address to publish; annotating one raises `InvalidServiceType` (D-12) |
| `spec.type == ExternalName` | OPT-OUT | CONTEXT Deferred Ideas — CNAME semantics, no single IP to register |
| Headless Services (`spec.clusterIP: None`) | OPT-OUT | CONTEXT Deferred Ideas — no single IP to register |
| `spec.clusterIP` / `spec.clusterIPs` as an entry IP source | OPT-OUT | Cluster-internal address, not reachable from the router's DNS consumers; ClusterIP is out of scope per CONTEXT § Phase Boundary |
| `spec.externalIPs` as an entry IP source | OPT-OUT | Not in the locked IP-resolution table (D-09/D-10/D-11); `ip-address` is the single explicit override path |
| `spec.loadBalancerIP` (deprecated since k8s 1.24) | OPT-OUT | Deprecated upstream; D-11 makes the `ip-address` annotation the override path instead |
| `spec.ipFamilies` / dual-stack (IPv4 + IPv6 AAAA entries) | OPT-OUT | CONTEXT Deferred Ideas — the host model is one IP per hostname; cross-cutting, touches the domain model |
| Multiple IPs from `status.loadBalancer.ingress[]` (beyond the first) | OPT-OUT | CONTEXT Deferred Ideas (multi-IP) — one IP per hostname in the host model |
| `spec.ports[]` / `spec.ports[].nodePort` | OPT-OUT | NodePort port numbers are topology-dependent and carry no A-record meaning; D-10 requires the explicit `ip-address` annotation instead |
| `spec.selector` | OPT-OUT | Backend pod selection; irrelevant to DNS entry creation |
| `spec.externalTrafficPolicy` / `spec.internalTrafficPolicy` | OPT-OUT | Traffic-steering behavior, not a hostname or IP source |
| `spec.sessionAffinity` / `spec.sessionAffinityConfig` | OPT-OUT | Traffic behavior, not a hostname or IP source |
| `spec.allocateLoadBalancerNodePorts` / `spec.healthCheckNodePort` | OPT-OUT | LB provisioning detail; not a hostname or IP source |
| `spec.loadBalancerSourceRanges` | OPT-OUT | LB firewall scoping; not a hostname or IP source |
| `services/status` write-back / `status.conditions` | OPT-OUT | CONTEXT Deferred Ideas — Services have no extension-friendly status subresource; the D-12 Kubernetes Events are the idiomatic substitute, and no `services/status` RBAC is granted |
| `delete` verb on `services` | OPT-OUT | The operator never deletes a Service; least-privilege D-24 scopes verbs to `get`/`list`/`watch`/`update`/`patch` |
| Label-selector cache scoping (`cache.ByObject` on `corev1.Service`) | OPT-OUT | D-04 — a `cache.ByObject` selector cannot filter on an annotation, only on a label; a label opt-in would be a breaking change to the opt-in contract (CONTEXT Deferred Ideas) |
| `EndpointSlice` (`discovery.k8s.io/v1`) / `Endpoints` (core/v1) | OPT-OUT | Backend pod addresses, not the externally reachable address a DNS entry should publish |
| User-supplied `router-hosts.fzymgc.house/tags` annotation | OPT-OUT | D-22 — provenance tags are load-bearing for ownership (D-21); mixing user-controlled values in reintroduces the HostMapping asymmetry. Deferred with its own ownership analysis |
| `router-hosts.fzymgc.house/grace-period` annotation (deletion delay) | OPT-OUT | CONTEXT Deferred Ideas — requires a restart-surviving scheduler abstraction the Go operator never ported; D-16 uses immediate finalizer-based cleanup |
| `--default-ingress-ip` as a Service IP fallback | OPT-OUT | D-11 — a Service's IP is knowable from the object itself, so a default is a guess; sharing the flag widens the cross-controller `(ip, hostname)` adoption-collision surface (T-07-02) |
| Success-path Events (`HostRegistered` / `HostDeleted`) | OPT-OUT | D-12 — they fire on every reconcile and would flood the event stream; the existing `log.Info` line covers them |

**Opt-outs with no reason:** none.
**Second-integration check:** this is the first core/v1 `Service` integration in
this project. No prior integration's opt-outs were carried over — the surface was
re-enumerated from `k8s.io/api@v0.36.1` rather than inherited from Phase 7's
Gateway API matrix.
