---
phase: 07
slug: gateway-api-support
status: secured
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-26
---

# Phase 07 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

Register origin: authored at plan time — all six `07-0N-PLAN.md` files carried a
parseable `<threat_model>` block, so this audit verified existing mitigations
rather than building a register retroactively.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Go module proxy → build | Third-party module source enters the binary at `go get` time | Executable code |
| Kubernetes API server → operator | Route and Gateway objects are attacker-influencable by anyone with create rights in any watched namespace | Hostnames, parentRefs, annotations |
| Namespace A route → namespace B Gateway | `parentRefs` may name a Gateway in another namespace, read directly without a ReferenceGrant | Gateway `status.addresses` |
| Cluster CRD inventory → operator startup | Which CRDs are installed is outside the operator's control and can change between deployments | GVK resolvability |
| operator → router-hosts gRPC server | Host mutations cross an mTLS boundary into the authoritative DNS store | DNS records (create/update/delete) |
| Helm chart → Kubernetes RBAC | The ClusterRole this chart ships is the operator's entire authorization envelope | Access-control policy |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-07-SC | Tampering | `go get sigs.k8s.io/gateway-api@v1.6.1` supply chain | high | mitigate | Module resolves to the official kubernetes-sigs repo already trusted for controller-runtime; `go.mod:29` pins v1.6.1 in the direct require block, `go.sum` records both hashes, `go mod tidy` is a no-op, and no `k8s.io/*` requirement moved off v0.36.1 | closed |
| T-07-01 | Denial of Service | `SetupWithManager` `.Watches(&gatewayv1.Gateway{}, ...)` | high | mitigate | Watch clause gated on `gatewayKindPresent(mapper, gatewayGVK)`; an unresolvable Gateway GVK would otherwise fail the manager's **shared** informer cache and take the already-shipped HostMapping and IngressRoute controllers down with it. Test `TestGatewayKindPresent_GatewayGVKAbsent` | closed |
| T-07-02 | Tampering | Host-entry ownership across all three adopters | high | mitigate | **Two parts.** (1) Every `DeleteHost` argument is read from the reconciled object's own `host-ids` annotation — never a hostname, IP, or cross-object lookup. (2) Adoption is gated on provenance in all three adopters so a foreign ID can never enter that annotation in the first place. See "T-07-02 remediation" below | closed |
| T-07-03 | Elevation of Privilege | `clusterrole.yaml` Gateway API rules (ASVS V4) | high | mitigate | Two rule blocks with different verb sets: `update`/`patch` only on the three route kinds (justified by the finalizer and annotation write-back); `gateways` read-only. No `create`, no `delete`, no `*/status` subresource. Verified by rendering the chart | closed |
| T-07-04 | Tampering | `getHostIDsAnnotation` corrupt-JSON path | high | mitigate | A corrupt annotation returns an error and requeues in both `syncRoute` and `reconcileDelete`, never proceeding on a partial view — proceeding would treat every tracked-but-unreadable hostname as removed and delete its live entry. Tests assert zero `HostClient` calls on that path | closed |
| T-07-07 | Tampering | `extractHostnames` (ASVS V5 Input Validation) | high | mitigate | Every hostname passes `validation.ValidateHostname` before any `HostClient` call; `*`-prefixed wildcards rejected outright. Failures skip-and-log rather than aborting, so one bad name cannot deny service to the rest of the route | closed |
| T-07-14 | Denial of Service | `SetupGatewayControllers` per-route-kind registration | high | mitigate | Each route kind gated on its version-exact GVK before any informer is constructed, so a partially installed or older-channel CRD set degrades to fewer controllers instead of a failed manager start. Tests `_PartiallyInstalled`, `_AllAbsent`, `_WrongVersion` | closed |
| T-07-06 | Spoofing | `GatewayRouteReconciler.Reconcile` (any namespace) | medium | accept | See Accepted Risks R-01 | closed |
| T-07-08 | Spoofing | `Gateway.status.addresses` as the IP source | medium | accept | See Accepted Risks R-02 | closed |
| T-07-09 | Elevation of Privilege | `cmd/operator/main.go` feature enablement | medium | mitigate | `--enable-gateway` defaults false and `SetupGatewayControllers` is reachable only inside that branch, so installing Gateway API CRDs alone never causes the operator to start writing DNS entries | closed |
| T-07-12 | Denial of Service | `syncRoute` with an unresolvable IP | medium | mitigate | Returns `RequeueAfter: requeueDelayShort` with a nil error rather than writing an IP-less entry or hot-looping; a permanently unresolvable route costs one lookup per interval and never corrupts DNS output | closed |
| T-07-16 | Elevation of Privilege | `rbac.create=false` path | medium | mitigate | The Gateway rules sit inside the existing `{{- if .Values.rbac.create -}}` guard; rendering with `rbac.create=false` produces zero ClusterRole objects | closed |
| T-07-17 | Tampering | chart-rendered `--enable-gateway` arg | medium | mitigate | Rendered only under `.Values.gateway.enabled`, which defaults false, so a chart upgrade cannot silently start writing DNS entries on a cluster that merely has the CRDs installed | closed |
| T-07-05 | Information Disclosure | `resolveIP` cross-namespace `Gateway` Get | low | accept | See Accepted Risks R-03 | closed |
| T-07-10 | Denial of Service | `extractHostnames` de-duplication | low | mitigate | A route repeating one hostname N times yields one entry, so a single object cannot fan out into N server writes per reconcile | closed |
| T-07-11 | Tampering | dot-less hostname acceptance (D-19) | low | accept | See Accepted Risks R-04 | closed |
| T-07-13 | Denial of Service | partial-delete retry loop | low | accept | See Accepted Risks R-05 | closed |
| T-07-15 | Denial of Service | `mapGatewayToRoutes` fan-out | low | accept | See Accepted Risks R-06 | closed |

*Status: open · closed · open — below high threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above `workflow.security_block_on` (high) count toward `threats_open`*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## T-07-02 remediation

T-07-02 was the one threat this audit found genuinely open, and it took two passes
to close. Recorded in full because the failure mode generalises.

**What the first audit found.** Part 1 of the clause (deletion arguments come only
from the object's own annotation) was intact. Part 2 ("a hostname shared with
another route, a HostMapping, or an IngressRoute cannot make one controller delete
another's entry") was falsified by `addOrAdoptGatewayHost`, added during code-review
remediation *after* the threat model was written. It adopted whatever
`FindHost(ip, hostname)` returned, with no ownership check. The server enforces
uniqueness on `(ip, hostname)`, so the conflicting entry could belong to another
owner; the adopted foreign ID entered this object's annotation, after which part 1
held mechanically while ownership did not, and stale-cleanup or `reconcileDelete`
would legitimately destroy another owner's live DNS entry.

**Why it was reachable in ordinary use.** `--default-ingress-ip` is a single flag
feeding every controller, so an IngressRoute hostname and a Gateway route hostname
routinely collide on the same IP — precisely the Traefik→Gateway-API migration this
phase exists to enable. No forged input required.

**First remediation (`c65c8a2`) and why it was insufficient.** Gated the Gateway
adopter on per-object provenance. Correct as far as it went, but it covered one of
three adopters, so the clause stayed false — and it made the collision *asymmetric*:
the Gateway side now politely refuses, making Gateway routes the guaranteed loser of
every collision. The re-audit caught this.

**Final remediation (`4f81538`).** Gated all three adopters:

| Adopter | Discriminator | Why |
|---------|---------------|-----|
| `addOrAdoptGatewayHost` | comment `k8s-gateway:<ns>/<name>` **and** `gateway` + KindName tags | Comment separates objects differing in namespace/name; the tag half is the **only** thing separating an HTTPRoute and a TLSRoute sharing one namespace/name, since both produce an identical comment |
| `IngressRouteReconciler.addOrAdopt` | comment `k8s-ingress:<ns>/<name>` **and** `traefik` + `ingress` tags | Both operator-derived |
| `HostMappingReconciler.adoptExistingHost` | comment `k8s:<ns>/<name>` **only** | Its tags come from user-supplied `Spec.Tags` and prove nothing about provenance |

Comment prefixes `k8s:` / `k8s-ingress:` / `k8s-gateway:` are disjoint, and
Kubernetes names cannot contain `:`, so no object can forge another's identity. A
principal able to set an arbitrary comment via the gRPC/CLI API already holds
`DeleteHost` — no escalation.

**Failure mode of refusal is safe.** The refused hostname was untracked by
definition, so stale-cleanup has nothing to delete for it. Gateway and IngressRoute
skip that hostname, set `hadError`, and requeue with a nil error (fixed interval, no
exponential backoff, no finalizer wedge); the rest of the object still converges.
HostMapping surfaces an `AdoptionRefused` condition. All self-recover when the
conflicting entry goes away.

**Why the original proof-test missed it.** `TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete`
was cited as the standing proof of this clause but could not reach the adoption
branch: its mock returned a fresh ID from every `AddHost`, modelling a server that
accepts duplicate `(ip, hostname)` pairs — which `internal/server/commands.go`
rejects. It passed without ever exercising the behavior it was named for. Rewritten
against a `fakeHostStore` that enforces the real uniqueness constraint. The same
unrealistic-fixture flaw was found and corrected in five further pre-existing
adoption tests across all three controllers.

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Disposition set by | Status |
|---------|------------|-----------|-------------|------|
| R-01 | T-07-06 | Any principal who can create a route in a watched namespace can claim any hostname in the router's DNS. This is the same trust model the already-shipped HostMapping and IngressRoute controllers operate under; the controls are cluster RBAC on route creation plus the `--enable-gateway` opt-in (D-06). Narrowing it would require a namespace allow-list, which no phase 7 requirement asks for | plan-time threat model | re-verified 2026-07-26 |
| R-02 | T-07-08 | Whoever controls the parent Gateway's status controls where the published hostname points. Inherent to GW-02 as written — the requirement *is* to resolve IPs from the parent Gateway's status. Cluster RBAC on `gateways/status` is the control and lives outside this operator, which holds no write verb on that subresource | plan-time threat model | re-verified 2026-07-26 |
| R-03 | T-07-05 | A route in namespace A can reference a Gateway in namespace B without a `ReferenceGrant`, surfacing that Gateway's `status.addresses` into a DNS entry. Explicitly out of scope per CONTEXT § Deferred Ideas ("ReferenceGrant enforcement for cross-namespace parentRefs"); the operator performs a read-only `Get` and is not acting as the Gateway controller. Narrowed during the phase — WR-02 added `isGatewayKindRef` so non-Gateway parentRefs no longer trigger a Get at all | plan-time threat model | re-verified 2026-07-26 |
| R-04 | T-07-11 | Under ADR `router-hosts-bzg` a bare dot-less name renders as `local-zone: "<name>." static`, making unbound authoritative for a whole pseudo-TLD. PROJECT.md records this as a known, project-wide, deliberately unenforced footgun; enforcing it in the Gateway controller alone would make it inconsistent with HostMapping and IngressRoute. A warning is emitted. Cross-cutting enforcement is a CONTEXT Deferred Idea | plan-time threat model | re-verified 2026-07-26 |
| R-05 | T-07-13 | A permanently failing `DeleteHost` keeps the finalizer and requeues, blocking Kubernetes garbage collection of that route until the server recovers or an operator patches the finalizer. Deliberate fail-closed tradeoff — the alternative is releasing the finalizer and orphaning live DNS entries. Re-verified after the CR-03 change: `ErrHostNotFound` is raised by the server only when the aggregate is absent or already deleted (transport faults map to `Unavailable`/`DeadlineExceeded`), so treating it as success orphans nothing and the fail-closed intent is preserved for genuine failures | plan-time threat model | re-verified 2026-07-26 |
| R-06 | T-07-15 | A Gateway referenced by many routes re-enqueues all of them on every status change. Controller-runtime deduplicates identical requests in its workqueue and serialises per object key, and the queue is bounded, so cost is proportional to real dependents rather than unbounded. Narrowed during the phase — WR-02 removed non-Gateway parentRefs from the index | plan-time threat model | re-verified 2026-07-26 |

---

## Unregistered Flags (informational — not counted in `threats_open`)

| Flag | Detail | Disposition |
|------|--------|-------------|
| No `## Threat Flags` sections | None of the six SUMMARY files recorded new attack surface, so summary flags were unusable as an audit input. Every threat was verified against source directly, and the post-plan surface added by the six code-review fix commits was audited and mapped anyway | Process note for future phases |
| Forged-but-well-formed `host-ids` annotation | The plan's own trust-boundary table states the annotation is user-editable. T-07-04 covers the *corrupt* case, but nothing covers a *valid-JSON annotation naming a foreign UUID* — the controller will `DeleteHost` it on hostname removal or object deletion. Requires knowing the target UUID, so materially harder than the adoption vector, and the same pattern exists in the pre-existing IngressRoute controller. No threat-register mapping | Follow-up — file as its own threat in a later phase |
| Gateway controller writes no status conditions | `gateway_controller.go` makes no `r.Status()` call, so a permanently refused adoption is retried silently every 30s, visible only in operator logs. Strictly better than the previous behavior (silently stealing the entry), but an operator debugging "my HTTPRoute hostname never resolves" must read controller logs | Follow-up — UX, not security |
| `ingressroute_controller.go` `ErrHostNotFound` gap | Pre-existing; `reconcileDelete` still lacks the CR-03 handling. Fails in the safe direction (stuck finalizer, no orphan). Recorded in `07-REVIEW-FIX.md` | Follow-up — out of phase 7 scope |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-26 | 18 | 17 | 1 (T-07-02) | gsd-security-auditor (full pass, ASVS 1) |
| 2026-07-26 | 1 (T-07-02) | 0 | 1 (T-07-02) | gsd-security-auditor (focused re-audit after `c65c8a2`; part 1 closed, part 2 still open — two adopters ungated) |
| 2026-07-26 | 18 | 18 | 0 | Orchestrator (after `4f81538`; both new gates mutation-tested — disabling either makes its refusal test fail) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] Gates green at closure: `task build` exit 0, `task lint` 0 issues, `task test:coverage:ci` 85.0% (≥80%)
