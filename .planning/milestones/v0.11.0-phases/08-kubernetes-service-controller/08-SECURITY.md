---
phase: 8
slug: kubernetes-service-controller
status: verified
# threats_open = count of OPEN threats at or above workflow.security_block_on severity (the blocking gate)
threats_open: 0
asvs_level: 1
created: 2026-07-27
---

# Phase 8 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

**Register origin:** authored at plan time — all five `08-0N-PLAN.md` files carried a parseable
`<threat_model>` block (26 rows, 21 unique IDs; T-08-04/05/07/08/10 restated across plans).

**Verification depth:** exceeded ASVS L1. For all six high-severity `mitigate` threats the auditor
built mutants of `internal/operator/service_controller.go` in a scratchpad and ran them via
`go test -overlay=…`; the repository was never modified. **A mitigation counted as verified only if
deleting it turned a passing test red.** A grep match was not accepted as evidence.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| Service annotations → operator | Any principal with `patch` on a Service in any namespace can request a DNS registration | hostname, aliases, IP address (untrusted) |
| router-hosts server → operator (`FindHost` result) | The conflicting entry returned on `AlreadyExists` may belong to another controller or a CLI user; `(ip, hostname)` is **not** proof of ownership | host entry ID, comment, tags |
| Service `host-ids` annotation → `DeleteHost` | Any ID reaching this annotation becomes a deletion target on the next opt-out or Service delete | host entry IDs (integrity-critical) |
| Operator → Kubernetes API (`events`) | Newly granted cluster-scoped `events` create/patch | security-relevant failure signals |
| Operator → router-hosts gRPC | mTLS-only; unchanged by this phase | host mutations |

---

## Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation | Status |
|-----------|----------|-----------|----------|-------------|------------|--------|
| T-08-01 | Tampering | `addOrAdoptService` on `ErrHostAlreadyExists` | high | mitigate | `service_controller.go:525` requires BOTH `existing.Comment == "k8s-service:<ns>/<name>"` AND `hasServiceProvenance(existing.Tags)`. Both halves mutation-proven load-bearing: dropping the tags half fails `AdoptionRefused/foreign_tags`; dropping the comment half fails `foreign_comment`. Adoption branch genuinely reached via `newFakeHostStore` | closed |
| T-08-03 | Tampering | hostname collision with IngressRoute / Gateway route / HostMapping | high | mitigate | Server `(ip,hostname)` uniqueness → `AlreadyExists` → T-08-01 gate refuses. D-11 verified structurally: `ServiceReconciler` has no `DefaultIP` field; `main.go` passes `defaultIngressIP` only to IngressRoute and Gateway | closed |
| T-08-04 | Repudiation | `Eventf` without a cluster-scoped `events` rule | high | mitigate | `clusterrole.yaml:55-57` renders `events` `create`/`patch`, ungated by either controller toggle; regression-gated in `Taskfile.yml:121-131`. **Artifact only — not yet effective in production; see Deployment Caveat** | closed |
| T-08-13 | Tampering | writing an IP-less or wrong-IP host entry | high | mitigate | `resolveServiceIP:154-170` walks `.IP` only; mutating it to fall back to `.Hostname` fails two subtests. No empty-IP write path — waiting and `ip == ""` both bypass `syncServiceHost`; subtests use `noAddHostMock` which `t.Fatal`s if `AddHost` is called | closed |
| T-08-17 | Elevation of Privilege | user-controlled values entering the provenance tag set | high | mitigate | D-22 holds: exactly four annotation keys declared (`enabled`, `hostname`, `aliases`, `ip-address`); no `tags` key exists in the package. Tag set built from operator-process `DefaultTags` plus the literal `"service"`. **No user-controlled value can reach the tag set**, so T-08-01's provenance half cannot be forged | closed |
| T-08-SC | Tampering | package-manager installs (supply chain) | high | mitigate | `git diff -- go.mod go.sum` empty across all phase-8 commits; 16 non-planning files touched, none dependency-related | closed |
| T-08-02 | Spoofing | unauthorized DNS registration by a namespace tenant | medium | accept | Two independent gates: `--enable-service` defaults false (`main.go:50`, guard `:139`) and the per-object `serviceEnabled` opt-in annotation | closed |
| T-08-05 | Elevation of Privilege | over-broad Service RBAC | medium | mitigate | `clusterrole.yaml:45-47` grants exactly five verbs, no `delete`; `Taskfile.yml:110-115` exact-string compares the rendered verbs line; `:135-138` rejects `services/status` | closed |
| T-08-06 | Tampering / DoS | corrupt or tampered `host-ids` annotation | medium | mitigate | Fail closed both paths: `syncService:324-327` requeues before any `HostClient` call; `reconcileDelete:557-563` requeues **without touching the finalizer**. Mutating the delete-path guard fails `corrupt_annotation_requeues_without_deleting` | closed |
| T-08-07 | Spoofing | non-FQDN hostname becomes authoritative for a pseudo-TLD | low | accept | Warn-not-reject at `:194-196`, consistent with sibling controllers under ADR `router-hosts-bzg`; pinned by `dotless_accepted_with_warning` | closed |
| T-08-08 | Elevation of Privilege | controller silently enabled by a chart upgrade | medium | mitigate | `--enable-service` default false; `Taskfile.yml:97-104` asserts flag count `0` by default and exactly `1` under `serviceController.enabled=true` | closed |
| T-08-10 | Denial of Service | informer caches every Service cluster-wide | low | accept | Documented trade-off in `values.yaml:68-71` and chart `README.md:326-327`, including the label-selector alternative | closed |
| T-08-11 | Spoofing | `ip-address` annotation points a hostname at an arbitrary IP | medium | accept | Server-side `validation.ValidateIPAddress` (`commands.go:96,197,388`) — the control the acceptance rests on, verified present. See Unregistered Flags for the availability half | closed |
| T-08-12 | Denial of Service | event flooding | low | mitigate | Exactly four `emitEvent` call sites, all failure/waiting reasons; no success-path event (`no_success_event_on_create`) | closed |
| T-08-14 | Tampering | malformed / oversized alias list | medium | mitigate | IP-rejection, hostname-validity and canonical-name halves present (`:229`, `:189`) with subtest coverage. **Over-long-list half absent in the Service path** | open — below `high` threshold (non-blocking) |
| T-08-15 | Tampering | nil alias slice silently retains stale aliases | medium | mitigate | `:218-245` returns non-nil on every path; mutating it to return `nil` when empty fails three tests including `AliasesClearedSendsEmptySlice` | closed |
| T-08-16 | Tampering | blind update re-appends events / lost OCC | medium | mitigate | `:453-481` reads first, passes `current.Version` as the OCC token, fails closed on non-NotFound read error and on nil-entry-nil-error. Replacing the read with a synthetic entry fails all four `UpdatePath` subtests | closed |
| T-08-18 | Denial of Service | DNS entry orphaned after the Service stops declaring it | medium | mitigate | Unconditional stale-cleanup pass `:396-412` (no early return on empty desired set); delete failure retains the ID. All four D-17 transitions covered plus `PartialFailureRetainsIDs` | closed |
| T-08-19 | Denial of Service | finalizer released while entries are still live | medium | mitigate | `:583-599` removes the finalizer only when `!hadDeleteError`; partial failure persists `remainingIDs` and requeues with the finalizer intact. Reverting CR-02 fails `host_not_found_during_cleanup_releases_finalizer`. Wedge direction closed by `serviceOwnsState:98-101` OR'd into the predicate. **Register wording corrected — see Documentation Findings** | closed |
| T-08-20 | Repudiation | chart verification that passes without proving anything | medium | mitigate | All six new `Taskfile.yml:97-145` assertions capture rendered output and compare or count it, printing the observed value on failure. No `grep -q` exit-status gate among them | closed |
| T-08-21 | Tampering | Helm values key collision | low | mitigate | `values.yaml:63-67` and chart `README.md:126` document the `serviceController.enabled` asymmetry; `rg -c '^service:' values.yaml` → 0 | closed |

*Status: open · closed · open — below `high` threshold (non-blocking)*
*Severity: critical > high > medium > low — only open threats at or above `workflow.security_block_on` count toward `threats_open`*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-08-01 | T-08-02 | Any principal able to annotate a Service in any namespace can publish a hostname. Bounded by two independent gates (operator flag default-false + required per-object opt-in annotation). Tightening further would require admission control, out of scope for a homelab control plane | Phase 8 plan-time decision (D-03) | 2026-07-27 |
| AR-08-02 | T-08-07 | Dot-less hostnames are warned about but accepted, matching HostMapping / IngressRoute / Gateway behavior. Under ADR `router-hosts-bzg` a bare name makes unbound authoritative for a pseudo-TLD. Enforcing in this one controller would make the operator inconsistent with itself; belongs in a cross-cutting validation change | Phase 8 plan-time decision (D-08) | 2026-07-27 |
| AR-08-03 | T-08-10 | The shared informer caches every Service in the cluster, not only annotated ones — a predicate filters events, not the cache. Accepted at homelab scale; the label-selector alternative would change the opt-in contract | Phase 8 plan-time decision (D-04) | 2026-07-27 |
| AR-08-04 | T-08-11 | The `ip-address` annotation lets an annotator point a hostname at an arbitrary IP. Accepted because the server validates the value as a well-formed IP before persisting, and the same exposure already exists for HostMapping | Phase 8 plan-time decision | 2026-07-27 |

---

## Deployment Caveat — T-08-04 (read before treating this phase as protecting production)

**This register certifies the chart artifact, not the running cluster.** Measured against the live
`fzymgc-house` cluster on 2026-07-27, independently by the orchestrator and re-measured by the auditor:

```text
kubectl auth can-i create events \
  --as=system:serviceaccount:router-hosts-operator:router-hosts-operator   →  no
```

The deployed `ClusterRole/router-hosts-operator` contains **zero** `events` rules. ArgoCD is pinned
to chart `0.10.11` from `ghcr.io/fzymgc-house/charts`; the repo is at `0.10.13`.

**T-08-04's threat — a security-relevant Event silently dropped because `Eventf` has no error
return — is live in production right now**, and has been since the operator was first deployed
(2025-12-31). It stays live until `0.10.13+` is released and the ArgoCD pin bumped. The mitigation
exists in the artifact and is regression-gated in `task test:chart`; it is **not yet effective**.

Do not let "the chart is correct" be read as "the cluster is protected." This is a rollout action
item, not a code gap, which is why it does not count toward `threats_open`.

The same deploy also lands Phase 7's Gateway API RBAC, which has likewise never shipped to this cluster.

---

## Unregistered Flags

| Flag | Source | Mapping |
|------|--------|---------|
| WR-01 — aliases can exceed the aggregate 50-alias cap | 08-REVIEW.md | Maps to **T-08-14** as a partial gap in a declared mitigation, not a quality nit. `service_controller.go:229` calls `ValidateAliases([]string{alias}, …)` with a one-element slice inside a per-segment loop, so `validation.go:93`'s `len(aliases) > MaxAliasesPerEntry` check is structurally unreachable from this controller. Bounded by the server enforcing the cap on the aggregate slice (`commands.go:102,264,394`), so an over-long list is rejected, never published — residual impact is availability/observability, not DNS integrity |
| WR-02 — `ip-address` never format-validated client-side | 08-REVIEW.md | **Partially unregistered.** The *spoofing* surface is registered and accepted under T-08-11. What is **not** registered: a malformed value is rejected server-side on every reconcile, producing an unbounded `requeueDelayLong` retry loop with **no** Kubernetes Event — `reasonMissingIPAddress` fires only when the annotation is absent. T-08-12 registers event *flooding*; nothing registers event *absence*. Recommend registering as a new low/medium DoS-or-Repudiation threat rather than folding it into T-08-11 |
| Process gap — no `## Threat Flags` section in any of the five SUMMARY files | 08-01…08-05-SUMMARY.md | Not a security finding, but the executors produced no new-attack-surface inventory for this phase. Both WARNINGs above were recovered from the code review, not the summaries — the `## Threat Flags` channel cannot be relied on as complete for Phase 8 |

---

## Documentation Findings (not open threats)

1. **T-08-19's plan-time register text was stale and is corrected here.** It read *"removes the
   finalizer only after every tracked `DeleteHost` succeeded."* Post-CR-02 (`bc00c9b`),
   `ErrHostNotFound` is treated as success (`service_controller.go:570-577`). The code is correct
   and the wording was stale — the pre-CR-02 literal reading describes exactly the wedge CR-02
   fixed. Corrected statement: *removes the finalizer only after every tracked `DeleteHost` either
   succeeded or returned `NotFound`; any other error retains the remaining IDs and requeues with the
   finalizer intact.*

2. **Three mitigations rest on plan-time-only gates with no standing regression guard.** T-08-SC's
   `git diff --exit-code -- go.mod go.sum`, T-08-21's `grep -c '^service:' values.yaml`, and
   T-08-20's two negative controls all ran at execution time and all hold in current state
   (re-verified during this audit), but none lives in `task test:chart`, `task ci`, or CI. All three
   threats are CLOSED on present state; none has a guard against future regression.

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-07-27 | 21 | 20 | 1 (non-blocking) | gsd-security-auditor (opus, ASVS L1 + L3 mutation testing on all high-severity threats) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed — no open threat at or above the `high` block threshold
- [x] `status: verified` set in frontmatter
- [ ] **Rollout action outstanding:** release chart `0.10.13+` and bump the ArgoCD pin, or T-08-04 remains live in production

**Approval:** verified 2026-07-27 (artifact); production rollout pending
