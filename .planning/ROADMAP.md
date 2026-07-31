# Roadmap: router-hosts

## Overview

router-hosts reached **v0.10.13** as an event-sourced, mTLS-secured DNS control plane with a CLI/TUI and a Kubernetes operator. Phases 1–6 reconstruct the shipped feature-spines as completed milestones so project state is anchored at an accurate built baseline. Phases 7–9 carry the project forward toward its north star — full operator / Gateway-API parity and hands-off cluster integration — starting with the largest gaps (Gateway API, then the Service controller) and finishing with hook reliability. Phase 10 opens a second axis: moving output rendering from the server to the consumer, so a single stateful server can feed N independent consumers without accreting a per-resolver format for each.

## Milestones

### ✅ v0.10.13 — v1 Shipped Baseline

Phases 1–6. Shipped pre-GSD; reconstructed retrospectively at bootstrap (2026-07-07).

### ✅ v0.11.0 — K8s-Native Automation

Phases 7–8. Shipped 2026-07-30 in PR #381; released as v0.11.0 (version bump
corrected by the follow-up `Release-As:` PR #382). Operator / Gateway-API parity.

### ✅ v0.12.0 — Hook Reliability & Metrics

Phase 9. Shipped 2026-07-31 in PR #389. Hook metrics wired (were dead code) and
hook execution detached from the write path with configurable per-hook timeouts.
Archived: [`milestones/v0.12.0-ROADMAP.md`](milestones/v0.12.0-ROADMAP.md).

### 📋 v0.13.0 — Consumer-Owned Output

Phase 10. Approved 2026-07-25 from #364.

## Phases

**Phase Numbering:**

- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked INSERTED)
- [x] **Phase 1: Event-Sourced Host Core (CLI + gRPC/mTLS)** - Event store, aggregate, aliases, hosts file, CLI/TUI over mTLS
- [x] **Phase 2: Certificate Lifecycle (SIGHUP + ACME DNS-01)** - Hot-reload certs and auto-issue via ACME DNS-01
- [x] **Phase 3: Kubernetes Operator (HostMapping + IngressRoute)** - Reconcile cluster resources into router DNS
- [x] **Phase 4: Observability (OpenTelemetry)** - Metrics export and trace-context propagation
- [x] **Phase 5: Split-Horizon DNS Output (dnsmasq + unbound)** - Leak-free per-name authoritative resolver config
- [x] **Phase 6: Aggregate Compaction (manual RPC + gauges)** - Operator-driven event-log compaction with observability
- [x] **Phase 7: Gateway API Support** - Reconcile HTTPRoute/GRPCRoute/TLSRoute hostnames into router DNS
- [x] **Phase 8: Kubernetes Service Controller** - DNS entries for LoadBalancer/NodePort Services
- [x] **Phase 9: Hook Reliability & Metrics** - Hook execution metrics + configurable timeout/concurrency
- [ ] **Phase 10: Consumer-Rendered Output (templates + sink)** - Caller-supplied templates, one-shot and as a continuous sink

## ✅ v0.10.13 — v1 Shipped Baseline (Phase Details)

### Phase 1: Event-Sourced Host Core (CLI + gRPC/mTLS)

**Goal**: A user can manage router DNS host entries end-to-end through an event-sourced, mTLS-secured client-server system.
**Depends on**: Nothing (foundation)
**Requirements**: CORE-01, CORE-02, CORE-03, CORE-04, CORE-05, ALIAS-01
**Success Criteria** (what must be TRUE):

1. User can add, update, and remove host entries (IP + hostname) from the CLI and see them reflected in the generated `hosts(5)` file
2. Every mutation is persisted as an immutable event in the SQLite event log; replaying events reproduces current state
3. Client and server refuse to communicate without valid mutual TLS certificates
4. User can assign multiple aliases to one canonical entry and browse/import/export entries via TUI and table/JSON/CSV

**Plans**: shipped (pre-GSD)
**Status**: Complete — shipped (v0.10.13; migrated Rust → Go 2026-02-22)

### Phase 2: Certificate Lifecycle (SIGHUP + ACME DNS-01)

**Goal**: The server keeps its TLS identity current with zero-downtime reloads and automatic ACME issuance.
**Depends on**: Phase 1
**Requirements**: CERT-01, ACME-01, ACME-02
**Success Criteria** (what must be TRUE):

1. Sending SIGHUP reloads certificates and config without dropping in-flight connections (validated against Vault Agent rotation)
2. The server automatically obtains and renews TLS certificates via ACME on a renewal loop
3. ACME DNS-01 challenges complete through Cloudflare using env-expanded credentials

**Plans**: shipped (pre-GSD)
**Status**: Complete — shipped (v0.10.13)

### Phase 3: Kubernetes Operator (HostMapping + IngressRoute)

**Goal**: Cluster resources register their hostnames in router DNS automatically over mTLS.
**Depends on**: Phase 1
**Requirements**: OPER-01, OPER-02, OPER-03
**Success Criteria** (what must be TRUE):

1. Creating a HostMapping custom resource results in a corresponding router DNS entry
2. IngressRoute hostnames sync to router DNS entries with configurable IP resolution
3. Deleting a source resource removes its DNS entry via the deletion scheduler

**Plans**: shipped (pre-GSD)
**Status**: Complete — shipped (v0.10.13; HostMapping + IngressRoute controllers only)

### Phase 4: Observability (OpenTelemetry)

**Goal**: Operators can observe server behavior through metrics and distributed traces.
**Depends on**: Phase 1
**Requirements**: OBS-01, OBS-02
**Success Criteria** (what must be TRUE):

1. The server exports metrics via OpenTelemetry (OTLP / Prometheus) that a collector can scrape
2. Trace context propagates across gRPC requests so a request can be followed end-to-end

**Plans**: shipped (pre-GSD)
**Status**: Complete — shipped (v0.10.13)

### Phase 5: Split-Horizon DNS Output (dnsmasq + unbound)

**Goal**: The server emits authoritative resolver config for the internal domain without leaking ECH/AAAA to public recursion.
**Depends on**: Phase 1
**Requirements**: DNSOUT-01, DNSOUT-02
**Success Criteria** (what must be TRUE):

1. On each successful write the server regenerates a `dnsmasq` config alongside the hosts file
2. The server emits an `unbound` config with one `local-zone "<fqdn>." static` per managed name (hostname + each alias)
3. Querying a managed name's HTTPS (type-65) or AAAA record does not leak to upstream recursion, and unmanaged sibling names are not NXDOMAIN'd (ADR router-hosts-bzg)

**Plans**: shipped (pre-GSD)
**Status**: Complete — shipped (v0.10.13)

### Phase 6: Aggregate Compaction (manual RPC + gauges)

**Goal**: An operator can bound event-log growth for a runaway aggregate and observe when to act.
**Depends on**: Phase 1
**Requirements**: COMP-01, COMP-02
**Success Criteria** (what must be TRUE):

1. Invoking `CompactAggregates` (RPC/CLI) replaces an aggregate's history with a single `HostCompacted` seed event at the preserved OCC version, atomically
2. A compacted aggregate rehydrates to identical live/deleted state with its ULID and hostname preserved
3. `router_hosts_aggregate_events_max` and `router_hosts_aggregates_over_threshold` gauges are exported for remediation alerts

**Plans**: shipped (pre-GSD)
**Status**: Complete — shipped (v0.10.13; governed by ADRs v5b, vl8, 4w2)

## ✅ v0.11.0 — K8s-Native Automation (Phase Details)

### Phase 7: Gateway API Support

**Goal**: Gateway API routes auto-populate router DNS, closing the largest operator-parity gap toward the north star.
**Depends on**: Phase 3
**Requirements**: GW-01, GW-02, GW-03
**Success Criteria** (what must be TRUE):

1. Creating an HTTPRoute, GRPCRoute, or TLSRoute results in router DNS entries for each of its hostnames
2. Route entry IPs are resolved from the parent Gateway's `status.addresses`
3. Deleting or editing a route updates/removes the corresponding DNS entries, and the shipped Helm chart + RBAC grant the operator watch/list access to Gateway API resources

**Plans**: 6/6 plans executed

Plans:
**Wave 1**

- [x] 07-01-PLAN.md — Tracer: pin gateway-api v1.6.1, share the host-ids helpers, and take one HTTPRoute hostname end to end into a router DNS entry
- [x] 07-06-PLAN.md — Helm chart: Gateway API RBAC, `gateway.enabled` opt-in, and chart docs

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 07-02-PLAN.md — Expand to GRPCRoute and TLSRoute; filter wildcard, duplicate, and invalid hostnames

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 07-03-PLAN.md — Complete IP resolution from parent Gateway `status.addresses`, including fallback and no-IP requeue

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 07-04-PLAN.md — Route lifecycle: create/update/delete diff, finalizer cleanup, corrupt-annotation safety

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 07-05-PLAN.md — parentRef field index, Gateway re-enqueue, and CRD-presence gating for every watched kind

**Status**: Complete (2026-07-26) — 6 plans across 5 waves; verified 16/16 must-haves. Code review found 4 Critical + 2 Warning issues, all fixed and re-verified before completion.

### Phase 8: Kubernetes Service Controller

**Goal**: Externally-reachable Services register their DNS automatically, completing "Gateway API + Ingress + Services" parity.
**Depends on**: Phase 3
**Requirements**: SVC-01, SVC-02
**Success Criteria** (what must be TRUE):

1. A LoadBalancer or NodePort Service with the configured annotations produces router DNS entries
2. Service IPs are resolved per the IP-resolution rules, and entries are removed when the Service is deleted

**Plans**: 5/5 plans executed

Plans:
**Wave 1**

- [x] 08-01-PLAN.md — Tracer: one annotated LoadBalancer Service becomes one router DNS entry, behind `--enable-service`

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 08-02-PLAN.md — IP resolution matrix, the four failure/waiting Events, and the cluster-scoped `events` RBAC fix

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 08-03-PLAN.md — Hostname validation, aliases, and the fail-closed per-host sync path
- [x] 08-05-PLAN.md — Chart `serviceController.enabled` toggle, `task test:chart` content assertions, and chart docs

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 08-04-PLAN.md — Desired-set diff, provenance-gated adoption, and finalizer cleanup

**Status**: Complete (2026-07-30) — 5 plans across 4 waves; 2/2 success criteria verified. Deep code review found 2 Critical + 2 Warning, all fixed and re-verified; security audit closed 20/21 threats with `threats_open: 0`; UAT 39/40 (1 blocked on deployment). Shipped in PR #381. **Deployment caveat:** T-08-04 (Events RBAC) remains live in production until v0.11.0 is released and the ArgoCD pin is bumped — see `08-SECURITY.md` § Deployment Caveat.

## ✅ v0.12.0 — Hook Reliability & Metrics (Phase Details)

Archived — see [`milestones/v0.12.0-ROADMAP.md`](milestones/v0.12.0-ROADMAP.md)
for full phase detail, plans, stats, and carried-forward items.

- [x] **Phase 9: Hook Reliability & Metrics** — 5/5 plans, complete 2026-07-31,
  shipped in PR #389. Requirements HOOK-01, HOOK-02.

## 📋 v0.13.0 — Consumer-Owned Output (Phase Details)

### Phase 10: Consumer-Rendered Output (templates + sink)

**Goal**: A consumer defines its own output format and keeps it current, so one stateful server feeds N independent consumers and new resolver formats stop requiring an upstream release.
**Depends on**: Phase 1
**Requirements**: TMPL-01, TMPL-02, TMPL-03, TMPL-04, TMPL-05, TMPL-06, TMPL-07
**Success Criteria** (what must be TRUE):

1. A caller supplies a template and receives host data rendered through it, with no code change to this project
2. The field set a template may reference is documented and versioned, and a template referencing an undefined key fails loudly rather than rendering empty
3. A render or write failure leaves any previously written artifact byte-identical, and a concurrent reader never observes a partially written file
4. Sink mode reflects a host mutation without operator intervention and recovers on its own after a connection interruption, without emitting a truncated artifact
5. Neither side of a stream can be driven out of memory by the other: the server yields lazily instead of materializing the full result set, and the client refuses an unbounded response rather than collecting it
6. Existing `unbound_conf_path` and `ExportHosts` format behavior is unchanged, demonstrated by existing tests still passing

**Plans**: TBD
**Status**: Not started — approved 2026-07-25 from #364 (`approved-feature`); absorbs #23 (lazy `ExportHosts` streaming) as TMPL-06 and #38 (client-side collection bound) as TMPL-07

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 (Phases 1–6 already shipped)

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Event-Sourced Host Core | v1 Baseline | shipped | Complete | v0.10.13 |
| 2. Certificate Lifecycle | v1 Baseline | shipped | Complete | v0.10.13 |
| 3. Kubernetes Operator | v1 Baseline | shipped | Complete | v0.10.13 |
| 4. Observability | v1 Baseline | shipped | Complete | v0.10.13 |
| 5. Split-Horizon DNS Output | v1 Baseline | shipped | Complete | v0.10.13 |
| 6. Aggregate Compaction | v1 Baseline | shipped | Complete | v0.10.13 |
| 7. Gateway API Support | K8s-Native Automation | 6/6 | Complete | 2026-07-26 |
| 8. Service Controller | K8s-Native Automation | 5/5 | Complete | 2026-07-30 |
| 9. Hook Reliability & Metrics | Hook Reliability & Metrics | 5/5 | Complete | 2026-07-31 |
| 10. Consumer-Rendered Output | Consumer-Owned Output | 0/TBD | Not started | - |
