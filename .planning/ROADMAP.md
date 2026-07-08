# Roadmap: router-hosts

## Overview

router-hosts reached **v0.10.13** as an event-sourced, mTLS-secured DNS control plane with a CLI/TUI and a Kubernetes operator. Phases 1–6 reconstruct the shipped feature-spines as completed milestones so project state is anchored at an accurate built baseline. Phases 7–9 carry the project forward toward its north star — full operator / Gateway-API parity and hands-off cluster integration — starting with the largest gaps (Gateway API, then the Service controller) and finishing with hook reliability.

## Milestones

- ✅ **v1 Shipped Baseline** — Phases 1–6 (shipped, at v0.10.13)
- 🚧 **K8s-Native Automation** — Phases 7–9 (active; north-star parity)

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
- [ ] **Phase 7: Gateway API Support** - Reconcile HTTPRoute/GRPCRoute/TLSRoute hostnames into router DNS
- [ ] **Phase 8: Kubernetes Service Controller** - DNS entries for LoadBalancer/NodePort Services
- [ ] **Phase 9: Hook Reliability & Metrics** - Hook execution metrics + configurable timeout/concurrency

## Phase Details

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

### Phase 7: Gateway API Support

**Goal**: Gateway API routes auto-populate router DNS, closing the largest operator-parity gap toward the north star.
**Depends on**: Phase 3
**Requirements**: GW-01, GW-02, GW-03
**Success Criteria** (what must be TRUE):

1. Creating an HTTPRoute, GRPCRoute, or TLSRoute results in router DNS entries for each of its hostnames
2. Route entry IPs are resolved from the parent Gateway's `status.addresses`
3. Deleting or editing a route updates/removes the corresponding DNS entries, and the shipped Helm chart + RBAC grant the operator watch/list access to Gateway API resources
**Plans**: TBD
**Status**: Not started — design exists (2026-06-07, Draft); no Gateway API controller or `gateway-api` dependency in the Go operator yet

### Phase 8: Kubernetes Service Controller

**Goal**: Externally-reachable Services register their DNS automatically, completing "Gateway API + Ingress + Services" parity.
**Depends on**: Phase 3
**Requirements**: SVC-01, SVC-02
**Success Criteria** (what must be TRUE):

1. A LoadBalancer or NodePort Service with the configured annotations produces router DNS entries
2. Service IPs are resolved per the IP-resolution rules, and entries are removed when the Service is deleted
**Plans**: TBD
**Status**: Not started — Rust-era design (2026-01-02) never ported to the Go operator; north-star parity gap

### Phase 9: Hook Reliability & Metrics

**Goal**: Post-edit hooks are observable and cannot stall the write path.
**Depends on**: Phase 1
**Requirements**: HOOK-01, HOOK-02
**Success Criteria** (what must be TRUE):

1. Each `on_success` / `on_failure` hook execution emits count, duration, and outcome metrics (closes the dead-metrics gap, router-hosts-0ed)
2. A per-hook timeout is configurable (no longer a fixed 30s) and hook execution is bounded so a slow hook cannot block write processing (router-hosts-ee0)
**Plans**: TBD
**Status**: Not started

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 (Phases 1–6 already shipped)

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Event-Sourced Host Core | v1 Baseline | shipped | Complete | v0.10.13 |
| 2. Certificate Lifecycle | v1 Baseline | shipped | Complete | v0.10.13 |
| 3. Kubernetes Operator | v1 Baseline | shipped | Complete | v0.10.13 |
| 4. Observability | v1 Baseline | shipped | Complete | v0.10.13 |
| 5. Split-Horizon DNS Output | v1 Baseline | shipped | Complete | v0.10.13 |
| 6. Aggregate Compaction | v1 Baseline | shipped | Complete | v0.10.13 |
| 7. Gateway API Support | K8s-Native Automation | 0/TBD | Not started | - |
| 8. Service Controller | K8s-Native Automation | 0/TBD | Not started | - |
| 9. Hook Reliability & Metrics | K8s-Native Automation | 0/TBD | Not started | - |
