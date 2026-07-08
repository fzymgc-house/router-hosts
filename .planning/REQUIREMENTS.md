# Requirements: router-hosts

**Defined:** 2026-07-07
**Core Value:** Cluster and CLI actors declare a hostname once, and the router's authoritative DNS output stays correct, leak-free, and hands-off.

> Provenance: no PRDs exist. Validated requirements are reconstructed from 10 SPEC design docs and the mapped Go codebase (shipped at v0.10.13). Active requirements are the open forward gaps, gated by four locked ADRs.

## v1 Requirements

### Core — Event-Sourced Host Management (Phase 1, shipped)

- [x] **CORE-01**: User can add, update, and remove DNS host entries (IP + hostname) via the CLI
- [x] **CORE-02**: Every mutation is recorded as an immutable domain event in an event-sourced SQLite store with per-aggregate optimistic concurrency
- [x] **CORE-03**: Server regenerates the `hosts(5)` file from the projected read model on every successful write
- [x] **CORE-04**: Client and server communicate over gRPC secured by mutual TLS
- [x] **CORE-05**: User can browse/edit entries via an interactive TUI and import/export in table, JSON, and CSV formats
- [x] **ALIAS-01**: User can assign multiple hostname aliases to a single canonical host entry

### Certificates & ACME (Phase 2, shipped)

- [x] **CERT-01**: Server reloads TLS certificates and config on SIGHUP without dropping in-flight connections (supports Vault Agent rotation)
- [x] **ACME-01**: Server automatically obtains and renews TLS certificates via ACME with a renewal loop
- [x] **ACME-02**: Server completes ACME DNS-01 challenges through Cloudflare using env-expanded credentials

### Kubernetes Operator — Core Controllers (Phase 3, shipped)

- [x] **OPER-01**: Operator reconciles HostMapping custom resources into router DNS entries over mTLS
- [x] **OPER-02**: Operator syncs IngressRoute hostnames to router DNS entries with configurable IP resolution
- [x] **OPER-03**: Operator removes DNS entries when their source resource is deleted (deletion scheduling)

### Observability (Phase 4, shipped)

- [x] **OBS-01**: Server exports metrics via OpenTelemetry (OTLP / Prometheus)
- [x] **OBS-02**: Server propagates trace context across gRPC requests

### Split-Horizon DNS Output (Phase 5, shipped)

- [x] **DNSOUT-01**: Server emits a `dnsmasq` configuration file alongside the hosts file
- [x] **DNSOUT-02**: Server emits an `unbound` configuration using per-name `local-zone static` directives that do not leak HTTPS/ECH (type-65) or AAAA records to recursion (ADR router-hosts-bzg)

### Aggregate Compaction (Phase 6, shipped)

- [x] **COMP-01**: Operator can compact a host aggregate's event history to a single `HostCompacted` seed event at the preserved OCC version via the `CompactAggregates` RPC/CLI (ADRs router-hosts-v5b, -4w2)
- [x] **COMP-02**: Server exposes aggregate-level gauges (max events per aggregate, aggregates over threshold) for compaction remediation (ADR router-hosts-vl8)

### Gateway API Support (Phase 7, active)

- [ ] **GW-01**: Operator reconciles Gateway API HTTPRoute / GRPCRoute / TLSRoute hostnames into router DNS entries
- [ ] **GW-02**: Operator resolves route IPs from the parent Gateway's `status.addresses`
- [ ] **GW-03**: Helm chart and RBAC grant the operator watch/list access to Gateway API route resources

### Kubernetes Service Controller (Phase 8, active)

- [ ] **SVC-01**: Operator creates router DNS entries for LoadBalancer and NodePort Services from configured annotations
- [ ] **SVC-02**: Operator resolves Service IPs and removes entries when the Service is deleted

### Hook Reliability & Metrics (Phase 9, active)

- [ ] **HOOK-01**: Server emits execution metrics (count, duration, outcome) for `on_success` / `on_failure` hooks (currently dead code — tracked as router-hosts-0ed)
- [ ] **HOOK-02**: Hook execution supports a configurable per-hook timeout and a bounded concurrency model so a slow hook cannot block the write path (currently fixed 30s + sequential — tracked as router-hosts-ee0)

## v2 Requirements

Acknowledged but deferred; not in the current roadmap.

### Storage / History

- **HIST-01**: Per-aggregate snapshot tables + snapshot-accelerated rehydration (would restore GetAtTime across compaction; deferred per ADR router-hosts-vl8/-4w2)
- **HIST-02**: Automatic / threshold-triggered compaction (deferred as YAGNI per ADR router-hosts-vl8)

### Maintainability

- **DEBT-01**: Remove in-tree Rust-era `legacy_migration.go` once all deployments are known-migrated

## Out of Scope

| Feature | Reason |
|---------|--------|
| Auto-compaction / snapshot tables / retention windows | YAGNI; root causes already fixed (ADR router-hosts-vl8) |
| GetAtTime replay across compacted aggregates | No production caller; deliberately sacrificed (ADR router-hosts-4w2) |
| unbound `typetransparent` / zone-wide `local-zone` | Re-leaks ECH/AAAA or NXDOMAINs siblings (ADR router-hosts-bzg) |
| Rust / Cargo / kube-rs / instant-acme stack | Superseded by 2026-02-22 Go migration |
| DuckDB / alternate storage backends | SQLite-only, pure-Go, no CGo by design |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CORE-01 | Phase 1 | Complete |
| CORE-02 | Phase 1 | Complete |
| CORE-03 | Phase 1 | Complete |
| CORE-04 | Phase 1 | Complete |
| CORE-05 | Phase 1 | Complete |
| ALIAS-01 | Phase 1 | Complete |
| CERT-01 | Phase 2 | Complete |
| ACME-01 | Phase 2 | Complete |
| ACME-02 | Phase 2 | Complete |
| OPER-01 | Phase 3 | Complete |
| OPER-02 | Phase 3 | Complete |
| OPER-03 | Phase 3 | Complete |
| OBS-01 | Phase 4 | Complete |
| OBS-02 | Phase 4 | Complete |
| DNSOUT-01 | Phase 5 | Complete |
| DNSOUT-02 | Phase 5 | Complete |
| COMP-01 | Phase 6 | Complete |
| COMP-02 | Phase 6 | Complete |
| GW-01 | Phase 7 | Pending |
| GW-02 | Phase 7 | Pending |
| GW-03 | Phase 7 | Pending |
| SVC-01 | Phase 8 | Pending |
| SVC-02 | Phase 8 | Pending |
| HOOK-01 | Phase 9 | Pending |
| HOOK-02 | Phase 9 | Pending |

**Coverage:**

- v1 requirements: 25 total (18 shipped / Complete, 7 active / Pending)
- Mapped to phases: 25
- Unmapped: 0 ✓

---

*Requirements defined: 2026-07-07*
*Last updated: 2026-07-07 after ingest-driven bootstrap (retrospective + forward)*
