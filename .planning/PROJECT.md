# router-hosts

## What This Is

router-hosts is a Go control plane for managing DNS host entries on Linux router hosts. It combines an event-sourced gRPC/mTLS server (with a Cobra CLI and Bubble Tea TUI) and a Kubernetes operator, so that both humans and cluster resources can register hostnames that are rendered into `hosts(5)`, `dnsmasq`, and `unbound` output. It is a mature, in-production project shipped at **v0.10.13**, not a greenfield effort.

## Core Value

Cluster and CLI actors declare a hostname once, and the router's authoritative DNS output stays correct, leak-free, and hands-off — the tool disappears into the GitOps workflow.

## North Star

**K8s-native automation.** Cluster resources (Gateway API routes, Ingress/IngressRoute, and Services) auto-populate router DNS with full operator parity. Forward prioritization is weighted toward operator / Gateway-API parity and hands-off cluster integration. The success metric: a hostname exposed in the cluster requires zero manual router action to become resolvable.

## Requirements

### Validated

Shipped and running in the Go codebase at v0.10.13.

- ✓ Event-sourced host management: add/update/remove entries, immutable SQLite event log, per-aggregate optimistic concurrency — Phase 1
- ✓ Hostname aliases (multiple names per canonical entry) — Phase 1
- ✓ CLI + interactive TUI + table/JSON/CSV import/export — Phase 1
- ✓ gRPC client-server secured by mutual TLS — Phase 1
- ✓ SIGHUP certificate/config hot-reload (Vault Agent rotation) — Phase 2
- ✓ ACME automatic certificates via DNS-01 (Cloudflare/lego) — Phase 2
- ✓ Kubernetes operator: HostMapping + IngressRoute controllers — Phase 3
- ✓ OpenTelemetry metrics + trace-context propagation — Phase 4
- ✓ Split-horizon DNS output: dnsmasq + unbound (ECH/AAAA-leak-free per-name `static` zones) — Phase 5
- ✓ Operator-driven aggregate compaction (manual CompactAggregates RPC + gauges) — Phase 6

### Active

Open forward work toward the north star. Building toward these.

- [ ] Gateway API support: operator reconciles HTTPRoute/GRPCRoute/TLSRoute hostnames (Phase 7)
- [ ] Kubernetes Service controller: DNS entries for LoadBalancer/NodePort Services (Phase 8)
- [ ] Hook reliability: emit hook execution metrics + configurable timeout/concurrency (Phase 9)

### Out of Scope

- **Automatic compaction, per-aggregate snapshot tables, snapshot-accelerated rehydration, truncation-retention windows** — deferred as YAGNI; runaway root causes already fixed (ADR router-hosts-vl8).
- **`GetAtTime` point-in-time replay across compacted aggregates** — deliberately sacrificed; no production caller (ADR router-hosts-4w2).
- **unbound `typetransparent` or zone-wide `local-zone`** — rejected; re-leaks ECH/AAAA or NXDOMAINs unmanaged siblings (ADR router-hosts-bzg).
- **Rust / Cargo / kube-rs / instant-acme stack** — superseded by the 2026-02-22 Go migration; historical only.
- **DuckDB / alternate storage backends** — SQLite-only (pure-Go, no CGo) by design.

## Context

- **Stack transition (history):** The system was originally implemented in Rust (crates, kube-rs, instant-acme). The 2026-02-22 Go migration superseded that stack; the current codebase is Go 1.26, SQLite-only via `zombiezen.com/go/sqlite` (no CGo), with a Go `cmd/operator`. Rust-era design/plan docs (sqlite-default-\*, acme-pebble-testing, operator-impl, service-controller-impl) are historical intent, not current architecture.
- **Requirements provenance:** No PRDs exist. Requirements are reconstructed from 10 SPEC design docs and inferred from the mapped Go codebase, gated by four locked ADRs.
- **Operator reality (v0.10.13):** Only HostMapping and IngressRoute controllers are registered; only the HostMapping CRD ships. Service controller (designed in the Rust era, never ported) and Gateway API support (design status: Draft) are the concrete north-star gaps.
- **Known refinement areas** (from codebase concerns): oversized `service.go`/`commands.go`; in-tree Rust-era `legacy_migration.go`; pre-release protobuf pseudo-version pin.

## Constraints

- **Tech stack**: Go 1.26+, `CGO_ENABLED=0` — fully static binaries, pure-Go SQLite. No CGo toolchain.
- **Storage**: SQLite only (event log + snapshots). Single-file, single-writer semantics.
- **Concurrency**: All writes serialized through a single-goroutine `WriteQueue`; per-aggregate optimistic concurrency via `expectedVersion`. New write paths MUST be retry-safe/idempotent.
- **Security**: mTLS-only trust boundary. TLS/CA verification MUST NOT be skipped; no `InsecureSkipVerify`.
- **DNS output**: Managed inventories MUST carry FQDNs — a bare non-FQDN alias makes unbound authoritative for a whole pseudo-TLD (documented footgun, not enforced).
- **Errors**: Structured errors via `samber/oops` with domain codes; no `log.Fatal`/`os.Exit` in library code.
- **Testing**: ≥80% coverage enforced; `task test` (never raw `go test`); no real-filesystem writes in tests.

## Locked Decisions (ADRs)

These four ADRs are `Status: Accepted` and **LOCKED**. They cannot be overridden by any lower-precedence source or by future planning without an explicit superseding ADR.

<decisions>

<decision id="router-hosts-4w2" status="LOCKED" title="Sacrifice GetAtTime time-travel across compaction">
Compaction destroys pre-compaction event history. `GetAtTime` for a compacted aggregate returns only the single seed event's state; no effort is spent preserving point-in-time replay. Rationale: `GetAtTime` has no production caller (no RPC/CLI/operator); a per-aggregate snapshot table is the correct future solution if a caller is ever added, not indefinite log retention. Consequence: `GetAtTime` semantics are silently broken for compacted aggregates; a future caller must account for this at the call site.
</decision>

<decision id="router-hosts-bzg" status="LOCKED" title="Use unbound static per-name zones (not zone-wide / typetransparent)">
Emit one `local-zone: "<fqdn>." static` per managed name (hostname and each alias), with that name's A/AAAA `local-data` lines beneath it. Do NOT use `typetransparent` (re-leaks HTTPS/type-65 ECH + AAAA to recursion) and do NOT declare a single zone-wide `local-zone` (NXDOMAINs unmanaged sibling names). Per-name `static` bounds the authoritative blast radius to exactly the managed name and definitively closes the ECH/AAAA leak class at the resolver level. Governs the `unbound_conf_path` output. Ref: GH #349.
</decision>

<decision id="router-hosts-v5b" status="LOCKED" title="Compact aggregates via HostCompacted seed event">
Compaction atomically deletes all events for an aggregate and inserts a single `HostCompacted` seed event carrying the full folded state (including a `Deleted` flag) at the preserved high-water OCC version, inside one `ImmediateTransaction` routed through the `WriteQueue`. Fold and seed construction live in the storage layer. Preserving version `V` keeps the OCC contract unbroken; `HostCompacted` carries `Deleted:true` so live and deleted aggregates compact uniformly. Consequence: O(1) rehydration after compaction; ULID and hostname preserved; atomic rollback on failure; pre-compaction history destroyed.
</decision>

<decision id="router-hosts-vl8" status="LOCKED" title="Scope compaction to manual remediate + observe">
Deliver only a manual `CompactAggregates` gRPC RPC + CLI and two aggregate-level observable gauges (`router_hosts_aggregate_events_max`, `router_hosts_aggregates_over_threshold`). Defer per-aggregate snapshot tables, snapshot-accelerated rehydration, auto-compaction, and truncation-retention windows as YAGNI (root-cause runaways already fixed by commit-on-timeout and idempotent reconcile). Consequence: minimal, operator-driven, auditable surface; no automatic protection — an operator must act on gauge alerts.
</decision>

</decisions>

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Rust → Go migration (2026-02-22) | Simpler storage, pure-Go SQLite, unified toolchain | ✓ Good — current stack |
| SQLite-only storage, no CGo | Static binaries, homelab-scale write volume | ✓ Good |
| Event sourcing + CQRS + single-writer WriteQueue | Auditable, idempotent, ordering guarantees | ✓ Good |
| Sacrifice GetAtTime across compaction (4w2) | No production caller | ✓ Good (LOCKED) |
| unbound per-name `static` zones (bzg) | Closes ECH/AAAA leak, bounds blast radius | ✓ Good (LOCKED) |
| HostCompacted seed at preserved OCC version (v5b) | O(1) rehydration, OCC intact | ✓ Good (LOCKED) |
| Manual remediate+observe compaction only (vl8) | YAGNI on auto/snapshots | ✓ Good (LOCKED) |

---

*Last updated: 2026-07-07 after ingest-driven project bootstrap (retrospective + forward)*
