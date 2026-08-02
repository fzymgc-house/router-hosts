# router-hosts

## What This Is

router-hosts is a Go control plane for managing DNS host entries on Linux router hosts. It combines an event-sourced gRPC/mTLS server (with a Cobra CLI and Bubble Tea TUI) and a Kubernetes operator, so that both humans and cluster resources can register hostnames that are rendered into `hosts(5)`, `dnsmasq`, and `unbound` output. It is a mature, in-production project, not a greenfield effort.

## Current State

**Shipped:** v0.13.0 (2026-08-02, PR #404)

| Milestone | Phases | Delivered |
|-----------|--------|-----------|
| v0.10.13 — v1 Shipped Baseline | 1–6 | Event-sourced core, cert lifecycle, K8s operator, OTel, split-horizon DNS output, aggregate compaction |
| v0.11.0 — K8s-Native Automation | 7–8 | Gateway API routes (HTTPRoute/GRPCRoute/TLSRoute) and LoadBalancer/NodePort Services auto-populate router DNS |
| v0.12.0 — Hook Reliability & Metrics | 9 | Post-edit hooks emit metrics and no longer block the write path; per-hook configurable timeouts |
| v0.13.0 — Consumer-Owned Output | 1 | Caller-supplied templates rendered client-side, one-shot and as a self-healing sink, over a new `WatchHosts` RPC; every snapshot carries a monotonic change ID |

**Next:** not yet defined. Run `/gsd-new-milestone` to scope it. Three parked
items sit in the ROADMAP backlog (999.1–999.3): wire the e2e tiers into CI
(#403), close the hardware-dependent verification gap, and finish server-side
lazy streaming (#400/#401).

> **Phase numbering restarted at this milestone.** v0.10.13 through v0.12.0 used
> continuous numbering (phases 1–9). v0.13.0 restarts at Phase 1. When a
> historical phase number appears in an archived document it refers to the old
> sequence; phase references in this milestone's live artifacts are v0.13.0-local.
> Archived phase directories live under `milestones/<version>-phases/`.

## Current Milestone

None active. v0.13.0 closed 2026-08-02; the next milestone is unscoped.

<details>
<summary>Shipped: v0.13.0 Consumer-Owned Output</summary>

**Goal:** A consumer defines its own output format and keeps it current, so one
stateful server feeds N independent consumers and new resolver formats stop
requiring an upstream release.

Approved 2026-07-25 from #364. Absorbed #23 (lazy `ExportHosts`) as TMPL-06
and #38 (client-side collection bound) as TMPL-07. TMPL-02 was called the
highest-risk requirement at planning time — once consumers depend on a template
field set, that set becomes a compatibility obligation the proto does not cover;
it was handled with an explicit version gate rather than left implicit.

All eight requirements (TMPL-01…08) shipped. TMPL-06 was amended mid-milestone
after cross-AI review: the original "O(1) memory" claim overreached, since
chunked sends do not deliver it, so storage-layer laziness was descoped
to #400/#401 and the requirement rewritten as bounded wire messages with client
backpressure. `unbound_conf_path` (#349) and existing `ExportHosts` format
strings stayed out of scope and were left unchanged.

</details>

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
- ✓ Gateway API support: operator reconciles HTTPRoute/GRPCRoute/TLSRoute hostnames into router DNS, IPs resolved from the parent Gateway's `status.addresses`, opt-in via `--enable-gateway` — Validated in Phase 7: Gateway API Support (GW-01, GW-02, GW-03)
- ✓ Kubernetes Service controller: annotated LoadBalancer/NodePort Services register their hostnames, IPs resolved from `status.loadBalancer.ingress[]` or the `ip-address` annotation, opt-in via `--enable-service` — Validated in Phase 8: Kubernetes Service Controller (SVC-01, SVC-02). **Not yet deployed** — see the rollout note under Context.
- ✓ Hook reliability: post-edit hooks emit execution metrics (count, duration, outcome), run detached from the write path with per-hook configurable timeouts, bounded concurrency, coalescing, and a bounded-drain shutdown — Validated in v0.12.0 Phase 9: Hook Reliability & Metrics (HOOK-01, HOOK-02)
- ✓ Consumer-rendered output: `render` (one-shot) and `watch` (long-lived sink) drive caller-supplied Go templates against a documented, versioned data contract; contract-version declaration is enforced before any RPC; artifacts are written temp-file-plus-rename so a render failure leaves the previous file byte-identical; the sink reflects mutations with no polling (server-side change notification), reconnects with jittered backoff, and reports health both upstream and to a local sidecar; every snapshot carries a monotonic change ID naming server state — Validated in v0.13.0 Phase 1: Consumer-Rendered Output (TMPL-01…08)

### Active

Open forward work toward the north star. Building toward these.

- [ ] Lazy storage-layer read for `ExportHosts`/`WatchHosts` — the wire is bounded and the client refuses unbounded responses, but `store.ListAll` still folds full event history into memory server-side. Deliberately deferred out of TMPL-06 (#400, #401).
- [ ] Deployment-level verification harness — containerize the manual resolver-reload and two-node convergence checks (a real unbound container plus two sink containers) so they stop needing a second physical machine. Raised during Phase 1 UAT; the same harness would cover the `proc_e2e` tier's container extension points.
- [ ] Wire the three e2e tiers (`e2e`, `docker_e2e`, `proc_e2e`) into CI — none currently run in `ci-go.yml` (#403).

### Out of Scope

- **Automatic compaction, per-aggregate snapshot tables, snapshot-accelerated rehydration, truncation-retention windows** — deferred as YAGNI; runaway root causes already fixed (ADR router-hosts-vl8).
- **`GetAtTime` point-in-time replay across compacted aggregates** — deliberately sacrificed; no production caller (ADR router-hosts-4w2).
- **unbound `typetransparent` or zone-wide `local-zone`** — rejected; re-leaks ECH/AAAA or NXDOMAINs unmanaged siblings (ADR router-hosts-bzg).
- **Rust / Cargo / kube-rs / instant-acme stack** — superseded by the 2026-02-22 Go migration; historical only.
- **DuckDB / alternate storage backends** — SQLite-only (pure-Go, no CGo) by design.

## Context

- **Stack transition (history):** The system was originally implemented in Rust (crates, kube-rs, instant-acme). The 2026-02-22 Go migration superseded that stack; the current codebase is Go 1.26, SQLite-only via `zombiezen.com/go/sqlite` (no CGo), with a Go `cmd/operator`. Rust-era design/plan docs (sqlite-default-\*, acme-pebble-testing, operator-impl, service-controller-impl) are historical intent, not current architecture.
- **Requirements provenance:** No PRDs exist. Requirements are reconstructed from 10 SPEC design docs and inferred from the mapped Go codebase, gated by four locked ADRs.
- **Operator reality (after Phase 8):** Four controller families are registered — HostMapping, IngressRoute/IngressRouteTCP, Gateway API routes (one `GatewayRouteReconciler` per kind for HTTPRoute/GRPCRoute/TLSRoute, sharing one `syncRoute` core and the single `router-hosts.fzymgc.house/gateway-cleanup` finalizer), and Services. Only the HostMapping CRD ships; Gateway API CRDs are a documented cluster prerequisite the chart deliberately does not bundle, and each kind is gated on RESTMapper presence so absent CRDs skip cleanly instead of crash-looping the manager. The Service controller was built fresh in Go and shipped in v0.11.0, closing what was previously the north star's last concrete gap; it is **not yet deployed** — see the rollout note under Validated.
- **Consumer surface (after v0.13.0):** Output rendering is no longer server-owned. `render` and `watch` execute caller-supplied templates in the consumer's own process, so adding a resolver format needs no upstream release and the server never parses template text. Three e2e tiers now exist — `e2e` (in-process), `docker_e2e` (containerized server), and `proc_e2e` (real OS processes, the only tier that observes CLI-flag resolution).
- **Codebase state:** 86.3% test coverage against an enforced 80% floor; `task test`, all three e2e tiers, and `task build` green as of the v0.13.0 audit.
- **Known refinement areas** (from codebase concerns): oversized `service.go`/`commands.go`; in-tree Rust-era `legacy_migration.go`; pre-release protobuf pseudo-version pin; no e2e tier gates CI (#403).

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
| Change ID derived BEFORE `store.ListAll` (D-21, Phase 1) | Makes it a LOWER bound on entries sent. Deriving after would make it an upper bound, which the client-side skip turns into a permanently stale consumer that self-reports converged | ✓ Good — counter-intuitive, do not "fix" back |
| In-transaction event-ID ordering guard, not a DB sequence (D-18/D-20, Phase 1) | A DB-owned monotonic sequence contradicts locked D-18 ("the change ID is the ULID of the newest event"). Guard re-mints above `MAX(event_id)` inside `insertEvent` | ✓ Good — amend D-18 before revisiting |
| Sink hook failure retains the NEW artifact, never rolls back (D-12a, Phase 1) | Write health and reload health are independent outcomes; rolling back would discard correct data because a downstream reload failed | ✓ Good |
| Third e2e tier running real OS processes (`proc_e2e`, Phase 1) | The in-process and Docker tiers both drive the client in-process and cannot observe CLI flag→config resolution — the exact blind spot that let a bound-but-unread `--config` ship green through 45 UAT checkpoints | ✓ Good — any CLI-surface claim must be proven here |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):

1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):

1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---

*Last updated: 2026-08-02 after the v0.13.0 milestone — Consumer-Owned Output shipped (PR #404); next milestone unscoped*
