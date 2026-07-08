# Decisions (ADR Intel)

Extracted from classified ADRs. All four are `Status: Accepted` and LOCKED — they cannot be auto-overridden by any lower-precedence source. Each entry preserved separately.

---

## DEC-sacrifice-getattime-time-travel

- source: docs/adr/router-hosts-4w2-sacrifice-getattime-time-travel-across-compaction.md
- id: router-hosts-4w2
- status: locked (Accepted, 2026-06-26)
- scope: GetAtTime, HostProjection, compaction, event log, snapshots

Decision: Accept that compaction destroys pre-compaction event history. `GetAtTime` for a compacted aggregate returns only the single seed event's state; no effort is spent preserving point-in-time replay. Rationale: `GetAtTime` has no production caller (no RPC/CLI/operator); a per-aggregate snapshot table is the correct future solution if a caller is ever added, not indefinite log retention.

Consequence: `GetAtTime` semantics are silently broken for compacted aggregates; a future caller must account for this at the call site.

---

## DEC-unbound-static-per-name-zones

- source: docs/adr/router-hosts-bzg-use-unbound-static-per-name-zones-not-zone-wide-or-typetrans.md
- id: router-hosts-bzg
- status: locked (Accepted, 2026-07-07)
- scope: unbound, local-zone config, split-horizon DNS, unbound_conf_path output, fzymgc.house domain
- external ref: GH #349

Decision: Emit one `local-zone: "<fqdn>." static` per managed name (hostname and each alias), with that name's A/AAAA `local-data` lines beneath it. Do NOT use `typetransparent` (re-leaks HTTPS/type-65 ECH + AAAA to recursion) and do NOT declare a single zone-wide `local-zone` (NXDOMAINs unmanaged sibling names). Per-name `static` bounds the authoritative blast radius to exactly the managed name.

Consequence: Definitively closes the ECH/AAAA leak class at the resolver level. Footgun: a bare non-FQDN alias makes unbound authoritative for a whole pseudo-TLD — inventories MUST carry FQDNs (documented, not enforced). Governs the `unbound_conf_path` SPEC.

---

## DEC-compact-via-hostcompacted-seed

- source: docs/adr/router-hosts-v5b-compact-aggregates-via-hostcompacted-seed-event.md
- id: router-hosts-v5b
- status: locked (Accepted, 2026-06-26)
- scope: host aggregate, compaction, HostCompacted event, EventStore interface, storage layer, OCC versioning, rehydration

Decision: Compaction atomically deletes all events for an aggregate and inserts a single `HostCompacted` seed event carrying the full folded state (including a `Deleted` flag) at the preserved high-water OCC version, inside one `ImmediateTransaction` routed through the `WriteQueue`. Fold and seed construction live in the storage layer. Preserving version `V` keeps the OCC contract unbroken; `HostCompacted` carries `Deleted:true` so live and deleted aggregates compact uniformly.

Consequence: O(1) rehydration after compaction; ULID and hostname preserved; atomic rollback on failure. Pre-compaction history destroyed (ties to DEC-sacrifice-getattime).

---

## DEC-scope-compaction-manual-remediate-observe

- source: docs/adr/router-hosts-vl8-scope-compaction-manual-remediate-observe.md
- id: router-hosts-vl8
- status: locked (Accepted, 2026-06-26)
- scope: CompactAggregates gRPC RPC, aggregate compaction, event log, observability gauges (router_hosts_aggregate_events_max, router_hosts_aggregates_over_threshold)

Decision: Deliver only a manual `CompactAggregates` gRPC RPC + CLI and two aggregate-level observable gauges. Defer per-aggregate snapshot tables, snapshot-accelerated rehydration, auto-compaction, and truncation-retention windows as YAGNI (root-cause runaways already fixed by eda.1 commit-on-timeout and eda.4 idempotent reconcile).

Consequence: Minimal code surface, operator-driven and auditable. No automatic protection — an operator must act on gauge alerts.
