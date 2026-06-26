<!-- markdownlint-disable MD013 -->
<!-- adr-render: source=bd:router-hosts-vl8; do not edit manually; use `/adr update router-hosts-vl8` -->

# Scope compaction to manual remediate+observe

**Date:** 2026-06-26
**Status:** Accepted
**Decision:** router-hosts-vl8
**Deciders:** sean

## Context

The aggregate-bloat runaway root causes (`eda.1` commit-on-timeout, `eda.4` idempotent reconcile) landed before this design (PR #332). The scope question was whether to build only a manual remediation command plus cardinality-safe metrics, or to also build per-aggregate snapshot-accelerated rehydration, auto-compaction, or truncation-retention windows — each a structurally different system.

## Decision

Deliver only a manual `CompactAggregates` gRPC RPC + CLI and two aggregate-level observable gauges. Defer per-aggregate snapshot tables, snapshot-accelerated rehydration, auto-compaction, and truncation-retention windows as YAGNI.

## Rationale

- `eda.1` and `eda.4` fixed the engine and the trigger of the runaway, so new aggregates stay small (a normal host is a create plus a handful of updates).
- The minimal path needs no scheduler component, no background compaction process, and no snapshot schema to maintain.
- Observable gauges (`router_hosts_aggregate_events_max`, `router_hosts_aggregates_over_threshold`) provide early warning if a future regression reintroduces growth.

## Alternatives Considered

- **Manual `CompactAggregates` RPC + observable gauges (chosen):** minimal scope; remediates existing damage; operator-driven and auditable. Cost: requires operator action if a future runaway occurs.
- **Full snapshot machinery — per-aggregate snapshot table + accelerated rehydration (rejected):** resilient to future runaways and preserves time-travel, but new schema + storage-interface surface and large scope — YAGNI given the runaway is stopped.
- **Auto-compaction on startup or schedule (rejected):** no operator action required, but implicitly mutates the event log (harder to audit) and adds a scheduler component.

## Consequences

- Positive: minimal code surface; remediates existing damage; auditable operator-driven mutations.
- Negative: no automatic protection — an operator must act on gauge alerts.
- Neutral: the future-revisit path (per-aggregate snapshot table) is explicitly named in the spec's Future section.
