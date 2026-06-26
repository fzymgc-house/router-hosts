<!-- markdownlint-disable MD013 -->
<!-- adr-render: source=bd:router-hosts-4w2; do not edit manually; use `/adr update router-hosts-4w2` -->

# Sacrifice GetAtTime time-travel across compaction

**Date:** 2026-06-26
**Status:** Accepted
**Decision:** router-hosts-4w2
**Deciders:** sean

## Context

`GetAtTime` (event-replay point-in-time, `projection.go:111`) is declared in the `HostProjection` interface and unit-tested, but has no production caller — no gRPC RPC, no CLI, no operator. Compaction irrevocably deletes the pre-compaction event log, which permanently breaks point-in-time replay for compacted aggregates.

## Decision

Accept that compaction destroys pre-compaction event history. `GetAtTime` for a compacted aggregate returns only the single seed event's state. No effort is spent preserving time-travel.

## Rationale

- `GetAtTime` has no production consumer; preserving it would add cost for zero runtime benefit.
- If a future caller is ever added, the per-aggregate snapshot table (named in the spec's Future section) is the correct solution — not retaining the full log indefinitely.

## Alternatives Considered

- **Accept `GetAtTime` breakage; no caller to protect (chosen):** compaction stays simple (delete-all + insert-seed) with no extra storage. Cost: `GetAtTime` returns incomplete results for compacted aggregates if a caller is ever added.
- **Retain pre-compaction events / no delete (rejected):** keeps time-travel fully intact but negates the entire purpose of compaction (the log stays large).
- **Pre-compaction snapshot preserving time-travel up to the compaction point (rejected):** partial time-travel, but requires the per-aggregate snapshot table this design explicitly defers.

## Consequences

- Positive: no additional storage or retention bookkeeping.
- Negative: `GetAtTime` semantics are silently broken for compacted aggregates; a future caller must account for this at the call site.
- Neutral: the interface method remains declared; the behavior change is not reflected in its signature, so it must be documented if a caller is added.
