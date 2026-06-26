<!-- markdownlint-disable MD013 -->
<!-- adr-render: source=bd:router-hosts-v5b; do not edit manually; use `/adr update router-hosts-v5b` -->

# Compact aggregates via HostCompacted seed event

**Date:** 2026-06-26
**Status:** Accepted
**Decision:** router-hosts-v5b
**Deciders:** sean

## Context

A host aggregate reached ~91k events, causing O(N) rehydration to exceed the gRPC deadline. Compaction must restore O(1) rehydration without changing the aggregate ULID or breaking in-flight optimistic-concurrency (OCC) clients. The choice determines the storage data model (what a compacted aggregate looks like) and the `EventStore` interface contract.

## Decision

Compaction atomically deletes all events for an aggregate and inserts a single `HostCompacted` seed event carrying the full folded state (including a `Deleted` flag) at the preserved high-water OCC version, inside one `ImmediateTransaction` routed through the `WriteQueue`. The fold and seed construction live in the storage layer.

## Rationale

- Preserving version `V` keeps the OCC contract unbroken — in-flight clients holding `V` do not see a transient conflict on their next write.
- `HostCompacted` carries `Deleted:true` so live and deleted aggregates compact uniformly; a lone `HostDeleted` seed folds to `nil` in `replayEvents` (its case is guarded by `if entry != nil`) and therefore cannot be used.
- A dedicated event type is honest and auditable (`FoldedEventCount`, `CompactedAt`); reusing `HostImported` would misread as a re-import and reset timestamps.
- The storage layer owns the fold because `replayEvents`/`insertEvent` are package-private and deleted aggregates are invisible to `GetByID`.

## Alternatives Considered

- **In-place fold to a single `HostCompacted` seed (chosen):** ULID + OCC version preserved; one transaction; uniform live/deleted handling. Cost: pre-compaction event history is destroyed.
- **Delete + recreate aggregate (rejected):** simplest (reuses `HostCreated`), but changes the ULID, briefly drops DNS, and breaks clients holding the old ULID.
- **Per-aggregate snapshot table (rejected):** O(1) rehydration on every startup and preserves time-travel, but requires new schema and is large scope — YAGNI given the runaway root cause is already fixed.

## Consequences

- Positive: O(1) rehydration after compaction; ULID and hostname preserved; atomic rollback on failure.
- Negative: `GetAtTime` returns incomplete history for compacted aggregates.
- Neutral: `FoldedEventCount` and `CompactedAt` provide an audit trail in the seed event.
