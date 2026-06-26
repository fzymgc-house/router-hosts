# Aggregate Compaction (gc) + Event-Count Observability — Design

- **Date:** 2026-06-26
- **Status:** Draft (pending design-review gate)
- **Bead:** `router-hosts-eda.2` (feature) / `router-hosts-eda.2.1` (design)
- **Issues:** #330 (remaining compaction portion), #323 (recurrence verification)
- **Supersedes scope of:** the worker's original 4-feature breakdown in `router-hosts-eda.2` notes

## Context

Triage of the aggregate-bloat runaway (#330/#323/#331/#313) found a single host aggregate
at ~91k events. The root causes are fixed and **already landed** in PR #332:

- `eda.1` — event append no longer commits past the request deadline (the *engine*).
- `eda.4` — operator reconcile is idempotent on `AlreadyExists` (the *trigger*).
- `eda.3` — snapshot schema repair + startup assertion.

With the runaway stopped, **new aggregates stay small** (a normal host is a create plus a
handful of updates). Two gaps remain:

1. **Existing damage.** Aggregates already bloated (e.g. the ~91k one) replay O(N) on every
   rehydration. The pain was *latency* — `LoadEvents` (`internal/storage/sqlite/eventstore.go:103`)
   replays the entire log, and at 91k events that exceeded the gRPC deadline. Disk is a
   non-issue (91k tiny rows). There is no in-tool way to shrink a bloated aggregate; the only
   workaround is `host delete`/recreate, which changes the ULID and briefly drops DNS.
2. **No early warning.** Nothing surfaces per-aggregate event growth, so a future regression
   would again only be noticed once writes start timing out.

## Grounding (Rule 7)

- The existing `snapshots` table is a **whole-file** backup (`hosts_content` + `entries_json`
  for the entire store), consumed only by `RollbackToSnapshot`. It is **not** per-aggregate.
- `GetAtTime` (event-replay point-in-time, `projection.go:111`) is in the `HostProjection`
  interface (`internal/storage/storage.go`) and unit-tested but has **no production caller** —
  no gRPC RPC, no CLI, no operator. "Time-travel" is latent capability, not a shipped feature.
- The existing `hostEntriesGauge` (`metrics.go:96`) is a **synchronous** `Int64Gauge` whose
  setter `SetHostEntriesCount` (`metrics.go:259`) has **no production caller** — i.e. there is
  *no* existing per-scrape metrics callback to hook into. New per-scrape metrics must introduce
  their own collection mechanism (see Event-count metric below). Fixing the dormant
  `hostEntriesGauge` is out of scope.
- `replayEvents` (`projection.go:154`) seeds the fold on `HostCreated`/`HostImported`; a new
  seed event type must be handled there.
- Domain events are stored as internal JSON (`events.event_type` / `event_data`) — **not**
  proto. A new internal event type needs no buf regeneration.
- `AppendEventsBatch` (`eventstore.go:75`) already performs atomic multi-row writes via
  `ImmediateTransaction` — compaction reuses this atomicity pattern.
- Writes are serialized through `WriteQueue` (`internal/server/writequeue.go`); compaction
  must run through the same queue to avoid racing a concurrent `UpdateHost`.

## Goals / Non-goals

**Goals**

- Provide an operator-driven **compaction** operation that collapses a bloated aggregate's
  event log to a single state-bearing event, remediating already-damaged aggregates.
- Expose a **cardinality-safe metric** of per-aggregate event growth for early warning.

**Non-goals (explicitly deferred — YAGNI now that the runaway is fixed)**

- Per-aggregate snapshot table and snapshot-accelerated rehydration.
- Periodic/automatic compaction or truncation-of-history retention windows.
- Preserving point-in-time replay (`GetAtTime`) across compaction — it has no caller.
- Auto-compaction on startup (may be revisited if a future runaway recurs).

## Design

### Compaction mechanism

For an aggregate with folded current state `S` at high-water version `V` and `N` events,
compaction runs **inside one `ImmediateTransaction`, submitted through `WriteQueue`** so it
serializes with normal writes:

1. Load all events, fold to `S` via `replayEvents`, read high-water `V`.
2. Delete all events for the aggregate.
3. Insert a single new internal **`HostCompacted`** event carrying the full state `S`, stamped
   at **version `V`** (preserve high-water → optimistic-concurrency contract is unbroken; a
   client/operator holding `V` still matches, no transient conflict).

Result: the aggregate retains its ULID, hostname, and OCC version, but holds exactly one
event. Rehydration becomes O(1).

**`HostCompacted` event** — a new struct in `internal/domain/events.go` carrying the full
folded host state: `ip`, `hostname`, `aliases`, `comment`, `tags`, **and the original
`created_at`/`updated_at`** (so the post-compaction fold is byte-identical to the pre-compaction
`HostEntry`), plus `compacted_at` and `folded_event_count` for audit.

Registering a new event type touches **four sites** (all in `internal/domain/events.go` except
the last), and omitting any one produces a runtime decode/replay error:

1. `EventType.Valid()` (`events.go:17`) — add the `HostCompacted` event-type constant.
2. `HostEvent.Decode()` (`events.go:115`) — add the JSON-unmarshal case (the `default` case
   errors on unknown types).
3. `HostEvent.OccurredAt()` (`events.go:198`) — return `compacted_at`.
4. `replayEvents` (`projection.go:154`) — seed case reconstructing the entry fields directly
   from the event (original timestamps, **not** "now").

This faithful-reproduction property is exactly what the "fold correctness" unit test asserts
(pre-fold `HostEntry` == post-compaction `HostEntry`).
A dedicated event is honest and auditable — the log shows "compacted at T, N events folded" —
unlike reusing `HostImported`, which would read as a spurious re-import and reset timestamps.

**Deleted aggregates.** An aggregate whose folded state is `Deleted` is collapsed to a single
retained terminal `HostDeleted` event (preserves `ListAll` filtering; does not resurrect a
tombstone or purge the record outright).

**Idempotency.** Compacting an aggregate that already has ≤1 event is a no-op (cheap count
check first).

### Storage interface additions

The `EventStore` interface (`internal/storage/storage.go:43`) gains **two new methods**; both
must be implemented in the SQLite backend and added to the `storagetest` compliance suite:

```go
// CompactAggregate atomically replaces all events for aggregateID with the single
// seed event, in one ImmediateTransaction. Rolls back on any failure. seed already
// carries the preserved high-water version. No-op if the aggregate has <= 1 event.
CompactAggregate(ctx context.Context, aggregateID ulid.ULID, seed domain.EventEnvelope) error

// ListAggregateIDs returns every aggregate ID in the event log, INCLUDING deleted
// aggregates (it reads distinct aggregate_id from events, not the projection).
// Backs both `compact --over N` selection and the event-count metric.
ListAggregateIDs(ctx context.Context) ([]ulid.ULID, error)
```

`ListAggregateIDs` is implemented by promoting the existing package-private
`getDistinctAggregateIDs` helper. `CompactAggregate` is the only method that deletes events —
no existing method does (`AppendEvent`/`AppendEventsBatch` insert only) — and it reuses the
`ImmediateTransaction` pattern from `AppendEventsBatch` (`eventstore.go:75`). The command
handler folds the log → state `S` + version `V`, builds the `HostCompacted` seed envelope at
`V`, and calls `CompactAggregate`; the whole call is submitted through `WriteQueue`.

### API surface

New gRPC RPC `CompactAggregates` (added to `proto/router_hosts/v1/hosts.proto` + buf regen via
`task proto:generate`) backed by a command handler, plus a Cobra CLI command:

- `router-hosts compact <aggregate-id>` — compact one aggregate.
- `router-hosts compact --over <N>` — compact every aggregate with `> N` events. Selection
  uses `ListAggregateIDs` + `CountEvents` per ID (both cheap).

Proto sketch (final field numbering/style to match existing `hosts.proto` conventions):

```proto
message CompactAggregatesRequest {
  oneof target {
    string aggregate_id = 1;   // compact exactly this aggregate
    int64  over_threshold = 2; // compact every aggregate with event_count > this
  }
  bool dry_run = 3;            // report what would be compacted; make no changes
}
message CompactedAggregate {
  string aggregate_id = 1;
  int64  events_before = 2;
  int64  events_after = 3;     // 1 (or 0 for a purged-then-reseeded path); typically 1
  int64  version = 4;          // preserved high-water version (informational/audit only)
  // NOTE: HostEntry.version is `string` ("opaque") in hosts.proto. This field is
  // informational, not an OCC token, so int64 is defensible — but the plan should pick
  // int64 vs string consciously to stay consistent with surrounding proto style.
}
message CompactAggregatesResponse {
  repeated CompactedAggregate compacted = 1;
  int64 total_events_reclaimed = 2;
}
```

The `dry_run` path lists candidates (via `ListAggregateIDs` + `CountEvents`) without mutating
the log — cheap to include and a useful safety check before a bulk `--over N`.

### Event-count metric (cardinality-safe)

**No per-aggregate (ULID) labels** — that is unbounded Prometheus cardinality. There is **no
existing per-scrape callback** to reuse — `hostEntriesGauge` is a dormant *synchronous*
`Int64Gauge` with no production pusher (see Grounding). So introduce **OTel observable (async)
gauges** whose callback runs at collection time:

- `router_hosts_aggregate_events_max` (`Int64ObservableGauge`) — the maximum event count across
  all aggregates.
- `router_hosts_aggregates_over_threshold` (`Int64ObservableGauge`) — count of aggregates whose
  event count exceeds a configured warn level (server config value, default e.g. 1000).

Both are registered via `meter.Int64ObservableGauge(...)` plus a single `meter.RegisterCallback`
that calls `ListAggregateIDs` then `CountEvents` per ID and reports via
`observer.ObserveInt64(gauge, value)` (the correct OTel Go observer method for this instrument —
not `Observe`). Async/observable is the correct instrument: the value is *pulled* at scrape time,
unlike the existing push-style `Int64Gauge`. The callback MUST honor the passed context.

**Wiring:** the callback needs a storage reference, which `Metrics` (`metrics.go:32`) and
`NewMetrics` do not currently hold. The plan must thread the `EventStore` into the callback —
either by giving `Metrics` a storage field or by registering the observable gauges at
server-setup time where the store is already in scope. Pick one in the plan.

**Trade-off (noted):** the callback is O(aggregates) per scrape; acceptable at this deployment's
scale (small host count). If host count ever grows large, move to an incrementally-maintained
counter — out of scope here.

### Safety / edge cases

- **Atomic:** delete-all + insert-seed happen in one transaction; any failure rolls back and
  leaves the full log intact.
- **Serialized:** routed through `WriteQueue`; cannot interleave with a concurrent write to the
  same aggregate.
- **Version preserved:** OCC continues from `V`; no client-visible version regression.
- **Identity preserved:** ULID and hostname unchanged (unlike the delete/recreate workaround).

## Testing

- **Unit:** fold correctness (compacted state equals pre-compaction fold); version preservation;
  atomic rollback on injected failure (log unchanged); deleted-aggregate path collapses to one
  `HostDeleted`; `--over N` selects exactly the over-threshold aggregates; idempotent no-op on a
  ≤1-event aggregate.
- **Regression (the #330/#323 scenario):** synthetically bloat an aggregate to many events,
  compact it, assert event count → 1, version preserved, and a subsequent `UpdateHost` at the
  preserved version succeeds. This is the regression guard required by the project's bug-fix rule.
- **Metric:** `router_hosts_aggregate_events_max` reflects a bloated aggregate and drops after
  compaction; `router_hosts_aggregates_over_threshold` counts correctly around the boundary.

## Decisions (and rationale)

| Decision | Choice | Why |
|----------|--------|-----|
| Scope | Remediate + observe only | Runaway already fixed by `eda.1`/`eda.4`; full snapshot machinery is YAGNI. |
| Trigger | Manual command (single + `--over N`) | Operator-driven, explicit, auditable; no implicit mutation of the event log. |
| Compacted version | Preserve high-water `V` | Keeps the OCC contract unbroken — no transient version conflict for in-flight clients. |
| Seed event | New internal `HostCompacted` | Honest/auditable; no proto change (events are internal JSON). |
| Time-travel | Sacrificed (no caller) | `GetAtTime` has no production consumer; preserving it would add cost for zero benefit. |
| Metric cardinality | Aggregate-level gauges, no ULID labels | Per-ULID labels are unbounded Prometheus cardinality. |

## Future (out of scope)

If a future change reintroduces unbounded growth despite `eda.1`/`eda.4`, revisit:
per-aggregate snapshot table + snapshot-accelerated rehydration, automatic
compaction-on-startup with a threshold, and/or a hard per-aggregate event-count circuit
breaker. None are warranted today.
