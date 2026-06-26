# Aggregate Compaction (gc) + Event-Count Observability — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a manual server-side compaction command that collapses a bloated host aggregate's event log to a single state-bearing event (preserving the high-water version), plus cardinality-safe metrics for per-aggregate event growth.

**Architecture:** A new internal `HostCompacted` domain event seeds the projection fold with the full folded state (including a `Deleted` flag, so live and deleted aggregates compact uniformly). Two new `EventStore` methods — `ListAggregateIDs` and `CompactAggregate` (folds + atomically replaces the log inside one transaction) — back a `CompactAggregates` gRPC RPC + `compact` CLI command, both routed through the existing `WriteQueue`. Two OTel observable gauges report max/over-threshold event counts.

**Tech Stack:** Go 1.25, `zombiezen.com/go/sqlite` (pure-Go SQLite), `samber/oops` errors, buf/protobuf gRPC, Cobra CLI, OpenTelemetry metrics (`go.opentelemetry.io/otel/metric` v1.44.0), `oklog/ulid/v2`.

**Spec:** `docs/superpowers/specs/2026-06-26-aggregate-compaction-design.md`
**Beads:** epic `router-hosts-eda` → feature `router-hosts-eda.2` → design `router-hosts-eda.2.1`

---

## Refinements over the spec (grounded during planning)

Three deliberate, code-grounded improvements over `2026-06-26-aggregate-compaction-design.md`:

1. **Event registration = 6 sites, not 4.** The spec named `Valid()`/`Decode()`/`OccurredAt()`/`replayEvents`. Grounding showed `NewHostEvent()` (the type→`EventType` switch) and the const block are *also* required — without `NewHostEvent`, the event can't be constructed at all.
2. **Deleted aggregates use `HostCompacted{Deleted:true}`, not a `HostDeleted` seed.** The spec's "collapse deleted → single `HostDeleted`" is broken: `replayEvents`' `HostDeleted` case is guarded by `if entry != nil`, so a *lone* `HostDeleted` folds to `nil`. Adding a `Deleted` field to `HostCompacted` lets live and deleted aggregates compact uniformly with byte-identical folds.
3. **`CompactAggregate(ctx, id) (CompactResult, error)` folds internally** — the spec sketched `CompactAggregate(ctx, id, seed)`. The fold must happen in the storage layer because `replayEvents`/`insertEvent` are package-private and deleted aggregates aren't visible via `GetByID`. Storage builds the seed itself.

## Conventions for this plan

- **Test iteration:** use focused `go test ./<pkg>/... -run <TestName> -v` for the red/green loop. Before **every commit**, run the authoritative gates: `task lint` and `task test` (full suite + race detector; the project rule is that `task test` is the source of truth — focused `go test` is iteration only).
- **Commits:** Conventional Commits, subject ≤50 chars, `scope` from `cog.toml`. Every commit message ends with the AI byline:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`
- **VCS:** jj (see `references/vcs-preamble.md`). `jj commit -m "..."` per task.
- **Errors:** wrap with `oops.Wrapf(err, "context")`; never `log.Fatal`/`os.Exit` in library code.

## File structure (what each task touches)

| File | Responsibility | Tasks |
|------|----------------|-------|
| `internal/domain/events.go` | `HostCompacted` event type + 5 registration sites + struct | 1 |
| `internal/storage/sqlite/projection.go` | `replayEvents` seed case; promote `getDistinctAggregateIDs` | 1, 2 |
| `internal/domain/events_test.go` | domain event round-trip tests | 1 |
| `internal/storage/sqlite/projection_test.go` (or `sqlite_test.go`) | fold-correctness tests | 1 |
| `internal/storage/storage.go` | `EventStore` interface: `ListAggregateIDs`, `CompactAggregate`; `CompactResult` type | 2, 3 |
| `internal/storage/sqlite/eventstore.go` | SQLite impl of both new methods + `deleteEventsForAggregate` helper | 2, 3 |
| `internal/storage/storagetest/suite.go` | compliance tests for new methods | 2, 3 |
| `internal/server/commands.go` | `CompactAggregate` / `CompactAggregatesOver` command handlers | 4 |
| `internal/server/commands_test.go` | command-handler tests | 4 |
| `proto/router_hosts/v1/hosts.proto` | `CompactAggregates` RPC + messages | 5 |
| `internal/server/service.go` | `CompactAggregates` gRPC handler | 6 |
| `internal/server/service_test.go` | service handler test | 6 |
| `internal/client/commands/compact.go` (new) + `root.go` | `compact` CLI command | 7 |
| `internal/server/metrics.go` + `internal/client/commands/serve.go` | observable gauges + wiring | 8 |

---

## Task 1: `HostCompacted` domain event + projection fold

**Files:**
- Modify: `internal/domain/events.go` (const block ~55, `Valid()` ~17, `Decode()` ~115, `OccurredAt()` ~198, `NewHostEvent()` ~233, new struct after `HostImported` ~359)
- Modify: `internal/storage/sqlite/projection.go:154` (`replayEvents` switch)
- Test: `internal/domain/events_test.go`, `internal/storage/sqlite/sqlite_test.go`

Design note: `HostCompacted` carries the **full folded state including `Deleted`** so a single seed event folds byte-identically to the pre-compaction `HostEntry` for both live and deleted aggregates. (This replaces the spec's "collapse deleted → `HostDeleted`" idea, which fails: a lone `HostDeleted` folds to `nil` because the `HostDeleted` replay case is guarded by `if entry != nil`.)

- [ ] **Step 1: Write the failing domain test**

In `internal/domain/events_test.go`:

```go
func TestHostCompactedRoundTrip(t *testing.T) {
	comment := "svc"
	orig := domain.HostCompacted{
		IPAddress:        "192.168.1.10",
		Hostname:         "llm-gw.fzymgc.house",
		Aliases:          []string{"mcp-gw.fzymgc.house"},
		Comment:          &comment,
		Tags:             []string{"k8s"},
		Deleted:          false,
		CreatedAt:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt:        time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		CompactedAt:      time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC),
		FoldedEventCount: 91178,
	}

	he, err := domain.NewHostEvent(orig)
	require.NoError(t, err)
	require.Equal(t, domain.EventTypeHostCompacted, he.Type)

	decoded, err := he.Decode()
	require.NoError(t, err)
	got, ok := decoded.(domain.HostCompacted)
	require.True(t, ok)
	require.Equal(t, orig, got)

	occ, err := he.OccurredAt()
	require.NoError(t, err)
	require.Equal(t, orig.CompactedAt, occ)
}
```

- [ ] **Step 2: Run it; verify it fails to compile**

Run: `go test ./internal/domain/ -run TestHostCompactedRoundTrip -v`
Expected: FAIL — `undefined: domain.HostCompacted` / `domain.EventTypeHostCompacted`.

- [ ] **Step 3: Add the event type constant**

In `internal/domain/events.go` const block, after `EventTypeHostImported`:

```go
	EventTypeHostCompacted EventType = "HostCompacted"
```

- [ ] **Step 4: Add the `Valid()` case**

In `EventType.Valid()` switch, add `EventTypeHostCompacted` to the `case` list:

```go
		EventTypeHostImported,
		EventTypeHostCompacted,
		EventTypeSnapshotCreated,
```

- [ ] **Step 5: Define the `HostCompacted` struct**

In `internal/domain/events.go`, after the `HostImported` struct (~line 359):

```go
// HostCompacted is a synthetic seed event written by compaction. It replaces an
// aggregate's entire event log with a single event carrying the full folded
// state (including Deleted), so the post-compaction fold is byte-identical to
// the pre-compaction HostEntry. CompactedAt/FoldedEventCount are audit metadata.
type HostCompacted struct {
	IPAddress        string    `json:"ip_address"`
	Hostname         string    `json:"hostname"`
	Aliases          []string  `json:"aliases"`
	Comment          *string   `json:"comment,omitempty"`
	Tags             []string  `json:"tags"`
	Deleted          bool      `json:"deleted"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	CompactedAt      time.Time `json:"compacted_at"`
	FoldedEventCount int64     `json:"folded_event_count"`
}
```

- [ ] **Step 6: Add the `Decode()` case**

In `HostEvent.Decode()`, after the `EventTypeHostImported` case:

```go
	case EventTypeHostCompacted:
		var v HostCompacted
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, err
		}
		return v, nil
```

- [ ] **Step 7: Add the `OccurredAt()` case**

In `HostEvent.OccurredAt()`, after the `HostImported` case:

```go
	case HostCompacted:
		return ev.CompactedAt, nil
```

- [ ] **Step 8: Add the `NewHostEvent()` case**

In `NewHostEvent()`, after the `HostImported` case. No re-validation — the state is reconstructed from already-committed, already-valid events:

```go
	case HostCompacted:
		eventType = EventTypeHostCompacted
```

- [ ] **Step 9: Run the domain test; verify it passes**

Run: `go test ./internal/domain/ -run TestHostCompactedRoundTrip -v`
Expected: PASS.

- [ ] **Step 10: Write the failing fold test**

In `internal/storage/sqlite/sqlite_test.go` (uses the package-private `replayEvents`):

```go
func TestReplayEventsHostCompactedSeedsFullState(t *testing.T) {
	aggID := ulid.Make()
	comment := "svc"
	ev := domain.HostCompacted{
		IPAddress: "192.168.1.10", Hostname: "llm-gw.fzymgc.house",
		Aliases: []string{"a.fzymgc.house"}, Comment: &comment, Tags: []string{"k8s"},
		Deleted:   false,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		CompactedAt: time.Date(2026, 6, 26, 0, 0, 0, 0, time.UTC), FoldedEventCount: 5,
	}
	he, err := domain.NewHostEvent(ev)
	require.NoError(t, err)
	env := domain.EventEnvelope{
		EventID: ulid.Make(), AggregateID: aggID, Event: he, Version: 42,
		CreatedAt: time.Date(2026, 6, 26, 1, 0, 0, 0, time.UTC),
	}

	entry, err := replayEvents(aggID, []domain.EventEnvelope{env})
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.Equal(t, "192.168.1.10", entry.IP)
	require.Equal(t, "llm-gw.fzymgc.house", entry.Hostname)
	require.Equal(t, ev.CreatedAt, entry.CreatedAt)
	require.Equal(t, ev.UpdatedAt, entry.UpdatedAt) // original UpdatedAt, NOT env.CreatedAt
	require.Equal(t, int64(42), entry.Version)      // preserved high-water version
	require.False(t, entry.Deleted)
}

func TestReplayEventsHostCompactedDeleted(t *testing.T) {
	aggID := ulid.Make()
	ev := domain.HostCompacted{
		IPAddress: "192.168.1.10", Hostname: "gone.fzymgc.house",
		Deleted: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		CompactedAt: time.Now().UTC(), FoldedEventCount: 3,
	}
	he, _ := domain.NewHostEvent(ev)
	env := domain.EventEnvelope{EventID: ulid.Make(), AggregateID: aggID, Event: he, Version: 7, CreatedAt: time.Now().UTC()}
	entry, err := replayEvents(aggID, []domain.EventEnvelope{env})
	require.NoError(t, err)
	require.NotNil(t, entry)
	require.True(t, entry.Deleted)
}
```

- [ ] **Step 11: Run it; verify it fails**

Run: `go test ./internal/storage/sqlite/ -run TestReplayEventsHostCompacted -v`
Expected: FAIL — `unknown event type "HostCompacted"` from the `replayEvents` `default` case.

- [ ] **Step 12: Add the `replayEvents` seed case**

In `internal/storage/sqlite/projection.go`, in the `replayEvents` switch, after the `domain.HostImported` case. It seeds from the carried state and uses the event's **own** timestamps (not `env.CreatedAt`):

```go
		case domain.HostCompacted:
			entry = &domain.HostEntry{
				ID:        aggregateID,
				IP:        ev.IPAddress,
				Hostname:  ev.Hostname,
				Aliases:   ev.Aliases,
				Comment:   ev.Comment,
				Tags:      ev.Tags,
				CreatedAt: ev.CreatedAt,
				UpdatedAt: ev.UpdatedAt,
				Version:   env.Version,
				Deleted:   ev.Deleted,
			}
```

- [ ] **Step 13: Run the fold tests; verify they pass**

Run: `go test ./internal/storage/sqlite/ -run TestReplayEventsHostCompacted -v`
Expected: PASS.

- [ ] **Step 14: Gate + commit**

Run: `task lint && task test`
Then: `jj commit -m "feat(domain): add HostCompacted seed event + replay"`

---

## Task 2: `ListAggregateIDs` on `EventStore`

**Files:**
- Modify: `internal/storage/storage.go:43` (interface)
- Modify: `internal/storage/sqlite/eventstore.go` (new method) and `projection.go` (export helper if needed)
- Modify: `internal/storage/storagetest/suite.go` (compliance test)

Note: `getDistinctAggregateIDs(conn)` already exists in `projection.go` and returns ALL distinct aggregate IDs from the `events` table (including deleted aggregates). The new method wraps it with `withConn`.

- [ ] **Step 1: Write the failing compliance test**

In `internal/storage/storagetest/suite.go`, add a test function:

```go
// TestEventStoreListAggregateIDs verifies all aggregate IDs (incl. deleted) are returned.
func TestEventStoreListAggregateIDs(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	id1, id2 := ulid.Make(), ulid.Make()
	mustAppendCreated(t, store, id1, "10.0.0.1", "a.example.com")
	mustAppendCreated(t, store, id2, "10.0.0.2", "b.example.com")

	ids, err := store.ListAggregateIDs(ctx)
	require.NoError(t, err)
	got := map[string]bool{}
	for _, id := range ids {
		got[id.String()] = true
	}
	require.True(t, got[id1.String()])
	require.True(t, got[id2.String()])
}
```

Then register it in `RunAll` after `TestEventStoreBatchAppendRollback`:

```go
	t.Run("EventStoreListAggregateIDs", func(t *testing.T) {
		TestEventStoreListAggregateIDs(t, factory(t))
	})
```

> If a `mustAppendCreated(t, store, id, ip, host)` helper does not already exist in `suite.go`, add one that builds a `HostCreated` envelope at version 1 via `domain.NewHostEvent` and calls `store.AppendEvent(ctx, id, env, 0)`. Check the file first — reuse the existing append helper if present.

- [ ] **Step 2: Run it; verify it fails to compile**

Run: `go test ./internal/storage/sqlite/ -run TestCompliance/EventStoreListAggregateIDs -v`
Expected: FAIL — `store.ListAggregateIDs undefined`.

- [ ] **Step 3: Add the interface method**

In `internal/storage/storage.go`, `EventStore` interface, after `CountEvents`:

```go
	// ListAggregateIDs returns every distinct aggregate ID in the event log,
	// INCLUDING deleted aggregates (reads distinct aggregate_id from events).
	ListAggregateIDs(ctx context.Context) ([]ulid.ULID, error)
```

- [ ] **Step 4: Implement on `*Storage`**

In `internal/storage/sqlite/eventstore.go`:

```go
// ListAggregateIDs returns every distinct aggregate ID in the event log.
func (s *Storage) ListAggregateIDs(ctx context.Context) ([]ulid.ULID, error) {
	var ids []ulid.ULID
	err := s.withConn(ctx, func(conn *sqlite.Conn) error {
		var innerErr error
		ids, innerErr = getDistinctAggregateIDs(conn)
		return innerErr
	})
	if err != nil {
		return nil, oops.Wrapf(err, "list aggregate ids")
	}
	return ids, nil
}
```

- [ ] **Step 5: Run the compliance test; verify it passes**

Run: `go test ./internal/storage/sqlite/ -run TestCompliance/EventStoreListAggregateIDs -v`
Expected: PASS.

- [ ] **Step 6: Verify no other `EventStore` implementer breaks**

Run: `go build ./...`
Expected: PASS. (If a mock implements `EventStore`/`storage.Storage` — e.g. in `internal/server/*_test.go` — add the method there; the compiler will name the file.)

- [ ] **Step 7: Gate + commit**

Run: `task lint && task test`
Then: `jj commit -m "feat(storage): add ListAggregateIDs to EventStore"`

---

## Task 3: `CompactAggregate` storage method

**Files:**
- Modify: `internal/storage/storage.go` (interface + `CompactResult` type)
- Modify: `internal/storage/sqlite/eventstore.go` (impl + `deleteEventsForAggregate` helper)
- Modify: `internal/storage/storagetest/suite.go` (compliance tests)

The method folds the log (via `replayEvents`), builds a `HostCompacted` seed at the high-water version, and atomically (one `ImmediateTransaction`) deletes all events + inserts the seed. No-op for ≤1 event. Folding lives here because `replayEvents`/`insertEvent` are package-private and deleted aggregates are visible (unlike `GetByID`, which errors on them).

- [ ] **Step 1: Write the failing regression + edge tests**

In `internal/storage/storagetest/suite.go`:

```go
// TestEventStoreCompactAggregate is the #330/#323 regression: a bloated aggregate
// compacts to one event with its version and folded state preserved.
func TestEventStoreCompactAggregate(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	id := ulid.Make()

	// Bloat: 1 create + 20 IP changes => 21 events, version 21.
	mustAppendCreated(t, store, id, "10.0.0.1", "h.example.com")
	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+2)
		ev, _ := domain.NewHostEvent(domain.IPAddressChanged{NewIP: ip, ChangedAt: time.Now().UTC()})
		env := domain.EventEnvelope{EventID: ulid.Make(), AggregateID: id, Event: ev, Version: int64(i + 2), CreatedAt: time.Now().UTC()}
		require.NoError(t, store.AppendEvent(ctx, id, env, int64(i+1)))
	}
	before, err := store.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(21), before.Version)

	res, err := store.CompactAggregate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(21), res.EventsBefore)
	require.Equal(t, int64(1), res.EventsAfter)
	require.Equal(t, int64(21), res.Version)

	// Event count is now 1; current version preserved.
	cnt, err := store.CountEvents(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(1), cnt)
	v, err := store.GetCurrentVersion(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(21), v)

	// Folded state is byte-identical (same Version means OCC unbroken).
	after, err := store.GetByID(ctx, id)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

// TestEventStoreCompactAggregateNoopSmall: <=1 event is a no-op.
func TestEventStoreCompactAggregateNoop(t *testing.T, store storage.Storage) {
	t.Helper()
	ctx := context.Background()
	id := ulid.Make()
	mustAppendCreated(t, store, id, "10.0.0.1", "h.example.com")
	res, err := store.CompactAggregate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(1), res.EventsBefore)
	require.Equal(t, int64(1), res.EventsAfter)
	cnt, _ := store.CountEvents(ctx, id)
	require.Equal(t, int64(1), cnt)
}
```

Register both in `RunAll`:

```go
	t.Run("EventStoreCompactAggregate", func(t *testing.T) {
		TestEventStoreCompactAggregate(t, factory(t))
	})
	t.Run("EventStoreCompactAggregateNoop", func(t *testing.T) {
		TestEventStoreCompactAggregateNoop(t, factory(t))
	})
```

(Add `"fmt"` to the suite.go imports if not present.)

- [ ] **Step 2: Run; verify it fails to compile**

Run: `go test ./internal/storage/sqlite/ -run TestCompliance/EventStoreCompactAggregate -v`
Expected: FAIL — `store.CompactAggregate undefined`, `storage.CompactResult undefined`.

- [ ] **Step 3: Add `CompactResult` + interface method**

In `internal/storage/storage.go`, near the other shared types:

```go
// CompactResult summarizes a CompactAggregate operation.
type CompactResult struct {
	AggregateID  ulid.ULID
	EventsBefore int64
	EventsAfter  int64
	Version      int64 // preserved high-water version
}
```

In the `EventStore` interface, after `ListAggregateIDs`:

```go
	// CompactAggregate folds the aggregate's event log and atomically replaces
	// it with a single HostCompacted seed event at the preserved high-water
	// version. No-op if the aggregate has <= 1 event. The whole operation is one
	// transaction; any failure rolls back and leaves the log intact.
	CompactAggregate(ctx context.Context, aggregateID ulid.ULID) (CompactResult, error)
```

- [ ] **Step 4: Add the `deleteEventsForAggregate` helper**

In `internal/storage/sqlite/eventstore.go`:

```go
// deleteEventsForAggregate removes all events for an aggregate. Caller must be
// inside a transaction.
func deleteEventsForAggregate(conn *sqlite.Conn, aggregateID ulid.ULID) error {
	return sqlitex.Execute(conn,
		`DELETE FROM events WHERE aggregate_id = ?`,
		&sqlitex.ExecOptions{Args: []any{aggregateID.String()}})
}
```

- [ ] **Step 5: Implement `CompactAggregate`**

In `internal/storage/sqlite/eventstore.go`:

```go
// CompactAggregate collapses an aggregate's event log to a single HostCompacted
// seed event at the preserved high-water version, atomically.
func (s *Storage) CompactAggregate(ctx context.Context, aggregateID ulid.ULID) (storage.CompactResult, error) {
	result := storage.CompactResult{AggregateID: aggregateID}
	err := s.withConn(ctx, func(conn *sqlite.Conn) (err error) {
		endFn, txErr := sqlitex.ImmediateTransaction(conn)
		if txErr != nil {
			return oops.Wrapf(txErr, "begin transaction")
		}
		defer endFn(&err)

		events, loadErr := loadEventsForAggregate(conn, aggregateID)
		if loadErr != nil {
			return loadErr
		}
		result.EventsBefore = int64(len(events))
		if len(events) <= 1 {
			result.EventsAfter = result.EventsBefore
			if len(events) == 1 {
				result.Version = events[0].Version
			}
			return nil // no-op
		}

		entry, replayErr := replayEvents(aggregateID, events)
		if replayErr != nil {
			return replayErr
		}
		if entry == nil {
			return oops.Errorf("compact: aggregate %s folded to nil", aggregateID)
		}

		highWater := events[len(events)-1].Version // events are ORDER BY version ASC
		seedEvent := domain.HostCompacted{
			IPAddress:        entry.IP,
			Hostname:         entry.Hostname,
			Aliases:          entry.Aliases,
			Comment:          entry.Comment,
			Tags:             entry.Tags,
			Deleted:          entry.Deleted,
			CreatedAt:        entry.CreatedAt,
			UpdatedAt:        entry.UpdatedAt,
			CompactedAt:      time.Now().UTC(),
			FoldedEventCount: int64(len(events)),
		}
		he, evErr := domain.NewHostEvent(seedEvent)
		if evErr != nil {
			return oops.Wrapf(evErr, "build compacted seed")
		}
		seed := domain.EventEnvelope{
			EventID:     ulid.Make(),
			AggregateID: aggregateID,
			Event:       he,
			Version:     highWater,
			CreatedAt:   time.Now().UTC(),
		}

		if delErr := deleteEventsForAggregate(conn, aggregateID); delErr != nil {
			return oops.Wrapf(delErr, "delete events for %s", aggregateID)
		}
		if insErr := insertEvent(conn, seed); insErr != nil {
			return oops.Wrapf(insErr, "insert compacted seed for %s", aggregateID)
		}
		result.EventsAfter = 1
		result.Version = highWater
		return nil
	})
	if err != nil {
		return storage.CompactResult{}, oops.Wrapf(err, "compact aggregate %s", aggregateID)
	}
	return result, nil
}
```

> Verify `time` is imported in `eventstore.go`; add it if not.

- [ ] **Step 6: Run the regression tests; verify they pass**

Run: `go test ./internal/storage/sqlite/ -run TestCompliance/EventStoreCompactAggregate -v`
Expected: PASS (both `EventStoreCompactAggregate` and `EventStoreCompactAggregateNoop`).

- [ ] **Step 7: Build (catch other implementers)**

Run: `go build ./...`
Expected: PASS. Add the two new methods to any test mock implementing `EventStore`/`storage.Storage`.

- [ ] **Step 8: Gate + commit**

Run: `task lint && task test`
Then: `jj commit -m "feat(storage): add CompactAggregate event-log compaction"`

---

## Task 4: Command-handler compaction (single + bulk, write-queued)

**Files:**
- Modify: `internal/server/commands.go`
- Test: `internal/server/commands_test.go`

Both commands route through `submitWrite` (the `WriteQueue`) so compaction serializes with `UpdateHost`/`DeleteHost`, exactly like `RollbackToSnapshot`.

- [ ] **Step 1: Write the failing test**

The existing `newTestHandler(t)` returns `(*CommandHandler, context.Context)` and does **not** expose its store (and `CommandHandler.store` is unexported), so these tests build the store explicitly to get a handle. Add a shared `seedBloated` helper (it's in `package server`, so Task 6's service test reuses it). Ensure `commands_test.go` imports `time` and `"github.com/fzymgc-house/router-hosts/internal/storage"` (it already imports `context`, `fmt`, `log/slog`, `ulid`, `domain`, `sqlite`).

```go
// seedBloated appends 1 HostCreated + (n-1) IPAddressChanged events to a fresh
// aggregate and returns its id. Shared by commands_test.go and service_test.go.
func seedBloated(t *testing.T, ctx context.Context, store storage.Storage, n int) ulid.ULID {
	t.Helper()
	id := ulid.Make()
	created, err := domain.NewHostEvent(domain.HostCreated{
		IPAddress: "10.0.0.1", Hostname: fmt.Sprintf("h-%s.local", id.String()[:8]),
		Aliases: []string{}, Tags: []string{}, CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.NoError(t, store.AppendEvent(ctx, id, domain.EventEnvelope{
		EventID: ulid.Make(), AggregateID: id, Event: created, Version: 1, CreatedAt: time.Now().UTC(),
	}, 0))
	for i := 1; i < n; i++ {
		ch, err := domain.NewHostEvent(domain.IPAddressChanged{
			NewIP: fmt.Sprintf("10.0.0.%d", i+1), ChangedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
		require.NoError(t, store.AppendEvent(ctx, id, domain.EventEnvelope{
			EventID: ulid.Make(), AggregateID: id, Event: ch, Version: int64(i + 1), CreatedAt: time.Now().UTC(),
		}, int64(i)))
	}
	return id
}

func newCompactTestStore(t *testing.T) (storage.Storage, context.Context) {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.New("file::memory:?mode=memory&cache=shared", slog.Default())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(ctx))
	t.Cleanup(func() { _ = store.Close() })
	return store, ctx
}

func TestCommandHandlerCompactAggregate(t *testing.T) {
	store, ctx := newCompactTestStore(t)
	h := NewCommandHandler(store)
	id := seedBloated(t, ctx, store, 15)

	res, err := h.CompactAggregate(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(15), res.EventsBefore)
	require.Equal(t, int64(1), res.EventsAfter)

	cnt, err := store.CountEvents(ctx, id)
	require.NoError(t, err)
	require.Equal(t, int64(1), cnt)
}

func TestCommandHandlerCompactAggregatesOver(t *testing.T) {
	store, ctx := newCompactTestStore(t)
	h := NewCommandHandler(store)
	big := seedBloated(t, ctx, store, 12)
	small := seedBloated(t, ctx, store, 2)

	results, err := h.CompactAggregatesOver(ctx, 5)
	require.NoError(t, err)
	require.Len(t, results, 1) // only the >5-event aggregate
	require.Equal(t, big.String(), results[0].AggregateID.String())

	cntSmall, err := store.CountEvents(ctx, small)
	require.NoError(t, err)
	require.Equal(t, int64(2), cntSmall) // untouched
}
```

> **Acceptance note (minor):** `CompactAggregatesOver` holds the write queue for the whole `ListAggregateIDs` + per-ID sweep, briefly blocking concurrent writes. Acceptable at this deployment's small host count; if host count grows, batch or chunk the sweep.

- [ ] **Step 2: Run; verify it fails**

Run: `go test ./internal/server/ -run TestCommandHandlerCompact -v`
Expected: FAIL — `h.CompactAggregate undefined`.

- [ ] **Step 3: Implement the command handlers**

In `internal/server/commands.go`:

```go
// CompactAggregate compacts a single aggregate, serialized through the write queue.
func (h *CommandHandler) CompactAggregate(ctx context.Context, id ulid.ULID) (storage.CompactResult, error) {
	var res storage.CompactResult
	err := h.submitWrite(ctx, func() error {
		var compErr error
		res, compErr = h.store.CompactAggregate(ctx, id)
		return compErr
	})
	if err != nil {
		return storage.CompactResult{}, err
	}
	return res, nil
}

// CompactAggregatesOver compacts every aggregate whose event count exceeds
// threshold. Selection (ListAggregateIDs + CountEvents) and each compaction run
// through the write queue. Aggregates compacted to <= threshold are skipped.
func (h *CommandHandler) CompactAggregatesOver(ctx context.Context, threshold int64) ([]storage.CompactResult, error) {
	var results []storage.CompactResult
	err := h.submitWrite(ctx, func() error {
		ids, listErr := h.store.ListAggregateIDs(ctx)
		if listErr != nil {
			return listErr
		}
		for _, id := range ids {
			count, cErr := h.store.CountEvents(ctx, id)
			if cErr != nil {
				return cErr
			}
			if count <= threshold {
				continue
			}
			res, compErr := h.store.CompactAggregate(ctx, id)
			if compErr != nil {
				return compErr
			}
			results = append(results, res)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}
```

> `storage` and `ulid` are already imported in `commands.go`.

- [ ] **Step 4: Run; verify it passes**

Run: `go test ./internal/server/ -run TestCommandHandlerCompact -v`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `task lint && task test`
Then: `jj commit -m "feat(server): add compaction command handlers"`

---

## Task 5: Proto `CompactAggregates` RPC

**Files:**
- Modify: `proto/router_hosts/v1/hosts.proto`
- Regenerate: `api/v1/router_hosts/v1/*.pb.go` via `task proto:generate`

- [ ] **Step 1: Add the RPC to the service block**

In `proto/router_hosts/v1/hosts.proto`, inside `service HostsService`, after `DeleteSnapshot`:

```proto
  // Compact bloated aggregates by folding their event log to a single event
  rpc CompactAggregates(CompactAggregatesRequest) returns (CompactAggregatesResponse);
```

- [ ] **Step 2: Add the messages**

Near the snapshot messages:

```proto
// Request to compact one aggregate or all aggregates over an event-count threshold
message CompactAggregatesRequest {
  oneof target {
    // Compact exactly this aggregate (ULID)
    string aggregate_id = 1;
    // Compact every aggregate whose event count exceeds this threshold
    int64 over_threshold = 2;
  }
  // If true, report what would be compacted without modifying anything
  bool dry_run = 3;
}

// Per-aggregate compaction result
message CompactedAggregate {
  string aggregate_id = 1;
  int64 events_before = 2;
  int64 events_after = 3;
  int64 version = 4; // preserved high-water (OCC) version — for audit/confirmation, not a write token
}

// Response after compaction
message CompactAggregatesResponse {
  repeated CompactedAggregate compacted = 1;
  int64 total_events_reclaimed = 2;
}
```

- [ ] **Step 3: Regenerate stubs**

Run: `task proto:generate`
Expected: updates `api/v1/router_hosts/v1/hosts.pb.go` (+ grpc stub) with `CompactAggregatesRequest`, `CompactAggregatesResponse`, `CompactedAggregate`, and `HostsServiceServer.CompactAggregates`.

- [ ] **Step 4: Verify generated types compile**

Run: `go build ./api/...`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `task lint`  (buf lint runs here; `task test` not needed — no Go logic yet, but run `go build ./...`)
Then: `jj commit -m "feat(proto): add CompactAggregates RPC"`

---

## Task 6: gRPC service handler

**Files:**
- Modify: `internal/server/service.go`
- Test: `internal/server/service_test.go`

Mirror `RollbackToSnapshot`: parse the request, delegate to the command handler, map results to the proto response, and call `mapError` on failure. (The command handler already does write-queue serialization, so the handler itself does not wrap in `submitWrite`.)

- [ ] **Step 1: Write the failing handler test**

The existing harness is `newServiceTestEnv(t) *serviceTestEnv` (service_test.go:41) with fields `client hostsv1.HostsServiceClient`, `store storage.Storage`, `handler *CommandHandler`. RPCs go through the bufconn `env.client`; seed via `env.store`. Reuse the `seedBloated` helper added in Task 4 (same `package server`). Ensure `service_test.go` imports `codes` (`google.golang.org/grpc/codes`) and `status` (`google.golang.org/grpc/status`) — existing invalid-ULID tests already use them.

```go
func TestService_CompactAggregates_Single(t *testing.T) {
	env := newServiceTestEnv(t)
	ctx := context.Background()
	id := seedBloated(t, ctx, env.store, 10)

	resp, err := env.client.CompactAggregates(ctx, &hostsv1.CompactAggregatesRequest{
		Target: &hostsv1.CompactAggregatesRequest_AggregateId{AggregateId: id.String()},
	})
	require.NoError(t, err)
	require.Len(t, resp.GetCompacted(), 1)
	require.Equal(t, int64(10), resp.GetCompacted()[0].GetEventsBefore())
	require.Equal(t, int64(1), resp.GetCompacted()[0].GetEventsAfter())
	require.Equal(t, int64(9), resp.GetTotalEventsReclaimed())
}

func TestService_CompactAggregates_InvalidID(t *testing.T) {
	env := newServiceTestEnv(t)
	_, err := env.client.CompactAggregates(context.Background(), &hostsv1.CompactAggregatesRequest{
		Target: &hostsv1.CompactAggregatesRequest_AggregateId{AggregateId: "not-a-ulid"},
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}
```

- [ ] **Step 2: Run; verify it fails**

Run: `go test ./internal/server/ -run TestService_CompactAggregates -v`
Expected: FAIL — `svc.CompactAggregates undefined`.

- [ ] **Step 3: Implement the handler**

In `internal/server/service.go`:

```go
// CompactAggregates compacts one aggregate or all aggregates over a threshold.
func (s *HostsServiceImpl) CompactAggregates(ctx context.Context, req *hostsv1.CompactAggregatesRequest) (*hostsv1.CompactAggregatesResponse, error) {
	var results []storage.CompactResult

	switch t := req.GetTarget().(type) {
	case *hostsv1.CompactAggregatesRequest_AggregateId:
		id, err := ulid.Parse(t.AggregateId)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid aggregate_id %q: %v", t.AggregateId, err)
		}
		if req.GetDryRun() {
			res, derr := s.dryRunOne(ctx, id)
			if derr != nil {
				return nil, mapError(derr)
			}
			results = []storage.CompactResult{res}
		} else {
			res, cerr := s.handler.CompactAggregate(ctx, id)
			if cerr != nil {
				return nil, mapError(cerr)
			}
			results = []storage.CompactResult{res}
		}
	case *hostsv1.CompactAggregatesRequest_OverThreshold:
		if req.GetDryRun() {
			res, derr := s.dryRunOver(ctx, t.OverThreshold)
			if derr != nil {
				return nil, mapError(derr)
			}
			results = res
		} else {
			res, cerr := s.handler.CompactAggregatesOver(ctx, t.OverThreshold)
			if cerr != nil {
				return nil, mapError(cerr)
			}
			results = res
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "target (aggregate_id or over_threshold) is required")
	}

	resp := &hostsv1.CompactAggregatesResponse{}
	var reclaimed int64
	for _, r := range results {
		resp.Compacted = append(resp.Compacted, &hostsv1.CompactedAggregate{
			AggregateId:  r.AggregateID.String(),
			EventsBefore: r.EventsBefore,
			EventsAfter:  r.EventsAfter,
			Version:      r.Version,
		})
		reclaimed += r.EventsBefore - r.EventsAfter
	}
	resp.TotalEventsReclaimed = reclaimed
	return resp, nil
}

// dryRunOne reports counts without mutating (events_after = events_before).
func (s *HostsServiceImpl) dryRunOne(ctx context.Context, id ulid.ULID) (storage.CompactResult, error) {
	count, err := s.store.CountEvents(ctx, id)
	if err != nil {
		return storage.CompactResult{}, err
	}
	v, err := s.store.GetCurrentVersion(ctx, id)
	if err != nil {
		return storage.CompactResult{}, err
	}
	return storage.CompactResult{AggregateID: id, EventsBefore: count, EventsAfter: count, Version: v}, nil
}

// dryRunOver reports which aggregates exceed threshold without mutating.
func (s *HostsServiceImpl) dryRunOver(ctx context.Context, threshold int64) ([]storage.CompactResult, error) {
	ids, err := s.store.ListAggregateIDs(ctx)
	if err != nil {
		return nil, err
	}
	var out []storage.CompactResult
	for _, id := range ids {
		count, cerr := s.store.CountEvents(ctx, id)
		if cerr != nil {
			return nil, cerr
		}
		if count > threshold {
			out = append(out, storage.CompactResult{AggregateID: id, EventsBefore: count, EventsAfter: count})
		}
	}
	return out, nil
}
```

> `status`, `codes`, `ulid`, `storage`, `hostsv1` are already imported in `service.go`.

- [ ] **Step 4: Run; verify it passes**

Run: `go test ./internal/server/ -run TestService_CompactAggregates -v`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

Run: `task lint && task test`
Then: `jj commit -m "feat(server): add CompactAggregates gRPC handler"`

---

## Task 7: CLI `compact` command

**Files:**
- Create: `internal/client/commands/compact.go`
- Modify: `internal/client/commands/root.go` (register the command)
- Test: `internal/client/commands/compact_test.go` (optional smoke — mirror existing command tests if present)

- [ ] **Step 1: Create the command**

`internal/client/commands/compact.go` (mirrors `snapshot.go` patterns — `newClientFromFlags`, `commandContext`, `Flags.Quiet`):

```go
package commands

import (
	"fmt"
	"log/slog"

	"github.com/samber/oops"
	"github.com/spf13/cobra"

	hostsv1 "github.com/fzymgc-house/router-hosts/api/v1/router_hosts/v1"
)

// newCompactCmd creates the "compact" command (single aggregate or --over N).
func newCompactCmd() *cobra.Command {
	var (
		over   int64
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "compact [aggregate-id]",
		Short: "Compact bloated aggregates (fold event log to a single event)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !cmd.Flags().Changed("over") {
				return oops.Errorf("provide an aggregate-id or --over N")
			}
			if len(args) == 1 && cmd.Flags().Changed("over") {
				return oops.Errorf("specify either an aggregate-id or --over, not both")
			}

			c, err := newClientFromFlags()
			if err != nil {
				return err
			}
			defer func() {
				if cerr := c.Close(); cerr != nil {
					slog.Warn("closing client connection", "error", cerr)
				}
			}()

			req := &hostsv1.CompactAggregatesRequest{DryRun: dryRun}
			if len(args) == 1 {
				req.Target = &hostsv1.CompactAggregatesRequest_AggregateId{AggregateId: args[0]}
			} else {
				req.Target = &hostsv1.CompactAggregatesRequest_OverThreshold{OverThreshold: over}
			}

			ctx, cancel := commandContext()
			defer cancel()

			resp, err := c.Hosts.CompactAggregates(ctx, req)
			if err != nil {
				return oops.Wrapf(err, "compacting aggregates")
			}

			if !Flags.Quiet {
				verb := "compacted"
				if dryRun {
					verb = "would compact"
				}
				for _, a := range resp.GetCompacted() {
					_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s %s: %d -> %d events (v%d)\n",
						verb, a.GetAggregateId(), a.GetEventsBefore(), a.GetEventsAfter(), a.GetVersion())
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "total events reclaimed: %d\n", resp.GetTotalEventsReclaimed())
			}
			return nil
		},
	}

	cmd.Flags().Int64Var(&over, "over", 0, "compact every aggregate with more than N events")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be compacted without changing anything")
	return cmd
}
```

- [ ] **Step 2: Register it**

In `internal/client/commands/root.go`, where other commands are added to the root command (find the `rootCmd.AddCommand(...)` / `newSnapshotCmd()` registration site):

```go
	rootCmd.AddCommand(newCompactCmd())
```

- [ ] **Step 3: Verify it builds and shows in help**

Run: `go build ./... && go run ./cmd/router-hosts compact --help`
Expected: builds; help shows `compact [aggregate-id]` with `--over` and `--dry-run` flags.

- [ ] **Step 4: Gate + commit**

Run: `task lint && task test`
Then: `jj commit -m "feat(client): add compact CLI command"`

---

## Task 8: Event-count observable-gauge metrics

**Files:**
- Modify: `internal/server/metrics.go` (new `RegisterAggregateEventGauges` method + const)
- Modify: `internal/client/commands/serve.go` (wire it where `store` + `metrics` are both in scope)
- Test: `internal/server/metrics_test.go`

The gauges are **observable (async)** — the value is pulled at scrape time. The callback closes over the `EventStore`; it is registered only when metrics are enabled (real `meterProvider`), and is a no-op for `DisabledMetrics` (nil `meterProvider`). No struct fields added (the gauges live in the callback registration), so `DisabledMetrics` is untouched.

- [ ] **Step 1: Write the failing test**

In `internal/server/metrics_test.go`:

```go
func TestRegisterAggregateEventGaugesNoopWhenDisabled(t *testing.T) {
	m := server.DisabledMetrics()
	// Must not panic / error when there is no meter provider.
	err := m.RegisterAggregateEventGauges(nil, 1000)
	require.NoError(t, err)
}
```

(A full end-to-end scrape assertion is covered by `task test` against a real meter provider; this guards the disabled path and the method's existence/signature.)

- [ ] **Step 2: Run; verify it fails**

Run: `go test ./internal/server/ -run TestRegisterAggregateEventGauges -v`
Expected: FAIL — `m.RegisterAggregateEventGauges undefined`.

- [ ] **Step 3: Add the const + method**

In `internal/server/metrics.go` (add `storage` import: `"github.com/fzymgc-house/router-hosts/internal/storage"`):

```go
// DefaultAggregateEventsWarnThreshold is the default per-aggregate event count
// above which an aggregate is counted by router_hosts_aggregates_over_threshold.
const DefaultAggregateEventsWarnThreshold int64 = 1000

// RegisterAggregateEventGauges registers two observable gauges that report
// per-aggregate event growth, pulled at scrape time. No-op when metrics are
// disabled (nil meter provider). The callback iterates ListAggregateIDs +
// CountEvents; acceptable at this deployment's scale.
func (m *Metrics) RegisterAggregateEventGauges(store storage.EventStore, warnThreshold int64) error {
	if m.meterProvider == nil || store == nil {
		return nil
	}
	meter := m.meterProvider.Meter("router-hosts")

	maxGauge, err := meter.Int64ObservableGauge("router_hosts_aggregate_events_max",
		otelmetric.WithDescription("Maximum event count across all aggregates"),
	)
	if err != nil {
		return oops.Wrapf(err, "create aggregate_events_max gauge")
	}
	overGauge, err := meter.Int64ObservableGauge("router_hosts_aggregates_over_threshold",
		otelmetric.WithDescription("Number of aggregates whose event count exceeds the warn threshold"),
	)
	if err != nil {
		return oops.Wrapf(err, "create aggregates_over_threshold gauge")
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o otelmetric.Observer) error {
			ids, listErr := store.ListAggregateIDs(ctx)
			if listErr != nil {
				return listErr
			}
			var maxCount, over int64
			for _, id := range ids {
				c, cErr := store.CountEvents(ctx, id)
				if cErr != nil {
					return cErr
				}
				if c > maxCount {
					maxCount = c
				}
				if c > warnThreshold {
					over++
				}
			}
			o.ObserveInt64(maxGauge, maxCount)
			o.ObserveInt64(overGauge, over)
			return nil
		},
		maxGauge, overGauge,
	)
	if err != nil {
		return oops.Wrapf(err, "register aggregate-event gauge callback")
	}
	return nil
}
```

- [ ] **Step 4: Run; verify it passes**

Run: `go test ./internal/server/ -run TestRegisterAggregateEventGauges -v`
Expected: PASS.

- [ ] **Step 5: Wire it into serve**

In `internal/client/commands/serve.go`, inside the `if cfg.Metrics != nil && cfg.Metrics.OTel != nil { ... }` block, after `metrics, err = server.NewMetricsFromConfig(...)` succeeds (and `store` is in scope from earlier in the function):

```go
		if rerr := metrics.RegisterAggregateEventGauges(store, server.DefaultAggregateEventsWarnThreshold); rerr != nil {
			return oops.Wrapf(rerr, "register aggregate-event gauges")
		}
```

- [ ] **Step 6: Build + gate + commit**

Run: `go build ./... && task lint && task test`
Then: `jj commit -m "feat(server): add aggregate event-count gauges"`

---

## Final verification (after all tasks)

- [ ] Run the full pipeline: `task ci` (lint + test + build + buf). Expected: all green, coverage ≥80%.
- [ ] Manual smoke against a dev server: `router-hosts compact --over 1000 --dry-run` lists candidates; `router-hosts compact <id>` reports `N -> 1 events`; a follow-up `host get <id>` shows identical state at the preserved version, and `host update <id> --version <V> ...` succeeds (OCC unbroken).
- [ ] Confirm `eda.5` (verify #323) can now be exercised: the regression test in Task 3 (`TestEventStoreCompactAggregate`) already demonstrates compact-then-update-at-preserved-version; `eda.5` adds the operator-level end-to-end check.

## Spec coverage check

| Spec requirement | Task |
|------------------|------|
| `HostCompacted` seed event (6 registration sites) | 1 |
| Faithful fold (byte-identical, incl. timestamps + Deleted) | 1, 3 |
| `ListAggregateIDs` (incl. deleted) | 2 |
| `CompactAggregate` atomic fold+replace, preserve version, no-op ≤1 | 3 |
| Deleted-aggregate handling (uniform via `HostCompacted.Deleted`) | 1, 3 |
| Write-queue serialization | 4 |
| `compact <id>` / `compact --over N` / `--dry-run` | 5, 6, 7 |
| `CompactAggregates` RPC | 5, 6 |
| Cardinality-safe observable-gauge metrics | 8 |
| Regression for #330/#323 (compact→update-at-version) | 3 |
<!-- adr-capture: sha256=5d480f58a68c787e; session=cli; ts=2026-06-26T17:15:52Z; adrs=router-hosts-v5b,router-hosts-vl8,router-hosts-4w2 -->
