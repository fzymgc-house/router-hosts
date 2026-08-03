# Phase 2: Cursor-Based Lazy Storage Reads - Research

**Researched:** 2026-08-03
**Domain:** Go event-sourced SQLite storage layer, gRPC streaming, allocation benchmarking
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Requirement Accuracy**
- **D-01:** LAZY-02/ROADMAP SC2's "total event-log size" claim was already true before this phase began (`ListAll` never held every aggregate's full log at once). The wording is amended to **total entry count**, which is what the cursor genuinely bounds. Amendment routed through the GSD verb surface with user sign-off (rule `01ygyqn0by`), mirroring TMPL-06's 2026-07-31 precedent.
- **D-01a:** The ROADMAP's claim that `hosts` **and** `json` sort globally is wrong. Only `hosts` (via `FormatHostsFile`) sorts. `json`/`csv` do not sort. The highest-risk requirement is narrower than the roadmap believed.

**ExportHosts Format Scope**
- **D-02:** `hosts` format is **descoped** — drains the cursor, sorts, renders as today. Residual `O(N entries)` named explicitly (sanctioned by `REQUIREMENTS.md:123`).
- **D-03:** `json` and `csv` are **stream-rendered** page by page into a writer flushing at the existing 64 KiB `exportChunkSize` boundary, replacing today's three full materializations (`entries` + `out`/`csvBuf` + `data`). `json` must reproduce `MarshalIndent(out, "", "  ")`'s exact two-space layout byte-for-byte (pinned by golden fixture, D-14). The empty-payload single-message carve-out in `sendExportChunks` (review L14) MUST survive.
- **D-04:** Migration scope is the two named consumers plus three free wins:
  - `internal/server/service.go:687` `ExportHosts` (LAZY-02)
  - `internal/server/watch.go:97` `sendSnapshot`/`WatchHosts` (LAZY-02, already entry-at-a-time)
  - `internal/server/service.go:200` hook entry-count (`len()` only)
  - `internal/storage/sqlite/projection.go:78`/`:92` `FindByIPAndHostname`/`Search`
  **Not migrating:** `hostsfile.go:31`, `unboundconf.go:55`, `dnsmasqconf.go:46` (sort globally, would be descoped anyway); `service.go:765` `CreateSnapshot`, `:884` `RollbackToSnapshot` (need the full set); `commands.go:451` (pending Q-04, now resolved — see Open Questions).

**Cursor API Shape and Granularity**
- **D-05:** Published interface gains a **stateless keyset page function** shaped roughly `ListPage(ctx, after ulid.ULID, limit int) (entries []domain.HostEntry, next ulid.ULID, done bool, err error)`. Chosen over a stateful cursor object and over `iter.Seq2` range-over-func. Exact signature is Claude's discretion. Accepted consequence: `withConn` returns its pool connection per call, so consecutive pages run on different connections — no cross-page read snapshot is structurally available.
- **D-06:** Pages are **per-aggregate and entry-counted**. `loadEventsForAggregate` + `replayEvents` stay atomic within one page fetch — a reader can never observe half an aggregate's history. **LAZY-03's literal scenario is therefore unreachable by construction**, satisfied by documenting that impossibility and pinning the two reachable variants: (1) compacting an aggregate the cursor has not yet reached → reader sees the `HostCompacted`-derived entry at the preserved OCC version; (2) compacting an aggregate the cursor has already passed → invisible to this cursor, reader keeps the pre-compaction value already emitted. Event-budgeted pages were considered and rejected (deferred idea).
- **D-07:** `ListAll` **stays**, reimplemented as a thin drain loop over `ListPage`. This makes the new `ORDER BY` reach **all seven untouched callers**, not just migrated ones — D-14's golden fixtures must cover them.
- **D-08:** A page **fills to N live entries** — `ListPage` loops internally over aggregates until it has N live entries or the store is exhausted. A short page means, and only means, `done`. Precedent: `sendExportChunks`'s review-L14 carve-out.

**Mid-Stream Consistency**
- **D-09:** Contract is **documented precisely rather than strengthened**: every aggregate present at cursor start is yielded exactly once in ascending aggregate-ULID order (IDs immutable); an aggregate created mid-read normally sorts ahead and is included, but the CONTEXT.md text as drafted overstates the same-millisecond ambiguity — see the correction under Code Examples/Pitfalls; an entry's value reflects the instant its page was fetched, not one global instant (the real weakness). Continuous with TMPL-08 and issue #401.
- **D-10:** Keyset forces an explicit `ORDER BY aggregate_id`, becoming a documented, tested contract. **Verified empirically this session** — see Open Questions Q-01 — that it reproduces today's de-facto order exactly.

**Benchmark Rig**
- **D-11:** Benchmark asserts a **ratio across two fixtures** (~1k and ~10k entries): paged path's peak allocation stays flat within tolerance as entry count grows 10×, drained path scales roughly linearly. No absolute ceiling.
- **D-12:** Fixture is **mixed-depth with deleted aggregates** — mostly shallow, a deliberate minority deep, a realistic share deleted.
- **D-13:** Benchmark lives behind its **own build tag with its own CI job**, folded into `ci-go-complete`, mirroring Phase 1's job pattern exactly. Must run outside `-race` (which both slows a 10k fixture and perturbs allocation accounting). **Proven RED on a Linux runner before acceptance** (Phase 1 D-16, memory `cq0rfk0qjc`).
- **D-14:** LAZY-04 proven by **golden fixtures captured before any behavior change**, in the phase's first plan, covering: `ExportHosts`'s `hosts`/`json`/`csv`; the client-side v0.13.0 consumer-template rendering; the three non-migrating regeneration writers (downstream of D-10's new ordering via D-07's wrapper even though they don't migrate).

### Claude's Discretion
- Exact `ListPage` signature and option surface within D-05's shape
- Default page size: constant, package var (`renderDrainLimit`/`MaxTrackedSinks` precedent), or caller-only
- Whether the deleted-aggregate filter runs in SQL or in Go after replay (Q-03, informed by research below)
- The streaming writer's internal shape for D-03, given the 64 KiB boundary and empty-payload behavior are preserved
- Build-tag name, runner profile, and timeout for D-13's job
- Whether `SnapshotComplete.Count` accumulates during paging or is derived

### Deferred Ideas (OUT OF SCOPE)
- Event-budgeted pages (bound the deep-aggregate term too) — revisit if a real deployment produces a deep-enough aggregate
- Two-pass key sort for the `hosts` format — collides with the chosen consistency contract
- Stateful cursor object holding a read snapshot — reconsider alongside issue #401
- Fencing with `LatestEventID` to detect a torn export — cheapest upgrade if operators report inconsistent exports
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-------------------|
| LAZY-01 | `storage.HostProjection` exposes a keyset cursor read; published interface change, not internal optimization | Code Examples: `ListPage` query pattern; `storage.go:120-126` interface site confirmed by Read this session |
| LAZY-02 | `ExportHosts`/`WatchHosts` peak memory tracks page size not entry count, proven by measured `AllocsPerRun`/memstats benchmark against a 10k+ fixture | Validation Architecture section; Pitfall "AllocsPerRun measures the wrong quantity"; verified streaming-json reproduction (Q-05) removes D-03's fallback risk |
| LAZY-03 | Cursor mid-compaction lands on `HostCompacted` seed at preserved OCC version, documented + tested | `CompactAggregate` read this session (`eventstore.go:255-345`); confirms same `aggregate_id` is reused so cursor position is unaffected by compaction timing |
| LAZY-04 | Byte-identical rendered output before/after, every format | Q-01 empirical proof (`ORDER BY` is a no-op); Q-05 empirical proof (streaming JSON is byte-identical); existing test/golden-fixture inventory documented below |
</phase_requirements>

## Summary

This phase adds a keyset-paginated read path to `storage.HostProjection` and rewires `ExportHosts`/`WatchHosts` to consume it, while proving the memory claim with a real benchmark rather than an API-shape argument. The codebase investigation this session resolved every blocking open question CONTEXT.md left for research:

- **Q-01 (ORDER BY no-op) — CONFIRMED by execution**, twice: a 5-row hand-built case and a 2000-aggregate/random-order/random-version-count case, both against the exact production schema and index (`idx_events_aggregate ON events(aggregate_id, event_version)`). SQLite's query planner already answers `SELECT DISTINCT aggregate_id FROM events` via `SCAN ... USING COVERING INDEX idx_events_aggregate`, which yields ascending order for free — adding an explicit `ORDER BY aggregate_id` changes nothing observable.
- **Q-02 (WAL mode) — CONFIRMED absent.** No `PrepareConn` hook is passed to `sqlitex.NewPool` (`sqlite.go:42-49`) and no `journal_mode` pragma appears anywhere in `internal/storage/sqlite`. The pool runs SQLite's compiled-in default (rollback/DELETE journal), not WAL. A single pinned connection reading across pages would therefore **block concurrent writers** for its duration — not a free upgrade path, and worth stating plainly in D-09's contract documentation.
- **Q-04 (`commands.go:451`) — RESOLVED.** It is `CommandHandler.ListHosts`, feeding the streaming `ListHosts` RPC (`service.go:360`), which sends entries in whatever order the store returns with no client-visible sort and no test pinning order. D-10's new ordering is cosmetic here — safe, no golden-fixture risk.
- **Q-05 (json byte-identical streaming) — CONFIRMED possible, no fallback needed.** A per-element `json.MarshalIndent(elem, "  ", "  ")` framed manually with `"[\n"`, `",\n"` / `"\n"` separators, and `"]"` reproduces `json.MarshalIndent(out, "", "  ")` byte-for-byte for the empty, single-element, and multi-element cases (verified by a standalone Go program this session). This removes the stated risk from D-03 entirely — the planner does not need to budget for a buffered-json fallback.
- **A correction to D-09's own justification:** the weak-contract wording in CONTEXT.md attributes same-millisecond ordering ambiguity to `ulid.Make()`. Production aggregate-ID minting does **not** use `ulid.Make()` — `CommandHandler.newID()` (`commands.go:56-58`) mints through the shared `internal/eventid` singleton generator, which is read-this-session confirmed strictly monotonic even within one millisecond (`eventid.go:49-61`). Within this single-process, single-`WriteQueue` deployment model, there is no same-millisecond tie for newly created aggregates. D-09's *decision* (document, don't strengthen) stands, but the doc text should not cite `ulid.Make()`'s weakness as the reason — the real remaining gap is purely "value freshness is per-page, not per-read," as D-09 already separately states.

**Primary recommendation:** Implement `ListPage` as a stateless keyset function backed by `WHERE aggregate_id > ? ORDER BY aggregate_id LIMIT ?` against the existing `idx_events_aggregate` covering index (no migration needed), reimplement `ListAll` as a drain loop over it, stream `json`/`csv` per-element into the existing 64 KiB chunker using the verified byte-identical framing pattern below, and measure peak memory with a `runtime.MemStats`-based sampler rather than relying on `testing.AllocsPerRun` alone (it measures allocation *count*, not peak *live* bytes — see Pitfalls).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Keyset pagination query | Database/Storage | — | `storage/sqlite/projection.go` owns the SQL; no new schema needed, existing covering index already ascending-sorted |
| `HostProjection` interface change | API/Backend (storage package) | — | `storage.go:120-126` is the published Go interface every backend and the conformance suite must satisfy |
| Streaming render (`json`/`csv`) | API/Backend | — | `internal/server/service.go` `ExportHosts`; writes directly to the gRPC stream via the existing `exportChunkSender` |
| Peak-memory benchmark | API/Backend (test infra) | CI/CD | New build-tagged Go benchmark + CI job, mirrors Phase 1's `e2e-docker`/`e2e-proc` pattern |
| Compaction/cursor interaction | Database/Storage | API/Backend | `CompactAggregate` (eventstore.go) is storage-layer; the cursor's observed behavior is a storage-layer contract documented for API-layer consumers |
| Client-side template rendering (unaffected) | Browser/Client (CLI process) | — | Consumes `WatchHosts` stream; ordering contract change is transparent as long as byte-identity holds |

## Standard Stack

No new external dependencies. This phase is implemented entirely with:

### Core (already in go.mod — no install needed)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|---------------|
| `zombiezen.com/go/sqlite` | v1.4.2 `[VERIFIED: go.mod]` | Pure-Go SQLite driver, keyset query execution | Already the project's sole storage backend |
| `github.com/oklog/ulid/v2` | v2.1.2 `[VERIFIED: go.mod]` | ULID parse/compare for cursor `after` parameter | Already used throughout the domain layer |
| `encoding/json`, `encoding/csv` (stdlib) | Go 1.26.5 `[VERIFIED: go.mod]` | Streaming render for `json`/`csv` formats | No third-party JSON streaming library needed — verified hand-rolled framing reproduces `MarshalIndent` exactly (see Code Examples) |
| `testing`, `runtime` (stdlib) | Go 1.26.5 | Benchmark + peak-memory measurement | `testing.AllocsPerRun`, `runtime.MemStats` — verified via `go doc` this session |

### Supporting (already in go.mod)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `github.com/stretchr/testify` | v1.11.1 `[VERIFIED: go.mod]` | Assertions in the conformance suite / golden fixture tests | Every existing storage/server test uses it |
| `pgregory.net/rapid` | v1.3.0 `[VERIFIED: go.mod]` | Property-based testing, project convention (CLAUDE.md) | Optional for the keyset conformance test (e.g., proving exactly-once-per-aggregate across arbitrary page sizes) |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-framed streaming JSON | A streaming JSON library (`json-iterator`, `segmentio/encoding`) | Unnecessary — stdlib reproduces the exact byte layout; adding a dependency for this is pure risk with no upside, and this project's Out of Scope list already rejects unnecessary machinery |
| `runtime.MemStats` peak sampling | `runtime/pprof` heap profile diffing | pprof heap profiles are *sampled* (1-in-512KB by default) and better suited to finding allocation sites than proving a flat-vs-linear peak-memory ratio across two fixture sizes; MemStats sampling is simpler and directly answers D-11's question |
| Stateless `ListPage` function | `iter.Seq2[domain.HostEntry, error]` range-over-func | Rejected in CONTEXT.md D-05 — hides paging, reads as internal optimization, violates LAZY-01's "published interface change" requirement. Go 1.26.5 `[VERIFIED: go.mod]` supports it fine; not a version constraint |

**Installation:** None required — no `go get` / `npm install` step for this phase.

## Package Legitimacy Audit

**Not applicable.** This phase introduces zero new external packages (Go or otherwise). Every library used is already present in `go.mod` and was installed by a prior phase. The Package Legitimacy Gate protocol's registry checks are skipped because there is nothing new to check.

## Architecture Patterns

### System Architecture Diagram

```
                    ┌─────────────────────────────────────────┐
                    │         gRPC client (CLI / sink)         │
                    └───────────────┬───────────────┬─────────┘
                                     │ ExportHosts   │ WatchHosts
                                     ▼               ▼
                    ┌─────────────────────────────────────────┐
                    │      internal/server (API tier)          │
                    │                                           │
                    │  ExportHosts(format)                      │
                    │   ├─ "hosts" → drain ListPage loop         │
                    │   │            (D-02: descoped, O(N))     │
                    │   ├─ "json"  → per-page streaming render  │
                    │   │            → sendExportChunks (64KiB) │
                    │   └─ "csv"   → per-page streaming render  │
                    │                → sendExportChunks (64KiB) │
                    │                                           │
                    │  sendSnapshot (WatchHosts)                │
                    │   └─ drain ListPage loop, entry-at-a-time │
                    │      Send (already lazy pre-phase)        │
                    └───────────────┬───────────────────────────┘
                                    │ storage.HostProjection.ListPage(ctx, after, limit)
                                    ▼
                    ┌─────────────────────────────────────────┐
                    │   internal/storage/sqlite (Storage tier)  │
                    │                                           │
                    │  ListPage:                                │
                    │   1. SELECT DISTINCT aggregate_id          │
                    │      WHERE aggregate_id > ?                │
                    │      ORDER BY aggregate_id LIMIT ?         │
                    │      (covering index idx_events_aggregate) │
                    │   2. loop: loadEventsForAggregate + replay │
                    │      until N live entries or exhausted     │
                    │      (D-08 fill-to-N; skips deleted/tombs) │
                    │   3. return (entries, next cursor, done)   │
                    │                                           │
                    │  ListAll = drain loop over ListPage (D-07) │
                    │  withConn: one pool connection PER CALL    │
                    │  (D-05 consequence — no cross-page snapshot│
                    │   possible; journal mode is NOT WAL, see   │
                    │   Q-02 below)                              │
                    └───────────────┬───────────────────────────┘
                                    ▼
                    ┌─────────────────────────────────────────┐
                    │   SQLite events table (single file)       │
                    │   idx_events_aggregate(aggregate_id,       │
                    │                        event_version)      │
                    └─────────────────────────────────────────┘
```

### Recommended Project Structure

No new directories. Changes land in existing files:

```
internal/storage/
├── storage.go              # HostProjection gains ListPage (LAZY-01)
├── sqlite/
│   ├── projection.go        # ListPage impl; ListAll becomes drain loop over it
│   └── projection_bench_test.go  # NEW — build-tagged peak-memory benchmark (D-13)
└── storagetest/
    └── suite.go              # NEW conformance tests: keyset paging, exactly-once,
                               # compaction-mid-cursor (LAZY-03), ORDER BY contract (D-10)

internal/server/
├── service.go                # ExportHosts: json/csv become streaming writers (D-03)
└── watch.go                  # sendSnapshot: swap ListAll for ListPage drain loop (D-04)

.github/workflows/ci-go.yml   # NEW job for D-13's benchmark tier, folded into
                               # ci-go-complete's needs: list (Phase 1 D-01/D-02 pattern)
Taskfile.yml                  # NEW task target for the benchmark tier
```

### Pattern 1: Keyset Pagination Query (LAZY-01)

**What:** Page through distinct aggregate IDs using `aggregate_id > ?` rather than `OFFSET`, backed by the existing covering index.
**When to use:** Every `ListPage` call.
**Verified this session** — `EXPLAIN QUERY PLAN` on the production schema confirms `idx_events_aggregate(aggregate_id, event_version)` already services this query without a temp B-tree:

```sql
-- Source: verified this session against internal/storage/sqlite/migrations/001_initial.sql
-- schema + a 2000-aggregate randomized fixture (see Sources)
SELECT DISTINCT aggregate_id
FROM events
WHERE aggregate_id > ?
ORDER BY aggregate_id
LIMIT ?
```

```go
// Source: pattern derived from existing getDistinctAggregateIDs
// (internal/storage/sqlite/projection.go:315-333), read this session.
// after is the zero ULID for the first page.
func getAggregateIDPage(conn *sqlite.Conn, after ulid.ULID, limit int) ([]ulid.ULID, error) {
    var ids []ulid.ULID
    err := sqlitex.Execute(conn,
        `SELECT DISTINCT aggregate_id FROM events
         WHERE aggregate_id > ? ORDER BY aggregate_id LIMIT ?`,
        &sqlitex.ExecOptions{
            Args: []any{after.String(), limit},
            ResultFunc: func(stmt *sqlite.Stmt) error {
                id, parseErr := ulid.Parse(stmt.ColumnText(0))
                if parseErr != nil {
                    return parseErr
                }
                ids = append(ids, id)
                return nil
            },
        })
    if err != nil {
        return nil, oops.Wrapf(err, "get aggregate id page after %s", after)
    }
    return ids, nil
}
```

No schema migration is required — `idx_events_aggregate` already exists (`migrations/001_initial.sql:12`) and already covers this exact query shape.

### Pattern 2: D-08 Fill-to-N with Deleted-Aggregate Skip

**What:** `ListPage` must keep pulling aggregate-ID batches and replaying them until it has accumulated N *live* (non-deleted) entries, or the aggregate-ID space is exhausted — a short page must mean `done`, never "try again."
**When to use:** `ListPage`'s internal loop.
**Existing precedent this pattern must not regress:** `sendExportChunks`'s review-L14 empty-payload carve-out — this repo already paid once for a drain loop that broke on an empty-but-not-done response (`service.go:656-663`, read this session).

```go
// Source: pattern only — combines the existing getDistinctAggregateIDs query
// shape (now keyset-bounded, Pattern 1) with the existing per-aggregate
// loadEventsForAggregate/replayEvents pair (projection.go:154, :336).
// Sketch, not a verified byte-for-byte quote.
func (s *Storage) ListPage(ctx context.Context, after ulid.ULID, limit int) (entries []domain.HostEntry, next ulid.ULID, done bool, err error) {
    err = s.withConn(ctx, func(conn *sqlite.Conn) error {
        cursor := after
        for len(entries) < limit {
            // Fetch a batch of aggregate IDs larger than the remaining need,
            // since some will be deleted/tombstoned and yield no live entry.
            ids, idErr := getAggregateIDPage(conn, cursor, limit-len(entries))
            if idErr != nil {
                return idErr
            }
            if len(ids) == 0 {
                done = true
                return nil // exhausted — short page, but done=true
            }
            for _, id := range ids {
                cursor = id
                events, loadErr := loadEventsForAggregate(conn, id)
                if loadErr != nil {
                    return loadErr
                }
                entry, replayErr := replayEvents(id, events)
                if replayErr != nil {
                    return replayErr
                }
                if entry != nil && !entry.Deleted {
                    entries = append(entries, *entry)
                }
                if len(entries) >= limit {
                    break
                }
            }
        }
        next = cursor
        return nil
    })
    return entries, next, done, err
}
```

### Pattern 3: Byte-Identical Streaming JSON (D-03, resolves Q-05)

**What:** Reproduce `json.MarshalIndent(out, "", "  ")`'s exact byte layout while writing one element at a time.
**Verified this session** by direct execution (Go program, `bytes.Equal` against the buffered baseline) for empty, single-element, and multi-element inputs — all matched exactly:

```go
// Source: verified this session (standalone Go program, see Sources) —
// bytes.Equal(buffered, streamed) == true for empty/one/two-element cases.
func writeJSONStream(w io.Writer, first bool, isLast bool, elem jsonEntry) error {
    if first {
        if _, err := io.WriteString(w, "["); err != nil {
            return err
        }
    }
    // Empty-inventory case: the buffered baseline emits "[]" for a non-nil
    // empty slice (make([]jsonEntry, 0)) — NEVER "null". A nil slice would
    // marshal to "null" (verified this session) — service.go:712 always
    // constructs a non-nil slice via make(), so this divergence cannot occur
    // with the current entry-building code; preserve that non-nil invariant
    // in the streaming rewrite.
    b, err := json.MarshalIndent(elem, "  ", "  ")
    if err != nil {
        return err
    }
    if _, err := io.WriteString(w, "\n  "); err != nil {
        return err
    }
    if _, err := w.Write(b); err != nil {
        return err
    }
    if isLast {
        _, err = io.WriteString(w, "\n]")
    } else {
        _, err = io.WriteString(w, ",")
    }
    return err
}
// Empty-entries case (zero elements): write exactly "[]" — matches
// json.MarshalIndent(make([]jsonEntry, 0), "", "  ").
```

### Pattern 4: Peak-Memory Sampling (D-11/D-12, resolves Q-06)

**What:** `testing.AllocsPerRun` reports the *mean allocation count* across repeated calls — it does not measure peak *live* heap bytes, and total cumulative bytes allocated (`-benchmem`'s B/op, or a before/after `TotalAlloc` delta) also scales with total entries touched in **both** the paged and drained paths, since both eventually process every entry. Neither proves D-11's "peak stays flat" claim by itself. The technique that does: sample `runtime.MemStats.HeapAlloc` at short intervals *during* the call and track the maximum observed value.
**Verified via `go doc` this session:** `testing.AllocsPerRun` forces `GOMAXPROCS=1` during measurement and runs the function once as warm-up before averaging — both relevant to D-13's own-build-tag isolation from `-race`.

```go
// Source: pattern only, informed by go doc testing.AllocsPerRun and
// go doc runtime.MemStats (verified this session), plus general Go community
// guidance on HeapAlloc sampling for peak-memory measurement.
func peakHeapDuring(f func()) (peakBytes uint64) {
    done := make(chan struct{})
    var ms runtime.MemStats
    go func() {
        ticker := time.NewTicker(200 * time.Microsecond)
        defer ticker.Stop()
        for {
            select {
            case <-done:
                return
            case <-ticker.C:
                runtime.ReadMemStats(&ms)
                if ms.HeapAlloc > peakBytes {
                    peakBytes = ms.HeapAlloc
                }
            }
        }
    }()
    runtime.GC()
    f()
    close(done)
    return peakBytes
}
```

**Caveat to name in the plan:** `runtime.ReadMemStats` briefly stops the world; polling too aggressively (sub-100µs) perturbs the very thing being measured. A 100-500µs interval is a reasonable starting point; the plan should record whatever interval it settles on and note it is a sampled approximation, not an exact peak.

### Anti-Patterns to Avoid
- **Trusting `AllocsPerRun`/`-benchmem` alone to prove "peak" claims:** they report cumulative totals across the call, not the high-water mark at any instant. Both paths touch every entry eventually, so cumulative allocation count/bytes will scale with N for both the paged and drained paths — only the sampled peak distinguishes them. This is the single most important correction this research makes to the literal LAZY-02 wording ("proven by a measured benchmark (`AllocsPerRun`/memstats)") — treat `memstats` as the load-bearing half via peak sampling, with `AllocsPerRun`/`-benchmem` as a secondary, weaker signal.
- **Adding a `journal_mode=wal` pragma as a side effect of this phase:** it would change `withConn`'s per-call connection behavior (D-05's accepted consequence) and is explicitly a **deferred** upgrade path per the stateful-cursor rejection — not this phase's scope. Confirmed absent today (Q-02); do not introduce it incidentally while touching `sqlite.go`.
- **Re-deriving Q-01/Q-05 by reading the query/marshaler instead of running it:** both were settled this session by execution, per this project's own standing rule (memory `b9gbp3bp20`, cited in CONTEXT.md). The planner should still have an executor re-run these as pinned tests (not just trust this document), but should not need to re-litigate them by inspection.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| Keyset pagination cursor encoding | A custom opaque cursor token/base64 blob | The aggregate's own ULID as the cursor value | ULIDs are already the aggregate identity and are lexicographically sortable — no encoding layer needed, and D-05 explicitly chose "caller owns page size, cursor is the last-seen aggregate ID" over a stateful/opaque cursor |
| Peak-memory measurement | A hand-rolled memory profiler or reimplementing pprof sampling | `runtime.MemStats.HeapAlloc` polling (Pattern 4) | This is a small, well-understood technique; building anything more elaborate (e.g., a custom allocator hook) is disproportionate to a benchmark that runs in one CI job |
| JSON streaming byte-identity | A third-party streaming JSON encoder | Stdlib `encoding/json.MarshalIndent` per-element + manual framing (Pattern 3) | Verified byte-identical this session; a third-party encoder's indent behavior is a new unverified byte-format risk for zero benefit |

**Key insight:** every mechanism this phase needs — keyset queries, streaming writers, peak-memory sampling — already has a minimal stdlib or already-vendored-library answer. The risk in this phase is not "what library solves this" but "does the byte-level and memory-level behavior actually match the claim," which is why this research prioritized empirical verification over library selection.

## Common Pitfalls

### Pitfall 1: `AllocsPerRun` measures the wrong quantity for LAZY-02's claim
**What goes wrong:** A benchmark using only `testing.AllocsPerRun` or `-benchmem`'s allocs/op and B/op will show both the paged and drained paths scaling with N (both touch every entry), producing a benchmark that looks like it disproves the phase's own thesis.
**Why it happens:** These tools report *cumulative* allocation over the call, not the *peak simultaneously-live* heap — and cumulative allocation for "touch N entries once" is O(N) regardless of whether you hold them all at once or one page at a time.
**How to avoid:** Use peak-sampling (Pattern 4) as the primary metric for D-11's ratio assertion; report `AllocsPerRun`/B/op as a secondary, informational figure only.
**Warning signs:** A "ratio" that comes out close to 1:1 for both paths despite the code clearly not accumulating — check whether the benchmark is reading `TotalAlloc`/allocs-count instead of a sampled peak.

### Pitfall 2: `json.MarshalIndent` on a nil slice vs. an empty slice
**What goes wrong:** `json.MarshalIndent(nil, "", "  ")` produces the 4-byte literal `null`, not `[]`. If a streaming rewrite ever constructs its "no entries" case from a nil slice instead of explicitly emitting `"[]"`, LAZY-04's byte-identity breaks silently for the empty-inventory case.
**Why it happens:** Go's `encoding/json` treats nil slices and empty-but-non-nil slices differently by design (this is a`nil`-vs-`[]`gotcha).
**How to avoid:** The existing code always builds `out := make([]jsonEntry, len(entries))` (never nil), so this divergence cannot occur today — but the streaming rewrite must preserve an explicit `"[]"` literal for the zero-entries case rather than falling through to whatever a generic "no first element written" code path would naturally produce.
**Warning signs:** A golden-fixture test for the empty-inventory `json` format is the direct guard; write it before touching `ExportHosts`'s json branch (D-14 already requires this).

### Pitfall 3: Rollback-journal mode, not WAL — a cross-page read is not a snapshot
**What goes wrong:** Assuming `ListPage`'s successive calls (each on a possibly-different pooled connection) see a consistent point-in-time view of the database, the way a single long-lived WAL read transaction would.
**Why it happens:** WAL mode is a common enough SQLite default assumption that it's easy to assume without checking. This project does not configure it (Q-02, confirmed by reading `sqlite.go:42-49` this session — no `PrepareConn`, no pragma anywhere in `internal/storage/sqlite`).
**How to avoid:** D-09's contract documentation should state plainly that a paged read sees a snapshot-per-page, not snapshot-for-the-whole-read, and that this is unrelated to whether WAL is enabled — it follows directly from D-05's per-call connection checkout regardless of journal mode. If a future phase wants a true cross-page snapshot, enabling WAL is a prerequisite but not sufficient by itself (would also need a single pinned connection across pages, which the current `ListPage` shape does not hold).
**Warning signs:** A flaky consistency test that assumes atomicity across pages under concurrent writes.

### Pitfall 4: `-race` distorts the very quantity being benchmarked
**What goes wrong:** Running the peak-memory benchmark under `task test` (which passes `-race`) both slows a 10k-entry fixture significantly and changes allocation behavior (the race detector adds its own shadow-memory bookkeeping), making the recorded numbers not represent production allocation patterns.
**Why it happens:** `-race` instruments every memory access, which is fundamentally incompatible with an allocation-focused measurement.
**How to avoid:** D-13 already requires the benchmark live behind its own build tag with its own CI job, mirroring the existing `append_bench_test.go` precedent (`go test -bench ... -benchtime 1x -run '^$'`, deliberately outside `task test`'s `-race` matrix).
**Warning signs:** Numbers that vary wildly between local (`task test`) and CI runs, or between `-race` and non-`-race` invocations.

### Pitfall 5: Compaction reuses the same `aggregate_id` — cursor position is unaffected, but content is
**What goes wrong:** Assuming compaction "moves" an aggregate in keyset order, requiring special-case cursor logic.
**Why it happens:** Intuition that compaction "replaces" an aggregate might suggest a new identity.
**How to avoid:** Verified this session (`eventstore.go:255-345`): `CompactAggregate` deletes the aggregate's event rows and inserts one new `HostCompacted` seed event **for the same `aggregate_id`**, with a **freshly minted `event_id`** (via `eventid.New()`, not tied to the old rows). The aggregate's position in `ORDER BY aggregate_id` therefore never changes — only its content does when replayed. This is exactly what makes D-06's "unreachable by construction" claim correct: a page fetch either happens strictly before or strictly after the compaction's commit, and either way it sees one atomic replay result for that `aggregate_id`, never a torn state.
**Warning signs:** None expected if the planner writes the two D-06 reachable-variant tests as scoped (before/after compaction, not "during").

## Code Examples

### Existing keyset-adjacent query (baseline, read this session)
```go
// Source: internal/storage/sqlite/projection.go:315-333 (verbatim, read this session)
func getDistinctAggregateIDs(conn *sqlite.Conn) ([]ulid.ULID, error) {
	var ids []ulid.ULID
	err := sqlitex.Execute(conn,
		`SELECT DISTINCT aggregate_id FROM events`,
		&sqlitex.ExecOptions{
			ResultFunc: func(stmt *sqlite.Stmt) error {
				id, parseErr := ulid.Parse(stmt.ColumnText(0))
				if parseErr != nil {
					return parseErr
				}
				ids = append(ids, id)
				return nil
			},
		})
	if err != nil {
		return nil, oops.Wrapf(err, "get aggregate ids")
	}
	return ids, nil
}
```
This is the function `ListPage`'s query (Pattern 1) extends with `WHERE aggregate_id > ?` and `LIMIT ?`.

### Existing 64 KiB chunk framing (baseline, read this session)
```go
// Source: internal/server/service.go:656-677 (verbatim, read this session)
const exportChunkSize = 64 * 1024 // 64 KiB

func sendExportChunks(stream exportChunkSender, data []byte) error {
	if len(data) == 0 {
		return stream.Send(&hostsv1.ExportHostsResponse{Chunk: data})
	}
	for offset := 0; offset < len(data); offset += exportChunkSize {
		end := offset + exportChunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := stream.Send(&hostsv1.ExportHostsResponse{Chunk: data[offset:end]}); err != nil {
			return err
		}
	}
	return nil
}
```
D-03's streaming writer for `json`/`csv` should feed this same function (or an incremental equivalent that flushes at the same 64 KiB boundary) rather than replacing it.

### Production aggregate-ID minting (the D-09 correction, verified this session)
```go
// Source: internal/eventid/eventid.go:49-61 (verbatim, read this session)
// New mints a ULID guaranteed to sort strictly greater than every value this
// generator has previously returned or been seeded with, even when many
// calls land inside the same millisecond or the wall clock steps backward.
func (g *Generator) New() ulid.ULID {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := ulid.MustNew(ulid.Timestamp(time.Now()), g.entropy)
	if id.Compare(g.floor) <= 0 {
		id = next(g.floor)
	}
	g.floor = id
	return id
}
```
```go
// Source: internal/server/commands.go:56-58, :112 (verbatim, read this session)
// newID generates a new ULID [...] Minted through the shared internal/eventid
// generator rather than a per-handler entropy source [...]
func (h *CommandHandler) newID() ulid.ULID {
	return eventid.New()
}
// ... AddHost:
// id := h.newID()
```
New aggregate IDs are minted through this same monotonic singleton — not `ulid.Make()` — so within this single-process server there is no same-millisecond ordering ambiguity for newly created aggregates.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-------------------|---------------|--------|
| `ListAll` folds every aggregate one-at-a-time already (never held full log) | Same replay mechanics, now exposed via a paged, published interface | This phase (LAZY-01) | The behavior wasn't broken; the *interface* was the gap — TMPL-06 (2026-07-31) already had to be publicly amended for exactly this "claims exceed what the shape proves" pattern (D-01/D-01a repeat it) |
| `ExportHosts` `json`/`csv`: 3 full materializations (`entries`, `out`/`csvBuf`, `data`) before any byte is framed | Per-page streaming render straight into the existing 64 KiB chunker | This phase (LAZY-02/D-03) | Removes the actual O(N) peak this phase's benchmark is meant to demonstrate; TMPL-06's chunking bounded the wire, not the heap (explicitly called out in CONTEXT.md D-03) |
| No `ORDER BY` on `getDistinctAggregateIDs` (relies on planner's incidental covering-index scan order) | Explicit, tested, documented `ORDER BY aggregate_id` contract | This phase (D-10) | Verified this session to be behavior-preserving, not a behavior change — closes a latent "works by accident" gap |

**Deprecated/outdated:** None — this phase does not remove or replace any library; it adds an interface method and changes internal rendering strategy.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|-----------------|
| A1 | The SQLite query-planner behavior verified against `sqlite3` CLI 3.54.0 and Python's `sqlite3` module (both linking system/bundled SQLite) generalizes to zombiezen's pure-Go SQLite build used in production | Pattern 1, Open Questions Q-01 | Low — the covering-index DISTINCT-scan optimization is a long-standing, version-stable SQLite query-planner behavior (not a recent addition), and the planner should still have an executor pin this with a real Go test against the zombiezen-backed `Storage`, not merely trust this cross-implementation inference |
| A2 | `runtime.MemStats.HeapAlloc` polling at 100-500µs intervals gives a stable-enough peak signal for D-11's ratio assertion without excessive `-race`-like perturbation | Pattern 4, Pitfall 1 | Medium — if the sampling interval proves too coarse (misses a brief peak) or too fine (perturbs GC/scheduling), D-11's tolerance may need to be looser than expected, or the interval retuned; this is exactly what Q-06 asked research to inform, and it remains an empirical tuning question the plan should settle by running the benchmark, not by reading this document |

**If this table is empty:** N/A — two items above need executor confirmation via a real Go benchmark run before being treated as settled facts.

## Open Questions

All six of CONTEXT.md's research questions were addressed this session. Status:

1. **Q-01 (blocks D-10) — RESOLVED.** `SELECT DISTINCT aggregate_id FROM events` already returns ascending TEXT order in practice, verified by execution against the production schema/index with both a small hand-built case (5 rows) and a 2000-aggregate randomized-insertion-order case. Adding `ORDER BY aggregate_id` is a documented no-op. **Residual for planning:** pin this with a real Go test against zombiezen's `Storage` (see Assumption A1) — this session's proof used the `sqlite3` CLI and Python's `sqlite3` module, not the exact production driver.

2. **Q-02 (constrains D-09) — RESOLVED.** WAL mode is **not** active. No `PrepareConn`/pragma configures it anywhere in `internal/storage/sqlite` (confirmed by reading `sqlite.go` in full and grepping the package for `journal_mode`/`PRAGMA`/`WAL`). D-09's contract documentation should state the per-page-snapshot weakness follows from the per-call connection checkout (D-05), independent of journal mode, and that WAL is not a "just enable it" upgrade path — it changes `withConn` semantics, which is explicitly deferred territory.

3. **Q-03 (informs Claude's discretion) — PARTIALLY RESOLVED, left as discretion.** Deleted state IS knowable pre-replay from the latest event's `event_type` column for every event type except `HostCompacted` (whose `Deleted` flag lives inside the JSON blob, per `HostCompacted.Deleted` in `internal/domain/events.go:385`, read this session). A SQL-side filter (e.g., a correlated subquery on `MAX(event_version)`'s `event_type`) could skip most deleted aggregates before replay, but would still need a Go-side fallback for compacted-and-deleted aggregates, so it cannot fully replace the after-replay check — only reduce how often it's needed. Given D-08 already loops in Go regardless, and CONTEXT.md explicitly reserves this as "an optimization, not a contract change," this research recommends: **start with the simpler after-replay filter** (matches the existing `ListAll` pattern exactly, D-07's byte-identity goal is trivially satisfied) and treat the SQL pre-filter as a follow-up optimization only if the benchmark shows deleted-aggregate replay is a measurable cost at 10k-entry scale.

4. **Q-04 (blocks D-04's final scope) — RESOLVED.** `internal/server/commands.go:451` is `CommandHandler.ListHosts`, called only by the streaming `ListHosts` RPC handler (`service.go:360-373`), which sends entries in receive order with no sort and no test asserting a specific order. D-10's new `ORDER BY` is safe here — no golden-fixture risk, no migration required for LAZY-02 (it was never in D-04's scope; this only confirms the "why not" is sound).

5. **Q-05 (blocks D-03) — RESOLVED, no fallback needed.** Byte-identical streaming reproduction of `json.MarshalIndent(out, "", "  ")` **is** achievable — verified this session with a standalone Go program comparing buffered vs. per-element-streamed output for empty, one-element, and two-element (with omitted/present optional fields) cases, all `bytes.Equal`. D-03's stated fallback ("buffered json, name the residual") is not needed; the planner can go straight to full streaming for `json`.

6. **Q-06 (informs D-11) — RESOLVED as a recommendation, tuning left to execution.** `testing.AllocsPerRun` and `-benchmem`'s allocs/op and B/op measure cumulative totals across a call, not peak live heap, and are the wrong primary tool for D-11's "peak stays flat" claim (see Pitfall 1) — both the paged and drained code paths touch every entry, so cumulative figures scale with N for both. The recommended technique is `runtime.MemStats.HeapAlloc` sampled via a background ticker during the call, tracking the maximum (Pattern 4). The exact polling interval and tolerance percentage are an empirical tuning question (Assumption A2) that the plan should settle by running the benchmark against both fixture sizes and observing actual noise, not by picking a number in advance.

## Environment Availability

Not applicable — this phase has no new external service/runtime dependencies. SQLite access is via the already-vendored pure-Go `zombiezen.com/go/sqlite`; the `sqlite3` CLI (present locally, used only for this session's empirical verification) is not a build or runtime dependency of the project.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Go `testing` + `stretchr/testify` v1.11.1 `[VERIFIED: go.mod]`; `pgregory.net/rapid` v1.3.0 available for property-based tests |
| Config file | None — plain `go test`, orchestrated via `Taskfile.yml` |
| Quick run command | `go test ./internal/storage/... ./internal/server/... -run TestHostProjection -race -count=1` |
| Full suite command | `task test` (all packages, `-race`); benchmark tier is a **separate**, non-`-race` command (see below) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|--------------|
| LAZY-01 | `ListPage` keyset pagination, exactly-once-per-aggregate, ascending order | unit (storagetest conformance) | `go test ./internal/storage/... -run TestHostProjectionListPage -race` | ❌ Wave 0 — new test in `storagetest/suite.go` |
| LAZY-01 | `ListAll` remains behavior-identical as a drain-loop wrapper | unit | `go test ./internal/storage/... -run TestHostProjectionListAll -race` | ✅ exists (`storagetest/suite.go:550`), must keep passing unmodified |
| LAZY-02 | Peak allocation ratio (1k vs 10k) stays flat for paged path, scales for drained | benchmark, own build tag | `go test -tags lazybench -bench BenchmarkPeakMemory -benchtime 1x -run '^$' ./internal/storage/sqlite/` | ❌ Wave 0 — new file + new CI job |
| LAZY-03 | Cursor-not-yet-reached compaction → sees `HostCompacted` at preserved version | unit (storagetest conformance) | `go test ./internal/storage/... -run TestHostProjectionListPage_CompactionAhead -race` | ❌ Wave 0 |
| LAZY-03 | Cursor-already-passed compaction → invisible, prior value retained | unit (storagetest conformance) | `go test ./internal/storage/... -run TestHostProjectionListPage_CompactionBehind -race` | ❌ Wave 0 |
| LAZY-04 | `ExportHosts` `hosts`/`json`/`csv` byte-identical pre/post change | golden fixture (server) | `go test ./internal/server/... -run TestExportHosts_Golden -race` | ❌ Wave 0 — capture BEFORE any behavior change (D-14) |
| LAZY-04 | Client-side v0.13.0 template rendering byte-identical | golden fixture (client) | `go test ./internal/client/template/... -run TestTemplate_Golden -race` | ❌ Wave 0 — capture BEFORE any behavior change |
| LAZY-04 | Three non-migrating regeneration writers (`hostsfile`, `unboundconf`, `dnsmasqconf`) unaffected by D-10's ordering | golden fixture (server) | `go test ./internal/server/... -run 'TestFormatConf_Golden|TestUnboundFormatConf_Golden|TestHostsFile.*Golden'` | ✅ `TestFormatConf_Golden`/`TestUnboundFormatConf_Golden` exist; hosts-file golden equivalent should be confirmed/added in Wave 0 |
| LAZY-01/02 | D-10's `ORDER BY` reproduces today's de-facto order exactly (Q-01) | unit (storage) | `go test ./internal/storage/sqlite/... -run TestGetDistinctAggregateIDs_OrderMatchesDeFacto -race` | ❌ Wave 0 — pins this session's empirical finding against the real zombiezen driver |

### Sampling Rate
- **Per task commit:** `go test ./internal/storage/... ./internal/server/... -race -count=1` (excludes the benchmark tier — too slow/noisy for per-commit)
- **Per wave merge:** `task test` (full `-race` suite) + the benchmark tier once, non-`-race`, to catch a gross regression early even though it isn't the CI gate yet
- **Phase gate:** Full `task test:coverage:ci` green, benchmark tier's CI job green with the D-11 ratio assertion passing, and the RED-proof commit for the new gate linked (D-13, Phase 1 D-16 precedent)

### Wave 0 Gaps
- [ ] `internal/storage/storagetest/suite.go` — add `TestHostProjectionListPage*` conformance tests (keyset paging, exactly-once, ascending order, D-08 fill-to-N, deleted-aggregate skip)
- [ ] `internal/storage/storagetest/suite.go` — add `TestHostProjectionListPage_Compaction{Ahead,Behind}` (LAZY-03)
- [ ] `internal/storage/sqlite/projection_bench_test.go` (or similar, build-tagged) — new peak-memory benchmark (LAZY-02), mirroring `append_bench_test.go`'s "own tag, outside `task test`" precedent
- [ ] `internal/server/service_test.go` (or a new `service_export_golden_test.go`) — capture byte-exact golden fixtures for `hosts`/`json`/`csv` **before** D-03's rewrite lands (D-14)
- [ ] `internal/client/template/template_test.go` — confirm/add a byte-exact golden fixture for consumer-template rendering **before** any change (D-14)
- [ ] `.github/workflows/ci-go.yml` — new benchmark-tier job + `ci-go-complete` `needs:` update (D-13)
- [ ] `Taskfile.yml` — new task target for the benchmark tier (referenced by both local dev and the new CI job)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|----------------|---------|--------------------|
| V2 Authentication | No | Unchanged — mTLS auth on the existing gRPC service is out of this phase's scope |
| V3 Session Management | No | No session state introduced; `ListPage` is stateless per D-05 (explicit design goal) |
| V4 Access Control | No | No new RPC, no new authz surface — `ListPage` is a storage-internal method, not wire-exposed |
| V5 Input Validation | Yes, narrow | `ListPage(ctx, after, limit)`'s `limit` parameter is **not wire-exposed** — verified this session against `proto/router_hosts/v1/hosts.proto:264-289`: neither `ExportHostsRequest` nor `WatchHostsRequest` carries a page-size field. `limit` is therefore an internal constant/package-var (Claude's discretion, D-05/D-08), not attacker-controlled input. Still validate defensively at the `ListPage` boundary (reject `limit <= 0`) so a future internal caller bug can't cause an infinite loop or a zero-progress cursor |
| V6 Cryptography | No | No crypto operations in this phase |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|------------------------|
| Future wire-exposure of `limit` without bounds-checking | Denial of Service | If a future phase ever exposes page size on the wire (not this phase — `limit` stays server-internal), it MUST be clamped to a maximum server-side default, mirroring the existing `ClientLimitsConfig` (`max_stream_entries`/`max_stream_bytes`, `internal/config`) pattern already used for the reverse (client-side) direction. Not required by this phase, but worth flagging so a later phase doesn't introduce it silently |
| Deep single-aggregate history (unbounded within one page fill) | Denial of Service (resource exhaustion) | Already named and accepted in D-06/D-12: pages bound entry *count*, not the event *count* replayed for one deep aggregate. ADR `router-hosts-vl8`'s manual compaction is the stated remedy; event-budgeted pages were considered and explicitly deferred. This phase's benchmark fixture (D-12) deliberately includes deep aggregates to make this residual risk visible in the recorded numbers rather than hidden |
| Partial/torn read exposed as if consistent (information disclosure via stale data, not corruption) | Tampering-adjacent (data integrity of the read, not an attack surface) | D-09's documented weak contract (page-instant value freshness, not read-instant) is a design tradeoff, not a vulnerability — no untrusted party can force a specific value to appear stale beyond what a legitimate concurrent write already does. No new mitigation needed this phase; issue #401 tracks the eventual atomic-read strengthening |

## Sources

### Primary (HIGH confidence — verified by execution or direct file read this session)
- `internal/storage/storage.go:120-126` — `HostProjection` interface, read this session
- `internal/storage/sqlite/projection.go` (full file) — `ListAll`, `replayEvents`, `getDistinctAggregateIDs`, `loadEventsForAggregate`, read this session
- `internal/storage/sqlite/sqlite.go` (full file) — `New`/`NewPool` call site, confirmed no `PrepareConn`/pragma, read this session
- `internal/storage/sqlite/eventstore.go:196-345` — `ListAggregateIDs`, `CompactAggregate`, `selectLatestEventID`, read this session
- `internal/eventid/eventid.go` (full file) — monotonic generator, read this session
- `internal/server/commands.go:1-90, 420-479` — `newID`, `AddHost` mint site, `ListHosts` (line 451), read this session
- `internal/server/service.go:180-229, 355-373, 640-790` — hook entry-count, `ListHosts` RPC, `sendExportChunks`/`ExportHosts`, read this session
- `internal/server/watch.go` (full file) — `sendSnapshot`, `watchFollow*`, read this session
- `internal/server/hostsfile.go`, `unboundconf.go` (partial) — `FormatHostsFile`'s global sort, generator `Regenerate` call sites, read this session
- `internal/storage/storagetest/suite.go:540-650` — existing `HostProjection` conformance tests, read this session
- `internal/domain/host.go:10-26` — `HostEntry` struct incl. `Deleted` tombstone semantics, read this session
- `internal/domain/events.go:57-68, 375-390` — `EventType` constants, `HostCompacted` struct, read this session
- `internal/storage/sqlite/migrations/001_initial.sql` — schema + `idx_events_aggregate` index, read this session
- `.github/workflows/ci-go.yml` (full file) — existing job pattern for D-13's new job, read this session
- `Taskfile.yml` (full file) — existing task pattern, read this session
- `internal/storage/sqlite/append_bench_test.go` — precedent for own-tag/outside-`task test` benchmarks, read this session
- `proto/router_hosts/v1/hosts.proto:264-289` — confirms `limit`/page-size is not wire-exposed, read this session
- Empirical proof, Q-01: `sqlite3` CLI 3.54.0 against the exact production schema (5-row and 2000-aggregate/randomized cases) — both `SELECT DISTINCT` with and without `ORDER BY` produced identical, ascending output; query plan confirmed `SCAN events USING COVERING INDEX idx_events_aggregate`
- Empirical proof, Q-05: standalone Go program comparing `json.MarshalIndent(out, "", "  ")` against manual per-element streaming framing for empty/one/two-element cases — `bytes.Equal` true in all cases; also discovered the `nil`-vs-empty-slice `null`/`[]` divergence (Pitfall 2)
- `go doc testing.AllocsPerRun`, `go doc runtime.MemStats`, `go doc testing.B.ReportAllocs` — stdlib semantics, verified this session
- `go.mod` — dependency versions (`zombiezen.com/go/sqlite v1.4.2`, `oklog/ulid/v2 v2.1.2`, `stretchr/testify v1.11.1`, `pgregory.net/rapid v1.3.0`, `go 1.26.5`), read this session

### Secondary (MEDIUM confidence)
- WebSearch: "Go benchmark measure peak heap usage runtime.MemStats HeapAlloc sampling goroutine ticker technique" — confirmed HeapAlloc-sampling-via-ticker is a recognized community technique for peak-memory measurement, corroborating (not the sole basis for) Pattern 4

### Tertiary (LOW confidence)
- None used as load-bearing — every claim above either cites a file read this session or an execution performed this session

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; all versions read directly from `go.mod`
- Architecture: HIGH — patterns derived from and cross-checked against the actual current code, not inferred from the phase description alone
- Pitfalls: HIGH — the two most consequential pitfalls (AllocsPerRun's wrong-quantity risk, MarshalIndent nil-vs-empty) were discovered and confirmed by direct execution this session, not carried over from training data
- Open Questions resolution: HIGH for Q-01/Q-02/Q-04/Q-05 (execution- or full-file-read-based); MEDIUM for Q-03 (partial — recommendation given, full resolution deferred to benchmark results) and Q-06 (technique recommended, exact tuning parameters deferred to execution)

**Research date:** 2026-08-03
**Valid until:** 2026-09-02 (30 days — stable domain: SQLite query-planner behavior and Go stdlib JSON/testing semantics do not change on a fast cadence, but re-verify Q-01 against the actual zombiezen driver rather than extending this document's cross-implementation inference indefinitely)
