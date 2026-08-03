---
phase: 02-cursor-based-lazy-storage-reads
plan: 02
subsystem: database
tags: [sqlite, cqrs, keyset-pagination, grpc-streaming, event-sourcing]

# Dependency graph
requires:
  - phase: 02-cursor-based-lazy-storage-reads
    provides: "02-01's four golden fixtures (ExportHosts hosts/json/csv, hosts-file writer, client template, de-facto aggregate-ID order) as the byte-identity oracle this plan must not disturb"
provides:
  - "storage.HostProjection.ListPage — the published keyset page function (tuple-4 signature) every later plan in this phase builds on"
  - "sqlite.Storage.ListPage — the keyset implementation over idx_events_aggregate, no new index, no migration"
  - "ListAll reimplemented as a thin drain loop over ListPage (D-07) — one read path, one ordering, verified by an unmodified conformance test"
  - "WatchHosts' sendSnapshot served entirely through ListPage pages — the phase's tracer, proven end-to-end over a real gRPC stream"
  - "storagetest.TestHostProjectionListPage — cross-backend keyset conformance suite (9 subtests) registered in RunAll"
affects: [02-03, 02-04, 02-05, 02-06]

actuals:
  tokens: 9416
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Keyset pagination via WHERE aggregate_id > ? ORDER BY aggregate_id LIMIT ?, served by the existing idx_events_aggregate covering index"
    - "Package-level page-size vars (defaultListPageSize in sqlite, snapshotPageSize in server), not consts, following the MaxTrackedSinks precedent so tests shrink page size instead of seeding large fixtures"
    - "Conformance-suite subtest isolation via a currentMaxAggregateID cursor plus a short sleep, avoiding flakiness from ulid.Make()'s same-millisecond ordering ambiguity when many scenarios share one store instance"

key-files:
  created:
    - internal/storage/sqlite/projection_page_test.go
  modified:
    - internal/storage/storage.go
    - internal/storage/sqlite/projection.go
    - internal/server/watch.go
    - internal/server/watch_test.go
    - internal/storage/storagetest/suite.go

key-decisions:
  - "Task 1 checkpoint (blocking:decision) was auto-selected by --auto mode, not typed by a human — recorded verbatim below for an honest audit trail"
  - "ctx.Err() is checked explicitly at the top of ListPage rather than relying solely on sqlitex.Pool.Take(ctx)'s own context handling: Take's select between an already-ready free connection and ctx.Done() does not deterministically prefer either arm when both are ready, so an already-cancelled context is not guaranteed to short-circuit a same-instant Take. The explicit check makes cancellation deterministic and testable."
  - "getAggregateIDPage and ListPage both live in internal/storage/sqlite/projection.go per the plan's exact file assignment; no new file was needed for the production implementation"
  - "A new sqlite-package test file (projection_page_test.go) was added beyond the plan's literal <files> list for Task 2, to give the TDD RED/GREEN cycle real assertions (boundary exclusion, fill-to-N, drain equivalence, cancellation, limit validation) ahead of Task 3's cross-backend conformance suite — the <files> list was read as the primary production-file set, not an exhaustive list excluding necessary test scaffolding"

patterns-established:
  - "Conformance-suite subtest isolation: capture currentMaxAggregateID (with a deliberate sleep past a millisecond boundary) before seeding a subtest's own fixtures, so exact-count assertions are correct regardless of what earlier subtests in the same store seeded"

requirements-completed: [LAZY-01, LAZY-02, LAZY-04]

coverage:
  - id: D1
    description: "storage.HostProjection publishes ListPage (tuple-4 signature: entries, next, done, err) with a doc comment carrying the ordering, fill-to-N, atomicity, and consistency contract at the density of the ZeroChangeID precedent"
    requirement: "LAZY-01"
    verification:
      - kind: unit
        ref: "internal/storage/sqlite/projection_page_test.go#TestListPage_RejectsNonPositiveLimit"
        status: pass
      - kind: unit
        ref: "internal/storage/storagetest/suite.go#TestHostProjectionListPage"
        status: pass
    human_judgment: false
  - id: D2
    description: "sqlite.Storage.ListPage implements the keyset query via getAggregateIDPage, served by the existing idx_events_aggregate covering index with no new index or migration; ListAll is reimplemented as a thin drain loop over ListPage with its existing conformance test passing unmodified"
    requirement: "LAZY-01"
    verification:
      - kind: unit
        ref: "internal/storage/sqlite/projection_page_test.go#TestListPage_DrainEquivalentToListAll"
        status: pass
      - kind: unit
        ref: "internal/storage/storagetest/suite.go#TestHostProjectionListAll (unmodified body, confirmed via git diff)"
        status: pass
    human_judgment: false
  - id: D3
    description: "WatchHosts' one-shot snapshot is served entirely through ListPage pages: every entry arrives exactly once with no duplicates across multiple pages, the change-ID-before-read (TMPL-08 H1) ordering is preserved verbatim, and the mutatingListStore seam (renamed from mutatingListAllStore) proves the mid-read-mutation regression tests still exercise a live interception point"
    requirement: "LAZY-02"
    verification:
      - kind: unit
        ref: "internal/server/watch_test.go#TestService_WatchHosts_OneShotSnapshot_MultiplePages"
        status: pass
      - kind: unit
        ref: "internal/server/watch_test.go#TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries"
        status: pass
      - kind: unit
        ref: "internal/server/watch_test.go#TestService_WatchHosts_FollowSnapshotIDIsLowerBoundOnEntries"
        status: pass
    human_judgment: false
  - id: D4
    description: "Plan 02-01's four golden fixtures remain green with zero fixture edits, and the cross-backend ListPage conformance suite's boundary and fill-to-N assertions were each demonstrated RED against a deliberately wrong implementation before being trusted"
    requirement: "LAZY-04"
    verification:
      - kind: unit
        ref: "TestExportHosts_Golden|TestFormatHostsFile_Golden|TestTemplate_Golden|TestGetDistinctAggregateIDs_OrderMatchesDeFacto (git diff confirms zero fixture-file edits)"
        status: pass
      - kind: unit
        ref: "internal/storage/storagetest/suite.go#TestHostProjectionListPage (boundary and fill-to-N subtests, RED proofs recorded in this SUMMARY)"
        status: pass
    human_judgment: false

duration: ~50min
completed: 2026-08-03
status: complete
---

# Phase 2 Plan 2: Keyset ListPage Published, WatchHosts Snapshot Streamed Through It Summary

**`storage.HostProjection.ListPage` lands as a published keyset cursor (tuple-4 signature), `ListAll` becomes a drain loop over it, and `WatchHosts`' snapshot is proven end-to-end through real pages over a bufconn gRPC stream — the phase's tracer slice, backed by a 9-subtest cross-backend conformance suite.**

## Performance

- **Duration:** ~50 min
- **Started:** 2026-08-03T20:55:00Z (approx.)
- **Completed:** 2026-08-03T21:12:29Z
- **Tasks:** 3 (Task 1 was a checkpoint:decision, auto-selected — no code)
- **Files modified:** 5 modified, 1 created

## Task 1 Checkpoint Outcome (auto-selected, not human-typed)

**Type:** `checkpoint:decision`, `gate="blocking"` — auto-selected by `--auto`/`--chain` mode per the orchestrator's pre-resolution. No human typed this at the resume-signal; recorded here verbatim for an honest audit trail.

- **Signature: `tuple-4`.**
  `ListPage(ctx context.Context, after ulid.ULID, limit int) (entries []domain.HostEntry, next ulid.ULID, done bool, err error)`.
  Rationale recorded: exactly D-05's sketched shape, adds no new published type to `storage`, and `next`/`done` stay separately readable so a caller cannot mistake a zero cursor for exhaustion. The doc comment states `next` is meaningless when `done` is true.
- **Page size: package-level `var`, not `const`.**
  Implemented as TWO separate package vars — `defaultListPageSize` (`internal/storage/sqlite/projection.go`, used by `ListAll`'s drain loop) and `snapshotPageSize` (`internal/server/watch.go`, used by `sendSnapshot`'s drain loop) — following the `MaxTrackedSinks` precedent (`internal/server/sinkmetrics.go`) so tests can shrink either instead of seeding large fixtures. Two vars rather than one shared symbol because `server` intentionally does not import the concrete `sqlite` package (it depends only on the `storage.Storage` interface), and each caller owning its own page-size policy is consistent with D-05's "caller owns page size" principle.

D-09's cross-page snapshot contract was not reopened, per the checkpoint context's explicit scope boundary.

## Accomplishments

- `storage.HostProjection` gains `ListPage` with a doc comment at the density of the `ZeroChangeID` precedent, covering ordering (D-10), fill-to-N (D-08), atomicity (D-06), and consistency (D-09) — a published interface change, not an internal optimization (LAZY-01).
- `sqlite.Storage.ListPage` implements the keyset query via a new `getAggregateIDPage` helper (`WHERE aggregate_id > ? ORDER BY aggregate_id LIMIT ?`), served by the existing `idx_events_aggregate` covering index — no new index, no migration.
- `ListAll` is reimplemented as a thin drain loop over `ListPage` (D-07); `TestHostProjectionListAll` passes with its body byte-for-byte unmodified (confirmed via `git diff`, a pure-addition diff).
- `sendSnapshot` (`internal/server/watch.go`) drains `ListPage` instead of calling `ListAll` once, wiring a `WatchHosts` snapshot end-to-end through the new cursor — the phase's tracer, proven by a real bufconn gRPC stream test with `snapshotPageSize` shrunk to 3 against 10 seeded entries.
- The `mutatingListAllStore` test decorator (`internal/server/watch_test.go`) is renamed `mutatingListStore` and gains a `ListPage` override alongside its existing `ListAll` override, keeping `TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries` and its follow-mode mirror exercising a live interception seam rather than silently becoming no-ops.
- `storagetest.TestHostProjectionListPage` adds 9 named subtests to the cross-backend conformance suite (empty store, single aggregate, exact-boundary cursor, exactly-once across page sizes 1/2/9, cross-page ascending order, idempotency, D-08 fill-to-N with deleted aggregates, drain equivalence with `ListAll`, concurrent full drains), registered in `RunAll` and confirmed executing against the sqlite backend.
- All four of plan 02-01's golden fixtures remain green with zero fixture-file edits.

## Task Commits

Each task was committed atomically. **All three commits in this plan bypassed 1Password SSH commit signing** (`failed to fill whole buffer` — repo rule `3t12ry4n4m`, unattended run) via `git -c commit.gpgsign=false commit`. Confirmed unsigned with `git cat-file commit <sha> | rg -q '^gpgsig'` (all three returned "not found", i.e., unsigned) rather than relying on `git log --format='%G?'`.

1. **Task 1: Confirm the exact published ListPage signature** — checkpoint:decision, auto-selected, no commit (no code produced).
2. **Task 2: End-to-end "a WatchHosts snapshot served entirely through pages"** — TDD, two commits:
   - RED: `3511181` (test) — `test(storage): add failing tests for ListPage pagination`
   - GREEN: `bf8be5b` (feat) — `feat(storage): implement ListPage keyset pagination`
3. **Task 3: Cross-backend ListPage conformance tests** — `ba3ed50` (test) — `test(storage): add cross-backend ListPage conformance suite`

All three: unsigned (bypassed, see above).

## TDD Gate Compliance (Task 2)

Gate sequence verified in git log: `test(storage): add failing tests for ListPage pagination` (`3511181`) precedes `feat(storage): implement ListPage keyset pagination` (`bf8be5b`). No `refactor(...)` commit was needed.

**RED proof (verbatim), before `bf8be5b` landed:**

```
$ go test ./internal/storage/sqlite/... -run 'TestListPage_' -race -count=1 -v
# github.com/fzymgc-house/router-hosts/internal/storage/sqlite [github.com/fzymgc-house/router-hosts/internal/storage/sqlite.test]
internal/storage/sqlite/projection_page_test.go:42:42: store.ListPage undefined (type *Storage has no field or method ListPage)
internal/storage/sqlite/projection_page_test.go:64:34: store.ListPage undefined (type *Storage has no field or method ListPage)
internal/storage/sqlite/projection_page_test.go:91:37: store.ListPage undefined (type *Storage has no field or method ListPage)
internal/storage/sqlite/projection_page_test.go:137:37: store.ListPage undefined (type *Storage has no field or method ListPage)
internal/storage/sqlite/projection_page_test.go:145:36: store.ListPage undefined (type *Storage has no field or method ListPage)
internal/storage/sqlite/projection_page_test.go:176:38: store.ListPage undefined (type *Storage has no field or method ListPage)
FAIL	github.com/fzymgc-house/router-hosts/internal/storage/sqlite [build failed]

$ go test ./internal/server/... -run 'TestService_WatchHosts_' -race -count=1 -v
# github.com/fzymgc-house/router-hosts/internal/server [github.com/fzymgc-house/router-hosts/internal/server.test]
internal/server/watch_test.go:224:18: undefined: snapshotPageSize
internal/server/watch_test.go:225:2: undefined: snapshotPageSize
internal/server/watch_test.go:226:21: undefined: snapshotPageSize
internal/server/watch_test.go:291:19: m.Storage.ListPage undefined (type storage.Storage has no field or method ListPage)
FAIL	github.com/fzymgc-house/router-hosts/internal/server [build failed]
```

Both `sqlite` and `server` packages fail to build against tests targeting `ListPage`/`snapshotPageSize` before either exists — a stronger RED signal (build failure) than a subtle logic-bug RED, and the RED commit contains only `_test.go` files.

**GREEN confirmation:** after `bf8be5b`, `go test ./internal/storage/sqlite/... ./internal/server/... -race -count=1` passes cleanly (see full verification section below).

## Demonstrated-RED Proofs (all three, per plan `<verification>`)

### 1. Mutation-hook seam (Task 2)

Temporarily removed the `mutateOnce(ctx)` call from `mutatingListStore.ListPage`'s override (leaving only a passthrough to `m.Storage.ListPage`), then ran the two regression tests:

```
$ go test ./internal/server/... -run 'TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries|TestService_WatchHosts_FollowSnapshotIDIsLowerBoundOnEntries' -race -count=1 -v
    watch_test.go:337: Error: Should be true — "entry set must contain the mid-ListAll mutation"
    watch_test.go:345: Error: "01KZ4Q2JDNCV3612F8MAQ771Z2" is not less than "01KZ4Q2JDNCV3612F8MAQ771Z2"
--- FAIL: TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries (0.02s)
    watch_test.go:885: Error: Should be true — "entry set must contain the mid-ListAll mutation"
    watch_test.go:889: Error: "01KZ4Q2JE9G3DPAH2GS505QWZN" is not less than "01KZ4Q2JE9G3DPAH2GS505QWZN"
    watch_test.go:901: Error: "01KZ4Q2JE9G3DPAH2GS505QWZN" is not greater than "01KZ4Q2JE9G3DPAH2GS505QWZN"
--- FAIL: TestService_WatchHosts_FollowSnapshotIDIsLowerBoundOnEntries (0.02s)
FAIL
```

Both tests fail without the hook — proving the seam is live. The hook was restored immediately after, and both tests confirmed green again (`go test ... -race -count=1` → `ok`). The broken intermediate state was never committed.

### 2. Exact-boundary `>` loosened to `>=` (Task 3)

Temporarily changed `getAggregateIDPage`'s SQL predicate from `WHERE aggregate_id > ?` to `WHERE aggregate_id >= ?`, then ran the boundary subtest:

```
$ go test ./internal/storage/sqlite/... -run 'TestCompliance/HostProjectionListPage/exact-boundary' -race -count=1 -v
    suite.go:757: Error: Should be true
--- FAIL: TestCompliance/HostProjectionListPage/exact-boundary_cursor_separates_rather_than_merges (0.01s)
FAIL
```

Reverted (`>` restored) and re-ran: `ok github.com/fzymgc-house/router-hosts/internal/storage/sqlite`. `git diff` confirmed the file was byte-identical to its pre-mutation state after revert.

### 3. Fill-to-N counting scanned aggregates instead of live entries (Task 3)

Temporarily changed the fill-to-N loop's guard from `if entry != nil && !entry.Deleted` to `if entry != nil` (counting deleted aggregates toward the page), then ran the fill-to-N subtest:

```
$ go test ./internal/storage/sqlite/... -run 'TestCompliance/HostProjectionListPage/fill-to-N' -race -count=1 -v
    suite.go:882: Error: Should be true
--- FAIL: TestCompliance/HostProjectionListPage/fill-to-N_with_deleted_aggregates (0.02s)
FAIL
```

Reverted and re-ran: `ok github.com/fzymgc-house/router-hosts/internal/storage/sqlite`. `git diff` confirmed byte-identical restoration.

## Files Created/Modified

- `internal/storage/storage.go` — `HostProjection.ListPage` interface method + full doc comment (ordering/fill-to-N/atomicity/consistency contract); `ListAll`'s doc comment updated to steer new callers to `ListPage`.
- `internal/storage/sqlite/projection.go` — `defaultListPageSize` var, `getAggregateIDPage`, `ListPage` implementation, `ListAll` rewritten as a drain loop.
- `internal/storage/sqlite/projection_page_test.go` (new) — 5 unit tests for `ListPage`'s validation, cancellation, boundary, fill-to-N, and drain-equivalence behavior, written RED-first as part of Task 2's TDD cycle.
- `internal/server/watch.go` — `snapshotPageSize` var; `sendSnapshot` rewritten to drain `ListPage` with an accumulating count; doc comment updated to describe per-page (not per-drain) consistency.
- `internal/server/watch_test.go` — `mutatingListAllStore` renamed `mutatingListStore` with a `ListPage` override added alongside the existing `ListAll` override; new `TestService_WatchHosts_OneShotSnapshot_MultiplePages` test.
- `internal/storage/storagetest/suite.go` — `TestHostProjectionListPage` (9 subtests) plus `currentMaxAggregateID` and `idsOf` helpers; registered in `RunAll`. Purely additive — `TestHostProjectionListAll`'s body is untouched.

## Decisions Made

- Two page-size vars (`defaultListPageSize`, `snapshotPageSize`) instead of one shared symbol — see `key-decisions` in frontmatter for the architectural rationale (server package does not depend on the concrete sqlite backend).
- Explicit `ctx.Err()` check at the top of `ListPage` rather than relying solely on `sqlitex.Pool.Take(ctx)`'s own cancellation handling — see `key-decisions` in frontmatter.
- Added `internal/storage/sqlite/projection_page_test.go` beyond Task 2's literal `<files>` list, needed to give the TDD RED/GREEN cycle real assertions for behaviors (boundary, fill-to-N, cancellation, limit validation, drain equivalence) that the plan's own `<behavior>` block required be written failing-first, ahead of Task 3's broader cross-backend suite.
- Conformance-suite subtest isolation pattern (`currentMaxAggregateID` + sleep) invented to let 9 subtests share one store instance without flaky cross-subtest pollution, given `ulid.Make()`'s same-millisecond ordering is not guaranteed monotonic.

## Deviations from Plan

None beyond the two documented in "Decisions Made" above (both are Rule 2/Rule 3 style additions in service of the plan's own explicit TDD and RED-proof requirements, not scope changes). No architectural deviations (Rule 4) were needed.

## Issues Encountered

- 1Password SSH commit signing failed on all three commits in this plan (`failed to fill whole buffer`). Bypassed per repo rule `3t12ry4n4m` for this unattended run; all three SHAs recorded above as unsigned.

## Known Stubs

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `storage.HostProjection.ListPage` is published and stable; `ExportHosts`, the hook entry-count, `FindByIPAndHostname`, and `Search` (plan 02-04's scope) can now migrate onto it directly.
- `ListAll` is a pure wrapper, so any of the eleven pre-existing call sites downstream of `getDistinctAggregateIDs`'s new implicit ordering are already covered by this plan's golden-fixture verification.
- `storagetest.TestHostProjectionListPage` is the durable contract test for every future backend; a new backend implementing `storage.Storage` gets keyset-pagination compliance for free via `RunAll`.
- `task test` (full `-race` suite), `task lint` (golangci-lint + buf lint + manifests), and `task test:coverage:ci` (86.5%, threshold 80%) are all green at plan end.
- Ready for plan 02-03 / 02-04 (the phase's expansion tasks — `ExportHosts` streaming and the remaining free-win migrations).

---
*Phase: 02-cursor-based-lazy-storage-reads*
*Completed: 2026-08-03*

## Self-Check: PASSED

All three task commit hashes (`3511181`, `bf8be5b`, `ba3ed50`) verified present in `git log`. All created/modified files (`internal/storage/storage.go`, `internal/storage/sqlite/projection.go`, `internal/storage/sqlite/projection_page_test.go`, `internal/server/watch.go`, `internal/server/watch_test.go`, `internal/storage/storagetest/suite.go`) confirmed present on disk with the described content.
