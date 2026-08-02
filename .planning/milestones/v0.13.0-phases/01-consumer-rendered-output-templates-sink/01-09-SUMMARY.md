---
phase: 01-consumer-rendered-output-templates-sink
plan: 09
subsystem: storage
tags: [event-sourcing, ulid, sqlite, change-id, monotonic-id, storage-contract]

requires: []
provides:
  - "internal/eventid: a monotonic ULID generator (Generator, New/Seed/NewAfter, package singleton, SwapDefault)"
  - "storage.EventStore.LatestEventID and storage.ZeroChangeID: the storage-layer change-ID contract every backend must satisfy"
  - "An in-transaction ordering guard in sqlite's insertEvent: no commit lands an event ID at or below the log's current maximum, unconditionally, including a caller-supplied zero ID into an empty store"
  - "Startup floor seeding: sqlite.Storage.Initialize seeds internal/eventid from LatestEventID after migrations"
affects: [templates-consumer-rendered-output, change-id-derivation, output-sink]

actuals:
  tokens: 18000
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Value-type generator with a package singleton + SwapDefault escape hatch, so a test can hold a fully-controlled floor without process-wide interference"
    - "In-transaction re-mint-on-violation guard (never reject) at the single storage funnel, applied unconditionally with no emptiness special case"
    - "Compliance-suite cases (EventStoreLatestEventID, EventStoreCompactionAdvancesLatestEventID, EventStoreAppendNeverLowersLatestEventID) that every EventStore backend must pass via storagetest.RunAll"

key-files:
  created:
    - internal/eventid/eventid.go
    - internal/eventid/eventid_test.go
    - internal/storage/sqlite/compaction_monotonic_test.go
    - internal/storage/sqlite/eventid_guard_test.go
    - internal/storage/sqlite/append_bench_test.go
  modified:
    - internal/server/commands.go
    - internal/server/service_test.go
    - internal/storage/storage.go
    - internal/storage/sqlite/eventstore.go
    - internal/storage/sqlite/sqlite.go
    - internal/storage/sqlite/sqlite_test.go
    - internal/storage/storagetest/suite.go

key-decisions:
  - "Re-mint a non-advancing event ID rather than reject the append — keeps a legitimate concurrent write successful while making MAX(event_id) advance, per the plan's explicit design"
  - "The in-transaction comparison against MAX(event_id) is unconditional (no emptiness branch); an empty log is a zero maximum via selectLatestEventID's NULL-to-zero-ULID mapping, so a caller-supplied zero ID is always re-minted rather than colliding with storage.ZeroChangeID (round-4 H1)"
  - "legacy_migration.go:183 remains the one INSERT INTO events statement outside insertEvent's guard, documented and bounded (runs before eventid.Seed, one-shot, skips on non-empty events table) rather than claimed away"

patterns-established:
  - "Generator value type + package singleton + SwapDefault: any future process-wide monotonic-ID need in this codebase should follow this shape rather than bare package vars, so tests can hold a floor they fully control"

requirements-completed: [TMPL-08]

coverage:
  - id: D1
    description: "internal/eventid mints monotonically increasing ULIDs against a raisable floor (New/Seed/NewAfter), replacing CommandHandler's per-handler entropy and CompactAggregate's bare ulid.Make() seed"
    requirement: "TMPL-08"
    verification:
      - kind: unit
        ref: "internal/eventid/eventid_test.go#TestEventID_StrictlyIncreasing,TestEventID_Unique,TestEventID_ConcurrentUse,TestEventID_SeedRaisesFloor,TestEventID_SeedIgnoresLowerValue,TestEventID_NewAfterAlwaysGreater,TestEventID_SwapDefaultRestores"
        status: pass
      - kind: unit
        ref: "internal/storage/sqlite/compaction_monotonic_test.go#TestCompactAggregate_AdvancesLatestEventID,TestCompactAggregate_AdvancesWhenAggregateHeldTheMaximum"
        status: pass
    human_judgment: false
  - id: D2
    description: "storage.EventStore.LatestEventID and storage.ZeroChangeID give every backend a change-ID contract: the greatest event_id, or the zero-ULID sentinel on an empty log"
    requirement: "TMPL-08"
    verification:
      - kind: unit
        ref: "internal/storage/storagetest/suite.go#TestEventStoreLatestEventID,TestEventStoreCompactionAdvancesLatestEventID (run via internal/storage/sqlite/compliance_test.go TestCompliance)"
        status: pass
    human_judgment: false
  - id: D3
    description: "insertEvent's in-transaction ordering guard: no commit lands an event ID at or below the log's current maximum, from any append path, any caller, any mint order, or across a restart — including the zero-ULID-into-empty-store edge case"
    requirement: "TMPL-08"
    verification:
      - kind: unit
        ref: "internal/storage/sqlite/eventid_guard_test.go#TestInsertEvent_LowerCallerSuppliedIDStillAdvancesMax,TestInsertEvent_ZeroIDIntoEmptyStoreRemints,TestInsertEvent_ZeroIDIntoNonEmptyStoreRemints,TestAppendEventsBatch_AllLowerIDsStillAdvanceMax,TestInsertEvent_ConcurrentReverseCommitOrderAdvancesMax,TestInitialize_SeedsGeneratorFromPersistedLog"
        status: pass
      - kind: unit
        ref: "internal/storage/storagetest/suite.go#TestEventStoreAppendNeverLowersLatestEventID"
        status: pass
    human_judgment: false

duration: ~55min
completed: 2026-08-01
status: complete
---

# Phase 1 Plan 09: Change-ID Storage Foundation Summary

**A shared `internal/eventid` generator plus an unconditional in-transaction ordering guard in sqlite's `insertEvent`, so `MAX(event_id)` can never fail to advance across a real state change — including the zero-ULID-into-empty-store edge case that a gated guard would have let through.**

## Performance

- **Duration:** ~55 min
- **Tasks:** 3
- **Files modified:** 12 (5 created, 7 modified)

## Accomplishments

- `internal/eventid`: one monotonic-floor generator (`New`/`Seed`/`NewAfter`) that `CommandHandler.newID()` and `CompactAggregate`'s replacement seed both mint through — the only two production mint sites now share one generator.
- `storage.EventStore.LatestEventID` + `storage.ZeroChangeID`: the change-ID contract (TMPL-08, D-18) every `EventStore` backend must satisfy, enforced by the shared compliance suite.
- An **unconditional** in-transaction ordering guard in `insertEvent` (the single funnel for `AppendEvent`, `AppendEvents`, `AppendEventsBatch` and `CompactAggregate`): a proposed event ID that does not already sort strictly above `MAX(event_id)` is re-minted via `eventid.NewAfter(max)`, with no emptiness special case — closing the round-4 H1 hole where a zero ULID into an empty store would have collided with `storage.ZeroChangeID`.
- Startup seeding: `sqlite.Storage.Initialize` seeds the generator's floor from `LatestEventID` after migrations commit, so a restart's first mint sorts above the persisted maximum even inside the same millisecond.
- Six deterministic regression tests plus two probabilistic ones, every one of them **verified RED** against the specific pre-fix code before being accepted (see Deviations/observations below).

## Task Commits

1. **Task 1: One event-ID generator with a monotonic floor** — `0730d98` (fix)
2. **Task 2: Read the log high-water mark as the change ID** — `2b59db6` (feat)
3. **Task 3: In-transaction ordering guard and startup floor seeding** — `c9b2de8` (fix)

*No separate plan-metadata commit was required beyond this SUMMARY's own commit.*

## Files Created/Modified

- `internal/eventid/eventid.go` — `Generator` type (`New`/`Seed`/`NewAfter`), package singleton, `SwapDefault`, unexported `next()` carry helper
- `internal/eventid/eventid_test.go` — 7 tests, each building its own `Generator` via `NewGenerator()`
- `internal/server/commands.go` — `newID()` now delegates to `eventid.New()`; removed the now-orphaned `entropy`/`mu` fields
- `internal/server/service_test.go` — fixed `TestService_Readiness_Unhealthy`'s in-memory DSN to include `cache=shared` (Rule 1 — see Deviations)
- `internal/storage/storage.go` — `EventStore.LatestEventID`, `storage.ZeroChangeID`, amended append-family doc comments stating the ordering obligation
- `internal/storage/sqlite/eventstore.go` — `LatestEventID`/`selectLatestEventID`, the in-transaction guard in `insertEvent`, `CompactAggregate`'s seed now mints via `eventid.New()`
- `internal/storage/sqlite/sqlite.go` — `Initialize` seeds `eventid` from `LatestEventID` after the migration body commits
- `internal/storage/sqlite/sqlite_test.go` — 4 event-ID mint sites routed through `eventid.New()` (see Deviations for the actual count vs. the plan's estimate)
- `internal/storage/sqlite/compaction_monotonic_test.go` (new) — `TestCompactAggregate_AdvancesLatestEventID`, `TestCompactAggregate_AdvancesWhenAggregateHeldTheMaximum`
- `internal/storage/sqlite/eventid_guard_test.go` (new) — the 6 deterministic guard/seeding regression tests
- `internal/storage/sqlite/append_bench_test.go` (new) — `BenchmarkAppendEventsBatch`
- `internal/storage/storagetest/suite.go` — `EventStoreLatestEventID`, `EventStoreCompactionAdvancesLatestEventID`, `EventStoreAppendNeverLowersLatestEventID`; 3 event-ID mint sites routed through `eventid.New()`

## Decisions Made

- Re-mint rather than reject a non-advancing proposed ID at the storage boundary (keeps legitimate concurrent writes successful; there is no retry loop above `insertEvent` that would absorb a rejection).
- The ordering comparison in `insertEvent` is unconditional — no `if log is non-empty` branch — because `selectLatestEventID` already maps an empty log to the zero ULID, so the general comparison subsumes the empty case without a redundant branch that invites a future "simplification" bug.
- `legacy_migration.go:183`'s direct `INSERT INTO events` is documented as the one bypass of the guard, not claimed away — it is safe because it runs strictly before `eventid.Seed` and is one-shot/non-empty-skipping.

## RED Verification Observations (review L3 / M7)

Every regression test below was observed failing against the specific pre-fix code before being accepted, per review L3's requirement to record the actual observed count rather than "failed at least once":

- **`TestCompactAggregate_AdvancesLatestEventID` / `TestCompactAggregate_AdvancesWhenAggregateHeldTheMaximum`** (Task 1): reverting the compaction seed to bare `ulid.Make()` and running `go test -race -count=50 -run TestCompactAggregate_Advances ./internal/storage/sqlite/` produced **10/50 failures** for the first test and **11/50 failures** for the second (21/100 total). Getting a genuine failure rate required restructuring the test to share one warmed-up `Storage` instance across repeats (see Deviations below) — a fresh store per repeat pays several milliseconds of migration/pool overhead under `-race`, which reliably pushed the compaction seed's mint into a *later* millisecond than the event it replaced, masking the bug entirely (0/50 observed failures) until that overhead was eliminated.
- **`TestInsertEvent_ConcurrentReverseCommitOrderAdvancesMax`** (Task 3): with the in-transaction guard's comparison disabled, the test failed deterministically (`"0" is not positive`) — A's commit left `LatestEventID` unchanged instead of advancing past B's.
- **`TestInitialize_SeedsGeneratorFromPersistedLog`** (Task 3): with the `eventid.Seed` call removed from `Initialize`, the discriminating assertion (`eventid.New()` immediately after `Initialize`, before any append) failed deterministically (`"-1" is not positive`) — the swapped-in zero-floor generator minted below the persisted hour-ahead maximum. Verified green again under `-count=3` with the seeding restored.
- **`TestInsertEvent_ZeroIDIntoEmptyStoreRemints`** (Task 3, round-4 H1): verified RED specifically against a guard carrying the round-3 revision's `"when the log is non-empty"` emptiness gate (not merely the guard fully disabled) — with that gate reintroduced, this test failed while its sibling `TestInsertEvent_ZeroIDIntoNonEmptyStoreRemints` and `TestInsertEvent_LowerCallerSuppliedIDStillAdvancesMax` both still passed, precisely demonstrating that only the empty-store path was broken.
- **`TestInsertEvent_LowerCallerSuppliedIDStillAdvancesMax`, `TestInsertEvent_ZeroIDIntoNonEmptyStoreRemints`, `TestAppendEventsBatch_AllLowerIDsStillAdvanceMax`** (Task 3): all observed failing with the guard's comparison fully disabled.

## Benchmark (review round-4 L5 — recorded measurement, not a CI gate)

`go test -bench BenchmarkAppendEventsBatch -benchtime 1x -run '^$' ./internal/storage/sqlite/` (informational only; `Taskfile.yml` is unchanged, no threshold wired into `task ci`):

| Batch size | ns/op |
|---|---|
| 1 | 532,417 |
| 100 | 1,203,709 |
| 1,000 | 11,879,125 |
| 10,000 | 77,724,667 |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `TestService_Readiness_Unhealthy`'s in-memory DSN broke under the new post-migration seeding read**

- **Found during:** Task 3, running the full `internal/server` suite
- **Issue:** The test opened `"file::memory:?mode=memory"` (no `cache=shared`), unlike every other in-memory DSN in this codebase. Without shared cache, each pooled connection gets its own private in-memory database. `Initialize`'s migration body ran on one pooled connection; the new post-migration `LatestEventID` seeding read (added by this plan, per its own explicit "after the withConn body returns" design) took a *separate* connection from the pool, which could be one that never saw the migration, failing with `sqlite: ... no such table: events`.
- **Fix:** Added `&cache=shared` to the test's DSN, matching the pattern used everywhere else in the test suite. Does not change the test's intent (`store.Close()` still closes the whole pool, so the subsequent readiness check still observes a closed store).
- **Files modified:** `internal/server/service_test.go`
- **Verification:** `go test -race -run TestService_Readiness ./internal/server/` green; full `internal/server` and repo-wide `go test ./...` green afterward.
- **Committed in:** `c9b2de8` (Task 3 commit)

**2. [Rule 3 - Blocking, corrected in-flight] Task 1's compaction regression test could not observe the bug it was written to catch, until restructured**

- **Found during:** Task 1, verifying RED against the reverted `ulid.Make()` seed
- **Issue:** A test that creates a fresh `Storage` (full migration + connection pool) per invocation pays several milliseconds of overhead under `-race` in this environment. That overhead reliably pushed the compaction seed's mint into a strictly later millisecond than the event it replaced, so the bug (two independent entropy sources racing within the *same* millisecond) never manifested — 0/50 observed failures, which is indistinguishable from "cannot fail" and would have shipped a non-discriminating regression test.
- **Fix:** Restructured `compaction_monotonic_test.go` to share one already-initialized `Storage` across every `-count` repeat (`go test -count=N` re-invokes the test function N times within one process, so a package-level store built once stays warm). This surfaced a second, related discovery: the shared store must use a **uniquely-named** in-memory DSN (`file:eventid_guard_monotonic_shared?...`), not the generic anonymous `file::memory:` DSN every other test uses — SQLite's shared-cache anonymous identity is process-wide, so a never-closed pool on that generic DSN would leak this file's already-migrated schema into every other test in the package expecting a fresh database (observed directly: a later, unrelated test failed with `index idx_events_aggregate already exists` during development of this fix).
- **Files modified:** `internal/storage/sqlite/compaction_monotonic_test.go`
- **Verification:** Full `internal/storage/sqlite` package suite green (39/39) after the fix; genuine 10/50 and 11/50 RED counts obtained (see above).
- **Committed in:** `0730d98` (Task 1 commit — the working, isolated version is what was committed; the broken intermediate designs were not)

**3. [Rule 1 - Documentation/count correction] Actual event-ID mint substitution count was 7, not the plan's enumerated 6**

- **Found during:** Task 3, enumerating `EventID:` sites in `storagetest/suite.go` and `sqlite_test.go` as the plan instructed ("enumerate them yourself first ... rather than trusting these line numbers")
- **Issue:** Task 2 (executed earlier in this same plan) added a 7th bare `EventID: ulid.Make()` site in `storagetest/suite.go` (inside the new `TestEventStoreCompactionAdvancesLatestEventID`), which the plan's Task 3 text — written before Task 2 ran — could not have counted.
- **Fix:** Substituted all 7 sites (3 in `storagetest/suite.go`, 4 in `sqlite_test.go`) through `eventid.New()`, satisfying the acceptance gate's "no matches" requirement rather than the specific "exactly 6" count.
- **Files modified:** `internal/storage/storagetest/suite.go`
- **Verification:** `rg -n 'EventID:\s*ulid\.Make\(\)' internal/storage/storagetest/suite.go internal/storage/sqlite/sqlite_test.go` returns no matches; bare `ulid.Make()` counts for aggregate/snapshot IDs remain large and non-zero (31 and 63) in each file, confirming the substitution did not spill onto non-event-ID mints.
- **Committed in:** `c9b2de8` (Task 3 commit)

---

**Total deviations:** 3 auto-fixed (1 Rule 1 bug, 1 Rule 3 blocking/test-design correction, 1 Rule 1 documentation/count correction)
**Impact on plan:** All three were necessary for correctness of the delivered tests and to keep the full test suite green. No scope creep — no behavior outside TMPL-08's change-ID foundation was touched.

## Issues Encountered

- **The plan's own verify commands for the compliance-suite subtests (`EventStoreLatestEventID`, `EventStoreCompactionAdvancesLatestEventID`, `EventStoreAppendNeverLowersLatestEventID`) are written as `-run 'Name'`, which Go's `-run` flag does not match against subtests** (these run as `TestCompliance/Name`, and a pattern with no `/` only matches top-level test names — `-run 'EventStoreLatestEventID'` reports "no tests to run" and exits 0, silently verifying nothing). This was worked around during verification by using `-run '/Name'` instead; it does not affect the tests themselves, which are correctly registered and pass. Documented here so a future reader who copy-pastes the plan's literal verify command does not mistake a silent no-op for a real green run.
- **`TestEventStoreAppendNeverLowersLatestEventID` needed reordering, not a second store, to cover the zero-ID-into-empty-store sub-case.** The plan describes this sub-case as needing "a freshly created store." Initially this was implemented by calling the compliance suite's `factory` a second time mid-test — but since `RunAll`'s factory always uses the same anonymous `file::memory:?...&cache=shared` DSN, a second call while the first store was still open (its `t.Cleanup` not yet fired) would return a pool attached to the *same* already-populated database, not a genuinely empty one. Resolved by reordering the function so the zero-ID sub-case runs first (while the store handed in by `RunAll` is still genuinely empty) and the lower-caller-ID sub-case runs second, reusing the same store — eliminating the need for a second store entirely.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

The change-ID premise TMPL-08 rests on is now true in the code: `MAX(event_id)` cannot regress or fail to advance across any real state change, from any append path, any caller, or any mint order, and `storage.ZeroChangeID` cannot collide with a real committed event ID. Later plans in this phase that derive a change ID from `LatestEventID` (sink mode, template data contract) can build on this without re-litigating the ordering guarantee.

No blockers. `go test -race -count=1 ./...` is green across the whole repository; `task lint` reports 0 issues.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-01*

## Self-Check: PASSED

- FOUND: `.planning/phases/01-consumer-rendered-output-templates-sink/01-09-SUMMARY.md`
- FOUND: `0730d98` (Task 1 commit)
- FOUND: `2b59db6` (Task 2 commit)
- FOUND: `c9b2de8` (Task 3 commit)
