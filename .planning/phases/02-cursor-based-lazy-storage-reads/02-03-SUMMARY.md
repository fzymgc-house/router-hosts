---
phase: 02-cursor-based-lazy-storage-reads
plan: 03
subsystem: database
tags: [sqlite, event-sourcing, compaction, keyset-pagination, documentation]

# Dependency graph
requires:
  - phase: 02-cursor-based-lazy-storage-reads
    provides: "02-02's published storage.HostProjection.ListPage (tuple-4 keyset signature) and its doc comment, which this plan pins with conformance tests and restates for an operator audience"
provides:
  - "storagetest.TestHostProjectionListPage_CompactionAhead / _CompactionBehind — the two reachable compaction-vs-cursor conformance tests, registered in RunAll"
  - "docs/contributing/architecture.md § Read Path: Ordering and Consistency Contract — operator-facing statement of D-10 ordering, D-09 paged-read consistency, and D-06 atomicity/compaction contracts"
affects: [02-04, 02-05, 02-06]

actuals:
  tokens: 3519
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "drainIDs test helper (storagetest/suite.go): fully drains ListPage from a cursor into an ordered ID slice, used to compare a keyset sequence captured before a mutation against one captured after — a full-sequence comparison, not a length or set comparison"

key-files:
  created: []
  modified:
    - internal/storage/storagetest/suite.go
    - docs/contributing/architecture.md

key-decisions:
  - "FA-02-01 is carried forward, not resolved, by this plan: LAZY-03's literal scenario (a cursor sitting INSIDE an aggregate's pre-compaction history) was not tested because D-06 makes it unreachable by construction — loadEventsForAggregate and replayEvents are atomic within one page fetch, so a page fetch happens either strictly before or strictly after a compaction commits. The two REACHABLE variants (compacting an aggregate the cursor has not yet reached; compacting one it already passed) were pinned instead. If a reviewer at /gsd-verify-work rejects that reading, LAZY-03 is NOT satisfied by this plan and D-06 must reopen."
  - "Both compaction tests passed GREEN the first time they were run against the real, unmodified CompactAggregate/ListPage — no production code change was needed to make them pass. This is itself evidence for D-06's atomicity claim, not a gap in the TDD process: the plan explicitly anticipated this outcome and required demonstrated-RED proofs via deliberate mutation instead of a classic missing-implementation RED phase."
  - "The CompactionBehind RED proof (loosening getAggregateIDPage's exact-boundary predicate from > to >=) caused an infinite loop rather than a clean assertion failure, because the mutated query keeps returning the cursor's own aggregate ID forever, so the unbounded ListPage fill-to-N loop never sets done. Rather than change the test to add an artificial iteration cap, the RED run was bounded with `go test -timeout 8s`, which cleanly panics and FAILs the run with a goroutine dump pinned at the exact broken query. This is treated as a valid RED signal (a hang under a real regression is itself a defect the test suite would flag in CI, which times out non-interactively) — see the recorded output below."

patterns-established:
  - "drainIDs helper in storagetest/suite.go for full-sequence keyset-position-stability assertions"

requirements-completed: [LAZY-03]

coverage:
  - id: D1
    description: "Two reachable compaction-vs-cursor conformance tests (CompactionAhead, CompactionBehind) registered and executing against the sqlite backend, asserting exact OCC-version equality and keyset-position stability, not mere presence"
    requirement: "LAZY-03"
    verification:
      - kind: unit
        ref: "internal/storage/storagetest/suite.go#TestHostProjectionListPage_CompactionAhead"
        status: pass
      - kind: unit
        ref: "internal/storage/storagetest/suite.go#TestHostProjectionListPage_CompactionBehind"
        status: pass
  - id: D2
    description: "FA-02-01 (LAZY-03's unclassified edge-probe row) is carried forward explicitly for human review rather than silently resolved by this plan"
    requirement: "LAZY-03"
    verification: []
    human_judgment: true
    rationale: "Whether 'testing the two reachable variants plus documenting the literal scenario's unreachability' actually satisfies LAZY-03 is an interpretive judgment about requirement intent, not something a test can settle. This plan's frontmatter states plainly that if a reviewer rejects that reading, LAZY-03 is not satisfied and D-06 must reopen."
  - id: D3
    description: "docs/contributing/architecture.md documents D-10 ordering, D-09's three-part paged-read consistency contract (exactly-once membership, mid-read creation ordering, per-page value freshness as the honest weakness), and D-06 atomicity/compaction, for an operator audience"
    verification:
      - kind: other
        ref: "task lint (includes rumdl markdown lint via lefthook pre-commit hook) — pass"
        status: pass
    human_judgment: false

duration: ~25min
completed: 2026-08-03
status: complete
---

# Phase 2 Plan 3: LAZY-03 Pinned — Compaction-vs-Cursor Conformance Tests and the Read-Path Contract Documented Summary

**Two conformance tests pin the reachable halves of LAZY-03 against the real `CompactAggregate`/`ListPage` with zero production changes, and `docs/contributing/architecture.md` gains an operator-facing statement of the ordering, paged-read consistency, and atomicity contracts — including the honest admission that WAL is not enabled and per-page value freshness, not whole-read consistency, is what the system actually delivers.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-08-03T21:20:00Z (approx.)
- **Completed:** 2026-08-03T21:27:13Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- `TestHostProjectionListPage_CompactionAhead` (`internal/storage/storagetest/suite.go`): seeds three aggregates, raises one's OCC version to 2 via a real `CommentUpdated` event, fetches page 1 so the cursor stops strictly before that aggregate, compacts it, then drains the rest — asserting the compacted entry's `Version` equals the value captured **before** compaction by exact equality (not presence), its IP/hostname/aliases/tags/comment match the pre-compaction values, and the full ordered aggregate-ID sequence is unchanged before vs. after compaction (keyset-position stability, RESEARCH.md Pitfall 5).
- `TestHostProjectionListPage_CompactionBehind` (`internal/storage/storagetest/suite.go`): fetches page 1 so the reader passes and holds one aggregate's value, then materially changes that aggregate (a real `CommentUpdated`) and compacts it — asserting the already-passed aggregate does not reappear on a later page, and the value the reader already holds from page 1 remains the pre-compaction, pre-update value.
- Both tests registered in `RunAll` and confirmed executing by name in `-v` output.
- `docs/contributing/architecture.md` gains a new `### Read Path: Ordering and Consistency Contract` subsection under `## Storage Layer`, stating D-10 (ascending aggregate-ULID order), D-09's three distinct consistency guarantees (exactly-once set membership; mid-read creation ordering attributed to `internal/eventid`, not `ulid.Make()`; per-page value freshness as the real weakness), the `withConn`/pool-checkout mechanism behind that weakness, that WAL is not enabled today and would not alone fix it, D-06's atomicity/compaction contract naming both new tests by name, and a pointer to `ListAll` as a thin drain loop plus GitHub issue #401 for the deferred atomic read.
- Plan 02-01's four golden fixtures (`TestExportHosts_Golden`, `TestFormatHostsFile_Golden`, `TestTemplate_Golden`, `TestGetDistinctAggregateIDs_OrderMatchesDeFacto`) remain green with zero fixture edits.

## Task Commits

Both tasks were committed atomically, and both signed successfully (no 1Password bypass needed this run, unlike plan 02-02):

1. **Task 1: Pin the two reachable compaction-vs-cursor variants** — `c88cd16` (test) — `test(storage): pin compaction-vs-cursor conformance (LAZY-03)`
2. **Task 2: Write the read ordering and paged-read consistency contracts into the architecture doc** — `40348f8` (docs) — `docs(storage): document read-path ordering and consistency contracts`

Both confirmed signed via `git cat-file commit <sha> | rg -q '^gpgsig'` (both found `gpgsig`, i.e., signed) — no unsigned/bypassed commits to record in this plan.

## Demonstrated-RED Proofs (both, per plan `<verification>` and critical-task-note requiring a named deliberate wrong change + green restored)

Both new tests passed GREEN the first time they were run against the real, unmodified `CompactAggregate`/`ListPage` — no production code change was needed, consistent with the plan's explicit expectation ("if a test cannot be made green without a production change, stop and surface that: it would mean D-06's atomicity claim is wrong"; no such surfacing was needed). To prove each test actually catches a real regression rather than trivially passing, each was run against a deliberately broken production file, confirmed to fail, then the file was reverted and confirmed byte-identical via `git diff` before either was re-run to green.

### 1. CompactionAhead — OCC version reset to a fixed value

**Deliberate wrong change:** In `internal/storage/sqlite/eventstore.go`, `CompactAggregate`'s replacement seed event's `Version` field was temporarily hardcoded to `1` instead of `highWater` (the preserved OCC version):

```go
seed := domain.EventEnvelope{
    EventID:     eventid.New(),
    AggregateID: aggregateID,
    Event:       he,
    Version:     1, // DELIBERATE BUG for RED proof — must be highWater
    CreatedAt:   time.Now().UTC(),
}
```

```
$ go test ./internal/storage/sqlite/... -run 'TestCompliance/HostProjectionListPage_CompactionAhead' -race -count=1 -v
    suite.go:1042: 
        	Error Trace:	.../internal/storage/storagetest/suite.go:1042
        	Error:      	Not equal:
        	            	expected: 2
        	            	actual  : 1
        	Test:       	TestCompliance/HostProjectionListPage_CompactionAhead
        	Messages:   	the OCC version must equal the value captured BEFORE compaction, never reset
--- FAIL: TestCompliance (0.04s)
    --- FAIL: TestCompliance/HostProjectionListPage_CompactionAhead (0.04s)
FAIL
```

(Note: this was caught by the entry's replayed `Version` assertion, not the earlier `compactResult.Version` assertion — the latter reads a separate in-memory field the bug did not touch, `result.Version = highWater`, which stays correct even when the persisted event's version is wrong. The test still caught the real defect: the version an actual reader observes via `ListPage`.)

Reverted (`Version: highWater` restored) and re-ran: `ok github.com/fzymgc-house/router-hosts/internal/storage/sqlite`. `git diff --stat internal/storage/sqlite/eventstore.go` confirmed byte-identical restoration (no output).

### 2. CompactionBehind — exact-boundary cursor predicate loosened

**Deliberate wrong change:** In `internal/storage/sqlite/projection.go`, `getAggregateIDPage`'s SQL predicate was temporarily loosened from `WHERE aggregate_id > ?` to `WHERE aggregate_id >= ?` (the same class of mutation used as a RED proof in plan 02-02).

This mutation does not fail cleanly — it causes the reader's cursor to keep re-matching its own last-consumed aggregate ID forever, so `ListPage`'s fill-to-N loop never observes an empty page and `done` never becomes true. Draining a full page from a re-included cursor is an infinite loop, not a bounded assertion failure. Rather than add an artificial iteration cap to the test (which would weaken the "does not reappear" contract it pins), the RED run was bounded at the `go test` level:

```
$ timeout 20 go test ./internal/storage/sqlite/... -run 'TestCompliance/HostProjectionListPage_CompactionBehind' -race -count=1 -v -timeout 8s
=== RUN   TestCompliance
=== RUN   TestCompliance/HostProjectionListPage_CompactionBehind
panic: test timed out after 8s
	running tests:
		TestCompliance (8s)
		TestCompliance/HostProjectionListPage_CompactionBehind (8s)
...
github.com/fzymgc-house/router-hosts/internal/storage/sqlite.getAggregateIDPage(...)
	.../internal/storage/sqlite/projection.go:393 +0x19c
github.com/fzymgc-house/router-hosts/internal/storage/sqlite.(*Storage).ListPage.func1(...)
	.../internal/storage/sqlite/projection.go:64 +0xa4
...
github.com/fzymgc-house/router-hosts/internal/storage/storagetest.TestHostProjectionListPage_CompactionBehind(...)
	.../internal/storage/storagetest/suite.go:1107 +0xaa4
FAIL	github.com/fzymgc-house/router-hosts/internal/storage/sqlite	8.295s
FAIL
```

The goroutine dump pins the hang exactly at the mutated query inside `getAggregateIDPage`, called from the test's own drain loop — a clean, non-interactive FAIL under a bounded timeout, the same failure mode CI's own timeout would produce against this regression.

Reverted (`>` restored) and re-ran: `ok github.com/fzymgc-house/router-hosts/internal/storage/sqlite` (`--- PASS: TestCompliance/HostProjectionListPage_CompactionBehind`). `git diff --stat internal/storage/sqlite/projection.go` confirmed byte-identical restoration (no output).

## Files Created/Modified

- `internal/storage/storagetest/suite.go` — `TestHostProjectionListPage_CompactionAhead`, `TestHostProjectionListPage_CompactionBehind`, and a `drainIDs` helper; both tests registered in `RunAll`. Purely additive (178 insertions, 0 deletions per `git diff --stat`); no existing test body changed.
- `docs/contributing/architecture.md` — new `### Read Path: Ordering and Consistency Contract` subsection (68 insertions).

## Decisions Made

See `key-decisions` in frontmatter: FA-02-01 carried forward explicitly (not resolved); both compaction tests were GREEN against unmodified production code on first run (expected, per plan); the CompactionBehind RED proof was bounded with `go test -timeout` rather than adding an artificial loop cap to the test itself.

## Deviations from Plan

None. Both tasks executed as specified. No production code was permanently modified (both temporary mutations used for RED proofs were reverted and confirmed byte-identical via `git diff`).

## Issues Encountered

- The first RED-proof attempt for CompactionBehind (loosening `>` to `>=`) hung the test binary rather than failing cleanly, because the unbounded drain loop in the test never observes `done = true` once the cursor re-matches itself. Resolved by re-running under `go test -timeout 8s`, which produces a clean, bounded FAIL with a goroutine dump pinpointing the exact broken line — a valid RED signal, and the mutation was still fully reverted afterward. See "Demonstrated-RED Proofs" above for the full account.

## Known Stubs

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- LAZY-03 is satisfied by the reading recorded in `key-decisions` / FA-02-01: two executing conformance tests plus a documented unreachability argument, not a doc comment alone. This reading requires human confirmation at `/gsd-verify-work` — if rejected, D-06 must reopen.
- `docs/contributing/architecture.md` now carries the D-10/D-09/D-06 contracts for any future contributor or operator; no planning-file-only tribal knowledge remains for these three decisions.
- `task test` (full `-race` suite) and `task lint` (golangci-lint + buf lint + markdown lint + manifests) are both green at plan end.
- No production code changed in this plan — `internal/storage/sqlite/eventstore.go` and `internal/storage/sqlite/projection.go` are untouched from their 02-02 state, confirmed via `git diff --stat` showing no changes to either file in this plan's commits.
- Ready for plan 02-04 (sibling plan in this wave, touching `internal/server/service.go` and `internal/storage/sqlite/projection.go` — this plan did not modify either in its final committed state).

---
*Phase: 02-cursor-based-lazy-storage-reads*
*Completed: 2026-08-03*

## Self-Check: PASSED

Both task commit hashes (`c88cd16`, `40348f8`) verified present in `git log`. Both files (`internal/storage/storagetest/suite.go`, `docs/contributing/architecture.md`) confirmed present on disk with the described content. Both commits confirmed signed via `git cat-file commit <sha> | rg -q '^gpgsig'`.
