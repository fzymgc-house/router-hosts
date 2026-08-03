---
phase: 02-cursor-based-lazy-storage-reads
plan: 01
subsystem: testing
tags: [golden-fixture, sqlite, zombiezen, json, csv, hosts-file, text-template, byte-identity]

# Dependency graph
requires: []
provides:
  - "TestExportHosts_Golden — byte-exact ExportHosts hosts/json/csv goldens including the empty-inventory single-message carve-out"
  - "TestFormatHostsFile_Golden — byte-exact hosts-file writer golden with a pinned sort tie-break"
  - "TestTemplate_Golden — byte-exact client-side consumer-template render golden"
  - "TestGetDistinctAggregateIDs_OrderMatchesDeFacto — executed proof (production driver) that the bare SELECT DISTINCT already returns ascending order"
affects: [02-02, 02-03, 02-04, 02-05, 02-06]

actuals:
  tokens: 5849
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "Golden fixtures assert literal `want` strings built with real seeded ULIDs substituted via fmt.Sprintf, never a re-implementation of the render logic under test"
    - "Empty-inventory single-message carve-out pinned by asserting message COUNT (exactly 1), not only concatenated bytes"

key-files:
  created:
    - internal/server/service_export_golden_test.go
    - internal/server/hostsfile_golden_test.go
    - internal/client/template/template_golden_test.go
    - internal/storage/sqlite/projection_order_test.go
  modified: []

key-decisions:
  - "TestFormatConf_Golden and TestUnboundFormatConf_Golden already existed and were already byte-exact — confirmed green by execution, no new tests added for those two writers (per plan instruction to add only if a run showed non-exactness)"
  - "Template golden avoided volatile-line stripping entirely: GeneratedAt is supplied by the test via a fixed timestamppb.New(fixedTime) rather than a wall-clock read, so there is no volatile line to strip in this render path (unlike the server-side hosts/conf goldens, which do call time.Now() internally)"
  - "TestGetDistinctAggregateIDs_OrderMatchesDeFacto uses a fixed-seed math/rand shuffle (not time-seeded) for a reproducible fixture across runs; no gosec/nolint needed since gosec is not enabled in .golangci.yml (linters.default: standard)"

patterns-established:
  - "Golden-fixture ID substitution: build the literal expected-output template as a Go string with %s placeholders, then fmt.Sprintf real seeded IDs into it at assert time — pins layout/ordering without hardcoding an unstable ULID"

requirements-completed: []  # LAZY-04 spans the whole phase; this plan lays its evidentiary foundation but does not itself close the requirement

coverage:
  - id: D1
    description: "Byte-exact ExportHosts goldens for hosts/json/csv, including the empty-inventory case (json exactly \"[]\", csv header-only, exactly one response message)"
    requirement: "LAZY-04"
    verification:
      - kind: unit
        ref: "internal/server/service_export_golden_test.go#TestExportHosts_Golden"
        status: pass
    human_judgment: false
  - id: D2
    description: "Byte-exact hosts-file writer golden with a pinned IP+hostname tie-break, and confirmation the two pre-existing conf-writer goldens are already byte-exact"
    requirement: "LAZY-04"
    verification:
      - kind: unit
        ref: "internal/server/hostsfile_golden_test.go#TestFormatHostsFile_Golden"
        status: pass
      - kind: unit
        ref: "internal/server/dnsmasqconf_test.go#TestFormatConf_Golden"
        status: pass
      - kind: unit
        ref: "internal/server/unboundconf_test.go#TestUnboundFormatConf_Golden"
        status: pass
    human_judgment: false
  - id: D3
    description: "Byte-exact client-side consumer-template render golden, including a newline-bearing comment through the sanitize FuncMap binding and the empty-entry-set case"
    requirement: "LAZY-04"
    verification:
      - kind: unit
        ref: "internal/client/template/template_golden_test.go#TestTemplate_Golden"
        status: pass
    human_judgment: false
  - id: D4
    description: "Today's de-facto ascending aggregate-ID order proven by execution against the real zombiezen.com/go/sqlite driver, including a tombstone delete and a CompactAggregate run (RESEARCH.md Assumption A1 / Q-01)"
    requirement: "LAZY-04"
    verification:
      - kind: unit
        ref: "internal/storage/sqlite/projection_order_test.go#TestGetDistinctAggregateIDs_OrderMatchesDeFacto"
        status: pass
    human_judgment: false

duration: ~25min
completed: 2026-08-03
status: complete
---

# Phase 2 Plan 1: Byte-Identity Baseline Goldens Summary

**Four golden/execution-proof test files pinning every LAZY-04 rendered surface and today's de-facto aggregate-ID order, captured against unmodified production code before any behavior change lands this phase.**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-08-03T20:25:00Z (approx.)
- **Completed:** 2026-08-03T20:50:14Z
- **Tasks:** 3
- **Files modified:** 4 (all new test files; zero production files touched)

## Accomplishments

- `TestExportHosts_Golden` pins `ExportHosts`' `hosts`/`json`/`csv` formats byte-for-byte, including the empty-inventory case: json renders exactly the two-byte literal `[]` (never `null`), csv renders the header row only, and the stream is proven to carry exactly one response message for empty inventory (the review-L14 `sendExportChunks` carve-out).
- `TestFormatHostsFile_Golden` pins the one regeneration writer (hosts-file) that had no prior byte-exact golden, with a fixture supplied out of sort order and two entries sharing an identical IP+hostname key so the sort's tie behavior is pinned, not merely its key ordering; also asserts `FormatHostsFile` mutates the caller's slice in place.
- `TestFormatConf_Golden` (dnsmasq) and `TestUnboundFormatConf_Golden` (unbound) were already byte-exact goldens — confirmed green by execution rather than assumed.
- `TestTemplate_Golden` pins the client-side consumer-template render path, covering a comment containing an embedded newline through the `sanitize` FuncMap binding and the empty-entry-set case.
- `TestGetDistinctAggregateIDs_OrderMatchesDeFacto` proves by execution against the production `zombiezen.com/go/sqlite` driver (not by reading the query) that today's bare `SELECT DISTINCT aggregate_id FROM events` already returns strictly ascending order, across 250 randomly-shuffled aggregates with varying event depth, a tombstone delete, and a `CompactAggregate` run whose target's keyset index is proven unchanged before/after. This closes RESEARCH.md Assumption A1 / Open Question Q-01, whose prior proof used the `sqlite3` CLI and Python's `sqlite3` module rather than the production driver.

## Task Commits

Each task was committed atomically:

1. **Task 1: Capture byte-exact ExportHosts goldens for hosts, json, and csv** - `fc8998c` (test)
2. **Task 2: Capture goldens for the three regeneration writers and the client consumer template** - `7def4a2` (test)
3. **Task 3: Pin today's de-facto aggregate-ID order against the real zombiezen driver** - `c6f6249` (test)

_No TDD RED/GREEN/REFACTOR split — every task in this plan is test-only by design (the plan changes no production code)._

## Files Created/Modified

- `internal/server/service_export_golden_test.go` - `TestExportHosts_Golden`: hosts/json/csv format goldens plus the empty-inventory sub-case
- `internal/server/hostsfile_golden_test.go` - `TestFormatHostsFile_Golden` (+ a reversed-input companion proving the assertion is on rendered order, not input order)
- `internal/client/template/template_golden_test.go` - `TestTemplate_Golden`: multi-entry newline-comment case and empty-entry-set case
- `internal/storage/sqlite/projection_order_test.go` - `TestGetDistinctAggregateIDs_OrderMatchesDeFacto`: 250-aggregate randomized-order execution proof, plus tombstone-delete and compaction sub-cases

## Decisions Made

- Confirmed (not assumed) that `TestFormatConf_Golden` and `TestUnboundFormatConf_Golden` are already byte-exact by running them; per the plan, no new goldens were added for those two writers.
- The template golden fixture supplies `GeneratedAt` via a fixed `timestamppb.New(fixedTime)` through `SnapshotComplete`, so there was no wall-clock-derived volatile line to strip — unlike the server-side hosts/conf goldens, which call `time.Now()` internally and require stripping the `# Last updated:` line.
- `TestGetDistinctAggregateIDs_OrderMatchesDeFacto`'s shuffle uses a fixed seed (`rand.NewSource(20260803)`) for a reproducible fixture; confirmed `gosec` is not in `.golangci.yml`'s enabled linter set, so no `//nolint` directive was needed or added (CLAUDE.md forbids adding one without explicit approval).

## Deviations from Plan

None - plan executed exactly as written. No production code was touched; `git status --porcelain internal/ api/` after each task showed only the new test files.

## Verbatim Run Output — Q-01 Production-Driver Proof

```
=== RUN   TestGetDistinctAggregateIDs_OrderMatchesDeFacto
=== RUN   TestGetDistinctAggregateIDs_OrderMatchesDeFacto/baseline:_ascending_order,_complete_set
=== RUN   TestGetDistinctAggregateIDs_OrderMatchesDeFacto/after_a_tombstone_delete
=== RUN   TestGetDistinctAggregateIDs_OrderMatchesDeFacto/after_CompactAggregate_on_one_aggregate
--- PASS: TestGetDistinctAggregateIDs_OrderMatchesDeFacto (0.18s)
    --- PASS: TestGetDistinctAggregateIDs_OrderMatchesDeFacto/baseline:_ascending_order,_complete_set (0.00s)
    --- PASS: TestGetDistinctAggregateIDs_OrderMatchesDeFacto/after_a_tombstone_delete (0.00s)
    --- PASS: TestGetDistinctAggregateIDs_OrderMatchesDeFacto/after_CompactAggregate_on_one_aggregate (0.00s)
PASS
ok  	github.com/fzymgc-house/router-hosts/internal/storage/sqlite	1.403s
```

Command: `go test ./internal/storage/sqlite/... -run TestGetDistinctAggregateIDs_OrderMatchesDeFacto -race -count=1 -v`

This is the production-driver re-proof RESEARCH.md's Assumption A1 required — the research session's own proof used the `sqlite3` CLI and Python's `sqlite3` module against the same schema/index, not `zombiezen.com/go/sqlite`.

## Verbatim Run Output — Pre-existing Conf Goldens

```
=== RUN   TestFormatConf_Golden
--- PASS: TestFormatConf_Golden (0.00s)
=== RUN   TestUnboundFormatConf_Golden
--- PASS: TestUnboundFormatConf_Golden (0.00s)
PASS
ok  	github.com/fzymgc-house/router-hosts/internal/server	1.271s
```

Command: `go test ./internal/server/... -run 'TestFormatConf_Golden|TestUnboundFormatConf_Golden' -race -count=1 -v`

## Issues Encountered

None.

## Known Stubs

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All four D-14 golden/execution-proof fixtures are green against unmodified production code. Every later plan in this phase must keep them green without editing them (must_haves prohibition: never re-record a golden from post-change output).
- `task test` (full `-race` suite) and `task lint` (golangci-lint + buf lint) are both green.
- `git status --porcelain` confirms zero non-test files were modified by this plan.
- Ready for plan 02-02 (the phase's leading `type="tracer"` slice), which can now assert byte-identity against these fixtures.

---
*Phase: 02-cursor-based-lazy-storage-reads*
*Completed: 2026-08-03*

## Self-Check: PASSED

All four created test files and all three task commit hashes (`fc8998c`, `7def4a2`, `c6f6249`) verified present on disk / in git history.
