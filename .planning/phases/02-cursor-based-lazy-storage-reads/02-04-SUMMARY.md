---
phase: 02-cursor-based-lazy-storage-reads
plan: 04
subsystem: database
tags: [grpc-streaming, json, csv, keyset-pagination, byte-identity, sqlite]

# Dependency graph
requires:
  - phase: 02-cursor-based-lazy-storage-reads
    provides: "02-02's published storage.HostProjection.ListPage (tuple-4 signature) and 02-01's four golden fixtures as the byte-identity oracle"
provides:
  - "ExportHosts' json and csv formats render page by page into a bounded 64 KiB chunkWriter, replacing three full inventory materializations (entries, out/csvBuf, data) with one bounded buffer — the change LAZY-02's benchmark (plan 02-05) measures"
  - "The hosts format explicitly descoped and documented in-code (D-02): still drains ListAll for FormatHostsFile's global sort, residual O(entry count) named as a deliberate, sanctioned decision"
  - "The hook entry-count path counts ListPage pages instead of materializing every entry to call len() on it"
  - "FindByIPAndHostname and Search stream ListPage pages instead of draining ListAll first; FindByIPAndHostname exits early on match"
affects: [02-05]

actuals:
  tokens: 7121
  tasks: 3
  commits: 4

tech-stack:
  added: []
  patterns:
    - "chunkWriter: an io.Writer with a fixed-capacity (exportChunkSize) internal buffer that flushes-and-resets rather than append-and-reslice, so its backing array never grows across the life of a stream — the actual heap-bounding mechanism behind D-03"
    - "Prefix-separator JSON array framing (write '[' or ',' before each element's '\\n  ' + MarshalIndent bytes, '[]' or trailing '\\n]' after the loop) reproduces json.MarshalIndent's exact byte layout without look-ahead for 'is this the last element'"
    - "pageLister func-typed seam (findByIPAndHostname) lets a test count page fetches via a counting wrapper closure, without a global test hook or an interface-level decorator on the concrete *Storage type"

key-files:
  created:
    - internal/server/service_export_stream_test.go
  modified:
    - internal/server/service.go
    - internal/server/hooks_wiring_test.go
    - internal/storage/sqlite/projection.go
    - internal/storage/sqlite/sqlite_test.go

key-decisions:
  - "Task 1's RED/GREEN TDD cycle was done by saving the finished implementation as a diff, reverting service.go to pre-change, writing the new streaming-specific tests against the reverted file (confirmed RED via build failure on exportPageSize undefined — a stronger RED signal than a logic-bug RED, per plan 02-02's precedent), then reapplying the diff for GREEN. This produced two commits (132e10a test, fd3ff29 feat) but the feat commit also carries Task 2's hook-count and hosts-residual-comment changes, made in the same original edit pass before the revert/reapply cycle — see Deviations."
  - "chunkWriter uses a fixed-capacity buffer with flush-and-reset (buf = buf[:0]) rather than append-and-reslice (buf = buf[n:]). The reslice approach would retain the whole backing array's capacity for the life of the writer even though only a small trailing window is 'live' — silently reintroducing an O(payload) heap footprint despite looking bounded. This was caught before committing, not discovered by a test."
  - "FindByIPAndHostname's early-exit loop is factored into a package-level pageLister func type + findByIPAndHostname(ctx, list, pageSize, ip, hostname) helper, rather than a global counting hook or an interface-level wrapper. FindByIPAndHostname is a method on the concrete *Storage type calling s.ListPage directly (not through an interface), so the mutatingListStore-style embedding decorator (watch_test.go precedent) cannot intercept it; the func-typed seam achieves the same call-counting test without a global mutable var."

patterns-established:
  - "Fixed-capacity buffer-with-flush-and-reset for a bounded streaming writer, as the general shape for 'accumulate up to N bytes, emit, repeat' — the append-and-reslice alternative silently defeats the boundedness it appears to provide."

requirements-completed: [LAZY-02, LAZY-04]

coverage:
  - id: D1
    description: "ExportHosts' json and csv formats render page by page directly into the export stream via a bounded chunkWriter, replacing three full inventory materializations with one bounded buffer; the out := make([]jsonEntry, len(entries)) full-slice allocation is gone"
    requirement: "LAZY-02"
    verification:
      - kind: unit
        ref: "internal/server/service_export_stream_test.go#TestExportHosts_ChunkBoundaryEquivalenceAcrossPages"
        status: pass
      - kind: unit
        ref: "internal/server/service_test.go#TestService_ExportHosts_ChunksLargePayloadJSON|TestService_ExportHosts_ChunksLargePayloadCSV (pre-existing, unmodified, still pass)"
        status: pass
    human_judgment: false
  - id: D2
    description: "json format output is byte-for-byte identical to json.MarshalIndent for empty/single/multi-entry cases including omitted comment key and no trailing newline; empty inventory still yields exactly one ExportHostsResponse message; 64 KiB exportChunkSize framing unchanged"
    requirement: "LAZY-04"
    verification:
      - kind: unit
        ref: "internal/server/service_export_golden_test.go#TestExportHosts_Golden (plan 02-01 fixture, zero edits — confirmed via git diff 7365008..HEAD)"
        status: pass
    human_judgment: false
  - id: D3
    description: "hosts format explicitly descoped (still drains ListAll + FormatHostsFile's global sort) with the residual O(entry count) named in an in-code comment; hook entry count counts pages instead of materializing every entry"
    requirement: "LAZY-02"
    verification:
      - kind: unit
        ref: "internal/server/service_export_golden_test.go#TestExportHosts_Golden (hosts sub-case, unmodified fixture)"
        status: pass
      - kind: unit
        ref: "internal/server/hooks_wiring_test.go#TestRegenerateOutputs_EntryCountExcludesDeleted"
        status: pass
    human_judgment: false
  - id: D4
    description: "FindByIPAndHostname and Search stream ListPage pages instead of draining ListAll first, with matchesFilter/hasAnyTag unchanged, cross-page order preserved, and nil-vs-empty return behavior unchanged"
    requirement: "LAZY-02"
    verification:
      - kind: unit
        ref: "internal/storage/sqlite/sqlite_test.go#TestFindByIPAndHostnameStopsAtFirstMatch"
        status: pass
      - kind: unit
        ref: "internal/storage/sqlite/sqlite_test.go#TestSearchPreservesAscendingOrderAcrossPages"
        status: pass
      - kind: unit
        ref: "internal/storage/sqlite/sqlite_test.go#TestSearchNoMatchReturnsNil"
        status: pass
    human_judgment: false

duration: ~20min (commit-timestamp span; total session including reads longer)
completed: 2026-08-03
status: complete
---

# Phase 2 Plan 4: Streaming ExportHosts, Descoped hosts, and D-04's Free Wins Summary

**`ExportHosts`' json/csv formats now render page by page through a fixed-64KiB-buffer chunkWriter instead of building three full-inventory copies; `hosts` is explicitly descoped with its residual named in code; the hook entry-count and the two in-package storage filters (`FindByIPAndHostname`, `Search`) now stream `ListPage` — and all four of plan 02-01's golden fixtures still pass with zero edits.**

## Performance

- **Duration:** ~20 min by commit timestamps (17:39–17:57 local); the full session including file reads, RESEARCH/PATTERNS/CONTEXT review, and the deliberate revert/reapply RED-GREEN cycle ran longer than the timestamp span alone suggests
- **Started:** 2026-08-03T21:39:24Z (first commit)
- **Completed:** 2026-08-03T21:57:00Z (approx, last commit)
- **Tasks:** 3
- **Files modified:** 3 modified (service.go, projection.go, hooks_wiring_test.go — plus sqlite_test.go), 1 created (service_export_stream_test.go)

## Accomplishments

- **D-03 (the plan's central change):** `ExportHosts`' `json` and `csv` branches no longer build `entries`, then `out []jsonEntry`/`bytes.Buffer`, then `data []byte` — three full materializations before `sendExportChunks` framed anything. They now drain `ListPage` and render each page directly into a new `chunkWriter` (an `io.Writer` with a fixed `exportChunkSize`-capacity buffer that flushes-and-resets, never growing across the life of a stream). The removed line, quoted verbatim per the plan's `<output>` requirement:

  ```go
  out := make([]jsonEntry, len(entries))
  ```

- **Byte-identity held throughout (LAZY-04):** all four of plan 02-01's golden fixtures (`TestExportHosts_Golden`, `TestFormatHostsFile_Golden`, `TestTemplate_Golden`, `TestGetDistinctAggregateIDs_OrderMatchesDeFacto`) pass with **zero edits to any fixture file** across every commit in this plan — confirmed via `git diff 7365008..HEAD -- <the four fixture files>` returning empty output.
- **Empty-payload single-message carve-out preserved:** `chunkWriter.Close()` sends exactly one message with an empty chunk when `Write` was never called, matching `sendExportChunks`' existing review-L14 behavior. `TestExportHosts_Golden`'s empty-inventory sub-case (asserting message count == 1) still passes unmodified.
- **Chunk framing unchanged:** a new `TestExportHosts_ChunkBoundaryEquivalenceAcrossPages` test recomputes the "expected" chunk-length sequence by feeding the streamed payload's concatenated bytes back through the **unchanged** `sendExportChunks` (the same function the `hosts` format still uses directly) and asserts it matches the streaming path's observed sequence — for a fixture spanning multiple `ListPage` pages AND multiple 64 KiB windows simultaneously. The pre-existing `TestService_ExportHosts_ChunksLargePayloadJSON`/`CSV` tests (single oversized entry, asserting every non-final chunk is exactly `exportChunkSize` bytes) also still pass unmodified.
- **D-02: `hosts` explicitly descoped.** Still drains `ListAll` to a slice and renders via `FormatHostsFile` exactly as before. The residual is named in an in-code comment on the branch (quoted verbatim per the plan's `<output>` requirement):

  ```go
  // D-02: hosts is explicitly descoped from the streaming rewrite —
  // this path holds every entry in memory for the IP-then-hostname
  // sort, and the residual is O(entry count), a deliberate, recorded
  // scope decision. REQUIREMENTS.md's Out of Scope table sanctions it:
  // "the residual O(N entries) held for the hosts/json IP-then-hostname
  // sort is not 'full event history' and is out of scope for v0.14.0".
  // FormatHostsFile sorts the caller's slice IN PLACE, so this drained
  // slice must not be reused after rendering.
  ```

- **D-04's three free wins taken, five exclusions untouched:**
  - The hook entry-count block (`service.go`) now calls a new `countLiveEntries` helper that accumulates a count across `ListPage` pages instead of materializing every entry to call `len()` on it. Best-effort-on-error behavior (same log message, same fields) preserved. New test `TestRegenerateOutputs_EntryCountExcludesDeleted` seeds 3 live entries plus 1 deleted one and confirms the on_success hook still reports 3.
  - `FindByIPAndHostname` (`projection.go`) now streams `ListPage` pages via a `findByIPAndHostname(ctx, list pageLister, pageSize, ip, hostname)` helper and returns as soon as it finds a match. `TestFindByIPAndHostnameStopsAtFirstMatch` seeds 5 aggregates with the match in the first (page size 1) and asserts exactly 1 page fetch via a counting wrapper closure passed through the `pageLister` seam — a full drain at that page size would need 6 calls.
  - `Search` (`projection.go`) now streams `ListPage` pages, appending only matching entries. `matchesFilter`/`hasAnyTag` are reused unchanged — confirmed by `git diff` showing the single hunk touching only `FindByIPAndHostname`/`Search`, with the predicate functions further down the file untouched. `TestSearchPreservesAscendingOrderAcrossPages` (page size shrunk to 1, 4 matches spanning 4 pages plus one non-matching interleaved aggregate) pins cross-page ascending order; `TestSearchNoMatchReturnsNil` pins the pre-existing nil-vs-empty-slice contract for the no-match case.
  - Exclusions verified untouched: `git status --porcelain internal/server/hostsfile.go internal/server/unboundconf.go internal/server/dnsmasqconf.go internal/server/commands.go` returns empty, and `git diff 7365008 -- internal/server/service.go`'s hunks confirmed to fall entirely outside `CreateSnapshot`/`RollbackToSnapshot`.

## Task Commits

Each task was committed atomically. All four commits in this plan are **signed** (confirmed via `git cat-file commit <sha> | rg -q '^gpgsig'`, not `git log --format='%G?'`, per the session's commit-signing note) — no bypasses needed this plan.

1. **Task 1: Stream-render the json and csv export formats page by page** — TDD, two commits:
   - RED: `132e10a` (test) — `test(server): add failing tests for streaming ExportHosts`
   - GREEN: `fd3ff29` (feat) — `feat(server): stream-render ExportHosts json/csv page by page`
2. **Task 2: Descope hosts explicitly and page-count the hook entry count** — `80659a3` (test) — `test(server): pin hook entry count excludes deleted aggregates`
3. **Task 3: Convert FindByIPAndHostname and Search to streaming page filters** — `9154c51` (feat) — `feat(storage): stream FindByIPAndHostname and Search over ListPage`

## TDD Gate Compliance (Task 1)

Gate sequence verified in git log: `test(server): add failing tests for streaming ExportHosts` (`132e10a`) precedes `feat(server): stream-render ExportHosts json/csv page by page` (`fd3ff29`). No `refactor(...)` commit was needed.

**RED proof (verbatim), before `fd3ff29` landed** — the finished implementation was saved as a diff, `internal/server/service.go` reverted to its pre-plan state, and the new test file (`service_export_stream_test.go`) checked against that reverted file:

```
$ go vet ./internal/server/...
# github.com/fzymgc-house/router-hosts/internal/server
vet: internal/server/service_export_stream_test.go:53:18: undefined: exportPageSize

$ go test ./internal/server/... -run 'TestExportHosts_ChunkBoundaryEquivalenceAcrossPages|TestExportHosts_StorageErrorMidStreamSurfacesAsStatus' -race -count=1 -v
# github.com/fzymgc-house/router-hosts/internal/server [github.com/fzymgc-house/router-hosts/internal/server.test]
internal/server/service_export_stream_test.go:53:18: undefined: exportPageSize
internal/server/service_export_stream_test.go:54:2: undefined: exportPageSize
internal/server/service_export_stream_test.go:55:21: undefined: exportPageSize
internal/server/service_export_stream_test.go:134:18: undefined: exportPageSize
internal/server/service_export_stream_test.go:135:2: undefined: exportPageSize
internal/server/service_export_stream_test.go:136:21: undefined: exportPageSize
FAIL	github.com/fzymgc-house/router-hosts/internal/server [build failed]
FAIL
```

A build failure — a stronger RED signal than a subtle logic-bug RED, matching plan 02-02's precedent.

**GREEN confirmation:** after reapplying the implementation diff (`fd3ff29`), `go test ./internal/server/... -race -count=1` passes cleanly, including both new tests:

```
=== RUN   TestExportHosts_ChunkBoundaryEquivalenceAcrossPages
=== RUN   TestExportHosts_ChunkBoundaryEquivalenceAcrossPages/json
=== RUN   TestExportHosts_ChunkBoundaryEquivalenceAcrossPages/csv
--- PASS: TestExportHosts_ChunkBoundaryEquivalenceAcrossPages (5.00s)
    --- PASS: TestExportHosts_ChunkBoundaryEquivalenceAcrossPages/json (0.05s)
    --- PASS: TestExportHosts_ChunkBoundaryEquivalenceAcrossPages/csv (0.04s)
=== RUN   TestExportHosts_StorageErrorMidStreamSurfacesAsStatus
=== RUN   TestExportHosts_StorageErrorMidStreamSurfacesAsStatus/json
=== RUN   TestExportHosts_StorageErrorMidStreamSurfacesAsStatus/csv
--- PASS: TestExportHosts_StorageErrorMidStreamSurfacesAsStatus (0.02s)
PASS
```

## Demonstrated-RED Proofs

### 1. Task 1's whole streaming implementation (build-failure RED, see TDD Gate Compliance above)

The strongest form of RED: every symbol the new tests reference (`exportPageSize`, and transitively `chunkWriter`/`exportJSONStream`/`exportCSVStream`) did not exist yet, so the package failed to compile. Recorded verbatim above.

### 2. Task 3's early-exit and ordering tests (build-failure RED)

Before `projection.go` was edited, `sqlite_test.go`'s new tests referenced `findByIPAndHostname` (the not-yet-extracted helper):

```
$ go vet ./internal/storage/sqlite/...
# github.com/fzymgc-house/router-hosts/internal/storage/sqlite [github.com/fzymgc-house/router-hosts/internal/storage/sqlite.test]
internal/storage/sqlite/sqlite_test.go:778:16: undefined: findByIPAndHostname
```

After implementing `pageLister`/`findByIPAndHostname` and rewriting `Search`, `go test ./internal/storage/... -race -count=1` passed cleanly, including the three new tests (`TestFindByIPAndHostnameStopsAtFirstMatch`, `TestSearchPreservesAscendingOrderAcrossPages`, `TestSearchNoMatchReturnsNil`).

## Files Created/Modified

- `internal/server/service.go` — `exportPageSize` var; `jsonEntry` hoisted to package scope; new `chunkWriter` type (`newChunkWriter`, `Write`, `flush`, `Close`); new `exportJSONStream`/`exportCSVStream` methods; `ExportHosts` rewritten to dispatch per format (hosts unchanged/inline, json/csv through the new streaming methods); new `countLiveEntries` helper; hook entry-count call site updated.
- `internal/server/service_export_stream_test.go` (new) — `TestExportHosts_ChunkBoundaryEquivalenceAcrossPages`, `fakeChunkCapture`, `TestExportHosts_StorageErrorMidStreamSurfacesAsStatus`, `errAfterNPages`.
- `internal/server/hooks_wiring_test.go` — `TestRegenerateOutputs_EntryCountExcludesDeleted`.
- `internal/storage/sqlite/projection.go` — `pageLister` func type; `FindByIPAndHostname` rewritten as a thin wrapper over new `findByIPAndHostname` helper; `Search` rewritten to stream `ListPage`.
- `internal/storage/sqlite/sqlite_test.go` — `TestFindByIPAndHostnameStopsAtFirstMatch`, `TestSearchPreservesAscendingOrderAcrossPages`, `TestSearchNoMatchReturnsNil`.

## Decisions Made

See `key-decisions` in frontmatter for the three architecturally load-bearing ones (RED/GREEN commit-boundary mechanics, the fixed-capacity-buffer choice for `chunkWriter`, and the `pageLister` func-typed test seam). All three are Rule 1/Rule 3 style implementation choices in service of the plan's own explicit requirements, not scope changes.

## Deviations from Plan

**1. [Process — commit boundary, not scope] Task 2's production changes landed inside Task 1's GREEN commit.**
- **Found during:** Task 1's RED/GREEN cycle.
- **What happened:** The hosts-branch residual comment and the hook entry-count migration (both Task 2's action items) were written in the same initial edit pass as Task 1's streaming rewrite, before the deliberate revert-and-reapply used to produce a genuine RED proof. Reapplying the saved diff for GREEN therefore reintroduced Task 2's code alongside Task 1's.
- **Effect:** `fd3ff29` ("feat(server): stream-render ExportHosts json/csv page by page") contains both Task 1's and Task 2's production code. Task 2's own commit (`80659a3`) is test-only — it adds `TestRegenerateOutputs_EntryCountExcludesDeleted`, the regression coverage for behavior that had already landed.
- **Why not fixed:** CLAUDE.md and this session's protocol both prohibit `git commit --amend`/rebase to retroactively split a landed commit; doing so would also violate "always create NEW commits."
- **Verification unaffected:** every Task 2 acceptance criterion (hosts residual comment present and quoted, hook count excludes deleted entries, five D-04 exclusions untouched, goldens green) is independently verified above regardless of which commit the code landed in.

No architectural deviations (Rule 4) were needed. No auto-fixed bugs (Rule 1) or added-missing-functionality (Rule 2) beyond what the plan's own action text specified.

## Issues Encountered

None — 1Password SSH commit signing worked cleanly for all four commits this plan (unlike plan 02-02, which bypassed all three). No bypasses to record.

## Known Stubs

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `task test` (full `-race` suite, all packages), `task lint` (golangci-lint + buf lint + manifests), and `task test:coverage:ci` (86.4%, threshold 80%) are all green at plan end.
- All four of plan 02-01's golden fixtures remain green with zero fixture-file edits — the byte-identity oracle plan 02-05's benchmark can build on is intact.
- The `out := make([]jsonEntry, len(entries))` full-slice allocation plan 02-05's benchmark needs gone is confirmed gone (quoted above, verified via diff, not grep).
- Ready for plan 02-05 (the benchmark measuring this plan's heap-bounding change).

---
*Phase: 02-cursor-based-lazy-storage-reads*
*Completed: 2026-08-03*

## Self-Check: PASSED

All four task commit hashes (`132e10a`, `fd3ff29`, `80659a3`, `9154c51`) verified present in `git log`. All created/modified files (`internal/server/service.go`, `internal/server/service_export_stream_test.go`, `internal/server/hooks_wiring_test.go`, `internal/storage/sqlite/projection.go`, `internal/storage/sqlite/sqlite_test.go`) confirmed present on disk with the described content. All four plan 02-01 golden fixtures confirmed passing with zero fixture-file diffs since `7365008` (the commit preceding this plan).
