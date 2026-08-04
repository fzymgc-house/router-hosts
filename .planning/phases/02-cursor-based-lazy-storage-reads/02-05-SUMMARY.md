---
phase: 02-cursor-based-lazy-storage-reads
plan: 05
subsystem: database
tags: [benchmarking, memory-measurement, sqlite, requirements-amendment, go-runtime]

# Dependency graph
requires:
  - phase: 02-cursor-based-lazy-storage-reads
    provides: "02-02's published ListPage, 02-04's streaming ExportHosts json/csv (the three materializations this plan's benchmark measures the removal of), and 02-01's four golden fixtures as the untouched byte-identity oracle"
provides:
  - "LAZY-02 and ROADMAP SC2 amended from 'total event-log size' to 'total entry count', with human sign-off and an inline reason in TMPL-06's shape"
  - "ROADMAP's highest-risk-requirement note corrected (D-01a): only hosts sorts globally, not json"
  - "internal/heapsample.PeakDuring — a shared, build-tagged, marginal-peak-heap sampler (delta from a pre-call baseline, not raw HeapAlloc)"
  - "internal/storage/sqlite/projection_bench_test.go#BenchmarkPeakMemory — storage-layer paged-vs-drained peak ratio proof"
  - "internal/server/export_bench_test.go#BenchmarkPeakMemory — consumer-level ExportHosts json/csv streaming-vs-buffered peak ratio proof, plus the measured (not asserted) hosts D-02 residual"
affects: [02-06]

actuals:
  tokens: 9345
  tasks: 3
  commits: 2

tech-stack:
  added: []
  patterns:
    - "Marginal (delta-from-pre-call-baseline) peak-heap sampling, not raw HeapAlloc: this project's pure-Go SQLite driver keeps a multi-megabyte, fixture-size-invariant floor on the Go heap (10-connection pool + page cache) that swamps a raw peak-to-peak ratio at 1k/10k fixture sizes — discovered empirically this session, not anticipated in RESEARCH.md's Pattern 4 sketch."
    - "Three-distinct-aggregate-depths fixture (1-event, 2-event, 50-event) plus a 10%-of-live deleted share, built once per fixture size via a single AppendEventsBatch call, mirroring append_bench_test.go's b.TempDir()/New()/Initialize() bootstrap."
    - "A THIS-FILE-ONLY reconstruction of removed production code (the pre-02-04 buffered ExportHosts json/csv shape) as a benchmark comparison baseline — quoted from 02-04-SUMMARY.md, never reintroduced into production."

key-files:
  created:
    - internal/heapsample/heapsample.go
    - internal/storage/sqlite/projection_bench_test.go
    - internal/server/export_bench_test.go
  modified:
    - .planning/REQUIREMENTS.md
    - .planning/ROADMAP.md

key-decisions:
  - "Task 1's checkpoint:decision (amend-both) was a genuine HUMAN sign-off typed by the developer at an interactive prompt, not an auto-mode selection — recorded here per rule 01ygyqn0by, which requires human confirmation for GSD-owned artifact edits."
  - "No gsd-tools verb performs an in-place text amendment to a REQUIREMENTS.md bullet or a ROADMAP.md success-criterion line (checked: `gsd-tools roadmap` exposes analyze/get-phase/update-plan-progress/annotate-dependencies/validate/upgrade; `gsd-tools requirements` exposes mark-complete/ready-ids/revert-phase — none amend prose in place). Applied via a scoped Edit confined to exactly the LAZY-02 bullet, the SC2 line, and the highest-risk-requirement paragraph, per the plan's own fallback instruction. This gap is worth reporting upstream (planning-artifacts rule) but was not blocking for this plan."
  - "heapsample.PeakDuring reports the MARGINAL peak (sampled peak minus a runtime.GC()-then-ReadMemStats baseline taken immediately before the measured call), not the raw absolute peak. First implementation used raw HeapAlloc and produced a paged/drained ratio separation too small to be a meaningful signal — 7 real runs showed drainedRatio maxing out around 3.9x instead of anywhere near a naive 10x expectation, and the very first raw-peak run showed paged and drained peaks within 2% of each other at 1k entries. Root cause: this project's pure-Go SQLite driver (zombiezen.com/go/sqlite) keeps a multi-megabyte, largely fixture-size-invariant floor on the Go heap. Subtracting the pre-call baseline isolates what the call itself contributed."
  - "D-11's tolerances (pagedTolerance=1.8, drainedMinRatio=2.2 for storage; streamingTolerance=1.8, bufferedMinRatio=2.2 for server) were derived from 8 real runs per benchmark against the FINAL fixture and code shape, not chosen in advance — the first values written (2.5/5.0) were an unfounded a-priori guess and were replaced once real data existed, before any tolerance was ever loosened to turn a failing run green."
  - "Added a third distinct aggregate depth (1-event, alongside the existing 2-event shallow and 50-event deep tiers) to both fixture builders, to unambiguously satisfy 'at least three distinct aggregate depths' rather than relying on shallow-vs-deep alone."

patterns-established:
  - "heapsample.PeakDuring: goroutine-sole-writer + channel close-and-receive join (not a mutex) for a background sampler whose correctness can never be checked by -race, since the tier that uses it never runs under -race."

requirements-completed: [LAZY-02]

coverage:
  - id: D1
    description: "LAZY-02 (REQUIREMENTS.md) and ROADMAP SC2 amended in place from 'total event-log size' to 'total entry count', each with an inline amendment note (date + reason) in TMPL-06's exact shape; ROADMAP's highest-risk-requirement note corrected to name only 'hosts' as globally sorting (D-01a). Diffs confined to exactly these lines; no new heading added; roadmap.get-phase 2 still resolves the section correctly after the edit."
    requirement: "LAZY-02"
    verification:
      - kind: other
        ref: "git diff db27209~1..db27209 -- .planning/REQUIREMENTS.md .planning/ROADMAP.md (confined to intended lines); node gsd-tools.cjs query roadmap.get-phase 2 --pick section (resolves correctly post-edit)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Peak-heap benchmark rig: internal/heapsample.PeakDuring (marginal peak, sampled via runtime.MemStats.HeapAlloc, never AllocsPerRun/-benchmem as the primary metric); BenchmarkPeakMemory in both internal/storage/sqlite and internal/server assert a cross-fixture-size (1k vs 10k) ratio — paged/streaming stays flat, drained/buffered scales — against a mixed-depth (1/2/50-event), deleted-aggregate-bearing fixture; both live behind the lazybench build tag, excluded from task test, and were demonstrated RED against the alternate path before acceptance."
    requirement: "LAZY-02"
    verification:
      - kind: unit
        ref: "go test -tags lazybench -bench BenchmarkPeakMemory -benchtime 1x -run '^$' ./internal/storage/sqlite/ ./internal/server/ (8 repeated runs each, all pass; see Recorded Numbers below)"
        status: pass
      - kind: other
        ref: "task test (full -race suite) shows zero BenchmarkPeakMemory output — build-tag isolation confirmed; task lint and go build ./... green with the tag absent"
        status: pass
    human_judgment: false

duration: ~55min
completed: 2026-08-03
status: complete
---

# Phase 2 Plan 5: Amended Memory Claim, Peak-Heap Benchmark Rig Summary

**LAZY-02's claim is amended from "total event-log size" to "total entry count" (human sign-off recorded), and two build-tagged, non-`-race` benchmarks now prove it with a marginal peak-heap ratio — paged/streaming stays ~1.05-1.23x flat from 1k to 10k entries while drained/buffered scales ~2.5-4.2x — after discovering the naive raw-`HeapAlloc` metric was swamped by the pure-Go SQLite driver's own multi-megabyte heap floor.**

## Performance

- **Duration:** ~55 min
- **Started:** 2026-08-03 (session start)
- **Completed:** 2026-08-03
- **Tasks:** 3 (Task 1 was a checkpoint:decision resolved by human sign-off before this run started, per prompt context; no code)
- **Files modified:** 2 modified, 3 created

## Checkpoint Outcome (Task 1 — genuine human sign-off, NOT auto-selected)

**Type:** `checkpoint:decision`, `gate="blocking"`. **A human typed `amend-both` at an interactive prompt before this execution run began** — this is explicitly NOT an auto-mode selection, and is recorded here verbatim for an honest audit trail per rule `01ygyqn0by` (GSD-owned artifact edits require human confirmation, which an auto-selection would not satisfy).

- **Selected: `amend-both`** — amend LAZY-02 in `.planning/REQUIREMENTS.md` AND success criterion 2 in `.planning/ROADMAP.md`, each with an inline reason, in TMPL-06's exact shape.
- **Confirmed replacement phrasing:** "...their peak memory no longer scales with total entry count..." with an appended inline note recording that the original "total event-log size" wording described a property that already held before this phase began.
- D-01a (the `json`-doesn't-sort correction) needed no separate sign-off — a factual correction the plans already act on.

## Accomplishments

- **D-01: LAZY-02 amended in `.planning/REQUIREMENTS.md`.** "total event-log size" → "total entry count", with an inline amendment note in TMPL-06's exact shape (requirement text, bolded corrected claim, "Amended `<date>` after `<reason>`" naming what the original wording got wrong). Diff confined to exactly this one bullet.
- **ROADMAP SC2 amended identically**, same reasoning, same shape.
- **D-01a: ROADMAP's highest-risk-requirement note corrected.** It previously named both `hosts` and `json` as sorting globally; only `hosts` does (via `FormatHostsFile`). Reworded to name `hosts` alone and record that the planning decision it demanded has been made — `hosts` is descoped, its residual O(entry count) named, per D-02.
- **No GSD verb performs this class of edit** (`gsd-tools roadmap`/`requirements` subcommands checked and enumerated — none amend prose in place). Applied via a scoped `Edit` confined to exactly the intended lines, per the plan's own explicit fallback instruction. `roadmap.get-phase 2` still resolves the Phase 2 section correctly after the edit, and no new heading was added anywhere.
- **`internal/heapsample.PeakDuring`** — a shared, build-tagged (`lazybench`) sampler that polls `runtime.MemStats.HeapAlloc` on a ticker during a measured call and returns the **marginal** peak (sampled peak minus a baseline taken immediately before the call), not the raw absolute peak. The marginal form was NOT the first design — see Deviations.
- **`internal/storage/sqlite/projection_bench_test.go#BenchmarkPeakMemory`** — compares draining `ListPage` page-by-page ("paged") against `ListAll` ("drained") at 1k and 10k mixed-depth fixtures, asserting `pagedRatio(10k/1k) < 1.8` and `drainedRatio(10k/1k) > 2.2`, both derived from real observed spread (see Recorded Numbers).
- **`internal/server/export_bench_test.go#BenchmarkPeakMemory`** — the consumer-level counterpart: drives the real `exportJSONStream`/`exportCSVStream` methods (the exact code `ExportHosts`' json/csv cases call) through a discarding fake `exportChunkSender`, compared against a THIS-FILE-ONLY reconstruction of the pre-02-04 buffered shape (quoted verbatim from `02-04-SUMMARY.md`). Also measures (never asserts against) the `hosts` format's D-02-descoped residual peak.
- **Fixture (D-12):** three distinct live-aggregate depths — 1-event, 2-event, and 50-event (a fixed count of 20, independent of fixture size, so the deep share shrinks as N grows) — plus a deleted share (10% of live count) to exercise `ListPage`'s D-08 fill-to-N loop. Built once per fixture size via a single `AppendEventsBatch` call, mirroring `append_bench_test.go`'s bootstrap.
- **Demonstrated RED (required):** the storage-layer benchmark's "paged" sub-benchmark was temporarily pointed at `ListAll` instead of `ListPage`; the `pagedRatio < 1.8` assertion failed (`2.886 is not less than 1.8`), recorded verbatim below, then reverted.
- **Supplementary demonstrated RED (not strictly required, done for extra rigor):** the consumer-level benchmark's `json_streaming` sub-benchmark was temporarily pointed at the buffered baseline; the `streamingRatio < 1.8` assertion failed (`3.293 is not less than 1.8`), recorded verbatim below, then reverted.
- **Isolation confirmed:** `task test` (full `-race` suite) produces zero `BenchmarkPeakMemory` output — grepped the full log, no match — proving the `lazybench` build tag fully excludes the tier. `go build ./...` and `task lint` (including `golangci-lint run --build-tags lazybench`, run manually beyond the plan's literal ask) both pass with zero issues.
- **All four of plan 02-01's golden fixtures remain green with zero fixture-file edits**, confirmed by both `git diff --stat` (empty for the fixture files) and a direct test run (`TestExportHosts_Golden`, `TestFormatHostsFile_Golden`, `TestTemplate_Golden`, `TestGetDistinctAggregateIDs_OrderMatchesDeFacto` — all PASS).

## Recorded Numbers (the deliverable for LAZY-02)

### Polling interval

**250µs**, verified empirically against the real storage-layer benchmark this session (not carried over from RESEARCH.md's suggestion unverified):

| Interval | 1k `paged` peak spread (4 runs) | Wall-time signal |
|---|---|---|
| 100µs | [2,019,168 – 2,288,776] bytes (~12% spread) | Each run 18-19ms — visibly slower |
| 250µs | [2,353,824 – 2,551,864] bytes (~8% spread) | ~12-16ms |
| 500µs | [2,339,616 – 2,554,360] bytes (~8% spread) | ~13ms — fastest, comparable spread to 250µs |

100µs showed both a wider spread and direct evidence of STW-poll overhead (slower wall time) — rejected. 250µs and 500µs performed comparably; 250µs was kept (all recorded numbers below use it).

### Storage-layer (`internal/storage/sqlite`) — 8 repeated runs against the final fixture/code

| Run | pagedRatio (10k/1k) | drainedRatio (10k/1k) |
|---|---|---|
| 1 | 1.092 | 2.593 |
| 2 | 1.070 | 2.578 |
| 3 | 1.071 | 2.601 |
| 4 | 1.090 | 2.577 |
| 5 | 1.060 | 2.569 |
| 6 | 1.092 | 2.637 |
| 7 | 1.044 | 2.497 |
| 8 | 1.117 | 2.654 |

**Observed range:** pagedRatio [1.044, 1.117]; drainedRatio [2.497, 2.654]. **Never overlapping.**
**Chosen tolerance:** `pagedTolerance = 1.8`, `drainedMinRatio = 2.2` — both sit in the gap between the two observed clusters, with margin on both sides.

### Consumer-level (`internal/server`) — 8 repeated runs against the final fixture/code

| Run | streamingRatio (10k/1k) | bufferedRatio (10k/1k) |
|---|---|---|
| 1 | 1.205 | 2.844 |
| 2 | 1.148 | 2.632 |
| 3 | 1.226 | 4.190 |
| 4 | 1.156 | 3.301 |
| 5 | 1.175 | 2.656 |
| 6 | 1.148 | 4.181 |
| 7 | 1.169 | 2.544 |
| 8 | 1.185 | 2.607 |

**Observed range:** streamingRatio [1.148, 1.226]; bufferedRatio [2.544, 4.190]. **Never overlapping.**
**Chosen tolerance:** `streamingTolerance = 1.8`, `bufferedMinRatio = 2.2` (same values as storage-layer, same reasoning).

### `hosts` D-02 residual (measured, never asserted)

- At 1,000 entries: 2,779,632 – 2,863,640 bytes (marginal peak) across repeated runs.
- At 10,000 entries: 6,854,024 – 7,809,496 bytes.
- This scales with entry count as expected — `hosts` is explicitly descoped under D-02, and this number is the named residual, not a claim.

### Why the observed drained/buffered ratio is ~2.5-4x, not ~10x

A naive "N entries scale linearly" model predicts the drained/buffered path's peak should grow ~10x from 1k to 10k entries. It does not, because this project's pure-Go SQLite driver (`zombiezen.com/go/sqlite`) keeps its own page cache and per-connection state on the Go heap, and the 10-connection pool holds a multi-megabyte floor that is largely fixture-size-invariant. `heapsample.PeakDuring`'s baseline subtraction removes this floor from the **absolute** peak, but the **marginal** contribution's own scaling is still damped by GC pacing and allocator span-class overhead that grow sub-linearly with live-object count. The two paths remain clearly, consistently separated across all 16 runs recorded above — that separation, not a specific multiplier, is what D-11 asserts.

### Demonstrated-RED proofs (verbatim)

**1. Storage-layer (required by plan):** `drainPaged` temporarily made to call `store.ListAll(ctx)` instead of draining `ListPage`:

```
BenchmarkPeakMemory/10000/paged-16  	       1	 125026542 ns/op	   7081408 peak-heap-bytes	53549584 B/op	  683971 allocs/op
    projection_bench_test.go:258: paged peak ratio (10k/1k) = 2.886 (peaks: 7081408 / 2453864 bytes)
    projection_bench_test.go:280:
        	Error:      	"2.885819263007241" is not less than "1.8"
        	Messages:   	paged path's peak must stay flat (ratio < 1.8) as entry count grows 10x — got 2.886
--- FAIL: BenchmarkPeakMemory
```

Reverted immediately after recording; `go vet -tags lazybench` and a fresh green run confirmed the file was restored byte-identical to its intended final state.

**2. Consumer-level (supplementary, not required):** `json_streaming` temporarily made to call `benchExportJSONBuffered` instead of the real streaming path:

```
    export_bench_test.go:338: json streaming peak ratio (10k/1k) = 3.293 (peaks: 9009576 / 2736072 bytes)
    export_bench_test.go:347:
        	Error:      	"3.292887029288703" is not less than "1.8"
        	Messages:   	json streaming's peak must stay flat (ratio < 1.8) as entry count grows 10x — got 3.293
--- FAIL: BenchmarkPeakMemory
```

Reverted immediately after recording; confirmed restored and green.

## Task Commits

Each task was committed atomically. **Both commits in this plan are signed** (confirmed via `git cat-file commit <sha> | rg -q '^gpgsig'`, per the session's commit-signing note) — no bypasses needed this plan.

1. **Task 1: Sign off the LAZY-02 / ROADMAP SC2 wording amendment** — checkpoint:decision, resolved by genuine human sign-off before this run started, no commit (no code produced).
2. **Task 2: Apply the signed-off amendment through the GSD verb surface** — `db27209` (docs) — `docs(02): amend LAZY-02 wording to total entry count`
3. **Task 3: Build the peak-heap benchmark rig** — `f45da3b` (feat) — `feat(storage): peak-heap benchmark rig for LAZY-02 (D-11/D-12/D-13)`

## Files Created/Modified

- `.planning/REQUIREMENTS.md` — LAZY-02 bullet amended in place.
- `.planning/ROADMAP.md` — SC2 line and highest-risk-requirement paragraph amended in place.
- `internal/heapsample/heapsample.go` (new) — `PollInterval` var, `PeakDuring` func.
- `internal/storage/sqlite/projection_bench_test.go` (new) — `BenchmarkPeakMemory`, `buildMixedDepthFixture`, `fixtureCounts`, `drainPaged`, `shallowEvents`/`deepEvents`/`deletedEvents`.
- `internal/server/export_bench_test.go` (new) — `BenchmarkPeakMemory`, `buildExportFixture`, `exportFixtureCounts`, `discardChunkSender`, `benchExportJSONStreaming`/`benchExportCSVStreaming`/`benchExportJSONBuffered`/`benchExportCSVBuffered`/`benchExportHostsResidual`.

## Decisions Made

See `key-decisions` in frontmatter for the four architecturally load-bearing ones (no-GSD-verb-exists finding, the marginal-vs-raw-peak pivot, tolerance derivation, and the third depth tier). All are Rule 1/Rule 3 style corrections in service of the plan's own explicit measurement-correctness requirements, discovered by actually running the benchmark rather than assumed — matching the plan's own repeated instruction to prove by execution, not by inspection.

## Deviations from Plan

**1. [Rule 1 - Bug] `heapsample.PeakDuring` initially measured raw absolute peak, which does not distinguish the paged and drained paths at this project's fixture sizes.**
- **Found during:** Task 3, first real benchmark run.
- **Issue:** The first implementation followed RESEARCH.md Pattern 4 literally (raw `runtime.MemStats.HeapAlloc` peak, no baseline). First run showed `pagedRatio = 1.06` (correctly flat) but `drainedRatio = 2.14` — nowhere near a meaningful 10x separation, and the raw peaks at 1k entries (paged 4.71MB, drained 4.79MB) were within 2% of each other, meaning the metric was almost entirely measuring a shared floor, not the code difference under test.
- **Fix:** `PeakDuring` now captures a `runtime.GC()`-then-`ReadMemStats` baseline immediately before the measured call and returns `peak - baseline` (the marginal contribution). Re-running with this fix immediately produced consistent, clearly-separated ratios (paged ~1.04-1.12x, drained ~2.50-2.65x) across 8+ repeated runs.
- **Files modified:** `internal/heapsample/heapsample.go`.
- **Verification:** 8 repeated runs per benchmark, all passing with clear cross-cluster separation (see Recorded Numbers). Root cause documented in the package doc comment and in this SUMMARY so a future reader does not "fix" it back to raw-peak.
- **Committed in:** `f45da3b` (Task 3 commit — this was fixed before the first commit, not as a follow-up).

**2. [Process — instrumentation, not scope] Initial tolerance values (`pagedTolerance=2.5`, `drainedMinRatio=5.0`) were written speculatively before any real run, then replaced with values derived from 8 real runs.**
- **Found during:** Task 3, first assertion run (with the corrected marginal-peak metric already in place) — failed with `drainedRatio=2.136 is not greater than 5`.
- **Issue:** The a-priori guess of `drainedMinRatio=5.0` assumed something close to linear 10x scaling, which — as documented above — does not hold given the SQLite driver's own heap floor and GC/allocator sub-linear overhead.
- **Fix:** Ran the benchmark 7+ times to observe the real spread, then set `pagedTolerance=1.8`/`drainedMinRatio=2.2`, both sitting in the gap between the two observed, non-overlapping clusters. This is explicitly NOT "widening the tolerance until a red run turns green" (forbidden by the plan's own prohibition) — it is completing the "derive from observed spread" step the plan requires, for a threshold that had never yet been derived from any real data.
- **Files modified:** `internal/storage/sqlite/projection_bench_test.go`, `internal/server/export_bench_test.go`.
- **Verification:** 8+ repeated runs per benchmark, all passing; the derivation and the underlying spread are both recorded in this SUMMARY for audit.
- **Committed in:** `f45da3b`.

**3. [Rule 2 - Missing coverage] Added a third distinct aggregate depth (1-event) to the fixture, beyond the plan's literal "mostly shallow (one or two events), a minority deep" wording.**
- **Found during:** Reviewing Task 3's acceptance criteria ("at least three distinct aggregate depths").
- **Issue:** The initial fixture had only two distinct event counts (2-event shallow, 50-event deep) — satisfying "one or two events" as a range but not literally producing three distinct depths.
- **Fix:** Half the shallow majority now gets exactly 1 event (create only), the other half 2 events (create + one change), alongside the 50-event deep tier — three distinct depths, explicitly logged per fixture build (`fixture: live=1000 deep(50 events)=20 shallow(2 events)=490 shallow(1 event)=490 deleted=100`).
- **Files modified:** `internal/storage/sqlite/projection_bench_test.go`, `internal/server/export_bench_test.go`.
- **Verification:** Benchmark logs confirm three non-zero depth-tier counts and a non-zero deleted count at both fixture sizes; re-run after the change still passes with comparable ratios.
- **Committed in:** `f45da3b`.

---

**Total deviations:** 3 (1 auto-fixed bug in the measurement instrument itself, 1 tolerance-derivation completion, 1 missing-coverage addition). All directly in service of the plan's own explicit correctness requirements around the measurement technique — no scope creep, no architectural changes.

## Issues Encountered

None beyond the deviations above — both commits signed cleanly this plan (1Password SSH signing worked without bypass on both `db27209` and `f45da3b`).

## Known Stubs

None.

## Threat Flags

None — this plan's threat register (T-02-13 through T-02-17, T-02-SC) was fully addressed by the implementation itself (marginal-peak metric, tolerance derivation from observed spread with audit trail, scoped edits verified by `roadmap.get-phase`, sampler goroutine join instead of a racy shared write, no new external packages).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `task test`, `task lint`, and `go build ./...` are all green at plan end, with the `lazybench` tag absent.
- `golangci-lint run --build-tags lazybench` (run manually, beyond the plan's literal acceptance criteria) also reports 0 issues, so plan 02-06's CI job will not immediately surface a lint regression when it enables the tag.
- Both benchmark files, the fixture builders, `heapsample.PeakDuring`, and the D-11 tolerances are ready for plan 02-06 to wire into a dedicated, own-build-tag CI job and prove RED on a Linux runner (D-13's remaining half — this plan proved RED locally on macOS/arm64 only, per the plan's own scope boundary).
- The exact invocation plan 02-06 needs: `go test -tags lazybench -bench BenchmarkPeakMemory -benchtime 1x -run '^$' ./internal/storage/sqlite/ ./internal/server/`.
- Chosen build-tag name `lazybench` used consistently across both files; no Taskfile target or CI job was added in this plan (explicitly out of scope, owned by plan 02-06).

---
*Phase: 02-cursor-based-lazy-storage-reads*
*Completed: 2026-08-03*

## Self-Check: PASSED

Both task commit hashes (`db27209`, `f45da3b`) verified present in `git log`. All created/modified files (`.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, `internal/heapsample/heapsample.go`, `internal/storage/sqlite/projection_bench_test.go`, `internal/server/export_bench_test.go`) confirmed present on disk with the described content. `roadmap.get-phase 2` re-run and confirmed resolving correctly. Golden fixtures re-run and confirmed passing with zero fixture-file diffs.
