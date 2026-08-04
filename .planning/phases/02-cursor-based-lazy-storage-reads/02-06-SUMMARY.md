---
phase: 02-cursor-based-lazy-storage-reads
plan: 06
subsystem: testing
tags: [ci, github-actions, benchmark-gate, taskfile, ciwiring, documentation]

# Dependency graph
requires:
  - phase: 02-cursor-based-lazy-storage-reads
    provides: "02-05's lazybench-tagged BenchmarkPeakMemory rig in internal/storage/sqlite and internal/server, and the exact go test invocation this plan wires into a task target"
provides:
  - "task test:bench:lazy target and bench-lazy Linux CI job folded into ci-go-complete's needs/env/comparison chain"
  - "internal/ciwiring invariant generalized from e2e-*-only to e2e-*/bench-*, proven with teeth (four demonstrated-RED runs)"
  - "The gate demonstrated RED on a real Linux CI runner (D-13, Phase 1 D-16, memory cq0rfk0qjc) — including catching a real defect in the gate's own tolerance on its first Linux run, not just a synthetic regression"
  - "The drained-arm assertion fixed from an absolute magnitude (drainedRatio > 2.2, macOS-derived) to a separation check (drainedRatio > pagedRatio * 1.4), itself proven still-live by a Linux deliberate-regression RED run"
  - "docs/contributing/testing.md and .planning/codebase/TESTING.md document the tier for contributors"
affects: []

actuals:
  tokens: 5615
  tasks: 3
  commits: 4

tech-stack:
  added: []
  patterns:
    - "internal/ciwiring's job-id matcher generalized from a single ^e2e- regex to an alternation (^(?:e2e|bench)-), so a future gated-tier prefix joins the invariant by extending one regex rather than duplicating the assertion block."
    - "Benchmark ratio assertions compare SEPARATION between two measured ratios (drainedRatio > pagedRatio * 1.4) rather than an absolute magnitude threshold, because a magnitude derived from repeated local runs on one OS/arch is exactly as machine-specific as a locally-observed behavior — proven by this plan's own Linux CI run going red against a macOS-derived constant."

key-files:
  created: []
  modified:
    - Taskfile.yml
    - .github/workflows/ci-go.yml
    - internal/ciwiring/ciwiring_test.go
    - internal/ciwiring/doc.go
    - internal/storage/sqlite/projection_bench_test.go
    - docs/contributing/testing.md
    - .planning/codebase/TESTING.md

key-decisions:
  - "Job id bench-lazy and task target test:bench:lazy (finalizing the plan's working names bench/test:bench)."
  - "internal/ciwiring's TestEveryE2ETierIsWiredIntoAggregator renamed to TestEveryGatedTierIsWiredIntoAggregator to match its widened scope (e2e-* and bench-*), with e2eJobPattern/e2eJobIDs/e2eNeedsIDs renamed to gatedTierJobPattern/gatedTierJobIDs/gatedTierNeedsIDs. All existing assertions (set equality, one env var per tier, != \"success\" comparison style, no == \"failure\", if: always(), aggregator name, workflow_dispatch present) preserved unchanged, now evaluated over the union of both prefixes."
  - "CI job timeout kept at 8 minutes, matching e2e-proc's value — local run of task test:bench:lazy completed in ~2.7s wall clock, far under any adjustment threshold."
  - "The drained-arm assertion was changed from a fixed absolute magnitude (drainedRatio > 2.2, derived from 15 local macOS/arm64 runs) to a separation check against the paged path's own ratio (drainedRatio > pagedRatio * 1.4), after the fixed magnitude went RED on its first real Linux CI run. This is NOT a threshold widening — the load-bearing pagedRatio < 1.8 bound is unchanged, and the new separation check was itself proven still-live by a deliberate-regression RED run on Linux CI (run 30868423963)."
  - "The Linux-runner RED proof used workflow_dispatch on a real branch plus a short-lived scratch branch for the deliberate-regression proof, rather than opening a PR — workflow_dispatch runs the full workflow including ci-go-complete without needing a PR, and the scratch branch was deleted (remotely and locally) once its RED evidence was captured."

patterns-established:
  - "When a benchmark-derived tolerance is expressed as a ratio, prefer separation between two measured ratios over an absolute magnitude — a magnitude threshold silently encodes the OS/arch it was tuned on."

requirements-completed: [LAZY-02]

coverage:
  - id: D1
    description: "Benchmark tier wired into Taskfile (task test:bench:lazy, no -race, no build dep) and CI (bench-lazy Linux job) via ci-go-complete's needs/env/comparison chain; internal/ciwiring's structural invariant generalized to cover e2e-*/bench-* and proven to have teeth"
    requirement: "LAZY-02"
    verification:
      - kind: unit
        ref: "internal/ciwiring/ciwiring_test.go#TestEveryGatedTierIsWiredIntoAggregator"
        status: pass
      - kind: other
        ref: "task --list (shows test:bench:lazy); task lint (golangci-lint, buf, manifests, yamlfmt all green)"
        status: pass
    human_judgment: false
  - id: D2
    description: "Gate proven RED on a real Linux CI runner per D-13/Phase-1-D-16/memory cq0rfk0qjc: the first real Linux run caught a genuine defect in the gate's own macOS-derived tolerance (not the synthetic regression), the fix was verified green on Linux, and a deliberate-regression RED proof confirmed both the tier job and ci-go-complete fail together and recover together"
    requirement: "LAZY-02"
    verification:
      - kind: other
        ref: "GitHub Actions workflow_dispatch runs 30867901912 (baseline — real defect caught RED), 30868301454 (post-fix verification green), 30868423963 (deliberate-regression RED proof on scratch branch scratch/bench-red-proof, commit 14c2bb6, since deleted)"
        status: pass
    human_judgment: true
    rationale: "This class of verification is inherently a human/orchestrator-run step: it requires an authorized git push to real GitHub Actions infrastructure and interpretation of live CI run results, which is why the plan encodes it as a blocking checkpoint rather than an in-agent automated check. The orchestrator performed and reported the evidence, recorded verbatim below, but the verification method itself is manual_procedural in kind even though every individual data point (exit codes, assertion failure text) is objective."
  - id: D3
    description: "docs/contributing/testing.md and .planning/codebase/TESTING.md document the benchmark tier: build tag, task target, CI job name, what it asserts (ratio, not absolute ceiling) and why, that allocs/op and B/op are informational only, the 250us polling interval and its stop-the-world caveat, and the hosts-format expected-scaling exception"
    requirement: "LAZY-02"
    verification:
      - kind: other
        ref: "rumdl check docs/contributing/testing.md .planning/codebase/TESTING.md (Success: No issues found); task lint; task test"
        status: pass
    human_judgment: false

duration: ~40min across the plan (Task 1 ~15min, Task 2 Linux-CI verification by orchestrator, Task 3 ~10min this run)
completed: 2026-08-03
status: complete
---

# Phase 2 Plan 6: Benchmark Tier Wired Into CI, Proven RED on Linux, Documented

**LAZY-02's peak-heap benchmark is now a required, blocking Linux CI gate (`bench-lazy` job via `task test:bench:lazy`) whose first real Linux run caught a genuine defect in its own macOS-derived tolerance — not the synthetic regression it was built to catch — and the fix (separation-based, not magnitude-based) was itself proven RED on Linux before being trusted.**

## Performance

- **Duration:** ~40 min of agent tool time total across the plan (Task 1 ~15 min in the original run; Task 2 was a blocking human-verify checkpoint resolved by the orchestrator against real GitHub Actions CI; Task 3 ~10 min in this run).
- **Started:** 2026-08-03.
- **Completed:** 2026-08-03.
- **Tasks:** 3 of 3 completed.
- **Files modified:** 7 (Taskfile.yml, .github/workflows/ci-go.yml, internal/ciwiring/ciwiring_test.go, internal/ciwiring/doc.go, internal/storage/sqlite/projection_bench_test.go, docs/contributing/testing.md, .planning/codebase/TESTING.md).

## Accomplishments

- **Task 1 — CI wiring.** `Taskfile.yml` gained `test:bench:lazy` (no `deps:`, no `-race`), `.github/workflows/ci-go.yml` gained a `bench-lazy` Linux job folded into `ci-go-complete`'s `needs:`/env/comparison chain, and `internal/ciwiring/ciwiring_test.go`'s structural invariant was generalized from `^e2e-`-only to `^(?:e2e|bench)-` and proven to have teeth via three demonstrated-RED runs (new job removed from `needs:`, its result env var removed, and — proving the generalization didn't weaken the original check — `e2e-proc` removed from `needs:`).
- **Task 2 — proven RED on a real Linux CI runner, and it found a real bug.** The mandatory Linux-runner RED proof (D-13, Phase 1 D-16, memory `cq0rfk0qjc`: a green run on macOS proves nothing about Linux CI) did not merely rubber-stamp the gate — its very first execution on Linux CI **failed for a reason nobody anticipated**: the drained-arm assertion's fixed `drainedRatio > 2.2` threshold, derived entirely from 15 local macOS/arm64 runs, did not travel to Linux/amd64, where the allocator and GC grow the drained path's marginal peak less. This is the single most useful finding of this plan — see "The Linux RED Proof Found a Real Defect" below for the full account. The tolerance was fixed to assert separation from the paged ratio instead of an absolute magnitude (commit `a0691da`), and that fix was itself proven still-live with a deliberate-regression RED run on Linux CI before being accepted.
- **Task 3 — contributor documentation.** `docs/contributing/testing.md` gained a "Benchmark Gate: peak-heap regression check (`lazybench`, LAZY-02)" section documenting the build tag, task target, CI job, the ratio-not-magnitude design and why (including the Linux-CI story above, so a future contributor cannot casually "simplify" it back), the informational-only nature of `allocs/op`/`B/op`, the 250µs polling interval and its stop-the-world caveat, and the `hosts`-format expected-scaling exception. `.planning/codebase/TESTING.md` got a matching, shorter summary.

## Task Commits

Each task was committed atomically. Task 2's checkpoint resolution (the tolerance fix) was performed and committed by the orchestrator between Task 1 and Task 3 of this execution.

1. **Task 1: Wire the benchmark tier into Taskfile, CI, and the ciwiring invariant** — `950c82f` (feat) — `feat(ci): gate LAZY-02 benchmark tier in CI`.
2. *(interim progress record, not a task commit)* `d7951b6` (docs) — `docs(02-06): record Task 1 progress; paused at Task 2 checkpoint`.
3. **Task 2 checkpoint resolution: fix the drained-arm tolerance after the Linux RED proof caught a real defect** — `a0691da` (fix) — `fix(test): assert peak-heap separation not magnitude`.
4. **Task 3: Document the benchmark tier for contributors** — `e75c2c6` (docs) — `docs(02-06): document the lazybench benchmark gate`. Signed cleanly, confirmed via `git cat-file commit e75c2c6 | rg -q '^gpgsig'` — no signing bypass needed.

**Plan metadata:** recorded in this commit's own metadata commit (STATE.md/ROADMAP.md/REQUIREMENTS.md/this SUMMARY.md).

## Files Created/Modified

- `Taskfile.yml` — added `test:bench:lazy` target.
- `.github/workflows/ci-go.yml` — added `bench-lazy` job; extended `ci-go-complete`'s `needs:`/env/comparison chain.
- `internal/ciwiring/ciwiring_test.go` — generalized the gated-tier invariant (`TestEveryGatedTierIsWiredIntoAggregator`).
- `internal/ciwiring/doc.go` — updated package comment to describe "gated-tier" jobs (e2e-* and bench-*).
- `internal/storage/sqlite/projection_bench_test.go` — drained-arm assertion changed from `drainedRatio > 2.2` (absolute magnitude) to `drainedRatio > pagedRatio * 1.4` (separation), with the reasoning written into the code comment.
- `docs/contributing/testing.md` — new "Benchmark Gate" section plus an updated CI Integration table/description covering `bench-lazy`.
- `.planning/codebase/TESTING.md` — added the benchmark-gate run command and a "Benchmark Gate (LAZY-02)" summary under Test Types.

## Decisions Made

See `key-decisions` in frontmatter: job/task-target naming (`bench-lazy` / `test:bench:lazy`), the rename of the invariant test and its helpers to reflect the widened scope, keeping the 8-minute CI timeout, the separation-not-magnitude fix to the drained-arm assertion (and why it is not a threshold widening), and using `workflow_dispatch` plus a scratch branch instead of an unmerged PR for the Linux-runner proof.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed the drained-arm benchmark assertion's non-portable absolute threshold**

- **Found during:** Task 2 (the mandatory Linux-runner RED proof, which the plan requires precisely because a green macOS run proves nothing about Linux CI).
- **Issue:** `BenchmarkPeakMemory`'s drained-arm assertion (`drainedRatio > 2.2`) was derived from 15 local macOS/arm64 runs. Its first real Linux CI run (`workflow_dispatch` run `30867901912`, `goos=linux goarch=amd64`, AMD EPYC) failed: `pagedRatio` was `1.010` (well inside its `< 1.8` bound — this half of the gate is portable) but `drainedRatio` was only `1.775`, below the macOS-derived `2.2` floor. Root cause: Linux's allocator/GC grow the drained path's marginal peak less than macOS's do, so the *qualitative* separation held (1.775 vs 1.010 is still decisive) but the *magnitude* constant did not travel.
- **Fix:** Replaced the fixed magnitude with a separation check against the paged path's own measured ratio: `require.Greaterf(b, drainedRatio, pagedRatio*1.4, ...)`. The load-bearing `pagedRatio < 1.8` bound is unchanged. The reasoning (including the specific Linux run numbers) is written directly into `projection_bench_test.go`'s comment so a future maintainer cannot "simplify" it back to a fixed multiplier without first reading why it isn't one.
- **Files modified:** `internal/storage/sqlite/projection_bench_test.go`.
- **Verification:** Verified green against real Linux CI (`workflow_dispatch` run `30868301454`, all 12 jobs including `bench-lazy` and `CI (Go) Complete` succeeded). The fix was then itself proven still-live with a deliberate-regression RED run on a real Linux runner (`workflow_dispatch` run `30868423963`, scratch branch `scratch/bench-red-proof`) — removing the drained arm's `ListAll` retention collapsed both paths to near-flat and the new separation assertion correctly failed (see full evidence below), proving the fix is not a rubber stamp.
- **Committed in:** `a0691da` (fix commit, part of Task 2's checkpoint resolution).

---

**Total deviations:** 1 auto-fixed (Rule 1 — bug in the gate's own portability, caught by doing exactly what the plan required: proving it on a real Linux runner before trusting it).
**Impact on plan:** This is the deviation the plan's Task 2 checkpoint existed to catch. It did not merely validate the gate — it found and fixed a real correctness defect in the gate itself, which is the single most valuable outcome of this plan and is documented at length in `docs/contributing/testing.md` so it does not get quietly reverted by a future contributor.

## Issues Encountered

None beyond the deviation documented above, which is itself the intended outcome of Task 2's mandatory Linux-runner proof rather than an unplanned failure.

## The Linux RED Proof Found a Real Defect (Task 2, full evidence)

D-13 requires this gate to be proven RED on a real Linux CI runner before acceptance (Phase 1 D-16: any gate this phase writes must itself be demonstrated red; durable memory `cq0rfk0qjc`: a green run on macOS proves nothing about Linux CI). This plan's own execution is the sharpest illustration of why that rule exists: the very first Linux run did not go green as expected — it caught a **real defect in the gate's own tolerance**, not the deliberate regression the proof was designed to test for. Recorded verbatim below.

### Step 1 — baseline dispatch revealed a REAL failure (not the deliberate one)

Run `30867901912` (`workflow_dispatch`, ref `docs/start-milestone-v0.14.0`, `goos=linux goarch=amd64`, AMD EPYC). `Benchmark (lazy storage reads)` FAILED, exit code 201, and `CI (Go) Complete` failed with it.

- storage `paged` peak ratio (10k/1k) = **1.010** (3,529,904 / 3,495,632 bytes) — the load-bearing `< 1.8` bound PASSED
- storage `drained` peak ratio = **1.775** (6,171,688 / 3,476,648 bytes)
- Failure: `projection_bench_test.go:313: "1.7751834525669552" is not greater than "2.2"` — `drained path's peak must scale with entry count (ratio > 2.2) — got 1.775`
- The entire `internal/server` consumer benchmark PASSED: `json_streaming` 3,295,472 -> 3,354,400 (**flat, 1.02**), `json_buffered_preD03` 3,292,208 -> 8,647,336 (**scales, 2.63**), `csv_streaming` flat 1.02, `csv_buffered_preD03` scales 2.56, `hosts_D02_residual` 3,290,472 -> 8,616,336 (measured, not asserted)

**Root cause:** the `drainedRatio > 2.2` NEGATIVE CONTROL was an absolute magnitude derived from 15 local macOS/arm64 runs. Linux/amd64's allocator and GC grow the drained path's marginal peak less, so the constant did not travel — even though the qualitative behavior did (1.775 vs 1.010 is still a decisive gap). A tolerance derived from repeated LOCAL runs is exactly as machine-specific as a locally-observed behavior. This is the threshold-level form of the repo's existing "green on macOS proves nothing about Linux CI" lesson.

### Fix (user-approved, commit `a0691da`)

The drained arm now asserts SEPARATION from `pagedRatio` (`drainedRatio > pagedRatio * 1.4`) instead of an absolute magnitude. The load-bearing `pagedRatio < 1.8` bound is UNCHANGED. This is explicitly NOT a widened threshold — it was proven still-live by a demonstrated-RED (below). The reasoning is written into the code comment so it is not "simplified" back.

### Step 2 — verification run GREEN on Linux

Run `30868301454`, all 12 jobs success including `Benchmark (lazy storage reads)` and `CI (Go) Complete`. Linux numbers: paged 3,442,568 -> 3,634,024; drained 3,489,640 -> 6,155,664; `json_streaming` 3,802,184 -> 3,379,336 (flat); `json_buffered_preD03` 2,785,104 -> 8,679,192 (scales).

### Step 3 — deliberate-regression RED proof on a real Linux runner

Scratch branch `scratch/bench-red-proof`, run `30868423963`. The regression removed the drained arm's `ListAll` retention so both arms go flat and separation collapses. Result: `Benchmark (lazy storage reads): failure` AND `CI (Go) Complete: failure` — proving both that the gate catches a real regression on Linux and that the `ci-go-complete` `needs:` binding propagates it.

- `projection_bench_test.go:286: paged peak ratio (10k/1k) = 1.028 (peaks: 3569368 / 3473496 bytes)`
- `projection_bench_test.go:287: drained peak ratio (10k/1k) = 1.068 (peaks: 3698280 / 3463400 bytes)`
- `Error: "1.0678177513426113" is not greater than "1.4386414148742361"`
- `Messages: drained path's peak must scale while the paged path stays flat: drainedRatio must exceed pagedRatio by 1.4x — got drained 1.068 vs paged 1.028 (threshold 1.439)`

### Step 4 — cleanup

Scratch branch deleted both remotely and locally (was `14c2bb6`); feature branch verified clean and back on `docs/start-milestone-v0.14.0`. No PR was opened — `workflow_dispatch` was used instead, which runs the full workflow including `ci-go-complete` without needing a PR.

## Task 1 Verification (all run and recorded verbatim)

### Baseline green

```
$ go test ./internal/ciwiring/... -race -count=1 -v
=== RUN   TestEveryGatedTierIsWiredIntoAggregator
--- PASS: TestEveryGatedTierIsWiredIntoAggregator (0.00s)
PASS
ok  	github.com/fzymgc-house/router-hosts/internal/ciwiring	1.092s
```

### Demonstrated-RED proof 1 — `bench-lazy` removed from `ci-go-complete`'s `needs:`

```
$ go test ./internal/ciwiring/... -race -count=1 -v
=== RUN   TestEveryGatedTierIsWiredIntoAggregator
    ciwiring_test.go:174: gated-tier jobs and ci-go-complete.needs are out of sync: declared but not needed=[bench-lazy], needed but not declared=[]
--- FAIL: TestEveryGatedTierIsWiredIntoAggregator (0.00s)
FAIL
```

Restored; re-run confirmed green (matches Baseline green above).

### Demonstrated-RED proof 2 — `BENCH_LAZY_RESULT` env var binding removed

```
$ go test ./internal/ciwiring/... -race -count=1 -v
=== RUN   TestEveryGatedTierIsWiredIntoAggregator
    ciwiring_test.go:189: ci-go-complete has no env var bound to ${{ needs.bench-lazy.result }}
--- FAIL: TestEveryGatedTierIsWiredIntoAggregator (0.00s)
FAIL
```

Restored; re-run confirmed green.

### Demonstrated-RED proof 3 — `e2e-proc` removed from `needs:` (proves the generalization did not weaken the original e2e-tier check)

```
$ go test ./internal/ciwiring/... -race -count=1 -v
=== RUN   TestEveryGatedTierIsWiredIntoAggregator
    ciwiring_test.go:174: gated-tier jobs and ci-go-complete.needs are out of sync: declared but not needed=[e2e-proc], needed but not declared=[]
--- FAIL: TestEveryGatedTierIsWiredIntoAggregator (0.00s)
FAIL
```

Restored; re-run confirmed green.

### `task --list` shows the new target

```
* test:bench:lazy:        Run the LAZY-02 peak-heap benchmark gate (no -race; race distorts the allocation accounting being measured)
```

### `task test` proven by execution not to run the benchmark tier

`task test` (full `-race` suite) run to completion, green. Its full output was grepped for `BenchmarkPeakMemory`: zero matches — confirmed by execution, not by inspecting the build tag.

### SHA byte-identity between `bench-lazy` and `e2e-proc`

Direct `awk`-scoped extraction of each job block's `uses:`/`go-version-file`/`cache:` lines showed `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, `actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`, and `namespacelabs/nscloud-cache-action@c5f8dab7560444c4bf8dbc64f1b203431873c547` byte-identical between the two blocks.

### `task lint` and `yamlfmt -lint` green

`task lint` (golangci-lint, buf lint/format, manifests verify) passed with 0 issues. `yamlfmt -lint .github/workflows/ci-go.yml Taskfile.yml` passed with no diff required.

## Task 3 Verification (this run)

```
$ rumdl check docs/contributing/testing.md .planning/codebase/TESTING.md
Success: No issues found in 1 file (18ms)
```

`task lint` green (golangci-lint 0 issues; buf lint/format clean; manifests up to date). `task test` (full `-race` suite) green across all packages, including `internal/ciwiring`. The pre-commit `lint-markdown`/`fmt-markdown` lefthook hooks also ran clean on the Task 3 commit.

## User Setup Required

None.

## Next Phase Readiness

Phase 2 (Cursor-Based Lazy Storage Reads) plan 6 of 6 is complete. LAZY-02's benchmark is a required, blocking, Linux-proven CI gate with contributor documentation, closing out D-13 (own-build-tag benchmark tier wired into CI and demonstrated RED) for this phase. This was the last plan in the phase.

---
*Phase: 02-cursor-based-lazy-storage-reads*
*Completed: 2026-08-03*

## Self-Check: PASSED

All 7 modified files and this SUMMARY.md confirmed present on disk; all 4 recorded commit hashes (950c82f, d7951b6, a0691da, e75c2c6) confirmed present in `git log --oneline --all`.
