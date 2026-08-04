---
phase: 02-cursor-based-lazy-storage-reads
plan: 06
subsystem: testing
tags: [ci, github-actions, benchmark-gate, taskfile, ciwiring]

# Dependency graph
requires:
  - phase: 02-cursor-based-lazy-storage-reads
    provides: "02-05's lazybench-tagged BenchmarkPeakMemory rig in internal/storage/sqlite and internal/server, and the exact go test invocation this plan wires into a task target"
provides:
  - "Task 1 ONLY: task test:bench:lazy target, bench-lazy CI job, ci-go-complete needs/env/comparison wiring, and a generalized internal/ciwiring invariant covering e2e-*/bench-* gated tiers"
affects: []

actuals:
  tokens: 6800
  tasks: 1
  commits: 1

tech-stack:
  added: []
  patterns:
    - "internal/ciwiring's job-id matcher generalized from a single ^e2e- regex to an alternation (^(?:e2e|bench)-), so a future gated-tier prefix joins the invariant by extending one regex rather than duplicating the assertion block."

key-files:
  created: []
  modified:
    - Taskfile.yml
    - .github/workflows/ci-go.yml
    - internal/ciwiring/ciwiring_test.go
    - internal/ciwiring/doc.go

key-decisions:
  - "Job id bench-lazy and task target test:bench:lazy (finalizing the plan's working names bench/test:bench)."
  - "internal/ciwiring's TestEveryE2ETierIsWiredIntoAggregator renamed to TestEveryGatedTierIsWiredIntoAggregator to match its widened scope (e2e-* and bench-*), with e2eJobPattern/e2eJobIDs/e2eNeedsIDs renamed to gatedTierJobPattern/gatedTierJobIDs/gatedTierNeedsIDs. All existing assertions (set equality, one env var per tier, != \"success\" comparison style, no == \"failure\", if: always(), aggregator name, workflow_dispatch present) preserved unchanged, now evaluated over the union of both prefixes."
  - "CI job timeout kept at 8 minutes, matching e2e-proc's value, per the plan's own guidance to adjust upward only if 02-05's recorded wall-clock demanded it. Local run of task test:bench:lazy completed in ~2.7s wall clock, far under any adjustment threshold."

patterns-established: []

requirements-completed: []

coverage: []

duration: N/A — plan intentionally paused mid-flight
completed: N/A
status: blocked
---

# Phase 2 Plan 6: Benchmark Tier Wired Into CI (Task 1 only — PLAN NOT COMPLETE)

**THIS SUMMARY DOCUMENTS TASK 1 ONLY. Task 2 (blocking human-verify checkpoint, Linux-runner RED proof) and Task 3 (contributor documentation) have NOT been executed. Do not treat this plan as complete — `status: blocked` above is deliberate, not a template omission.**

Task 1 wired the LAZY-02 benchmark into `task test:bench:lazy` and a new `bench-lazy` Linux CI
job folded into `ci-go-complete`, and generalized the `internal/ciwiring` structural invariant
from `e2e-*`-only to `e2e-*`/`bench-*` so a future edit that drops either kind of gated tier
from `needs:` fails a test rather than shipping ungated. Task 2's blocking checkpoint — proving
this new gate RED on a real Linux CI runner, per Phase 1 D-16 and durable memory `cq0rfk0qjc`
(a green run on macOS proves nothing about Linux CI) — has NOT been attempted. It requires a
`git push`, which this execution run was not authorized to do.

## Performance

- **Duration:** Task 1 only, ~15 min of tool time within this run.
- **Started:** 2026-08-03 (this execution)
- **Completed:** Task 1 committed 2026-08-03; Tasks 2-3 not started.
- **Tasks:** 1 of 3 completed.
- **Files modified:** 4.

## Accomplishments (Task 1 only)

- **`Taskfile.yml`** gains `test:bench:lazy`: no `deps:`, no `-race`, wrapping the exact `go test`
  invocation plan 02-05's SUMMARY recorded
  (`go test -tags lazybench -bench BenchmarkPeakMemory -benchtime 1x -run '^$' ./internal/storage/sqlite/ ./internal/server/`).
  Confirmed present via `task --list` after the edit.
- **`.github/workflows/ci-go.yml`** gains a `bench-lazy` job, copying `e2e-proc`'s
  checkout/setup-go/cache/task-install boilerplate verbatim (pinned SHAs byte-identical —
  confirmed by direct comparison, see Verification below), running on
  `namespace-profile-linux-amd64-4x8` with an 8-minute timeout, final step `task test:bench:lazy`.
  `ci-go-complete` extended: `bench-lazy` added to `needs:`, `BENCH_LAZY_RESULT` env var added,
  `[[ "$BENCH_LAZY_RESULT" != "success" ]] ||` added to the comparison chain (never
  `== "failure"`, matching Phase 1 D-01/D-02's established style).
- **`internal/ciwiring/ciwiring_test.go`** generalized: `e2eJobPattern` (`^e2e-`) became
  `gatedTierJobPattern` (`^(?:e2e|bench)-`); `e2eJobIDs`/`e2eNeedsIDs` renamed to
  `gatedTierJobIDs`/`gatedTierNeedsIDs`; the naming-convention guard now flags any job whose id
  contains "e2e" or "bench" but doesn't match the pattern; the test itself renamed
  `TestEveryE2ETierIsWiredIntoAggregator` → `TestEveryGatedTierIsWiredIntoAggregator`. Every
  existing assertion (set equality via sorted-joined-string comparison, exactly-one env var per
  tier, `!= "success"` comparison style, rejection of `== "failure"`, `if: always()`, aggregator
  name, `workflow_dispatch` presence) preserved unchanged, now evaluated over the union of both
  prefixes.
- **`internal/ciwiring/doc.go`** package comment updated to describe "gated-tier" jobs
  (e2e-* and bench-*) rather than e2e-only.

## Verification (Task 1 — all run and recorded verbatim)

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

Restored; re-run confirmed green (see Baseline green above, same output after restore).

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

`task test` (full `-race` suite) run to completion, green, 17.0s wall clock. Its full output was
grepped for `BenchmarkPeakMemory`: zero matches — confirmed by execution, not by inspecting the
build tag.

### SHA byte-identity between `bench-lazy` and `e2e-proc`

Direct `awk`-scoped extraction of each job block's `uses:`/`go-version-file`/`cache:` lines shows
`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`,
`actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`, and
`namespacelabs/nscloud-cache-action@c5f8dab7560444c4bf8dbc64f1b203431873c547` byte-identical
between the two blocks.

### `task test:bench:lazy` runs successfully locally (sanity check, not the Linux-CI RED proof)

Ran to completion in ~2.7s wall clock; both `internal/storage/sqlite` and `internal/server`
`BenchmarkPeakMemory` sub-benchmarks passed with output consistent with plan 02-05's recorded
ratios (paged/streaming flat, drained/buffered scaling, `hosts` residual scaling as expected —
this is a local macOS run and does NOT substitute for Task 2's required Linux-runner proof).

### `task lint` and `yamlfmt -lint` green

`task lint` (golangci-lint, buf lint/format, manifests verify) passed with 0 issues.
`yamlfmt -lint .github/workflows/ci-go.yml Taskfile.yml` passed with no diff required.

## Task Commits

1. **Task 1: Wire the benchmark tier into Taskfile, CI, and the ciwiring invariant** —
   `950c82f` (feat) — `feat(ci): gate LAZY-02 benchmark tier in CI`. Signed cleanly, confirmed via
   `git cat-file commit 950c82f | rg -q '^gpgsig'` — no signing bypass needed.

**No plan-metadata commit made.** The plan is not complete; STATE.md/ROADMAP.md/REQUIREMENTS.md
were NOT touched and this SUMMARY.md is NOT committed — see "NOT DONE" below.

## Files Created/Modified

- `Taskfile.yml` — added `test:bench:lazy` target.
- `.github/workflows/ci-go.yml` — added `bench-lazy` job; extended `ci-go-complete`'s
  `needs:`/env/comparison chain.
- `internal/ciwiring/ciwiring_test.go` — generalized the gated-tier invariant.
- `internal/ciwiring/doc.go` — updated package comment.

## Decisions Made

See `key-decisions` in frontmatter: job/task-target naming (`bench-lazy` / `test:bench:lazy`),
the rename of the invariant test and its helpers to reflect the widened scope, and the decision
to keep the 8-minute timeout given the ~2.7s local run time.

## Deviations from Plan

None — Task 1 executed exactly as written. No auto-fixes, no architectural changes, no rule 1-4
triggers.

## Issues Encountered

None for Task 1. Task 2 was not attempted — see "NOT DONE" below, this is a deliberate stop at a
blocking checkpoint, not a failure.

## NOT DONE — Task 2 and Task 3

**Task 2 (`type="checkpoint:human-verify" gate="blocking"`): NOT RUN.**

D-13 requires this gate proven RED on a real Linux CI runner before acceptance (Phase 1 D-16,
durable memory `cq0rfk0qjc` — a green run on macOS proves nothing about Linux CI). This requires:

1. Pushing the current branch (`docs/start-milestone-v0.14.0`) so the new `bench-lazy` job runs
   in real GitHub Actions CI, and confirming it is green there.
2. Pushing a deliberate regression on a **scratch branch** (per Phase 1's PR #415/#416 precedent,
   both closed unmerged) — pointing the paged benchmark at the drained path
   (`store.ListAll` instead of draining `ListPage`) — and capturing the job's RED log excerpt
   showing the ratio assertion's failure message.
3. Confirming `ci-go-complete` itself also reports failure while the tier is red.
4. Reverting the regression, confirming both return to green.
5. Closing the scratch PR unmerged.

**This execution run was explicitly not authorized to `git push`** (per this run's
`<execution_mode>` instructions), which is the hard blocker — every step above requires a real
push to a real CI runner. This is recorded as NOT-RUN rather than claimed complete, following the
precedent set by plans 09-05, 01-08, and 01-05.

**What is prepared to make the human's step cheap:**

- The exact regression diff to apply for the RED proof is:
  `internal/storage/sqlite/projection_bench_test.go`'s `drainPaged` helper (introduced in plan
  02-05) — temporarily change its call from draining `ListPage` to calling `store.ListAll(ctx)`
  directly, exactly as plan 02-05's own local demonstrated-RED proof did (see
  `02-05-SUMMARY.md`'s "Demonstrated-RED proofs" section for the exact before/after and the
  expected failure message shape: `"paged peak ratio (10k/1k) = 2.886 ... is not less than
  "1.8""`, with the concrete number varying run to run but the assertion failure shape identical).
- The command a human/CI runs is exactly `task test:bench:lazy` (already wired as the job's final
  step) — no new command needs to be invented.
- The `gh pr checks` polling command from the plan's Task 2 text:
  `gh pr checks <pr-number> --json name,state --jq '.[] | select(.name | test("bench|Bench"))'`.

**Task 3 (document the benchmark tier for contributors): NOT STARTED.** Blocked behind Task 2's
gate per the plan's task ordering — Task 3 is meant to document the tier "as it actually exists"
post-Task-1, which is available now, but the plan's structure places it after the checkpoint and
this run was instructed to stop at Task 2, not skip ahead to Task 3.

## User Setup Required

None for Task 1. Task 2 requires a human to run `git push` and observe real GitHub Actions CI —
see "NOT DONE" above.

## Next Phase Readiness

**This plan is NOT ready to be treated as done.** A continuation agent (or the same human) must:

1. Push this branch, resolve Task 2's checkpoint with real Linux-CI evidence (RED + restored
   green), close any scratch PR used for the regression proof.
2. Execute Task 3 (contributor documentation in `docs/contributing/testing.md` and
   `.planning/codebase/TESTING.md`).
3. Only then create the true, complete `02-06-SUMMARY.md` (this file will be overwritten) with
   `status: complete`, run `state.advance-plan`/`roadmap.update-plan-progress`/
   `requirements.mark-complete`, and make the final plan-metadata commit.

---
*Phase: 02-cursor-based-lazy-storage-reads*
*Completed: NOT COMPLETE — Task 1 of 3 only*
