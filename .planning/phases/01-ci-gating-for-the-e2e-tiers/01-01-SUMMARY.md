---
phase: 01-ci-gating-for-the-e2e-tiers
plan: 01
subsystem: testing
tags: [ci, github-actions, testify, yaml, testing.TB, e2e]

# Dependency graph
requires: []
provides:
  - "internal/testutil/wait.Until/UntilValue — shared bounded-timeout polling helper for tests"
  - "e2e/helpers_test.go's waitForServer routed through wait.Until"
  - "ci-go.yml workflow_dispatch trigger + e2e-fast job wired into ci-go-complete"
  - "internal/ciwiring — set-equality invariant test over the e2e-*/aggregator wiring"
affects: [01-02, 01-03, 01-04, 01-05]

# Actuals (#2632)
actuals:
  tokens: 5513
  tasks: 2
  commits: 4

tech-stack:
  added: [gopkg.in/yaml.v3 (promoted indirect->direct, no new module)]
  patterns:
    - "Non-_test.go, untagged, importable package importing testing (internal/storage/storagetest precedent), reused for internal/testutil/wait and internal/ciwiring"
    - "fakeTB implementing testing.TB (embedding a nil testing.TB) to observe Helper()/Fatalf() calls without triggering runtime.Goexit"
    - "Set-equality assertion via sorted-joined-string comparison instead of length comparison, to catch both extra and missing members in one check"

key-files:
  created:
    - internal/testutil/wait/wait.go
    - internal/testutil/wait/wait_test.go
    - internal/ciwiring/doc.go
    - internal/ciwiring/ciwiring_test.go
  modified:
    - e2e/helpers_test.go
    - .github/workflows/ci-go.yml
    - go.mod

key-decisions:
  - "wait's two-function split (Until for boolean conditions, UntilValue[T] for read-and-predicate-with-return) absorbs all five existing pollers' shapes without forcing an awkward zero-value dance on Until's callers (D-14/D-15)."
  - "internal/ciwiring's invariant test compares sorted, comma-joined string slices for set equality rather than any length check, so a swapped-but-same-count job set still fails (per plan direction, verified via no len( calls in the test file)."
  - "The invariant test's set difference reporting names exact job/env-var identifiers on failure, never a bare count mismatch."

patterns-established:
  - "internal/testutil/wait: the canonical home for all future readiness-poll conversions in this phase (plans 02-04 convert the remaining call sites through this package)."
  - "internal/ciwiring: a standing, set-based structural invariant — adding a fourth e2e-* job with no aggregator wiring turns it red automatically, no test edit required."

requirements-completed: [CI-01, CI-02, VRFY-05]

coverage:
  - id: D1
    description: "wait.Until and wait.UntilValue exist, evaluate their condition at least once even under a zero/elapsed timeout, call tb.Helper(), and report timeout via tb.Fatalf carrying the description (D-15) — no droppable error return."
    requirement: "VRFY-05"
    verification:
      - kind: unit
        ref: "internal/testutil/wait/wait_test.go#TestUntil_TimesOutAndCallsFatalfExactlyOnceWithDescAndTimeout"
        status: pass
      - kind: unit
        ref: "internal/testutil/wait/wait_test.go#TestUntil_EvaluatesConditionAtLeastOnceWithZeroTimeout"
        status: pass
      - kind: unit
        ref: "internal/testutil/wait/wait_test.go#TestUntilValue_TimesOutWithLastErrorInMessage"
        status: pass
    human_judgment: false
  - id: D2
    description: "e2e/helpers_test.go's waitForServer routes its readiness poll through wait.Until, and task test:e2e still passes."
    requirement: "VRFY-05"
    verification:
      - kind: e2e
        ref: "task test:e2e (go test -tags e2e -count=1 -v ./e2e/)"
        status: pass
    human_judgment: false
  - id: D3
    description: "ci-go.yml has a workflow_dispatch trigger and an e2e-fast job wired into ci-go-complete's needs, env block, and != \"success\" result-check, without editing the protect-main required-check set or the CI (Go) Complete name string."
    requirement: "CI-01"
    verification:
      - kind: unit
        ref: "internal/ciwiring/ciwiring_test.go#TestEveryE2ETierIsWiredIntoAggregator"
        status: pass
      - kind: other
        ref: "actionlint .github/workflows/ci-go.yml (exit 0)"
        status: pass
    human_judgment: false
  - id: D4
    description: "internal/ciwiring's invariant test asserts set-equality between top-level e2e-* jobs and the aggregator's needs/env/result-check wiring; adding an unwired e2e-* job turns it red with no test edit."
    requirement: "CI-01"
    verification:
      - kind: unit
        ref: "internal/ciwiring/ciwiring_test.go#TestEveryE2ETierIsWiredIntoAggregator (demonstrated red 4x: needs-list removal, env-binding removal, comparison-clause removal, unwired e2e-zzz job — see below)"
        status: pass
    human_judgment: false

duration: 15min
completed: 2026-08-03
status: complete
---

# Phase 1 Plan 1: Shared Readiness Helper + Fast E2E Tier Gate + Aggregator Invariant Summary

**Bounded-timeout `wait.Until`/`wait.UntilValue` helper backing a converted e2e poller, a pinned `e2e-fast` CI job wired into the required `ci-go-complete` aggregate, and a `internal/ciwiring` set-equality test that turns red the moment any e2e-\* job exists without full aggregator wiring.**

## Performance

- **Duration:** 15 min (Task 1 RED commit to Task 2 commit, by git timestamp; continuation-agent gap not counted)
- **Tasks:** 2/2
- **Files modified:** 7 (4 created, 3 modified)

## Accomplishments

- `internal/testutil/wait` — new, untagged, non-`_test.go` package (mirrors `internal/storage/storagetest`'s shape) exporting `Until` and `UntilValue[T]`, both calling `tb.Helper()`, evaluating their condition/fetch at least once regardless of timeout, and reporting timeout exclusively via `tb.Fatalf` (no droppable error return, per D-15).
- `e2e/helpers_test.go`'s `waitForServer` now routes through `wait.Until`; the hand-rolled deadline loop and its trailing `t.Fatalf` are gone. `task test:e2e` passes.
- `.github/workflows/ci-go.yml` gained a `workflow_dispatch:` trigger (D-05's repo-local half) and a new `e2e-fast` job (pinned SHAs copied byte-identically from the `test` job), wired into `ci-go-complete`'s `needs`, a dedicated `E2E_FAST_RESULT` env binding, and a `!= "success"` OR-chain clause — `CI (Go) Complete`'s name and the `protect-main` required-check set are untouched.
- `internal/ciwiring` — new package holding a single structural invariant test (`TestEveryE2ETierIsWiredIntoAggregator`) that parses `ci-go.yml` with `gopkg.in/yaml.v3` (promoted from indirect to direct requirement — the only permitted `go.mod` change) and asserts, via sorted-joined-string set comparison (no length check), that every top-level `e2e-*` job is represented in `ci-go-complete`'s `needs`, has exactly one `*_RESULT` env binding, and that binding is compared against `"success"` with `!=` in the run script. Also asserts `if: always()`, the exact `name: CI (Go) Complete` string, and the `workflow_dispatch` trigger.
- Demonstrated the invariant test failing four separate ways, each restored to a byte-identical file afterward (verified via `git diff --exit-code` / sha256 comparison) and confirmed green again:
  1. Removing `e2e-fast` from `ci-go-complete.needs` → failure names `e2e-fast` as "declared but not needed."
  2. Removing the `E2E_FAST_RESULT` env line → failure: `ci-go-complete has no env var bound to ${{ needs.e2e-fast.result }}`.
  3. Removing the `[[ "$E2E_FAST_RESULT" != "success" ]]` clause → failure names `E2E_FAST_RESULT` specifically as missing the comparison.
  4. Adding an unwired, bogus `e2e-zzz` job (per resume instructions) → failure: `declared but not needed=[e2e-zzz]`, proving a fourth tier added without aggregator wiring is caught automatically, no test edit required.

## Task Commits

Each task was committed atomically:

1. **Task 1 (tracer, TDD): shared wait helper + one converted poller + e2e-fast CI job**
   - `c4a4c3b` — `test(e2e): add failing tests for wait helper` (RED — package did not exist, build failed; see RED evidence below)
   - `72ab23e` — `feat(e2e): add shared bounded-timeout wait helper` (GREEN — implements `wait.Until`/`wait.UntilValue`, converts `waitForServer`)
   - `0f8953f` — `ci(e2e): run fast e2e tier as a gated job` (adds `workflow_dispatch`, `e2e-fast` job, extends `ci-go-complete`)
   - Independently re-verified by the orchestrator before this continuation: `go test ./internal/testutil/wait/...` ok, `go vet` clean, diff `cd9b5dc..0f8953f` touches only the 4 intended files.
2. **Task 2: aggregator wiring invariant test**
   - `9f767fd` — `test(ci): assert every e2e tier is wired into aggregator` (adds `internal/ciwiring`, promotes `gopkg.in/yaml.v3` to direct)

**Plan metadata:** committed separately after this SUMMARY (see final commit below).

_Note: Task 1 followed the RED/GREEN/CI three-commit discipline named in its `<action>`; Task 2 is a single test-only commit (no separate implementation commit — the "implementation" is the test itself validating existing wiring)._

## RED Evidence

**Task 1 — `wait_test.go` RED (reproduced this session to capture exact output; `wait.go` did not exist at commit `c4a4c3b`):**

```
$ go test ./internal/testutil/wait/...
github.com/fzymgc-house/router-hosts/internal/testutil/wait: no non-test Go files in /Volumes/Code/github.com/fzymgc-house/router-hosts/internal/testutil/wait
FAIL	github.com/fzymgc-house/router-hosts/internal/testutil/wait [build failed]
FAIL
```

Restored `wait.go` immediately after; `go test ./internal/testutil/wait/...` returned to `ok` (cached), confirmed no working-tree diff remained.

**Task 2 — `internal/ciwiring` invariant, four RED observations against the post-Task-1 workflow file (each followed by exact file restoration, verified via `git diff --exit-code .github/workflows/ci-go.yml`, and a green re-run):**

1. Deleted `e2e-fast` from `ci-go-complete.needs`:
   ```
   ciwiring_test.go:153: e2e-* jobs and ci-go-complete.needs are out of sync: declared but not needed=[e2e-fast], needed but not declared=[]
   ```
2. Deleted the `E2E_FAST_RESULT: ${{ needs.e2e-fast.result }}` env line:
   ```
   ciwiring_test.go:168: ci-go-complete has no env var bound to ${{ needs.e2e-fast.result }}
   ```
3. Deleted the `[[ "$E2E_FAST_RESULT" != "success" ]]` clause from the run script:
   ```
   ciwiring_test.go:176: ci-go-complete's run script does not compare E2E_FAST_RESULT against "success" with !=; expected to find "\"$E2E_FAST_RESULT\" != \"success\""
   ```
4. Added an unwired `e2e-zzz` stub job (bogus fourth tier, per resume instructions, restored to `ci-go-complete:` insertion point programmatically):
   ```
   ciwiring_test.go:153: e2e-* jobs and ci-go-complete.needs are out of sync: declared but not needed=[e2e-zzz], needed but not declared=[]
   ```

All four experiments restored the file to its committed state; `sha256sum` before/after matched and `git diff --exit-code .github/workflows/ci-go.yml` reported no diff each time.

## Files Created/Modified

- `internal/testutil/wait/wait.go` — `Until`/`UntilValue[T]` bounded-timeout polling helpers; package doc states the goroutine-calling contract per `testing.TB`'s documented semantics
- `internal/testutil/wait/wait_test.go` — unit tests via `fakeTB` (embeds a nil `testing.TB`), covering success/retry/timeout paths, zero-timeout at-least-once evaluation, `Helper()` call, and same-goroutine `Fatalf` recording
- `e2e/helpers_test.go` — `waitForServer` converted to a `wait.Until` call; import added
- `.github/workflows/ci-go.yml` — `workflow_dispatch` trigger, `e2e-fast` job (pinned SHAs matching the `test` job), `ci-go-complete` extended with `E2E_FAST_RESULT` binding and comparison
- `internal/ciwiring/doc.go` — package doc, zero statements (does not perturb `test:coverage:ci`'s 80% threshold)
- `internal/ciwiring/ciwiring_test.go` — the aggregator wiring invariant test
- `go.mod` — `gopkg.in/yaml.v3` promoted from `// indirect` to a direct requirement (no new module; already present in `go.sum`)

## Decisions Made

- `wait`'s two-function split (`Until` for boolean conditions, `UntilValue[T]` for read-and-predicate-with-return-value) covers all five existing pollers' shapes (`waitForServer`, `waitForDockerServer`, `waitForProcAddr`, `waitForFileContent`, `waitForSidecar`) without forcing later conversions into an awkward return-value dance. This was Claude's Discretion per CONTEXT.md and matches RESEARCH.md's design survey.
- `internal/ciwiring`'s invariant uses sorted, comma-joined string comparison for set equality (not a length check) so a same-count-but-wrong-members mismatch still fails; verified no `len(` calls appear anywhere in `ciwiring_test.go` (`rg -n 'len\(' internal/ciwiring/ciwiring_test.go` returns nothing).
- Failure messages throughout `ciwiring_test.go` name the specific job id or env var involved (never a bare count), matching the plan's explicit acceptance criterion.

## Deviations from Plan

None — plan executed exactly as written for both tasks. Task 2's `<files>` list in frontmatter included `go.sum`; no `go.sum` diff was produced by `go mod tidy` (the package was already fully resolved as an indirect dependency), so that file legitimately has zero changes rather than being omitted in error — confirmed via `go mod tidy && git diff --exit-code go.mod go.sum` before/after comparison (identical diff both times, i.e. idempotent).

## Issues Encountered

None. All verification commands (`go test ./internal/testutil/wait/... ./internal/ciwiring/...`, `task test`, `task test:coverage:ci`, `task lint`, `actionlint`, `go build ./...`) passed on first attempt after implementation.

## Verification Run (this session)

- `go test ./internal/ciwiring/...` — PASS
- `go test ./internal/testutil/wait/...` — PASS (cached from Task 1, re-confirmed via RED/GREEN toggle above)
- `task test` — all packages PASS, including `internal/ciwiring` and `internal/testutil/wait`
- `task test:coverage:ci` — 86.3% (threshold 80%); `internal/ciwiring` contributed zero statements as designed
- `task lint` (golangci-lint + buf lint/format + manifests:verify) — 0 issues, manifests up to date
- `go build ./...` — succeeds
- `go mod tidy && git diff --exit-code go.mod go.sum` run twice — identical diff both times (idempotent; only the intended indirect→direct promotion)
- `go list -deps ./cmd/router-hosts/...` and `./cmd/operator/...` — neither pulls in `internal/testutil/wait`

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- The `internal/testutil/wait` package, the `e2e-fast`/`ci-go-complete` wiring shape, and the `internal/ciwiring` set-based invariant are all in place and proven. Plans 02-04 (the remaining call-site conversions, `e2e-docker`/`e2e-proc` jobs, and the Docker hard-fail gate) can build directly on this foundation with no further design risk on the core shapes.
- No blockers. The invariant test in `internal/ciwiring` will automatically go red when plan 04 adds `e2e-docker`/`e2e-proc` without full wiring, and automatically go green again once they're wired in — no edit to the test itself is required, as designed.

## Self-Check: PASSED

All 8 claimed files confirmed present on disk; all 4 claimed commit hashes (`c4a4c3b`, `72ab23e`, `0f8953f`, `9f767fd`) confirmed present in `git log --oneline --all`.

---
*Phase: 01-ci-gating-for-the-e2e-tiers*
*Completed: 2026-08-03*
