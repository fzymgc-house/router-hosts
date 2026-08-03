---
phase: 01-ci-gating-for-the-e2e-tiers
plan: 02
subsystem: testing
tags: [e2e, proc_e2e, testify, wait-helper, ci]

# Dependency graph
requires: ["01-01"]
provides:
  - "e2e/e2e_test.go's five readiness polls routed through internal/testutil/wait"
  - "e2e/e2e_test.go:757's 300ms outage hold marked SLEEP-INTENTIONAL:"
  - "e2e/proc_harness_test.go's waitForProcAddr/waitForFileContent/waitForSidecar rewritten over wait.Until/wait.UntilValue"
  - "e2e/helpers_test.go's startServer bind-retry loop routed through wait.Until (decision P-01)"
affects: ["01-03", "01-04", "01-05"]

# Actuals (#2632)
actuals:
  tokens: 2691
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "wait.UntilValue's fetch closure returning a typed value directly (server.SinkSnapshot, []byte, procSinkStatus) instead of the caller re-deriving state after a boolean wait.Until"
    - "Closure-captured outer variable (var lis net.Listener) assigned inside a wait.Until condition closure, replacing a hand-rolled for/sleep/break retry loop (decision P-01)"

key-files:
  modified:
    - e2e/e2e_test.go
    - e2e/proc_harness_test.go
    - e2e/helpers_test.go

key-decisions:
  - "Decision P-01 taken as planned (no fallback): startServer's bind-retry loop routes through wait.Until with timeout expressed as maxBindAttempts*bindRetryDelay, keeping both consts as the single source of truth for the 20-attempt/100ms budget."
  - "waitForFileContent and waitForSidecar's diagnostic trade: UntilValue's timeout message now prints the last decoded value (%+v of the string / procSinkStatus) rather than raw JSON text. This was accepted as the simpler form per the plan's discretion clause — no real diagnostic gap surfaced while running the tier, so the outer-variable raw-JSON capture was not added."
  - "e2e_test.go's TestE2E_WatchSinkHealthKeyedByCN needed internal/server imported directly (for server.SinkSnapshot as UntilValue's type parameter), which the file did not previously import; this is a mechanical consequence of moving the assertions outside the loop body, not a design change."

patterns-established:
  - "internal/testutil/wait is now the exclusive readiness-poll mechanism across all three converted files in this plan; e2e/docker_e2e_test.go (plan 03's scope) is the only remaining unconverted file."

requirements-completed: [VRFY-05]

coverage:
  - id: D1
    description: "Twelve named readiness call sites across e2e_test.go, helpers_test.go, and proc_harness_test.go route through internal/testutil/wait; no post-loop sentinel + require.True survives."
    requirement: "VRFY-05"
    verification:
      - kind: unit
        ref: "rg -n 'require\\.True\\(t, (found|sawFailure|sawNewContent|failuresCleared)' e2e/e2e_test.go — no match"
        status: pass
      - kind: unit
        ref: "rg -c 't\\.Fatalf' e2e/proc_harness_test.go dropped from 8 (HEAD) to 3 — the five timeout Fatalfs inside the three converted pollers are gone"
        status: pass
      - kind: e2e
        ref: "task test:e2e (go test -tags e2e -count=1 -v ./e2e/)"
        status: pass
      - kind: e2e
        ref: "task test:e2e:proc (go test -tags proc_e2e -count=1 -v -timeout 5m ./e2e/)"
        status: pass
    human_judgment: false
  - id: D2
    description: "e2e_test.go's 300ms outage-window hold at line 757 survives byte-identical and carries a SLEEP-INTENTIONAL: marker within the three preceding lines (D-13)."
    requirement: "VRFY-05"
    verification:
      - kind: unit
        ref: "rg -n 'time\\.Sleep\\(300 \\* time\\.Millisecond\\)' e2e/e2e_test.go — exactly one match at line 757, unchanged"
        status: pass
      - kind: unit
        ref: "structural adjacency awk gate over e2e/e2e_test.go, e2e/helpers_test.go, e2e/proc_harness_test.go — exits 0, prints nothing"
        status: pass
    human_judgment: false
  - id: D3
    description: "TestE2E_WatchSinkHealthKeyedByCN's five assertions (CN key, ConsecutiveFailures==3, ContractVersion, RenderedChangeID, States len==1, no empty key) and TestE2E_WatchSinkSurvivesServerRestart's byte-identical outage assertion survive the conversion verbatim in meaning."
    requirement: "VRFY-05"
    verification:
      - kind: unit
        ref: "rg -n 'registry should hold exactly one key|registry must not hold an entry under the empty key|contract\\.TemplateVersion|artifact must stay byte-identical during the outage' e2e/e2e_test.go — all four match"
        status: pass
      - kind: e2e
        ref: "task test:e2e — TestE2E_WatchSinkHealthKeyedByCN and TestE2E_WatchSinkSurvivesServerRestart both PASS"
        status: pass
    human_judgment: false
  - id: D4
    description: "Both e2e and proc_e2e build tags compile cleanly after conversion, and docker_e2e (helpers_test.go's shared tag) still vets clean even though this plan does not run its full Docker suite."
    requirement: "VRFY-05"
    verification:
      - kind: other
        ref: "go vet -tags e2e ./e2e/...; go vet -tags proc_e2e ./e2e/...; go vet -tags docker_e2e ./e2e/... — all clean"
        status: pass
      - kind: other
        ref: "golangci-lint run --build-tags e2e ./e2e/...; golangci-lint run --build-tags proc_e2e ./e2e/... — 0 issues each"
        status: pass
    human_judgment: false

duration: 25min
completed: 2026-08-03
status: complete
---

# Phase 1 Plan 2: Convert Remaining e2e/proc_e2e Readiness Waits Summary

**Twelve remaining readiness-poll call sites across `e2e_test.go`, `proc_harness_test.go`, and `helpers_test.go` now route through `internal/testutil/wait`, with the one deliberate 300ms outage-window hold surviving byte-identical under a machine-matchable `SLEEP-INTENTIONAL:` marker.**

## Performance

- **Duration:** ~25 min (first Read to final commit, by git timestamp)
- **Tasks:** 3/3
- **Files modified:** 3 (e2e_test.go, proc_harness_test.go, helpers_test.go)

## Pre-Edit RED Observations (structural marker gate, run before any change)

Per each task's acceptance criteria, the marker-adjacency awk gate was run against the unmodified file before editing, to record its red output:

- **`e2e/e2e_test.go`** (Task 1): gate printed six lines — `681, 746, 757, 769, 794, 805` — and exited 1 (verified via re-run before edits; matches the plan's stated red observation exactly).
- **`e2e/proc_harness_test.go`** (Task 2): gate printed six lines — `357, 504, 512, 535, 542, 549` — and exited 1 (matches the plan's stated red observation; note line 535 is the read-error branch inside `waitForSidecar`, correctly included per the plan's note that RESEARCH.md's triage table omitted it).
- **`e2e/helpers_test.go`** (Task 3): gate printed one line — `216` — and exited 1 (line 382, `waitForServer`, was already converted by plan 01-01 and did not appear).

After each task's conversion, the same gate was re-run and exited 0 with no output — confirmed for all three files individually and again together in the final phase-level verification pass.

## Accomplishments

- **`e2e/e2e_test.go`** — 5 conversions:
  - `TestE2E_WatchSinkHealthKeyedByCN`'s sink-health-by-CN poll converted to a single `wait.UntilValue` call (fetch: `env.sinkHealth.Snapshot()`, pred: key presence). All five downstream assertions (`ConsecutiveFailures==3`, `ContractVersion`, `RenderedChangeID`, `len(States)==1`, no empty key) moved after the wait, unchanged in meaning. Required adding `internal/server` as an explicit import (for `server.SinkSnapshot` as the generic type parameter) — a mechanical consequence of the assertions now running outside the loop body, not a design change.
  - `TestE2E_WatchSinkSurvivesServerRestart` step 1's artifact-appears poll converted to `wait.UntilValue` over `os.ReadFile`.
  - The 300ms outage hold at line 757 left byte-identical; gained a `SLEEP-INTENTIONAL:` marker comment two lines above it, alongside (not replacing) the existing reviews-M4/M10 explanatory comment.
  - Step 3's failure-count poll, step 5's new-content poll, and step 5's failures-cleared poll all converted to `wait.Until`. All three post-loop sentinel booleans (`sawFailure`, `sawNewContent`, `failuresCleared`) and their `require.True` calls are gone.
- **`e2e/proc_harness_test.go`** — `waitForProcAddr`, `waitForFileContent`, and `waitForSidecar` rewritten as thin wrappers over `wait.Until`/`wait.UntilValue`. All three signatures are byte-identical to `git show HEAD:e2e/proc_harness_test.go` (verified). Six `time.Sleep` calls removed; `t.Fatalf` count in the file dropped from 8 to 3 (the five timeout Fatalfs inside these three functions are gone, replaced by the helper's).
- **`e2e/helpers_test.go`** — `startServer`'s bind-retry loop converted per decision P-01 (no fallback needed): `wait.Until` with timeout `maxBindAttempts * bindRetryDelay` (still 20 x 100ms = 2s) and interval `bindRetryDelay`. Both consts remain the single source of truth and are still referenced. The old `require.NoError(t, err, "listen on %s after %d attempts", ...)` sentinel is gone; a bind that never succeeds now fails via `wait.Until`'s own `t.Fatalf` naming the address.

## Task Commits

1. `f904895` — `test(e2e): route e2e tier readiness waits through wait helper`
2. `aeac45f` — `test(e2e): route proc_e2e pollers through wait helper`
3. `1026465` — `test(e2e): route bind retry through wait helper`

## Decisions Made

- **Decision P-01 taken as written, no fallback.** `golangci-lint` accepted the closure-capture pattern (`var lis net.Listener` assigned inside the `wait.Until` condition closure) with 0 issues, so the fallback (`SLEEP-INTENTIONAL:`-marked loop) described in the plan was not needed.
- **Diagnostic trade in `waitForFileContent`/`waitForSidecar` (recorded per plan's `<output>` instruction):** `wait.UntilValue`'s timeout message prints the last observed *decoded* value (`%+v` for `procSinkStatus`, the plain string for file content) rather than the raw JSON text the pre-conversion code printed via `lastRaw`. No real diagnostic gap surfaced while running `task test:e2e:proc`, so the simpler form (no outer-variable raw-JSON capture) was kept, per the plan's explicit permission to do so.
- **Bind-retry timeout expression:** written as `maxBindAttempts * bindRetryDelay` with spaces to match the plan's literal acceptance-criteria pattern; `gofumpt` (run automatically by the repo's pre-commit hook, per CLAUDE.md's mandated formatting) normalizes this to `maxBindAttempts*bindRetryDelay` with no spaces on write. The committed file therefore has no spaces around `*`. This is noted because the plan's acceptance criterion `rg -n 'maxBindAttempts \* bindRetryDelay'` (with literal spaces in the pattern) does not match the gofumpt-formatted output — the semantic requirement (timeout expressed as the product of the two named consts, not a literal duration) is satisfied; only the incidental whitespace differs from the criterion's exact string.

## Deviations from Plan

**1. [Rule 3 - formatting] `gofumpt` removes spaces around `*` in the bind-retry timeout expression**
- **Found during:** Task 3, immediately after writing `maxBindAttempts * bindRetryDelay`.
- **Issue:** The plan's acceptance criterion greps for the literal string `maxBindAttempts \* bindRetryDelay` (with spaces). `gofumpt`, which the repo's pre-commit hook runs unconditionally on every commit (CLAUDE.md: "You MUST run `golangci-lint run ./...` before committing" / gofumpt formatting), reformats this to `maxBindAttempts*bindRetryDelay` (no spaces).
- **Fix:** Accepted the gofumpt-normalized form rather than fighting the formatter or adding a `//nolint`-style suppression (which CLAUDE.md forbids without justification and approval). The underlying requirement — expressing the timeout as the product of the two named consts rather than a literal duration — is met; `rg -n 'maxBindAttempts\*bindRetryDelay'` (no spaces) matches at the exact call site.
- **Files modified:** `e2e/helpers_test.go`
- **Commit:** `1026465`

No other deviations. All three tasks executed exactly as the plan specified, including decision P-01 with no fallback triggered.

## Issues Encountered

None. All verification commands passed on first attempt: `go vet -tags e2e|proc_e2e|docker_e2e ./e2e/...`, `golangci-lint run --build-tags e2e|proc_e2e ./e2e/...`, `task test:e2e`, `task test:e2e:proc`, `task lint`, `task test` (full suite, race detector).

## Verification Run (this session)

- `task test:e2e` — all 13 `TestE2E_*` tests PASS, including `TestE2E_WatchSinkHealthKeyedByCN` and `TestE2E_WatchSinkSurvivesServerRestart`
- `task test:e2e:proc` — all 3 `TestProcE2E_*` tests PASS
- `go vet -tags e2e ./e2e/...` — clean
- `go vet -tags proc_e2e ./e2e/...` — clean
- `go vet -tags docker_e2e ./e2e/...` — clean (full Docker execution is plan 03's gate; this task only needed the compile signal, matching the plan's own scoping)
- `golangci-lint run --build-tags e2e ./e2e/...` — 0 issues
- `golangci-lint run --build-tags proc_e2e ./e2e/...` — 0 issues
- `task lint` (full repo: golangci-lint + buf lint/format + manifests:verify) — 0 issues, manifests up to date
- `task test` (full suite, `-race -count=1 ./...`) — all packages PASS
- Structural adjacency gate over all three files together — exits 0, prints nothing
- `git diff --stat` per task: Task 1 touched only `e2e/e2e_test.go`; Task 2 touched only `e2e/proc_harness_test.go`; Task 3 touched only `e2e/helpers_test.go`

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- All twelve named call sites across the three files this plan owns are converted; only `e2e/docker_e2e_test.go` (plan 03's scope) remains as an unconverted file in the `e2e/*.go` set.
- The phase-level structural marker gate (`awk ... e2e/e2e_test.go e2e/helpers_test.go e2e/proc_harness_test.go e2e/docker_e2e_test.go`) will still show `docker_e2e_test.go`'s sleeps as unconverted until plan 03 runs — this is expected and owned by that plan, not a regression here.
- No blockers for plans 03-05.

## Self-Check: PASSED

All 3 claimed modified files confirmed present on disk with the expected changes; all 3 claimed commit hashes (`f904895`, `aeac45f`, `1026465`) confirmed present in `git log --oneline --all`.

---
*Phase: 01-ci-gating-for-the-e2e-tiers*
*Completed: 2026-08-03*
