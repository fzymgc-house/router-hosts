---
phase: 01-consumer-rendered-output-templates-sink
plan: 11
subsystem: testing
tags: [e2e, testing, process, mtls, sink, harness, gap-closure]

requires:
  - phase: 01-consumer-rendered-output-templates-sink (plan 01-10)
    provides: LoadClientConfig's layer-1 explicit-path branch (the fix this
      plan's harness observes from outside the process boundary)
provides:
  - "proc_e2e build tag — real OS processes on both sides of mTLS, distinct from e2e (in-process) and docker_e2e (containerized server, in-process client)"
  - "e2e/proc_harness_test.go — reusable os/exec launchers, PKI (CN-parameterized), TOML config writers, hermetic child environment, filesystem-based polling"
  - "e2e/proc_e2e_test.go — three tests proving the --config seam from a real process boundary"
  - "task test:e2e:proc — Taskfile target, deps: ['build']"
  - "docs/contributing/testing.md — three-tier e2e story, the in-process blind spot, deferred container-harness extension points"
affects: []

actuals:
  tokens: 11704
  tasks: 3
  commits: 3

tech-stack:
  added: []
  patterns:
    - "proc_e2e is a THIRD, separate build tag/task target rather than an extension of e2e — keeps task test:e2e build-independent and keeps in-process server/service construction (helpers_test.go) out of a suite whose whole point is proving nothing is constructed in-process"
    - "Real-process negative grep carries a mandatory positive control against helpers_test.go, so the gate cannot be vacuously satisfied by a pattern that can never match"
    - "Every proc_e2e test discriminates on rendered CONTENT (named-target.example present / decoy-target.example absent) against two LIVE servers, never a dead decoy — a silent connection to a working wrong server is the actual defect class"
    - "hermeticEnv passes an explicit child-process environment slice (never inherited) so a test cannot accidentally pass on a developer's machine because of that machine's real config"

key-files:
  created:
    - e2e/proc_harness_test.go
    - e2e/proc_e2e_test.go
  modified:
    - Taskfile.yml
    - docs/contributing/testing.md

key-decisions:
  - "New proc_e2e build tag + task test:e2e:proc target, not an overload of the existing e2e tag — task test:e2e must keep running without a built binary"
  - "Certificate generation duplicated (~90 lines) from e2e/helpers_test.go rather than shared, so proc_harness_test.go never imports (and cannot accidentally reintroduce) in-process server/service construction"
  - "Server readiness polling uses a plain TCP dial (waitForProcAddr), not a full mTLS handshake — simpler, and sufficient since the actual mTLS/discrimination behavior is proven by the seeding and sink assertions, not the readiness check"
  - "reserveLocalPort's TOCTOU window (threat T-01-G1-12) accepted as-is per plan: bounded by a real readiness deadline with a named failure, not converted to log-output parsing"
  - "Suite deliberately NOT wired into ci-go.yml, matching the existing e2e/docker_e2e posture; recorded as threat T-01-G1-13 (accept) and tracked in GitHub issue #403 rather than silently decided"

patterns-established:
  - "A proc_e2e test is the correct home for any future test of CLI-flag-to-config-loading behavior; an in-process e2e test structurally cannot see that seam (documented explicitly in docs/contributing/testing.md so a future contributor picks the right tier)"

requirements-completed: [TMPL-05]

coverage:
  - id: D1
    description: "A test launches the built router-hosts binary as a real OS process and observes that watch --config <path> connects to the server named in <path> and to no other, discriminated by content between two live servers"
    requirement: TMPL-05
    verification:
      - kind: e2e
        ref: "e2e/proc_e2e_test.go#TestProcE2E_ColdStartWatchHonorsConfigFlag"
        status: pass
    human_judgment: false
  - id: D2
    description: "A watch process given an unreadable --config exits non-zero with the path in its output and writes no artifact, even with a valid config present on the XDG search path"
    requirement: TMPL-05
    verification:
      - kind: e2e
        ref: "e2e/proc_e2e_test.go#TestProcE2E_MissingExplicitConfigFailsLoudly"
        status: pass
    human_judgment: false
  - id: D3
    description: "A host mutation made by a second real CLI process propagates to the sink's artifact and advances the sidecar's rendered_change_id"
    requirement: TMPL-05
    verification:
      - kind: e2e
        ref: "e2e/proc_e2e_test.go#TestProcE2E_ChangeIDPropagatesToSidecar"
        status: pass
    human_judgment: false
  - id: D4
    description: "task test:e2e remains build-independent; the new proc_e2e tag does not make the pre-existing in-process suite require a built binary"
    verification:
      - kind: other
        ref: "task clean && task test:e2e (verified green with bin/ absent)"
        status: pass
    human_judgment: false
  - id: D5
    description: "Both key proc_e2e tests were demonstrated to FAIL when plan 01-10's fix is reverted, and PASS again once restored"
    verification:
      - kind: e2e
        ref: "manual revert-and-observe cycle (see Regression Demonstrations section below), both directions quoted"
        status: pass
    human_judgment: false
  - id: D6
    description: "Three-tier e2e story, the in-process blind spot, and the deferred container-harness extension points are documented"
    verification:
      - kind: other
        ref: "rumdl check docs/contributing/testing.md"
        status: pass
    human_judgment: false

duration: ~55min
completed: 2026-08-02
status: complete
---

# Phase 1 Plan 11: Real-process cold-start e2e for the --config seam (gap G-01-1) Summary

**A new `proc_e2e` test tier launches the shipped `router-hosts` binary as a real OS process on both sides of mTLS and proves `watch --config <path>` connects to the server named by `<path>` — the exact vantage point gap G-01-1 shipped through undetected.**

## Performance

- **Duration:** ~55 min
- **Tasks:** 3
- **Files modified:** 4 (2 created, 2 modified)

## Accomplishments

- New `proc_e2e` build tag + `task test:e2e:proc` target: a third e2e tier, distinct from the in-process `e2e` tag and the containerized-server-but-in-process-client `docker_e2e` tag
- `e2e/proc_harness_test.go`: reusable `os/exec` process launchers (`startServerProcess`, `startSinkProcess`, `runCLI`), CN-parameterized PKI (`newPKIBundle`/`issueClientCert`), transport-agnostic TOML config writers, a hermetic explicit child environment (`hermeticEnv`), and filesystem-based polling (`waitForFileContent`/`waitForSidecar`) — none of it constructs anything in-process
- `e2e/proc_e2e_test.go`: three tests, all discriminating on rendered content between real live processes:
  - `TestProcE2E_ColdStartWatchHonorsConfigFlag` — the tracer; two live servers, one named by `--config`, one a reachable decoy on the XDG search path
  - `TestProcE2E_MissingExplicitConfigFailsLoudly` — a bad `--config` dies loudly and writes nothing, even with a working config on the XDG fallback path
  - `TestProcE2E_ChangeIDPropagatesToSidecar` — a mutation from a SEPARATE real CLI process reaches a running sink's artifact and advances `rendered_change_id`
- `docs/contributing/testing.md`: rewritten to document all three e2e tiers, the in-process blind spot that let G-01-1 ship, the deferred containerized two-node harness's extension points, and a corrected (previously stale/inaccurate) CI Integration section
- GitHub issue [#403](https://github.com/fzymgc-house/router-hosts/issues/403) filed to track wiring all three e2e tiers into CI (currently none run there)

## Task Commits

1. **Task 1: Real-process cold start — two servers, one --config, correct artifact** - `fca11f5` (test, tracer)
2. **Task 2: Fail-loud on a bad --config, and change-ID propagation, both from real processes** - `1bb636d` (test)
3. **Task 3: Record the three-tier testing story and the deferred harness design** - `5b928f2` (docs)

## Tracer Feedback Gate

Task 1 is `type="tracer"`. Auto-mode was not active (`workflow.auto_advance=false`, `_auto_chain_active=false`), so per the tracer feedback gate I stopped after committing Task 1, presented the full automated verification (including the regression demonstration) as a `checkpoint:human-verify`, and the operator approved before Task 2/Task 3 proceeded. The operator additionally confirmed, independently re-running the negative gate, positive control, and `task test:e2e:proc`, that all reported numbers matched.

## Files Created/Modified

- `e2e/proc_harness_test.go` (new) - process-launching harness: `procBinaryPath`, `pkiBundle`/`newPKIBundle`/`issueClientCert`, `reserveLocalPort`, `writeServerConfigFile`/`writeClientConfigFile`, `serverProc`/`startServerProcess`, `sinkProc`/`startSinkProcess`, `runCLI`, `hermeticEnv`, `procSinkStatus`, `waitForFileContent`/`waitForSidecar`, `examplesTemplatePath`
- `e2e/proc_e2e_test.go` (new) - `TestProcE2E_ColdStartWatchHonorsConfigFlag`, `TestProcE2E_MissingExplicitConfigFailsLoudly`, `TestProcE2E_ChangeIDPropagatesToSidecar`
- `Taskfile.yml` - added `test:e2e:proc` (`deps: ['build']`, `go test -tags proc_e2e -count=1 -v -timeout 5m ./e2e/`)
- `docs/contributing/testing.md` - rewritten: three-tier table, in-process blind-spot explanation, `proc_e2e` test scenarios, hermetic-environment rationale, deferred container-harness extension points, corrected CI Integration section

## Decisions Made

- `proc_e2e` is a new, separate build tag rather than an extension of `e2e` — overloading `e2e` would silently make `task test:e2e` require a built binary and risk passing against a stale (pre-fix) binary
- Certificate generation in `proc_harness_test.go` deliberately duplicates ~90 lines from `e2e/helpers_test.go` instead of importing it, so this file can never accidentally reintroduce in-process server/service construction
- `startServerProcess` readiness polling (`waitForProcAddr`) uses a plain TCP dial rather than a full mTLS handshake — simpler, and the actual mTLS/config-resolution behavior is what the seeding and sink assertions prove, not the readiness poll
- `reserveLocalPort`'s TOCTOU window (T-01-G1-12) is accepted as documented in the plan: bounded by a real readiness deadline with a named failure message, never converted to parsing the bound port from server log output
- CI wiring for all three e2e tiers stays out of scope for this gap-closure plan; recorded as threat T-01-G1-13 (disposition: accept) and tracked in [issue #403](https://github.com/fzymgc-house/router-hosts/issues/403), per explicit operator confirmation during the tracer checkpoint

## Real-Process Gate + Positive Control (mandatory per plan)

Comment-stripped negative grep over the two new files, proving neither constructs a server/service/root-command/bufconn in-process:

```text
$ rg -v '^\s*//' e2e/proc_harness_test.go e2e/proc_e2e_test.go | rg -o 'server\.NewServer|NewHostsServiceImpl|NewRootCmd|bufconn' | wc -l | tr -d ' '
0
```

Positive control over the existing in-process helpers, proving the pattern CAN match (not vacuously satisfied):

```text
$ rg -v '^\s*//' e2e/helpers_test.go | rg -o 'server\.NewServer|NewHostsServiceImpl|NewRootCmd|bufconn' | wc -l | tr -d ' '
2
```

Process-launch gate (`exec.CommandContext`/`exec.Command` count in the harness):

```text
$ rg -o 'exec\.CommandContext|exec\.Command' e2e/proc_harness_test.go | wc -l | tr -d ' '
3
```

Discrimination gate (Task 1):

```text
$ rg -c 'named-target\.example' e2e/proc_e2e_test.go
3
$ rg -c 'decoy-target\.example' e2e/proc_e2e_test.go
3
```

Hermetic-environment gate:

```text
$ rg -c 'XDG_CONFIG_HOME' e2e/proc_harness_test.go
2
$ rg -c '"HOME"' e2e/proc_harness_test.go
2
```

Test count gate (Task 2):

```text
$ rg -o 'func TestProcE2E_[A-Za-z]*' e2e/proc_e2e_test.go | wc -l | tr -d ' '
3
```

## Regression Demonstrations (mandatory per plan — the single most important evidence)

### `TestProcE2E_ColdStartWatchHonorsConfigFlag` (Task 1)

Plan 01-10's layer-1 explicit-path branch in `internal/config/client.go` was disabled (`if false && overrides != nil && ...`), the binary rebuilt, and the tracer test re-run:

```text
--- FAIL: TestProcE2E_ColdStartWatchHonorsConfigFlag (0.48s)
    Error: "10.10.0.1\tnamed-target.example\n10.10.0.2\tdecoy-target.example\n" should not contain "decoy-target.example"
    Messages: rendered artifact must NOT contain the DECOY server's host — a silent connection to the decoy is the exact G-01-1 defect
```

The sink silently rendered BOTH the named host and the decoy host — proving the pre-fix binary connected to the XDG-discoverable decoy config in addition to (in this observation, effectively instead of correctly restricting to) the named one. This is the exact G-01-1 defect, reproduced from a real OS process for the first time in this repository.

The branch was then restored (`git diff internal/config/client.go` confirmed empty — byte-identical), the binary rebuilt, and the test re-run:

```text
--- PASS: TestProcE2E_ColdStartWatchHonorsConfigFlag (0.51s)
```

### `TestProcE2E_MissingExplicitConfigFailsLoudly` (Task 2)

Same revert (layer-1 branch disabled), binary rebuilt, test re-run:

```text
--- FAIL: TestProcE2E_MissingExplicitConfigFailsLoudly (30.27s)
    Error: "" does not contain ".../does-not-exist/client.toml"
    Error: Should be true
    Messages: no artifact must be written when the explicit --config fails to load, got stat error: <nil>
```

The pre-fix binary silently used the valid XDG-discovered config, ran as a functioning sink (produced no error output and DID write an artifact), and never exited — the 30-second wall-clock duration is the process running as a long-lived sink until the test's own context timeout killed it, rather than exiting immediately with an error as the fixed binary does. Both assertions failed for the correct, expected reason (empty output — no path was ever named because no error occurred; artifact present — a fallback connection succeeded).

The branch was restored (`git diff` confirmed empty), binary rebuilt, full suite re-run:

```text
--- PASS: TestProcE2E_MissingExplicitConfigFailsLoudly (0.07s)
```

## Change-ID Propagation — Observed Values (Task 2, mandatory per plan)

`TestProcE2E_ChangeIDPropagatesToSidecar` logs both observed ULIDs on every run rather than asserting non-emptiness twice. Representative run:

```text
proc_e2e_test.go:228: rendered_change_id: first=01KYZWRMHW4MXFM00A6M374QY7 second=01KYZWRMNQVK7SCFT01R4FZ669
```

Both are valid ULIDs and distinct: `first` and `second` differ, confirming `rendered_change_id` genuinely advanced after the second (separate-process) mutation rather than staying static.

## Fail-Loud Test Assertion Inspection (Task 2, mandatory per plan)

`TestProcE2E_MissingExplicitConfigFailsLoudly` asserts all three conditions the plan requires, not just one:

1. **Non-zero exit observed:** `require.True(t, errors.As(runErr, &exitErr))` then `assert.NotEqual(t, 0, exitErr.ExitCode())` — confirmed via `*exec.ExitError`.
2. **Missing path found in output:** `assert.Contains(t, out, missingCfgPath, ...)` against the process's combined stdout+stderr.
3. **Stat of the out path returns not-exist after the process ends:** `_, statErr := os.Stat(outPath); assert.True(t, os.IsNotExist(statErr), ...)`.

## Idempotency / No Leaks

`task test:e2e:proc` run twice in a row, both green, with `ps aux | grep -i router-hosts` returning empty between and after runs — no leaked `serve`/`watch` processes, no port or temp-directory collisions.

`task clean && task test:e2e` verified green with no `bin/` present — the new `proc_e2e` tag did not make the pre-existing in-process suite build-dependent.

## Verification

- `task test` — all packages pass (see note below on one pre-existing flaky test observed once under `task ci`, unrelated to this plan)
- `task lint` — 0 issues, no `//nolint` added
- `task test:e2e:proc` — all three tests PASS, run twice consecutively
- `task ci` — green on the run reported in this summary (see below)
- `git diff --name-only -- go.mod go.sum` — empty, no new dependency
- `git status --short` — clean at plan end

### Pre-existing flaky test observed (out of scope)

One `task ci` run surfaced a single flaky failure in `TestWatch_BackoffResetsAfterSuccess` (`internal/client/commands/watch_test.go`), a pre-existing timing-sensitive test unrelated to this plan's files (`"86.906667ms" is not greater than "88.970311ms"` — a real-wall-clock backoff-doubling assertion sensitive to machine load, observed running immediately after `task test:e2e:proc`'s several real OS processes). Re-run in isolation (`go test -race -count=1 -run TestWatch_BackoffResetsAfterSuccess ./internal/client/commands/...`) passed cleanly, and a subsequent full `task ci` run was fully green. Per the deviation rules' scope boundary (only auto-fix issues directly caused by the current task's changes), this was not touched — logged here for visibility, not filed as a new issue since it did not reproduce.

## Deviations from Plan

None — plan executed exactly as written, including both pre-authorized decisions the plan called out (no CI wiring; `reserveLocalPort` left with its accepted TOCTOU window rather than converted to log parsing).

## Known DX Wrinkle (non-defect, per operator note)

`gopls` reports "No packages found" for both `e2e/proc_harness_test.go` and `e2e/proc_e2e_test.go` in editors, because the `proc_e2e` build tag is not in `gopls`'s default build flags. This is expected for any tag-gated file (the same is already true of `e2e`/`docker_e2e`-tagged files) and requires no code change — it is an editor-configuration matter, not a defect in these files.

## Issues Encountered

- `startSinkProcess`'s target directory did not exist before the sink's first write attempt in the tracer test — `atomicfile.Write`'s temp-file creation failed with "no such file or directory". Fixed by creating the sink output directory (`os.MkdirAll`) before launching the sink process in each test. This is Rule 3 (blocking issue), fixed inline, verified by the subsequent green run.
- One unused-variable compile error (`waitForSidecar`'s `last` was assigned but its final fallback returned a fresh literal instead) caught by the Go compiler on first build; fixed by removing the redundant variable. Rule 1 (bug), fixed inline before any test ran.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Gap G-01-1 is now fully closed: plan 01-10 supplied the fix, this plan supplies the only harness in the repository that observes it from the real OS-process boundary the original UAT failure occurred at.
- `task test`, `task lint`, `task test:e2e`, `task test:e2e:proc`, and `task ci` are all green at plan end; `git status` is clean.
- The `proc_e2e` harness (`e2e/proc_harness_test.go`) is deliberately structured (CN-parameterized PKI, address-parameterized config writers, isolated launcher functions, filesystem-based observation, independently-handled sink instances) so the deferred containerized two-node verification (UAT test 42) can extend it rather than replace it — see `docs/contributing/testing.md`'s "Deferred: containerized two-node verification" section.
- GitHub issue #403 tracks the still-open decision of wiring any e2e tier into CI; no phase currently depends on that being resolved.

## Self-Check: PASSED

All created/modified files found on disk; all three task commits (`fca11f5`, `1bb636d`, `5b928f2`) found in git log.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-02*
