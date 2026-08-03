---
phase: 01-ci-gating-for-the-e2e-tiers
plan: 03
subsystem: testing
tags: [e2e, docker, ci-gating, testify]

requires:
  - phase: 01-01
    provides: internal/testutil/wait (Until/UntilValue), internal/ciwiring aggregator invariant

provides:
  - "internal/testutil/dockergate — tag-free, 100%-covered pure decision function (Decide) for the Docker precondition gate"
  - "dockergate.EnvVar (RH_E2E_REQUIRE_DOCKER), dockergate.Action (Proceed/Skip/Fatal)"
  - "e2e/docker_e2e_test.go's requireDocker routed through dockergate.Decide at both existing skip sites"
  - "e2e/docker_e2e_test.go's waitForDockerServer converted to wait.Until, with a t.Cleanup/t.Failed()-gated container-log dump"
  - "docs/contributing/testing.md corrected: all three e2e tiers now documented as running in CI, plus RH_E2E_REQUIRE_DOCKER semantics"

affects: [phase-01-plan-04 (ci-go.yml e2e-docker/e2e-proc jobs), phase-01-plan-05 (CI-03 red-proof negative controls)]

actuals:
  tokens: 3348
  tasks: 3
  commits: 5

tech-stack:
  added: []
  patterns:
    - "Tag-free decision function for a build-tagged test's precondition, so branch logic is covered by the ordinary Test job (not by a tier that could itself be skipped)"
    - "Presence-based (not truthiness-based) env-var gate: any non-empty value means required, no ParseBool/TrimSpace"
    - "t.Cleanup gated on t.Failed() preserves a diagnostic dump without adding a failure hook to a shared test helper"

key-files:
  created:
    - internal/testutil/dockergate/dockergate.go
    - internal/testutil/dockergate/dockergate_test.go
  modified:
    - e2e/docker_e2e_test.go
    - docs/contributing/testing.md

key-decisions:
  - "dockergate.Decide takes (envValue string, probeErr error) and returns Proceed/Skip/Fatal with no other inputs — kept free of os.Getenv so all cases are unit-testable without Docker or the docker_e2e tag"
  - "Both requireDocker skip sites (missing binary, dead daemon) route through the same dockergate.Decide call, satisfying D-06"
  - "waitForDockerServer's log dump moved into its own t.Cleanup at the top of the function, additive to (not a replacement of) buildAndStartContainer's existing container-removal cleanup, so the diagnostic fires on wait.Until's own Fatalf path too"

requirements-completed: []

coverage:
  - id: D1
    description: "dockergate.Decide covers all four env x probe combinations plus the presence-not-truthiness and no-trim boundary cases"
    requirement: "CI-04"
    verification:
      - kind: unit
        ref: "internal/testutil/dockergate/dockergate_test.go#TestDecide"
        status: pass
      - kind: unit
        ref: "internal/testutil/dockergate/dockergate_test.go#TestEnvVar"
        status: pass
      - kind: unit
        ref: "internal/testutil/dockergate/dockergate_test.go#TestActionZeroValueIsProceed"
        status: pass
    human_judgment: false
  - id: D2
    description: "requireDocker hard-fails (not skips) when RH_E2E_REQUIRE_DOCKER is set and Docker is unavailable, and still skips gracefully when unset"
    requirement: "CI-04"
    verification:
      - kind: e2e
        ref: "env RH_E2E_REQUIRE_DOCKER=1 PATH=/opt/homebrew/bin:/usr/bin:/bin go test -tags docker_e2e -run TestDockerE2E_OperatorBinaryExists ./e2e/ (FAIL, see below)"
        status: pass
      - kind: e2e
        ref: "env -u RH_E2E_REQUIRE_DOCKER PATH=/opt/homebrew/bin:/usr/bin:/bin go test -tags docker_e2e -run TestDockerE2E_OperatorBinaryExists ./e2e/ (SKIP, see below)"
        status: pass
    human_judgment: false
  - id: D3
    description: "waitForDockerServer's manual poll loop replaced by wait.Until; container-log diagnostic preserved via t.Cleanup gated on t.Failed()"
    requirement: "VRFY-05"
    verification:
      - kind: e2e
        ref: "task test:e2e:docker (TestDockerE2E_ImageBuildsAndServes, TestDockerE2E_WrongCARejected, TestDockerE2E_OperatorBinaryExists — all PASS with a live daemon)"
        status: pass
    human_judgment: false
  - id: D4
    description: "docs/contributing/testing.md's CI Integration section corrected; no longer claims no e2e tier runs in CI; documents RH_E2E_REQUIRE_DOCKER skip-vs-fail semantics"
    requirement: "VRFY-05"
    verification:
      - kind: other
        ref: "rumdl check docs/contributing/testing.md"
        status: pass
      - kind: other
        ref: "task docs:ci BINARY=/tmp/router-hosts"
        status: pass
    human_judgment: false

duration: 24min
completed: 2026-08-03
status: complete
---

# Phase 01 Plan 03: Docker Precondition Gate + Readiness Helper + Docs Summary

**Tag-free `dockergate.Decide` makes the Docker skip-vs-fail decision unit-tested every PR; `requireDocker` now hard-fails under `RH_E2E_REQUIRE_DOCKER`, `waitForDockerServer` runs on `wait.Until`, and the contributor docs stop claiming no e2e tier runs in CI.**

## Performance

- **Duration:** ~24 min
- **Started:** 2026-08-03T12:11:30Z (session continuation from 01-02)
- **Completed:** 2026-08-03T12:35:44Z
- **Tasks:** 3
- **Files modified:** 4 (2 created, 2 modified)

## Accomplishments

- `internal/testutil/dockergate` — a tag-free, `testing`-free, 100%-statement-covered pure function `Decide(envValue string, probeErr error) Action` deciding `Proceed`/`Skip`/`Fatal`, plus `EnvVar` as the single source of truth for `RH_E2E_REQUIRE_DOCKER`'s spelling.
- `e2e/docker_e2e_test.go`'s `requireDocker` rewritten so both precondition probes (missing `docker` binary, unreachable daemon) route through the same `dockergate.Decide` call — no unconditional `t.Skip` remains.
- `waitForDockerServer`'s hand-rolled deadline loop replaced by `wait.Until`; its container-log diagnostic now lives in a `t.Cleanup` gated on `t.Failed()`, so it fires on every failure path (including `wait.Until`'s own `t.Fatalf`) without adding a Docker-specific hook to the shared helper.
- `docs/contributing/testing.md`'s "CI Integration" section rewritten to describe all three tiers as required PR gates via `ci-go-complete`, plus a new `RH_E2E_REQUIRE_DOCKER` subsection and an updated harness-building-blocks note pointing at `internal/testutil/wait` and the `SLEEP-INTENTIONAL:` marker convention.

## Task Commits

Each task was committed atomically:

1. **Task 1: Build the tag-free Docker precondition decision function** — `030f685` (test, RED) then `448cc41` (feat, GREEN)
2. **Task 2: Env-gate requireDocker and route waitForDockerServer through the shared helper** — `a56b332` (feat: hard-fail docker tier when required) then `170e38e` (test: route docker readiness through wait helper)
3. **Task 3: Correct the contributor testing docs** — `a71d149` (docs: document CI gating and RH_E2E_REQUIRE_DOCKER)

**Plan metadata:** pending (this commit)

## Files Created/Modified

- `internal/testutil/dockergate/dockergate.go` — `EnvVar`, `Action` (`Proceed`/`Skip`/`Fatal`), `Decide` — pure, tag-free, 100% covered
- `internal/testutil/dockergate/dockergate_test.go` — 8 cases across `TestDecide`, `TestEnvVar`, `TestActionZeroValueIsProceed`
- `e2e/docker_e2e_test.go` — `requireDocker` env-gated via `dockergate.Decide`; `waitForDockerServer` converted to `wait.Until` + `t.Cleanup`
- `docs/contributing/testing.md` — CI Integration section corrected, `RH_E2E_REQUIRE_DOCKER` documented, harness building-blocks bullet updated

## Decisions Made

- `Decide` takes no ambient state (no `os.Getenv` inside the package) — the caller passes `os.Getenv(dockergate.EnvVar)` in, keeping every case testable without env manipulation tricks.
- The gate is presence-based, not truthiness-based, by design (per plan): `Decide("0", err)` and `Decide("  ", err)` both return `Fatal`. Pinned by dedicated test cases so no future edit "helpfully" adds `strconv.ParseBool`.
- `waitForDockerServer`'s new `t.Cleanup` is additive to — not a replacement of — `buildAndStartContainer`'s existing container-removal cleanup (which already had its own failure-gated log dump). The plan's decision P-02 asked for the diagnostic to live specifically inside `waitForDockerServer`, since that function no longer has its own inline `t.Fatalf`/log-dump pairs after the `wait.Until` conversion.

## Deviations from Plan

None - plan executed exactly as written. `docs/reference/api.md` and `docs/reference/cli.md` were regenerated as a side effect of `task docs:ci` (a pre-existing gotcha per CLAUDE.md/known_gotchas) and reverted with `git checkout --` before committing, per the plan's own scope boundary.

## Issues Encountered

None. Docker was available in this execution environment, so `task test:e2e:docker` and the hard-fail/skip proofs were run for real rather than recorded as NOT-RUN.

## Verification Evidence

### RED proof — `dockergate_test.go` before `dockergate.go` existed

```
github.com/fzymgc-house/router-hosts/internal/testutil/dockergate: no non-test Go files in /Volumes/Code/github.com/fzymgc-house/router-hosts/internal/testutil/dockergate
FAIL	github.com/fzymgc-house/router-hosts/internal/testutil/dockergate [build failed]
FAIL
```

### GREEN — after implementation

```
ok  	github.com/fzymgc-house/router-hosts/internal/testutil/dockergate	0.201s
```

100% statement coverage of `Decide` (`go tool cover -func`):
```
github.com/fzymgc-house/router-hosts/internal/testutil/dockergate/dockergate.go:44:	Decide		100.0%
total:											(statements)	100.0%
```

### Pre-edit marker-gate output for `e2e/docker_e2e_test.go` (before Task 2's edit)

```
$ awk 'FNR==1{mark=-100} /SLEEP-INTENTIONAL:/{mark=FNR} /time\.Sleep\(/{ if (FNR-mark>3) { print FILENAME":"FNR; bad=1 } } END{exit bad+0}' e2e/docker_e2e_test.go
e2e/docker_e2e_test.go:276
exit=1
```

Post-edit: the same gate exits 0 and prints nothing (`rg -n 'time\.Sleep' e2e/docker_e2e_test.go` returns no match).

### Local hard-fail proof (D-10's fourth negative control, code-level half)

With `RH_E2E_REQUIRE_DOCKER=1` and `docker` removed from `PATH`:

```
$ env RH_E2E_REQUIRE_DOCKER=1 PATH=/opt/homebrew/bin:/usr/bin:/bin go test -tags docker_e2e -run TestDockerE2E_OperatorBinaryExists ./e2e/
--- FAIL: TestDockerE2E_OperatorBinaryExists (0.00s)
    docker_e2e_test.go:120: docker not found, but RH_E2E_REQUIRE_DOCKER is set: exec: "docker": executable file not found in $PATH
FAIL
FAIL	github.com/fzymgc-house/router-hosts/e2e	0.215s
FAIL
EXIT=1
```

With the same `PATH` but `RH_E2E_REQUIRE_DOCKER` unset:

```
$ env -u RH_E2E_REQUIRE_DOCKER PATH=/opt/homebrew/bin:/usr/bin:/bin go test -tags docker_e2e -v -run TestDockerE2E_OperatorBinaryExists ./e2e/
=== RUN   TestDockerE2E_OperatorBinaryExists
    docker_e2e_test.go:120: docker not found, skipping Docker E2E test
--- SKIP: TestDockerE2E_OperatorBinaryExists (0.00s)
PASS
ok  	github.com/fzymgc-house/router-hosts/e2e	0.154s
```

### `task test:e2e:docker` with a live Docker daemon

```
=== RUN   TestDockerE2E_ImageBuildsAndServes
--- PASS: TestDockerE2E_ImageBuildsAndServes (1.58s)
=== RUN   TestDockerE2E_WrongCARejected
--- PASS: TestDockerE2E_WrongCARejected (1.45s)
=== RUN   TestDockerE2E_OperatorBinaryExists
--- PASS: TestDockerE2E_OperatorBinaryExists (0.74s)
PASS
ok  	github.com/fzymgc-house/router-hosts/e2e	4.075s
```

### Static checks

- `rg -n 'RH_E2E_REQUIRE_DOCKER' --type go .` — exactly one non-test declaration (`dockergate.go`'s `EnvVar`) plus the expected assertion in `dockergate_test.go`; zero matches in `docker_e2e_test.go`.
- `golangci-lint run ./internal/testutil/...` — 0 issues.
- `golangci-lint run --build-tags docker_e2e ./e2e/...` — 12 pre-existing `unused` findings in `e2e/helpers_test.go`, confirmed present before this plan's changes (`git stash` + re-lint), out of scope per the plan's scope boundary; 0 findings attributable to `docker_e2e_test.go`.
- `task test:coverage:ci` — 86.4% (threshold 80%).
- `rumdl check docs/contributing/testing.md` — no issues.
- `task docs:ci BINARY=/tmp/router-hosts` — succeeded; regenerated `docs/reference/{api,cli}.md` reverted afterward (out of scope).

## Requirements Note

This plan's frontmatter lists `requirements: [CI-04, VRFY-05]`, but CI-04 in
`.planning/REQUIREMENTS.md` reads as a conjunction — "container tiers hard-fail
... AND `proc_e2e` builds fresh in-job" — and this plan's own objective states
it delivers only "CI-04's first half" (the container hard-fail half; D-08's
`proc_e2e` fresh-build structural requirement is plan 04's). **CI-04 is
deliberately NOT marked complete in REQUIREMENTS.md by this plan** — mirroring
the TMPL-05 precedent (01-05 in STATE.md's decision log) of not marking a
conjunctive requirement complete until every conjunct is delivered. VRFY-05 was
already `[x]` from plan 01-02 (its two other named consumers, `e2e`/`proc_e2e`,
plus the harness); this plan completes VRFY-05's third named consumer
(`docker_e2e`), so no change to that checkbox was needed.

## Next Phase Readiness

- Plan 04 can now add the `e2e-docker` CI job, setting `RH_E2E_REQUIRE_DOCKER: "1"` — `dockergate.EnvVar` is the single string both sides must agree on.
- Plan 05's CI-03 red-proof negative control for "docker fails rather than skips" can point at the same local reproduction recorded above; no CI-level equivalent has been run yet (that is plan 05's scope).
- No blockers. `e2e/docker_e2e_test.go` is now free of unmarked `time.Sleep` and of any Docker-specific code inside `internal/testutil/wait`.

---
*Phase: 01-ci-gating-for-the-e2e-tiers*
*Completed: 2026-08-03*

## Self-Check: PASSED

All 4 created/modified files and all 5 task commit hashes verified present.
