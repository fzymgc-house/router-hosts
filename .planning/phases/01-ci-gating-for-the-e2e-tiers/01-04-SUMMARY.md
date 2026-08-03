---
phase: 01-ci-gating-for-the-e2e-tiers
plan: 04
subsystem: ci
tags: [ci-gating, github-actions, e2e, docker, proc]

requires:
  - phase: 01-01
    provides: internal/ciwiring set-equality invariant, e2e-fast job, workflow_dispatch trigger
  - phase: 01-03
    provides: internal/testutil/dockergate.EnvVar (RH_E2E_REQUIRE_DOCKER)

provides:
  - "ci-go.yml e2e-docker job — job-level RH_E2E_REQUIRE_DOCKER: \"1\", no Docker setup action"
  - "ci-go.yml e2e-proc job — rm -rf bin/ step runs before task test:e2e:proc, forcing a fresh build"
  - "ci-go-complete needs all ten jobs; E2E_DOCKER_RESULT/E2E_PROC_RESULT bound and compared != \"success\""

affects: [phase-01-plan-05 (CI-03 negative controls exercising the completed aggregator)]

actuals:
  tokens: 3200
  tasks: 2
  commits: 2

tech-stack:
  added: []
  patterns:
    - "New e2e-* job blocks clone the existing e2e-fast/test step skeleton verbatim (checkout, setup-go, nscloud-cache-action cache:go, install task) rather than inventing a new setup sequence"
    - "Structural fresh-build via an explicit rm -rf bin/ step ordered before the Taskfile target that depends on build, rather than relying on absence-of-cache as an implicit guarantee"

key-files:
  created: []
  modified:
    - .github/workflows/ci-go.yml

key-decisions:
  - "No Docker setup action added to e2e-docker — Namespace runners provide Docker natively and docker/setup-buildx-action would overwrite their Remote Builder configuration (RESEARCH.md Q-01); D-07's fallback branch deliberately not implemented"
  - "e2e-docker's env: RH_E2E_REQUIRE_DOCKER copied character-for-character from dockergate.EnvVar rather than retyped, and verified via rg -o byte comparison against internal/testutil/dockergate/dockergate.go"
  - "e2e-proc's rm -rf bin/ placed as its own named step, after task install and before the final task test:e2e:proc step, with an inline comment recording why (cache:go never touches bin/, so removal is the only thing making a stale binary structurally impossible)"
  - "on: keys left exactly pull_request + workflow_dispatch; no merge_group/push added, keeping D-03's single-stage PR-time gate intact"

requirements-completed: [CI-01, CI-02, CI-04]

coverage:
  - id: T1
    description: "e2e-docker and e2e-proc jobs exist with correct runner profiles, timeouts, pinned SHAs, hard-fail env var, and ordered bin/ removal"
    requirement: "CI-01, CI-04"
    verification:
      - kind: other
        ref: "actionlint .github/workflows/ci-go.yml"
        status: pass
      - kind: other
        ref: "yq set-equality assertions over jobs, env, and step ordering (see Verification Evidence)"
        status: pass
    human_judgment: false
  - id: T2
    description: "ci-go-complete needs all ten jobs, binds ten distinct *_RESULT vars, compares all ten with != \"success\", and internal/ciwiring's invariant passes unmodified"
    requirement: "CI-01, CI-02"
    verification:
      - kind: unit
        ref: "go test ./internal/ciwiring/... (TestEveryE2ETierIsWiredIntoAggregator)"
        status: pass
      - kind: other
        ref: "task test"
        status: pass
      - kind: other
        ref: "phase-level D-16 sleep-marker adjacency gate over e2e/*.go"
        status: pass
    human_judgment: false

duration: ~20min
completed: 2026-08-03
status: complete
---

# Phase 01 Plan 04: Complete the E2E Tier Set in CI Summary

**`ci-go.yml` grows from one e2e tier to three — `e2e-docker` (hard-fails without Docker) and `e2e-proc` (structurally fresh-built) join `e2e-fast`, and `ci-go-complete` now gates merge on all ten jobs, turning `internal/ciwiring`'s standing invariant test from red to green without touching the test itself.**

## Performance

- **Duration:** ~20 min
- **Tasks:** 2
- **Files modified:** 1 (`.github/workflows/ci-go.yml`)

## Accomplishments

- Added `e2e-docker` (`namespace-profile-linux-amd64-4x8`, 10min timeout) with a job-level `env: RH_E2E_REQUIRE_DOCKER: "1"`, cloning the existing setup-step skeleton (checkout, setup-go, `nscloud-cache-action` with `cache: go`, install task) with byte-identical pinned SHAs, then running `task test:e2e:docker`. No Docker setup action added.
- Added `e2e-proc` (`namespace-profile-linux-amd64-4x8`, 8min timeout) with the same setup skeleton, then a dedicated `rm -rf bin/` step (commented, explaining why) placed after `task` install and before `task test:e2e:proc`, so the Taskfile's `deps: ['build']` rebuilds both binaries from source every run.
- Extended `ci-go-complete`'s `needs:` to all ten jobs, added `E2E_DOCKER_RESULT`/`E2E_PROC_RESULT` env bindings, and appended their `!= "success"` clauses to the OR-chain — leaving `if: always()`, `name: CI (Go) Complete`, and every pre-existing job untouched.
- `internal/ciwiring/ciwiring_test.go` (from plan 01) went from a demonstrated red state (declared-but-not-needed: `e2e-docker`, `e2e-proc`) to green, with the test file itself never edited.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add the e2e-docker and e2e-proc jobs** — `a78de21` (`ci(e2e): add docker and proc e2e tier jobs`)
2. **Task 2: Complete the aggregator and turn the invariant test green** — `3b2c842` (`ci(e2e): gate merges on all three e2e tiers`)

**Plan metadata:** this commit (docs)

## Files Created/Modified

- `.github/workflows/ci-go.yml` — `e2e-docker` job, `e2e-proc` job, `ci-go-complete`'s completed `needs`/`env`/result-check

## Decisions Made

- Copied the three pinned action SHAs (`actions/checkout`, `actions/setup-go`, `namespacelabs/nscloud-cache-action`) byte-for-byte from the `test` job rather than re-resolving tags, per T-01-11's mitigation.
- `RH_E2E_REQUIRE_DOCKER`'s spelling in the workflow YAML was verified against `dockergate.EnvVar` via `rg -o` on both files producing identical output, closing T-01-12.
- Followed the house pattern (`go install github.com/go-task/task/v3/cmd/task@latest`) for installing `task` in both new jobs, matching `test`/`manifests`/`docs`; T-01-SC (floating `@latest`) accepted per the plan's threat register rather than pinned unilaterally in this phase.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## Verification Evidence

### Task 1 — job existence, env var, and ordering

```
$ actionlint .github/workflows/ci-go.yml
(exit 0, no output)

$ yq -e '[.jobs | keys | .[] | select(test("^e2e-"))] | sort | join(",") == "e2e-docker,e2e-fast,e2e-proc"' .github/workflows/ci-go.yml
true

$ yq -e '.jobs["e2e-docker"].env["RH_E2E_REQUIRE_DOCKER"] != null' .github/workflows/ci-go.yml
true

$ rg -o 'RH_E2E_REQUIRE_DOCKER' .github/workflows/ci-go.yml | sort -u
RH_E2E_REQUIRE_DOCKER
$ rg -o 'RH_E2E_REQUIRE_DOCKER' internal/testutil/dockergate/dockergate.go | sort -u
RH_E2E_REQUIRE_DOCKER

$ yq '[.jobs["e2e-proc"].steps[] | .run // ""] | to_entries | map(select(.value | test("rm -rf bin/|task test:e2e:proc"))) | .[].key' .github/workflows/ci-go.yml
4
5
# index 4 (rm -rf bin/) precedes index 5 (task test:e2e:proc)

$ yq -e '[.jobs[] | select(has("steps")) | .steps[] | .uses // "" | select(test("setup-buildx|setup-qemu|nscloud-setup"))] | length == 0' .github/workflows/ci-go.yml
true

$ yq -e '[.jobs[] | select(has("steps")) | .steps[] | select(.uses // "" | test("nscloud-cache-action")) | .with.cache] | unique | join(",") == "go"' .github/workflows/ci-go.yml
true

$ yq -e '.on | has("paths") or (.on.pull_request | has("paths") or has("paths-ignore"))'  .github/workflows/ci-go.yml
false
```

### Natural RED — after task 1, before task 2

```
$ go test ./internal/ciwiring/...
--- FAIL: TestEveryE2ETierIsWiredIntoAggregator (0.00s)
    ciwiring_test.go:153: e2e-* jobs and ci-go-complete.needs are out of sync: declared but not needed=[e2e-docker e2e-proc], needed but not declared=[]
FAIL
FAIL	github.com/fzymgc-house/router-hosts/internal/ciwiring	0.139s
FAIL
```

### Task 2 — aggregator completion, GREEN

```
$ actionlint .github/workflows/ci-go.yml
(exit 0, no output)

$ go test ./internal/ciwiring/...
ok  	github.com/fzymgc-house/router-hosts/internal/ciwiring	0.053s

$ git diff --exit-code internal/ciwiring/
(exit 0 — no changes; the invariant test itself was never edited)

$ yq -e '.jobs["ci-go-complete"].needs | sort | join(",") == "buf-check,build,docs,e2e-docker,e2e-fast,e2e-proc,lint,manifests,test,vuln"' .github/workflows/ci-go.yml
true

$ yq '.jobs["ci-go-complete"].steps[0].env | keys | sort | join(",")' .github/workflows/ci-go.yml
BUF_RESULT,BUILD_RESULT,DOCS_RESULT,E2E_DOCKER_RESULT,E2E_FAST_RESULT,E2E_PROC_RESULT,LINT_RESULT,MANIFESTS_RESULT,TEST_RESULT,VULN_RESULT

$ yq '.jobs["ci-go-complete"].steps[0].run' .github/workflows/ci-go.yml | rg -o '!= "success"' | wc -l
10

$ yq '.jobs["ci-go-complete"].steps[0].run' .github/workflows/ci-go.yml | rg -c '== "failure"'
0

$ yq '.jobs["ci-go-complete"].name' .github/workflows/ci-go.yml
CI (Go) Complete
$ yq '.jobs["ci-go-complete"].if' .github/workflows/ci-go.yml
always()
```

### protect-main ruleset — confirmed untouched (read-only)

```
$ gh api repos/fzymgc-house/router-hosts/rulesets --jq '.[] | select(.name=="protect-main") | .id'
10601376

$ gh api repos/fzymgc-house/router-hosts/rulesets/10601376 --jq '[.rules[] | select(.type=="required_status_checks") | .parameters.required_status_checks[].context] | sort | join(",")'
CI (Go) Complete,Vulnerability check
```

### `task test`

```
$ task test
ok  	github.com/fzymgc-house/router-hosts/cmd/operator	1.774s
ok  	github.com/fzymgc-house/router-hosts/internal/acme	4.630s
ok  	github.com/fzymgc-house/router-hosts/internal/atomicfile	1.558s
ok  	github.com/fzymgc-house/router-hosts/internal/ciwiring	1.518s
... (all packages ok, no failures)
```

### Phase-level D-16 sleep-marker adjacency gate

```
$ awk 'FNR==1{mark=-100} /SLEEP-INTENTIONAL:/{mark=FNR} /time\.Sleep\(/{ if (FNR-mark>3) { print FILENAME":"FNR; bad=1 } } END{exit bad+0}' e2e/*.go
(exit 0, no output)
```

Green across all four `e2e/*.go` files (`docker_e2e_test.go`, `e2e_test.go`, `helpers_test.go`, `proc_harness_test.go`) — every `time.Sleep` remains preceded within three lines by a `SLEEP-INTENTIONAL:` marker, unchanged from the state plans 02/03 left it. This plan touched no `e2e/*.go` file.

### yamlfmt

```
$ yamlfmt -lint .github/workflows/ci-go.yml
(exit 0, no output — already formatted)
```

## D-03 single-stage shape confirmed

```
$ yq -e '.on | keys | sort | join(",") == "pull_request,workflow_dispatch"' .github/workflows/ci-go.yml
true
$ ls .github/workflows/
ci-go.yml  cleanup-images.yml  docs.yml  release-please.yml  release.yml
(no merge-time e2e workflow added; all four other workflows pre-existed this plan)
```

## Requirements Note

`CI-01`, `CI-02`, and `CI-04` are all marked complete by this plan (see
`requirements-completed` in frontmatter). `CI-04` was a conjunction across
plans 03 and 04 — plan 03 delivered the container hard-fail half, this plan
delivers the `proc_e2e` structural fresh-build half (D-08) — so this is the
plan that closes it, mirroring the TMPL-05 precedent already used twice in
this project's decision log.

## Next Phase Readiness

- Plan 05 can now write CI-03's negative controls (deliberately breaking each
  tier and observing `ci-go-complete` fail) against a fully wired aggregator.
- No blockers. `protect-main`'s required-check set is unchanged; no new
  required status-check context was created.

---
*Phase: 01-ci-gating-for-the-e2e-tiers*
*Completed: 2026-08-03*

## Self-Check: PASSED

All modified files and both task commit hashes verified present:
- FOUND: `.github/workflows/ci-go.yml`
- FOUND: `a78de21` (Task 1 commit)
- FOUND: `3b2c842` (Task 2 commit)
