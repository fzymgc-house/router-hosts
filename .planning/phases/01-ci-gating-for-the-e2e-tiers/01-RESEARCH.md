# Phase 1: CI Gating for the e2e Tiers - Research

**Researched:** 2026-08-02
**Domain:** GitHub Actions CI wiring (Namespace-hosted runners), Go build-tag test tiers, readiness-polling helper design
**Confidence:** HIGH (mechanics verified by reading the actual workflow/config/test files and running local timing/lint probes) / MEDIUM (Namespace Docker-daemon claim, sourced from Namespace's own docs, not independently reproduced on their infra) / LOW (Q-03 CI-minute cost, extrapolated from local timings — the new jobs have never run in this repo's CI)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Gate Topology and Triggers**

- **D-01:** The three e2e jobs fold into the **existing** `ci-go-complete` aggregator — added to its `needs:` list and to its explicit result-check block. The repository's required-check set stays at exactly two contexts (`CI (Go) Complete`, `Vulnerability check`) and the `protect-main` ruleset is **not** edited.
- **D-02:** Preserve `ci-go-complete`'s existing `!= "success"` comparison style for the new jobs (not `== "failure"`). Under `if: always()`, a `cancelled` or `skipped` job is also `!= "success"`.
- **D-03:** CI-02's two-tier reading **collapses to a single PR-time gate** — there is no merge-queue mechanism in this repo. All three tiers run on every PR.
- **D-04:** Three **parallel** jobs (`e2e-fast`, `e2e-docker`, `e2e-proc`), matching how `lint`/`vuln`/`test`/`build` are already structured.
- **D-05:** Resolve the ship-note CI stall with **both** available fixes: add `workflow_dispatch` to `ci-go.yml`, **and** strip the `[ci skip]` marker from `/gsd-ship`'s ship-note commit.

**Docker Availability and Fresh Builds (CI-04)**

- **D-06:** `requireDocker` becomes **env-gated**, not unconditionally fatal: hard-fail when `RH_E2E_REQUIRE_DOCKER` is set (the `e2e-docker` CI job sets it), skip otherwise. Both existing skip sites (`e2e/docker_e2e_test.go:139-141` missing binary, `:143-145` dead daemon) route through the same gate.
- **D-07:** Whether the Namespace runner profiles provide a Docker daemon is **unknown and must be researched**. Planning may assume it works, but must carry a fallback if a setup action is required.
- **D-08:** `proc_e2e` builds fresh **structurally, not by convention**: the job removes `bin/` before `task build`, and no cache step restores `bin/`.

**Red Demonstration (CI-03)**

- **D-09:** Red proofs are staged as **throwaway PRs from scratch branches** — push a deliberately-broken branch, open a PR, capture the failing run URL, close without merging.
- **D-10:** **Four** negative controls are required: one per tier, plus one proving `e2e-docker` **fails rather than skips** when Docker is unavailable.
- **D-11:** Each tier's regression must be one that **only that tier catches**. For `proc_e2e` specifically, the regression is a reintroduction of the **G-01-1 CLI-flag→config seam** defect. The researcher selects equivalents for `e2e` and `docker_e2e`.

**Readiness Helper (VRFY-05)**

- **D-13:** Scope is **readiness/synchronization sleeps only**. `e2e/e2e_test.go:757` (300ms deliberate outage-window hold) MUST NOT be converted or removed; it MUST carry an explicit marker comment. Poll intervals inside already-bounded loops are routed **through** the helper, not deleted.
- **D-14:** The helper lives in **`internal/testutil/wait`** — a normal (non-`_test.go`), untagged, importable package. Fallback if genuinely blocked: `e2e/wait_test.go` tagged `e2e || docker_e2e || proc_e2e`.
- **D-15:** On timeout the helper calls **`t.Fatalf`** with the condition's human-readable description (taking `testing.TB`, calling `t.Helper()`). No return path a caller can silently drop.
- **D-16:** The acceptance criterion for this work MUST NOT be a grep count on `time.Sleep`. Assert on structure: each converted call site routes through the helper, and each intentional sleep carries its marker comment. Any gate written for this phase must itself be demonstrated red before acceptance.

### Claude's Discretion

- Runner profile sizing and per-job timeouts for the three e2e jobs
- The exact signature and option surface of `wait.Until` beyond D-15's constraints (`testing.TB`, `t.Helper()`, `t.Fatalf` on timeout, a description string)
- Which specific regressions serve as tier-unique red proofs for `e2e` and `docker_e2e` (D-11 fixes only `proc_e2e`'s) — **resolved by this research, see "Red-Proof Regression Selection" below**
- Job naming, beyond the `e2e-fast` / `e2e-docker` / `e2e-proc` shape

### Deferred Ideas (OUT OF SCOPE)

- **Merge queue** — would implement CI-02's two-stage gating as literally worded. Rejected for this phase.
- **Separate `E2E Complete` required check** — rejected under D-01.
- **Path-filtering the slow tiers** on docs-only diffs — parked pending Q-03's answer (see below — cost appears modest at current job granularity, so path-filtering is not recommended for this phase).
- **Nightly-scheduled e2e cadence and a flake-quarantine convention** — out of scope for v0.14.0.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CI-01 | All three e2e tiers run as CI jobs; single aggregated required check fails if any tier fails | `ci-go-complete` extension pattern verified against the live `.github/workflows/ci-go.yml:136-164`; see "Extending ci-go-complete" |
| CI-02 | Fast tier gates every PR; container/process tiers gate merge — collapsed to PR-time per D-03 | `protect-main` ruleset fetched live via `gh api`; confirms no `merge_group` rule and squash-only merges, validating D-03's claim |
| CI-03 | Each new gate demonstrated red before acceptance | Red-proof regressions identified with exact file:line for all three tiers, each verified to be tier-unique by tracing which test file exercises which code path |
| CI-04 | Docker tier hard-fails (not skips) when Docker unavailable; `proc_e2e` builds fresh in-job | `requireDocker` skip sites read at `docker_e2e_test.go:136-146`; `nscloud-cache-action`'s cache scope confirmed via Namespace docs to never touch `bin/` |
| VRFY-05 | Shared bounded-timeout wait helper replacing five ad-hoc pollers and six bare sleeps | All sleep/poller call sites catalogued with file:line and classification below; in-repo precedent for the `testing`-importing package shape found and empirically verified (`internal/storage/storagetest/suite.go`) |
</phase_requirements>

## Summary

This phase is pure CI/test-infrastructure wiring — no product code changes. All three e2e tiers (`e2e`, `docker_e2e`, `proc_e2e`) already exist, build, and pass; the work is (1) adding three parallel GitHub Actions jobs that invoke the existing `task test:e2e*` targets, (2) folding their results into the existing `ci-go-complete` aggregator using the exact pattern already used for seven other jobs, (3) making the Docker tier fail loudly instead of skipping when Docker is absent, (4) making `proc_e2e`'s build structurally fresh, (5) proving each new gate can actually go red, and (6) consolidating five ad-hoc polling helpers plus six bare `time.Sleep` calls into one shared `internal/testutil/wait` package.

Every open question CONTEXT.md assigned to research has a concrete, evidence-backed answer:

- **Q-01 (Docker on Namespace runners):** Namespace's own documentation states Docker (`docker build` AND `docker run`) works out of the box with **no setup action** — and explicitly warns that adding `docker/setup-buildx-action` will *break* the default Remote Builder acceleration. D-07's fallback branch is therefore not needed; planning should NOT add a Docker setup action.
- **Q-02 (`internal/testutil/wait` importing `testing`):** This exact shape — a non-`_test.go`, untagged, importable package that imports `"testing"` — already exists in this module at `internal/storage/storagetest/suite.go`. Empirically confirmed: `golangci-lint run ./internal/storage/storagetest/...` reports 0 issues, and `go list -deps ./cmd/router-hosts/... | rg storagetest` / `./cmd/operator/...` both return no match, proving neither binary's dependency graph pulls it in. `internal/testutil/wait` can follow the identical shape with the same guarantees, provided nothing under `cmd/` imports it (a `go list -deps` check the plan should encode as its own gate).
- **Q-03 (CI-minute cost):** The existing 7-job workflow is cheap on Namespace's infrastructure — per-job durations sampled from 15 recent PR runs are almost all in the 10-90 second range (`gh run view --json jobs`), with total PR wall-clock of 70-220 seconds across all jobs run in parallel. Local timing proxies (not CI-measured, since the new jobs don't exist yet) put `e2e` at ~5s, `proc_e2e` (build+test) at ~22s, and `docker_e2e` (image build+test) at ~40-60s. Because jobs run in parallel, the PR-gate wall-clock addition is bounded by the slowest new job, not their sum — path-filtering is very unlikely to be worth the complexity at this repo's PR volume, but this is a LOW-confidence extrapolation since none of the three jobs has ever executed inside this repo's actual CI.

<critical_finding>
**D-05's `[ci skip]` marker strip is NOT achievable inside this repository.** The marker lives in the globally-installed GSD tool (`$HOME/.claude/gsd-core/workflows/ship.md:457`, in this commit-message template: `"docs(${padded_phase}): ship phase ${PHASE_NUMBER} — PR #${PR_NUMBER} [ci skip]"`), not in any file under `.planning/` or elsewhere in this repo. No repo-local override of `/gsd-ship` exists (checked `.claude/`, `.gsd*` — none found). **The plan can only implement the `workflow_dispatch:` half of D-05** (a repo file, `.github/workflows/ci-go.yml`); the marker-strip half is out of this repo's reach and should be surfaced to the user as a manual global-config change or an upstream GSD issue, not silently dropped or worked around locally.
</critical_finding>

**Primary recommendation:** Add `e2e-fast`, `e2e-docker`, `e2e-proc` as three new parallel jobs cloned from the existing `test` job skeleton (checkout → setup-go → nscloud-cache-action → install task → run task target), wire all three into `ci-go-complete`'s `needs:` and result-check block exactly like the seven existing jobs, do NOT add any Docker setup action, and build the readiness helper at `internal/testutil/wait` following the `storagetest` package's proven shape.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| PR-time test-tier execution | CI/CD (GitHub Actions) | — | `ci-go.yml` triggers only on `pull_request`; there is no merge-queue or push-to-main trigger in this repo |
| Aggregated pass/fail signal | CI/CD (GitHub Actions) | Branch protection (`protect-main` ruleset) | `ci-go-complete` computes the aggregate; the ruleset only ever sees that one context plus `Vulnerability check` |
| Docker daemon availability | CI runner infrastructure (Namespace) | — | Namespace's Remote Builder + daemon is a property of the runner image, not something this repo configures |
| Fresh-binary guarantee for `proc_e2e` | CI job step (`rm -rf bin/` before `task build`) | Taskfile (`test:e2e:proc`'s `deps: ['build']`) | The job step is the structural enforcement point; the Taskfile dependency alone is "not yet broken," not "cannot be broken" |
| Readiness polling | Go test package (`internal/testutil/wait`) | Individual `*_test.go` call sites | The package owns the bounded-timeout/backoff logic once; call sites only supply a condition function and description |
| Red-proof evidence | GSD verification verbs (`/gsd-verify-work`, `/gsd-validate-phase`) | — | Per D-12 and repo rule `01ygyqn0by`, `.planning/`-owned artifacts (`{NN}-VALIDATION.md`, `{NN}-UAT.md`) are written only by their owning verb |

## Q-01: Namespace Runner Docker Availability (blocks D-07)

**Finding: Docker works out of the box on Namespace runners. No setup action needed or recommended.**

From Namespace's official docs (`https://namespace.so/docs/solutions/github-actions/docker-builds`), fetched directly [CITED: namespace.so/docs/solutions/github-actions/docker-builds]:

> "No configuration changes required." / "No docker/setup-buildx-action or docker/setup-qemu-action required!"

The docs further state that `docker/setup-buildx-action` will **overwrite** the runner's default Remote Builder configuration if used — i.e. adding it is actively harmful, not merely redundant. This directly resolves D-07: **do not add `namespacelabs/nscloud-setup`, `docker/setup-buildx-action`, or any Docker setup action to the `e2e-docker` job.** `docker build` and `docker run` are available immediately after `actions/checkout`.

Namespace's runner-configuration docs [CITED: namespace.so/docs/reference/github-actions/runner-configuration] describe the shape sizing as vCPU×memory (e.g. `2x4`, `4x8`) but did not state a hard minimum for `docker build` + container-run workloads. Given the current workflow already uses `namespace-profile-linux-amd64-4x8` for the two jobs that do real work (`vuln`, `test`), and Namespace's own docs note that actual build compute for `docker build` happens on Remote Builders (decoupled from the runner's own CPU/memory), the safe, unremarkable choice is:

- `e2e-fast` (in-process `e2e`, mirrors `test`'s workload shape): `namespace-profile-linux-amd64-4x8`
- `e2e-docker` (image build + container run + gRPC dial): `namespace-profile-linux-amd64-4x8`
- `e2e-proc` (native compile + two OS processes): `namespace-profile-linux-amd64-4x8`

This is `[ASSUMED]` sizing (Claude's Discretion per CONTEXT.md) — Namespace's docs do not name a required minimum, so `4x8` (matching the existing heaviest-workload jobs) is a conservative default that can be right-sized down after the first real run if profiling shows it's overkill.

**Timeouts:** the existing jobs range 5-15 minutes. `task test:e2e:docker` already sets `-timeout 5m` at the `go test` level (Taskfile.yml:35); `task test:e2e:proc` too (Taskfile.yml:40). Recommend `timeout-minutes: 10` for `e2e-docker` (image build adds meaningful wall-clock beyond the 5m test timeout) and `timeout-minutes: 8` for `e2e-fast`/`e2e-proc`, mirroring the `test` job's 15-minute ceiling scaled down for tiers that are individually smaller in scope.

## Q-02: `internal/testutil/wait` Importing `testing` (constrains D-14)

**Finding: This exact package shape already exists and works cleanly in this module. No fallback needed.**

`internal/storage/storagetest/suite.go` [VERIFIED: internal/storage/storagetest/suite.go:1-18] is a normal (non-`_test.go`), untagged, importable package that imports `"testing"` directly:

```go
// Package storagetest provides a reusable compliance test suite that any
// storage.Storage implementation must pass. Embed these functions into a
// backend-specific _test.go file and call them with a freshly initialised store.
package storagetest

import (
	"context"
	"fmt"
	"testing"
	"time"
	...
)
```

Empirical checks run this session:

1. **Lint:** `golangci-lint run ./internal/storage/storagetest/...` → `0 issues.` [VERIFIED: ran this session against `.golangci.yml`'s live config — `revive`, `gocritic`, `misspell`, `nilerr`, `errorlint`, `exhaustive`, `prealloc` all enabled]
2. **`cmd/` isolation:** `go list -deps ./cmd/router-hosts/...` and `go list -deps ./cmd/operator/...`, each piped through `rg storagetest`, both returned **no match** (exit 1) [VERIFIED: ran this session] — neither shipped binary's dependency graph includes the `testing`-importing package, confirming import isolation works exactly as D-14 assumes.
3. **Consumers today:** only `internal/storage/sqlite/compliance_test.go` (a `_test.go` file) imports `storagetest` [VERIFIED: `rg` result this session] — the same consumption pattern the three e2e build tags (`e2e`, `docker_e2e`, `proc_e2e`) would use for `internal/testutil/wait`.

**Recommendation:** build `internal/testutil/wait` with the identical shape (plain package, imports `testing`, no build tag). Add a `go list -deps ./cmd/... | rg testutil/wait` isolation check as one of this phase's own gates (mirrors the empirical check above) — this gives CI-03's "demonstrated red" requirement something concrete to prove for VRFY-05's own acceptance, per D-16's ban on grep-count gates elsewhere.

The documented fallback (`e2e/wait_test.go` tagged `e2e || docker_e2e || proc_e2e`) is **not needed** — D-14's primary choice is empirically clear.

## Q-03: CI-Minute Cost of All Three Tiers on Every PR (informs D-03's cost tradeoff)

**Finding: current workflow is cheap; the three new tiers will very likely stay in the same order of magnitude. Path-filtering is not recommended for this phase.**

Sampled 15 recent PR-triggered `ci-go.yml` runs via `gh run list --workflow=ci-go.yml --limit 15 --json ...` [VERIFIED: ran this session]. Full-workflow wall-clock (`createdAt` → `updatedAt`, all 7 existing jobs running in parallel) ranged from 41s to 218s, median ~92s. Per-job breakdown from two representative runs (`gh run view <id> --json jobs`) [VERIFIED: ran this session]:

| Job | Run 1 duration | Run 2 duration |
|-----|----------------|-----------------|
| Lint | 72s | 65s |
| Vulnerability check | 9s | 10s |
| Test | 11s | 47s |
| Build | 10s | 10s |
| Buf lint & format | 4s | 5s |
| Manifests up to date | 11s | 27s |
| Docs build (strict) | 19s | 23s |

These numbers reflect Namespace's Remote Builder + persistent Go module/build cache (`nscloud-cache-action`), which is why even `go test ./internal/...` completes in 11-47s despite ≥80% coverage enforcement across the whole module.

**Local timing proxies for the three new tiers** (run this session on this machine, NOT on Namespace infra — presented as a rough order-of-magnitude signal, not a CI measurement):

| Tier | Local wall-clock | What it measures |
|------|-------------------|-------------------|
| `e2e` (`go test -tags e2e ./e2e/`) | ~4.7s | compile + full in-process mTLS suite |
| `proc_e2e` build + test | ~20.6s (build) + ~1.5s (test) ≈ 22s | `task build` (two binaries) + real-process suite |
| `docker_e2e` full tier (`task test:e2e:docker`) | ~39-43s | multi-stage Docker image build + container run + 3 tests |

Because the three new jobs run in **parallel** with each other and with the existing seven (D-04), the PR-gate wall-clock addition is bounded by the slowest single new job — most likely `e2e-docker` given the image build step — not by their sum. Total *billed* job-minutes (sum across all jobs) grows by roughly the sum of the three new jobs' individual durations, which based on the proxies above is on the order of a low single-digit number of additional job-minutes per PR.

**Confidence: LOW.** None of the three tiers has ever run inside this repo's actual CI environment; Namespace's remote-builder caching behavior for a fresh Docker image build (no prior layer cache on a brand-new ephemeral runner, though Namespace's Remote Builders may retain their own cross-run cache per their "advanced caching" claim) is not something this session could verify directly. **Recommendation:** do not path-filter in this phase (D-03 already collapses to PR-time gating and path-filtering was explicitly deferred pending this answer); instead, treat the first few real red-proof and merge-gate runs (already required by CI-03/D-09) as the actual measurement, and revisit path-filtering only if real numbers turn out to be materially higher than this estimate.

## Standard Stack

### Core

| Component | Version | Purpose | Why Standard |
|-----------|---------|---------|---------------|
| GitHub Actions (`pull_request` trigger) | n/a | CI orchestration | Already the only trigger in `ci-go.yml` [VERIFIED: `.github/workflows/ci-go.yml:2-4`] |
| Namespace Cloud runners (`namespace-profile-linux-amd64-*`) | n/a | Hosted runner infra with Remote Builders + persistent cache | Already used by all 7 existing jobs [VERIFIED: `.github/workflows/ci-go.yml`, every job's `runs-on:`] |
| `namespacelabs/nscloud-cache-action@c5f8dab...` (pinned to `# v1`) | pinned SHA | Go module/build cache (`GOCACHE`/`GOMODCACHE` only) | Already used in every job; confirmed via Namespace docs to never touch project output dirs like `bin/` [CITED: namespace.so cache-action docs] |
| `go-task/task/v3` | installed via `go install ...@latest` | Task runner invoked by CI (`task test:coverage:ci`, etc.) | Already the pattern in `test`, `manifests`, `docs` jobs; CLAUDE.md mandates `task` over direct `go` invocations |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `testing.TB` (stdlib) | go1.26.5 [VERIFIED: go.mod:3] | Interface for `wait.Until`'s parameter, so it works from both `*testing.T` and `*testing.B` call sites | Standard Go pattern for test-helper packages; matches D-15's requirement |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `internal/testutil/wait` (plain package) | `e2e/wait_test.go` tagged `e2e \|\| docker_e2e \|\| proc_e2e` | Rejected — Q-02 found no problem with the plain-package approach, and a `_test.go` file cannot be imported across packages, which would wrongly constrain Phase 3's harness |
| `docker/setup-buildx-action` on `e2e-docker` | none (do nothing) | Rejected — Namespace explicitly documents this action as harmful on their runners, overwriting the default Remote Builder config |
| A fourth, separate `E2E Complete` required check | Folding into `ci-go-complete` | Rejected under D-01 — see CONTEXT.md |

**Installation:** no new dependencies. This phase adds zero third-party Go packages — the readiness helper is pure stdlib (`time`, `testing`) plus this module's own error wrapping (`samber/oops`, already a project dependency).

## Package Legitimacy Audit

**Not applicable.** This phase installs no new external packages (Go module or otherwise). `internal/testutil/wait` is built entirely on the Go standard library. No `go.mod` changes are anticipated.

## Architecture Patterns

### System Architecture Diagram

```
PR opened/pushed
      │
      ▼
GitHub Actions: ci-go.yml (trigger: pull_request → branches: [main])
      │
      ├──────────────┬──────────────┬──────────────┬────────────┬─────────────┬───────────┐
      ▼              ▼              ▼              ▼            ▼             ▼           ▼
   [lint]         [vuln]         [test]         [build]    [buf-check]   [manifests]   [docs]
      │              │              │              │            │             │           │
      │           (existing 7 jobs, unchanged)                                            │
      │              │              │              │            │             │           │
      └──────┬───────┴──────┬───────┴──────┬───────┴─────┬──────┴──────┬──────┴─────┬─────┘
             │              │              │             │             │            │
             ▼              ▼              ▼             ▼             ▼            ▼
        [e2e-fast]     [e2e-docker]    [e2e-proc]   (NEW jobs, parallel to existing 7)
             │              │              │
        go test -tags   docker build   task build (rm -rf bin/ first)
        e2e ./e2e/      + docker run   → go test -tags proc_e2e ./e2e/
        (in-process     RH_E2E_REQUIRE
        real mTLS)      _DOCKER=1 set
             │              │              │
             └──────────────┴──────────────┘
                             │
                             ▼
                    ci-go-complete (if: always(), needs: [...all 10 jobs])
                    checks needs.*.result != "success" for every job
                    (skipped/cancelled/failed all trip the gate — D-02)
                             │
                             ▼
                  protect-main ruleset (UNCHANGED — D-01)
                  required: "CI (Go) Complete" + "Vulnerability check"
                             │
                             ▼
                      Merge allowed / blocked
```

Every readiness wait inside `e2e-fast`/`e2e-docker`/`e2e-proc`'s test processes routes through `internal/testutil/wait.Until` rather than a bare `time.Sleep` loop — this is a code-level concern inside the jobs above, not a separate pipeline stage.

### Recommended Project Structure

```
.github/workflows/ci-go.yml     # +3 job blocks, extended ci-go-complete needs/checks, +workflow_dispatch trigger
internal/testutil/wait/
├── wait.go                     # Until(tb testing.TB, timeout, interval time.Duration, desc string, cond func() bool)
└── wait_test.go                # unit tests for the helper itself (timeout path, success path, description in Fatalf message)
e2e/
├── e2e_test.go                 # 5 of 6 time.Sleep calls converted to wait.Until; line 757's kept + marker comment
├── docker_e2e_test.go          # requireDocker gains RH_E2E_REQUIRE_DOCKER branch; waitForDockerServer's poll converted
├── proc_harness_test.go        # waitForProcAddr/waitForFileContent/waitForSidecar's internal loops converted
└── helpers_test.go             # startServer's bind-retry loop (line 216) converted
```

### Pattern 1: Extending `ci-go-complete`

**What:** Add a job to the `needs:` array and a corresponding `env:`/`if` check inside the existing shell script, following the exact shape already used for all 7 current jobs.
**When to use:** Any time a new required-signal job is added to this workflow.
**Example:**
```yaml
# Source: .github/workflows/ci-go.yml:136-164 (read this session)
  ci-go-complete:
    name: CI (Go) Complete
    if: always()
    needs: [lint, vuln, test, build, buf-check, manifests, docs, e2e-fast, e2e-docker, e2e-proc]
    runs-on: namespace-profile-linux-amd64-2x4
    timeout-minutes: 5
    steps:
      - name: Check job results
        env:
          LINT_RESULT: ${{ needs.lint.result }}
          # ...existing 6 vars...
          E2E_FAST_RESULT: ${{ needs.e2e-fast.result }}
          E2E_DOCKER_RESULT: ${{ needs.e2e-docker.result }}
          E2E_PROC_RESULT: ${{ needs.e2e-proc.result }}
        run: |
          if [[ "$LINT_RESULT" != "success" ]] || \
             # ...existing 6 checks... \
             [[ "$E2E_FAST_RESULT" != "success" ]] || \
             [[ "$E2E_DOCKER_RESULT" != "success" ]] || \
             [[ "$E2E_PROC_RESULT" != "success" ]]; then
            echo "One or more CI jobs failed"
            exit 1
          fi
          echo "All CI jobs passed"
```

### Pattern 2: New Job Skeleton (matching the `test` job)

**What:** checkout → setup-go (with `go-version-file: go.mod`, `cache: false`) → `nscloud-cache-action` (Go module/build cache only) → install `task` → run the target.
**When to use:** For all three new jobs; `e2e-docker` additionally sets `RH_E2E_REQUIRE_DOCKER=1` in its `env:`.
**Example:**
```yaml
# Source: .github/workflows/ci-go.yml:39-56 (the `test` job, read this session), adapted
  e2e-fast:
    name: E2E (fast)
    runs-on: namespace-profile-linux-amd64-4x8
    timeout-minutes: 8
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7
        with:
          go-version-file: go.mod
          cache: false
      - name: Cache Go modules and build
        uses: namespacelabs/nscloud-cache-action@c5f8dab7560444c4bf8dbc64f1b203431873c547 # v1
        with:
          cache: go
      - name: Install task runner
        run: go install github.com/go-task/task/v3/cmd/task@latest
      - name: Run fast e2e tier
        run: task test:e2e

  e2e-docker:
    name: E2E (docker)
    runs-on: namespace-profile-linux-amd64-4x8
    timeout-minutes: 10
    env:
      RH_E2E_REQUIRE_DOCKER: "1"       # D-06: hard-fail instead of skip
    steps:
      # ...same checkout/setup-go/cache/task-install steps...
      - name: Run docker e2e tier
        run: task test:e2e:docker      # already has deps:['docker:build']

  e2e-proc:
    name: E2E (proc)
    runs-on: namespace-profile-linux-amd64-4x8
    timeout-minutes: 8
    steps:
      # ...same checkout/setup-go/cache/task-install steps...
      - name: Remove any pre-existing bin/ (structural fresh build, D-08)
        run: rm -rf bin/
      - name: Run proc e2e tier
        run: task test:e2e:proc        # already has deps:['build']
```

`nscloud-cache-action`'s `cache: go` mode only persists `GOCACHE`/`GOMODCACHE` [CITED: namespace.so cache-action docs, fetched this session] — it never touches `bin/`, so D-08's `rm -rf bin/` step is a structural belt-and-suspenders guarantee on top of an already-true property, converting "nobody has broken it yet" into "cannot be broken."

### Pattern 3: Env-Gated `requireDocker` (D-06)

**What:** Replace the unconditional `t.Skip` at both existing skip sites with a branch on `RH_E2E_REQUIRE_DOCKER`.
**When to use:** `e2e/docker_e2e_test.go`'s `requireDocker` helper.
**Example:**
```go
// Source: e2e/docker_e2e_test.go:136-146 (read this session) — CURRENT code:
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found, skipping Docker E2E test")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running, skipping Docker E2E test")
	}
}

// PROPOSED shape (D-06): gate the skip itself on the env var.
func requireDocker(t *testing.T) {
	t.Helper()
	required := os.Getenv("RH_E2E_REQUIRE_DOCKER") != ""
	if _, err := exec.LookPath("docker"); err != nil {
		if required {
			t.Fatalf("docker not found, but RH_E2E_REQUIRE_DOCKER is set: %v", err)
		}
		t.Skip("docker not found, skipping Docker E2E test")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		if required {
			t.Fatalf("docker daemon not running, but RH_E2E_REQUIRE_DOCKER is set: %v", err)
		}
		t.Skip("docker daemon not running, skipping Docker E2E test")
	}
}
```
Both skip sites [VERIFIED: `e2e/docker_e2e_test.go:139-141` (`docker not found`), `:143-145` (`docker daemon not running`)] must route through the same `required` check per D-06's "both existing skip sites" requirement.

### Anti-Patterns to Avoid

- **Relying on `nscloud-cache-action`'s absence-of-a-`bin/`-cache-step as the only guarantee for D-08.** That property already holds today (verified above) but is not enforced — a future PR could add a cache step for `bin/` without anyone noticing. The `rm -rf bin/` step makes the guarantee structural.
- **Using `docker/setup-buildx-action` "just to be safe."** Namespace's docs are explicit that this actively degrades the runner (overwrites Remote Builder config). Do not add it, do not add `namespacelabs/nscloud-setup` either — no setup action of any kind is needed for `e2e-docker`.
- **Writing the acceptance gate for VRFY-05 as `rg -c 'time.Sleep' e2e/*.go`.** Explicitly forbidden by D-16 — cannot distinguish the intentional `e2e_test.go:757` hold from a readiness sleep, and stops matching the moment anyone renames the pattern.
- **Hand-writing `{NN}-VALIDATION.md` / `{NN}-UAT.md` with the four red-proof run URLs.** Per D-12, these are GSD-owned artifacts written only by `/gsd-verify-work` / `/gsd-validate-phase`. The plan should route red-proof evidence capture through those verbs, not a manual Write.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| Bounded-timeout polling with a clear failure message | A sixth ad-hoc `for time.Now().Before(deadline) { ...; time.Sleep(x) }` loop | `internal/testutil/wait.Until` | This phase exists specifically to stop this pattern from being reinvented per file — five near-identical copies already exist (`waitForServer`, `waitForDockerServer`, `waitForProcAddr`, `waitForFileContent`, `waitForSidecar`) |
| CI aggregate pass/fail signal | A second required check, a custom GitHub App, or a bash script polling the Checks API | `ci-go-complete`'s existing `if: always()` + `needs:` + shell result-check pattern | Already proven correct for 7 jobs; D-01 explicitly rejects introducing a new required-context failure mode |
| Docker daemon setup on Namespace runners | Any `docker/setup-*` or `nscloud-setup` action | Nothing — it's present by default | Namespace's docs state adding a setup action actively breaks the pre-configured Remote Builder acceleration |

**Key insight:** every piece of "new machinery" this phase needs (a job skeleton, an aggregator pattern, a Docker daemon) already has a working, in-repo or vendor-documented precedent. The work is wiring existing pieces together, not designing new mechanisms — the CONTEXT.md's own framing ("this is wiring, not new test code") extends to the CI layer itself.

## Red-Proof Regression Selection (D-11, resolves Claude's Discretion item)

CI-03 requires each of the three tiers to be demonstrated red against a regression **only that tier catches**. `proc_e2e`'s regression is fixed by D-11; this research selects the other two and verifies tier-uniqueness by tracing which test files exercise which code paths.

### `proc_e2e` (fixed by D-11): reintroduce G-01-1

**Regression:** delete or comment out `internal/client/commands/connect.go:29-31`:
```go
// Source: internal/client/commands/connect.go:29-31 (read this session)
	if Flags.Config != "" {
		overrides.ConfigPath = &Flags.Config
	}
```
With this removed, the `--config` CLI flag is silently ignored and `LoadClientConfig` falls through to XDG auto-discovery — exactly the G-01-1 defect plan `01-10` fixed [VERIFIED: `.planning/milestones/v0.13.0-phases/01-consumer-rendered-output-templates-sink/01-10-SUMMARY.md`, which captured the pre-fix RED output for this exact code path].

**Why `proc_e2e`-unique:** `TestProcE2E_ColdStartWatchHonorsConfigFlag`, `TestProcE2E_MissingExplicitConfigFailsLoudly`, and `TestProcE2E_ChangeIDPropagatesToSidecar` [VERIFIED: `e2e/proc_e2e_test.go:32, 113, 172`] all invoke the shipped binary via `os/exec` with a real `--config <path>` flag, which is the only place in this repo's test suite where Cobra's flag-parsing → `connect.go` wiring is exercised from outside the process. The in-process `e2e` tier never passes `--config` on a command line — `TestE2E_WatchSinkSurvivesServerRestart` builds a `cobra.Command` via `commands.NewRootCmd(...)` and sets flags like `--server`, `--cert`, `--key`, `--ca` directly [VERIFIED: `e2e/e2e_test.go:719-728`], never `--config`. `docker_e2e` tests the *server* container only and never invokes the client CLI's `--config` flag at all [VERIFIED: `e2e/docker_e2e_test.go` — no `--config` references outside `serve --config` baked into `Dockerfile`'s `CMD`]. Removing `connect.go:29-31` therefore fails only `proc_e2e`'s three tests.

### `e2e` (selected by this research): break CN-based sink-health keying

**Regression:** change `internal/server/peercn.go:39`:
```go
// Source: internal/server/peercn.go:27-40 (read this session) — CURRENT code:
func commonNameFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", oops.Errorf("no peer info in context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", oops.Errorf("connection is not TLS-authenticated")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", oops.Errorf("no verified client certificate chain")
	}
	return tlsInfo.State.VerifiedChains[0][0].Subject.CommonName, nil  // line 39 — regression target
}
```
Change the final `return` to `return "", nil` (silently discard the real CN, return empty string with no error).

**Why `e2e`-unique:** `TestE2E_WatchSinkHealthKeyedByCN` [VERIFIED: `e2e/e2e_test.go:641-684`] asserts three things this change breaks: the registry holds an entry keyed by the literal CN `e2e-test-client` (line 665-680: `snap.States["e2e-test-client"]`), `snap.States` has exactly length 1, and `snap.States[""]` (the empty key) is explicitly asserted absent (`hasEmptyKey` must be `false`, line 675-676). With the regression, the entry would land under the empty key instead, failing both the length-1 assertion and the not-empty-key assertion. Neither `docker_e2e` nor `proc_e2e` exercises `WatchHosts` or the server's `SinkHealth` registry at all — `docker_e2e`'s three tests are `TestDockerE2E_ImageBuildsAndServes`, `TestDockerE2E_WrongCARejected`, `TestDockerE2E_OperatorBinaryExists` [VERIFIED: `e2e/docker_e2e_test.go:41, 94, 118` — none call `WatchHosts`]; `proc_e2e`'s tests observe the sink only through the sidecar's on-disk JSON status file (`procSinkStatus` — `RenderedChangeID`, `ConsecutiveFailures`), which never surfaces the server-side `SinkHealth` registry's per-CN keying at all [VERIFIED: `e2e/proc_harness_test.go:478-489`, the `procSinkStatus` struct has no CN-keyed field].

### `docker_e2e` (selected by this research): drop the operator binary from the image

**Regression:** delete `Dockerfile:24`:
```dockerfile
# Source: Dockerfile:20-29 (read this session) — CURRENT code:
FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --from=builder /out/router-hosts /usr/local/bin/router-hosts
COPY --from=builder /out/operator /usr/local/bin/operator   # <-- delete this line

EXPOSE 50051

ENTRYPOINT ["router-hosts"]
CMD ["serve", "--config", "/etc/router-hosts/server.toml"]
```

**Why `docker_e2e`-unique:** `TestDockerE2E_OperatorBinaryExists` [VERIFIED: `e2e/docker_e2e_test.go:118-134`] runs `docker run --rm --entrypoint operator <image> --help` and asserts the output does not contain `"not found"` and is non-empty. Deleting the `COPY` line makes `docker run` fail with an entrypoint-not-found error, failing this test. Neither `e2e` (in-process, no Docker image involved at all) nor `proc_e2e` (uses the locally-built `bin/router-hosts` from `task build`, never touches the Docker image or the `operator` binary at all [VERIFIED: `e2e/proc_harness_test.go:47-66`, `procBinaryPath` only resolves `bin/router-hosts` or `$ROUTER_HOSTS_BIN`]) can observe this regression.

### The fourth negative control (D-10): `e2e-docker` fails rather than skips

**What to prove:** with `RH_E2E_REQUIRE_DOCKER=1` set and Docker made unavailable (e.g. `PATH` stripped of `docker`, or run on a Docker-less runner), the job must fail (`t.Fatalf`), not report green via `t.Skip`. This is a proof of the D-06 code change itself, not of a tier's product-code regression — stage it as its own throwaway PR per D-09, run with `RH_E2E_REQUIRE_DOCKER=1` and Docker deliberately made unreachable, and confirm the job result is `failure`, never `skipped`/`success`.

## Sleep and Poller Triage (D-13, full enumeration)

All `time.Sleep` calls and ad-hoc pollers across the four e2e test files, read directly this session with exact line numbers:

### `e2e/e2e_test.go` (6 `time.Sleep` calls total — matches CONTEXT.md's count)

| Line | Context | Classification | Action |
|------|---------|-----------------|--------|
| 681 | `TestE2E_WatchSinkHealthKeyedByCN`, poll loop waiting for `snap.States["e2e-test-client"]` to appear, 5s deadline (line 662) | (c) poll interval inside an already-bounded loop | Route through `wait.Until` |
| 746 | `TestE2E_WatchSinkSurvivesServerRestart` step 1, poll loop waiting for the artifact file to first appear, 10s deadline (line 739) | (a) readiness/synchronization | Convert to `wait.Until` |
| **757** | `TestE2E_WatchSinkSurvivesServerRestart` step 3, **300ms fixed hold** while server is down, explicitly commented (lines 750-752: "No wait-for-readiness here: that is exactly what would remove the outage window step 3 asserts against") | **(b) intentional duration-hold** | **KEEP.** MUST NOT convert. D-13 requires an explicit marker comment survive a future sweep — the existing comment already explains why; strengthen it with a literal marker token (e.g. `// SLEEP-INTENTIONAL:` prefix) so a future automated sweep can positively identify it, not just infer intent from prose |
| 769 | `TestE2E_WatchSinkSurvivesServerRestart` step 3 continued, poll loop waiting for `sawFailure`, 10s deadline (line 763) | (a) readiness/synchronization | Convert to `wait.Until` |
| 794 | `TestE2E_WatchSinkSurvivesServerRestart` step 5, poll loop waiting for `sawNewContent`, 15s deadline (line 787) | (a) readiness/synchronization | Convert to `wait.Until` |
| 805 | `TestE2E_WatchSinkSurvivesServerRestart` step 5 continued, poll loop waiting for `failuresCleared`, 10s deadline (line 799) | (a) readiness/synchronization | Convert to `wait.Until` |

### `e2e/docker_e2e_test.go` (1 `time.Sleep` call)

| Line | Context | Classification | Action |
|------|---------|-----------------|--------|
| 276 | `waitForDockerServer`, poll loop dialing the container until Liveness succeeds, 30s deadline (`startupTimeout`, line 24 + 257) | (a)/(c) readiness poller — this whole function is one of the five ad-hoc pollers named in CONTEXT.md | Rewrite `waitForDockerServer` to call `wait.Until` internally instead of hand-rolling the loop |

### `e2e/proc_harness_test.go` (5 `time.Sleep` calls, across 3 named pollers)

| Line | Context | Classification | Action |
|------|---------|-----------------|--------|
| 357 | `waitForProcAddr`, poll loop dialing TCP until connect succeeds, 10s deadline (line 350) | (a)/(c) readiness poller | Rewrite `waitForProcAddr` to call `wait.Until` |
| 504 | `waitForFileContent`, poll loop, error branch (file not yet readable) | (a)/(c) readiness poller | Rewrite `waitForFileContent` to call `wait.Until` |
| 512 | `waitForFileContent`, poll loop, predicate-not-yet-satisfied branch | (a)/(c) readiness poller | Same function, same conversion |
| 542 | `waitForSidecar`, poll loop, error/parse branch | (a)/(c) readiness poller | Rewrite `waitForSidecar` to call `wait.Until` |
| 549 | `waitForSidecar`, poll loop, predicate-not-yet-satisfied branch | (a)/(c) readiness poller | Same function, same conversion |

### `e2e/helpers_test.go` (1 `time.Sleep` call, tagged `e2e || docker_e2e`)

| Line | Context | Classification | Action |
|------|---------|-----------------|--------|
| 216 | `startServer`'s bind-retry loop, `bindRetryDelay = 100 * time.Millisecond` (line 208), retrying `net.Listen` up to `maxBindAttempts = 20` (line 207) | (c) poll interval inside an already-bounded loop — this is a **retry-on-error** loop, not a "wait for a condition to become true" loop in the same shape as the others (it retries the *action* itself, not a passive read) | Route through `wait.Until` if the helper's condition-function shape can express "attempt `net.Listen`, succeed or retry" (e.g. condition function performs the listen attempt and captures the result via closure); otherwise this is the one call site where a thin wrapper around `wait.Until` (or leaving it as a documented exception) may be warranted — **flag for the planner to decide `wait.Until`'s exact signature against this call site specifically**, since it is structurally different from the six "poll a getter until a predicate is true" call sites everywhere else |

### Total conversion count

**5 named ad-hoc pollers to rewrite:** `waitForServer` (helpers_test.go, referenced but not itself a `time.Sleep` site directly — it calls `tls.DialWithDialer` in a loop with `time.Sleep(50*time.Millisecond)` at line 382, not separately tabulated above because it lives inside `helpers_test.go`'s `waitForServer` function, distinct from the bind-retry loop at line 216), `waitForDockerServer`, `waitForProcAddr`, `waitForFileContent`, `waitForSidecar`.

Correction to the above table: `helpers_test.go` actually contains **two** poll loops, not one — the bind-retry loop (line 216, inside `startServer`) and `waitForServer` itself (line 382, its own named poller). Re-verified this session: [VERIFIED: `e2e/helpers_test.go:216` and `:382`, both read directly].

| Line | Context | Classification | Action |
|------|---------|-----------------|--------|
| 382 | `waitForServer`, poll loop dialing TLS until connect succeeds, 10s deadline (line 372) | (a)/(c) readiness poller — the fifth named poller | Rewrite `waitForServer` to call `wait.Until` |

**Grand total: 13 `time.Sleep` call sites** (6 in `e2e_test.go` + 1 in `docker_e2e_test.go` + 5 in `proc_harness_test.go` + 2 in `helpers_test.go` [corrected from 1]), of which **12 convert to `wait.Until`** and **1 (`e2e_test.go:757`) stays as an intentional hold with a strengthened marker comment.**

## `wait.Until` Design Survey

Surveying the five/six existing pollers' shapes to design one signature that absorbs all of them:

| Poller | Deadline shape | Poll interval | Failure mode |
|--------|-----------------|-----------------|----------------|
| `waitForServer` (helpers_test.go:367-385) | `time.Now().Add(10*time.Second)` computed once | `50 * time.Millisecond` | `t.Fatalf("server at %s did not become ready within 10 seconds", addr)` |
| `waitForDockerServer` (docker_e2e_test.go:253-280) | `time.Now().Add(startupTimeout)` (30s) | `500 * time.Millisecond` | `t.Fatalf(...)` **plus** a side effect (dumps container logs) on both the inner "container exited" branch and the final timeout |
| `waitForProcAddr` (proc_harness_test.go:347-360) | `time.Now().Add(10*time.Second)` | `50 * time.Millisecond` | `t.Fatalf("server at %s did not become ready within 10 seconds", addr)` |
| `waitForFileContent` (proc_harness_test.go:494-520) | caller-supplied `deadline time.Duration` parameter | `100 * time.Millisecond` | `t.Fatalf` with **last observed content or last error** interpolated into the message — returns the satisfying content as a value |
| `waitForSidecar` (proc_harness_test.go:525-557) | caller-supplied `deadline time.Duration` parameter | `100 * time.Millisecond` | Same shape as `waitForFileContent`, parses JSON per attempt, returns the satisfying `procSinkStatus` value |
| Inline loop, `TestE2E_WatchSinkHealthKeyedByCN` (e2e_test.go:662-683) | `time.Now().Add(5*time.Second)` | `20 * time.Millisecond` | `require.True(t, found, ...)` after the loop — NOT `t.Fatalf` inside the loop |

**Design implication for `wait.Until`:** two shapes are actually in use — (1) "poll until true, `Fatalf` on timeout, no return value needed" (`waitForServer`, `waitForProcAddr`) and (2) "poll until predicate(value) is true, `Fatalf` with the last-observed value on timeout, RETURN the satisfying value" (`waitForFileContent`, `waitForSidecar`). D-15 mandates `t.Fatalf` on timeout with no silently-droppable return path either way. A generic-friendly signature that covers both:

```go
// Source: designed this session from the survey above, consistent with D-15
package wait

import (
	"testing"
	"time"
)

// Until polls cond every interval until it returns true or timeout elapses.
// On timeout, it calls tb.Fatalf with desc — there is no error return to
// silently ignore (D-15).
func Until(tb testing.TB, timeout, interval time.Duration, desc string, cond func() bool) {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(interval)
	}
	tb.Fatalf("timed out after %s waiting for: %s", timeout, desc)
}

// UntilValue polls fetch every interval until pred(value) is true or timeout
// elapses, returning the satisfying value. On timeout, it calls tb.Fatalf
// with desc and the LAST observed value/error — matching waitForFileContent
// and waitForSidecar's existing "show me what I actually saw" contract.
func UntilValue[T any](tb testing.TB, timeout, interval time.Duration, desc string, fetch func() (T, error), pred func(T) bool) T {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	var last T
	var lastErr error
	for time.Now().Before(deadline) {
		v, err := fetch()
		if err != nil {
			lastErr = err
			time.Sleep(interval)
			continue
		}
		lastErr = nil
		last = v
		if pred(v) {
			return v
		}
		time.Sleep(interval)
	}
	if lastErr != nil {
		tb.Fatalf("timed out after %s waiting for %s; last error: %v", timeout, desc, lastErr)
	} else {
		tb.Fatalf("timed out after %s waiting for %s; last value: %+v", timeout, desc, last)
	}
	var zero T
	return zero
}
```

This is `[ASSUMED]` design (Claude's Discretion per CONTEXT.md — "the exact signature and option surface of `wait.Until` beyond D-15's constraints" is explicitly left open). The two-function split (`Until` / `UntilValue[T]`) is a recommendation, not a locked decision; the planner may collapse to a single generic function if preferred, as long as D-15's constraints (`testing.TB` param, `t.Helper()`, `t.Fatalf` on timeout with a human-readable description, no silently-droppable return) hold for every converted call site. `waitForDockerServer`'s extra side effect (dumping container logs before `t.Fatalf`) does not fit cleanly into either generic shape — the planner should decide whether that log-dump becomes a `desc`-string enrichment (call `docker logs` before constructing the description) or stays as a thin wrapper around `wait.Until` that catches the timeout via a deferred check. Flagging this as an open design point rather than prescribing it, since D-15 doesn't speak to side-effecting failure handlers.

## Common Pitfalls

### Pitfall 1: Treating `[ci skip]` as fully fixable within this repo

**What goes wrong:** A plan task attempts to "strip the `[ci skip]` marker" by editing a file under `.planning/` or `.github/`, but the actual marker lives in the globally-installed GSD tool's `ship.md` template, not in this repo at all.
**Why it happens:** CONTEXT.md's D-05 bundles both fixes together without noting the marker lives outside repo scope.
**How to avoid:** Scope the plan's D-05 task to `workflow_dispatch:` only (a real `.github/workflows/ci-go.yml` change); surface the marker-strip as a note to the user (edit their own `$HOME/.claude/gsd-core/workflows/ship.md`, or file an upstream GSD issue) rather than a repo task.
**Warning signs:** A task whose acceptance criterion is "grep for `[ci skip]` in this repo returns nothing" — that will trivially pass without touching the actual marker, since it was never in this repo.

### Pitfall 2: `t.Skip` silently reporting green when Docker/binary preconditions aren't met

**What goes wrong:** CI-04 exists precisely because `docker_e2e_test.go:139-145`'s `t.Skip` calls currently make "no Docker on this runner" indistinguishable from "Docker tests passed." A conversion to `RH_E2E_REQUIRE_DOCKER` that isn't actually **set in the CI job's `env:`** silently preserves the old skip-as-success behavior.
**Why it happens:** The env var must be set in the `e2e-docker` job specifically — it's easy to add the code branch but forget the job-level `env:` block, or to typo the variable name between the Go code and the workflow YAML.
**How to avoid:** D-10's fourth negative control (this research's addition) exists specifically to catch this — deliberately make Docker unavailable with the env var set and confirm the job fails, not skips.
**Warning signs:** `e2e-docker` reporting `success` in a run log that also shows "docker not found" or "docker daemon not running" in its output.

### Pitfall 3: Converting `e2e_test.go:757`'s intentional sleep by pattern-matching on "this is inside a loop"

**What goes wrong:** Line 757's `time.Sleep(300 * time.Millisecond)` sits between two poll-loop conversions (line 746 above it, line 769 below it) in the same test function. A mechanical "convert every `time.Sleep` in this file" pass would catch it too.
**Why it happens:** It's visually surrounded by call sites that DO convert, and it's the same syntactic shape (`time.Sleep(duration)`) as the ones that do.
**How to avoid:** D-13 already names this exact line as the one exception. The plan's conversion task should explicitly enumerate all 13 sites (this research's table) rather than grep-and-convert-everything, and the line-757 sleep should gain a stronger marker (e.g. a `SLEEP-INTENTIONAL:` comment prefix) precisely so a future mechanical pass doesn't repeat this mistake.
**Warning signs:** `TestE2E_WatchSinkSurvivesServerRestart`'s step-3 outage-window assertion (comparing `initialBytes` to `stillBytes`) becomes vacuously true because the "wait" that used to hold the window open now returns as soon as some unrelated condition is met.

### Pitfall 4: `bin/` bind-retry loop (helpers_test.go:216) not fitting `wait.Until`'s "poll a getter" shape

**What goes wrong:** Naively forcing this call site into `wait.Until(tb, ..., func() bool { ... })` requires the condition closure to perform the actual `net.Listen` attempt and mutate `lis`/`err` via closure capture — this works but is a different idiom (retry-an-action vs. poll-a-getter) from every other call site, and a signature designed only around the six "poll-a-getter" sites may not compose cleanly here.
**Why it happens:** This is the ONE call site (of 13) that is structurally a retry-on-error loop rather than a wait-for-a-condition loop.
**How to avoid:** Flagged explicitly above in the Sleep Triage table — the planner should decide during plan-writing whether `wait.Until`'s condition-function signature accommodates this via closure capture (likely fine) or whether this site is a documented, justified exception.
**Warning signs:** A `wait.Until` call at this site that returns `true`/`false` without ever assigning the actual listener — silently discarding the bind result the way a naive refactor might.

## Code Examples

### Namespace's warning against adding a Docker setup action

```text
# Source: https://namespace.so/docs/solutions/github-actions/docker-builds (fetched this session)
"No configuration changes required."
"No docker/setup-buildx-action or docker/setup-qemu-action required!"
[Running docker/setup-buildx-action will overwrite the default configuration
 and prevent you from using Remote Builders.]
```

### `nscloud-cache-action`'s cache scope

```text
# Source: Namespace docs for nscloud-cache-action (fetched this session)
`cache: go` stores GOCACHE and GOMODCACHE on the attached Cache Volume.
Does not restore or persist project-specific output directories (e.g. bin/).
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|-------------------|----------------|--------|
| `docker_e2e` `t.Skip`s when Docker unavailable | Env-gated hard-fail via `RH_E2E_REQUIRE_DOCKER` | This phase (CI-04) | A green `e2e-docker` job now unconditionally means the Docker tests actually ran |
| Five separate hand-rolled polling loops | One shared `internal/testutil/wait` package | This phase (VRFY-05) | Anti-flake timeout/backoff logic lives in one place; future test files (including Phase 3's harness) reuse it rather than writing a sixth copy |
| `proc_e2e`/`docker_e2e` never run in CI | Both run on every PR as required gates | This phase (CI-01/02) | The G-01-1-class defect class (CLI-flag→config seam) that shipped past `e2e`/`docker_e2e` in v0.13.0 now has a dedicated, required gate |

**Deprecated/outdated:** the "wiring for CI deferred as GitHub issue #403" state [VERIFIED: STATE.md line 174 — "01-11: CI wiring for all three e2e tiers deferred; tracked as GitHub issue #403"] is what this phase closes.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|-----------------|
| A1 | Runner profile size `namespace-profile-linux-amd64-4x8` is adequate for all three new jobs | Q-01 / Standard Stack | Under-provisioning would show up as slow or OOM-killed jobs on first real CI run; trivially fixed by bumping the profile — not a correctness risk |
| A2 | `wait.Until`/`UntilValue[T]`'s exact two-function split is the right shape | `wait.Until` Design Survey | The planner may choose a different signature; D-15's hard constraints (`testing.TB`, `t.Helper()`, `t.Fatalf`, no droppable return) are what actually matter and are independently verified against all 13 call sites |
| A3 | `helpers_test.go:216`'s bind-retry loop can be expressed through the same `wait.Until` condition-function shape as the other 12 sites via closure capture | Sleep Triage, Pitfall 4 | If it can't compose cleanly, this one site may need to stay a documented exception rather than route through the helper — does not block VRFY-05's substance for the other 12 sites |
| A4 | Namespace's Remote Builder cache persists usefully across ephemeral CI runners for the `e2e-docker` job's `docker build` step (affecting Q-03's cost estimate) | Q-03 | If it does NOT persist well, `e2e-docker`'s real CI duration could be meaningfully higher than the ~40-60s local proxy; only resolvable by observing the first real CI runs (which D-09's red-proof PRs will produce regardless) |

**If this table is empty:** N/A — see above.

## Open Questions

All three CONTEXT.md-assigned open questions (Q-01, Q-02, Q-03) are resolved above with evidence. Two smaller open points remain for the planner:

1. **How does `wait.Until` accommodate `helpers_test.go:216`'s retry-on-error shape?**
   - What we know: 12 of 13 call sites are "poll a getter until a predicate holds" and compose cleanly with the proposed signatures.
   - What's unclear: whether the 13th (bind-retry) site should route through the same helper via closure capture, or stay a documented, justified exception.
   - Recommendation: attempt the closure-capture conversion first; if it reads awkwardly, document the exception rather than force it — D-13 only requires poll-intervals-inside-bounded-loops to route through the helper, and this is arguably a "retry an action," not a "poll a getter," which is a defensible boundary to draw.

2. **Does `waitForDockerServer`'s container-log-dump-on-failure side effect fit inside `wait.Until`, or does it need a thin wrapper?**
   - What we know: the existing function dumps `docker logs` both on "container exited early" and on final timeout, which `wait.Until`'s generic timeout message doesn't natively support.
   - What's unclear: whether this is worth a `wait.Until` option/hook, or should stay as a thin wrapper function in `docker_e2e_test.go` that calls `wait.Until` for the polling and separately handles the log dump.
   - Recommendation: keep it simple — a thin wrapper in `docker_e2e_test.go` that calls `wait.Until` for the core poll and does its own `docker logs` dump before re-raising via `t.Fatalf` (or by including the logs in `desc`) is consistent with D-15 without over-engineering the shared helper's interface for one caller's side effect.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|--------------|-----------|---------|----------|
| Docker (local, for this research's timing checks) | Local proxy timing of `docker_e2e` tier | ✓ | Docker Desktop, confirmed via `docker info` this session | — |
| Namespace-hosted CI runners | All new jobs in production | Not independently verifiable from this environment — relies on Namespace's own documentation | — | None needed — Q-01's finding is that no fallback/setup action is required |
| `gh` CLI | Sampling CI run history, ruleset inspection | ✓ | used this session (`gh run list`, `gh run view`, `gh api`, `gh pr list/view`) | — |
| `golangci-lint` | Empirical Q-02 check | ✓ | ran this session against live `.golangci.yml` | — |

**Missing dependencies with no fallback:** none.

**Missing dependencies with fallback:** none — this phase's environment dependencies are all either already present in CI (Namespace, Docker) or already verified working locally.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Go stdlib `testing` (`go test`), build-tag-gated tiers |
| Config file | none — behavior is driven entirely by `Taskfile.yml`'s `test:e2e*` targets and `go test -tags <tag>` |
| Quick run command | `task test:e2e` (in-process, ~5s) |
| Full suite command | `task test:e2e && task test:e2e:docker && task test:e2e:proc` (all three tiers, sequential locally; parallel in CI as separate jobs) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|---------------|
| CI-01 | All three tiers run as CI jobs; aggregate fails if any fails | CI integration (workflow-level) | Push a scratch-branch PR observing all 10 jobs + `ci-go-complete` in the Actions UI; no local `go test` equivalent exists for "does the YAML wire correctly" | ❌ — requires a real PR run, not a local test file |
| CI-02 | Fast tier gates every PR; container/proc gate merge (collapsed to PR-time per D-03) | CI integration | Same PR observation as CI-01 — `protect-main`'s required-check evaluation is a GitHub-side behavior, not locally testable | ❌ |
| CI-03 | Each gate demonstrated red | Manual/scripted red-proof (throwaway PR per D-09) | Apply one of the three regressions above on a scratch branch, open a PR, observe the specific job (and only that job) go red, capture the run URL | ❌ — by design, this is a one-time demonstration, not a standing automated test |
| CI-04 | Docker tier hard-fails (not skips) without Docker; `proc_e2e` fresh-builds | unit (Go) + CI integration | `go test -tags docker_e2e -run TestRequireDocker ./e2e/` (new small unit test recommended, see Wave 0 Gaps) for the code-level branch; the "doesn't restore `bin/` from cache" half needs the fourth negative control (D-10) on a scratch-branch PR | Partial — `requireDocker`'s branch logic itself has no dedicated unit test today |
| VRFY-05 | Shared bounded-timeout helper, no fixed readiness sleeps, `t.Fatalf` on timeout | unit (Go) | `go test ./internal/testutil/wait/...` (new package's own tests: timeout path fires `t.Fatalf` with the description, success path returns without calling `Fatalf`) | ❌ Wave 0 — package doesn't exist yet |

### Sampling Rate

- **Per task commit:** `task test:e2e` (fast, in-process — cheapest signal for wiring changes) plus `golangci-lint run ./...` for any new/modified Go file
- **Per wave merge:** `task ci` (lint + test) locally; the three new CI jobs themselves only get exercised for real once pushed to a PR — this phase's own verification loop should include at least one intermediate scratch-branch push before the final red-proof PRs, to catch YAML syntax errors cheaply
- **Phase gate:** All four red-proof throwaway PRs (D-09/D-10) captured with run URLs, plus a final "everything green" PR run before merge

### Wave 0 Gaps

- [ ] `internal/testutil/wait/wait.go` + `internal/testutil/wait/wait_test.go` — the package does not exist yet; needs unit tests for both the timeout-fires-`t.Fatalf` path and the success-returns-cleanly path (using a fake `testing.TB` or a sub-test's own `t` with `t.Run` + checking for the expected failure via a recover/mock pattern, since `t.Fatalf` calls `runtime.Goexit()` and can't be asserted via ordinary `require`)
- [ ] A small unit test for `requireDocker`'s env-gated branch logic (`RH_E2E_REQUIRE_DOCKER` set vs. unset, Docker present vs. absent) — today this logic has zero test coverage of its own; the code lives inside `//go:build docker_e2e`, so this test would need the same tag, or the branch logic could be extracted to a small testable helper function importable without the build tag
- [ ] Framework install: none — `go test` and `task` are already fully wired; no new test framework needed

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|-----------------|---------|---------------------|
| V2 Authentication | No | This phase touches no auth code paths — the `e2e`-unique red proof deliberately targets `peercn.go`'s CN extraction, but only as a THROWAWAY regression on a scratch branch never merged, not a shipped change |
| V3 Session Management | No | N/A |
| V4 Access Control | No | N/A |
| V5 Input Validation | No | No new input-handling code — CI YAML and a Go stdlib-only test helper |
| V6 Cryptography | No | No cryptographic code touched |

### Known Threat Patterns for CI/CD wiring

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|------------------------|
| A required check silently reporting `skipped` as if it were `success` | Tampering (of the trust signal, not data) | D-02's `!= "success"` comparison already treats `skipped`/`cancelled` as failing — verified this is preserved for all 10 jobs in the extended `ci-go-complete` script |
| `t.Skip` masking a missing precondition as a passing test (CI-04's whole motivation) | Repudiation (a green run that didn't actually test what it claims to) | `RH_E2E_REQUIRE_DOCKER` env-gated hard-fail (D-06), proven by the fourth negative control (D-10) |
| A throwaway red-proof regression accidentally landing on `main` | Tampering | D-09 mandates throwaway PRs from scratch branches, closed without merging — the plan should make this an explicit, checked step, not an implicit assumption |
| CI YAML pinned-SHA actions drifting to an unpinned/mutable ref when copy-pasting the new job blocks | Tampering (supply chain) | Copy the exact pinned SHAs already used in the `test` job skeleton (`actions/checkout@3d3c42e...`, `actions/setup-go@b7ad1dad...`, `nscloud-cache-action@c5f8dab7...`) rather than re-resolving `@v7`/`@v1` tags |

## Sources

### Primary (HIGH confidence — verified this session by reading repo files or running commands)

- `.github/workflows/ci-go.yml` — full file read; job skeletons, `ci-go-complete` aggregator pattern
- `Taskfile.yml` — `test:e2e`, `test:e2e:docker`, `test:e2e:proc` targets and their `deps`
- `.golangci.yml` — live lint config used for the Q-02 empirical check
- `e2e/e2e_test.go`, `e2e/docker_e2e_test.go`, `e2e/proc_harness_test.go`, `e2e/proc_e2e_test.go`, `e2e/helpers_test.go` — full files read; every sleep/poller site and every red-proof test enumerated by line number
- `internal/config/client.go`, `internal/client/commands/connect.go` — G-01-1's fix location, confirmed
- `internal/server/peercn.go` — CN-extraction code for the `e2e`-unique red proof
- `Dockerfile` — operator-binary COPY line for the `docker_e2e`-unique red proof
- `internal/storage/storagetest/suite.go` — Q-02's in-repo precedent
- `gh api repos/fzymgc-house/router-hosts/rulesets/10601376` — live `protect-main` ruleset confirming required contexts, squash-only merges, no merge-queue rule
- `gh run list` / `gh run view` — 15 sampled PR run durations, 2 detailed per-job breakdowns
- `.planning/milestones/v0.13.0-phases/01-consumer-rendered-output-templates-sink/01-10-SUMMARY.md` — G-01-1's original fix and pre-fix RED evidence
- `$HOME/.claude/gsd-core/workflows/ship.md:453-457` — the `[ci skip]` marker's actual location, confirming it is outside this repo

### Secondary (MEDIUM confidence — official vendor docs, fetched but not independently reproduced on Namespace's infra)

- `https://namespace.so/docs/solutions/github-actions/docker-builds` — Docker daemon availability, `docker/setup-buildx-action` warning
- `https://namespace.so/docs/reference/github-actions/runner-configuration` — profile naming/sizing
- `https://namespace.so/docs/reference/github-actions/nscloud-cache-action` — cache scope (`GOCACHE`/`GOMODCACHE` only)
- GitHub Docs on required status checks evaluating against the latest commit SHA (general `workflow_dispatch` recovery-path reasoning for D-05's first half)

### Tertiary (LOW confidence — local extrapolation, not CI-measured)

- Local timing proxies for `e2e`, `docker_e2e`, `proc_e2e` tiers (Q-03) — run on this development machine's Docker Desktop, not Namespace's infrastructure; presented explicitly as order-of-magnitude signal only

## Metadata

**Confidence breakdown:**

- Standard stack / CI mechanics: HIGH — every claim about the existing workflow, ruleset, and test files was verified by reading the actual file or running the actual command this session
- Docker-on-Namespace (Q-01): MEDIUM — sourced from Namespace's own official docs (CITED), not independently reproduced by actually running a job on their infrastructure in this session
- Q-02 (`testing` import safety): HIGH — directly empirically verified against this exact module's lint config and dependency graph, with an existing in-repo precedent
- Q-03 (CI-minute cost): LOW — extrapolated from local timing, since none of the three new tiers has ever executed inside this repo's real CI environment
- Red-proof regression selection: HIGH — each regression's tier-uniqueness was verified by tracing which specific test file/assertion exercises the affected code path and confirming the other two tiers' test files contain no equivalent exercise

**Research date:** 2026-08-02
**Valid until:** ~2026-09-01 (30 days — GitHub Actions/Namespace infra and this repo's own CI config are the primary time-sensitive inputs; the code-level findings, e.g. G-01-1's fix location and the sleep/poller enumeration, are stable until the next phase touches these files)
</content>
