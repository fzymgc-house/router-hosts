---
phase: 01-ci-gating-for-the-e2e-tiers
verified: 2026-08-03T21:00:00Z
status: passed
score: 8/8 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification: no
---

# Phase 01: CI Gating for the E2E Tiers — Verification Report

**Phase Goal:** "A change cannot reach `main` without all three e2e tiers having actually run against it — and each gate has been watched going red, so 'never observed to fail' is ruled out."
**Verified:** 2026-08-03T21:00:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | All three e2e tiers (`e2e-fast`, `e2e-docker`, `e2e-proc`) exist as CI jobs, each bind a distinct `*_RESULT` env var, and are compared `!= "success"` | ✓ VERIFIED | Read `.github/workflows/ci-go.yml`: three jobs present; `ci-go-complete.needs` = `[lint, vuln, test, build, buf-check, manifests, docs, e2e-fast, e2e-docker, e2e-proc]`; ten distinct `*_RESULT` env bindings; run script contains exactly 10 `!= "success"` clauses and 0 `== "failure"` clauses (counted directly) |
| 2 | The required-check name is exactly `CI (Go) Complete`, `on:` is exactly `pull_request` + `workflow_dispatch`, no paths filter | ✓ VERIFIED | `ci-go.yml` lines 1-5, 200-201 read directly: `name: CI (Go) Complete`, `on: {pull_request: {branches:[main]}, workflow_dispatch:}`, no `paths`/`paths-ignore` key anywhere in the file (`rg -n 'bin/'`/manual read confirm no filter block) |
| 3 | `internal/ciwiring`'s invariant test asserts genuine set-equality (not count) between top-level `e2e-*` jobs and the aggregator's needs/env/result-check wiring | ✓ VERIFIED | Read `internal/ciwiring/ciwiring_test.go` in full: sorted-joined-string comparison (`strings.Join(declaredTiers,",") != strings.Join(wiredTiers,",")`), zero `len(` calls used for equality, `go test ./internal/ciwiring/...` passes locally |
| 4 | Four negative controls (CI-03) are evidenced with real GitHub Actions run URLs, each showing the target job = failure and the other two e2e jobs = success | ✓ VERIFIED | Spot-checked 2 of 4 via `gh run view --json jobs` directly (not trusting SUMMARY text): run 30828580687 (PR #415, control 1) — `E2E (fast)=failure`, `E2E (docker)=success`, `E2E (proc)=success`, all 7 pre-existing jobs=success, `CI (Go) Complete=failure`; run 30819896321 (PR #413, control 4) — `E2E (docker)=failure`, `E2E (fast)=success`, `E2E (proc)=success`, `CI (Go) Complete=failure`. Both match 01-05-SUMMARY.md's claims exactly. |
| 5 | `RH_E2E_REQUIRE_DOCKER` is set at job level in `ci-go.yml`, spelling matches `dockergate.EnvVar` exactly; `e2e-proc` removes `bin/` before `task test:e2e:proc`; no job restores `bin/` from cache | ✓ VERIFIED | `ci-go.yml`'s `e2e-docker.env.RH_E2E_REQUIRE_DOCKER: "1"` byte-matches `internal/testutil/dockergate/dockergate.go`'s `const EnvVar = "RH_E2E_REQUIRE_DOCKER"`; `rm -rf bin/` step precedes `task test:e2e:proc` step (lines 191-199); `rg -n 'bin/' .github/workflows/ci-go.yml` returns only the `rm -rf bin/` step and its comment — no cache path references `bin/` |
| 6 | The shared `wait` helper is genuinely reused by `e2e`, `docker_e2e`, and `proc_e2e` tiers; no readiness poll retains a sentinel-bool + require.True fallthrough | ✓ VERIFIED | `rg -n 'internal/testutil/wait' e2e/*.go` shows imports in all four files (`e2e_test.go`, `helpers_test.go`, `docker_e2e_test.go`, `proc_harness_test.go`) covering all three build tags (`e2e`, `docker_e2e`, `proc_e2e`); `rg` for `require.True(t, (found\|sawFailure\|sawNewContent\|failuresCleared)` returns no matches anywhere in `e2e/*.go` |
| 7 | D-16 structural gate: across all four `e2e/*.go` files, every `time.Sleep` is preceded within three lines by a `SLEEP-INTENTIONAL:` marker, verified by adjacency | ✓ VERIFIED | Ran the exact adjacency awk gate directly (not the SUMMARY's claim): exits 0, prints nothing. Independently confirmed only one `time.Sleep` remains repo-wide in `e2e/*.go` (`e2e_test.go:757`, the deliberate 300ms outage hold), immediately preceded by a `SLEEP-INTENTIONAL:` comment |
| 8 | The docker cert-permission fix (790befc) confines the `0o644` relaxation to `docker_e2e` call sites; the `e2e` tier still writes `0o600` | ✓ VERIFIED | `git show 790befc` and direct `rg` of current call sites: `e2e/docker_e2e_test.go`'s three `writePEM(...)` calls pass `0o644`; `e2e/helpers_test.go`'s five `writePEM(...)` calls pass `0o600` |

**Score:** 8/8 truths verified (0 present, behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/testutil/wait/wait.go` | Bounded-timeout helper, no droppable error return | ✓ VERIFIED | Read in full: `Until`/`UntilValue[T]`, both call `tb.Helper()` first, evaluate at least once before deadline check, report only via `tb.Fatalf`, no `error` return type on either function |
| `internal/testutil/dockergate/dockergate.go` | Tag-free, pure `Decide` function | ✓ VERIFIED | Read in full: no `testing` import, no `os` import, `Decide(envValue string, probeErr error) Action` matches spec exactly (Fatal iff non-empty envValue + non-nil probeErr) |
| `internal/ciwiring/ciwiring_test.go` | Set-equality aggregator invariant | ✓ VERIFIED | Read in full; `go test ./internal/ciwiring/...` passes against the live workflow file |
| `.github/workflows/ci-go.yml` | Three e2e jobs, extended aggregator, workflow_dispatch trigger | ✓ VERIFIED | Read in full; `actionlint` exits 0 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `e2e-docker.env.RH_E2E_REQUIRE_DOCKER` | `dockergate.EnvVar` | literal string match | ✓ WIRED | Both sides read `"RH_E2E_REQUIRE_DOCKER"` — confirmed by direct read of both files |
| Each `e2e-*` job | `ci-go-complete.needs`/env/result-check | `internal/ciwiring` invariant | ✓ WIRED | Test passes against live file; manually re-derived the set-equality by reading `ci-go.yml` directly |
| `e2e/*.go` (all 4 build tags) | `internal/testutil/wait` | import | ✓ WIRED | All four files import the package |
| `protect-main` ruleset | `CI (Go) Complete` context | required status check | ✓ WIRED | `gh api .../rulesets/10601376` confirms required contexts are exactly `CI (Go) Complete, Vulnerability check` — unchanged, read-only check |

### Behavioral Spot-Checks / Probe Execution

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| ciwiring invariant test passes | `go test ./internal/ciwiring/...` | `ok` | ✓ PASS |
| dockergate/wait unit tests pass | `go test ./internal/testutil/...` | `ok` (both packages) | ✓ PASS |
| Workflow YAML is syntactically/semantically valid | `actionlint .github/workflows/ci-go.yml` | exit 0, no output | ✓ PASS |
| D-16 structural adjacency gate | `awk ... e2e/*.go` | exit 0, no output | ✓ PASS |
| Repo builds | `go build ./...` | success | ✓ PASS |
| `testutil/wait`/`testutil/dockergate` never reach shipped binaries | `go list -deps ./cmd/{router-hosts,operator}/...` piped to `rg` | no match (both) | ✓ PASS |
| CI-03 negative control 1 (spot-check, not trusting SUMMARY) | `gh run view 30828580687 --json jobs` | `E2E (fast)=failure`, others `success`, `CI (Go) Complete=failure` | ✓ PASS |
| CI-03 negative control 4 (spot-check, not trusting SUMMARY) | `gh run view 30819896321 --json jobs` | `E2E (docker)=failure`, others `success`, `CI (Go) Complete=failure` | ✓ PASS |
| All four throwaway PRs closed, unmerged | `gh pr view {412,413,415,416} --json state,mergedAt` | all `CLOSED`/`null` | ✓ PASS |
| No scratch branches remain | `git ls-remote --heads origin 'rp/*'`, `git branch -a \| rg rp/` | empty | ✓ PASS |
| No red-proof commit reached the phase branch | `git log --oneline main..HEAD \| rg 'red proof'` | empty | ✓ PASS |
| Both follow-up GitHub issues exist and are open | `gh issue view {417,418} --json state` | both `OPEN` | ✓ PASS |
| `protect-main` ruleset untouched | `gh api .../rulesets/10601376` | `CI (Go) Complete,Vulnerability check` | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|--------------|--------|----------|
| CI-01 | 01-01, 01-04 | All three e2e tiers run as CI jobs; single aggregated required check | ✓ SATISFIED | `ci-go.yml` + `internal/ciwiring` invariant, verified directly |
| CI-02 | 01-01, 01-04 | Fast tier gates every PR; container/process tiers gate merge (collapsed to single-stage per D-03, documented deviation) | ✓ SATISFIED | All three tiers run at PR time via the same required aggregate; D-03's single-stage rationale is recorded in 01-04-PLAN.md's `<ci_02_note>` and matches the live `on:` block |
| CI-03 | 01-05 | Each gate demonstrated red against a reintroduced regression before acceptance | ✓ SATISFIED | 4 negative controls, 2 independently spot-checked via `gh run view` (not SUMMARY text) |
| CI-04 | 01-03, 01-04 | Container tiers hard-fail (not skip) when Docker unavailable; `proc_e2e` builds fresh in-job | ✓ SATISFIED | `dockergate.Decide` + `RH_E2E_REQUIRE_DOCKER` env wire; `rm -rf bin/` step ordered before `task test:e2e:proc` |
| VRFY-05 | 01-01, 01-02, 01-03 | Shared wait-strategy helper reused by `docker_e2e`, `proc_e2e`, and the harness | ✓ SATISFIED | `internal/testutil/wait` imported by all four `e2e/*.go` files across all three build tags |

No orphaned requirements: `.planning/REQUIREMENTS.md`'s traceability table maps exactly these five IDs to v0.14.0 Phase 1, matching the five IDs declared across the five plans' frontmatter.

### Anti-Patterns Found

None blocking. `rg` for `TODO|FIXME|XXX|HACK|PLACEHOLDER` across the phase's changed files returns no matches. No `//nolint` directives added. No debt markers.

One pre-existing structural robustness gap noted in code review (WR-01, `internal/ciwiring/ciwiring_test.go`): the invariant filters both sides of its set-equality comparison through the same `^e2e-` regex, so a job that abandons the `e2e-` naming convention entirely would be invisible to the invariant on both sides simultaneously. Confirmed present in the current code — this is a genuine latent gap, but per the phase's own scope (the three real tiers `e2e-fast`/`e2e-docker`/`e2e-proc` are all correctly prefixed and fully wired today) it does not affect present-day goal achievement. Recorded here as a WARNING, not a BLOCKER, matching the code review's own disposition and the reviewer's explicit note not to treat it as blocking this phase.

### Known Non-Defects (excluded from gaps per verification instructions)

- REQUIREMENTS.md's traceability table (lines 171-179) reads `Pending` while the corresponding checkboxes read `[x]` — a known `table_unmatched` tool gap, not a phase defect. Not hand-edited.
- Two GitHub issues (#417 cert defect, #418 upstream `[ci skip]`) are deliberate open follow-ups, not gaps.
- The phase branch is not pushed and has no PR — that is `/gsd-ship`'s job.

## Gaps Summary

None. All eight derived must-have truths verified directly against the live codebase and, where evidentiary (CI-03's negative controls, the protect-main ruleset state), against live GitHub API/Actions data rather than SUMMARY.md claims. The phase goal — a change cannot reach `main` without all three e2e tiers having actually run against it, with each gate having been observed going red — is achieved.

---
_Verified: 2026-08-03T21:00:00Z_
_Verifier: Claude (gsd-verifier)_
