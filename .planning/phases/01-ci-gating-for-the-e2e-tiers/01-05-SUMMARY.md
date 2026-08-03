---
phase: 01-ci-gating-for-the-e2e-tiers
plan: 05
subsystem: testing
tags: [ci, e2e, docker, negative-controls, gosec, distroless]

requires:
  - phase: 01-ci-gating-for-the-e2e-tiers
    provides: "plan 01-04's ci-go.yml with e2e-fast/e2e-docker/e2e-proc jobs and the extended CI (Go) Complete aggregator"
provides:
  - "A permanent fix for the e2e-docker CI job's cert-permission failure (blocking every merge to main)"
  - "Four CI-03 negative controls, each captured as a closed/unmerged throwaway PR"
  - "A recorded developer decision on D-05's out-of-repo [ci skip] half"
  - "Two GitHub issues tracking the cert-permission defect and the D-05 upstream follow-up"
affects: [ci-gating, e2e-tiers]

actuals:
  tokens: 4200
  tasks: 4
  commits: 3

tech-stack:
  added: []
  patterns:
    - "writePEM(t, dir, name, data, mode) — explicit per-tier file mode instead of a single hardcoded constant, so a shared test helper can serve both an in-process reader and a container with a different UID"

key-files:
  created: []
  modified:
    - "e2e/helpers_test.go — writePEM gained a mode parameter; in-process e2e call sites pass 0o600"
    - "e2e/docker_e2e_test.go — docker_e2e call sites pass 0o644 so UID 65532 can read bind-mounted certs"

key-decisions:
  - "Cert-permission fix: change file mode only (0o600 -> 0o644 for docker_e2e's writePEM callers), not directory mode, container --user, or a baked-in test image. Individual files are bind-mounted (not the containing t.TempDir()), so Docker mounts each file's own inode directly at its container target path; the container's own /certs directory is auto-created by dockerd with normal traversable permissions. The host tmpDir's 0o700 mode (from testing.T.TempDir()) is therefore irrelevant to container-side access — only the file's own permission bits matter, since its owning UID (the CI runner) never matches the container's UID 65532."
  - "D-05 out-of-repo disposition: file-issue-only (issue #418). The workflow_dispatch half already shipped in plan 01-01; the [ci skip] marker lives in the globally-installed GSD runtime, which no agent working in this repo may edit."
  - "Control 1 (e2e tier) and Control 3 (proc_e2e tier) used simpler regressions than 01-05-PLAN.md's originally proposed candidates (a CN-blanking change in watch.go, and deleting connect.go's --config override), substituted during a prior session after PR #414 established CI-level tier-uniqueness for a service.go Trigger-string regression. Both substitute regressions were re-verified locally (full five-cell matrix) and in real CI before acceptance, satisfying D-11's tier-uniqueness bar the same as the plan's original candidates would have."

requirements-completed: [CI-03]

coverage:
  - id: D1
    description: "e2e-docker CI job's cert-permission failure is fixed: docker-mounted throwaway mTLS certs are now readable by the distroless nonroot image's UID 65532, verified by a real CI run (not just local Docker Desktop, which masks the UID-mismatch defect)"
    requirement: "CI-03"
    verification:
      - kind: e2e
        ref: "PR #415 run https://github.com/fzymgc-house/router-hosts/actions/runs/30828580687 — E2E (docker) concluded success with the fix present"
      - kind: e2e
        ref: "PR #416 run https://github.com/fzymgc-house/router-hosts/actions/runs/30829014408 — E2E (docker) again concluded success"
    human_judgment: true
    rationale: "The fix's correctness depends on real Linux UID semantics that this session's local macOS Docker Desktop verification cannot exercise (Docker Desktop's VM masks the UID mismatch); a human should confirm the linked CI run logs and conclusions rather than trust local-green alone."
  - id: D2
    description: "Negative control 1 (e2e tier): a regression only the e2e tier catches (internal/server/service.go's pre-rollback Trigger string), captured as a closed/unmerged throwaway PR with the target job red and both other e2e jobs green"
    requirement: "CI-03"
    verification:
      - kind: e2e
        ref: "PR #415 (closed, unmerged) run https://github.com/fzymgc-house/router-hosts/actions/runs/30828580687 — E2E (fast)=failure (TestE2E_RollbackCreatesBackup only), E2E (docker)=success, E2E (proc)=success, all 7 pre-existing jobs=success, CI (Go) Complete=failure"
    human_judgment: true
    rationale: "D-11's tier-uniqueness claim and D-09's teardown-without-merge claim are evidentiary assertions about a live CI run and repository state; per D-12 a human confirms them rather than an agent self-certifying its own negative control."
  - id: D3
    description: "Negative control 2 (docker_e2e tier): missing operator binary in the built image, captured as a closed/unmerged throwaway PR with only E2E (docker) red"
    requirement: "CI-03"
    verification:
      - kind: e2e
        ref: "PR #412 (closed, unmerged) run https://github.com/fzymgc-house/router-hosts/actions/runs/30818557788 — E2E (docker)=failure, E2E (fast)=success, E2E (proc)=success, all 7 pre-existing jobs=success, CI (Go) Complete=failure"
    human_judgment: true
    rationale: "Captured in a prior session; carried forward here as part of this plan's four-control acceptance criteria and re-confirmed via gh run view during this session."
  - id: D4
    description: "Negative control 3 (proc_e2e tier): a reintroduced G-01-1-shaped regression (main.go's error-path os.Exit(1) -> os.Exit(0)), captured as a closed/unmerged throwaway PR with only E2E (proc) red"
    requirement: "CI-03"
    verification:
      - kind: e2e
        ref: "PR #416 (closed, unmerged) run https://github.com/fzymgc-house/router-hosts/actions/runs/30829014408 — E2E (proc)=failure (TestProcE2E_MissingExplicitConfigFailsLoudly), E2E (fast)=success, E2E (docker)=success, all 7 pre-existing jobs=success, CI (Go) Complete=failure"
    human_judgment: true
    rationale: "Same as D2/D3 — a live CI conclusion and repo-state claim that D-12 routes through human confirmation, not agent self-certification."
  - id: D5
    description: "Negative control 4 (D-10, docker-unavailable): e2e-docker fails rather than skips when Docker is made unreachable with RH_E2E_REQUIRE_DOCKER set, captured as a closed/unmerged throwaway PR"
    requirement: "CI-03"
    verification:
      - kind: e2e
        ref: "PR #413 (closed, unmerged) run https://github.com/fzymgc-house/router-hosts/actions/runs/30819896321 — E2E (docker)=failure with RH_E2E_REQUIRE_DOCKER in the log (no skip-as-success), CI (Go) Complete=failure"
    human_judgment: true
    rationale: "Captured in a prior session; carried forward here and re-confirmed via gh run view during this session."
  - id: D6
    description: "All four throwaway PRs (#412, #413, #415, #416) are closed and unmerged, and no scratch rp/* branch remains locally or on origin"
    verification:
      - kind: other
        ref: "gh pr view {412,413,415,416} --json state,mergedAt all report CLOSED/null; git ls-remote --heads origin 'rp/*' returns empty; git branch -a has no rp/* entries"
        status: pass
    human_judgment: false
  - id: D7
    description: "D-05's out-of-repo [ci skip] follow-up and the cert-permission defect from job 1 each have a tracked GitHub issue"
    verification:
      - kind: other
        ref: "gh issue view 417 (cert-permission defect), gh issue view 418 (D-05 upstream follow-up) both exist and are OPEN"
        status: pass
    human_judgment: false

duration: 55min
completed: 2026-08-03
status: complete
---

# Phase 1 Plan 5: CI-03 Negative Controls, plus the Cert-Permission Fix That Blocked Them Summary

**Fixed a real CI-blocking defect (docker-mounted mTLS certs unreadable by the distroless nonroot UID), then captured all four CI-03 negative controls as closed/unmerged throwaway PRs — every one of the three e2e tiers has now been observed failing in real CI, and so has the Docker-unavailable hard-fail wire.**

## Performance

- **Duration:** 55 min
- **Completed:** 2026-08-03
- **Tasks:** 4 (fix the blocking defect; capture Control 1 e2e tier; capture Control 3 proc_e2e tier; record evidence + D-05 decision + issues)
- **Files modified:** 2 (`e2e/helpers_test.go`, `e2e/docker_e2e_test.go`) on the phase branch; `internal/server/service.go` and `cmd/router-hosts/main.go` only on throwaway branches, both deleted

## Accomplishments

- Fixed the `e2e-docker` CI job's cert-permission failure, which had never once passed in CI and would have blocked every merge to `main` once plan 01-04's gate landed. Root cause: `writePEM` wrote throwaway mTLS certs at `0o600`, owned by the CI runner's UID; the `docker_e2e` tier bind-mounts those files into `gcr.io/distroless/static:nonroot`, which runs as UID 65532 — a UID that never matches the runner's UID. `writePEM` now takes an explicit `mode` parameter: the in-process `e2e` tier keeps `0o600` (same process reads what it writes), the `docker_e2e` tier now writes `0o644`.
- Verified the fix in real CI, not just locally: PR #415's run (`E2E (docker)` = `success`) and PR #416's run (`E2E (docker)` = `success` again) both ran on top of the fix. Local-only verification would have proven nothing, since Docker Desktop's macOS VM masks the exact UID mismatch this defect depends on.
- Captured Control 1 (e2e tier): `internal/server/service.go`'s pre-rollback backup `Trigger` string changed from `"pre-rollback"` to `"pre-rollback-BROKEN"`. Local pre-check matrix: `task lint` green, `task test` green, `task test:e2e` red (only `TestE2E_RollbackCreatesBackup`), `task test:e2e:docker` green, `task test:e2e:proc` green. PR #415's CI run matched exactly: `E2E (fast)` = `failure`, `E2E (docker)` = `success`, `E2E (proc)` = `success`, all seven pre-existing jobs `success`, `CI (Go) Complete` = `failure`.
- Captured Control 3 (proc_e2e tier): `cmd/router-hosts/main.go`'s error-path `os.Exit(1)` changed to `os.Exit(0)`. `cmd/router-hosts` has no test file (main() cannot be unit-tested by construction), so only `proc_e2e`, which execs the real shipped binary and reads its exit code, can catch this. Local pre-check matrix: `task lint` green, `task test` green, `task test:e2e` green, `task test:e2e:docker` green, `task test:e2e:proc` red (`TestProcE2E_MissingExplicitConfigFailsLoudly`). PR #416's CI run matched: `E2E (proc)` = `failure`, `E2E (fast)` = `success`, `E2E (docker)` = `success`, all seven pre-existing jobs `success`, `CI (Go) Complete` = `failure`.
- Controls 2 (docker_e2e tier, missing operator binary, PR #412) and 4 (D-10 docker-unavailable-fails-not-skips, PR #413) were captured in a prior session; both re-confirmed here via `gh run view --json jobs` before being counted toward this plan's four-control completion.
- Resolved D-05's out-of-repo half: filed issue #418 tracking the `[ci skip]` marker in `/gsd-ship`'s ship-note commit template (lives in the globally-installed GSD runtime, out of this repo's reach) — disposition `file-issue-only`, relying on the already-shipped `workflow_dispatch` trigger for manual recovery.
- Filed issue #417 tracking the cert-permission defect fixed in this plan, referencing the fixing commit.
- All four throwaway PRs (#412, #413, #415, #416) closed without merging; all scratch branches deleted locally and on origin.

## Task Commits

1. **Job 1 fix: cert-permission fix for docker_e2e tier** - `790befc` (fix) — committed to the phase branch
2. **Control 1 (e2e tier) regression** - `4e854d2` (test) — committed only to throwaway branch `rp/e2e-rollback-trigger-v2`, deleted after capture; never merged, never reached the phase branch
3. **Control 3 (proc_e2e tier) regression** - `bc19d37` (test) — committed only to throwaway branch `rp/proc-e2e-exit-code`, deleted after capture; never merged, never reached the phase branch

**Plan metadata:** this commit (docs: complete plan)

_Note: Controls 1 and 3's regression commits exist only in GitHub's PR history for #415/#416 (both closed) — `git log --oneline main..HEAD` on the phase branch contains neither hash, confirming D-09's no-knowingly-broken-commit-on-a-real-branch requirement._

## Files Created/Modified

- `e2e/helpers_test.go` - `writePEM` gained a `mode os.FileMode` parameter; in-process `e2e` tier call sites (`setupTestEnv`) pass `0o600`
- `e2e/docker_e2e_test.go` - `docker_e2e` tier call sites pass `0o644` so the container's UID 65532 can read bind-mounted certs

## Decisions Made

- Fixed the cert-permission defect by changing file mode only (`0o600` -> `0o644` for the three docker-mounted files), not directory mode, not `docker run --user`, not a baked-in test image. Individual files are bind-mounted (`-v tmpDir+"/ca.crt":/certs/ca.crt:ro`, not the containing `t.TempDir()`), so Docker mounts each file's own inode directly at its container target path — the container's `/certs` directory is auto-created by dockerd with normal traversable permissions, making the host `t.TempDir()`'s `0o700` mode irrelevant to container-side access. `gosec`/G306 was not a blocker: this repo's `.golangci.yml` does not enable the `gosec` linter, and `task lint` stayed clean with the change.
- D-05's out-of-repo half: `file-issue-only` (issue #418), matching the directive that no agent may edit the globally-installed GSD runtime.
- Controls 1 and 3 used regressions substituted in a prior session (`internal/server/service.go`'s Trigger string; `cmd/router-hosts/main.go`'s exit code) rather than 01-05-PLAN.md's originally proposed candidates (a CN-blanking change in `watch.go`; deleting `connect.go`'s `--config` override). Both were independently re-verified with the full five-cell local pre-check matrix and a real CI run in this session before being accepted, satisfying D-11's tier-uniqueness requirement on the same terms as the plan's original candidates.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed e2e-docker cert-permission failure blocking every merge to main**
- **Found during:** Pre-task investigation (orchestrator-verified defect, stated as job 1 of this session's directive)
- **Issue:** `writePEM` wrote docker-mounted mTLS certs at `0o600`, owned by the CI runner's UID; the containerized server (running as UID 65532 in the distroless nonroot image) could not open them, failing `TestDockerE2E_ImageBuildsAndServes` and `TestDockerE2E_WrongCARejected` deterministically in real CI (6/6 runs) while passing locally on macOS (Docker Desktop masks the UID mismatch).
- **Fix:** Added a `mode os.FileMode` parameter to `writePEM`; `docker_e2e` call sites now pass `0o644`, `e2e` (in-process) call sites keep `0o600`.
- **Files modified:** `e2e/helpers_test.go`, `e2e/docker_e2e_test.go`
- **Verification:** `task test`, `task lint`, `task test:e2e`, `task test:e2e:docker`, `task test:e2e:proc` all green locally; confirmed in real CI on PR #415 and #416 (`E2E (docker)` = `success` on both).
- **Committed in:** `790befc`

---

**Total deviations:** 1 auto-fixed (Rule 1 — bug fix, explicitly authorized by the session's job 1 directive rather than discovered mid-task)
**Impact on plan:** Necessary precondition for the plan's own controls: with the defect unfixed, every negative-control run would have shown `E2E (docker)` red for the wrong reason, contaminating the evidence D-11 requires. No scope creep — the fix touches only the two files the docker-mounted cert path runs through.

## Issues Encountered

- The `Edit` tool's exact-string match failed once on `internal/server/service.go` despite the target line existing verbatim (confirmed via a Python string-count check) — worked around with a scripted in-place replacement for that one edit; the phase branch's own `e2e/helpers_test.go`/`docker_e2e_test.go` edits used the `Edit` tool normally.
- None of the four CI runs hit the documented PR #404 check-suite-outage flake (missing check suite for ~15 min); PR #416's checks took ~20s longer than #415's to register but resolved without intervention.

## User Setup Required

None - no external service configuration required. `gh auth status` already reported push access for this session.

## Next Phase Readiness

- All four CI-03 negative controls are on record; the three e2e gates and the Docker-unavailable hard-fail wire have each been observed failing in real CI, closing out D-09/D-10/D-11's requirements.
- The cert-permission defect that would have silently wedged every future merge (once plan 01-04's gate went live) is fixed and verified in CI, not just locally.
- D-05 is fully resolved for this repo: `workflow_dispatch` (plan 01-01) plus a tracked upstream-follow-up issue (#418) for the out-of-repo `[ci skip]` marker.
- Two issues (#417, #418) give both discovered items a durable, tracked origin outside this ephemeral session.
- Phase 1's remaining acceptance bar is the human confirmation step this SUMMARY's `coverage:` block routes to `/gsd-verify-work` (D2–D5, D1) — the four run URLs and the fix verification are ready for that review.

---
*Phase: 01-ci-gating-for-the-e2e-tiers*
*Completed: 2026-08-03*
