---
status: complete
phase: 01-ci-gating-for-the-e2e-tiers
source: [01-01-SUMMARY.md, 01-02-SUMMARY.md, 01-03-SUMMARY.md, 01-04-SUMMARY.md, 01-05-SUMMARY.md]
started: 2026-08-03T15:52:17Z
updated: 2026-08-03T15:53:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Confirm auto-covered deliverables (plans 01-01 through 01-04)
expected: |
  - 01-01/D1: wait.Until/wait.UntilValue semantics (D-15) — internal/testutil/wait/wait_test.go, 3 passing tests
  - 01-01/D2: e2e/helpers_test.go's waitForServer routes through wait.Until — task test:e2e pass
  - 01-01/D3: ci-go.yml workflow_dispatch + e2e-fast wired into ci-go-complete — internal/ciwiring test pass
  - 01-01/D4: ciwiring set-equality invariant test — pass
  - 01-02/D1: twelve readiness call sites route through wait.Until — grep + task test:e2e + task test:e2e:proc pass
  - 01-02/D2: e2e_test.go:757 outage-window sleep survives with SLEEP-INTENTIONAL marker — grep + structural gate pass
  - 01-02/D3: TestE2E_WatchSinkHealthKeyedByCN assertions — pass
  - 01-02/D4: e2e and proc_e2e build tags compile cleanly — pass
  - 01-03/D1: dockergate.Decide covers all env x probe combinations — 3 unit tests pass
  - 01-03/D2: requireDocker hard-fails when RH_E2E_REQUIRE_DOCKER set, skips otherwise — pass
  - 01-03/D3: waitForDockerServer routes through wait.Until, container-log diagnostic preserved — pass
  - 01-03/D4: docs/contributing/testing.md CI Integration section corrected — pass
  - 01-04/T1: e2e-docker and e2e-proc jobs exist with correct runner profiles/timeouts/pinned SHAs/env var — actionlint + yq assertions pass
  - 01-04/T2: ci-go-complete needs all ten jobs, binds ten *_RESULT vars, != "success" check — ciwiring test + task test pass
result: pass
source: automated-confirmed

### 2. e2e-docker cert-permission fix, verified in real CI
expected: |
  writePEM's docker_e2e call sites write certs at 0o644 (was 0o600), and a
  real CI run on the fix shows E2E (docker) concluding success — not just a
  local macOS pass, which cannot exercise the UID-mismatch defect.
result: pass
reported: "Confirmed via gh run view --json jobs for run 30828580687 (PR #415) and run 30829014408 (PR #416): E2E (docker) = success in both, on top of commit 790befc. Prior to the fix this job had never once passed in real CI (6/6 prior failures per the session's verified defect statement)."

### 3. Negative control 1 (e2e tier) — red proof
expected: |
  A regression only the e2e tier catches (internal/server/service.go's
  pre-rollback Trigger string) makes E2E (fast) fail while E2E (docker) and
  E2E (proc) stay green, all seven pre-existing jobs stay green, and
  CI (Go) Complete fails, in a throwaway PR later closed unmerged.
result: pass
reported: "Confirmed via gh run view --json jobs for run 30828580687 (PR #415, closed, unmerged): E2E (fast)=failure (TestE2E_RollbackCreatesBackup only, per job log), E2E (docker)=success, E2E (proc)=success, Lint/Vulnerability check/Test/Build/Buf lint & format/Manifests up to date/Docs build (strict)=success, CI (Go) Complete=failure."

### 4. Negative control 2 (docker_e2e tier) — red proof
expected: |
  A regression only the docker_e2e tier catches (missing operator binary in
  the built image) makes E2E (docker) fail while E2E (fast) and E2E (proc)
  stay green, all seven pre-existing jobs stay green, and CI (Go) Complete
  fails, in a throwaway PR later closed unmerged.
result: pass
reported: "Confirmed via gh run view --json jobs for run 30818557788 (PR #412, closed, unmerged, captured in a prior session and re-checked this session): E2E (docker)=failure, E2E (fast)=success, E2E (proc)=success, all seven pre-existing jobs=success, CI (Go) Complete=failure."

### 5. Negative control 3 (proc_e2e tier) — red proof
expected: |
  A regression only the proc_e2e tier catches (cmd/router-hosts/main.go's
  error-path os.Exit(1) -> os.Exit(0)) makes E2E (proc) fail while
  E2E (fast) and E2E (docker) stay green, all seven pre-existing jobs stay
  green, and CI (Go) Complete fails, in a throwaway PR later closed
  unmerged.
result: pass
reported: "Confirmed via gh run view --json jobs for run 30829014408 (PR #416, closed, unmerged): E2E (proc)=failure (TestProcE2E_MissingExplicitConfigFailsLoudly, per job log), E2E (fast)=success, E2E (docker)=success, all seven pre-existing jobs=success, CI (Go) Complete=failure."

### 6. Negative control 4 (D-10, docker-unavailable fails not skips) — red proof
expected: |
  With RH_E2E_REQUIRE_DOCKER set and Docker made unreachable in the
  e2e-docker job, the job fails (not skips) and its log contains the
  RH_E2E_REQUIRE_DOCKER failure message, with CI (Go) Complete also
  failing, in a throwaway PR later closed unmerged.
result: pass
reported: "Confirmed via gh run view --json jobs for run 30819896321 (PR #413, closed, unmerged, captured in a prior session and re-checked this session): E2E (docker)=failure, log contains 'docker not found, but RH_E2E_REQUIRE_DOCKER is set' with no 'skipping' string, CI (Go) Complete=failure."

### 7. All four throwaway PRs closed unmerged; no scratch branches remain
expected: PRs #412, #413, #415, #416 all report state CLOSED and mergedAt null; no rp/* branch exists locally or on origin.
result: pass
source: automated
coverage_id: D6

### 8. GitHub issues filed for both discovered items
expected: Issue #417 (cert-permission defect) and #418 (D-05 upstream [ci skip] follow-up) both exist and are open.
result: pass
source: automated
coverage_id: D7

## Summary

total: 8
passed: 8
issues: 0
pending: 0
skipped: 0

## Gaps

[none]
