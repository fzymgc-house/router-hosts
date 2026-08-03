---
phase: 01-ci-gating-for-the-e2e-tiers
reviewed: 2026-08-03T18:00:00Z
depth: standard
files_reviewed: 13
files_reviewed_list:
  - .github/workflows/ci-go.yml
  - docs/contributing/testing.md
  - e2e/docker_e2e_test.go
  - e2e/e2e_test.go
  - e2e/helpers_test.go
  - e2e/proc_harness_test.go
  - go.mod
  - internal/ciwiring/ciwiring_test.go
  - internal/ciwiring/doc.go
  - internal/testutil/dockergate/dockergate.go
  - internal/testutil/dockergate/dockergate_test.go
  - internal/testutil/wait/wait.go
  - internal/testutil/wait/wait_test.go
findings:
  critical: 0
  warning: 0
  info: 1
  total: 1
status: issues-found
---

# Phase 01: CI Gating for the E2E Tiers — Code Review Report (Re-review, iteration 2)

**Reviewed:** 2026-08-03T18:00:00Z
**Depth:** standard
**Files Reviewed:** 13
**Status:** issues-found (info only)

## Summary

Second-iteration re-review focused on commit `5e24f79` (`fix(test): guard
e2e invariant against off-prefix ids`), which is the only change since
iteration 1 (+12 lines, `internal/ciwiring/ciwiring_test.go` only; `git show
--stat 5e24f79` confirms no other file in scope was touched).

**WR-01 is resolved as a live defect.** The fix adds a naming-convention
guard (lines 145-155) that iterates `wf.Jobs` unfiltered and fails the test
if any job id contains the substring `e2e` (case-insensitively) without
matching `^e2e-`. Verified:

- **Ordering:** the guard loop runs at lines 151-155, strictly before
  `declaredTiers`/`wiredTiers` are computed (lines 157-158) and before the
  set-equality comparison (line 163). An off-convention e2e-shaped job now
  fails with the guard's explicit naming-convention message rather than
  silently vanishing from both sides of the comparison — the ordering
  comment in the code (lines 148-150) accurately describes this.
- **No false positives:** none of the 7 pre-existing jobs
  (`lint`, `vuln`, `test`, `build`, `buf-check`, `manifests`, `docs`) or the
  aggregator (`ci-go-complete`) contain the substring `e2e`, so the guard
  does not trip on any current job (confirmed by reading `ci-go.yml` in
  full).
- **`strings` import:** already present pre-fix (used by `strings.Join`
  elsewhere in the same file); the fix adds no new import and needs none.
- **Compiles and passes:** `go test ./internal/ciwiring/... -run
  TestEveryE2ETierIsWiredIntoAggregator -v` → PASS. `go vet
  ./internal/ciwiring/...` and `golangci-lint run ./internal/ciwiring/...`
  → clean, 0 issues.
- **Regression check on the other 12 files:** untouched since iteration 1
  (only `ciwiring_test.go` appears in the commit); re-scanned briefly for
  regressions, none found.

**Residual gap (see IN-01 below, not a Warning):** the guard narrows the
hole rather than closing it. A job id containing no "e2e" substring at all
(e.g. `container-suite`, `integration`, a bare acronym unrelated to "e2e")
would still evade both the guard and the `^e2e-` prefix filter, and would
therefore remain invisible to the whole invariant on both sides at once —
the same underlying failure mode as the original WR-01, just requiring a
more contrived job name to trigger. This is a known, judgment-call residual
limit of a substring-based guard, not a live defect (no job in the current
workflow triggers it), so it is recorded as Info rather than re-opening the
Warning.

No new Critical or Warning findings. No hardcoded secrets, no dangerous
functions, no empty catch blocks introduced by this fix.

## Info

### IN-01: Naming-convention guard narrows but does not close the "off-prefix job invisible to both sides" gap

**File:** `internal/ciwiring/ciwiring_test.go:151-155`
**Issue:** The new guard only catches jobs whose id contains the substring
`e2e` (case-insensitively) but doesn't start with `e2e-` (e.g. `docker-e2e`).
It does not catch a job id with zero "e2e" substring at all (e.g.
`container-suite`), which would still be excluded from both `e2eJobIDs` and
`e2eNeedsIDs` simultaneously — invisible to the invariant, exactly as in the
original WR-01, just via a name that doesn't even hint at "e2e". This is a
residual gap inherent to any substring/regex-based classification without an
external, independently-maintained list of tier names to check against.
**Fix (optional, out of current scope):** If closing this fully is ever
desired, replace the substring heuristic with an explicit allowlist of
tier ids maintained as a package-level `var` (e.g. `var knownE2ETiers =
[]string{"e2e-fast", "e2e-docker", "e2e-proc"}`) that the test asserts
`declaredTiers` matches exactly, forcing any new tier — regardless of
naming — to require a one-line edit to this test file, which a reviewer
would see in the diff. This is a design tradeoff (test-file coupling vs.
convention-based looseness) rather than a bug, so it is filed as Info for
the team to decide on, not auto-fixed.

---

_Reviewed: 2026-08-03T18:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
</content>
