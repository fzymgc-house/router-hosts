---
phase: 01-ci-gating-for-the-e2e-tiers
reviewed: 2026-08-03T16:02:54Z
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
  warning: 1
  info: 0
  total: 1
status: issues-found
---

# Phase 01: CI Gating for the E2E Tiers — Code Review Report

**Reviewed:** 2026-08-03T16:02:54Z
**Depth:** standard
**Files Reviewed:** 13
**Status:** issues-found

## Summary

Reviewed all 13 files changed across plans 01-05 of this phase: the
`internal/testutil/wait` bounded-timeout polling helper, the
`internal/testutil/dockergate` precondition-decision function, the
`internal/ciwiring` aggregator-wiring invariant test, the three new
`e2e-*` CI jobs plus the completed `ci-go-complete` aggregator in
`ci-go.yml`, the ~12 readiness-poll conversions across the three `e2e/*.go`
test files, the `writePEM` mode parameterization, and the corrected
`docs/contributing/testing.md`.

Traced `wait.Until`/`wait.UntilValue` for at-least-once evaluation under a
zero/elapsed timeout (confirmed correct, both by code inspection and by
`go test`), for goroutine safety of `tb.Fatalf` (all call sites in this
diff invoke `wait.Until`/`UntilValue` synchronously on the test's own
goroutine — no call from inside a `go func()`), and for leaked
tickers/timers (none — `time.Sleep`, not `time.Ticker`). Verified
`dockergate.Decide`'s truth table is total and correct across all four
`(env, probeErr)` combinations, including the deliberate presence-based
(not truthiness-based) semantics for `"0"` and whitespace-only values.
Verified the `0o644` cert-mode relaxation is confined to `docker_e2e`-tagged
call sites only (`e2e/docker_e2e_test.go`); the in-process `e2e` tier's
`setupTestEnv` still writes `0o600` exclusively, confirmed via `rg` across
both files' `writePEM` call sites. Ran `go vet -tags {e2e,proc_e2e,docker_e2e}
./e2e/...`, `go test ./internal/testutil/... ./internal/ciwiring/...`,
`task lint`, and `actionlint .github/workflows/ci-go.yml` — all clean.

One structural robustness gap was found in `internal/ciwiring`'s aggregator
invariant (see WR-01 below): the test derives its "expected" e2e-tier set
from a regex over job IDs (`^e2e-`) applied identically to both sides of
the comparison, so a job that does not use that literal prefix is invisible
to the invariant on **both** sides at once — the exact "malformed/renamed
job silently drops out of both sets" failure mode this review was asked to
check for. It does not affect the three jobs currently in the workflow
(`e2e-fast`, `e2e-docker`, `e2e-proc`, all correctly prefixed and fully
wired), and the zero-jobs vacuous-pass case is explicitly guarded against
(`declaredTiers == nil` check), so this is a WARNING on future robustness,
not a live defect.

No Critical findings. No hardcoded secrets, no shell-injection risk in
`ci-go.yml`'s `run:` blocks (all interpolated values are GitHub Actions
`needs.*.result` strings, not attacker-controlled input), no `//nolint`
directives, no empty catch blocks, no leftover unconverted readiness polls
(`rg` for the pre-conversion sentinel patterns — `require.True(t,
found|saw*|*Cleared)` — returns no matches in any of the three converted
files), and the one deliberate `SLEEP-INTENTIONAL:`-marked sleep survives
byte-identical.

## Warnings

### WR-01: `internal/ciwiring`'s invariant is blind to jobs that don't use the literal `e2e-` prefix on both sides at once

**File:** `internal/ciwiring/ciwiring_test.go:56-79, 145-151`
**Issue:** `e2eJobIDs` and `e2eNeedsIDs` both filter their input through the
same `^e2e-` regex before the set-equality comparison runs:

```go
var e2eJobPattern = regexp.MustCompile(`^e2e-`)
...
declaredTiers := e2eJobIDs(wf.Jobs)           // filters wf.Jobs keys by e2eJobPattern
wiredTiers := e2eNeedsIDs(aggregator.Needs)   // filters aggregator.Needs by e2eJobPattern
if strings.Join(declaredTiers, ",") != strings.Join(wiredTiers, ",") { ... }
```

Because the *same* prefix filter is applied before either side is ever
compared, a job whose ID does not start with the literal string `e2e-` is
excluded from both `declaredTiers` and `wiredTiers` simultaneously — it
never enters the comparison at all, rather than causing a mismatch.

Concrete failure scenario: a future contributor adds a fourth e2e tier and,
for whatever reason (a rename, a differently-styled team convention, a
typo that happens to still read as intentional, e.g. `docker-e2e` instead
of `e2e-docker`), gives it a job ID that doesn't start with `e2e-`. If they
consistently forget to add it to `ci-go-complete`'s `needs`/`env`/result-check
(the exact gap this invariant exists to catch), the test still passes:
`declaredTiers` and `wiredTiers` are computed as if that job doesn't exist,
because neither the job's own ID nor any (correctly absent) `needs` entry
for it matches `^e2e-`. The job then runs on every PR, contributes nothing
to the required check, and `internal/ciwiring`'s own doc comment claim —
"a tier that runs and reports but is never wired into the required check
cannot be added silently" — is exactly the case this scenario defeats.

This is distinct from (and does not undermine) the zero-jobs vacuous-pass
case, which the test does correctly guard against via the separate
`if declaredTiers == nil` check at line 159-161. It's also distinct from
a same-prefix typo (e.g. `e2e-dokcer`), which the regex still matches and
the invariant still catches as a "declared but not needed" mismatch. The
gap is specific to job IDs that abandon the `e2e-` prefix convention
entirely.

**Fix:** Add a second, independent check that does not rely on the same
filter for both sides — e.g., assert that no job ID (as a whole, unfiltered
list from `wf.Jobs`) contains the substring `e2e` case-insensitively unless
it also matches `^e2e-`, which would surface an off-convention e2e-shaped
job by name rather than silently passing it through:

```go
// Guard against a tier drifting off the naming convention entirely,
// which would make it invisible to both e2eJobIDs and e2eNeedsIDs at
// once and defeat this whole invariant.
for id := range wf.Jobs {
    if strings.Contains(strings.ToLower(id), "e2e") && !e2eJobPattern.MatchString(id) {
        t.Fatalf("job %q looks like an e2e tier but does not match the required e2e-* naming convention this invariant depends on", id)
    }
}
```

Alternatively (simpler, more conservative), hardcode the minimum expected
tier count (`len(declaredTiers) >= 3`) as a floor so an off-convention
rename that silently drops a tier to zero-observed-but-still-running at
least changes a number a reviewer would notice in the diff, though this is
a weaker guarantee than the substring check above.

---

_Reviewed: 2026-08-03T16:02:54Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
