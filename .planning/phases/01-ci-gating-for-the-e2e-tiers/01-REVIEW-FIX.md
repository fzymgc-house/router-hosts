---
phase: 01-ci-gating-for-the-e2e-tiers
fixed_at: 2026-08-03T16:59:50Z
review_path: .planning/phases/01-ci-gating-for-the-e2e-tiers/01-REVIEW.md
iteration: 1
findings_in_scope: 1
fixed: 1
skipped: 0
status: all_fixed
---

# Phase 01: CI Gating for the E2E Tiers — Code Review Fix Report

**Fixed at:** 2026-08-03T16:59:50Z
**Source review:** .planning/phases/01-ci-gating-for-the-e2e-tiers/01-REVIEW.md
**Iteration:** 1

**Summary:**
- Findings in scope: 1 (Critical + Warning; Info excluded, `--all` not passed)
- Fixed: 1
- Skipped: 0

## Fixed Issues

### WR-01: `internal/ciwiring`'s invariant is blind to jobs that don't use the literal `e2e-` prefix on both sides at once

**Files modified:** `internal/ciwiring/ciwiring_test.go`
**Commit:** `5e24f79`
**Applied fix:** Implemented the review's primary suggestion (the substring
guard), placed before the set-equality comparison in
`TestEveryE2ETierIsWiredIntoAggregator`:

```go
// Guard against a tier drifting off the naming convention entirely,
// which would make it invisible to both e2eJobIDs and e2eNeedsIDs at
// once (both filter through the same e2eJobPattern) and defeat this
// whole invariant. Must run before the set-equality comparison below
// so an off-convention job fails with this naming message rather than
// silently vanishing from both sides of that comparison.
for id := range wf.Jobs {
    if strings.Contains(strings.ToLower(id), "e2e") && !e2eJobPattern.MatchString(id) {
        t.Fatalf("job %q looks like an e2e tier but does not match the required e2e-* naming convention this invariant depends on", id)
    }
}
```

`strings` was already imported (used by `strings.Join`/`strings.Contains`
elsewhere in the file), so no import changes were needed. The three
existing jobs (`e2e-fast`, `e2e-docker`, `e2e-proc`) plus `ci-go-complete`
itself do not trip the guard, confirmed by the real workflow file still
passing after the fix (see verification below). No change to `doc.go` was
needed — its existing claim ("a tier that runs and reports but is never
wired into the required check cannot be added silently") is now backed by
this guard rather than contradicted by it.

**Mandatory red-proof observations (verbatim):**

1. Added a temporary off-convention job `docker-e2e:` to
   `.github/workflows/ci-go.yml` (inside the isolated worktree only),
   deliberately not wired into `ci-go-complete`'s `needs`/`env`/result
   check.
2. Ran `go test ./internal/ciwiring/... -run TestEveryE2ETierIsWiredIntoAggregator -v`:

   ```
   === RUN   TestEveryE2ETierIsWiredIntoAggregator
       ciwiring_test.go:153: job "docker-e2e" looks like an e2e tier but does not match the required e2e-* naming convention this invariant depends on
   --- FAIL: TestEveryE2ETierIsWiredIntoAggregator (0.00s)
   FAIL
   FAIL	github.com/fzymgc-house/router-hosts/internal/ciwiring	0.057s
   FAIL
   ```

   This is the new naming-convention message, not a set-equality mismatch,
   confirming the guard (not some other assertion) is what caught it.
3. Reverted `.github/workflows/ci-go.yml` completely (restored from a
   pre-edit backup copy). Confirmed byte-identical via `git diff --stat --
   .github/workflows/ci-go.yml` (empty output, exit 0) and a direct `diff`
   against the pre-edit backup (`BYTE_IDENTICAL`).
4. Re-ran the same test:

   ```
   === RUN   TestEveryE2ETierIsWiredIntoAggregator
   --- PASS: TestEveryE2ETierIsWiredIntoAggregator (0.00s)
   PASS
   ok  	github.com/fzymgc-house/router-hosts/internal/ciwiring	0.061s
   ```

Both observations reported verbatim above: FAIL with the naming-convention
message when off-convention, PASS after the byte-identical revert.

## Skipped Issues

None — the single in-scope finding was fixed.

## Verification

All run inside the isolated worktree (`/tmp/sv-01-reviewfix-*`, attached to
temp branch `gsd-reviewfix/01-*`, fast-forwarded into
`docs/start-milestone-v0.14.0` and torn down after the fix commit — see
Environment note below):

- `go test ./internal/ciwiring/...` → `ok  	github.com/fzymgc-house/router-hosts/internal/ciwiring	0.125s`
- `task test` → all packages `ok` (race detector enabled), including
  `internal/ciwiring 1.111s`
- `task lint` → `golangci-lint run ./...` → `0 issues.`; `buf lint` clean;
  `buf format --diff --exit-code` clean; `task manifests:verify` →
  "Manifests are up to date." (no `//nolint` directives added)

**Environment note:** all fixing, red-proof, and verification steps above
ran inside the isolated git worktree created for this run (per
`workflow.use_worktrees: true`), not in the main checkout. The worktree had
full Go module/build caching available (shared `GOPATH`/module cache) so
`task test`/`task lint` ran identically to the main checkout. The fix
commit was fast-forwarded into `docs/start-milestone-v0.14.0` in the main
checkout after teardown, so the committed state is reproducible there;
the worktree itself no longer exists.

---

_Fixed: 2026-08-03T16:59:50Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
