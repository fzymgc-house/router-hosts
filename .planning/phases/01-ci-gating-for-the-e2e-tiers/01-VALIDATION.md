---
phase: 1
slug: ci-gating-for-the-e2e-tiers
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-02
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go stdlib `testing` (`go test`), build-tag-gated tiers (`e2e`, `docker_e2e`, `proc_e2e`) |
| **Config file** | none — driven by `Taskfile.yml`'s `test:e2e*` targets and `go test -tags <tag>` |
| **Quick run command** | `task test:e2e` |
| **Full suite command** | `task test:e2e && task test:e2e:docker && task test:e2e:proc` |
| **Estimated runtime** | ~5s quick; ~70–90s full (local proxy timing, LOW confidence — see RESEARCH.md Q-03) |

---

## Sampling Rate

- **After every task commit:** Run `task test:e2e`, plus `golangci-lint run ./...` for any new/modified Go file
- **After every plan wave:** Run `task ci` locally; push at least one intermediate scratch-branch commit so CI YAML errors surface cheaply before the red-proof PRs
- **Before `/gsd-verify-work`:** Full suite green, and all four red-proof run URLs (D-09/D-10) captured
- **Max feedback latency:** 90 seconds locally; CI job feedback is bounded by the slowest tier

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| *(populated during execution — plans not yet written)* | | | | | | | | | ⬜ pending |

---

## Wave 0 Requirements

- [ ] `internal/testutil/wait/wait.go` + `internal/testutil/wait/wait_test.go` — new package; needs unit tests for both the timeout-fires-`t.Fatalf` path and the success-returns-cleanly path (`t.Fatalf` calls `runtime.Goexit()`, so assert via a fake `testing.TB`, not `require`)
- [ ] Unit coverage for `requireDocker`'s env-gated branch (`RH_E2E_REQUIRE_DOCKER` set/unset × Docker present/absent) — zero coverage today; logic sits under `//go:build docker_e2e`, so either tag the test identically or extract the branch to a tag-free testable helper
- [ ] Framework install: none — `go test` and `task` are already wired

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| All three tiers run as CI jobs; `ci-go-complete` fails if any tier fails | CI-01 | Whether the YAML wires correctly is a GitHub-side behavior with no local `go test` equivalent | Push a scratch-branch PR; observe all jobs plus `ci-go-complete` in the Actions UI |
| Required-check evaluation blocks merge | CI-02 | `protect-main` ruleset evaluation happens GitHub-side | Same PR observation as CI-01; confirm merge is blocked while any tier is red |
| Each gate demonstrated red | CI-03 | One-time demonstration by design, not a standing test | Per D-09: apply one tier-unique regression on a scratch branch, open a throwaway PR, observe only that job go red, capture the run URL, close without merging |
| `proc_e2e` does not restore `bin/` from cache | CI-04 | Cache-restore absence is observable only in a real CI run | Fourth negative control (D-10) on a scratch-branch PR |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
