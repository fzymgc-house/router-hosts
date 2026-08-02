# Phase 1: CI Gating for the e2e Tiers - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-02
**Phase:** 1-CI Gating for the e2e Tiers
**Areas discussed:** Gate topology & triggers, Docker hard-fail vs. local dev, Red-demonstration protocol (CI-03), Readiness helper scope (VRFY-05)

---

## Gate topology & triggers

### Q1 — How should the three e2e jobs attach to the required-check set?

| Option | Description | Selected |
|--------|-------------|----------|
| Fold into `ci-go-complete` | Add the 3 jobs to the existing aggregator's `needs:` and result-check block. Required-check set stays at 2, no ruleset edit. | ✓ |
| Separate `E2E Complete` aggregator | New aggregator over just the 3 tiers, added to the ruleset as a 3rd required check. Clearer signal, mirrors the `Vulnerability check` precedent. | |

**User's choice:** Fold into `ci-go-complete`
**Notes:** Avoids introducing a required-but-possibly-unreported context during the same phase that establishes gating.

### Q2 — CI-02's PR-vs-merge distinction has no mechanism (no merge queue, `pull_request`-only trigger, squash-only merges). How to resolve?

| Option | Description | Selected |
|--------|-------------|----------|
| Collapse to PR-time | All three tiers run on every PR; CI-02's two-stage wording becomes descriptive. The PR check *is* the merge gate. | ✓ |
| Enable a merge queue | Add `merge_queue` rule + `merge_group:` trigger to implement CI-02 literally. | |
| Path-filter the slow tiers | Skip container/process tiers on docs-only diffs. | |

**User's choice:** Collapse to PR-time
**Notes:** Merge queue judged to be its own phase's worth of work. Path-filtering parked pending the CI-minute question (Q-03). Flagged during discussion that this makes CI-02 satisfied *descriptively* rather than mechanically — recorded in CONTEXT.md D-03 rather than silently glossed. Offered to propose a REQUIREMENTS.md text change separately; not done here per rule `01ygyqn0by`.

### Q3 — Resolving the `[ci skip]` / unreported-head-SHA blocker

| Option | Description | Selected |
|--------|-------------|----------|
| Both: `workflow_dispatch` + strip marker | Defense in depth — the two fixes cover different failure causes. | ✓ |
| Strip the `[ci skip]` marker only | Addresses the known cause; no recovery mechanism for unrelated stalls. | |
| `workflow_dispatch` only | Manual re-run button; the stall becomes routine rather than exceptional. | |

**User's choice:** Both
**Notes:** `workflow_dispatch` also covers the unexplained PR #404 check-suite outage recorded in STATE.md.

### Q4 — Job layout

| Option | Description | Selected |
|--------|-------------|----------|
| Three parallel jobs | Wall-clock = slowest tier; failure names the tier; matches existing lint/vuln/test/build structure. | ✓ |
| One job, three sequential steps | Fewer runner minutes on setup; serial wall-clock; fast-tier failure masks the others. | |

**User's choice:** Three parallel jobs

---

## Docker hard-fail vs. local dev

### Q1 — How should `requireDocker` be gated?

| Option | Description | Selected |
|--------|-------------|----------|
| Env-gated (`RH_E2E_REQUIRE_DOCKER`) | `t.Fatal` in CI, `t.Skip` locally. Satisfies CI-04 where it matters, keeps local dev workable. | ✓ |
| Unconditional `t.Fatal` | The build tag is itself the opt-in. Simplest, no new convention. | |
| CI-side preflight step | Leave test code alone, fail the job before tests run. Doesn't satisfy CI-04's literal wording. | |

**User's choice:** Env-gated
**Notes:** Both existing skip sites (missing binary, dead daemon) route through the same gate.

### Q2 — Do the Namespace runner profiles provide Docker?

| Option | Description | Selected |
|--------|-------------|----------|
| Treat as unknown — research it | Flag for `gsd-phase-researcher`; plan on the assumption it works, with a fallback. | ✓ |
| Docker is available, no setup needed | | |
| Needs an explicit setup action | | |

**User's choice:** Research it
**Notes:** Recorded as open question Q-01.

### Q3 — How explicit should `proc_e2e`'s fresh-build guarantee be?

| Option | Description | Selected |
|--------|-------------|----------|
| No `bin/` caching + assert freshness | `rm -rf bin/` before `task build`; structural guarantee. | ✓ |
| Rely on Taskfile `deps` | Works today; guarantee is "nobody has broken it yet". | |

**User's choice:** No `bin/` caching + assert freshness
**Notes:** The rejected option is the exact shape CI-03 exists to rule out.

---

## Red-demonstration protocol (CI-03)

### Q1 — How should the red demonstration be staged?

| Option | Description | Selected |
|--------|-------------|----------|
| Throwaway PR from a scratch branch | Broken commits stay out of the phase branch; doubles as the PR-specific-vs-repo-wide probe for the #404 outage. | ✓ |
| Temporary revert commit on the phase branch | Evidence in branch history; carries knowingly-broken commits. | |
| Local reproduction only | Proves the *test* fails, not the *gate* — advised against. | |

**User's choice:** Throwaway PR from a scratch branch

### Q2 — Which gates need their own red proof?

| Option | Description | Selected |
|--------|-------------|----------|
| All 3 tiers + the Docker hard-fail | Four negative controls, covering every new gate including CI-04's own fix. | ✓ |
| All 3 tiers only | Take the skip→fail change on code review. | |
| One shared regression across all 3 | Proves wiring, not that any tier is load-bearing. | |

**User's choice:** All 3 tiers + the Docker hard-fail

### Q3 — Must each tier's regression be tier-unique?

| Option | Description | Selected |
|--------|-------------|----------|
| Require tier-unique regressions | For `proc_e2e`, reintroduce the G-01-1 CLI-flag→config seam bug. | ✓ |
| Any regression that turns the tier red | Simpler to construct; can't distinguish added coverage from redundancy. | |

**User's choice:** Tier-unique regressions

### Q4 — Where does the red-proof evidence live?

| Option | Description | Selected |
|--------|-------------|----------|
| `01-VALIDATION.md` | Follows the 09-05 / 01-08 precedent. | |
| Commit bodies + PR description | Evidence next to the change; scattered, collapsed by squash-merge. | |

**User's choice (free text):** *"use GSD for what it does, and that should include valdiate. DO NOT HAND EDIT the file(s) GSD owns"*
**Notes:** Neither offered option was taken as posed. Verified that `gsd-tools validate` / `verify` are consistency-checkers, not the VALIDATION.md writer — that artifact is produced by `/gsd-verify-work` and `/gsd-validate-phase`. Captured as D-12: evidence is recorded through those verbs; no agent hand-writes the file. Consistent with repo rule `01ygyqn0by`.

---

## Readiness helper scope (VRFY-05)

### Q1 — Actual scope of "the bare `time.Sleep` calls are gone"

| Option | Description | Selected |
|--------|-------------|----------|
| Only readiness/synchronization sleeps | Intentional duration-holding sleeps stay, marked; poll intervals route through the helper. | ✓ |
| Every `time.Sleep` in the three tiers | Literal reading of SC4; breaks the outage-window assertion. | |
| Only the ones in `e2e_test.go` | Narrowest literal reading; leaves 9 sleeps elsewhere. | |

**User's choice:** Only readiness/synchronization sleeps
**Notes:** Surfaced during discussion that `e2e_test.go:757` is a deliberate 300ms outage-window sleep whose comment explicitly says a readiness wait would destroy what the test asserts (reviews M4, M10). A blanket sweep would have silently broken it.

### Q2 — Where should the shared helper live?

| Option | Description | Selected |
|--------|-------------|----------|
| `internal/testutil/wait` (importable, untagged) | Reachable by all three tags and by Phase 3's harness regardless of its layout. | ✓ |
| `e2e/wait_test.go` with all three tags | Test-only, stays out of the module tree; forces Phase 3's harness into the `e2e` package. | |

**User's choice:** `internal/testutil/wait`
**Notes:** Flagged that this package imports `testing` from a non-test package — recorded as open question Q-02, with the rejected option as the documented fallback.

### Q3 — How should the helper report a timeout?

| Option | Description | Selected |
|--------|-------------|----------|
| `t.Fatalf` with the condition description | No return path a caller can drop. | ✓ |
| Return an error, caller decides | More composable; an ignored return recreates the failure mode VRFY-05 targets. | |

**User's choice:** `t.Fatalf`

### Q4 — Should acceptance be a grep count on `time.Sleep`?

| Option | Description | Selected |
|--------|-------------|----------|
| No — assert on structure instead | A count gate can't distinguish the two kinds of sleep and needs a magic number. | ✓ |
| Yes — a bounded count gate is fine | Cheap and mechanical. | |

**User's choice:** No — assert on structure
**Notes:** Consistent with the user's `grepping` rule: a gate must be demonstrated red and must test what it claims.

---

## Claude's Discretion

- Runner profile sizing and per-job timeouts for the three e2e jobs
- `wait.Until`'s signature beyond the D-15 constraints
- Tier-unique regressions for `e2e` and `docker_e2e` (only `proc_e2e`'s is fixed)
- Job naming beyond the `e2e-fast` / `e2e-docker` / `e2e-proc` shape

## Deferred Ideas

- Merge queue (would implement CI-02's two-stage gating literally)
- Separate `E2E Complete` required check
- Path-filtering the slow tiers on docs-only diffs (pending Q-03)
- Nightly e2e cadence + flake-quarantine convention (already out of scope for v0.14.0)
