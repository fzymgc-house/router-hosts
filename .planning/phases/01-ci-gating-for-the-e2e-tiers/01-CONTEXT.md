# Phase 1: CI Gating for the e2e Tiers - Context

**Gathered:** 2026-08-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Make three already-existing, already-passing test tiers (`e2e`, `docker_e2e`,
`proc_e2e`) **load-bearing**: run them in CI, attach them to the required-check
set so no change reaches `main` without them, prove each one is able to fail,
and consolidate readiness waiting into a single shared helper.

This is wiring, not new test coverage. No new assertions about product behavior
are in scope — only the machinery that makes existing assertions block a merge.

**Requirements:** CI-01, CI-02, CI-03, CI-04, VRFY-05

**Explicitly NOT in this phase:**

- Any containerized deployment-verification harness (Phase 3, VRFY-01…04)
- Closing v0.13.0 Phase 1's `uat-passed: false` (Phase 3's bar, VRFY-04)
- Nightly-scheduled e2e cadence and flake-quarantine convention (deferred at
  roadmap time; see STATE.md Deferred Items)

</domain>

<decisions>
## Implementation Decisions

### Gate Topology and Triggers

- **D-01:** The three e2e jobs fold into the **existing** `ci-go-complete`
  aggregator — added to its `needs:` list and to its explicit result-check
  block. The repository's required-check set stays at exactly two contexts
  (`CI (Go) Complete`, `Vulnerability check`) and the `protect-main` ruleset is
  **not** edited. Chosen over a separate `E2E Complete` required check because
  a required context that is mistyped or never reported blocks merges silently,
  and this phase should not introduce that failure mode while establishing
  gates. — **Reversibility:** reversible — splitting the aggregator later is a
  workflow edit plus one ruleset addition.

- **D-02:** Preserve `ci-go-complete`'s existing `!= "success"` comparison
  style for the new jobs (not `== "failure"`). Under `if: always()`, a
  `cancelled` or `skipped` job is also `!= "success"`, which is what SC1's
  "fails if any tier fails" requires. This is a correctness constraint, not a
  style preference.

- **D-03:** CI-02's distinction — fast tier gates every PR, container and
  process tiers gate merge to `main` — **collapses to a single PR-time gate**.
  There is no mechanism for the two-tier reading in this repository:
  `ci-go.yml` triggers only on `pull_request`, the `protect-main` ruleset has
  no `merge_queue` rule, and merges are squash-only. All three tiers therefore
  run on every PR, and because the PR check *is* the merge gate, nothing can
  reach `main` without all three green. **The substance of CI-02 is satisfied;
  its wording describes a two-stage mechanism that does not exist here.** A
  merge queue was considered and rejected as its own phase's worth of work.
  — **Reversibility:** reversible — adding a merge queue later re-splits the
  gates without undoing anything built here.

- **D-04:** Three **parallel** jobs (`e2e-fast`, `e2e-docker`, `e2e-proc`),
  matching how `lint`/`vuln`/`test`/`build` are already structured. Wall-clock
  is the slowest tier rather than the sum, a failure names the tier directly,
  and each tier gets its own runner profile and timeout.

- **D-05:** Resolve the ship-note CI stall with **both** available fixes: add
  `workflow_dispatch` to `ci-go.yml`, **and** strip the `[ci skip]` marker from
  `/gsd-ship`'s ship-note commit. The two address different causes — the marker
  is the known cause of unreported checks on the head SHA, while
  `workflow_dispatch` is the only recovery path if a check suite goes missing
  for an unrelated reason (which happened during PR #404 and was never
  explained). See STATE.md "Blockers/Concerns".

### Docker Availability and Fresh Builds (CI-04)

- **D-06:** `requireDocker` becomes **env-gated**, not unconditionally fatal:
  hard-fail when `RH_E2E_REQUIRE_DOCKER` is set (the `e2e-docker` CI job sets
  it), skip otherwise. This satisfies CI-04 where it matters — a green CI run
  can no longer mean "skipped" — while keeping `task test:e2e:docker` usable
  for contributors without a Docker daemon. Both existing skip sites
  (`e2e/docker_e2e_test.go:140` missing binary, `:144` dead daemon) route
  through the same gate.

- **D-07:** Whether the Namespace runner profiles
  (`namespace-profile-linux-amd64-*`) provide a Docker daemon is **unknown and
  must be researched** — see Open Questions. Planning may assume it works, but
  must carry a fallback if a setup action is required.

- **D-08:** `proc_e2e` builds fresh **structurally, not by convention**: the
  job removes `bin/` before `task build`, and no cache step restores `bin/`.
  Go module and build caching (compiler cache, not artifacts) is retained.
  Relying on "no cache step touches `bin/` today" was rejected — that is a
  property nobody has broken yet rather than an enforced one, which is the
  exact shape CI-03 exists to rule out.

### Red Demonstration (CI-03)

- **D-09:** Red proofs are staged as **throwaway PRs from scratch branches** —
  push a deliberately-broken branch, open a PR, capture the failing run URL,
  close without merging. Keeps knowingly-broken commits out of the phase
  branch's history, and doubles as the PR-specific-vs-repo-wide probe STATE.md
  asks for regarding the unexplained #404 check-suite outage.

- **D-10:** **Four** negative controls are required, not three: one per tier,
  plus one proving `e2e-docker` **fails rather than skips** when Docker is
  unavailable. The skip→fail change in D-06 is itself a new gate that has never
  been observed firing, so it needs its own proof.

- **D-11:** Each tier's regression must be one that **only that tier catches**.
  A shared-cause failure turns all three red at once and proves the wiring, not
  that any individual tier is load-bearing. For `proc_e2e` specifically, the
  regression is a reintroduction of the **G-01-1 CLI-flag→config seam** defect
  — the exact bug that shipped past the other tiers and the stated justification
  for making `proc_e2e` a required gate (CI-02). The researcher selects
  equivalents for `e2e` and `docker_e2e`.

- **D-12:** Red-proof evidence is recorded **through GSD's own verification
  verbs** (`/gsd-verify-work`, `/gsd-validate-phase`), which own
  `{NN}-VALIDATION.md` / `{NN}-UAT.md`. These files MUST NOT be hand-written by
  any agent. Per repo rule `01ygyqn0by`, GSD-owned `.planning/` artifacts are
  written by their owning verb; if no verb fits a needed shape, that is
  reported upstream, not worked around locally.

### Readiness Helper (VRFY-05)

- **D-13:** Scope is **readiness/synchronization sleeps only** — sleeps used to
  wait for a condition to become true. A blanket removal of `time.Sleep` was
  rejected: `e2e/e2e_test.go:757` is a deliberate 300ms sleep holding an outage
  window open, carrying a comment that says so and that survived two review
  rounds (reviews M4, M10). Removing it would destroy the assertion the test
  exists to make. Intentional duration-holding sleeps stay and MUST carry a
  marker comment so a future sweep does not remove them. Poll intervals inside
  already-bounded loops (e.g. `e2e_test.go:681`, `helpers_test.go:216`) are
  routed **through** the helper, not deleted.

- **D-14:** The helper lives in **`internal/testutil/wait`** — a normal
  (non-`_test.go`), untagged, importable package. This is the only location
  reachable by all three build tags *and* by Phase 3's harness regardless of
  what tag or directory that harness lands in. The alternative
  (`e2e/wait_test.go` tagged `e2e || docker_e2e || proc_e2e`) was rejected
  because a `_test.go` file cannot be imported across packages, which would
  force Phase 3's harness into the `e2e` directory and package — constraining a
  phase not yet planned. — **Reversibility:** costly — moving it later means
  touching every converted call site across three build tags plus Phase 3.

- **D-15:** On timeout the helper calls **`t.Fatalf`** with the condition's
  human-readable description (taking `testing.TB`, calling `t.Helper()`).
  Returning an error was rejected: an ignored return value recreates precisely
  the fall-through-to-a-confusing-assertion failure mode VRFY-05 exists to
  eliminate. There must be no return path a caller can silently drop.

- **D-16:** The acceptance criterion for this work MUST NOT be a grep count on
  `time.Sleep`. Such a gate cannot distinguish an intentional outage-window
  sleep from a readiness guess, goes green the moment someone writes the same
  bug with a different token, and needs a hand-maintained magic number. Assert
  on structure instead: each converted call site routes through the helper, and
  each intentional sleep carries its marker comment. Any gate written for this
  phase must itself be demonstrated red before acceptance (CI-03 applies to the
  phase's own gates, not only to CI jobs).

### Claude's Discretion

- Runner profile sizing and per-job timeouts for the three e2e jobs
- The exact signature and option surface of `wait.Until` beyond D-15's
  constraints (`testing.TB`, `t.Helper()`, `t.Fatalf` on timeout, a description
  string)
- Which specific regressions serve as tier-unique red proofs for `e2e` and
  `docker_e2e` (D-11 fixes only `proc_e2e`'s)
- Job naming, beyond the `e2e-fast` / `e2e-docker` / `e2e-proc` shape

</decisions>

<open_questions>
## Open Questions for Research

These are NOT decided. `gsd-phase-researcher` must resolve them.

- **Q-01 (blocks D-07):** Do the `namespace-profile-linux-amd64-*` runner
  profiles provide a working Docker daemon out of the box, or is a setup action
  (`namespacelabs/nscloud-setup`, `docker/setup-buildx-action`, or similar)
  required? Which profile size does a `docker build` plus container run need?

- **Q-02 (constrains D-14):** Does an `internal/testutil/wait` package that
  imports `testing` cause problems in this module — `golangci-lint` findings,
  test-flag registration leaking into any binary that transitively imports it,
  or release-binary size impact? Nothing under `cmd/` should import it, but
  confirm rather than assume. If it is a genuine problem, the fallback is
  `e2e/wait_test.go` with all three tags, accepting the Phase 3 constraint.

- **Q-03:** What is the CI-minute cost of running all three tiers on every PR
  at current PR volume? D-03 collapses everything to PR-time; if the cost is
  material, path-filtering was the rejected alternative and can be revisited
  — but note a skipped required job reports `skipped`, not `success`, which
  D-02's comparison style already handles correctly.

</open_questions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Planning Artifacts

- `.planning/ROADMAP.md` § "Phase 1: CI Gating for the e2e Tiers" — goal,
  dependencies, and the four success criteria
- `.planning/REQUIREMENTS.md` lines 77–80 (CI-01…CI-04), line 90 (VRFY-05) —
  requirement text this phase must satisfy
- `.planning/STATE.md` § "Blockers/Concerns" — the `[ci skip]` / required-check
  stall (D-05) and the unexplained PR #404 check-suite outage (D-09)

### CI and Build Configuration

- `.github/workflows/ci-go.yml` — trigger block (lines 2–4), the `test` job as
  the pattern for a new job (lines 39–62), and `ci-go-complete` (lines 136–175)
  which D-01 and D-02 modify
- `Taskfile.yml` lines 27–40 — `test:e2e`, `test:e2e:docker`, `test:e2e:proc`
  and their `deps`
- `protect-main` ruleset (GitHub ruleset id `10601376`) — required contexts are
  `CI (Go) Complete` and `Vulnerability check`; D-01 leaves this untouched

### Test Tiers

- `e2e/docker_e2e_test.go` — `requireDocker` at lines 136–146 (D-06's two skip
  sites); build tag `docker_e2e`
- `e2e/e2e_test.go` — build tag `e2e`; line 681 poll-interval sleep (convert),
  line 757 intentional outage-window sleep with its explanatory comment (D-13,
  MUST NOT convert)
- `e2e/helpers_test.go` — build tag `e2e || docker_e2e`, the tag split that
  makes D-14 necessary; line 216 bind-retry backoff
- `e2e/proc_harness_test.go` — build tag `proc_e2e`; six sleeps to triage
  under D-13

### Project Conventions

- `CLAUDE.md` — `task` over direct `go` invocations; conventional commit types
  and scopes (`ci`, `e2e`, `test`); ≥80% coverage gate
- `.planning/codebase/TESTING.md` — existing testing strategy
- `docs/contributing/testing.md` — contributor-facing testing docs; may need
  updating for the `RH_E2E_REQUIRE_DOCKER` convention introduced by D-06

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`ci-go-complete` aggregator pattern** (`ci-go.yml:136-175`): `if: always()`
  plus `needs:` plus an explicit per-job `!= "success"` result check. D-01
  extends this rather than inventing a new shape.
- **Existing job scaffolding** (`ci-go.yml:39-62`): checkout → `setup-go` with
  `go-version-file: go.mod` and `cache: false` → `nscloud-cache-action` → install
  `task` → run a task. The three e2e jobs follow this skeleton.
- **Taskfile e2e targets already exist** with correct dependencies:
  `test:e2e:docker` has `deps: ['docker:build']`, `test:e2e:proc` has
  `deps: ['build']`. CI jobs invoke these rather than raw `go test`, per
  CLAUDE.md.

### Established Patterns

- **Build-tag tiering:** `e2e`, `docker_e2e`, `proc_e2e` are three distinct
  tags. `helpers_test.go` is `e2e || docker_e2e` — `proc_e2e` cannot see it.
  This is the structural constraint behind D-14.
- **`Vulnerability check` precedent:** a context that is *both* separately
  required *and* inside `ci-go-complete`'s `needs`. Establishes that
  double-listing is acceptable here if a separate e2e check is ever wanted.
- **Negative controls are an established practice in this repo:** phase 08's
  chart RBAC assertions were each proven to fail before being accepted;
  plan 01-11 used revert-and-observe. D-10/D-11/D-16 continue that practice.
- **Honest not-run recording:** plans 09-05 and 01-08 recorded verifications as
  explicitly NOT-RUN rather than claiming completion. D-12 keeps that standard.

### Integration Points

- `ci-go.yml` gains three jobs and an extended `ci-go-complete`; the ruleset is
  untouched (D-01)
- `internal/testutil/wait` is a **new package**, imported by test files across
  all three build tags and, later, by Phase 3's harness (D-14)
- `e2e/docker_e2e_test.go`'s `requireDocker` gains an env-var branch (D-06)
- `/gsd-ship`'s ship-note commit and `ci-go.yml`'s trigger block both change
  under D-05

</code_context>

<specifics>
## Specific Ideas

- The `proc_e2e` red proof is specifically the **G-01-1 CLI-flag→config seam**
  regression — not an arbitrary bug. That defect shipped past the other two
  tiers and is the documented reason `proc_e2e` is a required gate. Reproducing
  it is what makes the proof mean something.
- `e2e/e2e_test.go:757`'s sleep is load-bearing and must survive this phase. Its
  existing comment already explains why; D-13 asks that the marker be made
  explicit enough to survive a future sweep.
- The user's standing position, restated during this discussion: **use GSD for
  what GSD does.** Artifacts GSD owns are written by GSD's verbs. This governs
  D-12 and applies to every `.planning/` file this phase touches.

</specifics>

<deferred>
## Deferred Ideas

- **Merge queue** — would implement CI-02's two-stage gating as literally
  worded (fast tier per-push, slow tiers on `merge_group`). Rejected for this
  phase as a repo-level ruleset change amounting to its own phase. D-03 is
  fully forward-compatible with adding it later.
- **Separate `E2E Complete` required check** — better failure-signal
  granularity; rejected under D-01 to avoid introducing a required-but-possibly-
  unreported context during the same phase that establishes gating.
- **Path-filtering the slow tiers** on docs-only diffs — a CI-minute
  optimization; parked pending Q-03's answer.
- **Nightly-scheduled e2e cadence and a flake-quarantine convention** —
  already recorded as out of scope for v0.14.0 in STATE.md Deferred Items.
  Noted here because "how does a flaky tier get quarantined without silently
  disabling a gate" is a real question this phase's gating will eventually
  raise.

</deferred>

---

*Phase: 1-CI Gating for the e2e Tiers*
*Context gathered: 2026-08-02*
