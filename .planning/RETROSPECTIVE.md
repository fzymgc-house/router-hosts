# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v0.13.0 — Consumer-Owned Output

**Shipped:** 2026-08-02 (PR #404)
**Phases:** 1 | **Plans:** 11 | **Tasks:** 32

### What Was Built

- A `WatchHosts` bidirectional streaming RPC serving host data as structured
  messages, consumed by `render` (one-shot) and `watch` (continuous sink)
- A documented, versioned template data contract with a version gate that refuses
  an undeclared or mismatched template before any connection or write, plus a
  shared sanitizing FuncMap closing the #349 newline-injection class
- A monotonic change ID (`internal/eventid` generator + an unconditional
  in-transaction ordering guard in sqlite's `insertEvent`) so `MAX(event_id)`
  cannot fail to advance across a real state change
- Bounded wire messages in both directions with client-side entry and byte
  ceilings that refuse rather than truncate
- Per-consumer sink health keyed by verified mTLS common name, projected through
  seven OTel gauges, plus a local sidecar status file
- A third e2e tier (`proc_e2e`) running the shipped binary as real OS processes

### What Worked

- **Cross-AI plan review before execution.** Reviewers (codex + pi) independently
  found the change-ID derivation-order defect from opposite directions, before a
  line was written. All 8 plans were revised in place; plan count and wave
  structure survived unchanged, which suggests the review caught semantics rather
  than structure.
- **Revert-and-observe as the standard for regression tests.** Several plans
  required demonstrating a new test FAILING against pre-fix code before accepting
  it. That is what distinguished a real regression test from one that passes
  vacuously.
- **Recording NOT-RUN honestly.** UAT test 42 and four manual deployment checks
  were recorded as not-run rather than assumed, quietly skipped, or marked pass.
  The debt stayed visible all the way into the PR body and the milestone audit.

### What Was Inefficient

- **A blocker shipped green through 45 UAT items.** `--config` was registered but
  never read, so `watch --config <path>` silently dialed whatever XDG discovery
  found. Two gap-closure plans (01-10, 01-11) were needed after UAT. The root
  cause was a test-harness blind spot, not a coding slip: both existing e2e tiers
  drive the client in-process and structurally cannot observe CLI-flag resolution.
- **The fix's own regression control still does not gate merges.** `proc_e2e`
  exists and passes, but no e2e tier runs in `ci-go.yml` (#403). The control that
  would have caught G-01-1 is outside the gate that would have stopped it.
- **A requirement had to be amended mid-milestone.** TMPL-06 originally claimed
  "O(1) memory", which chunked sends do not deliver. Caught in review, rewritten
  as bounded wire messages with client backpressure, storage-layer laziness
  descoped to #400/#401. Better caught then than claimed at ship.

### Patterns Established

- **Derive-before-read ordering:** a change ID minted strictly *before* the
  corresponding `ListAll`, making it a lower bound on the entries it accompanies.
  The intuitive reverse makes it an upper bound, which a client-side skip turns
  into a permanently stale consumer that self-reports converged.
- **Neutral contract package:** `internal/contract` owns the version constant so
  neither server nor client package owns the other's.
- **Package-level `var` (not `const`) for test-lowerable bounds**, so a test can
  shrink a ceiling instead of seeding 50,000 entries.
- **Any CLI-surface claim must be proven in `proc_e2e`.** In-process tiers cannot
  see the flag-to-config seam.
- **Single shared sanitizer** (`internal/sanitize.CommentField`) reachable from
  both server generators and the client template FuncMap, so the two cannot
  diverge.

### Key Lessons

1. **A test tier's vantage point is part of its contract.** Both pre-existing e2e
   tiers were real and passing and still could not see the defect. Coverage
   percentage said nothing about it. Ask what a tier structurally cannot observe.
2. **Reviews that find semantic inversions pay for themselves.** The
   derivation-order and lost-update findings were not style notes; either would
   have produced a consumer that reports itself healthy while serving stale DNS.
3. **Overclaiming in a requirement is a defect in the requirement.** TMPL-06's
   "O(1) memory" would have shipped as a false guarantee. Amend the requirement,
   do not quietly under-deliver against it.
4. **A gate that cannot fail is worse than no gate.** Recurring theme this
   milestone — the `[ci skip]` ship note, the in-process e2e blind spot, and
   `rg --` swallowing its own filters all produced green signals that tested
   nothing.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Notable process change |
|-----------|--------|-------|------------------------|
| v0.10.13 | 6 | shipped pre-GSD | Baseline reconstructed retrospectively at bootstrap |
| v0.11.0 | 2 | 11 | Operator/Gateway-API parity; chart RBAC assertions with negative controls |
| v0.12.0 | 1 | 5 | Hook metrics wired (were dead code); execution detached from write path |
| v0.13.0 | 1 | 11 | Cross-AI plan review before execution; third e2e tier; retroactive security audit |

### Recurring Themes

- **Dead or vacuous controls keep surfacing.** v0.12.0 found hook metrics that
  were registered but never recorded. v0.13.0 found an e2e blind spot, a `[ci
  skip]` that silently blocked required checks, and stale VALIDATION.md commands
  that exit 0 while testing nothing. Worth an explicit "prove it goes red" habit.
- **Deferred verification concentrates on hardware.** Both v0.12.0 (OTel scrape)
  and v0.13.0 (resolver reload, two-node convergence) deferred exactly the checks
  needing real infrastructure. Backlog 999.2 exists to stop this recurring.
