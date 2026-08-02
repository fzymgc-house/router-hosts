# Feature Research

**Domain:** Internal quality/verification tooling for an event-sourced Go control plane (CI test-tier gating, containerized deployment verification, cursor-based streaming reads)
**Researched:** 2026-08-02
**Confidence:** MEDIUM

**Calibration note:** v0.14.0 is internal quality work, not new user-facing capability. There are no competing products or end-user features to differentiate on. This document is thinner than a typical FEATURES.md by design — where a category is genuinely empty (e.g. Competitor Feature Analysis) it says so rather than inventing content.

## Feature Landscape

### Table Stakes (Must Be True For This Milestone To Be Considered Done)

These aren't "nice to have" — PROJECT.md already scoped v0.14.0 tightly around exactly these three items (closes #403, #400, #401, #23), and the "harness bar is green-not-built": a harness that exists but doesn't pass leaves the gap open exactly as before.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| All three e2e tiers wired into `ci-go.yml` as required checks | #403 is explicitly the closing criterion; none of `e2e`, `docker_e2e`, `proc_e2e` currently run in CI despite existing in the codebase | LOW–MEDIUM | Tiers and build tags (`e2e`, `docker_e2e`, `proc_e2e`) already exist from v0.13.0 Phase 1 — this is CI wiring, not new test code |
| Tier-to-event mapping: fast tier on every PR, container/process tiers gate merge to `main` | Standard practice across every source found: unit/fast tests gate PRs cheaply; container- and process-based tiers are expensive enough that gating merge (not every push) is the common pattern | LOW | `proc_e2e` is explicitly the only tier that observes CLI-flag→config resolution (the blind spot that shipped a bound-but-unread `--config` through 45 green UAT checkpoints) — it must run before merge, not be optional |
| Wait-strategy-based readiness checks, not fixed sleeps | Universal finding across every CI/testcontainers source: fixed sleeps are the single largest cause of tier flakiness, and pass/fail differently across CI runner speeds | LOW | Directly relevant here: post-edit hooks run **detached from the write path** (v0.12.0 Phase 9, D-HOOK-01). Any container/process check that asserts "the reload happened" MUST poll with a bounded timeout — a synchronous assumption will be flaky by construction given this codebase's own async-hook design |
| Single aggregated required-check / branch-protection gate across all tiers | When tiers run as separate parallel CI jobs (recommended, not one serialized job), branch protection needs one job that `needs:` all tiers and fails if any failed — otherwise merges can slip through on a tier nobody actually made required | LOW | Direct wiring task once tiers exist as jobs |
| Deployment harness: real Unbound container + two independent sink containers, no second physical machine | This is the literal replacement PROJECT.md scopes for the hardware-dependent gap; UAT-42 (resolver reload + two-node convergence) and four manual deployment checks are named as the pass bar | MEDIUM–HIGH | No ready-made Go `testcontainers-go` Unbound module exists (Java ecosystem has one — `unbound-testcontainers`); router-hosts needs a custom container/config-mount setup, likely reusing the `docker_e2e` tier's existing container patterns |
| Resolver-reload check asserts a real DNS answer, not a file/process signal | "Credible" reload verification means issuing an actual DNS query against the running Unbound container after zone regeneration and asserting the record value (or NXDOMAIN for removed names) — asserting only "file changed" or "container healthy" proves nothing about whether Unbound actually loaded it | MEDIUM | Directly exercises the locked per-name `static` zone design (ADR router-hosts-bzg) — the check should assert exactly the per-name zone behavior that ADR mandates, e.g. an unmanaged sibling name still resolves normally (no zone-wide NXDOMAIN leak) |
| Convergence check asserts state equality, not "no error" | A credible check compares the same observable both sinks are supposed to agree on — this project already has the right primitive: the monotonic change ID every `WatchHosts` snapshot carries (v0.13.0 TMPL-08). Two independent sinks reporting the same change ID for the same host state is a real convergence assertion; "both processes exited 0" is not | MEDIUM | Reuses existing infrastructure — this is an argument for LOW added complexity relative to inventing a new convergence primitive |
| Cursor over `HostProjection` reads is a monotonic position tied to existing event ordering, not a row offset | Every source on cursor pagination agrees: `OFFSET`-style pagination breaks under concurrent inserts (rows shift, causing skipped or duplicated reads); a stable cursor must be an opaque, order-preserving key | LOW–MEDIUM | Router-hosts already has the right ordering primitive to reuse: the in-transaction event-ID guard that re-mints IDs above `MAX(event_id)` (D-18/D-20) and the change ID defined as "ULID of the newest event." The cursor should be built on this existing ordering, not a new mechanism |
| Documented, explicit cursor behavior across a mid-stream compaction | This is the genuinely new semantics question the milestone raises — no prior art in this codebase defines it, and the research is unambiguous that *undefined* behavior here becomes silent data loss | MEDIUM | Concrete decision needed: when a cursor is positioned inside an aggregate's pre-compaction history and that aggregate gets compacted (ADR router-hosts-v5b — history deleted, replaced by one `HostCompacted` seed at the preserved OCC version), does the streaming reader (a) jump straight to the seed event, (b) return a defined "resume from seed" signal, or (c) error? Any of the three is acceptable **as long as it is written down and tested** — leaving it implicit is the anti-pattern |
| Streaming reads bounded in memory, replacing `store.ListAll` | #400/#401 — this is an explicit API-surface change to `storage.HostProjection`, not an internal optimization; PROJECT.md flags it as such | MEDIUM | `ExportHosts`/`WatchHosts` currently fold full event history into memory server-side before the first byte ships; this is the concrete performance defect the cursor work fixes |

### Differentiators (Beyond The Pass Bar — Worth Doing If Cheap)

This category is intentionally thin. Nothing here is required to close #403/#400/#401/#23; each item is a quality-of-life improvement on top of the table-stakes bar above.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Shared "wait-for-convergence" test helper reused across `docker_e2e`, `proc_e2e`, and the new deployment harness | Reduces duplicated polling/timeout logic and keeps flakiness-prevention consistent across all three tiers instead of reinventing it per test file | LOW | Natural byproduct of building the harness carefully the first time |
| Flake-quarantine convention (track and bound flaky-test rate rather than block merges on a single rerun) | Common industry pattern for keeping expensive tiers trustworthy over time without teams learning to bypass gates | LOW | Optional — router-hosts' e2e suite is small (homelab scale); a formal quarantine budget is more machinery than this suite currently needs. Worth revisiting only if `docker_e2e`/`proc_e2e` prove flaky in practice |
| Track-based gap list for streaming reads (record known gaps, revisit, expire after N positions) | The general event-sourcing answer to gaps in a globally-interleaved multi-writer log | N/A here — see Anti-Features | Explicitly **not needed**: see below |

### Anti-Features (Would Be Over-Engineering For This Codebase)

| Anti-Feature | Why It Looks Appealing | Why It's Wrong Here | Do Instead |
|--------------|------------------------|----------------------|------------|
| Generic multi-writer gap-detection/tracking subsystem (pending-gap list, timeout-based gap cleanup) | This is the standard event-sourcing answer to "what if the projection observes event 11 before event 10 commits" | Router-hosts serializes **all** writes through a single-goroutine `WriteQueue` (constraint already locked in PROJECT.md) — the concurrent-out-of-order-commit race this machinery exists to solve cannot occur here by construction. Building it solves a problem this architecture doesn't have | Rely on the existing single-writer serialization + the in-transaction event-ID guard (D-18/D-20) that already guarantees gap-free, monotonic ordering |
| Distributed exactly-once delivery guarantees for streaming reads | Sounds like the "correct" answer for a consumer-facing streaming API | Every event-sourcing source surveyed agrees this is a distributed-systems problem out of scope for a library; router-hosts' sink already handles at-least-once delivery correctly today (idempotent snapshot application, reconnect with jittered backoff — TMPL-01…08) | Keep consumers idempotent on change ID, as the existing sink already does; do not add delivery-guarantee machinery to the storage layer |
| Nightly-scheduled e2e run as a distinct CI cadence | Common pattern in larger orgs (fast/PR tier, integration/merge tier, nightly/full-regression tier) | Nothing in this project's scope or PROJECT.md calls for a fourth cadence; adding a nightly schedule is CI-scheduling machinery this milestone doesn't need and wasn't asked to build | Two gating events only: PR (fast tier) and merge to `main` (container + process tiers) — matches the three tiers this project actually has |
| Second physical machine for deployment verification | Was the actual prior approach | This is precisely the gap v0.14.0 closes — flagged explicitly as what the containerized harness replaces | Two sink containers + one Unbound container on a shared Docker network, as scoped |
| Convergence check based on container/process exit status or health-check-only signals | Simplest thing to implement | Proves the process didn't crash, not that state converged — this is the textbook "check that always passes" flakiness trap the research calls out repeatedly | Assert on the actual monotonic change ID / DNS answer, per Table Stakes above |
| `GetAtTime`-style point-in-time replay revived to give cursor consumers a way to "look behind" a compaction | Feels like the natural fix if a cursor lands mid-compacted-aggregate | Already sacrificed and locked (ADR router-hosts-4w2) with no production caller; reviving it to serve a cursor edge case is exactly the kind of scope creep that ADR pre-empted | Define the cursor's post-compaction behavior as "jump to seed" (or an explicit resume signal) — consistent with the same tradeoff already accepted for `GetAtTime` |

## Feature Dependencies

```
CI tier gating (item 1)
    └──requires──> existing e2e/docker_e2e/proc_e2e build tags & test code (v0.13.0 Phase 1, already shipped)
    └──requires──> CI runner with Docker available (for docker_e2e, and the harness below)
    └──enhanced-by──> deployment-verification harness (item 2) — the harness is a natural
                       extension point for docker_e2e/proc_e2e, per PROJECT.md's own note

Deployment-verification harness (item 2)
    └──requires──> split-horizon unbound per-name static zone output (Phase 5, ADR router-hosts-bzg)
    └──requires──> WatchHosts / render / watch consumer sink infra (v0.13.0 Phase 1, TMPL-01..08)
    └──requires──> monotonic change ID per snapshot (v0.13.0 TMPL-08) — this is the convergence
                    assertion's actual payload
    └──requires──> awareness that post-edit hooks run detached/async (v0.12.0 Phase 9) — the
                    harness MUST poll with a bounded timeout, never assume synchronous reload

Cursor-based streaming reads (item 3)
    └──requires──> in-transaction event-ID ordering guard (D-18/D-20) — the ordering primitive
                    the cursor is built on
    └──requires──> change ID = ULID of newest event, derived before ListAll (D-21)
    └──interacts-with──> HostCompacted seed compaction (ADR router-hosts-v5b) — defines the one
                          genuinely new semantics question this milestone must answer
    └──inherits-tradeoff-from──> GetAtTime sacrifice across compaction (ADR router-hosts-4w2) —
                                  the same "post-compaction history is gone" reality applies to
                                  a cursor as it does to GetAtTime; do not re-litigate it
    └──changes──> storage.HostProjection interface (explicitly an API-surface change per
                  PROJECT.md, not an internal implementation swap)
```

### Dependency Notes

- **CI tier gating requires the harness to be green, not merely runnable.** PROJECT.md is explicit: "the harness bar is green-not-built... a harness that exists but has not retired the gap leaves phase 1 blocked exactly as before." Wiring `proc_e2e`/`docker_e2e` into CI before UAT-42 and the four manual deployment checks actually pass would satisfy #403's letter while leaving its purpose unmet.
- **The convergence check's correctness depends entirely on reusing the existing change-ID primitive.** Building a bespoke "convergence" concept (e.g. diffing rendered file contents byte-for-byte) would duplicate what TMPL-08's monotonic change ID already gives for free, and would be more fragile (file diffs are sensitive to template whitespace/ordering; change-ID comparison is not).
- **Cursor compaction semantics inherit from, rather than reopen, ADR router-hosts-4w2.** That ADR already accepted "point-in-time replay across compacted aggregates is broken, no caller needs it." A cursor is a different consumer than `GetAtTime`, so it needs its own explicit answer — but that answer should be "compaction is visible as a defined jump/resume signal," not "let's bring back history retention to avoid the question."

## MVP Definition

### Launch With (v0.14.0)

This milestone has no smaller MVP to slice — PROJECT.md already scoped it as the minimum set closing four issues. All three are required together because the CI-gating item's value depends on the harness being green.

- [ ] Three e2e tiers wired into `ci-go.yml` with tier-appropriate gating (PR for fast tier, merge for container/process tiers) — closes #403
- [ ] Containerized deployment-verification harness (Unbound + two sink containers) passing UAT-42 and the four manual deployment checks it replaces
- [ ] Cursor-based `storage.HostProjection` reads for `ExportHosts`/`WatchHosts`, with explicit, tested behavior for a cursor spanning a mid-stream compaction — closes #400/#401/#23

### Add After Validation

- [ ] Shared wait-for-convergence test helper, if the three tiers end up duplicating polling logic during implementation
- [ ] Flake-quarantine convention, only if `docker_e2e`/`proc_e2e` prove flaky in practice after landing in CI

### Future Consideration (Not This Milestone)

- [ ] Multi-writer / distributed event store — would reopen the gap-detection question this milestone deliberately doesn't need to answer. No indication in PROJECT.md this is coming.

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Wire three e2e tiers into CI as required checks | HIGH (closes a known CI gap, #403) | LOW–MEDIUM | P1 |
| Containerized Unbound + two-sink deployment harness | HIGH (retires hardware dependency, closes UAT-42) | MEDIUM–HIGH | P1 |
| Cursor-based `HostProjection` reads with defined compaction semantics | HIGH (fixes a real server-side memory defect, #400/#401/#23) | MEDIUM | P1 |
| Shared convergence-wait test helper | LOW–MEDIUM (DX only) | LOW | P2 |
| Flake-quarantine convention | LOW (preventive) | LOW | P3 |

**Priority key:**
- P1: Required — this is the entire scope of v0.14.0
- P2: Should have if it falls out cheaply during implementation
- P3: Nice to have, revisit only if flakiness materializes

## Competitor Feature Analysis

N/A. This is internal quality/verification tooling for an existing homelab control plane, not a market-facing product feature. There is no competitor set to analyze — the relevant comparison points (industry CI-tiering conventions, testcontainers patterns, event-sourcing cursor/gap-detection literature) are captured in the Table Stakes and Anti-Features sections above instead of being force-fit into a competitor matrix.

## Sources

- `binarylog.dev` — "Building Real Integration Tests in Go with Testcontainers" (2026-06-13) — Go-specific testcontainers patterns, build tags, wait strategies, CI staging — MEDIUM confidence (single-author blog, but corroborated by multiple independent sources below)
- `ardura.consulting` — "CI/CD Testing Integration: Step-by-Step Setup Guide" (2026-03-16) — tier-to-event gating conventions (PR/merge/nightly), flake-budget concept — MEDIUM confidence
- GitHub PR `Zipstack/unstract#2151` — real-world CI restructure into unit/integration/e2e jobs with one aggregated required-check job — MEDIUM confidence (primary source, actual shipped CI config)
- `github.com/testcontainers/workshop-go` — official Testcontainers Go workshop, e2e-with-real-dependencies step — MEDIUM-HIGH confidence (vendor-adjacent, official examples repo)
- `gitlab.com/buralo/oss/unbound-testcontainers` — Unbound-specific testcontainers module (Java) — MEDIUM confidence, directly relevant prior art for the DNS-resolver harness question, though no Go equivalent exists
- `gethook.to/blog` — "Cursor-Based Pagination and Event Replay" — cursor vs. offset pagination, compound-key cursors — MEDIUM confidence
- `docs.ecotone.tech` and `blog.ecotone.tech` — gap detection and consistency in event-sourced global projections, partitioned-vs-global projection gap analysis — MEDIUM confidence (vendor docs for a real event-sourcing framework, cross-corroborated across two of their own posts)
- `sidorenko.me/blog` — "Eventium: Design Decisions and Internals" — auto-increment IDs are not gap-free under concurrency, single-writer serialization eliminates the class of problem — MEDIUM confidence, and directly corroborates why router-hosts' existing single-writer `WriteQueue` constraint already avoids the gap-detection problem
- `planetgeek.ch` — "Event Sourcing: temporally misplaced or duplicated events" (2026-06-16) — practitioner experience on duplicate/misplaced events in long-running event-sourced systems — MEDIUM confidence
- `.planning/PROJECT.md` (this repo) — authoritative source for existing architecture, locked ADRs, and exact milestone scope

---
*Feature research for: router-hosts v0.14.0 — Verification & Lazy Reads*
*Researched: 2026-08-02*
