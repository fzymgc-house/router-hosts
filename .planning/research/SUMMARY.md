# Research Summary: v0.14.0 "Verification & Lazy Reads"

**Synthesis Date:** 2026-08-02  
**Milestone Status:** Three scoped, independent capabilities requiring synchronized delivery  
**Overall Confidence:** HIGH (grounded in source inspection, not domain generalization)

---

## Executive Summary

router-hosts v0.14.0 targets three internal quality/verification items that close gaps identified in earlier phases. The work is gap closure: wiring existing e2e tiers into CI to gate merges (addressing the G-01-1 blind spot), building a containerized deployment-verification harness to retire a hardware dependency, and refactoring server-side storage reads to be cursor-paginated and memory-bounded.

**Recommended approach:** Deliverable with no new external dependencies except testcontainers-go v0.43.0 (testing-only, build-tag quarantined). The work is well-scoped; the codebase's locked ADRs already establish design boundaries (D-21 watermark ordering, D-18/D-20 event ID sequencing, ADR router-hosts-v5b compaction semantics). The primary risk is accepting visible API compliance ("cursor added") as evidence of invisible requirement closure ("server memory is bounded"), repeating the TMPL-06 overreach that had to be amended.

**Key risks and mitigation:**

1. **Scoping trap:** Cursor pagination on `HostProjection` is necessary for `WatchHosts` but NOT sufficient for `ExportHosts` `hosts`/`json` formats because `FormatHostsFile` requires global sort before rendering. Mitigation: explicitly descope these formats or commit to storage-layer redesign.

2. **Repeat-mistake risk:** TMPL-06 showed "chunking outbound messages does not bound server-side memory if source still folds everything into memory." Any memory claim must be backed by concrete benchmark (AllocsPerRun/memstats against 10k+ fixture) with precise number.

3. **Anti-vacuity:** `docker_e2e_test.go` has `t.Skip` reporting green when Docker missing; `proc_e2e`'s binary-freshness check doesn't prove *currency*. Mitigation: hard-fail CI pre-checks (Docker availability, fresh builds) and require each tier demonstrated failing against deliberately-broken commit before acceptance.

---

## Key Findings by Research Category

### Stack Research

**Confidence: HIGH** (versions verified against pkg.go.dev, GitHub releases, Alpine index Aug 2026; runners confirmed against Namespace docs)

**New dependencies:**
- `github.com/testcontainers/testcontainers-go` v0.43.0 (compose module)
  - 3-container deployment-verification harness (Unbound + 2 sinks)
  - Build-tag quarantine: Must be behind new `convergence_e2e` tag to prevent shipped-binary bloat

**No new dependencies for cursor:**
- Uses existing `zombiezen.com/go/sqlite`
- New method: `ListPage(ctx, cursor string, limit int) (entries []domain.HostEntry, nextCursor string, err error)`
- SQL change only: keyset pagination on `aggregate_id` ULID (lexically sorted, resumable)

**Critical notes:**
- Alpine `unbound` 1.23.1-r1 (v3.22) or 1.25.2-r0 (edge): pin by digest in harness Dockerfile
- `docker compose` v2 plugin required on CI runners: verify as explicit pre-step (fail fast vs. skip)

---

### Features Research

**Confidence: MEDIUM** (internal quality work; no user-facing features to differentiate)

**Table Stakes (all required together):**
1. Three e2e tiers wired into CI as required checks (closes #403; tests exist and pass, pure CI wiring)
2. Tier-to-event gating: fast tier on PR, container/process tiers gate merge (proc_e2e is ONLY tier observing CLI flag/config resolution — the G-01-1 blind spot)
3. Wait-strategy-based readiness, not fixed sleeps (mandatory for harness given post-edit hooks run detached/async)
4. Real Unbound + two independent sink containers on shared network (UAT-42 convergence bar: resolver reload + two-node agreement)
5. Cursor must be aggregate-ID keyed, not event-ID or row-offset (compaction deletes and reseeds; event-row cursors dangle)
6. Explicit cursor compaction semantics (jump-to-seed, resume-signal, or error) written down and tested
7. Streaming reads bounded in memory (measured benchmark required; TMPL-06 lesson)

---

### Architecture Research

**Confidence: HIGH** (every claim traced to actual source files)

**Three mostly-independent capabilities with sequencing benefits:**

1. **Capability 1: CI Wiring** — Three new jobs in `.github/workflows/ci-go.yml`, extend `ci-go-complete` aggregator. Zero source changes. Risk: tier isolation under contention.

2. **Capability 2: Deployment-Verification Harness** — Extends `proc_e2e` design patterns; new runtime (compose + 3 containers). Convergence has TWO legs: (a) sidecar file change-ID match, (b) live DNS query returning new record. No server-side code changes.

3. **Capability 3: Cursor-Based Reads** — API-surface change (`ListPage` added); SQL query refactor. **SCOPING TRAP:** `WatchHosts` benefits fully; `ExportHosts` `hosts`/`json` formats still need global sort before rendering — cursor at read layer is **necessary but NOT sufficient**.

**Build order (risk-based):**
1. CI Wiring (zero risk, closes #403, establishes job pattern)
2. Cursor (protected by wired e2e tiers; harness built against final shape)
3. Harness (highest effort, validates end-state)

---

### Pitfalls Research

**Confidence: HIGH** (grounded in codebase history: G-01-1, TMPL-06 amendment, D-21 lesson)

**15 critical pitfalls organized by phase:**

#### CI Gating Phase (5 pitfalls)
1. **Docker-tier soft-skip reports green** → Add `docker info || exit 1` pre-step; fail if any `--- SKIP` in log
2. **`proc_e2e` runs against stale binary** → `task build` immediately before test in SAME job, no cache restore
3. **`e2e`/`docker_e2e` sufficient, `proc_e2e` deferred** → Branch protection MUST list `proc_e2e` as required
4. **Gate never observed failing (vacuous)** → PR must link CI runs on deliberately-broken branches showing each tier failing
5. **Flaky tiers disabled within weeks** → No fixed ports; polling with explicit deadline multiples; tier isolation

#### Deployment-Verification Harness Phase (5 pitfalls)
6. **Assertion on file diff, not live resolver** → Must include `dig`/`unbound-control lookup`; use actual hook mechanism
7. **Negative caching / stale entries masking** → No pre-queries; UPDATE assertions use exact-set equality
8. **Vacuous convergence (timeout-as-success)** → Polling helper returns explicit `converged bool`; assert pre/post divergence
9. **Multi-container startup races** → Use `depends_on: condition: service_healthy` with real healthchecks
10. **Loopback assumptions breaking in bridge networking** → No `127.0.0.1` literals; explicit cross-container DNS smoke test

#### Cursor-Based Lazy Reads Phase (5 pitfalls)
11. **Cursor dangling on event rows post-compaction** → Cursor MUST be aggregate-ID keyed; test compaction mid-stream
12. **Re-derived membership per page silently drops entries** → Watermark captured BEFORE iteration (D-21 pattern)
13. **Unproven "bounded memory" claim (TMPL-06 repeat)** → Benchmark test required; `AllocsPerRun` against 10k+ fixture with precise bound
14. **Accidental materialized read model introduction** → No cross-call server-side cache/snapshot
15. **Long-held read transaction colliding with WriteQueue** → One transaction per page (like `ListAll`'s `withConn`)

---

## Implications for Roadmap

### Phase 1: CI Gating (e2e Tiers into CI)

**Delivers:** Three tiers wired as CI jobs; #403 closed; G-01-1 blind spot addressed  
**Features:** Tier wiring, tier-to-event gating, wait-strategy conventions  
**Pitfalls to avoid:** All 5 CI-gating pitfalls (soft-skip, stale binary, proc_e2e optional, vacuous gates, flakiness)  
**Acceptance criteria:** Hard-fail Docker pre-check; vacuity test showing each tier failing on deliberately-broken commits  
**Research needed:** None — code exists and proven  
**Confidence:** HIGH

### Phase 2: Cursor-Based Streaming Reads

**Delivers:** `ListPage()` on `HostProjection`; `WatchHosts` refactored to page internally; streaming memory bounded  
**Features:** Cursor interface (aggregate-ID keyed), compaction semantics defined, measured memory claim  
**Pitfalls to avoid:** All 5 cursor pitfalls (event-row dangling, re-derived membership, unproven memory, accidental cache, long-held transaction)  
**Must decide before planning:**
  - **Compaction semantics:** When cursor lands mid-compacted history, what happens? Jump-to-seed, resume-signal, or error? Must be written down and tested.
  - **ExportHosts scope:** Descope `hosts`/`json` global-sort requirement (leave fully materialized), or redesign storage layer?

**Acceptance criteria:** Benchmark shows memory scales with page size only; compaction test exists; cursor semantic decision documented  
**Research needed:** Compaction behavior is a DESIGN DECISION, not a hidden risk — must be made during planning  
**Confidence:** MEDIUM–HIGH

### Phase 3: Deployment-Verification Harness

**Delivers:** Real Unbound + 2 sink containers; resolver-reload + two-node convergence assertions; UAT-42 passing  
**Features:** Real harness (green not built), wait-strategy readiness, live DNS convergence oracle  
**Pitfalls to avoid:** All 5 harness pitfalls (file-diff assertion, negative cache, vacuous convergence, startup races, loopback)  
**Acceptance criteria:**
  - UAT item #42 passes (resolver reload + two-node convergence)
  - Four deferred manual deployment checks execute and pass
  - Each pitfall guard visible in final code/config

**Research needed:** None — `proc_e2e` docs already design extension points  
**Confidence:** HIGH

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|-----------|-------|
| Stack | HIGH | Versions verified against current package indexes; runners confirmed vs. Namespace docs |
| Features | MEDIUM–HIGH | Grounded in locked PROJECT.md; cursor compaction semantics awaits explicit design choice (not an unknown) |
| Architecture | HIGH | Every claim traced to actual source; build order clear; scoping trap explicit |
| Pitfalls | HIGH | Grounded in codebase history (G-01-1, TMPL-06); acceptance criteria specific and verifiable |

**Gaps requiring planning-phase resolution:**
- Cursor compaction semantics (jump, signal, or error) — design decision, not research gap
- ExportHosts format scope (descope or redesign) — scoping decision
- Memory measurement rig (fixture size, benchmark pattern, bounds) — set during planning

---

## Summary for Roadmapper

Three capabilities, all required together. Mostly independent; sequencing matters for risk and avoiding rework. Build order: **CI Gating (Phase 1)** → **Cursor (Phase 2)** → **Harness (Phase 3)**.

**Critical cross-cutting requirements (all phases):**
- Memory claims backed by measured benchmarks (TMPL-06 lesson)
- New CI gates demonstrated failing against deliberately-broken commits (G-01-1 lesson)
- Wait-strategy readiness mandatory; no fixed sleeps
- Cursor aggregate-ID keyed, never event-row keyed

**Three explicit planning questions:**
1. Cursor compaction behavior when landing mid-compacted history?
2. ExportHosts `hosts`/`json` format scope: descope or redesign?
3. Memory measurement rig specifics (fixture size, benchmark pattern, bound)?

---

*Research synthesis for: router-hosts v0.14.0 — Verification & Lazy Reads*  
*Synthesis: 2026-08-02*
