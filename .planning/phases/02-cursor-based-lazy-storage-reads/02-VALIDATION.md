---
phase: 2
slug: cursor-based-lazy-storage-reads
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-03
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Seeded from `02-RESEARCH.md` § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go `testing` + `stretchr/testify` v1.11.1; `pgregory.net/rapid` v1.3.0 available for property-based tests |
| **Config file** | none — plain `go test`, orchestrated via `Taskfile.yml` |
| **Quick run command** | `go test ./internal/storage/... ./internal/server/... -race -count=1` |
| **Full suite command** | `task test` |
| **Benchmark tier** | separate, **non-`-race`**, own build tag — `-race` distorts the quantity being measured |
| **Estimated runtime** | ~60s quick · ~5 min full suite |

---

## Sampling Rate

- **After every task commit:** Run `go test ./internal/storage/... ./internal/server/... -race -count=1` (excludes the benchmark tier — too slow/noisy per-commit)
- **After every plan wave:** Run `task test` (full `-race` suite) plus the benchmark tier once, non-`-race`, to catch a gross regression early
- **Before `/gsd-verify-work`:** `task test:coverage:ci` green, benchmark-tier CI job green with the LAZY-02 ratio assertion passing, RED-proof commit for the new gate linked (D-13)
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| {N}-01-01 | 01 | 1 | REQ-{XX} | T-{N}-01 / — | {expected secure behavior or "N/A"} | unit | `{command}` | ✅ / ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

*Populated per task during execution; the requirement→test map below is the authority on what each task must satisfy.*

### Requirement → Test Map (from RESEARCH.md)

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| LAZY-01 | `ListPage` keyset pagination, exactly-once-per-aggregate, ascending order | unit (storagetest conformance) | `go test ./internal/storage/... -run TestHostProjectionListPage -race` | ❌ Wave 0 |
| LAZY-01 | `ListAll` remains behavior-identical as a drain-loop wrapper | unit | `go test ./internal/storage/... -run TestHostProjectionListAll -race` | ✅ exists — must keep passing unmodified |
| LAZY-02 | Peak allocation ratio (1k vs 10k) flat for paged path, scaling for drained | benchmark, own build tag | `go test -tags lazybench -bench BenchmarkPeakMemory -benchtime 1x -run '^$' ./internal/storage/sqlite/` | ❌ Wave 0 — new file + new CI job |
| LAZY-03 | Cursor-not-yet-reached compaction → sees `HostCompacted` at preserved version | unit (storagetest conformance) | `go test ./internal/storage/... -run TestHostProjectionListPage_CompactionAhead -race` | ❌ Wave 0 |
| LAZY-03 | Cursor-already-passed compaction → invisible, prior value retained | unit (storagetest conformance) | `go test ./internal/storage/... -run TestHostProjectionListPage_CompactionBehind -race` | ❌ Wave 0 |
| LAZY-04 | `ExportHosts` `hosts`/`json`/`csv` byte-identical pre/post change | golden fixture (server) | `go test ./internal/server/... -run TestExportHosts_Golden -race` | ❌ Wave 0 — capture BEFORE any behavior change (D-14) |
| LAZY-04 | Client-side v0.13.0 template rendering byte-identical | golden fixture (client) | `go test ./internal/client/template/... -run TestTemplate_Golden -race` | ❌ Wave 0 — capture BEFORE any behavior change |
| LAZY-04 | Three non-migrating regeneration writers unaffected by D-10's ordering | golden fixture (server) | `go test ./internal/server/... -run 'TestFormatConf_Golden\|TestUnboundFormatConf_Golden\|TestHostsFile.*Golden'` | ✅ two exist; hosts-file equivalent confirmed/added in Wave 0 |
| LAZY-01/02 | D-10's `ORDER BY` reproduces today's de-facto order exactly (Q-01) | unit (storage) | `go test ./internal/storage/sqlite/... -run TestGetDistinctAggregateIDs_OrderMatchesDeFacto -race` | ❌ Wave 0 — pins the empirical finding against the real zombiezen driver |

---

## Wave 0 Requirements

- [ ] `internal/storage/storagetest/suite.go` — add `TestHostProjectionListPage*` conformance tests (keyset paging, exactly-once, ascending order, fill-to-N, deleted-aggregate skip)
- [ ] `internal/storage/storagetest/suite.go` — add `TestHostProjectionListPage_Compaction{Ahead,Behind}` (LAZY-03)
- [ ] `internal/storage/sqlite/projection_bench_test.go` — build-tagged peak-memory benchmark (LAZY-02), mirroring `append_bench_test.go`'s "own tag, outside `task test`" precedent
- [ ] `internal/server/` — byte-exact golden fixtures for `hosts`/`json`/`csv` captured **before** the streaming rewrite lands (D-14)
- [ ] `internal/client/template/` — byte-exact golden fixture for consumer-template rendering captured **before** any change (D-14)
- [ ] `.github/workflows/ci-go.yml` — benchmark-tier job + `ci-go-complete` `needs:` update (D-13)
- [ ] `Taskfile.yml` — task target for the benchmark tier, referenced by both local dev and the new CI job

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Peak-heap ratio interpretation | LAZY-02 | The automated assertion pins a ratio threshold, but judging whether the recorded absolute numbers are *honest* (flat-peak vs. cumulative-allocation artifact) requires reading the sampling methodology, not just the pass/fail | Read the benchmark's `runtime.MemStats.HeapAlloc` sampling loop; confirm it samples **during** the call rather than reporting `AllocsPerRun`/`-benchmem` cumulative totals, which scale with N for both paths and cannot distinguish them |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
