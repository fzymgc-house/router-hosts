# Phase 2: Cursor-Based Lazy Storage Reads - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-03
**Phase:** 2-Cursor-Based Lazy Storage Reads
**Areas discussed:** ExportHosts format scope, Cursor API shape & granularity, Mid-stream consistency contract, Benchmark rig & asserted bound

---

## Area Selection

All four proposed gray areas were selected for discussion. Two further items —
call-site migration scope and the mechanical form of LAZY-04's proof — were
offered as Claude's discretion but ended up discussed explicitly (D-04, D-14).

---

## ExportHosts Format Scope

### Q1 — the LAZY-02 premise mismatch

Raised after the codebase scout found that `ListAll` already reassigns `events`
per aggregate and `replayEvents` retains no reference to the slice, so peak
memory never scaled with total event-log size.

| Option | Description | Selected |
|--------|-------------|----------|
| Amend to entry count | Restate LAZY-02/SC2 as page-size-vs-total-entry-count via the GSD verb surface with sign-off; TMPL-06 precedent | ✓ |
| Keep wording, benchmark entries | Leave the requirement, record the discrepancy in the phase SUMMARY instead | |
| Verify before deciding | Treat the read as a hypothesis; have research prove it by measurement first | |

**User's choice:** Amend to entry count
**Notes:** Rule `01ygyqn0by` governs — no agent hand-edits REQUIREMENTS.md. TMPL-06's 2026-07-31 amendment is the standing precedent for a public requirement correction.

### Q2 — the `hosts` format's global sort

| Option | Description | Selected |
|--------|-------------|----------|
| Descope, name the residual | Drain, sort, render; document residual O(N entries) per REQUIREMENTS.md:123 | ✓ |
| Two-pass key sort | Pass 1 collects sort keys only, pass 2 re-fetches in order; real reduction, but the passes can disagree | |
| Sort in SQL | json_extract + expression index — a materialized read model, explicitly Out of Scope | |

**User's choice:** Descope, name the residual
**Notes:** REQUIREMENTS.md:123 already anticipates exactly this residual, so no amendment is needed for it.

### Q3 — streaming json and csv

| Option | Description | Selected |
|--------|-------------|----------|
| Stream both | Writer flushing at the existing 64 KiB boundary; kills all three materializations | ✓ |
| Stream csv only | csv.Writer is trivially streamable; json keeps buffered MarshalIndent, zero LAZY-04 risk | |
| Neither — page the store read only | Interface change lands but ExportHosts' peak is unchanged | |

**User's choice:** Stream both
**Notes:** The named risk — reproducing `MarshalIndent(out, "", "  ")` byte-for-byte — became research question Q-05, with buffered json as the stated fallback.

### Q4 — call-site migration scope

| Option | Description | Selected |
|--------|-------------|----------|
| Named two + free wins | ExportHosts, WatchHosts, service.go:200 count-only, projection.go:78/:92 | ✓ |
| Named two only | Tightest scope, maps 1:1 onto LAZY-02 | |
| Every read path | Adds the three regeneration writers, which would be descoped anyway | |

**User's choice:** Named two + free wins
**Notes:** `commands.go:451` was the one site left unclassified; it became research question Q-04.

---

## Cursor API Shape & Granularity

### Q1 — the published interface

| Option | Description | Selected |
|--------|-------------|----------|
| Keyset page function | Stateless `ListPage(ctx, after, limit)`; visibly a cursor, caller owns page size, resumable | ✓ |
| Stateful cursor object | Only shape that can hold a read snapshot; needs lifecycle management and a long-lived read txn | |
| iter.Seq2 range-over-func | Most idiomatic for Go 1.26, but hides paging and reads as an internal optimization | |

**User's choice:** Keyset page function
**Notes:** Accepted consequence — `withConn` returns its pool connection per call, so no cross-page snapshot is available. That trade is what the consistency contract documents.

### Q2 — granularity and LAZY-03

| Option | Description | Selected |
|--------|-------------|----------|
| Per-aggregate, entry-counted | LAZY-03's scenario unreachable by construction; document it, test the two reachable variants | ✓ |
| Per-aggregate, event-budgeted | Bounds the deep-aggregate term too; complicates keyset arithmetic and the asserted bound | |
| Per-event cursor | Makes LAZY-03 literally reachable, but requires buffering partial replay state for an API nobody asked for | |

**User's choice:** Per-aggregate, entry-counted
**Notes:** The deep-aggregate term stays unbounded, with ADR `router-hosts-vl8`'s manual compaction as its stated remedy. Event-budgeted pages recorded as a deferred idea.

### Q3 — ListAll's fate

| Option | Description | Selected |
|--------|-------------|----------|
| Thin wrapper over ListPage | One read path to verify; ordering becomes definitionally identical | ✓ |
| Keep both implementations | Zero regression risk to untouched callers, but two paths that can drift | |
| Remove ListAll | Cleanest final interface; contradicts the scoping decision | |

**User's choice:** Thin wrapper over ListPage
**Notes:** Consequence surfaced during the question — the new ORDER BY reaches all seven untouched callers, which drove the golden-fixture coverage decision.

### Q4 — page-fill semantics

| Option | Description | Selected |
|--------|-------------|----------|
| Fill to N live entries | Short page means only `done`; avoids the empty-but-not-done bug shape | ✓ |
| N aggregates scanned per page | Precise work bound per call; every caller must handle empty-not-done forever | |
| Fill to N, capped by scan count | Bounds both; costs a second knob and reintroduces the rare empty page | |

**User's choice:** Fill to N live entries
**Notes:** `sendExportChunks`' review-L14 carve-out cited as the precedent — this repo has already paid once for a drain loop breaking on an empty response.

---

## Mid-Stream Consistency Contract

### Q1 — what a paged read promises

| Option | Description | Selected |
|--------|-------------|----------|
| Document the precise weak contract | Exactly-once in ascending ULID order for aggregates present at start; page-instant value freshness | ✓ |
| Fence with LatestEventID | Detects a torn export; costs a second contract surface and an unbounded retry question | |
| Hold a read snapshot | True consistency; requires reversing the API-shape decision | |

**User's choice:** Document the precise weak contract
**Notes:** Continuous with TMPL-08's deliberate change-ID-before-read ordering and with issue #401's deferred atomic read. Fencing recorded as a deferred idea.

### Q2 — the ordering contract

| Option | Description | Selected |
|--------|-------------|----------|
| Declare it, pin it, verify no drift | Ascending ULID becomes contract; empirically check it matches today's de-facto DISTINCT order | ✓ |
| Declare it, accept a diff if any | Faster, but LAZY-04 has no carve-out, so it would need amending too | |
| Explicitly not a contract | Keeps future freedom; undercut because golden fixtures would depend on the order anyway | |

**User's choice:** Declare it, pin it, verify no drift
**Notes:** The empirical check became research question Q-01, explicitly to be settled by execution rather than by reading the query.

---

## Benchmark Rig & Asserted Bound

### Q1 — what the benchmark asserts

| Option | Description | Selected |
|--------|-------------|----------|
| Ratio across two fixtures | ~1k and ~10k; paged path flat while drained path scales linearly; survives runner differences | ✓ |
| Absolute ceiling on one fixture | Easiest number to quote; machine- and version-sensitive, becomes a bumped magic number | |
| Record, don't assert | Satisfies LAZY-02's literal wording with zero flake; buys no regression protection | |

**User's choice:** Ratio across two fixtures
**Notes:** States the amended LAZY-02 claim directly rather than encoding a machine-specific number.

### Q2 — fixture composition

| Option | Description | Selected |
|--------|-------------|----------|
| Mixed depth plus deleted | Exercises the deep-aggregate term and the fill-to-N loop — the design's two weakest points | ✓ |
| Uniform shallow | Cleanest signal, fastest to build; measures only the happy path | |
| Replay a real store | Most credible distribution; needs a capture that doesn't exist and hurts assertion stability | |

**User's choice:** Mixed depth plus deleted

### Q3 — where the assertion runs

| Option | Description | Selected |
|--------|-------------|----------|
| Own build tag + CI job | Keeps the measurement out of the `-race` matrix that would distort allocation accounting | ✓ |
| Normal task test matrix | Simplest wiring; inherits `-race`, weakening the exact claim being made | |
| Own tag, not in the required set | Isolates flake; a tier that can't block a merge isn't load-bearing | |

**User's choice:** Own build tag + CI job
**Notes:** RED proof required on a Linux runner before acceptance — Phase 1 D-16 plus memory `cq0rfk0qjc`.

### Q4 — proving LAZY-04

| Option | Description | Selected |
|--------|-------------|----------|
| Golden fixtures captured pre-change | Committed before any behavior change; covers ExportHosts formats, client templates, and the three regeneration writers | ✓ |
| Differential old-vs-new in-process | Catches more input shapes via rapid; costs carrying dead code and vanishes when deleted | |
| Extend existing tests | Smallest diff; "existing tests still pass" is not the byte-identical claim | |

**User's choice:** Golden fixtures captured pre-change
**Notes:** Coverage deliberately includes the three non-migrating regeneration writers, because the ListAll-as-wrapper decision puts them downstream of the new ordering.

---

## Claude's Discretion

- Exact `ListPage` signature and option surface within the chosen shape
- Default page size and whether it is a constant, a package var, or caller-only
- Whether the deleted-aggregate filter runs in SQL or in Go after replay
- The streaming writer's internal shape, given the 64 KiB boundary and the
  empty-payload single-message behavior are preserved
- Build-tag name, runner profile, and timeout for the benchmark job
- Whether `SnapshotComplete.Count` accumulates during paging or is derived

## Deferred Ideas

- Event-budgeted pages — would bound the deep-aggregate term; revisit if a real
  deployment produces an aggregate deep enough to matter
- Two-pass key sort for the `hosts` format — genuine peak reduction without an
  index; collides with the chosen consistency contract
- Stateful cursor object holding a read snapshot — reconsider alongside issue
  #401's atomic read
- Fencing with `LatestEventID` so a caller can detect a torn export — the
  cheapest available upgrade if operators report inconsistent exports
