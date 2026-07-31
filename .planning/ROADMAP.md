# Roadmap: router-hosts

## Overview

router-hosts is an event-sourced, mTLS-secured DNS control plane with a CLI/TUI
and a Kubernetes operator, shipped through v0.12.0. Milestones v0.10.13 through
v0.12.0 built the baseline and then drove toward the north star — operator /
Gateway-API parity and hands-off cluster integration — finishing with hook
reliability.

**v0.13.0 opens a second axis:** moving output rendering from the server to the
consumer, so a single stateful server can feed N independent consumers without
accreting a per-resolver output format for each one.

> **Phase numbering restarted at v0.13.0.** Milestones v0.10.13–v0.12.0 used a
> single continuous sequence (phases 1–9). This milestone restarts at Phase 1.
> Where an archived document says "Phase 1" it means Event-Sourced Host Core;
> in this file and in v0.13.0's live artifacts, Phase 1 means Consumer-Rendered
> Output. Historical phase detail and phase directories are archived under
> `milestones/<version>-ROADMAP.md` and `milestones/<version>-phases/`.

## Milestones

### ✅ v0.10.13 — v1 Shipped Baseline

Phases 1–6 (previous numbering). Shipped pre-GSD; reconstructed retrospectively
at bootstrap (2026-07-07). Archived:
[`milestones/v0.10.13-ROADMAP.md`](milestones/v0.10.13-ROADMAP.md).

### ✅ v0.11.0 — K8s-Native Automation

Phases 7–8 (previous numbering). Shipped 2026-07-30 in PR #381; released as
v0.11.0 (version bump corrected by the follow-up `Release-As:` PR #382).
Operator / Gateway-API parity. Archived:
[`milestones/v0.11.0-ROADMAP.md`](milestones/v0.11.0-ROADMAP.md).

### ✅ v0.12.0 — Hook Reliability & Metrics

Phase 9 (previous numbering). Shipped 2026-07-31 in PR #389. Hook metrics wired
(were dead code) and hook execution detached from the write path with
configurable per-hook timeouts. Archived:
[`milestones/v0.12.0-ROADMAP.md`](milestones/v0.12.0-ROADMAP.md).

### 📋 v0.13.0 — Consumer-Owned Output

Phase 1. Approved 2026-07-25 from #364. **Current milestone.**

## Phases

**Phase Numbering:**

- Numbering is milestone-local from v0.13.0 onward and restarts at 1 each milestone
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (1.1, 1.2): Urgent insertions (marked INSERTED)

**v0.13.0 — Consumer-Owned Output:**

- [ ] **Phase 1: Consumer-Rendered Output (templates + sink)** - Caller-supplied templates, one-shot and as a continuous sink

## 📋 v0.13.0 — Consumer-Owned Output (Phase Details)

### Phase 1: Consumer-Rendered Output (templates + sink)

**Goal**: A consumer defines its own output format and keeps it current, so one stateful server feeds N independent consumers and new resolver formats stop requiring an upstream release.
**Depends on**: Nothing in this milestone. Builds on already-shipped surfaces — the event-sourced host core and `ExportHosts` streaming (v0.10.13, previous-numbering Phase 1) — so it starts from a green baseline rather than waiting on sibling work.
**Requirements**: TMPL-01, TMPL-02, TMPL-03, TMPL-04, TMPL-05, TMPL-06, TMPL-07
**Success Criteria** (what must be TRUE):

1. A caller supplies a template and receives host data rendered through it, with no code change to this project
2. The field set a template may reference is documented and versioned, and a template referencing an undefined key fails loudly rather than rendering empty
3. A render or write failure leaves any previously written artifact byte-identical, and a concurrent reader never observes a partially written file
4. Sink mode reflects a host mutation without operator intervention and recovers on its own after a connection interruption, without emitting a truncated artifact
5. Neither side of a stream can be driven out of memory by the other: the server yields lazily instead of materializing the full result set, and the client refuses an unbounded response rather than collecting it
6. Existing `unbound_conf_path` and `ExportHosts` format behavior is unchanged, demonstrated by existing tests still passing

**Plans**: TBD
**Status**: Not started — approved 2026-07-25 from #364 (`approved-feature`); absorbs #23 (lazy `ExportHosts` streaming) as TMPL-06 and #38 (client-side collection bound) as TMPL-07

**Highest-risk requirement**: TMPL-02. Once consumers depend on a template field
set, that set becomes a compatibility surface the proto contract does not cover
— renaming or removing a field breaks every consumer template even though the
proto is untouched. Decide the contract deliberately at plan time rather than
letting it default to whatever the internal struct exposes.

**Open for planning** (deliberately unresolved in the roadmap):

- Template engine — `text/template` is the default assumption (no new dependency), but the choice is a planning decision
- Transport for sink mode — client-initiated is preferred so the server holds no per-sink registration, credentials, or retry state; server-push was considered and rejected in #364

**Explicitly out of scope**: changes to `unbound_conf_path` (#349) and to the
existing `ExportHosts` format strings.

## Progress

**Execution Order:**
Single phase this milestone — Phase 1 stands alone.

**Current milestone (v0.13.0):**

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Consumer-Rendered Output | 0/TBD | Not started | - |

**Shipped (previous continuous numbering):**

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Event-Sourced Host Core | v0.10.13 | shipped | Complete | v0.10.13 |
| 2. Certificate Lifecycle | v0.10.13 | shipped | Complete | v0.10.13 |
| 3. Kubernetes Operator | v0.10.13 | shipped | Complete | v0.10.13 |
| 4. Observability | v0.10.13 | shipped | Complete | v0.10.13 |
| 5. Split-Horizon DNS Output | v0.10.13 | shipped | Complete | v0.10.13 |
| 6. Aggregate Compaction | v0.10.13 | shipped | Complete | v0.10.13 |
| 7. Gateway API Support | v0.11.0 | 6/6 | Complete | 2026-07-26 |
| 8. Service Controller | v0.11.0 | 5/5 | Complete | 2026-07-30 |
| 9. Hook Reliability & Metrics | v0.12.0 | 5/5 | Complete | 2026-07-31 |
