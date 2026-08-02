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

- [x] **Phase 1: Consumer-Rendered Output (templates + sink)** - Caller-supplied templates, one-shot and as a continuous sink (completed 2026-08-01)

## 📋 v0.13.0 — Consumer-Owned Output (Phase Details)

### Phase 1: Consumer-Rendered Output (templates + sink)

**Goal**: A consumer defines its own output format and keeps it current, so one stateful server feeds N independent consumers and new resolver formats stop requiring an upstream release.
**Depends on**: Nothing in this milestone. Builds on already-shipped surfaces — the event-sourced host core and `ExportHosts` streaming (v0.10.13, previous-numbering Phase 1) — so it starts from a green baseline rather than waiting on sibling work.
**Requirements**: TMPL-01, TMPL-02, TMPL-03, TMPL-04, TMPL-05, TMPL-06, TMPL-07, TMPL-08
**Success Criteria** (what must be TRUE):

1. A caller supplies a template and receives host data rendered through it, with no code change to this project
2. The field set a template may reference is documented and versioned, and a template referencing an undefined key fails loudly rather than rendering empty
3. A render or write failure leaves any previously written artifact byte-identical, and a concurrent reader never observes a partially written file
4. Sink mode reflects a host mutation without operator intervention and recovers on its own after a connection interruption, without emitting a truncated artifact
5. The client cannot be driven out of memory by the server: wire messages are bounded, the client applies backpressure, and it refuses an unbounded response rather than collecting it. **Server-side materialization is explicitly out of scope for this phase** — see the amended TMPL-06 and follow-up issue #400; `store.ListAll` still folds every aggregate's event log into memory before streaming
6. Every snapshot carries a change ID naming the server state it represents, so a consumer can tell whether it is current and two consumers can be compared for convergence
7. Existing `unbound_conf_path` and `ExportHosts` format behavior is unchanged, demonstrated by existing tests still passing

**Plans**: 11/11 plans executed; 2 gap-closure plans added 2026-08-01 (11 total)

Plans:
**Wave 1**

- [x] 01-09-PLAN.md — Change-ID storage foundation: commit-ordered event IDs, in-transaction ordering guard, and `LatestEventID` (wave 1)
- [x] 01-05-PLAN.md — Sink health primitives: mTLS CN extraction, health registry, OTel gauges (wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 01-01-PLAN.md — Tracer: end-to-end template render over a new `WatchHosts` RPC, shared atomic writer (wave 2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 01-02-PLAN.md — Template data contract: version gate, sanitizing FuncMap, published field set, worked examples (wave 3)
- [x] 01-04-PLAN.md — Bounded wire messages and gRPC keepalive on both sides (wave 3)

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 01-03-PLAN.md — Client config error propagation, then bounded fail-loud stream collection (entries and bytes) (wave 4)
- [x] 01-06-PLAN.md — Server-side sink streaming: change notification and concurrent follow mode (wave 4)

**Wave 5** *(blocked on Wave 4 completion)*

- [x] 01-07-PLAN.md — Client sink CLI: `watch`, injectable runtime policy, sidecar status, post-write hook, reconnect (wave 5)

**Wave 6** *(blocked on Wave 5 completion)*

- [x] 01-08-PLAN.md — Real-mTLS e2e with server stop/start, operator guide, manual verification checkpoint (wave 6)

**Gap closure** *(added 2026-08-01 after UAT; closes G-01-1)*

- [x] 01-10-PLAN.md — Honor explicit `--config` in the client: plumb `Flags.Config` into the config loader, fail loudly on an unreadable path, never merge an XDG-discovered config (wave 1)
- [x] 01-11-PLAN.md — Real-process cold-start e2e (`proc_e2e` tag): launch the built binary as OS processes and prove `watch --config` targets the named server (wave 2, depends on 01-10)

**Status**: Planned 2026-07-31 — approved 2026-07-25 from #364 (`approved-feature`); absorbs #23 (lazy `ExportHosts` streaming) as TMPL-06 and #38 (client-side collection bound) as TMPL-07. **Replanned 2026-07-31** after cross-AI review (`01-REVIEWS.md`, reviewers codex + pi): all 8 plans revised in place, plan count and wave structure unchanged. TMPL-08 (change identity) added; TMPL-06 rescoped with storage-layer laziness deferred to #400. **Gap closure planned 2026-08-01** after UAT found G-01-1 (blocker): `--config` was registered but never read by the client, so `watch --config <path>` silently dialed whatever the XDG search found. Plans 01-10 (fix) and 01-11 (real-process e2e that can observe it) added; no TMPL requirement status changes

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
| 1. Consumer-Rendered Output | 11/11 | In Progress|  |

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
