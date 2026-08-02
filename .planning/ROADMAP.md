# Roadmap: router-hosts

## Overview

router-hosts is an event-sourced, mTLS-secured DNS control plane with a CLI/TUI
and a Kubernetes operator. Milestones v0.10.13 through v0.12.0 built the baseline
and drove toward the north star — operator / Gateway-API parity and hands-off
cluster integration — finishing with hook reliability. v0.13.0 opened a second
axis: output rendering moved from the server to the consumer, so one stateful
server feeds N independent consumers without accreting a per-resolver output
format for each.

> **Phase numbering restarted at v0.13.0.** Milestones v0.10.13–v0.12.0 used a
> single continuous sequence (phases 1–9). Where an archived document says
> "Phase 1" it means Event-Sourced Host Core; in v0.13.0 it means
> Consumer-Rendered Output. Historical phase detail and phase directories are
> archived under `milestones/<version>-ROADMAP.md` and
> `milestones/<version>-phases/`.

## Milestones

- ✅ **v0.10.13 — v1 Shipped Baseline** — Phases 1–6 (shipped pre-GSD, reconstructed 2026-07-07)
- ✅ **v0.11.0 — K8s-Native Automation** — Phases 7–8 (shipped 2026-07-30, PR #381)
- ✅ **v0.12.0 — Hook Reliability & Metrics** — Phase 9 (shipped 2026-07-31, PR #389)
- ✅ **v0.13.0 — Consumer-Owned Output** — Phase 1 (shipped 2026-08-02, PR #404)
- 📋 **Next milestone** — not yet defined (`/gsd-new-milestone`)

## Phases

<details>
<summary>✅ v0.10.13 — v1 Shipped Baseline (Phases 1–6) — SHIPPED</summary>

Archived: [`milestones/v0.10.13-ROADMAP.md`](milestones/v0.10.13-ROADMAP.md)

- [x] Phase 1: Event-Sourced Host Core
- [x] Phase 2: Certificate Lifecycle
- [x] Phase 3: Kubernetes Operator
- [x] Phase 4: Observability
- [x] Phase 5: Split-Horizon DNS Output
- [x] Phase 6: Aggregate Compaction

</details>

<details>
<summary>✅ v0.11.0 — K8s-Native Automation (Phases 7–8) — SHIPPED 2026-07-30</summary>

Archived: [`milestones/v0.11.0-ROADMAP.md`](milestones/v0.11.0-ROADMAP.md)

- [x] Phase 7: Gateway API Support (6/6 plans) — completed 2026-07-26
- [x] Phase 8: Service Controller (5/5 plans) — completed 2026-07-30

</details>

<details>
<summary>✅ v0.12.0 — Hook Reliability & Metrics (Phase 9) — SHIPPED 2026-07-31</summary>

Archived: [`milestones/v0.12.0-ROADMAP.md`](milestones/v0.12.0-ROADMAP.md)

- [x] Phase 9: Hook Reliability & Metrics (5/5 plans) — completed 2026-07-31

</details>

<details>
<summary>✅ v0.13.0 — Consumer-Owned Output (Phase 1) — SHIPPED 2026-08-02</summary>

Archived: [`milestones/v0.13.0-ROADMAP.md`](milestones/v0.13.0-ROADMAP.md)
Audit: [`milestones/v0.13.0-MILESTONE-AUDIT.md`](milestones/v0.13.0-MILESTONE-AUDIT.md)

- [x] Phase 1: Consumer-Rendered Output (templates + sink) (11/11 plans) — completed 2026-08-01

Caller-supplied templates rendered client-side, one-shot and as a continuous
sink, over a new `WatchHosts` RPC. Requirements TMPL-01 through TMPL-08, all
satisfied. Two gap-closure plans (01-10, 01-11) added after UAT found G-01-1.

</details>

## Progress

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
| 1. Consumer-Rendered Output | v0.13.0 | 11/11 | Complete | 2026-08-01 |

## Backlog

Unsequenced items parked from the v0.13.0 milestone audit
(`.planning/v0.13.0-MILESTONE-AUDIT.md`). Promote with `/gsd-review-backlog`.

### Phase 999.1: Wire the three e2e tiers into CI (BACKLOG)

**Goal:** `e2e`, `docker_e2e`, and `proc_e2e` gate merges instead of being
developer-only. `proc_e2e` is the only tier that observes the CLI-flag to config
seam — the exact blind spot that let blocker G-01-1 ship green through 45 UAT
items — and it currently does not gate anything. Tracked as #403 (threat
T-01-G1-13, disposition accept).
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.2: Close the hardware-dependent verification gap (BACKLOG)

**Goal:** Run the verifications this environment cannot: UAT test 42 (resolver
reload plus two-node convergence) and the four manual deployment checks from plan
01-08, all recorded NOT-RUN in `01-VALIDATION.md`. Needs a real unbound host and a
second machine. Until then phase 01 reports `uat-passed: false` permanently,
because the predicate counts only `pass`/`passed`.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.3: Server-side lazy streaming for store.ListAll (BACKLOG)

**Goal:** Finish the half of TMPL-06 that was explicitly descoped. The wire is
bounded and the client refuses an unbounded response, but `store.ListAll` still
enumerates every aggregate and replays its full event log into memory before the
first byte is sent. Needs a cursor-based `storage.HostProjection` method. Tracked
as #400 (absorbs #23's wire-layer half) and #401.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)
