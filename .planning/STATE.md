---
gsd_state_version: 1.0
milestone: v0.13.0
milestone_name: Consumer-Owned Output
status: planning
last_updated: "2026-07-31T22:12:05.691Z"
last_activity: 2026-07-31
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-31)

**Core value:** Declare a hostname once — the router's authoritative DNS output stays correct, leak-free, and hands-off.
**Current focus:** Milestone v0.13.0 — Consumer-Owned Output. Phase 1 (Consumer-Rendered Output: templates + sink) is defined with TMPL-01…07 and approved from #364; next step is `/gsd-discuss-phase 1`.

> **Phase numbering restarted at v0.13.0.** Phases 1–9 belong to the previous
> continuous sequence (v0.10.13–v0.12.0) and are archived under
> `milestones/<version>-phases/`. A bare "Phase 1" in this milestone's live
> artifacts means Consumer-Rendered Output, not the shipped Event-Sourced Host Core.

## Current Position

Phase: 1 — Consumer-Rendered Output (templates + sink)
Plan: —
Status: Requirements defined (TMPL-01…07); phase not yet planned
Last activity: 2026-07-31 — Milestone v0.13.0 started; phase numbering restarted at 1

## Performance Metrics

**Velocity:**

- Total plans completed: 16 phases shipped pre-GSD (no per-plan timing captured)
- Average duration: n/a (retrospective baseline)
- Total execution time: n/a

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1–6 (shipped) | shipped | - | - |
| 7 | 6 | - | - |
| 8 | 5 | - | - |
| 9 | 5 | - | - |

**Recent Trend:**

- Last shipped release: v0.10.13
- Trend: Stable (mature, in-production)

*Updated after each plan completion*
**Per-Plan Metrics:**

| Plan | Duration | Tasks | Files |
|------|----------|-------|-------|
| Phase 07 P01 | 40min | 4 tasks | 6 files |
| Phase 07 P06 | 25min | 2 tasks | 6 files |
| Phase 07-gateway-api-support P02 | 35min | 2 tasks | 2 files |
| Phase 07 P03 | 20min | 2 tasks | 2 files |
| Phase 07 P04 | 25min | 2 tasks | 2 files |
| Phase 07 P05 | 20min | 3 tasks | 2 files |
| Phase 08 P01 | 20min | 2 tasks | 3 files |
| Phase 08 P02 | 45min | 3 tasks | 3 files |
| Phase 08-kubernetes-service-controller P03 | 50min | 3 tasks | 2 files |
| Phase 08 P05 | ~40min | 3 tasks | 4 files |
| Phase 08 P04 | 70min | 3 tasks | 2 files |
| Phase 09 P01 | 3min | 3 tasks | 8 files |
| Phase 09 P02 | 15min | 2 tasks | 2 files |
| Phase 09 P03 | 12min | 3 tasks | 4 files |
| Phase 09 P04 | 6min | 3 tasks | 2 files |
| Phase 09 P05 | 25min | 3 tasks | 4 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md (Key Decisions table + Locked Decisions ADR blocks).
Load-bearing locked decisions affecting current/forward work:

- **router-hosts-bzg** (LOCKED): unbound per-name `local-zone static` — Phase 5 output constraint
- **router-hosts-v5b / -vl8 / -4w2** (LOCKED): compaction via HostCompacted seed, manual scope, GetAtTime sacrificed — Phase 6
- **Rust → Go migration (2026-02-22)**: current stack is Go/SQLite-only; Rust-era Service-controller design was never ported (Phase 8 gap)
- [Phase ?]: D-09 confirmed at plan checkpoint: single gatewayCleanupFinalizer (router-hosts.fzymgc.house/gateway-cleanup) shared across all three Gateway API route kinds, not per-kind finalizers
- [Phase ?]: Fixed pre-existing lefthook.yaml regex-vs-glob bug in check-yaml exclude (Rule 3, blocking); added .yamlfmt.yaml with retain_line_breaks:true to preserve values.yaml formatting style
- [Phase ?]: Gateway API RBAC: write verbs (update/patch) only on httproutes/grpcroutes/tlsroutes for finalizer+annotation write-back; gateways stays read-only get/list/watch
- [Phase ?]: GW-01 left incomplete in REQUIREMENTS.md until plan 04 finishes syncRoute's update/delete diff
- [Phase ?]: extractHostnames marks a hostname seen before validation, so a repeated invalid hostname logs one Warn, not N
- [Phase ?]: 07-03: resolveIP's ordering/type-filter/namespace-default behavior was already fully implemented in plan 07-01's tracer; task 1 needed only test coverage
- [Phase ?]: 07-03: resolveIP now logs Error (not Debug) on a non-NotFound parent Gateway Get failure; NotFound stays silent (D-16)
- [Phase ?]: 07-03: syncRoute requeues after requeueDelayShort with nil error when resolveIP yields no IP, before any HostClient call or annotation write (D-16, GW-02)
- [Phase ?]: 07-04: Removed syncRoute's pre-existing zero-hostnames early return so the stale-cleanup delete pass runs even when a route's hostnames are edited down to zero (Rule 1 bug fix)
- [Phase ?]: 07-04: syncRoute's update path is deliberately unconditional (no GetHost-before-Update guard) per D-13; reconcileDelete now performs full cleanup-then-finalizer-release; GW-01 marked complete
- [Phase ?]: 07-05: parentRef field index (D-17) + Gateway watch, gated on gatewayKindPresent(mapper, gatewayGVK) computed once and threaded through SetupWithManager(mgr, watchGateway) so a cluster with route CRDs but no Gateway CRD still starts cleanly (research Pitfall 1)
- [Phase ?]: 07-05: gatewayGVK built via gatewayGroupVersionKind("Gateway") not the deprecated gatewayv1.SchemeGroupVersion.WithKind, keeping all four GVKs on the same non-deprecated construction path
- [Phase ?]: Confirmed service-cleanup finalizer string per locked CONTEXT D-16 (checkpoint resolved: confirm-service-cleanup)
- [Phase ?]: 08-02: D-13 events RBAC gap confirmed empirically (0 events rules pre-change) before fixing; ClusterRole now grants services (get/list/watch/update/patch) and cluster-scoped events (create/patch)
- [Phase ?]: 08-02: resolveServiceIP rejects unsupported Service types before applying the ip-address annotation override, so ClusterIP/ExternalName cannot be resurrected by the annotation
- [Phase ?]: TestSyncService_UpdatePath tests syncServiceHost directly (not through full Reconcile) to isolate the D-18/D-19 fail-closed branch logic from annotation-persistence plumbing already covered elsewhere
- [Phase ?]: syncServiceHost failures are handled by syncService identically to the tracer's addOrAdoptService failures (log.Error + RequeueAfter: requeueDelayLong, nil returned error) — the previously-tracked ID survives because the annotation write is skipped on that branch
- [Phase ?]: D-23 followed exactly: serviceController.enabled key deliberately not named service.enabled, verified by asserting the bare service: key is absent from values.yaml
- [Phase ?]: Both required negative controls for task test:chart's new Service RBAC assertions were run manually (widened services verbs, deleted events rule), each proven to fail loudly, then reverted and re-verified green
- [Phase ?]: syncService restructured around a switch-computed desired set with no early return, so all four D-17 stop-managing transitions delete through one code path
- [Phase ?]: addOrAdoptService gates adoption on BOTH existing.Comment == k8s-service:<ns>/<name> AND hasServiceProvenance(tags) — refusing a foreign entry on either half
- [Phase ?]: HooksConfig.DefaultTimeout field added ahead of Plan 09-02's TOML wiring so serve.go could compile against cfg.Hooks.DefaultTimeout; field carries no resolution/validation logic yet
- [Phase ?]: executeHook records metrics against the caller's (runner) ctx, not the per-hook hookCtx, since hookCtx may already be Done() at recording time
- [Phase ?]: resolveTimeouts() is the primary positivity-enforcement point for hook timeouts; validate() negative-checks are a backstop for hand-constructed configs bypassing LoadServerConfig
- [Phase ?]: Timeout classification checks hookCtx.Err() before the process error; coalesced-run counter carries only {type}, no name attribute
- [Phase ?]: hookRunner.Trigger records router_hosts_hook_runs_coalesced_total exactly once per superseded request via context.Background(); adds a stopped-flag check closing a latent phantom-coalesce bug on repeated post-Stop triggers
- [Phase ?]: Phase 9 hook docs (09-05): reverted docs/reference/api.md and docs/reference/cli.md after every task docs:build run — stale generated files unrelated to this plan's scope
- [Phase ?]: Phase 9 (09-05): checkpoint Task 3 closed on documentation review only; live OTel scrape explicitly deferred, recorded in 09-VALIDATION.md as not-run rather than claimed done

### Pending Todos

None yet.

### Blockers/Concerns

- **[Phase 7]**: Gateway API is design-only (Draft, 2026-06-07) — no `gateway-api` dependency or controller in the Go operator; net-new implementation.
- **[Phase 8]**: Service controller exists only as superseded Rust-era design; must be built fresh in Go.
- **[Codebase]**: `service.go` (1033 LOC) and `commands.go` (519 LOC) are merge hotspots; in-tree `legacy_migration.go` is a permanent maintenance surface pending a removal milestone.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260728-ude | Fix WR-01/WR-02: aggregate alias cap, ip-address validation, InvalidConfiguration event | 2026-07-29 | 4403ad1 | [260728-ude-fix-wr-01-and-wr-02-from-08-review-md-ag](./quick/260728-ude-fix-wr-01-and-wr-02-from-08-review-md-ag/) |

## Deferred Items

Items acknowledged and carried forward:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Storage/History | Snapshot tables + auto-compaction (v2 HIST-01/02) | Deferred (YAGNI, ADR vl8) | 2026-07-07 |
| Maintainability | Remove Rust-era `legacy_migration.go` (v2 DEBT-01) | Deferred | 2026-07-07 |

## Session Continuity

Last session: 2026-07-31T16:19:20.896Z
Stopped at: Completed 09-05-PLAN.md
Resume file: None
