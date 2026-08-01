---
gsd_state_version: 1.0
milestone: v0.13.0
milestone_name: Consumer-Owned Output
current_phase: 01
current_phase_name: consumer-rendered-output-templates-sink
status: executing
stopped_at: Completed 01-03-PLAN.md
last_updated: "2026-08-01T18:41:07.993Z"
last_activity: 2026-08-01
last_activity_desc: Phase 01 execution started
progress:
  total_phases: 1
  completed_phases: 0
  total_plans: 9
  completed_plans: 6
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-07-31)

**Core value:** Declare a hostname once — the router's authoritative DNS output stays correct, leak-free, and hands-off.
**Current focus:** Phase 01 — consumer-rendered-output-templates-sink

> **Phase numbering restarted at v0.13.0.** Phases 1–9 belong to the previous
> continuous sequence (v0.10.13–v0.12.0) and are archived under
> `milestones/<version>-phases/`. A bare "Phase 1" in this milestone's live
> artifacts means Consumer-Rendered Output, not the shipped Event-Sourced Host Core.

## Current Position

Phase: 01 (consumer-rendered-output-templates-sink) — EXECUTING
Plan: 7 of 9
Status: Ready to execute
Last activity: 2026-08-01 — Phase 01 execution started

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
| Phase 01 P09 | 55min | 3 tasks | 12 files |
| Phase 01 P05 | 35min | 3 tasks | 6 files |
| Phase 01 P01 | ~75min | 3 tasks | 17 files |
| Phase 01 P02 | 70min | 3 tasks | 13 files |
| Phase 01 P04 | 45min | 2 tasks | 8 files |
| Phase 01 P03 | ~11min | 3 tasks | 12 files |

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
- [Phase ?]: 01-09: Generator value type + package singleton + SwapDefault escape hatch established as the pattern for any future process-wide monotonic-ID need
- [Phase ?]: 01-09: In-transaction ordering guard re-mints (never rejects) a non-advancing event ID at the single insertEvent funnel, unconditionally (no emptiness branch) to prevent zero-ULID collision with storage.ZeroChangeID
- [Phase ?]: 01-05: RecordStatus/RecordSeen fully overwrite SinkState on write (last-writer-wins for duplicate CNs), pinned by TestSinkHealth_DuplicateCNCollapsesLastWriterWins per review M6
- [Phase ?]: 01-05: MaxTrackedSinks is a package var (not const) so tests can shrink the eviction ceiling instead of seeding 1000+ entries
- [Phase ?]: 01-05: TMPL-05 not marked complete in REQUIREMENTS.md by this plan — only identity/registry/gauge primitives built, WatchHosts wiring deferred to plan 06
- [Phase ?]: 01-01: Change ID (LatestEventID) read strictly before ListAll in WatchHosts (H1); reversed order verified RED before rejection
- [Phase ?]: 01-01: Atomic {entries, latestEventID} single-transaction read deferred; filed as GitHub issue #401 alongside #400
- [Phase ?]: 01-01: renderDrainLimit is a package-level var (not const) so a test can lower it without seeding 50,000 entries
- [Phase ?]: 01-02: commentLineBreakReplacer moved to internal/sanitize.CommentField, shared by server generators and client template FuncMap
- [Phase ?]: 01-02: RequireVersion is exact string equality only (no semver/prefix); .Comment sanitize binding uses a single $comment := sanitize .Comment reference so a grep count-equality gate can prove no unsanitized emission path
- [Phase ?]: 01-02: .ChangeID's eventual-convergence claim scoped to sink/follow mode; one-shot render given its own weaker sentence (review round-3 M5)
- [Phase ?]: 01-04: ExportHosts chunks its already-formatted payload via sendExportChunks (exportChunkSize=64KiB); empty payload still sends exactly one message (review L14)
- [Phase ?]: 01-04: gRPC keepalive constructors renamed from plan's suggested Server-/Client-prefixed names to KeepaliveParams/KeepaliveEnforcementPolicy per package to fix a revive stutter lint finding (no acceptance grep depended on the original names)
- [Phase ?]: 01-04: Server keepalive 30s/10s ping with 15s min client interval, no connection-lifetime limits; client keepalive 20s/10s applied fleet-wide via NewClient, not sink-specific
- [Phase ?]: 01-03: LoadClientConfig now distinguishes benign absent-file from fatal present-but-invalid file, making the strict unknown-key rejection reachable (review H3)
- [Phase ?]: 01-03: ClientLimitsConfig (max_stream_entries/max_stream_bytes) with 50k/64MiB defaults, both bounds checked independently at every collecting call site (D-14, review L1)
- [Phase ?]: 01-03: client.Option (WithMaxStreamEntries/WithMaxStreamBytes) is the pinned test seam replacing plan 01's renderDrainLimit var; setupCmdTest made variadic (review L6/M8)

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

Last session: 2026-08-01T18:41:07.984Z
Stopped at: Completed 01-03-PLAN.md
Resume file: None
