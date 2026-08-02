---
phase: 01-consumer-rendered-output-templates-sink
plan: 05
subsystem: server
tags: [otel, observable-gauge, mtls, sink-health, cardinality, grpc]

requires: []
provides:
  - "internal/server/peercn.go: commonNameFromContext — the only permitted source of verified sink identity (D-13)"
  - "internal/server/sinkmetrics.go: SinkHealth, the in-memory per-consumer health registry that survives stream close (D-10)"
  - "internal/server/metrics.go: (*Metrics).RegisterSinkGauges — seven observable gauges projecting SinkHealth through the existing OTel pipeline"
affects: [watchhosts-handler, sink-mode, operator-guide]

actuals:
  tokens: 8150
  tasks: 3
  commits: 6

tech-stack:
  added: []
  patterns:
    - "Struct-argument recording methods (RecordStatus(cn, SinkState)) over widening positional parameter lists"
    - "MaxTrackedSinks as a package var (not const) so a test can shrink the eviction ceiling instead of seeding a thousand entries"
    - "Convergence expressed as a 0/1 observable gauge derived inside the callback, never as a label — the ULID itself never becomes an attribute"

key-files:
  created:
    - internal/server/peercn.go
    - internal/server/peercn_test.go
    - internal/server/sinkmetrics.go
    - internal/server/sinkmetrics_test.go
  modified:
    - internal/server/metrics.go
    - internal/server/metrics_test.go

key-decisions:
  - "RecordStatus/RecordSeen fully replace the previous SinkState on write (last-writer-wins), keyed by CN; duplicate CNs collapse by design (D-13, review M6) and are pinned by TestSinkHealth_DuplicateCNCollapsesLastWriterWins"
  - "MaxTrackedSinks declared as a mutable package var, not a const, specifically so TestSinkHealth_EvictsOldestPastCeiling can shrink the ceiling to 3 instead of seeding 1001 real entries"
  - "The removed router_hosts_sink_render_failures_total is never named in any code comment (only in this SUMMARY) — naming it in metrics.go would itself trip the phantom-counter acceptance gate"
  - "TMPL-05 is NOT marked complete in REQUIREMENTS.md by this plan — it lists TMPL-05 in its own frontmatter but the objective states plan 06 wires these primitives into WatchHosts; marking it complete here would falsely signal the full sink-mode behavior exists before the handler wiring lands"

patterns-established:
  - "commonNameFromContext as the sole entry point for sink identity: peer.FromContext -> credentials.TLSInfo type assertion -> VerifiedChains[0][0].Subject.CommonName, guarded defensively since ClientAuth: tls.RequireAndVerifyClientCert already enforces a verified chain"
  - "Observable-gauge registration mirroring RegisterAggregateEventGauges's no-op-on-nil-provider/nil-source shape, extended here to a second nil guard (nil health) and a callback that reads a snapshot rather than a live struct"

requirements-completed: [TMPL-05, TMPL-08]  # See "Requirements Note" below: TMPL-05 is only partially satisfied by this plan (primitives only, no WatchHosts wiring) and was NOT flipped via `requirements mark-complete`.

coverage:
  - id: D1
    description: "commonNameFromContext extracts the mTLS-verified peer identity from a stream context, or returns a clear error for each of the four failure modes (no peer, non-TLS auth, empty chain list, empty first chain)"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/server/peercn_test.go#TestCommonNameFromContext (5 subtests)"
        status: pass
    human_judgment: false
  - id: D2
    description: "SinkHealth registry: per-consumer state survives Disconnect, write health and reload health stay independent (D-12a), the connected count is identity-free and floors at zero, identity-extraction failures are counted separately, duplicate CNs collapse last-writer-wins (stated and tested, review M6), and the registry is safe under concurrent access"
    requirement: "TMPL-08"
    verification:
      - kind: unit
        ref: "internal/server/sinkmetrics_test.go#TestSinkHealth_RecordAndSnapshot,TestSinkHealth_StateSurvivesDisconnect,TestSinkHealth_ConnectedCountFloorsAtZero,TestSinkHealth_ConnectNeedsNoIdentity,TestSinkHealth_ReloadFailureKeepsLastSuccess,TestSinkHealth_ConvergedWhenChangeIDMatches,TestSinkHealth_NotConvergedWithoutReportedChangeID,TestSinkHealth_EvictsOldestPastCeiling,TestSinkHealth_SnapshotIsACopy,TestSinkHealth_ConcurrentAccess,TestSinkHealth_IdentityFailureCounts,TestSinkHealth_DuplicateCNCollapsesLastWriterWins"
        status: pass
    human_judgment: false
  - id: D3
    description: "Seven observable gauges project SinkHealth through the existing OTel pipeline at scrape time: per-identity last-seen/last-success/failures/reload-failed/converged (labelled only by cn), plus label-free connected and identity-failure counts; every instrument has a real observation point and the change ID never becomes a label"
    requirement: "TMPL-08"
    verification:
      - kind: unit
        ref: "internal/server/metrics_test.go#TestRegisterSinkGauges_RealProvider,TestRegisterSinkGauges_NilProviderNoop,TestRegisterSinkGauges_NilHealthNoop,TestRegisterSinkGauges_ConvergedReflectsChangeID,TestRegisterSinkGauges_ReloadFailedIsIndependentOfLastSuccess,TestRegisterSinkGauges_IdentityFailuresObservedWithoutAttributes"
        status: pass
    human_judgment: false

duration: ~35min
completed: 2026-08-01
status: complete
---

# Phase 1 Plan 05: Sink Health Primitives Summary

**Three standalone, unit-tested primitives for sink health — verified mTLS common-name extraction, an in-memory per-consumer health registry with independent write/reload health and last-writer-wins duplicate-CN semantics, and seven OTel observable gauges projecting that state — with no `WatchHosts` wiring yet (deferred to plan 06).**

## Performance

- **Duration:** ~35 min
- **Tasks:** 3
- **Files modified:** 6 (4 created, 2 modified)

## Accomplishments

- `internal/server/peercn.go`: `commonNameFromContext` implements the verified `peer.FromContext` -> `credentials.TLSInfo` -> `VerifiedChains[0][0].Subject.CommonName` chain exactly as pinned in 01-RESEARCH.md, guarded (defensively, not load-bearingly) against four failure modes.
- `internal/server/sinkmetrics.go`: `SinkHealth`, a concurrency-safe registry holding one retained record per verified consumer identity — `LastSuccess` (write health) and `ReloadFailed`/`LastReloadSuccess` (reload health, D-12a) are independent fields; `Connect`/`Disconnect`/`RecordIdentityFailure` are deliberately identity-free; duplicate CNs collapse with last-writer-wins semantics that are documented and pinned by test (review M6); `MaxTrackedSinks` bounds live series count, not lifetime label-value count, with oldest-`LastSeen` eviction logged at warn level.
- `internal/server/metrics.go`: `(*Metrics).RegisterSinkGauges` registers `router_hosts_sink_last_seen_timestamp_seconds`, `router_hosts_sink_last_success_timestamp_seconds`, `router_hosts_sink_consecutive_failures`, `router_hosts_sink_reload_failed`, `router_hosts_sink_converged`, `router_hosts_sinks_connected`, and `router_hosts_sink_identity_failures` — every one observed in a single scrape callback that only reads from the registry. `router_hosts_sink_render_failures_total` (review M5) was not created; no instrument in this plan ships unobserved.
- 23 new tests (5 + 12 + 6), all green under `-race`; full repo `task test` and `task lint` both clean; `go.mod`/`go.sum` unchanged.

## Task Commits

Each task followed TDD RED -> GREEN, both committed atomically:

1. **Task 1: Extract the mTLS common name from a stream context**
   - `04c8b1c` (test) — failing `TestCommonNameFromContext`, verified RED via build failure before `peercn.go` existed
   - `e7e8357` (feat) — `commonNameFromContext`
2. **Task 2: In-memory per-consumer sink health registry**
   - `74cf1b5` (test) — failing `TestSinkHealth_*` suite, verified RED via build failure before `sinkmetrics.go` existed
   - `1c6be15` (feat) — `SinkHealth` and its methods
3. **Task 3: Project sink health through the existing OTel pipeline**
   - `e29bf3b` (test) — failing `TestRegisterSinkGauges_*` suite, verified RED via build failure before `RegisterSinkGauges` existed
   - `f722b7e` (feat) — `(*Metrics).RegisterSinkGauges`

*No separate plan-metadata commit was required beyond this SUMMARY's own commit.*

## Files Created/Modified

- `internal/server/peercn.go` — `commonNameFromContext(ctx) (string, error)`
- `internal/server/peercn_test.go` — `TestCommonNameFromContext`, 5 table-driven subtests covering verified chain, no peer, non-TLS auth, empty chain list, empty first chain
- `internal/server/sinkmetrics.go` — `SinkState`, `SinkSnapshot`, `SinkHealth` and its methods (`RecordSeen`, `RecordStatus`, `RecordServerChange`, `Connect`, `Disconnect`, `RecordIdentityFailure`, `Snapshot`), `MaxTrackedSinks`
- `internal/server/sinkmetrics_test.go` — 12 tests, including the concurrency test (`sync.WaitGroup` + `-race`) and the eviction test (temporarily shrinks `MaxTrackedSinks`)
- `internal/server/metrics.go` — `(*Metrics).RegisterSinkGauges(health *SinkHealth) error`, appended after `RegisterAggregateEventGauges`; no changes to `NewMetrics`, `DisabledMetrics`, or the `Metrics` struct
- `internal/server/metrics_test.go` — 6 new tests appended after the aggregate-gauge tests, reusing the existing `newTestMetrics`/`collectMetrics`/`findMetric`/`extractAttrs` harness

## Decisions Made

- `RecordStatus`/`RecordSeen` fully overwrite the tracked `SinkState` on each call (last-writer-wins for duplicate CNs), rather than field-by-field partial merging — matches the plan's stated M6 semantics and is the simplest implementation that cannot accidentally derive one field from another (the D-12a independence requirement).
- `MaxTrackedSinks` is a package-level `var`, not a `const`, purely so `TestSinkHealth_EvictsOldestPastCeiling` can shrink the ceiling to 3 and drive eviction without seeding 1001 real map entries.
- Every per-identity gauge observation in the callback writes its own inline `otelmetric.WithAttributes(attribute.String("cn", cn))` rather than sharing one `attrs` variable across the five calls — this keeps the acceptance grep for label provenance (`attribute.String("cn"` count >= 5) meaningful as a per-call check rather than trivially satisfied by one shared variable.

## Deviations from Plan

**1. [Rule 1 - Corrected during authoring] Draft doc comment on `RegisterSinkGauges` named the removed identifiers, which the plan's own acceptance gate forbids**

- **Found during:** Task 3, running the acceptance-criteria grep `rg -n 'sink_render_failures_total|RecordSinkRenderFailure' internal/` before committing
- **Issue:** The first draft of `RegisterSinkGauges`'s doc comment explained the M5 rationale by name — `"router_hosts_sink_render_failures_total and RecordSinkRenderFailure are deliberately absent (review M5)..."` — which is exactly the failure mode the plan's acceptance criteria calls out: *"Do not leave a code comment naming either identifier... that comment fails this gate."*
- **Fix:** Rewrote the comment to explain the same reasoning (every instrument has a real observation point; the failure count is a gauge, not a counter, because it carries consumer-reported standing state) without naming either removed identifier.
- **Files modified:** `internal/server/metrics.go`
- **Verification:** `rg -n 'sink_render_failures_total|RecordSinkRenderFailure' internal/` returns no matches; `task lint` clean; full test suite green.
- **Committed in:** `f722b7e` (Task 3 feat commit — the corrected comment is what shipped; the naming draft was never committed)

---

**Total deviations:** 1 auto-fixed (Rule 1, doc-comment self-correction before commit)
**Impact on plan:** No scope creep; the fix only changed comment wording, not behavior.

## Issues Encountered

None beyond the deviation above.

## Requirements Note

This plan's frontmatter lists `TMPL-05` and `TMPL-08`. `TMPL-08` was already marked `Complete` in REQUIREMENTS.md by plan 01-09 (the change-ID storage foundation); this plan adds the consumer-facing convergence gauge that consumes it but does not itself change that requirement's status. `TMPL-05` ("sink mode holds the rendered artifact current...") is **not** marked complete here — this plan builds only the identity/registry/gauge primitives with no `WatchHosts` wiring, exactly as the plan's own objective states ("Plan 06 wires these into the `WatchHosts` handler"). Marking `TMPL-05` complete from this plan alone would falsely signal working sink-mode behavior before plans 06/07 land it. No `requirements mark-complete` call was made for either ID in this plan.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

Plan 06 can now wire `commonNameFromContext`, `SinkHealth`, and `RegisterSinkGauges` into the `WatchHosts` handler against primitives that are already unit-tested in isolation: `commonNameFromContext`'s error path is `SinkHealth.RecordIdentityFailure`'s real increment site, and `SinkHealth.RecordStatus`'s `RenderedChangeID` field is where plan 06's derived change ID lands for the convergence gauge to observe. Plan 08's operator guide still needs to carry the one-CN-per-consumer deployment requirement documented on `RecordStatus` (review M6).

No blockers. `go test -race -count=1 ./...` is green across the whole repository; `task lint` reports 0 issues; `go.mod`/`go.sum` unchanged.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-01*

## Self-Check: PASSED

- FOUND: `internal/server/peercn.go`
- FOUND: `internal/server/peercn_test.go`
- FOUND: `internal/server/sinkmetrics.go`
- FOUND: `internal/server/sinkmetrics_test.go`
- FOUND: `internal/server/metrics.go`
- FOUND: `internal/server/metrics_test.go`
- FOUND: `.planning/phases/01-consumer-rendered-output-templates-sink/01-05-SUMMARY.md`
- FOUND: `04c8b1c` (Task 1 test commit)
- FOUND: `e7e8357` (Task 1 feat commit)
- FOUND: `74cf1b5` (Task 2 test commit)
- FOUND: `1c6be15` (Task 2 feat commit)
- FOUND: `e29bf3b` (Task 3 test commit)
- FOUND: `f722b7e` (Task 3 feat commit)
