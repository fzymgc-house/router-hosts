---
phase: 9
slug: hook-reliability-metrics
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-31
---

# Phase 9 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Seeded from `09-RESEARCH.md` §Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go stdlib `testing` + `testify` (`require`/`assert`) — go.mod:15, `github.com/stretchr/testify v1.11.1` |
| **Config file** | none — no separate test config; `go test` flags only |
| **Quick run command** | `task test -- -run '<AnchoredPattern>' ./internal/server/ ./internal/config/` |
| **Full suite command** | `task test` (all packages); `task ci` for the full pipeline (lint + test + build + buf) |
| **Estimated runtime** | ~10s scoped · ~90s full suite (race detector enabled) |

**`-run` is an unanchored regex — prove scope, never infer it.** Anchor every
pattern (`'^TestFoo$'`). Before trusting any scoped command in this file,
enumerate the inventory and match the `--- PASS` count against it:

```bash
rg '^func Test' internal/server/*_test.go internal/config/*_test.go
task test -- -run '<pattern>' -v ./internal/server/ | rg -c '^--- PASS'
```

A shared name prefix is not proof of family coverage: `TestHookExecutor` does
**not** match a sibling `TestHookRunnerCoalesces`. This has regressed twice in
this repo (Phase 7 and again inside Phase 8's own VALIDATION.md).

---

## Sampling Rate

- **After every task commit:** the anchored `task test -- -run '<pattern>' <pkg>` scoped to the files that task touched
- **After every plan wave:** `task test ./internal/server/... ./internal/config/...`
- **Before `/gsd-verify-work`:** `task ci` green
- **Max feedback latency:** ~15 seconds for scoped runs

---

## Per-Task Verification Map

> Requirement-level rows seeded here; the planner assigns Task IDs and the
> executor flips Status. Every row must end ✅ green before phase verification.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 09-01-T1 | 09-01 | 1 | HOOK-01 | — | N/A | unit | `task test -- -run '^TestHookExecutor_RecordsSuccessMetric$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-01-T1 | 09-01 | 1 | HOOK-02 | — | N/A | integration | `task test -- -run '^TestRegenerateOutputs_DetachesFromHooks$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-01-T1 | 09-01 | 1 | HOOK-02 | — | N/A | unit | `task test -- -run '^TestHookExecutor_ResolvesPerHookTimeout$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-01-T1 | 09-01 | 1 | HOOK-01 | T-09-04 | `ROUTER_HOSTS_ERROR` CR/LF/NUL sanitization survives the executor refactor | unit | `task test -- -run '^TestHookExecutor_ErrorMessageSanitization$\|^TestHookExecutor_ErrorMessageSanitizesAllControlChars$' ./internal/server/` | ✅ existing | ⬜ pending |
| 09-01-T2 | 09-01 | 1 | HOOK-01 | — | N/A | build | `task build` (proves `serve.go` constructs metrics before the hook executor) | ✅ existing | ⬜ pending |
| 09-01-T3 | 09-01 | 1 | HOOK-02 | T-09-05 | A detached hook is not killed by RPC-context cancellation | integration | `task test -- -run '^TestHookRunner_SurvivesRPCContextCancellation$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-01-T3 | 09-01 | 1 | HOOK-01 | — | N/A | unit | `task test -- -run '^TestNewHookExecutor_DefaultsToDisabledMetrics$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-01-T3 | 09-01 | 1 | HOOK-01 | — | N/A | integration | `task test -- -run '^TestRegenerateOutputs_NoHooksEmitsNoMetrics$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-02-T1 | 09-02 | 2 | HOOK-02 | — | N/A | unit | `task test -- -run '^TestLoadServerConfig_HookTimeoutResolution$\|^TestLoadServerConfig_HookTimeoutExplicitZeroInherits$\|^TestLoadServerConfig_EmptyHooksTable$' ./internal/config/` | ✅ W0 | ✅ green |
| 09-02-T1 | 09-02 | 2 | HOOK-02 | T-09-01 | Every resolved effective timeout is positive after config load, for all key combinations | unit | `task test -- -run '^TestHooksConfig_ResolveTimeouts_Invariant$' ./internal/config/` | ✅ W0 | ✅ green |
| 09-02-T2 | 09-02 | 2 | HOOK-02 | T-09-01 | Negative timeout rejected at config load, not silently coerced | unit | `task test -- -run '^TestLoadServerConfig_HookTimeoutRejectsNegative$\|^TestHookDefinition_Validate$' ./internal/config/` | ✅ extend | ✅ green |
| 09-02-T2 | 09-02 | 2 | HOOK-02 | T-09-14 | Unquoted integer decodes to nanoseconds — pinned by test, mitigated by docs | unit | `task test -- -run '^TestLoadServerConfig_HookTimeoutEncoding$' ./internal/config/` | ✅ W0 | ✅ green |
| 09-03-T1 | 09-03 | 2 | HOOK-01 | T-09-10 | A deadline kill records `status="timeout"`, never `status="failure"` | unit | `task test -- -run '^TestHookExecutor_RecordsTimeoutStatus$\|^TestHookExecutor_RecordsFailureStatus$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-03-T2 | 09-03 | 2 | HOOK-01 | T-09-11 | Coalesced runs use a separate instrument so `executions_total` stays a truthful execution count | unit | `task test -- -run '^TestRecordHookRunCoalesced$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-03-T2 | 09-03 | 2 | HOOK-01 | — | N/A | unit | `task test -- -run '^TestNewMetrics$\|^TestDisabledMetrics$' ./internal/server/` | ✅ extend | ⬜ pending |
| 09-03-T3 | 09-03 | 2 | HOOK-01 | T-09-06 | Counter attribute key set is exactly `{name, type, status}` — no command output or error text | unit | `task test -- -run '^TestHookExecutor_SubMillisecondDurationRecorded$\|^TestHookExecutor_SameNameDistinctTypeSeries$\|^TestHookExecutor_BatchRecordsOneDatapointPerHookInOrder$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-04-T1 | 09-04 | 3 | HOOK-02 | T-09-02 | Pending work bounded at one; no trigger silently lost (executed + coalesced == triggered) | integration | `task test -- -run '^TestHookRunner_CoalescesSupersededRuns$\|^TestHookRunner_ConcurrentTriggersConserve$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-04-T2 | 09-04 | 3 | HOOK-02 | T-09-03 | Bounded drain then cancel — no hook subprocess outlives `Stop` past its deadline | integration | `task test -- -run '^TestHookRunner_StopDrainsThenCancels$\|^TestHookRunner_StopDrainsInFlightBatch$\|^TestHookRunner_StopDrainsPendingRequest$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-04-T2 | 09-04 | 3 | HOOK-02 | T-09-12 | A post-`Stop` `Trigger` parks no undrainable work | integration | `task test -- -run '^TestHookRunner_TriggerAfterStopIsNoOp$\|^TestHookRunner_StopIsIdempotent$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-04-T3 | 09-04 | 3 | HOOK-02 | — | N/A | integration | `task test -- -run '^TestHookRunner_BatchOrderIsDeclarationOrder$\|^TestHookRunner_SupersededNeverRunsAfterSuperseder$' ./internal/server/` | ❌ W0 | ⬜ pending |
| 09-05-T1 | 09-05 | 4 | HOOK-01, HOOK-02 | T-09-13 | No stale fixed-30s / synchronous-hook claim survives in operator docs | docs | `rumdl check docs/guides/operations.md docs/contributing/architecture.md && task docs:build` | ✅ existing | ⬜ pending |
| 09-05-T2 | 09-05 | 4 | HOOK-02 | T-09-14 | Unquoted-integer nanoseconds footgun documented | docs | `rumdl check docs/reference/configuration.md && task ci` | ✅ existing | ⬜ pending |
| 09-05-T3 | 09-05 | 4 | HOOK-01 | — | N/A | manual | blocking human-verify checkpoint — see Manual-Only Verifications below | n/a | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/server/hookrunner_test.go` — new file: coalescing, drain-then-cancel, RPC-context survival, write-path detachment
- [ ] Extend `internal/server/hooks_test.go` — metrics-recording assertions (status classification, `WithMetrics` default)
- [ ] Extend `internal/server/metrics_test.go` — new coalesced instrument in `TestNewMetrics` / `TestDisabledMetrics`, plus `TestRecordHookRunCoalesced`
- [ ] Extend `internal/config/server_test.go` — timeout decode / default-inheritance / rejection table cases
- [ ] No framework install needed — testify + stdlib `testing` already cover everything; no fixtures beyond `t.TempDir()`

---

## Determinism Contract

**The write-path-does-not-block assertion MUST NOT compare wall-clock timings.**
"Returned in <5ms while the hook sleeps 10s" is a CI-load flake, not a proof.

Use a filesystem sentinel inside `t.TempDir()`:

1. Hook command blocks polling for a sentinel that does not yet exist.
2. Call the write path; it returns (a synchronous Go call — if it blocked, the test would hang, which is itself the failure signal).
3. Assert the hook's completion marker is **absent**.
4. Create the sentinel; wait for the hook's completion marker to appear.

This proves *ordering* — the write returned before the hook could possibly have
finished — without measuring time at all. `writequeue_test.go`'s signal-channel
technique does not transfer directly because a hook body runs in a subprocess
(`sh -c`) that cannot receive a Go channel; a `t.TempDir()` sentinel is the
process-boundary-safe analog and is the sanctioned filesystem mechanism under
CLAUDE.md's "no real filesystem writes in tests" rule.

**Goroutine-leak checking:** `go.uber.org/goleak` is deliberately NOT a
dependency. Follow `writequeue_test.go`'s existing deterministic
`quit`/`done`-channel lifecycle assertions instead of adding it.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Hook metrics visible on a live OTel/Prometheus scrape | HOOK-01 | Requires a running collector; unit tests assert the recording call and instrument registration, not end-to-end export | Run the server with `[metrics.otel]` configured, trigger a host mutation, confirm `router_hosts_hook_executions_total` and `router_hosts_hook_runs_coalesced_total` appear in the scrape with expected labels |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Every scoped `-run` pattern proven by `--- PASS` count against an `rg '^func Test'` inventory
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
