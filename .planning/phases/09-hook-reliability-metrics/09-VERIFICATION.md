---
phase: 09-hook-reliability-metrics
verified: 2026-07-31T16:51:16Z
status: human_needed
score: 24/25 must-haves verified
behavior_unverified: 0
overrides_applied: 0
behavior_unverified_items: [] # none — all behavior-dependent truths have passing behavioral tests
human_verification:
  - test: "One must_have truth is a documented, intentionally-unreproducible race backstop (09-04): 'A Trigger arriving at the exact instant a batch finishes either runs or is counted as coalesced, never vanishing.' Confirm the argument-based proof in the file-level BACKSTOP comment at the top of internal/server/hookrunner_test.go is sound (the shared mutex totally orders Trigger's pending-overwrite against runPending's pending-take, so there is no interleaving where a request is dropped by neither path)."
    expected: "A human/domain reviewer agrees the mutex-based argument closes the interleaving, since no test can force the exact scheduler interleaving on demand."
    why_human: "Per the phase's own VALIDATION.md and 09-04-PLAN.md, this is a documented, intentional verification limit — not reproducible by an automated test. The verifier can confirm the argument is documented and the two supporting tests (TestHookRunner_CoalescesSupersededRuns, TestHookRunner_ConcurrentTriggersConserve) pass, but cannot mechanically confirm the interleaving claim itself."
  - test: "The phase's live OTel/Prometheus scrape (09-05-T3 checkpoint) was closed on documentation review only; the optional live-scrape steps (start a server with [metrics.otel], mutate a host, scrape a real collector, confirm router_hosts_hook_executions_total / _duration_seconds / _runs_coalesced_total appear with correct labels) were never executed."
    expected: "An operator with a running server + OTel collector performs the scrape once and confirms the three hook instruments appear with the documented attributes."
    why_human: "Consciously deferred per 09-VALIDATION.md's Manual-Only Verifications table — no collector was available in the execution session. This is a known deferral, not a gap (see below), but it remains an outstanding human-verification item before the phase's observability claim is proven end-to-end in a real environment."
---

# Phase 9: Hook Reliability & Metrics Verification Report

**Phase Goal:** Post-edit hooks are observable and cannot stall the write path.
**Verified:** 2026-07-31T16:51:16Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

Both ROADMAP.md Success Criteria plus the phase's aggregated PLAN must-haves (across 09-01..09-05, backstop entries called out separately) were checked directly against the current source tree on `feat/hook-reliability-metrics` (33 commits ahead of `main`).

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| SC1 | Each `on_success`/`on_failure` hook execution emits count, duration, and outcome metrics | ✓ VERIFIED | `executeHook` (`internal/server/hooks.go:187-227`) calls `h.metrics.RecordHookExecution(ctx, hook.Name, event, status, time.Since(start))` on every run; `router_hosts_hook_executions_total` and `_duration_seconds` are real OTel instruments (`internal/server/metrics.go`); `serve.go`'s `configureMetricsAndHooks` wires a real `*Metrics` via `WithMetrics`, not `DisabledMetrics()`. `task test -- -run '^TestConfigureMetricsAndHooks' ./internal/client/commands/` passes (verified live). |
| SC2 | A per-hook timeout is configurable (no longer fixed 30s) and hook execution is bounded so a slow hook cannot block write processing | ✓ VERIFIED | `HookDefinition.Timeout` + `HooksConfig.DefaultTimeout` + `resolveTimeouts()` (`internal/config/server.go:186-220`) implement the three-link chain, called between `meta.Undecoded()` and `cfg.validate()` in `LoadServerConfig`. `regenerateOutputs` (`internal/server/service.go:150-169`) calls `s.hooks.TriggerSuccess/TriggerFailure` — no synchronous hook call remains on the RPC path (`rg 's\.hooks\.Run' internal/server/service.go` → no matches). |
| D1 (09-01) | `regenerateOutputs` returns before triggered hooks complete | ✓ VERIFIED | `TestRegenerateOutputs_DetachesFromHooks` — filesystem-sentinel ordering, no wall-clock comparison. Confirmed by reading `service.go` and `hookrunner.go` (Trigger never blocks; loop runs `runBatch` async). |
| D2 (09-01) | Every hook execution records executions_total + duration_seconds with name/type/status | ✓ VERIFIED | `hooks.go:221`; test `TestHookExecutor_RecordsSuccessMetric` present and (per `task ci`) passing. |
| D3 (09-01) | Each hook's timeout resolved once at construction, no run-time global-default lookup | ✓ VERIFIED | `NewHookExecutor` resolves `Timeout` per-hook at construction (`hooks.go:69-83`); `executeHook` reads `hook.Timeout` only. |
| D4 (09-01) | Hook execution derives context from the runner's server-lifecycle context, not RPC context | ✓ VERIFIED | `hookRunRequest` has no `context.Context` field; `newHookRunner` uses `context.WithCancel(context.Background())`; `runBatch` always passes `r.ctx`. `TestHookRunner_SurvivesRPCContextCancellation` exists and (per `task ci`) passes. |
| D5 (09-01) | Zero hooks configured → zero `router_hosts_hook_*` datapoints | ✓ VERIFIED | `regenerateOutputs`'s `s.hooks == nil \|\| !ran` early return (`service.go:150-152`); `TestRegenerateOutputs_NoHooksEmitsNoMetrics` present. |
| D6 (09-01) | `NewHookExecutor` without `WithMetrics` holds non-nil `*Metrics` (DisabledMetrics) | ✓ VERIFIED | `hooks.go:89` (`metrics: DisabledMetrics()`); `WithMetrics(nil)` is a documented no-op (`hooks.go:45-51`). |
| Backstop (09-01) | A hook subprocess is terminated when the runner's base context is cancelled | ✓ VERIFIED (empirical) | Ran `TestHookRunner_StopDrainsThenCancels` live: a hook that never unblocks is killed when `Stop`'s deadline expires and `r.cancel()` fires — log shows `error.err="... signal: killed"` and the completion marker is asserted absent. This exceeds a presence check: it directly observed process termination. |
| D1 (09-02) | Timeout resolves through exactly one chain: per-hook → `[hooks] default_timeout` → 30s | ✓ VERIFIED | `resolveTimeouts()` implements all three links in one function; source-ordering confirmed live via `rg`. |
| D2 (09-02) | After `LoadServerConfig` succeeds, every hook has `Timeout > 0` for every combination | ✓ VERIFIED | `resolveTimeouts()` enforces positivity for `DefaultTimeout` and every hook in both lists before returning `nil` (`server.go:186-220`). |
| D4/D5 (09-02) | Negative per-hook / negative `default_timeout` rejected at load, naming the right key | ✓ VERIFIED | `resolveTimeouts()`'s positivity checks return `oops.Code(domain.CodeValidation)` naming the hook or `default_timeout`; `HookDefinition.validate()`/`HooksConfig.validate()` add a backstop check for hand-constructed values. |
| D7 (09-02) | Bare integer TOML decodes to nanoseconds, positive, therefore accepted | ✓ VERIFIED | Documented and pinned by `TestLoadServerConfig_HookTimeoutEncoding` per plan; matches BurntSushi/toml semantics; documentation confirms this exact behavior (see below). |
| Backstop (09-02) | No hand-constructed `config.Config` in `internal/config` or its callers regresses from the new validate check | ✓ VERIFIED (exhaustive grep) | `rg '\.validate\(\)' internal/config/ internal/server/ internal/client/'` → all call sites are `internal/config/server_test.go`, `internal/config/client.go:75`, and `internal/config/server.go` itself (the four internal call sites, `client.go`'s single caller). No caller outside `internal/config`'s own test/production files exists, and `task ci`'s full test run is green — the claim is exhaustively checkable by enumeration, not merely arguable. |
| D1-D3 (09-03) | `status="timeout"` fires only on deadline kill (context-error-first ordering); `status="failure"` on self-inflicted non-zero exit | ✓ VERIFIED | `executeHook`'s switch checks `errors.Is(hookCtx.Err(), context.DeadlineExceeded)` BEFORE `err != nil` (`hooks.go:212-220`) — confirmed by direct read of source; this is the exact ordering the phase's own review (09-REVIEW.md) independently verified empirically. |
| D4 (09-03) | `router_hosts_hook_runs_coalesced_total` exists in both `NewMetrics` and `DisabledMetrics`, nil-safe | ✓ VERIFIED | `metrics.go` — both constructors create the instrument; `RecordHookRunCoalesced` has no nil-metrics dependency. |
| D8 (09-03) | `router_hosts_hook_duration_seconds` still omits the `status` attribute | ✓ VERIFIED | Doc comment preserved, unchanged attribute set in `RecordHookExecution`'s histogram record; not contradicted anywhere in the diff. |
| Prohibition (09-03) | `status="timeout"` is never folded back into `failure` for Rust parity | ✓ VERIFIED | Confirmed as a distinct, first-class constant `hookStatusTimeout` used exclusively for the deadline-exceeded branch. |
| D1-D5 (09-04) | Coalescing bounded at one, conservation law holds, latest-wins, ordering preserved, bounded Stop with cancel-on-deadline | ✓ VERIFIED | `Trigger` (`hookrunner.go:77-97`) captures `coalesced := r.pending != nil` under the mutex before overwriting, records `RecordHookRunCoalesced` exactly once outside the lock; `pending` stays a single pointer, `trigger` channel stays capacity 1 (confirmed live via `rg 'make(chan struct{}, 1)'`); `Stop` drains in-flight + pending, then cancels past the deadline — proven empirically above. |
| Prohibition (09-04) | Pending slot never exceeds depth 1 | ✓ VERIFIED | `pending *hookRunRequest` single field, capacity-1 `trigger` channel — confirmed by source read. |
| Backstop (09-04) | A Trigger arriving at the exact instant a batch finishes never vanishes | ⚠️ INSUFFICIENT_SPEC (abstain) | The claim is explicitly, deliberately unreproducible by test (documented in a `BACKSTOP` comment at the top of `internal/server/hookrunner_test.go`, arguing correctness from mutex total-ordering rather than a targeted interleaving test). Routed to human verification per the honest-verifier contract — this is not a code gap, it is an inherent limit of testing a race at the exact finish instant. |
| D1-D3 (09-05) | Docs no longer claim fixed 30s timeout; document detachment, coalescing, and the coalesced-counter metric row | ✓ VERIFIED | `rg -n 'Hooks run with 30s timeout' docs/guides/operations.md` → no match; `rg -n 'router_hosts_hook_runs_coalesced_total' docs/guides/operations.md docs/contributing/architecture.md` → both present. Confirmed by direct read: operations.md states "before its hooks have completed" and documents coalescing rationale. |
| D2 (09-05) | `docs/reference/configuration.md` documents the nanoseconds footgun with correct-vs-wrong TOML | ✓ VERIFIED | Confirmed by direct read: lines 99-120 state the unquoted-integer-is-nanoseconds behavior with a labelled correct/wrong snippet, negative-rejection rule, and no-upper-bound rationale. |

**Score:** 24/25 truths verified (1 correctly abstained per the honest-verifier backstop contract, 0 failed, 0 present-but-behavior-unverified)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `internal/server/hookrunner.go` | `hookRunner` type, coalescing, bounded Stop | ✓ VERIFIED | Exists, substantive, wired into `hooks.go`'s `Start`/`Stop`/`TriggerSuccess`/`TriggerFailure`. |
| `internal/config/server.go` | `DefaultHookTimeout`, `HookDefinition.Timeout`, `HooksConfig.resolveTimeouts()` | ✓ VERIFIED | All present, called from `LoadServerConfig` in the documented order. |
| `internal/server/hooks.go` | `WithMetrics`, status classifier, async surface | ✓ VERIFIED | Present, wired; classifier ordering confirmed correct by direct read. |
| `internal/server/metrics.go` | `hookRunsCoalescedTotal` + `RecordHookRunCoalesced` | ✓ VERIFIED | Present in both `NewMetrics` and `DisabledMetrics`. |
| `internal/client/commands/serve_wiring.go` | `configureMetricsAndHooks` — metrics before hook executor | ✓ VERIFIED | New file (added during code-review fix pass beyond the original plan text) extracts the wiring into a directly unit-testable function; exceeds the plan's original ask. |
| `docs/guides/operations.md` / `docs/reference/configuration.md` / `docs/contributing/architecture.md` | Updated hook documentation | ✓ VERIFIED | Confirmed accurate against shipped behavior by direct read. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `serve_wiring.go` (`configureMetricsAndHooks`) | `server.NewHookExecutor` | `server.WithMetrics(result.metrics)` called AFTER `server.NewMetricsFromConfig` | ✓ WIRED | Source order confirmed live (metrics block at lines 41-63, hook executor block at 65-79); `TestConfigureMetricsAndHooks_HookExecutorGetsRealMetrics` exists and passes. |
| `service.go` `regenerateOutputs` | `hookrunner.go` `Trigger` | `s.hooks.TriggerSuccess/TriggerFailure` (plain data, no RPC ctx) | ✓ WIRED | Confirmed by direct read; no `s.hooks.Run*` synchronous call remains. |
| `internal/config/server.go` `LoadServerConfig` | `resolveTimeouts()` | called after `meta.Undecoded()`, before `cfg.validate()` | ✓ WIRED | Line-order confirmed live via `rg`. |
| `hooks.go` `executeHook` | `metrics.go` `RecordHookExecution` | called after `CombinedOutput()`, before the oops wrap | ✓ WIRED | Confirmed by direct read of `executeHook`. |
| `hookrunner.go` `Trigger` | `metrics.go` `RecordHookRunCoalesced` | called on supersede, using `context.Background()` | ✓ WIRED | Confirmed by direct read; single call site (`rg -c` = 1). |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Metrics-before-hooks wiring order | `task test -- -run '^TestConfigureMetricsAndHooks' ./internal/client/commands/` | `ok ... 6.354s` | ✓ PASS |
| Timeout kills the subprocess (empirical, not inferred) | `task test -- -run '^TestHookRunner_StopDrainsThenCancels$' -v ./internal/server/` | `--- PASS`, log shows `signal: killed`, marker file absent | ✓ PASS |
| Config permission check remains first statement of `LoadServerConfig` | `rg -n -A3 'func LoadServerConfig' internal/config/server.go` | `checkConfigPermissions(path)` is the first statement | ✓ PASS |
| Coalesced counter is a separate instrument, no `status="skipped"`/`"coalesced"` on executions_total | `rg -n 'hookRunsCoalescedTotal\|hookExecsTotal\|status="skipped"\|status="coalesced"' internal/server/metrics.go` | Two distinct instruments, no forbidden status value | ✓ PASS |

### Full Suite / Coverage

| Command | Result | Status |
|---------|--------|--------|
| `task ci` (lint + buf lint/format + manifests + full `go test -race ./...`) | All packages `ok`, 0 lint issues, manifests up to date | ✓ PASS |
| `task test:coverage:ci` | 85.8% repo-wide (claimed 85.8% — matches exactly); `internal/server` 88.5% (claimed 88.4% — within normal run-to-run variance); `internal/config` 88.3% | ✓ PASS |
| `rumdl check docs/guides/operations.md docs/reference/configuration.md docs/contributing/architecture.md` | 0 issues | ✓ PASS |
| `task docs:build` (strict mode) | Exit 0; regenerated `docs/reference/api.md`/`cli.md` as a known pre-existing drift unrelated to this phase, reverted per SUMMARY's documented practice | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|--------------|--------|----------|
| HOOK-01 | 09-01, 09-03, 09-05 | Server emits execution metrics for hooks (previously dead code) | ✓ SATISFIED | `RecordHookExecution` has real callers on the live path; `serve.go` wires real metrics before the hook executor; verified live via test run. |
| HOOK-02 | 09-01, 09-02, 09-04, 09-05 | Configurable per-hook timeout + bounded concurrency so a slow hook cannot block writes | ✓ SATISFIED | Timeout resolution chain, detachment from RPC path, and bounded coalescing/drain all confirmed live. |

No orphaned requirements — REQUIREMENTS.md lists exactly HOOK-01 and HOOK-02 for Phase 9, both claimed and satisfied.

### Anti-Patterns Found

None. Scanned all phase-modified source and doc files for `TBD`/`FIXME`/`XXX`/`TODO`/`HACK`/`PLACEHOLDER` — zero matches. No debt markers requiring a blocker gate.

### Code Review Disposition (09-REVIEW.md)

The phase's own code review found 0 Critical, 3 Warning, 3 Info findings. Fix disposition (verified against current source, not just trusted from the review doc):

- **WR-01** (`Stop()` before `Start()` deadlocks, ignoring context deadline) — **fixed**, confirmed live: `hookrunner.go`'s `Stop()` checks `!r.started` first (line 109) and returns immediately.
- **WR-02** (`Start()` not idempotent, second call panics) — **fixed**, confirmed live: `Start()` guards on `r.started` (hooks.go / hookrunner.go lines 58-67).
- **WR-03** (no regression test for the HOOK-01 wiring-order fix) — **fixed**, confirmed live: `serve_wiring.go` + `serve_wiring_test.go` exist and `TestConfigureMetricsAndHooks_HookExecutorGetsRealMetrics` passes.
- **IN-01** (`NewHookExecutor` silently produces a zero-timeout hook on non-positive `defaultTimeout`) — **fixed**, confirmed live: `hooks.go:65-67` guards `if defaultTimeout <= 0 { defaultTimeout = config.DefaultHookTimeout }`.
- **IN-02** (a hook killed by `Stop`'s shutdown-cancel records `status="failure"` rather than a distinct outcome) — **consciously skipped**, per instructions a documented tradeoff, not a defect. Not treated as a gap here.
- **IN-03** (three metadata commits used plan-ID scopes) — **consciously skipped**, cosmetic, history not rewritten per repo policy. Not treated as a gap here.

### Known Deferrals (not gaps)

- **Live OTel/Prometheus scrape** (09-05-T3's optional steps) was not performed — no collector was available in the execution session. `09-VALIDATION.md` records this explicitly as "Deferred — not run," distinct from failed. Carried forward here as a human-verification item (see frontmatter) rather than a gap, per the phase's own documented deferral.
- **IN-02** and **IN-03** from the code review, per explicit instruction, are documented tradeoffs/cosmetic issues, not gaps.

## Gaps Summary

No blocking gaps found. Every ROADMAP.md success criterion and every PLAN must-have truth was checked directly against the current source tree (not the SUMMARY narrative), and `task ci` plus `task test:coverage:ci` were run live and matched the phase's own claims almost exactly (85.8% repo coverage matched exactly; `internal/server` at 88.5% vs. claimed 88.4%, an immaterial run-to-run variance).

The **status is `human_needed`, not `passed`**, solely because of two items that are, by the phase's own design, outside what an automated check can close:

1. The 09-04 backstop truth (finish-instant Trigger-vs-batch-completion race) is explicitly documented as unreproducible by test and closed by argument instead — the honest-verifier contract requires this to route to human review rather than being silently marked passed.
2. The optional live OTel scrape was never executed against a real collector, and remains open as a deferred verification item per the phase's own `09-VALIDATION.md`.

Both are pre-existing, explicitly-acknowledged phase decisions (documented in 09-04-PLAN.md's `must_haves` and 09-VALIDATION.md's Manual-Only Verifications table respectively) — they are not new findings and do not indicate incomplete or misrepresented work. If the developer accepts the mutex-ordering argument for the 09-04 backstop and is comfortable shipping without a live scrape (unit tests already prove instrument registration and the recording call sites), this phase is ready to ship.

---

*Verified: 2026-07-31T16:51:16Z*
*Verifier: Claude (gsd-verifier)*
