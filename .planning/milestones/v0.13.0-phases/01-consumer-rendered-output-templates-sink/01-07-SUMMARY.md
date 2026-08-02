---
phase: 01-consumer-rendered-output-templates-sink
plan: 07
subsystem: client
tags: [cli, sink, streaming, goroutine, backoff, sidecar, exec-hook, tdd]

requires:
  - phase: 01-consumer-rendered-output-templates-sink (plan 02, wave 1-2)
    provides: "internal/client/template contract-v1 (DeclaredVersion/RequireVersion/FromProto/Render), .ChangeID as a lower bound"
  - phase: 01-consumer-rendered-output-templates-sink (plan 03, wave 3)
    provides: "streamLimits/limitsFrom(*client.Client) client-side collection caps, applied here to the watch drain loop"
  - phase: 01-consumer-rendered-output-templates-sink (plan 06, wave 4)
    provides: "server-side WatchHosts follow mode, SinkStatus wire message, sendSnapshot's derive-before-ListAll change ID"
provides:
  - "internal/client/commands/sinkstatus.go: sinkStatus record, sinkHealthState (the single mutex-guarded owner of write health and reload health), writeSinkStatus/readSinkStatus over internal/atomicfile"
  - "internal/client/commands/posthook.go: runPostWriteHook, mirroring internal/server/hooks.go's exec.CommandContext + timeout-before-exit-status classification"
  - "internal/client/commands/watchpolicy.go: WatchPolicy (InitialBackoff, MaxBackoff, StatusInterval, Jitter), DefaultWatchPolicy, normalized() — one exported, injectable runtime policy with no mutable production globals"
  - "internal/client/commands/root.go: RootOption, WithWatchPolicy, NewRootCmd(opts ...RootOption) — the external test seam (review H4)"
  - "internal/client/commands/watch.go: router-hosts watch — newWatchCmd, runWatch (single session), runWatchRecvLoop, runWatchCycle, runWatchSupervised (reconnect+backoff)"
affects: [01-08]

actuals:
  tokens: 20560
  tasks: 3
  commits: 8

tech-stack:
  added: []
  patterns:
    - "sinkHealthState: one mutex-guarded type is the sole owner of state shared between a receive loop (writer) and a status ticker (reader); the reader only ever calls snapshot(), which returns a value copy — the same discipline internal/server/hookrunner.go already uses in this repo"
    - "Per-session context derived via context.WithCancel and explicitly cancelled (not only deferred) before waiting on a goroutine's completion channel, so a client stream's blocked Send is released before the wait begins and cannot deadlock — mirrors, but is not identical to, the server's non-joining handler in plan 06 (there, returning ends the RPC; here, the RPC is already aborted before the wait starts)"
    - "watchSessionResult{SnapshotWritten bool} as a second return value alongside error, so a supervising loop can reset backoff on 'this session got data to disk' independent of 'this session ended with an error' — an error-only contract cannot express both"
    - "WatchPolicy passed by value through an exported constructor option (RootOption/WithWatchPolicy), replacing package-level backoff variables so an external test package (plan 08's e2e_test) can inject deterministic timing"
    - "fakeHostsServiceClient (embeds the real hostsv1.HostsServiceClient interface, overrides only WatchHosts) and fakeWatchStream (implements the bidi stream interface directly) drive sink-cycle and goroutine-teardown behavior deterministically instead of over a real network stream, mirroring internal/server/watch_test.go's fakeWatchHostsStream precedent"

key-files:
  created:
    - internal/client/commands/sinkstatus.go
    - internal/client/commands/sinkstatus_test.go
    - internal/client/commands/posthook.go
    - internal/client/commands/posthook_test.go
    - internal/client/commands/watchpolicy.go
    - internal/client/commands/watchpolicy_test.go
    - internal/client/commands/watch.go
    - internal/client/commands/watch_test.go
  modified:
    - internal/client/commands/root.go

key-decisions:
  - "recordReloadFailure never touches ConsecutiveFailures — D-12a's middle outcome (artifact written, hook failed) leaves write health exactly as recordSuccess set it; reload health (reload_failed, last_reload_success) is a fully separate pair of fields, never derived from write health"
  - "The artifact is never rolled back after a hook runs. There is no code path in watch.go that rewrites --out with previously captured content, and no previous-content variable is retained across a write — retention plus a distinguishable reload_failed signal is the whole contract (D-12a)"
  - "The D-21 change-ID skip is guarded on three conditions in one expression: ID equality AND the artifact still exists (os.Stat) AND reload health is not failed. Dropping any one reintroduces a permanent failure mode: without the artifact check, an out-of-band deletion is never repaired (T-1-36); without the reload-health check, a failed reload can never retry because the artifact already carries the matching change ID (review M4, T-1-46)"
  - "runWatch derives its own cancellable session context and calls sessCancel() explicitly — not only via defer — immediately after the receive loop returns and BEFORE waiting on the status ticker's completion channel. The explicit call is what actually releases a ticker blocked in Send on flow control; the deferred call is the safety net for a panic or early-return path (review M5, round-3 M3)"
  - "The reconnect loop's backoff reset keys on watchSessionResult.SnapshotWritten, not on err == nil (review H5): a session that wrote successfully and only later lost its stream must still reset the backoff, and TestWatch_BackoffResetsAfterSuccessfulWriteEvenIfSessionLaterFails asserts exactly that case by timing the gap between reconnect attempts"
  - "--status-interval's own registered default is WatchPolicy.normalized().StatusInterval, not a literal duration; cmd.Flags().Changed(\"status-interval\") is what distinguishes an operator's explicit override from Cobra's filled-in default (review round-3 M2) — verified RED against a literal 30s default before being accepted"
  - "The sidecar is loaded at startup and adopted into sinkHealthState only when the artifact at --out still exists; when it does not, the loaded rendered_change_id is discarded and health starts empty, rather than partially trusting a record that describes data no longer on disk (review M3)"
  - "Sink-cycle and goroutine-teardown behavior is tested via a fake WatchHosts stream/client (no bufconn, no real network) for determinism and speed; only the startup-adoption and basic write/mutation paths use the real bufconn server, mirroring the fake-vs-real split plan 06 established server-side"

patterns-established:
  - "watchParams struct groups every value one runWatch/runWatchCycle call needs, following the streamLimits/limitsFrom precedent from plan 03 — no call site can pass some fields and forget others"

requirements-completed: [TMPL-03, TMPL-05, TMPL-08]

coverage:
  - id: D1
    description: "A long-lived watch keeps --out current as host data changes, with no polling; starting the command writes the artifact once immediately, and a mutation triggers a rewrite with no operator action"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch_test.go#TestWatch_WritesInitialArtifact,TestWatch_RewritesOnMutation"
        status: pass
    human_judgment: false
  - id: D2
    description: "Entries are buffered until the SnapshotComplete terminator; a partial snapshot (entries with no terminator) is never rendered, and the artifact reset happens after every terminator and every error path so an interrupted stream cannot produce a truncated artifact"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch_test.go#TestWatch_PartialSnapshotNotRendered"
        status: pass
    human_judgment: false
  - id: D3
    description: "Every pre-write failure mode (cap exceeded, contract version mismatch, render error) leaves the previous artifact byte-identical and records the failure to the sidecar without touching last_success or rendered_change_id"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch_test.go#TestWatch_CapExceededPreservesArtifact,TestWatch_VersionMismatchPreservesArtifact,TestWatch_RenderErrorPreservesArtifactAndRecordsFailure; internal/client/commands/sinkstatus_test.go#TestSinkStatus_FailurePreservesLastSuccess,TestSinkStatus_FailurePreservesRenderedChangeID"
        status: pass
    human_judgment: false
  - id: D4
    description: "D-12a's three-outcome model is implemented and distinguishable: a hook failure retains the NEWLY rendered artifact (never rolls back) and sets reload_failed alongside the new last_success, without incrementing consecutive_failures; a subsequent hook success clears reload_failed"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch_test.go#TestWatch_HookFailureRetainsNewArtifact,TestWatch_SuccessRunsPostWriteHook; internal/client/commands/sinkstatus_test.go#TestSinkStatus_ReloadFailureKeepsWriteHealth,TestSinkStatus_ReloadSuccessClearsFlag"
        status: pass
    human_judgment: false
  - id: D5
    description: "The D-21 client-side change-ID skip fires only when all three guards hold (ID match, artifact still exists, reload health not failed); an out-of-band artifact deletion is repaired despite a matching ID, and a failed reload is retried on the next identical snapshot rather than suppressed forever"
    requirement: "TMPL-08"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch_test.go#TestWatch_SkipsRedundantRenderOnSameChangeID,TestWatch_RendersWhenArtifactMissingDespiteSameChangeID,TestWatch_RetriesHookWhileReloadFailed"
        status: pass
    human_judgment: false
  - id: D6
    description: "The sidecar status file (D-11) is written atomically through internal/atomicfile, distinguishes write health from reload health as separate fields, and is read back faithfully; a missing file is not an error (first run), a corrupt file is; concurrent readers/writers of the health state produce no data race under -race"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/sinkstatus_test.go#TestSinkStatus_WriteAndRead,TestSinkStatus_SuccessClearsError,TestSinkStatus_DefaultPath,TestSinkStatus_ReadMissingFileIsNotAnError,TestSinkStatus_ReadCorruptFileErrors,TestSinkStatus_ConcurrentAccess,TestSinkStatus_Adopt,TestSinkStatus_SetContractVersion"
        status: pass
    human_judgment: false
  - id: D7
    description: "A post-write hook (D-16) exits zero returns no error, exits non-zero returns a named-exit-status error, outruns its timeout and is classified as a timeout (not a generic failure) via the same hookCtx.Err()-before-process-error ordering internal/server/hooks.go uses, and an empty command is a no-op"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/posthook_test.go#TestPostWriteHook_Success,TestPostWriteHook_NonZeroExit,TestPostWriteHook_Timeout,TestPostWriteHook_EmptyCommandIsNoop,TestPostWriteHook_DefaultTimeoutConstant"
        status: pass
    human_judgment: false
  - id: D8
    description: "WatchPolicy is one exported, injectable value (backoff bounds, jitter, status interval) with no mutable production globals; a nil Jitter or zero-valued field normalizes safely; the --status-interval flag's own default comes from the resolved policy, and only an explicit flag change overrides it — verified RED against a literal 30s default"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/watchpolicy_test.go#TestWatchPolicy_Defaults,TestWatchPolicy_NormalizesZeroFields,TestWatchPolicy_NilJitterIsSafe,TestWatchPolicy_DefaultJitterInRange; internal/client/commands/watch_test.go#TestWatch_StatusIntervalDefaultsFromPolicy,TestWatch_ExplicitStatusIntervalFlagOverridesPolicy"
        status: pass
    human_judgment: false
  - id: D9
    description: "The status-sender goroutine cannot outlive its session: runWatch derives a per-session cancellable context, cancels it explicitly before waiting (bounded) on the ticker's completion channel, and the wait is observed to actually depend on the ticker's own exit rather than merely being intended"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch_test.go#TestWatch_StatusTickerStopsWithSession"
        status: pass
    human_judgment: false
  - id: D10
    description: "A restarted consumer loads its sidecar at startup and adopts it only when the artifact it describes still exists; when the artifact is present the first identical snapshot is skipped (no hook run), and when the artifact is missing the loaded change ID is discarded and the hook runs"
    requirement: "TMPL-08"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch_test.go#TestWatch_LoadsSidecarAtStartup"
        status: pass
    human_judgment: false
  - id: D11
    description: "A stream ending in error triggers a reconnect after a bounded, exponentially-increasing, jittered wait; the wait resets to InitialBackoff based on the session's SnapshotWritten result (not its error), including when a session wrote successfully and only failed later; cancelling during a backoff wait returns promptly; a reconnect is byte-identical when nothing changed and resets the sidecar's consecutive-failure count on recovery"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch_test.go#TestWatch_ReconnectsAfterStreamError,TestWatch_ReconnectNoTruncation,TestWatch_BackoffResetsAfterSuccess,TestWatch_BackoffResetsAfterSuccessfulWriteEvenIfSessionLaterFails,TestWatch_ReconnectResetsConsecutiveFailures,TestWatch_CancelDuringBackoffReturnsPromptly"
        status: pass
    human_judgment: false
  - id: D12
    description: "The sink reports status upstream (last_success, consecutive_failures, contract_version, rendered_change_id, reload_failed, last_reload_success) on the opening message and on a periodic ticker, on the same stream it already holds open"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/watch.go#sinkStatusToProto,sendStatusTicker (opening request carries health.snapshot(); server-side recording already proven in plan 06's TestService_WatchHosts_FollowRecordsOpeningStatus/FollowRecordsStatus)"
        status: pass
    human_judgment: true
    rationale: "This plan proves the client constructs and sends the correct SinkStatus payload at the right times (opening message, periodic ticker); a genuine end-to-end proof that the server records and exposes it correctly through metrics was plan 06's responsibility and is not re-verified here. Plan 08's e2e suite is the natural place for a full round-trip check with both halves live."

duration: 23min
completed: 2026-08-01
status: complete
---

# Phase 1 Plan 07: Client Sink CLI — watch, Status File, Reconnect Summary

**`router-hosts watch` is now a real sink: a long-lived, snapshot-boundary-rendering, self-reconnecting CLI command that reports its own health both upstream and to a local sidecar, distinguishes all three D-12a sink-cycle outcomes, and never rolls the artifact back once a hook has run.**

## Performance

- **Duration:** 23 min
- **Tasks:** 3
- **Files modified:** 9 (8 created, 1 modified)

## Accomplishments

- `internal/client/commands/sinkstatus.go`: `sinkStatus` (the D-11 sidecar record: last_success, last_error, consecutive_failures, contract_version, rendered_change_id, reload_failed, last_reload_success) and `sinkHealthState`, the single mutex-guarded owner of every field shared between the receive loop and the status ticker. `recordSuccess`/`recordFailure` cover D-12a's write-health outcomes; `recordReloadFailure`/`recordReloadSuccess` cover reload health as a fully separate pair of fields — `recordReloadFailure` never touches `consecutive_failures`. `writeSinkStatus`/`readSinkStatus` go through `internal/atomicfile`; a missing sidecar is not an error, a corrupt one is.
- `internal/client/commands/posthook.go`: `runPostWriteHook` mirrors `internal/server/hooks.go`'s `exec.CommandContext` shape and its timeout-before-exit-status classification order exactly, so a deadline kill is never misreported as a generic non-zero exit.
- `internal/client/commands/watchpolicy.go` + `root.go`: `WatchPolicy` (InitialBackoff, MaxBackoff, StatusInterval, Jitter) is one exported, pass-by-value runtime policy — no package-level backoff variables exist anywhere in the package. `NewRootCmd` gained a variadic `opts ...RootOption` parameter and `WithWatchPolicy`, with every pre-existing `NewRootCmd()` call site left unedited.
- `internal/client/commands/watch.go`: `newWatchCmd` (the `watch` command, `--template`/`--out`/`--exec`/`--status-file`/`--status-interval`/`--exec-timeout`), `runWatch` (one stream session — opens with the current health snapshot as status, runs a status ticker and a receive loop concurrently, and cannot let the ticker outlive the session), `runWatchRecvLoop` (buffers entries until the terminator, applies the plan 03 caps, refuses the whole snapshot rather than truncating), `runWatchCycle` (the ordered D-12a cycle: version gate → D-21 change-ID skip → render → atomic write → recordSuccess → hook → sidecar write), and `runWatchSupervised` (the reconnect loop with policy-driven exponential backoff, jitter, and a reset keyed on `watchSessionResult.SnapshotWritten` rather than on the accompanying error).
- 43 new test functions (12 sinkstatus, 5 posthook, 4 watchpolicy, 22 watch) plus 2 subtests, all green under `-race`; the watch-command suite alone was additionally run at `-count=5` with no flake and completes in ~15s, well under the plan's 60-second bound.

## Task Commits

Each task followed TDD RED → GREEN, both committed atomically:

1. **Task 1: Sidecar status file, ownership model, and the post-write exec hook**
   - `5c79676` (test) — RED: failing tests for sink status, hook, and watch policy (build failure)
   - `6d00bcf` (feat) — GREEN: `WatchPolicy`/`DefaultWatchPolicy`/`RootOption`/`WithWatchPolicy`/variadic `NewRootCmd`
   - `abb6670` (feat) — GREEN: `sinkStatus`/`sinkHealthState`/`writeSinkStatus`/`readSinkStatus`/`runPostWriteHook`
2. **Task 2: The watch command — snapshot-boundary render, atomic write, upstream status**
   - `96e00fa` (test) — RED: failing tests for the watch sink command (build failure)
   - `4678881` (feat) — GREEN: `newWatchCmd`/`runWatch`/`runWatchRecvLoop`/`runWatchCycle`
3. **Task 3: Self-healing reconnect with bounded backoff**
   - `a56600d` (test) — RED: failing tests for reconnect backoff (build failure)
   - `74f65e5` (feat) — GREEN: `runWatchSupervised`
4. **Post-commit fix** (acceptance-criteria compliance, no behavior change)
   - `11d61c4` (docs) — reworded a comment that incidentally spelled out `commandContext()`/`signal.NotifyContext` a second time, which would have made two of the plan's exact-count grep gates fail

## Files Created/Modified

- `internal/client/commands/sinkstatus.go`, `sinkstatus_test.go` — the D-11 sidecar record and its ownership model
- `internal/client/commands/posthook.go`, `posthook_test.go` — the D-16 post-write exec hook
- `internal/client/commands/watchpolicy.go`, `watchpolicy_test.go` — the injectable runtime policy
- `internal/client/commands/watch.go`, `watch_test.go` — the `watch` command, its single-session and reconnect-supervised runners
- `internal/client/commands/root.go` — `RootOption`, `WithWatchPolicy`, variadic `NewRootCmd`, `watch` command registration

## Decisions Made

- **The artifact is never rolled back after a hook runs, structurally, not just by convention.** There is no code path in `watch.go` that rewrites `--out` with previously captured content, and no previous-content variable is retained across a write — verified both by test (`TestWatch_HookFailureRetainsNewArtifact` asserts the on-disk bytes are the *new* content) and by inspection (no such variable exists in the file).
- **The D-21 skip guard is one boolean expression checking all three conditions together** (ID match, artifact exists, reload health not failed), specifically so a future edit cannot silently drop one guard without visibly touching the same line the others are on.
- **`runWatchSupervised`'s backoff reset reads `watchSessionResult.SnapshotWritten`, never `err == nil`.** `TestWatch_BackoffResetsAfterSuccessfulWriteEvenIfSessionLaterFails` proves this by timing the gap between reconnect attempts: a session that wrote a snapshot and then failed still produces an `InitialBackoff`-sized wait, not a doubled one.
- **Sink-cycle and goroutine-teardown tests use a fake `WatchHosts` stream/client, not bufconn**, for the same reason plan 06 used a hand-rolled fake server-side: deterministic control over `Send`/`Recv` blocking behavior beats timing a real network stream. Only the startup-adoption and basic mutation-observing tests use the real bufconn server, where the shape of a genuine round trip matters more than microsecond control.
- **The two `--status-interval` precedence tests were written in `watch_test.go`, not `watchpolicy_test.go`** (where the pre-review plan text placed them), because they exercise `newWatchCmd`'s own flag registration and `Changed()` check, neither of which exists until Task 2's `watch.go` lands. Recorded as a deviation below and in `.planning/WINDOWS.md`.
- **`recordReloadFailure` accepts an unused `time.Time` parameter** for signature symmetry with `recordSuccess`/`recordReloadSuccess`; today's `sinkStatus` contract has no last-reload-*attempt* field (only last-reload-*success*) to store it in.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 — missing test coverage for a lint gate] `adopt()`, `setContractVersion()`, and `defaultPostWriteHookTimeout` were unused after Task 1 alone**

- **Found during:** Task 1's own `<verify>` step (`task lint`), before Task 2's `watch.go` (their only production caller) existed
- **Issue:** `golangci-lint`'s `unused` check failed on three symbols that Task 1 defines but Task 2 is the one that calls
- **Fix:** Added `TestSinkStatus_Adopt`, `TestSinkStatus_SetContractVersion`, and `TestPostWriteHook_DefaultTimeoutConstant` — legitimate, independently-useful unit tests of behavior the plan already specifies these methods/constant must have, exercised before their eventual caller exists rather than deferred
- **Files modified:** `internal/client/commands/sinkstatus_test.go`, `internal/client/commands/posthook_test.go`
- **Commit:** `abb6670` (folded into Task 1's GREEN commit, since it was discovered during that task's own verification step)

**Total deviations:** 1 auto-fixed (Rule 2) + 1 sequencing deviation (recorded in `.planning/WINDOWS.md`, entry #1: the two status-interval precedence tests moved from Task 1's file to Task 2's, for the reason above)
**Impact on plan:** No scope creep and no functional gap — every must-have truth and every enumerated test in `01-07-PLAN.md` is present and passing; the only changes are (a) two extra unit tests proving methods the plan already specified, and (b) two tests living in a different file than the pre-review plan text named, for a reason intrinsic to what those tests exercise.

## RED Verifications (mandatory per plan)

- **`TestWatchPolicy_StatusIntervalDefaultsFromPolicy`** was run against a `--status-interval` flag registered with a literal `30 * time.Second` default and confirmed to fail (`expected: "50ms", actual: "30s"`) before the flag's default was changed to `normalizedPolicy.StatusInterval` and the test re-verified green.
- **`TestWatch_StatusTickerStopsWithSession`** was run against a temporarily-modified `runWatch` that called `sessCancel()` but never waited on `tickerDone` before returning, and confirmed to fail (`"51.270792ms" is not greater than or equal to "200ms"` — `runWatch` returned before the ticker, still blocked in `Send`, had actually exited). The wait was restored and the test re-verified green, including at `-count=5` under `-race`.
- Both `internal/client/commands/watch_test.go` and `internal/client/commands/watch.go`, and `internal/client/commands/sinkstatus_test.go`/`posthook_test.go`/`watchpolicy_test.go`, were confirmed to produce genuine build failures (undefined symbols) before their corresponding implementation commits, per the TDD RED discipline this project runs under.

## Issues Encountered

- An early draft of `fakeWatchStream.Send` blocked on *every* call, including the opening `follow=true` request `runWatch` sends synchronously before spawning the ticker or receive loop — which meant `TestWatch_StatusTickerStopsWithSession` was accidentally exercising the OPENING send's block, not the ticker's, and would have passed even with the `tickerDone` wait removed (a silently non-discriminating test). Fixed by making only calls after the first block, and by making `Recv` block until context cancellation (simulating a live idle stream) rather than returning `io.EOF` immediately — which is what let the RED verification above actually distinguish the two implementations.
- Pre-existing sandbox noise (documented in prior plans' summaries, not introduced here): `host add` integration tests log `create temp file: open /dev/null.tmp.* : operation not permitted` because `setupCmdTest`'s `HostsFileGenerator` points at `/dev/null`; the error is logged, not returned, so affected tests still pass.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

Plan 08 (e2e suite and operator guide) can now drive a real `router-hosts watch` process against a real server, using `WithWatchPolicy` from outside this package (it is `RootOption`, exported, and the whole point of the H4 fix) to inject millisecond backoff bounds and a deterministic jitter for its own timing assertions. The sidecar contract (`sinkStatus` JSON shape) and the sink-cycle ordering are stable and match `docs/reference/template-contract.md`'s D-12a table from plan 02.

No blockers. `task test ./internal/client/...` is green under `-race` (including `-count=5`/`-count=10` repeated runs of the concurrency-sensitive suites); `task lint` reports 0 issues; `git diff` for this plan adds no line matching `nolint`; `task test` for the whole repository is green.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-01*

## Self-Check: PASSED

- FOUND: `internal/client/commands/sinkstatus.go`
- FOUND: `internal/client/commands/sinkstatus_test.go`
- FOUND: `internal/client/commands/posthook.go`
- FOUND: `internal/client/commands/posthook_test.go`
- FOUND: `internal/client/commands/watchpolicy.go`
- FOUND: `internal/client/commands/watchpolicy_test.go`
- FOUND: `internal/client/commands/watch.go`
- FOUND: `internal/client/commands/watch_test.go`
- FOUND: `internal/client/commands/root.go`
- FOUND: `5c79676` (test(01-07): add failing tests for sink status and watch policy)
- FOUND: `6d00bcf` (feat(client): add injectable watch runtime policy)
- FOUND: `abb6670` (feat(client): add sink status file and exec hook)
- FOUND: `96e00fa` (test(01-07): add failing tests for watch sink command)
- FOUND: `4678881` (feat(client): add watch sink command)
- FOUND: `a56600d` (test(01-07): add failing tests for reconnect backoff)
- FOUND: `74f65e5` (feat(client): reconnect sink stream with backoff)
- FOUND: `11d61c4` (docs(client): avoid literal commandContext/NotifyContext count drift)
