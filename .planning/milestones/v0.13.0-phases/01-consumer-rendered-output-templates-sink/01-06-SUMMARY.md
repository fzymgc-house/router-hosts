---
phase: 01-consumer-rendered-output-templates-sink
plan: 06
subsystem: server
tags: [grpc, streaming, goroutine, otel, mtls, sink-health, concurrency]

requires:
  - phase: 01-consumer-rendered-output-templates-sink (plan 01, wave 1)
    provides: "WatchHosts one-shot mode, sendSnapshot's derive-before-ListAll ordering, internal/contract"
  - phase: 01-consumer-rendered-output-templates-sink (plan 04, wave 2)
    provides: "gRPC keepalive on both sides, bounding the network-alive assumption the H1 teardown fix relies on"
  - phase: 01-consumer-rendered-output-templates-sink (plan 05, wave 3)
    provides: "commonNameFromContext, SinkHealth registry, RegisterSinkGauges — standalone, unit-tested primitives this plan wires in"
  - phase: 01-consumer-rendered-output-templates-sink (plan 09, wave 1)
    provides: "internal/eventid, LatestEventID, ZeroChangeID"
provides:
  - "internal/server/changenotify.go: changeNotifier — channel-close-as-broadcast fan-out primitive, coalescing bursts to at most one additional wake per busy subscriber"
  - "Notify() wired as the first statement of regenerateOutputs (every host mutation, before any generator) and as the second/last call site in a successful non-dry-run CompactAggregates (review round-3 H1)"
  - "internal/server/watch.go: WatchHosts follow mode — a genuine continuous sink with a non-joining two-goroutine handler (H1 fix), sendSnapshot extracted and shared between one-shot and follow paths"
  - "internal/client/commands/serve_wiring.go: SinkHealth constructed and wired into the real server startup path, with and without OTel"
affects: [01-07, 01-08]

actuals:
  tokens: 15100
  tasks: 3
  commits: 6

tech-stack:
  added: []
  patterns:
    - "Channel-close-as-broadcast fan-out (changeNotifier): closing the current generation channel releases every waiter simultaneously; taking the current channel after waking gives burst coalescing for free"
    - "Non-joining goroutine-pair stream handler: the handler goroutine owns neither Send nor Recv, selects on a capacity-2 error channel, and returns on the first error — returning from the handler (ending the RPC) is what unblocks a stalled Send or an idle Recv, not context cancellation"
    - "Hand-rolled fake implementing a generic gRPC streaming interface (fakeWatchHostsStream) to drive Send/Recv blocking behavior deterministically in tests, instead of depending on real network timing"
    - "Manufactured verified-peer context via peer.NewContext + credentials.TLSInfo (same technique as peercn_test.go) to exercise identity-keyed recording paths without a real mTLS handshake"

key-files:
  created:
    - internal/server/changenotify.go
    - internal/server/changenotify_test.go
  modified:
    - internal/server/service.go
    - internal/server/watch.go
    - internal/server/watch_test.go
    - internal/client/commands/serve_wiring.go
    - internal/client/commands/serve_wiring_test.go

key-decisions:
  - "The handler goroutine in watchFollow owns neither Send nor Recv and never joins the two goroutines it spawns (review H1) — this is the plan's central design decision and is enforced by a negative grep for sync.WaitGroup/wg.Wait() plus two teardown tests, both independently verified RED against a temporarily-reintroduced wg.Wait()-style join (see 'H1 RED Verification' below)"
  - "changeNotifier promises AT MOST one additional wake per busy subscriber during a burst, never a strict 'fewer than N' bound — the coalescing test (TestChangeNotifier_CoalescesBurst) controls its own timing to prove this deterministically; the stream-level burst test asserts convergence (upper bound N+1, final-state equality) instead of a wake count, per review M2"
  - "Notify() is the first statement of regenerateOutputs, above every generator block and the hooks early-return, so watcher latency is independent of server-owned filesystem generation and covers the generator-less deployment case (review M2)"
  - "CompactAggregates gets its own, second notify call site (gated on !dryRun && shrunk) since it never calls regenerateOutputs and would otherwise leave the change ID stale after a real compaction (review round-3 H1) — verified RED with the call temporarily removed"
  - "sendSnapshot is extracted so the one-shot and follow paths share one implementation, preserving plan 01's derive-before-ListAll ordering by construction rather than by convention"
  - "A client-reported rendered_change_id is recorded into SinkHealth but never read by the send path (D-21) — enforced by a dedicated test that reports the server's own current change ID and asserts a full snapshot still arrives"
  - "An unverifiable peer identity still streams, still moves the connected count, but records no per-identity health and increments a separate identity-failure counter, logged at warn (review L11)"

patterns-established:
  - "TDD RED verified via genuine test failure (not just build failure) for teardown-sensitive tests: the naive pre-review shape (handler owns Recv directly, single sender goroutine, cancel()+wg.Wait() before return) was temporarily reintroduced and both H1 teardown tests were confirmed to hang/fail before being reverted"

requirements-completed: [TMPL-06, TMPL-08]

coverage:
  - id: D1
    description: "A host mutation wakes every open watcher with no polling; a burst of mutations produces at most one additional wake per busy watcher (deterministic coalescing proof) and the stream converges on the final state (at most N+1 snapshots for N mutations, final entries and change ID match store state)"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/server/changenotify_test.go#TestChangeNotifier_ReleasesSubscriber,TestChangeNotifier_ReleasesAllSubscribers,TestChangeNotifier_SubscriptionAfterNotifyStillWaits,TestChangeNotifier_NotifyWithNoSubscribers,TestChangeNotifier_CoalescesBurst,TestChangeNotifier_ConcurrentUse; internal/server/watch_test.go#TestService_WatchHosts_FollowInitialSnapshot,TestService_WatchHosts_FollowPushesOnMutation,TestService_WatchHosts_FollowConvergesAfterBurst"
        status: pass
    human_judgment: false
  - id: D2
    description: "Every path that can move MAX(event_id) — any host mutation on any deployment configuration, and a successful non-dry-run compaction that actually shrinks an aggregate — reaches exactly one of two notify call expressions; a dry run and a no-op compaction notify nobody"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/server/changenotify_test.go#TestService_RegenerateOutputs_NotifiesWithoutGenerators,TestService_CompactAggregates_Notifies,TestService_CompactAggregates_DryRunDoesNotNotify,TestService_CompactAggregates_NoOpDoesNotNotify"
        status: pass
    human_judgment: false
  - id: D3
    description: "The follow-mode handler returns on the first error from either stream direction without ever joining a goroutine that may be blocked in Send or Recv, in both reviewer-identified windows (Send fails while Recv is idle; Recv sees EOF while Send is blocked on flow control), and repeated connect/disconnect churn returns the connected count to zero without accumulating goroutines"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/server/watch_test.go#TestService_WatchHosts_FollowSendErrorReturnsWhileRecvIdle,TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked,TestService_WatchHosts_FollowContextCancelReturns,TestService_WatchHosts_FollowChurnDoesNotAccumulate"
        status: pass
    human_judgment: false
  - id: D4
    description: "A consumer status report (opening message or mid-stream) updates that consumer's health record keyed only by verified mTLS common name; an unverifiable identity still streams but records no per-identity health and increments a separate identity-failure counter; a client-reported change ID never influences what the server sends; the follow-mode snapshot change ID remains a strict lower bound on its entries"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/server/watch_test.go#TestService_WatchHosts_FollowRecordsStatus,TestService_WatchHosts_FollowRecordsOpeningStatus,TestService_WatchHosts_FollowWithoutPeerIdentityStillStreams,TestService_WatchHosts_FollowIgnoresReportedChangeIDForSendDecision,TestService_WatchHosts_FollowSnapshotIDIsLowerBoundOnEntries"
        status: pass
    human_judgment: false
  - id: D5
    description: "Sink health is wired into the real server startup path, constructed unconditionally before the metrics block so status recording works with or without OTel, with sink gauges registered immediately after the existing aggregate-event gauges when OTel is configured"
    requirement: "TMPL-05"
    verification:
      - kind: unit
        ref: "internal/client/commands/serve_wiring_test.go#TestConfigureMetricsAndHooks_SinkHealthWithMetrics,TestConfigureMetricsAndHooks_SinkHealthWithoutMetrics,TestConfigureMetricsAndHooks_SinkOptionAlwaysPresent"
        status: pass
    human_judgment: false

duration: 21min
completed: 2026-08-01
status: complete
---

# Phase 1 Plan 06: Server-Side Sink Streaming — Change Notification and Follow Mode Summary

**`WatchHosts` follow mode is now a real continuous sink: a `changeNotifier` fan-out primitive wakes every open watcher on any host mutation or real compaction, and a deliberately non-joining two-goroutine stream handler pushes coalesced snapshots while independently recording per-consumer status keyed by verified mTLS identity — with both reviewer-identified teardown deadlocks proven fixed by tests that were confirmed to hang under the pre-review shape.**

## Performance

- **Duration:** 21 min
- **Tasks:** 3
- **Files modified:** 7 (2 created, 5 modified)

## Accomplishments

- `internal/server/changenotify.go`: `changeNotifier`, a channel-close-as-broadcast fan-out primitive. Closing the current generation channel releases every waiter at once; taking the current channel after waking collapses a burst to at most one additional wake per busy subscriber — stated precisely as an upper bound, never a "fewer than N" promise (review M2).
- `Notify()` wired as the first statement of `regenerateOutputs` (above every generator block and the hooks early-return), so watcher latency never waits on server-owned filesystem generation and is not skipped on a generator-less deployment. `CompactAggregates` gets its own second and last notify call site, gated on a successful non-dry-run compaction that actually shrunk an aggregate (review round-3 H1) — a dry run or a no-op compaction wakes nobody.
- `internal/server/watch.go`: follow mode replaces the `Unimplemented` stub with a genuine sink. `sendSnapshot` is extracted so one-shot and follow-mode share one terminator-and-change-ID implementation, preserving plan 01's derive-before-`ListAll` ordering. The follow handler spawns exactly two goroutines — one owning `Send`, one owning `Recv` — and never joins either; it selects on a capacity-2 error channel and returns on the first error, which is what actually unblocks a stalled `Send` or an idle `Recv` (review H1).
- Peer identity is resolved once via `commonNameFromContext`; failure logs at warn and increments `SinkHealth.RecordIdentityFailure()` (review L11) rather than substituting anything caller-supplied. A status payload on the opening message is recorded, not discarded (review L3). `rendered_change_id` is recorded but never read by the send path (D-21), enforced by a dedicated test.
- `internal/client/commands/serve_wiring.go`: `SinkHealth` is constructed unconditionally, before the metrics block, and `WithSinkHealth` is appended to `svcOpts` unconditionally so a deployment without OTel still gets status recording. `RegisterSinkGauges` runs immediately after the existing `RegisterAggregateEventGauges` call when OTel is configured.
- 29 new tests (6 notifier + 4 mutation/compaction-notify + 19 follow-mode-relevant `TestService_WatchHosts_*` incl. 7 pre-existing one-shot tests unchanged + 3 wiring tests), all green under `-race`; `-count=20` on the notifier and `-count=10` on follow mode show no flake; full repo `task test` and `task lint` both clean.

## Task Commits

Each task followed TDD RED -> GREEN, both committed atomically:

1. **Task 1: Broadcast change notification wired into the write path**
   - `85f9a36` (test) — RED: failing tests for change notification (build failure: `svc.changes` undefined)
   - `1729aba` (feat) — GREEN: `changeNotifier` + `Notify()` at the top of `regenerateOutputs` + the `CompactAggregates` notify site
2. **Task 2: Follow mode — concurrent snapshot push and status receive**
   - `be13b50` (test) — RED: failing tests for follow-mode streaming (build failure: `WithSinkHealth`/`svc.watchFollow` undefined)
   - `0cfa864` (feat) — GREEN: `watchFollow`, `watchFollowSend`, `watchFollowRecv`, `sinkStateFromStatus`, shared `sendSnapshot`
3. **Task 3: Wire sink health into the running server**
   - `001c921` (test) — RED: failing tests for sink health wiring (build failure: `hooksAndMetrics.sinkHealth` undefined)
   - `d8a14eb` (feat) — GREEN: `SinkHealth` construction + `WithSinkHealth` + `RegisterSinkGauges` in `configureMetricsAndHooks`

## Files Created/Modified

- `internal/server/changenotify.go` — `changeNotifier`, `newChangeNotifier`, `Subscribe`, `Notify`
- `internal/server/changenotify_test.go` — 6 `TestChangeNotifier_*` tests, `TestService_RegenerateOutputs_NotifiesWithoutGenerators`, 3 `TestService_CompactAggregates_*Notif*` tests
- `internal/server/service.go` — `changes *changeNotifier` and `sinkHealth *SinkHealth` fields on `HostsServiceImpl`, `WithSinkHealth` option, `Notify()` call at the top of `regenerateOutputs`, the gated notify call in `CompactAggregates`
- `internal/server/watch.go` — `sendSnapshot` (extracted, shared), `watchFollow`, `watchFollowSend`, `watchFollowRecv`, `sinkStateFromStatus`, `watchHostsStream` type alias
- `internal/server/watch_test.go` — `followTestEnv`/`newFollowTestEnv` (real bufconn+insecure wiring), `newBareFollowService` + `fakeWatchHostsStream` (deterministic goroutine-level driving), `newVerifiedFollowContext` (manufactured mTLS identity), 12 new `TestService_WatchHosts_Follow*` tests; deleted `TestService_WatchHosts_FollowUnimplemented`
- `internal/client/commands/serve_wiring.go` — `sinkHealth` field on `hooksAndMetrics`, unconditional `NewSinkHealth`/`WithSinkHealth`, conditional `RegisterSinkGauges`
- `internal/client/commands/serve_wiring_test.go` — 3 new `TestConfigureMetricsAndHooks_SinkHealth*`/`SinkOptionAlwaysPresent` tests

## Decisions Made

- **The non-joining handler design (review H1) is the plan's central decision** and is enforced three ways: a negative grep for `sync.WaitGroup`/`wg.Wait()` in `watch.go`, a `go func` count of exactly 2 (sender + receiver, handler owns neither), and two teardown tests each independently verified RED — see below.
- **`changeNotifier`'s guarantee is stated as an upper bound, never a lower bound** (review M2): "at most one additional wake per busy subscriber during a burst," not "one wake per burst." `TestChangeNotifier_CoalescesBurst` proves the upper bound deterministically by controlling its own timing (the subscriber is held busy by the test, not the scheduler); `TestService_WatchHosts_FollowConvergesAfterBurst` asserts convergence (≤ N+1 snapshots, final-state equality) rather than a wake count, avoiding the flake the original "fewer snapshots than mutations" phrasing would have encoded.
- **`sendSnapshot` extraction preserves the derive-before-`ListAll` ordering by construction**: both one-shot and follow-mode call the same helper, so the ordering cannot drift between the two paths — verified by a line-order grep and a follow-mode mirror of plan 01's lower-bound decorator test.
- **Fake-stream testing over real-network testing for goroutine-level H1 assertions**: `fakeWatchHostsStream` (a hand-rolled implementation of the generic `watchHostsStream` interface) drives `Send`/`Recv` blocking behavior deterministically, avoiding the scheduling races that made an early real-bufconn attempt at the "Recv sees EOF while Send is blocked" test flaky (see Issues Encountered).
- **Manufactured verified-peer contexts (`peer.NewContext` + `credentials.TLSInfo`) instead of a real mTLS handshake** for identity-keyed tests, mirroring `peercn_test.go`'s existing technique — avoids standing up a second TLS test harness for this plan.

## H1 RED Verification (mandatory per plan)

Both reviewer-identified teardown windows were confirmed to hang/fail under the pre-review naive shape (handler owns `Recv` directly in a loop, a single sender goroutine, `cancel()` + `wg.Wait()` before returning) before being accepted:

- `TestService_WatchHosts_FollowSendErrorReturnsWhileRecvIdle` (Codex's path — Send fails while Recv is idle): under the naive shape, failed with `context deadline exceeded`-equivalent behavior (the DB layer aborted on the racing `cancel()`), never returning within the 2s bound — `--- FAIL: TestService_WatchHosts_FollowSendErrorReturnsWhileRecvIdle (2.00s)`.
- `TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked` (pi's path — Recv sees EOF while Send is blocked on flow control): under the naive shape, `wg.Wait()` blocked forever waiting for the permanently-stuck sender — `--- FAIL: TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked (2.00s)`.

Both tests pass reliably (including `-count=10` under the race detector) against the actual, non-joining implementation.

## H1/round-3-H1 RED Verification for `TestService_CompactAggregates_Notifies`

The compaction notify call (`if !req.GetDryRun() && shrunk { s.changes.Notify() }`) was temporarily removed (replaced with `_ = shrunk` to isolate the missing call from an unrelated unused-variable build error) and the test was confirmed to fail:

```text
changenotify_test.go:241: a successful non-dry-run compaction did not notify watchers
--- FAIL: TestService_CompactAggregates_Notifies (2.03s)
```

The call was then restored and the full suite re-verified green.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Test fidelity bug] `fakeWatchHostsStream`'s Send had a ctx.Done() escape hatch that defeated its own teardown test**

- **Found during:** Task 2, while verifying `TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked` goes RED against the naive teardown
- **Issue:** The first draft's fake `Send` selected on both `sendBlock` (never closed) and `ctx.Done()`. Since the naive teardown's own `cancel()` call raced with (and often preceded) the sender reaching its blocking `Send`, the fake's `ctx.Done()` branch let `Send` return early even under the broken teardown — the test passed when it should have failed, silently certifying nothing.
- **Fix:** Removed the `ctx.Done()` branch from the fake's `sendFn`; a real stalled `Send` responds only to the underlying stream tearing down, never to a child context the handler derives and cancels itself, so the fake must not give it an escape hatch either.
- **Files modified:** `internal/server/watch_test.go`
- **Verification:** Re-ran the RED check — the corrected test now genuinely times out (`2.00s` FAIL) under the naive teardown and passes reliably under the fixed implementation.
- **Committed in:** `0cfa864` (Task 2 GREEN commit — the fix shipped with the implementation commit since it was discovered during that task's RED-verification step, not as a separate follow-up)

---

**Total deviations:** 1 auto-fixed (Rule 1, test fidelity correction discovered during mandatory RED verification)
**Impact on plan:** No scope creep — the fix corrected the test's own ability to detect the bug it exists to catch; no production behavior changed.

## Issues Encountered

- An early attempt at `TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked` using the real bufconn+insecure harness (closing the client connection to force a `Send` failure) turned out to race with the server-side stream context tearing down for the *same* reason as the fix itself — a genuinely dead transport unblocks `Recv` too, not just `Send`, which doesn't isolate the "Send stuck, Recv silent" window the test needs. Switched to the hand-rolled `fakeWatchHostsStream` approach, which gives full, deterministic control over each direction independently and is what the RED verification above relies on.

## Requirements Note

This plan's frontmatter lists `TMPL-05`, `TMPL-06`, `TMPL-08`. `TMPL-06` and `TMPL-08` were already marked `Complete` in `REQUIREMENTS.md` by earlier plans (01-04 and 01-01/01-09 respectively) and are unaffected here. **`TMPL-05` ("sink mode holds the rendered artifact current... and recovers after a connection interruption without emitting a truncated artifact") is NOT marked complete by this plan.** This plan implements the full server-side half (change notification, follow-mode streaming, sink health) but the requirement's "rendered artifact" and "recovers after a connection interruption" clauses describe the client-side consumer that plan 07 ("Client Sink CLI — watch, Status File, Reconnect") builds; `TMPL-05` is also listed in plan 07's own requirements. Marking it complete here would falsely signal a working end-to-end sink before plan 07 lands its half — the same reasoning plan 05's SUMMARY recorded for the same requirement. No `requirements mark-complete` call was made for `TMPL-05` in this plan.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

Plan 07 (Client Sink CLI) can now open a real follow-mode `WatchHosts` stream against a server that pushes coalesced snapshots and independently accepts status reports on the same stream — including honoring D-21 (a client-reported change ID never suppresses a send) and D-13 (only a verified mTLS CN is ever recorded). Plan 08's e2e suite and operator guide can exercise the full round trip; the operator guide should still carry the one-CN-per-consumer deployment note plan 05 documented (duplicate CNs collapse, last-writer-wins).

No blockers. `go test -race -count=1 ./...` is green across the whole repository; `task lint` reports 0 issues.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-01*

## Self-Check: PASSED

- FOUND: `internal/server/changenotify.go`
- FOUND: `internal/server/changenotify_test.go`
- FOUND: `internal/server/service.go`
- FOUND: `internal/server/watch.go`
- FOUND: `internal/server/watch_test.go`
- FOUND: `internal/client/commands/serve_wiring.go`
- FOUND: `internal/client/commands/serve_wiring_test.go`
- FOUND: `85f9a36` (test(01-06): add failing tests for change notification)
- FOUND: `1729aba` (feat(server): add change notification for watchers)
- FOUND: `be13b50` (test(01-06): add failing tests for follow-mode streaming)
- FOUND: `0cfa864` (feat(server): stream coalesced snapshots to sinks)
- FOUND: `001c921` (test(01-06): add failing tests for sink health wiring)
- FOUND: `d8a14eb` (feat(server): wire sink health into serve wiring)
