---
phase: 01-consumer-rendered-output-templates-sink
reviewed: 2026-08-01T20:57:26Z
depth: standard
files_reviewed: 34
files_reviewed_list:
  - internal/server/watch.go
  - internal/server/changenotify.go
  - internal/server/changenotify_test.go
  - internal/server/watch_test.go
  - internal/server/sinkmetrics.go
  - internal/server/sinkmetrics_test.go
  - internal/server/metrics.go
  - internal/server/metrics_test.go
  - internal/server/peercn.go
  - internal/server/peercn_test.go
  - internal/server/service.go
  - internal/server/service_test.go
  - internal/server/commands.go
  - internal/client/commands/watch.go
  - internal/client/commands/watch_test.go
  - internal/client/commands/watchpolicy.go
  - internal/client/commands/watchpolicy_test.go
  - internal/client/commands/posthook.go
  - internal/client/commands/posthook_test.go
  - internal/client/commands/sinkstatus.go
  - internal/client/commands/sinkstatus_test.go
  - internal/client/commands/render.go
  - internal/client/commands/render_test.go
  - internal/client/commands/host.go
  - internal/client/commands/snapshot.go
  - internal/client/commands/serve_wiring.go
  - internal/client/template/template.go
  - internal/sanitize/sanitize.go
  - internal/sanitize/sanitize_test.go
  - internal/eventid/eventid.go
  - internal/storage/sqlite/eventstore.go
  - internal/storage/sqlite/eventid_guard_test.go
  - internal/storage/storage.go
  - internal/atomicfile/atomicfile.go
  - internal/config/client.go
  - internal/client/client.go
  - internal/contract/contract.go
  - examples/templates/hosts.tmpl
  - examples/templates/dnsmasq.tmpl
  - examples/templates/unbound.tmpl
  - docs/reference/template-contract.md
  - docs/reference/cli.md
  - e2e/e2e_test.go
findings:
  critical: 0
  warning: 0
  info: 1
  total: 1
status: clean
---

# Phase 1: Code Review Report

**Reviewed:** 2026-08-01T20:57:26Z
**Depth:** standard
**Files Reviewed:** 34 read in full (list above); remainder of the 74-file
scope sampled by targeted grep for the invariant checks below
**Status:** clean

## Summary

This phase adds a client-rendered template pipeline (`render`/`watch`), a new
bidirectional `WatchHosts` RPC with per-consumer health reporting, a shared
monotonic event-ID generator with an in-transaction ordering guard, and a
shared sanitizing FuncMap for template output. All nine LOCKED invariants in
the task brief were checked directly against the code and hold:

1. **Change-ID-before-`ListAll` ordering** — `sendSnapshot` in
   `internal/server/watch.go:88-101` derives `changeID` from
   `s.store.LatestEventID` before calling `s.store.ListAll`, in both the
   one-shot and follow-mode paths (both route through this one helper).
   `TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries` and its follow-mode
   mirror exercise this with a decorator that mutates state mid-`ListAll` and
   assert the terminator's ID is strictly less than the post-stream maximum.
2. **Zero ULID never a committed event ID** — `insertEvent`
   (`internal/storage/sqlite/eventstore.go:373-473`) compares
   `env.EventID.Compare(max) <= 0` unconditionally, with no "log is
   non-empty" branch. `selectLatestEventID` returns the zero ULID for a NULL
   `MAX`, so a proposed zero ID against an empty log compares equal and is
   re-minted like any other non-advancing proposal.
   `TestInsertEvent_ZeroIDIntoEmptyStoreRemints` and
   `TestInsertEvent_ZeroIDIntoNonEmptyStoreRemints` pin both halves.
3. **`insertEvent` single funnel** — confirmed; the one known bypass
   (`legacy_migration.go:183`) is pre-existing, documented, and out of this
   phase's scope per the task brief. No new bypass was introduced.
4. **Artifact never rolled back after the post-write hook runs** —
   `runWatchCycle` (`internal/client/commands/watch.go:341-400`) calls
   `recordSuccess` before the hook, and `recordReloadFailure`
   (`sinkstatus.go:172-179`) only sets `ReloadFailed`/`LastError`, never
   touches `RenderedChangeID`/`ConsecutiveFailures`, and nothing in the write
   path re-executes `atomicfile.Write` or removes the artifact after a hook
   failure. `TestWatch_HookFailureRetainsNewArtifact` asserts the on-disk
   content is the newly rendered content, not the prior one.
5. **Staleness signalled via marker + metrics, never truncation** — every
   failure branch in `runWatchCycle` returns before `atomicfile.Write`, and
   `atomicfile.Write` itself (`internal/atomicfile/atomicfile.go`) only
   replaces the target via `os.Rename` after a fully successful
   create/write/fsync/close sequence, cleaning up the temp file on every
   error path without ever touching the destination path.
6/7. **CN not enforced-unique; `Connect`/`Disconnect` identity-free** —
   confirmed in `sinkmetrics.go` and `watch.go`; both are documented,
   deliberate, and tested (`TestService_WatchHosts_FollowWithoutPeerIdentityStillStreams`).
6. **One Send-goroutine, one Recv-goroutine, never two concurrent Senders** —
   `watchFollowSend` is the sole caller of `stream.Send` in `watch.go`;
   `watchFollowRecv` is the sole caller of `stream.Recv`. On the client side,
   `sendStatusTicker` is the sole `Send` owner and `runWatchRecvLoop` is the
   sole `Recv` owner in `watch.go` (client). No path calls `Send` from two
   goroutines.
7. **Non-joining handler; cancelling `stream.Context()`'s derivative does not
   unblock an in-flight `Send`/`Recv`** — `watchFollow` explicitly returns
   without a `wg.Wait()`, and this exact regression is guarded by
   `TestService_WatchHosts_FollowSendErrorReturnsWhileRecvIdle` and
   `TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked`, both of
   which are documented as having been verified to hang under a
   reintroduced `wg.Wait()`.

Resource bounds (TMPL-07): the client-side entry-count and byte-budget caps
are enforced identically and correctly (check-before-append, refuse-not-truncate)
at all four collecting call sites (`host.go` list/search, `snapshot.go`
list, `render.go`, and `watch.go`'s `runWatchRecvLoop`). The server-side
64 KiB `ExportHosts` chunker (`service.go:642-677`) cannot emit an unbounded
single message and correctly still emits one message for an empty payload.

Injection (D-17): `internal/sanitize/sanitize.CommentField` collapses both
`\r` and `\n` to spaces and is applied consistently to every `.Comment` and
every `.Tags` element in all three shipped example templates
(`hosts.tmpl`, `dnsmasq.tmpl`, `unbound.tmpl`), matching the identical
server-side `sanitizeCommentField` this package was extracted to share.

Exec hook (`internal/client/commands/posthook.go`): the command is entirely
operator-supplied (`--exec`), mirrors the server's own `hooks.go` shell-out
pattern and timeout-vs-exit-code classification, and never receives
server-controlled data interpolated into the command line — no injection
vector beyond what the operator already typed.

Error handling: no swallowed or shadowed errors were found in the reviewed
files; every fallible call either returns a wrapped `oops` error or is a
deliberate, documented "log and continue" (sidecar write failures, `Close()`
on client teardown) consistent with D-12/D-12a's "never abort an otherwise-
successful cycle over a secondary write."

Test quality: `watch_test.go` on both sides was read end-to-end looking for
the two documented "test that cannot fail" shapes described in the task
brief (a `ctx.Done()` escape hatch on a fake `Send`, and a first `Send` that
could itself block). Neither reappears — `TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked`'s
`sendBlock` channel is explicitly documented as "deliberately never closed"
to avoid exactly that regression, and the client-side `fakeWatchStream`'s
opening `Send` is unconditional (`callNum > 1` guards the blocking behavior)
so `runWatch` can always reach the point of spawning its ticker/recv loop.

No Critical or Warning findings. One Info-level observation below.

## Info

### IN-01: `sinkHealthState.recordReloadFailure`'s timestamp parameter is currently always discarded

**File:** `internal/client/commands/sinkstatus.go:172`
**Issue:** `recordReloadFailure(err error, _ time.Time)` accepts a timestamp
argument it never stores — every call site (`watch.go:392`) passes
`time.Now().UTC()` into it. The doc comment already explains this is
intentional ("accepted for signature symmetry with `recordSuccess` and
`recordReloadSuccess`; today's `sinkStatus` contract has no
last-reload-attempt field to store it in"), so this is not a defect, just a
note for the next contributor: if a `last_reload_attempt` field is ever
added to the sidecar contract, this is the parameter that already carries
the value it would need.
**Fix:** No action required now. When/if a `LastReloadAttempt` field is
added to `sinkStatus`, wire this parameter through instead of adding a new
one.

---

_Reviewed: 2026-08-01T20:57:26Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
