---
phase: 1
slug: consumer-rendered-output-templates-sink
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-31
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `01-RESEARCH.md` § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go stdlib `testing` + `stretchr/testify` (assert/require) + `pgregory.net/rapid` (property-based; already a direct dependency) |
| **Config file** | none — plain `go test`, invoked via Taskfile |
| **Quick run command** | `task test -- -run <TestName> ./internal/<pkg>/` |
| **Full suite command** | `task test` (== `go test -race -count=1 ./...`, `Taskfile.yml:21-26`) |
| **Estimated runtime** | full suite ~60–90s with `-race` |

> **Command discipline (memory `j8eyp0njgz`):** Go's `-run` is an **unanchored regex** over the
> test function name. A `Test<Noun>` pattern misses every `Test<Verb><Noun>` sibling — e.g.
> `-run 'TestTemplate'` does NOT match `TestRenderTemplate_...`. Before recording any quick-run
> command below as green, enumerate the inventory with `rg '^func Test' <pkg>/*_test.go`, run the
> candidate with `-v`, and confirm the `--- PASS` count equals the inventory count. Exit status
> proves nothing here — unmatched tests never run at all.

---

## Sampling Rate

- **After every task commit:** targeted `task test -- -run <TestName> <package>`
- **After every plan wave:** `task test` (full suite, `-race`)
- **Before `/gsd-verify-work`:** `task test:coverage:ci` green (80% threshold) **and** `task test:e2e`
  (build tag `e2e`, real mTLS, in-process) extended with at least one Watch-RPC round trip
- **Max feedback latency:** < 15s for targeted runs

---

## Per-Task Verification Map

Task IDs are assigned by the planner; this table maps requirements to their proving command and is
filled in per task during planning.

| Req ID | Behavior | Threat Ref | Test Type | Automated Command | File Exists | Status |
|--------|----------|------------|-----------|-------------------|-------------|--------|
| TMPL-01 | Template renders host data with no upstream code change | — | unit | `task test -- -run Template_Render ./internal/client/template/` | ❌ W0 | ⬜ pending |
| TMPL-02 | Documented/versioned field set exposed (`.Entries[].IPAddress/Hostname/Aliases/Tags/Comment`, `.Count`, `.GeneratedAt`, `.ContractVersion`) | — | unit | `task test -- -run TemplateData_FieldSet ./internal/client/template/` | ❌ W0 | ⬜ pending |
| TMPL-02 | Template declaring an incompatible contract version is refused **before** render (D-05) | — | unit | `task test -- -run ContractVersion ./internal/client/template/` | ❌ W0 | ⬜ pending |
| TMPL-03 | Undefined key fails loudly rather than rendering empty | — | unit | `task test -- -run UndefinedKey ./internal/client/template/` | ❌ W0 | ⬜ pending |
| TMPL-03 | Render or write failure leaves the prior artifact **byte-identical** (D-12) | T-1-03 | unit | `task test -- -run FailurePreservesArtifact ./internal/client/commands/` | ❌ W0 | ⬜ pending |
| TMPL-04 | Atomic write-and-rename; a concurrent reader never observes a partial file | — | unit | `task test -- -run AtomicWrite ./internal/atomicfile/` | ⚠️ exists at `internal/server/hostsfile_test.go:181-227`; **moves** this phase | ⬜ pending |
| TMPL-05 | Sink reflects a host mutation without polling | — | integration (bufconn) | `task test -- -run Watch ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-05 | Sink recovers after connection interruption without emitting a truncated artifact | T-1-02 | integration (bufconn) | `task test -- -run ReconnectNoTruncation ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-06 | Wire messages are bounded: one entry per Watch message, chunked ExportHosts sends (amended 2026-07-31 — storage-layer laziness is out of scope, see #400) | — | integration | `task test -- -run StreamsPerEntry ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-06 | Chunked ExportHosts output is byte-identical after reassembly, for all three formats (review L2 — existing tests read only the first response) | — | integration | `task test -- -run 'TestService_ExportHosts_ChunksLargePayload' ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-07 | Bounded client collection; clear error past the cap, **never** silent truncation | T-1-01 | unit | `task test -- -run CapExceeded ./internal/client/commands/` | ❌ W0 | ⬜ pending |
| TMPL-07 | Byte budget refuses fat entries below the entry cap (review L1) | T-1-05 | unit | `task test -- -run ByteBudgetExceeded ./internal/client/commands/` | ❌ W0 | ⬜ pending |
| TMPL-08 | Change ID = `MAX(event_id)`; zero-ULID on an empty log | — | unit | `task test -- -run EventStoreLatestEventID ./internal/storage/sqlite/` | ❌ W0 | ⬜ pending |
| TMPL-08 | Change ID advances across same-millisecond mutations (D-20 monotonicity) | T-1-33 | integration (bufconn) | `task test -- -run ChangeIDAdvancesOnMutation ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-08 | Server never uses a client-reported change ID to decide what to send (D-21) | T-1-34 | integration (bufconn) | `task test -- -run IgnoresReportedChangeIDForSendDecision ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-08 | Client skips a redundant render only when the artifact still exists (D-21) | T-1-36 | unit | `task test -- -run 'TestWatch_SkipsRedundantRenderOnSameChangeID\|TestWatch_RendersWhenArtifactMissing' ./internal/client/commands/` | ❌ W0 | ⬜ pending |
| D-09/D-10 | Server exposes per-consumer last-seen keyed by mTLS CN; survives stream close | — | unit | `task test -- -run SinkHealth ./internal/server/` | ❌ W0 | ⬜ pending |
| D-09/D-13 | CN keying validated over a REAL verified chain against the literal `e2e-test-client` (review M3) | T-1-30 | e2e | `task test:e2e` (`TestE2E_WatchSinkHealthKeyedByCN`) | ❌ W0 | ⬜ pending |
| D-12a | Hook failure retains the NEWLY written artifact and marks reload health, without touching the write-failure count (review H3) | T-1-35 | unit | `task test -- -run 'TestWatch_HookFailureRetainsNewArtifact\|TestSinkStatus_ReloadFailureKeepsWriteHealth' ./internal/client/commands/` | ❌ W0 | ⬜ pending |
| review H1 | Handler returns promptly when Send fails while Recv is idle, and when Recv hits EOF while Send is blocked on flow control | T-1-20 | integration (bufconn) | `task test -- -run 'TestService_WatchHosts_FollowSendErrorReturnsWhileRecvIdle\|TestService_WatchHosts_FollowRecvEOFReturnsWhileSendBlocked' ./internal/server/` | ❌ W0 | ⬜ pending |
| review H4 | Sink CLI health state is race-free under concurrent ticker reads and receive-loop writes | — | unit | `task test -- -count=10 -run TestSinkStatus_ConcurrentAccess ./internal/client/commands/` | ❌ W0 | ⬜ pending |
| review M4 | Sink survives a real server stop/restart under the running `watch` command, artifact byte-identical throughout | T-1-37 | e2e | `task test:e2e` (`TestE2E_WatchSinkSurvivesServerRestart`) | ❌ W0 | ⬜ pending |
| (regression) | `unbound_conf_path` and existing `ExportHosts` format strings unchanged | — | unit | `task test -- -run ExportHosts ./internal/server/` | ✅ exists | ⬜ pending |
| (regression) | Existing `unbound`/`dnsmasq`/hosts generators unaffected by the `atomicWriteFile` move | — | unit | `task test ./internal/server/` | ✅ exists | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/atomicfile/atomicfile_test.go` — relocated from `internal/server/hostsfile_test.go:181-227`; covers TMPL-04. The four existing tests (new-file, overwrite, temp cleanup, invalid path) move with the implementation.
- [ ] `internal/client/template/template_test.go` — new; covers TMPL-01, TMPL-02, TMPL-03 (struct-field typo failure, contract-version mismatch refusal, `.Count`/`.GeneratedAt` presence)
- [ ] `internal/server/watch_test.go` (or extend `service_test.go`) — new bufconn-based bidirectional test harness for TMPL-05 and TMPL-06
- [ ] `internal/client/commands/watch_test.go` — new; covers TMPL-07's cap error path and the D-12 byte-identical-on-failure guarantee at the CLI layer
- [ ] `e2e/` — extend with a real-mTLS Watch round trip (build tag `e2e`) once the Watch RPC exists

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Post-write exec hook actually reloads a real resolver | TMPL-05 / D-16 | Requires a live `unbound`/`dnsmasq` process; the automated suite asserts the hook is *invoked* with the right argv, not that a third-party daemon reloaded | Run the sink against a local unbound with `--exec 'unbound-control reload'`, mutate a host, confirm `dig` reflects the change without operator action |
| Two independent resolver nodes stay consistent | TMPL-01 / TMPL-08 / phase goal | Needs two hosts; the phase's success criterion is a deployment property, not a unit-testable one | Point two sinks at one server with the same template; mutate a host; confirm both artifacts converge, both sidecars report the same `rendered_change_id`, and both resolvers answer identically |
| A restarted server does not trigger a fleet-wide resolver reload | TMPL-08 / D-21 | Needs two or more sinks and a real server restart; the value is the *absence* of an action across a fleet, which a single-node test cannot observe | With two sinks running and current, restart the server; confirm neither sink re-runs its `--exec` command, because the change ID is unchanged and both artifacts still exist |

---

## Manual Verification Record (Plan 01-08 Task 3)

Recorded 2026-08-01, at phase close. All four deployment-level behaviors
below require real infrastructure (a live unbound host, a second machine)
that this execution environment does not have. Following the precedent
phase 9 set for its OTel scrape verification, each is recorded explicitly
as **NOT-RUN** — not claimed as done, and not softened into "covered by
automated tests" — with the reason, the concrete steps a future operator
can execute against real infrastructure, and the automated coverage that
DOES exist stated plainly so the gap is scoped honestly rather than
looking larger or smaller than it is.

### 1. Resolver reload actually reloads a real resolver (TMPL-05 / D-16)

**Status: NOT-RUN.** Reason: no unbound host / no second machine available
in this environment.

**Steps for a future operator:**

1. On a host running unbound, start:
   `router-hosts watch --template ./examples/templates/unbound.tmpl --out /etc/unbound/conf.d/router-hosts.conf --exec 'unbound-control reload'`
2. From another machine, add a host through the CLI.
3. Confirm `dig @<that host> <new-name>` answers correctly with no
   operator action on the sink host.
4. Confirm the sidecar `.status` file shows a fresh `last_success` and a
   zero `consecutive_failures`.

**Automated coverage that DOES exist:** `TestPostWriteHook_Success` /
`TestPostWriteHook_NonZeroExit` / `TestPostWriteHook_Timeout` (unit,
`internal/client/commands/posthook_test.go`) prove the hook is invoked
with the right command and its exit/timeout is classified correctly.
`TestWatch_SuccessRunsPostWriteHook` (unit,
`internal/client/commands/watch_test.go`) proves the hook runs after a
successful write. None of these prove a third-party `unbound` process
actually reloaded and started answering the new record — that is what
this manual step alone can prove.

### 2. Two independent resolver nodes stay consistent (TMPL-01 / TMPL-08 / phase goal)

**Status: NOT-RUN.** Reason: no unbound host / no second machine available
in this environment.

**Steps for a future operator:**

1. Point two sinks on two different hosts at the same server with the
   same template.
2. Mutate one host entry.
3. Confirm both artifacts converge to identical bytes.
4. Confirm both sidecar files report the **same** `rendered_change_id`,
   matching on both hosts.
5. Confirm `router_hosts_sink_converged` reads 1 for both CNs.
6. Confirm both resolvers answer identically.

**Automated coverage that DOES exist:** `TestE2E_WatchSnapshotOverMTLS`
(e2e, `e2e/e2e_test.go`, plan 01-08) proves that two `Watch` requests over
unchanged server state return the *same* change ID over a real mTLS
connection — the single-node half of D-19. Nothing in the automated suite
runs two independent consumer processes against one server simultaneously;
that is a genuinely deployment-level property a single-node test cannot
observe.

### 3. Restart does not trigger a fleet-wide reload; staleness/recovery behave correctly (TMPL-05 / TMPL-08 / D-12 / D-21)

**Status: NOT-RUN.** Reason: no unbound host / no second machine available
in this environment.

**Steps for a future operator:**

1. With two sinks running, stop the server.
2. Confirm both artifacts remain byte-identical (compare checksums before
   and after) and both sidecar files show a rising
   `consecutive_failures`.
3. Confirm the server-side sink last-seen metric ages (rather than
   disappearing) while the server is still up, and that after a server
   restart the metric's absence correctly reads as "not seen since
   restart" (D-10).
4. Restart the server and confirm both sinks reconnect on their own.
5. Confirm that because the change ID is unchanged, **neither** sink
   re-runs its reload command — the fleet-wide reload storm the change ID
   exists to prevent.
6. Mutate a host and confirm both sinks rewrite and reload.

**Automated coverage that DOES exist:** `TestE2E_WatchSinkSurvivesServerRestart`
(e2e, `e2e/e2e_test.go`, plan 01-08) proves this exact sequence for a
**single** sink against a real, genuinely stopped-and-restarted server
over real mTLS: byte-identical artifact during the outage, a rising
failure count, automatic reconnect, a rewrite on a post-restart mutation,
and the failure count returning to zero.
`TestWatch_SkipsRedundantRenderOnSameChangeID` (unit,
`internal/client/commands/watch_test.go`, plan 01-07) proves the D-21
skip fires on an unchanged change ID. What remains genuinely untested
automatically is the **fleet-wide** absence of a reload storm across
multiple simultaneous consumers, and the server-side last-seen metric's
behavior across a real restart under real OTel scraping.

### 4. Reload-failure outcome is diagnosable end to end (D-12a)

**Status: NOT-RUN.** Reason: no unbound host / no second machine available
in this environment.

**Steps for a future operator:**

1. On one sink host, point `--exec` at a command that exits non-zero (for
   example `sh -c 'exit 1'`).
2. Mutate a host entry.
3. Confirm the artifact **was** updated to the new content (never rolled
   back).
4. Confirm the sidecar shows `reload_failed: true` with a fresh
   `last_success` and a zero `consecutive_failures`.
5. Confirm `router_hosts_sink_reload_failed` reads 1 for that CN while
   `router_hosts_sink_last_success_timestamp_seconds` is fresh.
6. Restore a working reload command, mutate again, and confirm the flag
   clears.

**Automated coverage that DOES exist:** `TestWatch_HookFailureRetainsNewArtifact`
and `TestSinkStatus_ReloadFailureKeepsWriteHealth` (unit,
`internal/client/commands/watch_test.go` /
`internal/client/commands/sinkstatus_test.go`, plan 01-07) prove the
client-side half of this contract exactly: the newly rendered artifact is
retained, `reload_failed` is set, and `consecutive_failures` is left
untouched. What is not automatically proven is the server-side metric
(`router_hosts_sink_reload_failed`) reading 1 for a real consumer's CN
over a real OTel scrape, and a real resolver's actual (non-)reload
behavior.

### Automated gate re-run at phase close (2026-08-01)

- `task ci` — exit 0
- `task test:coverage:ci` — 86.2% (>= 80% threshold)
- `task test:e2e` — exit 0, including `TestE2E_WatchSnapshotOverMTLS`,
  `TestE2E_WatchPushesOnMutation`, `TestE2E_WatchSinkHealthKeyedByCN`,
  and `TestE2E_WatchSinkSurvivesServerRestart`

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or a Wave 0 dependency
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Every quick-run `-run` pattern empirically confirmed against its `rg '^func Test'` inventory (see Command discipline above)
- [ ] Feedback latency < 15s for targeted runs
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
