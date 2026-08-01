---
phase: 1
slug: consumer-rendered-output-templates-sink
round: 3
reviewed: 2026-08-01
reviewers: [codex, pi]
selection: explicit flags (--codex --pi)
plans_reviewed: 9
prior_rounds: "round 1 (2026-07-31) -> 63f0c98..1b555c4; round 2 (2026-08-01) -> 7d423a7"
risk_codex: HIGH
risk_pi: LOW-MEDIUM
---

# Phase 1 — Cross-AI Plan Reviews (Round 3)

Both lanes were **explicitly named**, both ran clean (`ok:true, stubbed:false` — no stubs, no
dropped lane, no `REVIEWED-WITHOUT-REPO-ACCESS` marker). Each received all 9 revised plans in
full; neither lane declares a prompt budget, so nothing was trimmed. Codex 2m32s, pi 3m04s,
invoked sequentially. Prompt ~126k tokens (up from ~93k in round 2).

Both were told this was round 3 and pointed at the four never-reviewed surfaces from `7d423a7`:
plan 01-09, the change-ID flip, the `WatchPolicy` seam, and Notify-as-first-statement.

## What round 3 confirmed, and what it did not

| Surface | Verdict |
|---|---|
| **H1 change-ID flip** | **Both confirm correct.** pi verified the test genuinely discriminates: under the wrong order the decorator's mutation ID is returned by both `LatestEventID` calls and the strictly-less assertion fails. Applied consistently in 01 and 06. |
| **Notify-first premise** | **Both verified against all six callers.** pi enumerated `service.go:108,211,285,314,594,850`; all run after the write commits. |
| **`WatchPolicy` seam** | **Both confirm it resolves the H4 compile failure.** `e2e/helpers_test.go:3` is `package e2e_test`; variadic `NewRootCmd` preserves existing callers. |
| **Plan 01-09** | **Motivating bug confirmed real by both — but the remedy is disputed, and the dispute resolves against the plan.** See below. |
| **NEW cross-plan gap** | **Both independently found compaction never notifies.** Three rounds of plan-local review missed it because it lives at the seam of the two newest plans. |

Three of the four new surfaces hold up. The fourth does not, and one entirely new HIGH appeared.

---

## Consensus Summary

### Both reviewers independently found the same new HIGH: compaction moves the change ID silently

`CompactAggregates` never calls `regenerateOutputs`. Verified independently — the only call sites
are `service.go:108` (startup), `:211`, `:285`, `:314`, `:594`, `:850`; compaction is not among them.

Plan 01-09 deliberately makes compaction advance `MAX(event_id)` (D-22's accepted "one redundant
render"). Plan 06 mandates exactly one notify site, inside `regenerateOutputs`. Together: after a
compaction the change ID has moved, **no watcher is ever told**, and the redundant render never
happens until an unrelated mutation lands. pi adds the sharper consequence — `RecordServerChange`
is only called from `sendSnapshot`, so the server's convergence gauge keeps comparing sinks against
the pre-compaction ID and reads `converged=1` while the real high-water mark has moved. An
operator-driven compaction on a quiet deployment leaves every sink's convergence signal wrong
indefinitely.

This is the strongest signal in round 3: a gap that is invisible to any single-plan review, found
by both lanes only once plans 06 and 09 existed together.

### Where they diverge: is plan 01-09's monotonicity invariant actually established?

A real disagreement, and it decides the phase's risk rating.

- **pi:** "the remedy is minimal correct fix" — verified `eventstore.go:258`, verified
  `LockedMonotonicReader` exists in the pinned oklog/ulid v2, rated the phase **LOW–MEDIUM**.
- **Codex:** three separate HIGHs — the generator is not monotonic relative to the persisted log
  after restart; the storage boundary still accepts caller-constructed IDs; and **mint order is
  not commit order**. Rated the phase **HIGH**.

**Adjudicated against source: Codex is right, and its third point is the serious one.**

`internal/server/commands.go` mints event IDs **outside** the write-queue lock in every command —
`:115` (`id := h.newID()`) and `:119` (`newEnvelope`, which mints `EventID` at `:77`) both precede
`submitWrite` at `:135`; the same shape repeats at `:201-268` before `:284`, and `:345` before
`:354`. Only the duplicate check and the store write execute inside the queue. Therefore:

1. Goroutine A mints `ID_A`; goroutine B mints `ID_B` > `ID_A`.
2. B wins the write queue and commits. Log max = `ID_B`.
3. A commits — writing an ID that sorts **below** an ID already in the log.
4. `MAX(event_id)` does not advance across A's commit. A watcher holding `ID_B` computes the same
   change ID, the D-21 skip fires, and **A's mutation is never rendered**.

That is the permanent-stale-zone failure TMPL-08 exists to prevent, reachable from ordinary
concurrent writes with no restart and no clock anomaly.

Plan 01-09 line 26 states the invariant flatly: *"Every event ID in the log is minted through one
process-wide monotonic generator, so no append path can produce an ID that sorts below an ID
already in the log (TMPL-08, D-20)."* The plan documents two residuals — process restart and a
backwards clock step, both inside the same millisecond (lines 31, 180-181, T-1-38). **Neither
covers this case.** Line 30's "safe under concurrent use" is about entropy-reader goroutine-safety
(threat T-1-39) — data races, not ordering.

pi did not trace mint-vs-commit ordering, which is why its LOW–MEDIUM runs too generous. Codex's
other two HIGHs are weaker but not wrong: the restart window is real yet has negligible practical
probability (process startup vastly exceeds one millisecond), and the storage-boundary point is
overstated for production (only two production append paths exist) though it does mean the
`LatestEventID` compliance case is exercised with `ulid.Make()` IDs from
`storagetest/suite.go:21`.

**The good news: Codex's proposed fix closes all three at once.** Seed the generator from
`LatestEventID` at storage startup, *and* reject-or-retry any proposed event ID `<= MAX(event_id)`
inside the append transaction. The in-transaction check is the load-bearing half — it makes mint
order irrelevant, which no process-local generator can do. The alternative Codex offers, a
database-owned monotonic sequence assigned in the append transaction, is stronger still and drops
lexical ULID ordering as the mechanism entirely.

---

## Findings by severity

Attribution: **both** = independently raised by both lanes. Verified = confirmed against source by the orchestrator.

### HIGH

| # | Finding | Source | Plan |
|---|---|---|---|
| H1 | Compaction advances `MAX(event_id)` but never notifies — no watcher learns of it until an unrelated mutation; `RecordServerChange` keeps reporting `converged=1` against a stale ID | **both** — **verified** | 06, 09 |
| H2 | Mint order is not commit order: IDs are minted outside the write queue (`commands.go:115,119` before `:135`), so a concurrent write can commit an ID below the log max and fail to advance it → skipped render | codex — **verified** | 09 |
| H3 | Generator is process-local, so it is not monotonic against the persisted log after restart. Plan documents this as accepted while also asserting the unqualified "no append path" truth — an internal contradiction | codex | 09 |
| H4 | `EventStore.AppendEvent(s)/AppendEventsBatch` accept caller-constructed envelopes, so routing two production sites cannot make the interface guarantee true; `storagetest/suite.go:21` mints with bare `ulid.Make()` | codex | 09 |
| H5 | `testEnv` still lacks the state `startServer` needs — `store`, `cfg`, `logger`, listener, handler and service are locals (`helpers_test.go:69,79,101`); adding `addr`/`sinkHealth`/`srvErrCh`/`running` does not let a fresh server be rebuilt. Same class as round-2 H6, only partially fixed | codex | 08 |

### MEDIUM

| # | Finding | Source | Plan |
|---|---|---|---|
| M1 | Follow-mode lower-bound test cannot get its second snapshot: the decorator mutates storage directly, which never calls `regenerateOutputs`, and there is exactly one notify site — the test hangs unless it explicitly calls `Notify` or mutates through the service | codex | 06 |
| M2 | `WatchPolicy.StatusInterval` vs the `--status-interval` Cobra flag (30s default) have no defined precedence; unless the flag default derives from the injected policy, Cobra overwrites it and the e2e seam cannot control ticker timing | codex | 07 |
| M3 | Blocked ticker `Send` has no observable completion path — `runWatch` is not required to confirm ticker exit before returning | codex | 07 |
| M4 | Stale `mu sync.Mutex // protects entropy` (`commands.go:23`) is orphaned once `entropy` is removed; plan 09 never mentions it and no criterion catches it | pi — **verified** | 09 |
| M5 | The lower-bound "corrected by the next notify cycle" truth holds only in follow mode; one-shot `render` has no next cycle, but plan 02's contract doc states convergence unconditionally | pi | 01, 02 |
| M6 | Reusing `env.client` after restart needs an explicit contract — bounded context tolerating reconnect, or redial and replace `env.conn`/`env.client` per start | codex | 08 |
| M7 | Compaction regression test is probabilistic (50 runs) and tests neither restart seeding, backward clock, nor storage-boundary insertion of a lower ID — the cases where the design still fails | codex | 09 |

### LOW

| # | Finding | Source | Plan |
|---|---|---|---|
| L1 | **Self-defeating gate:** `rg -c 'changes.Notify' internal/server/` returns 1 counts matching *lines*, not call sites — the plan's own mandated call-site comment inflates it to 2 and fails the gate. It also breaks the moment the H1 compaction-notify fix lands (correct code → count 2). Needs a call-expression-scoped pattern | pi — **verified** | 06 |
| L2 | "Committed on every entry" comment must exclude startup (`service.go:101/:108`) — safe, but it is an initial broadcast, not a post-commit notify | codex | 06 |
| L3 | `TestCompactAggregate_AdvancesLatestEventID` is only RED when the seed and prior max share a millisecond; SUMMARY should record the observed RED count out of 50, not "failed at least once" | pi | 09 |
| L4 | `TestWatch_LoadsSidecarAtStartup`'s artifact-deleted half is heavier than its marginal coverage — plan 07 unit tests already cover the D-21 artifact-exists guard | pi | 07 |

---

## Decisions Required Before Execution

1. **Event-ID monotonicity (H2, H3, H4)** — the process-local generator does not establish the
   invariant plan 09 asserts. Adopt one of Codex's two designs: (a) seed from `LatestEventID` at
   storage startup **and** reject/retry a proposed ID `<= MAX(event_id)` inside the append
   transaction, or (b) a database-owned monotonic sequence assigned in the same transaction.
   Option (a) is the smaller change and closes all three findings, because the in-transaction check
   is what makes mint order irrelevant. *Whichever is chosen, plan 09's line-26 truth must be
   restated to match what the mechanism actually guarantees* — the current unqualified claim is the
   defect, independent of the remedy.
2. **Compaction notification (H1)** — call `s.changes.Notify()` after a successful non-dry-run
   compaction in `CompactAggregates`, or route compaction through a shared "committed state
   changed" notifier. Add `TestService_CompactAggregates_Notifies`. **This forces L1**: plan 06's
   single-notify-site criterion must become a call-expression-scoped grep expecting 2, or the
   correct fix fails the gate.
3. **e2e restart harness (H5, M6)** — `testEnv` needs the full server-construction inputs (store,
   config, logger, service factory state), or a captured closure that rebuilds and re-registers a
   server. Decide also whether `env.conn`/`env.client` are redialed per start. Round-2 H6 was
   accepted as fixed on a change that does not actually make `startServer` implementable.
4. **Watch timing precedence (M2)** — state explicitly that the injected policy supplies the Cobra
   flag defaults and an explicitly-changed flag overrides the policy, or the e2e seam is inert.
5. **One-shot convergence scope (M5)** — scope plan 02's eventual-convergence language to sink
   (follow) mode; say that one-shot `render` reflects state at invocation and its ID understates
   entries by at most the mutations since the read began.

---

## Reviewer Verdicts

| Reviewer | Risk | Position |
|---|---|---|
| Codex | **HIGH** | Most earlier concurrency and client-safety issues are now well addressed, but TMPL-08 rests on an invariant plan 09 does not establish across restarts, arbitrary storage writers, or commit reordering; compaction moves the high-water mark without waking consumers; and the revised restart helper remains unimplementable from the proposed `testEnv` fields. "Otherwise the phase can still report false convergence — the exact failure the new change ID was intended to prevent." |
| pi | **LOW–MEDIUM** | All three round-3 mechanisms are individually correct and verified against source. Remaining risk concentrated in the compaction-notification gap — "one-line fix, but it sits exactly at the intersection of the two newest plans, which is why three rounds of plan-local review missed it." With compaction notify added, ready to execute. |

**The gap is one finding wide, and it is H2.** Both lanes verified the same three round-3
mechanisms and both found the same compaction gap. pi did not trace mint-vs-commit ordering; had it
done so, its "minimal correct fix" assessment of plan 09 would not stand. Weight Codex's HIGH here.

A note on trajectory: rounds 1 and 2 each found problems in what the *previous* revision wrote.
Round 3's two hardest findings (H1, H2) are instead about what the revisions *did not think to
touch* — a notification path and a lock boundary that predate this phase entirely. That is the
normal end state of adversarial review: the plan text is clean, and what remains is the codebase it
sits on.

---

## Codex Review

### Codex — Summary

The revised plan set is substantially stronger, especially around snapshot-ID ordering, client watch policy injection, config error propagation, and follow-stream teardown. However, the entirely new plan 01-09 still does not establish the durable monotonic change-ID invariant claimed by TMPL-08. It fixes the known compaction mint site, but monotonic mint order is neither initialized from persisted state nor enforced at the storage boundary. The revision also misses compaction notification entirely, and plan 08’s revised restart harness still lacks enough retained state to rebuild the server. These are execution-blocking issues.

### Codex — Strengths

- The change-ID ordering flip is correct. Reading `LatestEventID` before `ListAll` prevents old entries from being labelled with a newer ID; current reads are independent, and `ListAll` is a separate projection operation through `storage.Storage` ([internal/storage/storage.go:51](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/storage.go:51), [internal/storage/storage.go:79](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/storage.go:79)). The planned mutating `ListAll` decorator would distinguish the safe order from the reversed order.

- Moving notification to the start of `regenerateOutputs` is mechanically sound for the existing CRUD/rollback callers: they invoke regeneration only after their handler/write operation succeeds ([internal/server/service.go:205](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:205), [internal/server/service.go:281](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:281), [internal/server/service.go:311](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:311), [internal/server/service.go:784](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:784)). Moving the call above generators also removes unrelated filesystem latency from sink delivery.

- Plan 03 correctly identifies a real existing defect: both config-discovery and file-loading errors are currently discarded by nested success-only branches ([internal/config/client.go:50](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/config/client.go:50)). Making “missing” benign but “found and invalid” fatal is necessary before adding validated limit fields.

- The exported, variadic root option is the right seam for external e2e tests. The current constructor has no parameters ([internal/client/commands/root.go:44](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/client/commands/root.go:44)), while the e2e suite is an external package, so unexported timing variables would indeed be inaccessible.

- Plan 09 correctly identifies the existing compaction bug. Normal commands mint through a locked monotonic entropy source ([internal/server/commands.go:19](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/commands.go:19), [internal/server/commands.go:56](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/commands.go:56)), while compaction currently uses bare `ulid.Make()` ([internal/storage/sqlite/eventstore.go:240](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/sqlite/eventstore.go:240), [internal/storage/sqlite/eventstore.go:258](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/sqlite/eventstore.go:258)).

### Codex — Concerns

#### Plan 01-09

- **HIGH — The proposed generator is not monotonic relative to the persisted log after restart.**  
  Plan 09 explicitly accepts that a post-restart ID in the same millisecond may sort below the previous persisted maximum. That contradicts TMPL-08’s durable, monotonic change-ID requirement and the plan’s own truth that “no append path can produce an ID that sorts below an ID already in the log.” A package-global entropy source starts with no knowledge of existing rows. Since `event_id` is persisted as the ordering key and primary key, process-local monotonicity is insufficient.

- **HIGH — The storage boundary still accepts arbitrary event IDs.**  
  `EventStore.AppendEvent`, `AppendEvents`, and `AppendEventsBatch` all accept caller-constructed `EventEnvelope` values ([internal/storage/storage.go:51](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/storage.go:51)). The shared compliance helpers already construct envelopes using bare `ulid.Make()` ([internal/storage/storagetest/suite.go:21](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/storagetest/suite.go:21)). Routing two known production call sites through `eventid.New()` therefore does not make “every append path” monotonic and cannot make the `LatestEventID` interface guarantee true.

- **HIGH — Mint order is not necessarily commit order outside the production queue.**  
  `newEnvelope` can mint before entering `submitWrite`; for example AddHost creates its aggregate and event IDs before the queued closure begins ([internal/server/commands.go:113](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/commands.go:113), [internal/server/commands.go:131](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/commands.go:131)). The current production `WriteQueue` largely serializes commits, but the storage API itself permits concurrent direct writers. A lower ID can therefore commit after a higher ID, producing a real state change without advancing `MAX(event_id)`.

- **MEDIUM — The proposed compaction regression test is probabilistic.**  
  Running the broken `ulid.Make()` implementation 50 times makes failure highly likely, but not deterministic. More importantly, it does not test restart seeding, backward clock behavior, or storage-boundary insertion of a lower caller-supplied ID—the cases where the revised design still fails.

#### Plans 01 and 06

- **HIGH — Compaction advances the change ID but never notifies watchers.**  
  `CompactAggregates` calls the command handler and returns directly without calling `regenerateOutputs` or any equivalent notifier ([internal/server/service.go:926](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:926), [internal/server/service.go:943](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:943), [internal/server/service.go:961](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:961)). Plan 09 deliberately makes compaction advance `MAX(event_id)`, but plan 06’s single notification site only covers callers of `regenerateOutputs`. Existing connected sinks therefore retain the old change ID indefinitely after compaction, contrary to D-22’s expected redundant render and cross-consumer convergence semantics.

- **HIGH — The follow-mode lower-bound test’s “next snapshot” is not naturally triggered.**  
  The proposed decorator mutates directly inside `ListAll`. Direct storage mutation does not call `regenerateOutputs`, and the notifier has exactly one planned call site there. The first-snapshot inequality test works, but waiting for a second snapshot will hang unless the test explicitly calls `Notify` or performs another mutation through the service.

- **LOW — The “committed on every entry” comment must exclude startup.**  
  `RegenerateOutputs` is explicitly called at startup ([internal/server/service.go:101](/Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:101)). Startup has no immediately preceding write. Notification remains safe, but the comment should say “after successful mutation calls; startup is an initial broadcast,” rather than claiming every invocation follows a commit.

#### Plan 07

- **MEDIUM — `WatchPolicy.StatusInterval` and `--status-interval` have no defined precedence.**  
  The plan gives `WatchPolicy` a status interval used by e2e injection, while also specifying a Cobra flag with a fixed 30-second default. Unless the flag default is derived from the injected policy, Cobra’s default will overwrite the policy and the external test seam will not control ticker timing. The construction contract should state whether the flag overrides policy only when explicitly changed, or whether the policy supplies the flag’s default.

- **MEDIUM — A blocked ticker `Send` still needs an observable completion path.**  
  Per-session cancellation is correct, but the plan does not require `runWatch` to wait for or otherwise confirm ticker exit before returning. The proposed ticker-exit test implies such a seam, but the production ownership/lifecycle mechanism remains underspecified. A small completion channel is sufficient and does not violate single-send ownership.

#### Plan 08

- **HIGH — `testEnv` still lacks the state needed by `startServer`.**  
  The current server setup depends on local variables `store`, `cfg`, `logger`, listener, handler, and service ([e2e/helpers_test.go:69](/Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:69), [e2e/helpers_test.go:79](/Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:79), [e2e/helpers_test.go:101](/Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:101)). The revision adds `addr`, `sinkHealth`, `srvErrCh`, and `running`, but `startServer(t, env)` cannot build a fresh server over the same store because none of the store/config/logger/service factory state is retained on `testEnv`. This is the same class of incompleteness as round-2 H6, only partially fixed.

- **MEDIUM — Reusing the original `env.client` after restart needs an explicit contract.**  
  The existing `ClientConn` is created once and stored on `testEnv` ([e2e/helpers_test.go:120](/Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:120)). gRPC should reconnect to the same address, but helper calls made immediately after `startServer` must use a bounded context and tolerate transient reconnect state. Alternatively, redial and replace `env.conn`/`env.client` on each start.

#### Other plans

- Plans 02–05 are materially improved and no new execution-blocking issue was found in the round-3 changes.
- Plan 03’s new config fix is appropriately ordered before limit parsing.
- Plan 05’s duplicate-CN semantics and identity-failure gauge are now honest and testable.
- Plan 04’s empty-payload and fleet-wide keepalive clarifications close the earlier omissions.

### Codex — Suggestions

- Replace plan 09’s process-only generator invariant with one of these durable designs:

  - Preferred: add a database-owned monotonic sequence/change revision assigned in the same transaction as each append.
  - Smaller alternative: initialize the event-ID generator from `LatestEventID` during storage startup and reject/retry any proposed event ID `<= MAX(event_id)` inside the append transaction. This also handles arbitrary storage callers and commit ordering.

- If retaining ULIDs, make minting/validation transaction-coupled. A global generator alone cannot prove that the newest committed event owns the lexical maximum.

- Add deterministic plan-09 tests for:

  - restart within the same ULID millisecond;
  - appending an explicitly lower caller-supplied event ID;
  - two concurrent direct storage writers committing in reverse mint order;
  - backward-clock injection through an injectable clock.

- Notify after successful non-dry-run compaction. Either route compaction through a common “committed state changed” notifier or explicitly call the notifier from `CompactAggregates` when at least one aggregate was compacted.

- Fix the follow lower-bound test by explicitly triggering a second notification after the decorator mutation, or by performing the interleaving mutation through a service seam that commits and notifies.

- Define watch timing precedence explicitly: injected policy supplies Cobra defaults; an explicitly changed CLI flag overrides the policy.

- Expand `testEnv` with the persistent restart inputs—at minimum store, config, logger, and service construction state—or store a closure that builds and registers a fresh server from those captured resources.

### Codex — Risk Assessment

**Overall risk: HIGH**

Most earlier concurrency and client-safety issues are now well addressed, but TMPL-08 remains founded on an invariant plan 09 does not actually establish across restarts, arbitrary storage writers, or commit reordering. Additionally, compaction changes the new high-water mark without waking existing consumers, and the revised e2e restart helper remains unimplementable from the proposed `testEnv` fields. These should be resolved before execution; otherwise the phase can still report false convergence—the exact failure the new change ID was intended to prevent.

---

## pi Review

All key claims verified against source. Review follows.

---

**Repo verification performed.** Confirmed: `internal/storage/sqlite/eventstore.go:258` mints the compaction seed with bare `ulid.Make()`; `internal/server/commands.go:22,32,60` holds the mutex-guarded `*ulid.MonotonicEntropy`; `internal/config/client.go:55-59` swallows both inner errors exactly as H3 described; all six `regenerateOutputs` call sites (`service.go:108,211,285,314,594,850`) run *after* the write commits; `e2e/helpers_test.go:3` is `package e2e_test` with `srvErrCh` as a local at `:112` and TLS 1.2 floor at `:261`/`:369`; `ulid.LockedMonotonicReader` exists in the pinned oklog/ulid v2.

### pi — Summary

The round-3 revision is substantively correct on its three load-bearing changes. The H1 flip (change-ID derivation before `ListAll`) is sound, is applied consistently in plans 01 and 06, and — unlike round 2 — now has a test whose RED-against-reversed-order logic actually works (verified below). Plan 01-09's premise is real: the bare `ulid.Make()` at `eventstore.go:258` does bypass the monotonic generator, and routing both mint sites through a locked shared generator is the minimal correct fix. The Notify-first premise checks out against every caller. The `WatchPolicy` seam correctly resolves the external-test-package compile failure. I found one genuine cross-plan gap none of the three rounds caught (compaction does not notify), plus a handful of smaller items.

### pi — Strengths

- **H1 flip is logically airtight, and the RED-verification claim survives scrutiny.** With the wrong order, the decorator mutates inside `ListAll`, `LatestEventID` then returns the mutation's own ID, the post-stream `LatestEventID` returns the same value, and the "strictly less" assertion fails. With the right order it passes. The test genuinely discriminates. The follow-mode mirror (`FollowSnapshotIDIsLowerBoundOnEntries`) additionally asserts the *next* snapshot carries a strictly greater ID, which is the property that makes the lower bound self-correcting rather than merely labeled.
- **Plan 09's motivating bug is real and the remedy is minimal.** `eventstore.go:258` (`EventID: ulid.Make()`) is exactly as described; `LockedMonotonicReader` exists in the pinned dependency, so the concurrency-safety plan is implementable as written. The two-level test pinning (sqlite regression ×50 runs + `RunAll` compliance case) correctly addresses the ~50% pass rate of the broken code on a single run.
- **Notify-first premise verified.** Every `regenerateOutputs` caller — `AddHost` (`:207-211`), `UpdateHost` (`:281-285`), `DeleteHost` (`:311-314`), `ImportHosts` (`:593-594`), `RollbackToSnapshot` (`:846-850`), startup (`:108`) — invokes it strictly after the handler commit. Moving `Notify()` to the top is correct and needs no new call sites, exactly as plan 06 claims.
- **`WatchPolicy`/`WithWatchPolicy` resolves H4 correctly.** `e2e/helpers_test.go:3` confirms `package e2e_test`; unexported backoff vars were genuinely unreachable. Variadic `NewRootCmd(opts ...RootOption)` preserves all existing callers.
- **Wave restructuring is justified.** Plan 05's files (peercn, sinkmetrics, metrics) reference nothing from plan 01; dropping its `depends_on: 01-01` is honest dependency analysis, and plan 01's new dependency on 01-09 (`LatestEventID`, `ZeroChangeID`) is real.

### pi — Concerns

- **HIGH (cross-plan, never reviewed): Compaction advances the change ID but nothing notifies.** `CompactAggregates` (`service.go:927-…`) calls `handler.CompactAggregate` → `store.CompactAggregate` and **never calls `regenerateOutputs`** (verified — no notify site on that path, and plan 06 mandates exactly one notify site inside `regenerateOutputs`). After plan 09, compaction advances `MAX(event_id)` (D-22's accepted "one redundant render per compaction"). But with Notify only in `regenerateOutputs`, that redundant render **never happens until an unrelated mutation lands**. Worse, `RecordServerChange` is only called from `sendSnapshot`, so the server's convergence gauge keeps comparing sinks against the pre-compaction ID and reads converged=1 while the real high-water mark has moved. The system self-heals on the next mutation, but a quiet deployment that compacts (operator-driven, per COMP-01) leaves every sink's convergence signal silently wrong indefinitely. Fix is one line: `s.changes.Notify()` in `CompactAggregates` after a successful compaction (and it must be added to plan 06's "exactly one notify site" criterion, which currently greps for a count of 1 — `rg -c 'changes.Notify' internal/server/` returning 1 would fail the fix).
- **MEDIUM (plan 09): `mu sync.Mutex // protects entropy` left behind.** Plan 09 Task 1 removes the `entropy` field and reroutes `newID()` to `eventid.New()`, but never mentions the `mu` field at `commands.go:23`, which exists solely to guard `entropy`. After the change it is an unused field with a stale comment. No acceptance criterion catches it (`rg -n 'entropy'` returns nothing, but `mu` survives). Add "delete `mu`" to step 2 and a criterion.
- **MEDIUM (plan 01, must_haves vs. reality): "The change ID on a snapshot terminator is derived STRICTLY BEFORE store.ListAll… can never name state the entries do not contain" — this is true, but the one-shot path has no correction mechanism.** The lower-bound argument relies on "the next notify cycle" delivering a strictly greater ID. In one-shot `render` (follow=false), there is no next cycle — the consumer records an ID that understates its entries and only re-renders when the operator runs `render` again. This is benign for one-shot use (each invocation is operator-driven), but plan 01's must_have truth #10 ("corrected by the next notify cycle") is only true for follow mode. The contract doc (plan 02) should scope the eventual-convergence claim to sinks, not one-shot renders — currently it states it unconditionally.
- **LOW (plan 09): `TestCompactAggregate_AdvancesLatestEventID` RED-verification has a timing hole.** The test is only RED against the old code if the compaction seed and the prior max land in the *same millisecond* (a bare `ulid.Make()` in a later millisecond sorts greater and passes). Across `-count=50` runs the odds of never hitting a shared millisecond are low but nonzero on a slow machine. The plan acknowledges the probabilistic nature but prescribes no mitigation (e.g., no clock control). Acceptable, but the SUMMARY should record the observed RED count, not just "failed at least once."
- **LOW (plan 06): Notify-first on the startup path is a spurious wake with no subscribers — fine — but the acceptance criterion `rg -c 'changes.Notify' internal/server/` returns 1 counts matches, not call sites.** A comment mentioning `changes.Notify` (which the plan itself mandates writing at the call site) inflates the count to 2 and fails the gate on its own required comment. The criterion needs `\bs\.changes\.Notify\(\)` or a "call expressions only" note — same class of self-defeating gate the plans elsewhere carefully avoid.
- **LOW (plan 07): `TestWatch_LoadsSidecarAtStartup`'s artifact-deleted half depends on the server delivering a snapshot with the same change ID after the artifact is deleted — but plan 07's own skip logic then *re-renders* because `os.Stat` fails, which is correct, yet the test asserts the hook ran. Fine — but this exercises the D-21 artifact-exists guard through a full stack that plan 07's unit tests already cover; the e2e-value is marginal. Not a defect, just noting the test is heavier than its marginal coverage.**

### pi — Suggestions

1. **Add compaction notification to plan 06** (Task 1 or Task 2): call `s.changes.Notify()` after successful compaction in `CompactAggregates`, update the single-notify-site criterion to count call expressions (expected 2), and add `TestService_CompactAggregates_Notifies`. This closes the one place where the change ID moves without any watcher learning of it.
2. **Plan 09 Task 2, step 2:** explicitly delete the `mu` field from `CommandHandler` and add `rg -n 'mu sync.Mutex' internal/server/commands.go` → 0 as a criterion.
3. **Plan 02 Task 2:** in the `.ChangeID` doc section, state that eventual-within-one-notify-cycle convergence applies to **sink (follow) mode**; one-shot `render` reflects the state at invocation time and the ID understates entries by at most the mutations since the read began.
4. **Plan 06 acceptance criteria:** replace `rg -c 'changes.Notify'` count gates with call-expression-scoped greps, consistent with the two-token positive-grep discipline used everywhere else in this revision.
5. **Plan 09:** have the executor record the observed RED failure count (out of 50) in the SUMMARY, so a future reader can distinguish "fails ~50% as predicted" from "fails for an unrelated reason."

### pi — Risk Assessment

**LOW–MEDIUM.** The three round-3 mechanisms under review are individually correct and verified against source: the ID-generation fix targets a real bug (`eventstore.go:258`), the derivation flip is applied consistently with discriminating tests, and the policy seam fixes a genuine compile-time impossibility. The remaining risk is concentrated in the compaction-notification gap (HIGH-severity finding, one-line fix, but it sits exactly at the intersection of the two newest plans — 06 and 09 — which is why three rounds of plan-local review missed it) and in the usual execution risk of a 9-plan phase with this much acceptance-criteria machinery. With the compaction notify added, the plan set is ready to execute.
