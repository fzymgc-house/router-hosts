---
phase: 1
slug: consumer-rendered-output-templates-sink
round: 2
reviewed: 2026-08-01
reviewers: [codex, pi]
selection: explicit flags (--codex --pi)
plans_reviewed: 8
prior_round: 2026-07-31 (git 63f0c98..1b555c4 revised the plans in response)
risk_codex: HIGH
risk_pi: MEDIUM
---

# Phase 1 — Cross-AI Plan Reviews (Round 2)

Both lanes were **explicitly named**, both ran clean (`ok:true, stubbed:false` — no stubs,
no dropped lane, no `REVIEWED-WITHOUT-REPO-ACCESS` marker). Each received all 8 revised
plans in full; neither lane declares a prompt budget, so nothing was trimmed. Codex 3m09s,
pi 4m36s, invoked sequentially.

Both were told this was a second round and asked to prioritise **what the revision missed
or newly broke**, rather than re-deriving round 1.

## What round 2 was actually testing

Round 1 raised 4 HIGH / 6 MEDIUM / 8 LOW. Commit `1b555c4` claims all of them fixed, and
`63f0c98` applied four decisions plus one addition. That leaves two distinct surfaces:

| Surface | Status after round 2 |
|---|---|
| Round-1 fixes (H1, H3, H4, M2–M6, L1–L8) | **Both reviewers independently confirm these landed.** pi verified every one it could check; Codex lists each as a strength. No round-1 finding was re-raised. |
| **TMPL-08 change ID** (new in `63f0c98`, threaded through 6 plans) | **Both reviewers rate it HIGH.** Never reviewed before; it is now the phase's newest and most load-bearing invariant. |
| TMPL-06 amendment, D-17 FuncMap, D-12a three outcomes | Accepted by both as sound resolutions. |

The headline: **the revision fixed everything round 1 found, and the feature added alongside
those fixes is now the biggest risk in the phase.**

---

## Consensus Summary

### Both reviewers independently found the same new HIGH bug — from opposite ends

**Plan 01 derives the change ID *after* reading the entries** (`01-01-PLAN.md:399`), so a
mutation committing between `ListAll` and `LatestEventID` produces a terminator whose ID
names state the entries do not contain.

- **Codex** attacks the *rationale*: the plan says deriving afterward prevents the ID from
  describing newer state, but it "guarantees only that the ID is not older; it does not make
  entries and ID consistent." Reads are not held under the write queue, which is scoped to
  mutations (`service.go:784`).
- **pi** traces the *consequence* through Plan 07's D-21 client skip to a **permanently stale
  zone**: client renders entries(S1) recorded as ID2; the M2-triggered follow-up snapshot
  carries entries(S2) with the same ID2; the client skips it and serves S1 forever, reporting
  itself converged. No later snapshot changes the ID unless another mutation lands.

This is the strongest signal in the review: two reviewers, opposite directions of attack,
same line of the same plan. pi's trace also shows **every planned test passes with the wrong
order** — the failure only appears in production, silently.

The plan's own words at `01-01-PLAN.md:357-358` describe this exact hazard ("a deduping
consumer would silently keep serving a stale zone") as the thing TMPL-08 exists to prevent.
The revision reintroduced it through the terminator instead of through ULID generation.

### Where they diverge: the remedy

Not a contradiction — a difference in strength, and they compose.

- **pi: flip the order** (derive before `ListAll`). Then the ID *understates* state; the
  follow-up snapshot carries a strictly greater ID and the client re-renders. Cost: one
  redundant render. Never a permanent skip. One-line change.
- **Codex: make it atomic** — one SQLite read transaction returning `{entries, latestEventID}`,
  or read-ID → read-entries → read-ID-again with retry, or a projection generation recorded
  with the write.

pi's own MEDIUM concedes what Codex wants: even after the flip, the ID is a **lower bound**
on the snapshot's state, so `sink_converged` can briefly read 1 while the artifact holds newer
data. pi argues this is benign and self-healing within one notify cycle.

**Reconciled:** the flip is necessary and sufficient for *safety*. Atomicity is what the
*contract documentation* would need to keep its current wording. Since `.ChangeID` becomes a
consumer-visible compatibility surface the moment Plan 01 ships, the cheapest correct
combination is **flip the order AND soften the contract doc to "lower bound, convergence
eventual within one notify cycle"** — rather than build atomic snapshot machinery now.

### Direct contradiction — adjudicated against source

**Is the `MAX(event_id)` monotonicity premise sound?**

- **pi: "D-20 monotonicity claim verified."** Checked `CommandHandler.entropy` =
  `ulid.Monotonic(rand.Reader, 0)` (`commands.go:22,32,43`) and confirmed `oklog/ulid/v2@v2.1.2`
  defaults `inc` to `MaxUint32`, giving strictly increasing entropy within a millisecond.
- **Codex: "The monotonic-ID premise is false for compaction."** `CompactAggregate` mints its
  replacement seed with a bare `ulid.Make()` at `eventstore.go:258`, inside the storage layer,
  bypassing `CommandHandler` entirely.

**Codex is right; pi verified a narrower claim than the plan makes.** Confirmed independently:
`rg 'ulid\.(Make|New|MustNew)'` shows exactly two non-test event-ID construction sites —
`commands.go:60` (monotonic) and `eventstore.go:258` (bare `ulid.Make()`). `service.go:704` is a
snapshot ID, not an event ID, so it never enters `MAX(event_id)`.

The sharper form of the finding: `01-01-PLAN.md:352-359` instructs the executor to write a doc
comment asserting monotonicity and warning that "**any future** change to ID generation must
preserve monotonicity" — while the counterexample **already exists in the repo today**. The plan
would ship an invariant the codebase currently violates. D-22 ("compaction advances the change
ID — accepted") anticipated compaction moving the ID *forward*; it did not anticipate a
same-millisecond bare ULID sorting *below* the existing max, which makes the ID fail to advance
or regress.

---

## Findings by severity

Attribution: **both** = independently raised by both lanes. Verified = I confirmed against source.

### HIGH

| # | Finding | Source | Plan |
|---|---|---|---|
| H1 | Change ID derived after `ListAll`; snapshot can be labelled with an ID for state it does not contain. Via D-21 skip → **permanent stale zone that self-reports converged**. All planned tests pass with the wrong order | **both** | 01, 06 |
| H2 | Compaction mints its seed with bare `ulid.Make()` (`eventstore.go:258`), bypassing the monotonic generator — `MAX(event_id)` may fail to advance or regress. Plan writes the invariant as a future caution; the repo breaks it now | codex — **verified** | 01 |
| H3 | `LoadClientConfig` shadows and discards the inner error (`config/client.go:56-58`), so a found-but-invalid config file silently falls back to defaults — defeating the strict validation Plan 03 requires | codex — **verified** | 03 |
| H4 | e2e is package `e2e_test` (`helpers_test.go:3`) and cannot set unexported backoff vars in `internal/client/commands`. **The planned test will not compile** without an exported seam | codex | 08 |
| H5 | Backoff reset unimplementable under the stated `runWatch(...) error` contract — the supervisor sees only session end, but reset is specified on first successful snapshot write | codex | 07 |
| H6 | `restartServer` needs more lifecycle state than the proposed `testEnv` fields — `srv`, `cancel`, and a local-only `srvErrCh` (`helpers_test.go:33,112`) must all be replaced per start | codex | 08 |

### MEDIUM

| # | Finding | Source | Plan |
|---|---|---|---|
| M1 | Even after the flip, ID is a lower bound on snapshot state; contract doc must say so and define convergence as eventual within one notify cycle | **both** (pi explicit, codex implied) | 01, 02 |
| M2 | `Notify` fires only after all generators finish (`service.go:128→150`), coupling sink latency to legacy server-owned output and unrelated filesystem failures — weakens the phase's independent-consumer goal | codex | 06 |
| M3 | Sidecar state is written but never loaded at startup, so a consumer restart loses `rendered_change_id` and needlessly rewrites/reloads an already-current artifact | codex | 07 |
| M4 | Post-hook failure has no retry path: the artifact already carries the current ID, so the same-ID skip suppresses retry and `reload_failed` can stay true until host state changes | codex | 07 |
| M5 | Status-sender ticker needs the same teardown care as the server — a goroutine blocked in `Send` can outlive `runWatch` | codex | 07 |
| M6 | CN is not enforced-unique; duplicate CNs collapse into one registry record and merge their metrics | codex | 05 |
| M7 | `proto.Size` bounds serialized bytes, not retained heap — docs should not claim an exact 64 MiB ceiling | codex | 03 |
| M8 | `setupCmdTest` currently takes only `t` (`testhelper_test.go:23`); the new signature must be explicitly variadic or it breaks every existing caller | codex | 03 |
| M9 | Returning without joining relies on gRPC terminating both goroutines; no leak-count or churn assertion is specified | codex | 06 |
| M10 | `restartServer` that stops and immediately waits for readiness leaves no observable outage window — needs separate `stopServer`/`startServer` | codex | 08 |

### LOW

| # | Finding | Source | Plan |
|---|---|---|---|
| L1 | `renderDrainLimit` declared `const` but the test "temporarily lowers" it — a Go const cannot be lowered; executor will silently make it a var or write uncompilable test | pi | 01 |
| L2 | `TestWatch_SkipsRedundantRenderOnSameChangeID` asserts on mtime — flaky on coarse-granularity filesystems; the hook-count assertion already proves the skip | pi | 07 |
| L3 | `SinkHealth` eviction by oldest `LastSeen` can evict a *connected* idle sink; prefer disconnected-first | pi | 05 |
| L4 | `restartServer` port rebind can transiently fail; add one bounded `net.Listen` retry rather than hard `require.NoError` | pi | 08 |
| L5 | `FromProto` collapses nil vs. empty `Comment`; harmless today, worth one contract-doc line so v2 doesn't promise the distinction | pi | 02 |
| L6 | Plan 06 success criterion still says "exactly once per burst" while the revision correctly explains the notifier cannot guarantee it — internal contradiction | codex | 06 |
| L7 | `int32(len(entries))` can overflow before the client's 50k cap applies; the cap does not constrain server inventory | codex | 01 |
| L8 | "Exactly one CR/LF replacer" is an implementation-shape grep, not a behavioural gate; breaks on unrelated legitimate sanitization | codex | 02 |
| L9 | Client-template tests importing `internal/server` for the version constant couples a reusable package to the server; use a neutral shared package | codex | 02 |
| L10 | Harness TLS min is 1.2 (`helpers_test.go:258`) vs production 1.3 (`client.go:82`) — direct harness connections don't match production policy | codex | 08 |
| L11 | Identity-extraction failure still counts as connected; should also carry an error counter or prominent log | codex | 05 |
| L12 | Fixed keepalive values apply fleet-wide to all RPC clients, not only sinks | codex | 04 |
| L13 | `math/rand` package-level jitter complicates deterministic backoff tests unless injected | codex | 07 |
| L14 | No empty-payload chunking test, though the plan deliberately preserves a single empty response | codex | 04 |

---

## Decisions Required Before Execution

1. **Change-ID ordering and semantics (H1, M1)** — flip the derivation to before `ListAll` in
   `01-01-PLAN.md:399` and Plan 06's shared `sendSnapshot`, invert the accompanying comment, and
   restate the contract doc's `.ChangeID` as a **lower bound** with convergence eventual within
   one notify cycle. Decide separately whether to also build the atomic
   `{entries, latestEventID}` read Codex wants, or defer it as a follow-up issue. *Recommendation:
   flip now, document the bound, defer atomicity* — the flip removes the hazard, and atomicity is
   a storage-layer change of the same class as the #400 laziness already deferred.
2. **Compaction monotonicity (H2)** — either route `eventstore.go:258` through a shared monotonic
   generator, or abandon lexical `MAX(event_id)` for a database-owned sequence. Until one of those
   lands, Plan 01's doc comment asserts something false. This is a **prerequisite**, not a polish
   item: it invalidates the premise TMPL-08 rests on.
3. **Config error propagation (H3)** — `LoadClientConfig` must distinguish "no config file" from
   "config file present but invalid" before Plan 03 adds more strict fields. Fixing it after Plan 03
   ships means the new limits' validation is dead code in the file path.
4. **Watch runtime test seam (H4, H5, H6, M10)** — Codex's cross-plan suggestion is to define one
   injectable watch policy (backoff, jitter, ticker interval, test hooks) accepted by a testable
   command constructor, instead of mutable production globals. That single decision resolves four
   findings across Plans 07 and 08. Needs a call before Plan 07 is executed, since Plan 08 depends
   on the seam it exposes.
5. **Notify placement (M2)** — decide whether sink notification stays behind legacy generator
   execution or moves to fire directly on write commit. This is a phase-goal question
   (consumer independence), not a plan detail.

---

## Reviewer Verdicts

| Reviewer | Risk | Position |
|---|---|---|
| Codex | **HIGH** | The revision solved the round-1 issues, especially teardown and post-hook semantics. Remaining problems affect correctness, not polish: a snapshot can be labelled with an ID for data it did not contain; compaction violates the monotonic invariant; invalid config is silently ignored; the e2e backoff control is inaccessible from an external test package; reconnect and reload-failure retry semantics are incomplete. |
| pi | **MEDIUM** | The revision correctly addressed every first-round finding it could independently confirm. The one HIGH is a single-line ordering change with a clear test — but it sits on the phase's newest and most load-bearing invariant and would ship silently, since every planned test passes with the wrong order. "Fix that ordering and the phase is LOW-risk to execute." |

Both agree the phase is executable without re-planning from scratch. They differ on how much
must land first: pi sees one blocking line; Codex sees five correctness items. The gap is
mostly that Codex checked compaction, config loading, and e2e package boundaries — surfaces
pi did not reach — and each of those three checks out.

---

## Codex Review

### Codex — Summary

The revision substantially improves teardown, coalescing, sanitization, bounded collection, hook-failure semantics, and real-mTLS coverage. However, source verification uncovered three high-impact issues the revision missed: the proposed change ID does not identify the streamed snapshot atomically; compaction bypasses the claimed monotonic ID generator; and invalid client configuration is currently swallowed before validation. The e2e restart plan also depends on inaccessible unexported backoff variables. Overall, the plans are thoughtful but not yet execution-safe.

### Plan 01 — End-to-End Tracer

#### Strengths

- Correctly reuses the existing per-entry streaming pattern from [`internal/server/service.go:319`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:319>).
- Relocating the atomic writer is well scoped; the existing generators share a common implementation pattern.
- The typed template contract and buffered rendering directly address undefined fields and partial output.
- Adding storage compliance coverage is appropriate because `EventStore` is the shared abstraction at [`internal/storage/storage.go:51`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/storage.go:51>).

#### Concerns

- **HIGH — The change ID can describe state newer than the entries sent.** The plan reads `ListAll`, sends entries, and only then calls `LatestEventID`. Mutations can commit between those operations. The resulting terminator can contain mutation B’s event ID while the streamed entries contain state A. The plan explicitly claims deriving the ID afterward prevents this, but it guarantees only that the ID is not older; it does not make entries and ID consistent. Existing writes are serialized, but reads such as `ListAll` are not held under the write queue; rollback demonstrates the write queue is explicitly scoped around mutations at [`internal/server/service.go:784`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:784>).
- **HIGH — The monotonic-ID premise is false for compaction.** The plan says every append path uses `CommandHandler.newID`, but SQLite compaction creates its replacement event with bare `ulid.Make()` at [`internal/storage/sqlite/eventstore.go:258`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/sqlite/eventstore.go:258>). Compaction begins in the storage layer at [`internal/storage/sqlite/eventstore.go:210`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/storage/sqlite/eventstore.go:210>), bypassing `CommandHandler` entirely. A same-millisecond random ULID can sort below the removed maximum, so `MAX(event_id)` may fail to advance or can regress.
- **MEDIUM — The “same state yields the same ID” claim is stronger than the mechanism.** Event-log changes such as compaction change the ID without changing projected state. The plans acknowledge that case, so documentation should consistently call it an event-log high-water mark, not a pure state identity.
- **LOW — `int32(len(entries))` can overflow before the client applies its 50,000-entry limit.** The client cap does not constrain the server’s inventory.

#### Suggestions

- Make snapshot entries and change ID consistent through one of:
  - a storage method returning `{entries, latestEventID}` from one SQLite read transaction;
  - read-ID → read entries → read-ID again, retrying if the IDs differ;
  - a projection generation recorded atomically with committed writes.
- Route compaction ID creation through a shared monotonic generator, or abandon lexical ULID `MAX` in favor of a database-owned monotonic sequence.
- Add a test that mutates concurrently during snapshot assembly and verifies the terminator never names unsent state.
- Use `int64` for snapshot count or validate before conversion.

### Plan 02 — Template Contract

#### Strengths

- Moving the CR/LF sanitizer into a shared package correctly preserves the protection currently applied by `formatSuffix`.
- Installing the function map before parsing is correct for `text/template`.
- Requiring a named version block before connecting is a clean, fail-loud contract.
- Full-text fixture comparison for the unbound template is much stronger than the earlier declaration-count test.

#### Concerns

- **MEDIUM — Documentation may institutionalize the unsound change-ID semantics from Plan 01.** `.ChangeID` cannot truthfully be described as identifying the exact streamed state until snapshot consistency is fixed.
- **LOW — “Exactly one CR/LF replacer” is an implementation-shape gate, not a behavioral requirement.** The grep can fail on legitimate unrelated sanitization added elsewhere.
- **LOW — Importing `internal/server` from client-template tests couples a reusable client package’s tests to the server package.** A shared contract package would provide cleaner ownership for the version constant.

#### Suggestions

- Define the contract version in a neutral package shared by client and server.
- Describe `ChangeID` as an event-log revision unless Plan 01 gains an atomic snapshot mechanism.
- Prefer behavior tests over repository-wide replacer-count greps.

### Plan 03 — Bounded Client Collection

#### Strengths

- Adding both entry and byte limits fixes the earlier entry-count-only weakness.
- `proto.Size` is a sensible, deterministic measure of received wire volume.
- A named client option gives tests a stable seam.
- The plan correctly audits all `Recv`/`append` loops rather than relying on stale issue line numbers.

#### Concerns

- **HIGH — Invalid file configuration is currently silently discarded.** `LoadClientConfig` calls `loadClientConfigFile`, but accepts it only when `err == nil` and otherwise ignores the error at [`internal/config/client.go:56`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/config/client.go:56>). Therefore malformed limits, negative values rejected during file decoding, and unknown keys may silently fall back to defaults rather than producing the errors required by this plan. The strict unknown-key logic exists at [`internal/config/client.go:97`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/config/client.go:97>) but its error is swallowed by the caller.
- **MEDIUM — `proto.Size` bounds serialized bytes, not exact retained heap size.** Slice, string-header, and converted-object overhead remain. It still creates a practical bound, but documentation should not claim an exact 64 MiB memory ceiling.
- **MEDIUM — The proposed test-helper signature breaks all existing callers unless made variadic.** `setupCmdTest` currently takes only `t` at [`internal/client/commands/testhelper_test.go:23`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/client/commands/testhelper_test.go:23>). The plan should explicitly require `opts ...client.Option`.

#### Suggestions

- Change config loading to distinguish “no config found” from “config found but invalid.” Return parse, unknown-key, and validation errors for an existing file.
- Add tests where the server address comes from the environment while an existing file contains an invalid limit; this proves the file error is not masked.
- State that the byte budget bounds serialized response volume and provides a conservative operational control, not exact Go heap usage.
- Make `setupCmdTest(t, opts ...client.Option)` explicitly variadic.

### Plan 04 — Wire Streaming and Keepalive

#### Strengths

- The amended TMPL-06 scope now matches what the current `ListAll` architecture can actually deliver.
- Chunk reconstruction tests for all three formats close the earlier first-response-only coverage gap.
- Keeping format construction untouched reduces regression risk around existing export behavior.
- Testing the client/server keepalive enforcement invariant is valuable.

#### Concerns

- **MEDIUM — Export still builds multiple full-size representations.** `ListAll` materializes entries at [`internal/server/service.go:609`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:609>), then JSON creates another `out` slice at [`internal/server/service.go:634`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:634>), and every format builds the complete `data` buffer before chunking. This is permitted by the amended requirement, but operators should understand that chunking protects the receiver and wire, not server peak memory.
- **LOW — Fixed aggressive keepalive values add a fleet-wide behavior change to all RPC clients, not only sinks.** That deserves explicit compatibility and network-cost consideration.

#### Suggestions

- Make the operational documentation explicit that chunking occurs after full serialization.
- Consider applying keepalive only to long-lived client connections or making the values configurable if deployments include constrained links.
- Add an empty-payload chunking test because the plan deliberately preserves a single empty response.

### Plan 05 — Sink Health Primitives

#### Strengths

- Separating write success from reload success correctly implements the revised three-outcome model.
- The change ID is reduced to a 0/1 convergence observation instead of becoming a high-cardinality label.
- Identity extraction follows the real mTLS transport path rather than request data.
- The registry ceiling’s limitations are now documented honestly.

#### Concerns

- **MEDIUM — CN is not necessarily a unique certificate identity.** The harness uses a CN at [`e2e/helpers_test.go:222`](</Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:222>), but nothing shown enforces unique CN issuance. Two certificates with the same CN will overwrite the same registry record and collapse their metrics.
- **MEDIUM — Old CN series remain observable indefinitely within a process until eviction.** The 1,000-entry live cap helps server memory but does not prevent backend lifetime cardinality growth, as the revised plan itself acknowledges.
- **LOW — “Connected count even when identity verification fails” can hide authentication-path defects.** Production mTLS should make failure impossible; an identity-extraction failure should also have an error counter or prominent log.

#### Suggestions

- Document and enforce a deployment requirement that client certificate CNs are unique, or use a stronger stable identity such as certificate fingerprint/SAN.
- Add an identity-extraction-failure counter without a CN label.
- Include tests for duplicate CN connections so the chosen aggregation semantics are explicit.

### Plan 06 — Server Follow Mode

#### Strengths

- The revision correctly fixes the previous wait-before-return deadlock.
- Single ownership of `Send` and `Recv` matches grpc-go’s concurrency rules.
- Subscribe-before-read protects against mutations arriving during snapshot production.
- The opening status and D-21 server-side-skip boundary now have explicit tests.

#### Concerns

- **HIGH — Follow snapshots inherit Plan 01’s inconsistent change-ID race.** `sendSnapshot` remains a non-atomic `ListAll` plus `LatestEventID`, so convergence gauges and client deduplication can claim a consumer rendered a revision whose mutation was not included.
- **MEDIUM — Notification occurs only after all configured generators finish.** `regenerateOutputs` currently executes three potentially expensive writes before its early return at [`internal/server/service.go:128`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:128>). Placing `Notify` immediately before [`internal/server/service.go:150`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/server/service.go:150>) means consumer-owned sinks are delayed by legacy server-owned output generation. This weakens the phase goal of independent consumers and couples sink latency to unrelated filesystem failures.
- **MEDIUM — Returning without joining relies on gRPC promptly terminating both goroutines, but the plan lacks a leak-count or lifecycle assertion.** The bounded error channel avoids blocked reporting, but a repeated connect/disconnect test should prove goroutines do not accumulate.
- **LOW — The success criterion still says “exactly once per burst,” while the revision correctly explains that the notifier does not guarantee that.** This is an internal contradiction.

#### Suggestions

- Fix atomic snapshot identity before implementing follow mode.
- Notify immediately after mutation commit, separately from legacy output regeneration. Ideally call notification directly from successful write completion rather than from the output side-effect method.
- Add a repeated connection churn test that checks goroutine/connected-state stabilization.
- Replace “exactly once per burst” in Task 1’s done statement with the precise at-most-one-additional-wake guarantee.

### Plan 07 — Client Sink

#### Strengths

- The three outcomes are now correctly distinct.
- Artifact retention after hook failure is operationally sound.
- Mutex-owned health state closes the race identified in the first review.
- Snapshot terminators prevent rendering partial streams.
- The dedupe guard correctly checks both change ID and artifact existence.

#### Concerns

- **HIGH — Backoff reset is underspecified and cannot be implemented with the stated `runWatch(...) error` contract.** The supervising loop sees only when a session ends, but the plan says reset the backoff “as soon as a session successfully completes a snapshot write.” A session normally continues after that write and may fail later. `runWatch` needs a callback, result channel, or structured return carrying whether a snapshot succeeded.
- **MEDIUM — Existing sidecar state is written but never loaded on process startup.** The opening message is described as reporting “the state it already has on disk,” but a fresh process’s `sinkHealthState` starts empty. Therefore consumer-process restarts lose `rendered_change_id`, cannot report existing convergence immediately, and unnecessarily rewrite/reload an already-current artifact.
- **MEDIUM — A post-hook failure is logged but apparently does not cause retry of the hook until a later distinct snapshot.** Because the artifact now has the current change ID, the next identical snapshot is skipped, potentially leaving `reload_failed` permanently true until host state changes.
- **MEDIUM — Status-sender teardown needs the same care as the server.** A ticker goroutine blocked in `Send` can outlive `runWatch` unless session exit and stream cancellation are explicitly coordinated.
- **LOW — `math/rand` package-level behavior complicates deterministic backoff tests unless jitter is injected.**

#### Suggestions

- Give `runWatch` an `onSnapshotSuccess` callback or return a structured session result.
- Load and validate the sidecar on startup, using it only when the artifact exists.
- Define retry semantics for reload failures. Options include retrying the hook with backoff against the retained artifact or not applying the same-ID skip while `reload_failed` is true.
- Inject a jitter function and backoff policy for deterministic tests.
- Add explicit ticker-goroutine termination tests.

### Plan 08 — E2E and Documentation

#### Strengths

- Wiring `SinkHealth` into the real harness makes CN-keying coverage non-vacuous.
- Restarting the actual server is materially stronger than cancelling one RPC.
- Driving the real Cobra command covers configuration, TLS, reconnect, rendering, and sidecar behavior together.
- Manual verification distinguishes performed checks from explicitly unrun checks.

#### Concerns

- **HIGH — The e2e package cannot set the proposed unexported backoff variables.** The harness package is `e2e_test` at [`e2e/helpers_test.go:3`](</Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:3>), while the plan says it will set package-level variables in `internal/client/commands`. Unexported variables are inaccessible from this external test package. This test will not compile unless a public test seam or dependency injection is added.
- **HIGH — The restart helper needs more lifecycle state than the proposed `testEnv` fields.** The current environment retains `srv`, `cancel`, `conn`, and a local-only `srvErrCh` at [`e2e/helpers_test.go:33`](</Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:33>) and [`e2e/helpers_test.go:112`](</Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:112>). A reusable restart must replace the cancel function, server pointer, error channel, and probably client behavior safely. Merely adding `addr` and `sinkHealth` is insufficient.
- **MEDIUM — The existing gRPC client connection remains attached to the old server lifecycle.** The real watch command creates its own connection, but other `env.client` uses after restart need clear semantics.
- **MEDIUM — The test sequence says “call restartServer; while the server is down,” but a helper named `restartServer` that stops and immediately waits for readiness leaves no externally observable outage window.** The test needs separate `stopServer` and `startServer` operations.
- **MEDIUM — E2E stability depends on the Plan 07 backoff seam and reset semantics, both currently unresolved.**
- **LOW — The helper TLS configuration uses TLS 1.2 minimum at [`e2e/helpers_test.go:258`](</Volumes/Code/github.com/fzymgc-house/router-hosts/e2e/helpers_test.go:258>), while production client credentials require TLS 1.3 at [`internal/client/client.go:82`](</Volumes/Code/github.com/fzymgc-house/router-hosts/internal/client/client.go:82>). The real command path still uses production settings, but direct harness connections do not exactly match production policy.

#### Suggestions

- Add an exported or injected `WatchOptions`/backoff policy accepted by a testable command constructor; do not expose mutable production globals merely for e2e.
- Split restart into `stopServer` and `startServer`, with lifecycle state stored on `testEnv`.
- Store and replace `srvErrCh`, `cancel`, and `srv` on every start.
- Ensure cleanup handles both currently-running and already-stopped states.
- Align the harness TLS minimum with production TLS 1.3.
- Add a mutation during the outage so post-reconnect artifact rewriting is observable; unchanged state should exercise the dedupe path instead.

### Cross-Plan Suggestions

- Add a new prerequisite plan or revise Plan 01 to establish an atomic snapshot contract before the proto and client dedupe become compatibility surfaces.
- Fix compaction event ID generation before relying on lexical `MAX(event_id)`.
- Fix client-config error propagation before adding more strict configuration fields.
- Define a shared, injectable watch runtime policy covering backoff, jitter, ticker interval, and test hooks. This will simplify Plans 07 and 08 and eliminate mutable globals.
- Load sidecar state at startup and specify reload-failure retry behavior.
- Update all success criteria that still use the old “one snapshot per burst” wording.

### Codex — Risk Assessment

**Overall risk: HIGH**

The revision solved several important first-round issues, especially stream teardown and post-hook semantics. The remaining problems affect correctness rather than polish:

1. A snapshot can be labeled with a change ID for data it did not contain.
2. Compaction violates the claimed monotonic event-ID invariant.
3. Invalid limits in an existing config file can be silently ignored.
4. The proposed e2e backoff control is inaccessible from the external test package.
5. Reconnect backoff reset and reload-failure retry semantics are incomplete.

These should be resolved before execution because change identity, deduplication, and convergence metrics become consumer-visible compatibility behavior once Plan 01 ships.

---

### pi Review

I've verified the load-bearing claims against the repo (monotonic ULID entropy at `internal/server/commands.go:22` backed by `oklog/ulid/v2@v2.1.2` with `inc==0 → MaxUint32`, the `regenerateOutputs` early return at `internal/server/service.go:150`, the single-chunk `ExportHosts` send at `service.go:678`, the first-`Recv`-only export tests at `service_test.go:492/514/552`, the sanitizer at `hostsfile.go:121-129`, the e2e harness missing `WithSinkHealth` at `e2e/helpers_test.go:103`). Here's the review.

### pi — Summary

The revision is substantially improved: the H1 teardown fix is structurally correct, the H3/D-12a three-outcome model is coherent and enforced by a real test, the phantom metric (M5) is properly removed, and the M3/M4 e2e gaps are closed with harness changes I confirmed are needed (`e2e/helpers_test.go:103` indeed passes no `WithSinkHealth` today). However, the revision **introduced one new HIGH-severity correctness bug**: plan 01's change-ID derivation ordering interacts with plan 07's D-21 client-side skip to produce a permanently stale zone. There is also a residual LOW-level inconsistency around the `renderDrainLimit` test seam and a couple of flaky-test risks. Overall the plan set is executable and well-gated, but the change-ID ordering must be flipped before execution.

### Strengths

- **H1 teardown fix is correct and correctly gated.** Removing the join and returning on first error matches `grpc.ServerStream` semantics — RPC teardown unblocks a `Send` stalled on flow control. The two dedicated regression tests (`FollowSendErrorReturnsWhileRecvIdle`, `FollowRecvEOFReturnsWhileSendBlocked`) target the two distinct failure windows, and the "verify each goes RED against the pre-review teardown" acceptance criterion is exactly the right discipline for a test whose failure mode is a hang.
- **D-20 monotonicity claim verified.** `CommandHandler.entropy` is `ulid.Monotonic(rand.Reader, 0)` (`internal/server/commands.go:22,32,43`), and in the pinned `oklog/ulid/v2 v2.1.2`, `Monotonic(e, 0)` defaults `inc` to `math.MaxUint32`, yielding strictly increasing entropy within one millisecond. `MAX(event_id)` is sound, and `TestService_WatchHosts_ChangeIDAdvancesOnMutation` (50 same-ms mutations, no sleep) tests the actual property rather than the clock.
- **Notify placement verified.** `regenerateOutputs` has the early return at `internal/server/service.go:150` (`if s.hooks == nil || !ran`), and placing `Notify()` before it correctly covers generator-less deployments. Single notify site covering all mutation paths is right.
- **Review L2 fix is real.** The existing `TestService_ExportHosts_*` tests do read only the first response (`service_test.go:492`, `:514`, `:552`), so the new multi-chunk reconstruction tests with full-concatenation equality plus ragged-chunk assertions supply coverage that genuinely did not exist.
- **M5 removal is the right call.** A counter that nothing increments is worse than absent, and deriving increments from repeated status reports would double-count. The consecutive-failures gauge is the correct instrument for consumer-reported standing state.
- **M6 restatement is honest.** The "what is bounded / what is not" split (label *source* is the real bound, not the eviction ceiling) is the accurate cardinality story, and keeping the change ID out of labels by construction is correct.
- **H3 resolution is sound.** "Never roll back after the hook ran" is the only defensible semantics — on hook failure it is unknowable whether the resolver already read the new file. `TestWatch_HookFailureRetainsNewArtifact` asserting the on-disk bytes equal the *newly rendered* content (not mere existence) is the assertion that actually distinguishes retention from rollback.
- **Plan 03's dual bound is justified by the code.** I confirmed `internal/validation` caps hostnames/aliases but not comment/tag length, so the entry-count-only cap was genuinely insufficient; `proto.Size` on the received message is the right measurement.

### Concerns

#### HIGH — Plan 01's change-ID derivation ordering creates a permanent-stale-zone bug when combined with plan 07's D-21 skip

Plan 01 Task 2 step 5 says: *"Derive the change ID **after** reading the entries, not before, so the ID can never claim to describe state newer than what was actually sent."* Trace the race this opens:

1. Sender calls `store.ListAll` → gets entries reflecting state S1.
2. Mutation M2 commits (new event ID2 > ID1) → `changeNotifier.Notify()` fires.
3. Sender calls `LatestEventID` → gets **ID2**, and sends terminator with entries(S1) + changeID(ID2).
4. Client renders entries(S1), records changeID = ID2.
5. M2's notify wakes the sender; it sends snapshot entries(S2) + changeID(ID2).
6. Client-side skip (plan 07, step 3b): incoming ID2 == last rendered ID2, artifact exists → **skip**. The consumer serves entries(S1) forever, believing it is current at ID2. No further snapshot will ever carry a different ID unless another mutation lands.

The plan's stated rationale optimizes for the harmless direction. Deriving **before** `ListAll` (ID1, then entries possibly including M2) is safe: the terminator understates the state, the M2-triggered follow-up snapshot carries ID2 ≠ ID1, and the client renders again — costing one redundant render, never a permanent skip. This is precisely the failure mode TMPL-08/D-20 exists to prevent ("a deduping client would skip a real update and serve a stale zone silently" — the plan's own words), reintroduced through the terminator rather than through ULID generation. The ordering must be flipped in plan 01 step 5 and in plan 06's shared `sendSnapshot`, and the plan's comment text inverted. Note this also means `TestService_WatchHosts_ChangeIDAdvancesOnMutation`-style tests don't catch it — a dedicated test mutating *between* `ListAll` and terminator and asserting the *next* snapshot is not skippable would (i.e., a follow-mode test asserting convergence after a mid-send mutation, which plan 06's `FollowConvergesAfterBurst` partially covers — it should explicitly assert the final snapshot's ID **differs from** any ID sent with a stale entry set, or equivalently that final entries match final state, which it does assert; but the one-shot path and the ID-entry consistency invariant itself need the ordering fix regardless).

#### MEDIUM — Plan 06's sender shares the same flawed ID-entry consistency window even after the flip

Even with derive-before, a snapshot can contain entries *newer* than its ID (mutation lands between `LatestEventID` and `ListAll`). That's safe for the skip logic but means the terminator's ID does not exactly name the entries' state — `sink_converged` could briefly read 1 while the artifact actually contains newer data. This is benign and self-healing (the follow-up snapshot corrects it), but the plan set never states this invariant explicitly. The contract doc (plan 02 Task 2) should say the change ID is a *lower bound* on the snapshot's state, and convergence is eventual within one notify cycle.

#### LOW — `renderDrainLimit` constant vs. test seam contradiction

Plan 01 Task 2 says "Declare `renderDrainLimit = 50_000`" and the test "drives the limit by temporarily lowering the package-level `renderDrainLimit`". A Go `const` cannot be lowered by a test. Either declare it as a package-level `var` (and say so), or give `render` the option seam from the start. As written, the executor will either make it a var silently (contradicting "compiled-in constant") or write a test that can't compile.

#### LOW — `TestWatch_SkipsRedundantRenderOnSameChangeID` asserts on artifact mtime

Modification-time comparison is flaky on fast filesystems with coarse mtime granularity (or `noatime`-style behaviors). The hook-run-count assertion already proves the skip; the mtime assertion should be dropped or replaced with a write-count instrument (e.g., wrapping `atomicfile.Write` behind a counter in the test, or asserting the file's content+birth-time via `os.Stat` on the same open handle).

#### LOW — `SinkHealth` eviction can evict a currently-connected idle sink

`MaxTrackedSinks` eviction by oldest `LastSeen` doesn't distinguish connected from disconnected entries. A long-quiet connected sink whose ticker interval exceeds the eviction churn could lose its entry mid-connection (its next status report recreates it, so self-healing, but the gauge blips to absent). Prefer evicting only among *disconnected* entries first; fall back to oldest overall only if all entries are connected.

#### LOW — `restartServer` port rebind

Re-listening on the same `127.0.0.1:PORT` after shutdown is generally fine for a listening socket (no TIME_WAIT), but if the old server's accepted connections linger in TIME_WAIT on that port, some platforms can briefly refuse the bind. Recommend one bounded retry on `net.Listen` failure inside `restartServer` rather than a hard `require.NoError`.

#### LOW — `FromProto` collapses nil vs. empty Comment

Proto `GetComment()` returns `""` for absent comments, but `formatSuffix` treats nil and empty identically, so no behavioral loss for the shipped formats. Worth one line in the contract doc that `.Comment` is never distinguishable-as-absent in templates, so a future contract v2 doesn't accidentally promise that distinction.

### Suggestions

1. **Flip the derivation order (blocking):** plan 01 Task 2 step 5 and plan 06 `sendSnapshot` — call `LatestEventID` **before** `ListAll`, and add a follow-mode test that mutates between the terminator of snapshot N and snapshot N+1, asserting the client-visible invariant "no skipped snapshot leaves entries behind the recorded ID" (concretely: final entries == final state, already present, plus an assertion that any ID sent with a complete-but-superseded entry set is followed by a snapshot with a strictly greater ID).
2. Document in the contract doc (plan 02) that the change ID is a lower bound on snapshot state and convergence is eventual within one notify cycle.
3. Make `renderDrainLimit` a package-level `var` explicitly, or seed it via a test-only option; reconcile the "compiled-in constant" language.
4. Drop the mtime assertion in the skip test; keep the hook-count assertion.
5. Prefer disconnected-first eviction in `SinkHealth`; note the connected-entry fallback in the doc comment.
6. Add a bounded retry to `restartServer`'s `net.Listen`.
7. In plan 08's manual checkpoint, add one step asserting the mid-flight mutation race empirically (mutate rapidly during a sink's first snapshot and confirm convergence), since unit tests under bufconn rarely reproduce it.

### pi — Risk Assessment

**MEDIUM.** The architecture, teardown design, contract gating, and metric discipline are sound and unusually well-verified against the actual code — the revision correctly addressed every first-round finding I could independently confirm (H1, H3, M2–M6, L1–L8). The one HIGH finding (change-ID derivation order vs. D-21 skip) is a single-line ordering change with a clear test, but it sits exactly on the phase's newest and most load-bearing invariant, and it would ship silently: every planned test passes with the wrong order, and the failure only manifests in production as a permanently stale zone that reports itself current. Fix that ordering and the phase is LOW-risk to execute.
