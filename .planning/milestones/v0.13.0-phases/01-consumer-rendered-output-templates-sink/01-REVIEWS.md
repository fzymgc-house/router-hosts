---
phase: 1
slug: consumer-rendered-output-templates-sink
round: 4
reviewed: 2026-08-01
reviewers: [codex, pi]
selection: explicit flags (--codex --pi)
plans_reviewed: 9
prior_rounds: "r1 -> 63f0c98..1b555c4; r2 -> 7d423a7; r3 -> aa322cd"
risk_codex: MEDIUM
risk_pi: LOW
---

# Phase 1 — Cross-AI Plan Reviews (Round 4)

Both lanes **explicitly named**, both clean (`ok:true, stubbed:false`, no stubs, no dropped lane,
no `REVIEWED-WITHOUT-REPO-ACCESS`). All 9 plans in full, no budget, nothing trimmed. Codex 1m47s,
pi 4m32s. Prompt ~143k tokens.

Both were told this was round 4, pointed at the in-transaction guard as the never-reviewed surface,
and told explicitly that a short review reporting genuine convergence beats a padded one.

## This is the first round where neither reviewer rates the phase HIGH

| Round | Codex | pi | Review length (codex/pi) |
|---|---|---|---|
| 1 | HIGH | MEDIUM | — |
| 2 | HIGH | MEDIUM | 216 / 71 lines |
| 3 | HIGH | LOW–MEDIUM | 97 / 40 lines |
| **4** | **MEDIUM** | **LOW** | **45 / 31 lines** |

Both explicitly use the word *converged*. pi: "This round looks like real convergence: the remaining
items are one overclaim to correct and two small acknowledgements, not design changes." Codex: "Once
that case and the restart-test isolation are addressed, the plan set should be considered low risk
and converged."

---

## Consensus Summary

### The in-transaction guard is correct — independently verified by both, in mechanism detail

This is the strongest positive result across four rounds. Both lanes traced the guard against real
code rather than accepting the plan's description:

- **Placement.** All four append paths — `AppendEvent` (`eventstore.go:21`), `AppendEvents` (`:55`),
  `AppendEventsBatch` (`:93`), `CompactAggregate` (`:210`) — funnel through `insertEvent` (`:313`)
  while holding a `sqlitex.ImmediateTransaction`. SQLite takes the write lock up front, so the
  `MAX(event_id)` re-read cannot race a concurrent commit.
- **Multi-event transactions stay ordered.** Repeated `insertEvent` calls share the connection and
  transaction, so each later `MAX` read observes the earlier inserts of the same transaction —
  `AppendEvents` and `AppendEventsBatch` are correct.
- **Lexical ordering is sound.** `event_id TEXT PRIMARY KEY` (`migrations/001_initial.sql:3`) makes
  `MAX` an indexed seek, not a scan.
- **`EventID`-as-advisory is safe.** Neither lane found any production consumer of a caller-minted
  `EventID` after append. `CommandHandler` returns projected `HostEntry` values, never the proposed
  ID; stored envelopes are decoded back from the database (`projection.go:164`). The only read-back
  equality assertions are in tests (`storagetest/suite.go:72`, `sqlite_test.go:85`), which the plan
  reroutes through `eventid.New()`.
- **pi additionally cleared `RollbackToSnapshot`** (`service.go:769-852`): it builds envelopes via
  `PrepareAddEvent`/`PrepareDeleteEvent` and commits through `AppendEventsBatch`, so it passes
  through the guard and D-22's "rollback advances rather than regresses" survives.

Both also independently confirm the guard is the *right* fix — pi: "no process-local generator could
close it."

### The bulk-path cost question, answered

Both reviewers were asked directly whether the per-row `SELECT MAX(event_id)` is acceptable on
`AppendEventsBatch`. Both say yes: an indexed primary-key maximum on a connection and transaction
already held. Codex would like a recorded benchmark rather than a CI threshold; pi notes the plan's
acknowledgement (T-1-54) exists but never names the batch/import/**rollback** paths it actually
affects.

### Two new findings — one per lane, no overlap

Unlike rounds 2 and 3, the lanes did not converge on a single issue. They found different things,
and both check out.

---

## Findings by severity

Verified = confirmed against source by the orchestrator.

### HIGH

| # | Finding | Source | Plan |
|---|---|---|---|
| H1 | **Zero-ULID / empty-store sentinel collision.** Plan 09 line 484 gates the guard: *"When the log is non-empty and the envelope's `EventID` does not compare strictly greater than that maximum, replace..."* On an empty store the guard is skipped entirely, so a caller-supplied zero ULID inserts verbatim. `MAX(event_id)` then equals the zero ULID — indistinguishable from `ZeroChangeID`, the empty-store sentinel — so `LatestEventID` reports "empty" for a log holding one event and the wire carries the sentinel for a non-empty store. No planned test covers "zero ID into empty store" | codex — **verified verbatim** | 09 |

Reachability: no production path mints a zero `EventID`, but `EventStore.AppendEvent(s)` accepts
caller-constructed envelopes (`storage.go:51`), and a zero-value `domain.EventEnvelope` has a zero
`EventID`. The compliance suite is exactly where a future backend would hit it. Fix is cheap —
always re-mint a zero proposed ID regardless of log emptiness.

### MEDIUM

| # | Finding | Source | Plan |
|---|---|---|---|
| M1 | **The "single INSERT funnel" claim is factually false.** `internal/storage/sqlite/legacy_migration.go:183` executes a direct `INSERT INTO events` with preserved Rust-era IDs, bypassing `insertEvent` entirely. Plan 09 asserts the single-funnel claim in **five places** (lines 55, 71, 126, 461, 614) | pi — **verified** | 09 |
| M2 | **Restart-seeding test is not independently discriminating.** The `internal/eventid` floor is package-global, so a same-process test can raise it before `TestInitialize_SeedsGeneratorFromPersistedLog` runs; and if the test reads the ID back from storage, the in-transaction guard repairs an unseeded proposal and the test passes even with `Initialize` seeding deleted | codex | 09 |

On M1 — the code is currently **safe**, and pi verified why: the legacy migration runs inside
`Initialize`'s `withConn` body (`sqlite.go:73`, guarded by `isMigrationApplied(conn,
legacyMigrationVersion)` at `:91`), i.e. *before* the proposed `eventid.Seed(LatestEventID)` at the
end of `Initialize`; it is one-shot; and it skips entirely when `events` is non-empty
(`legacy_migration.go:43-49`). The defect is the false claim, not the behavior — and it is the same
*class* as round 3's H2: a plan asserting an invariant the codebase does not satisfy. That it
recurred is worth noting.

### LOW

| # | Finding | Source | Plan |
|---|---|---|---|
| L1 | Plan 01's final `<done>` (line 692) still says the change ID names the **"exact server state"** — contradicting the lower-bound restatement rounds 2–3 established and the rest of the plan | codex — **verified** | 01 |
| L2 | T-1-54 acknowledges the per-row `MAX` cost generically but never names the paths it hits — `AppendEventsBatch` is import **and rollback** (`service.go:836`) | pi | 09 |
| L3 | `metrics_test.go:627` constructs an envelope with bare `ulid.Make()` and appends through the store; the plan delegates it to "check, do not assume" rather than including it in the `ulid.Make()` → `eventid.New()` substitution set or stating why it is exempt | pi | 09 |
| L4 | Compaction correctness relies on seed + floor + guard together, not the guard alone — `CompactAggregate` deletes the aggregate before `insertEvent` (`eventstore.go:252, :268-273`), so if the deleted aggregate held the global maximum, the in-transaction `MAX` sees only the remainder. Safe as designed; the combined-mechanism explanation must survive in comments and tests | codex | 09 |
| L5 | No benchmark or recorded measurement for `AppendEventsBatch` at representative sizes (1 / 100 / 1k / 10k) | codex | 09 |

---

## Decisions Required Before Execution

Only one is a correctness fix; the rest are accuracy and test-quality items.

1. **Zero-ULID guard case (H1)** — drop the non-empty gating and always re-mint when the proposed ID
   does not sort strictly greater, treating an empty log as a zero maximum. Codex suggests a
   `(max ulid.ULID, found bool, error)` helper or an explicit `env.EventID == ulid.Zero` check. Add
   `TestInsertEvent_ZeroIDIntoEmptyStoreRemints`, assert `LatestEventID` is non-zero afterward, and
   extend the `EventStoreAppendNeverLowersLatestEventID` compliance case.
2. **Correct the single-funnel claim (M1)** — name `legacy_migration.go:183` in plan 09, state its
   safety argument (runs before seeding, one-shot, skips on non-empty `events`), note its DEBT-01
   removal horizon, and reword to "the single funnel for all **post-migration** appends" in all five
   places. Do not add a funnel-count gate without accounting for it.
3. **Make the seeding test discriminating (M2)** — give `internal/eventid` a test-only isolated
   generator (or a generator value with a package singleton), and assert the ID from `eventid.New()`
   *immediately after `Initialize` and before any append*, so the guard cannot mask a missing seed.
4. **Fix plan 01's stale `<done>` text (L1)** — "exact server state" → lower bound, consistent with
   the rest of the plan set.
5. **Small accuracy items (L2, L3)** — name the bulk paths in T-1-54; decide `metrics_test.go:627`
   in-plan rather than delegating it to the compiler.

---

## Reviewer Verdicts

| Reviewer | Risk | Position |
|---|---|---|
| Codex | **MEDIUM** | "The central concurrency design is correct and materially stronger than round 3: immediate transactions plus a guard in the single insert funnel close reverse commit ordering and arbitrary caller IDs without changing D-18's ULID contract." The zero-ULID collision is a genuine TMPL-08 hole and should be fixed first; after that and the restart-test isolation, "low risk and converged." |
| pi | **LOW** | "The one MEDIUM finding is a documentation/claim-accuracy issue, not a correctness defect." Guard mechanism, advisory-ID contract and seeding all trace correctly against real code; the new tests' determinism is a genuine improvement over round 3. "Nothing else of substance." |

The gap is one finding wide again, and this time it is H1 — pi did not test the empty-store path.
Both verdicts are consistent with the same underlying picture: the design is right, and what remains
is one edge case plus claim accuracy.

pi explicitly re-checked every round-3 revision item — compaction notify (correctly a no-op against
the `len(events) <= 1` early return at `eventstore.go:226-231`), the call-expression-scoped
count-of-2 gate, `testEnv` construction inputs, `Flags().Changed` precedence, `tickerDone` — and
reported no new findings on any of them.

**Trajectory.** Round 1 found design defects. Round 2 found what the revision broke. Round 3 found
what the plans never thought to touch — pre-existing code. Round 4 found one edge case in the new
mechanism and one false claim about the old codebase. The findings are getting smaller and more
local, which is what convergence looks like. H1 is worth fixing before execution; the rest could
defensibly be handled during it.

---

## Codex Review

### Codex — Summary

The plan set is close to convergence, and the new in-transaction strategy is fundamentally sound: every SQLite append path uses `insertEvent` while holding an immediate write transaction, so reading the maximum and conditionally re-minting there closes the mint-order/commit-order race. Caller-supplied event IDs also appear safe as advisory values because production command results expose aggregate state, not the proposed event ID. I found one substantive sentinel edge case and one test-isolation weakness in plan 09. The remaining round-3 revisions—compaction notification, status-interval precedence, ticker completion, and e2e restart construction—are directionally correct.

### Codex — Strengths

- The guard is placed at the correct storage funnel. `AppendEvent`, `AppendEvents`, and `AppendEventsBatch` each begin a `sqlitex.ImmediateTransaction` before calling `insertEvent` (`internal/storage/sqlite/eventstore.go:21`, :55, :93), and compaction does the same before its delete/insert sequence (:210–283). SQLite therefore excludes another writer between the planned `MAX(event_id)` read and insert.

- Multi-event transactions remain correctly ordered. `AppendEvents` and `AppendEventsBatch` call `insertEvent` repeatedly on the same connection and transaction (:55–130), so each later `MAX` read sees earlier inserts from that transaction. The extra query is an indexed primary-key maximum, not a table scan (`event_id TEXT PRIMARY KEY` in `internal/storage/sqlite/migrations/001_initial.sql:3`).

- Advisory `EventID` does not appear to break production callers. `CommandHandler` constructs envelopes and returns projected `HostEntry` values or errors; it does not return or subsequently compare the proposed event ID (`internal/server/commands.go:105`, :195–290, :340–360). Stored envelopes are later decoded from the database, so projections observe any replacement ID naturally (`internal/storage/sqlite/projection.go:164`).

- The plan correctly updates tests that explicitly assume supplied-ID equality. The current equality assumptions are concentrated in the storage compliance and SQLite tests (`internal/storage/storagetest/suite.go:72`, `internal/storage/sqlite/sqlite_test.go:85`); production code has no equivalent dependency.

- Compaction notification closes a real cross-plan gap. `CompactAggregates` currently returns directly after calling the compaction handler and never invokes `regenerateOutputs` (`internal/server/service.go:927`). A separate notify after an actual shrink is therefore necessary once compaction advances the change ID.

- The bulk-path cost is acknowledged honestly. One indexed `MAX` lookup per row is real overhead, especially in `AppendEventsBatch`, but it occurs on an already-held connection and transaction. For this operator/import workload, accepting that cost in favor of correctness is reasonable.

### Codex — Concerns

- **HIGH — the empty-store zero-ULID case can collide with the sentinel.** Plan 09 says the guard re-mints only “when the log is non-empty.” But `LatestEventID` deliberately represents an empty log as the zero ULID, and `EventStore` accepts caller-constructed envelopes (`internal/storage/storage.go:51`). A caller can therefore append an envelope whose proposed ID is the zero ULID into an empty store. If the guard skips comparison because the log is empty, the row is stored with the zero ID and `LatestEventID` remains indistinguishable from the empty-store sentinel after a real commit. None of the proposed tests covers “zero ID into empty store.”

- **MEDIUM — the restart-seeding test is vulnerable to process-global state and may test the guard instead of seeding.** The proposed `internal/eventid` floor is package-global. Tests in the same process can raise it before `TestInitialize_SeedsGeneratorFromPersistedLog`, making the supposedly fresh generator not fresh. Conversely, if the test checks the ID read back from storage, the in-transaction guard can repair an unseeded proposal and let the test pass with `Initialize` seeding removed. The current plan’s RED-verification instruction helps during implementation but does not make the permanent regression test independently discriminating.

- **LOW — compaction correctness relies on both mechanisms, not solely on the insert guard.** `CompactAggregate` deletes the aggregate before calling `insertEvent` (`internal/storage/sqlite/eventstore.go:252`, :268–273). If the deleted aggregate held the global maximum, `MAX(event_id)` inside `insertEvent` sees only the remaining log. The planned `eventid.New()` seed, raised persisted floor, and guard together make this safe; the guard alone does not preserve the deleted maximum. Comments and tests should retain that combined-mechanism explanation.

- **LOW — bulk cost deserves an explicit benchmark or recorded measurement.** `AppendEventsBatch` loops per event inside one transaction (`internal/storage/sqlite/eventstore.go:93`), so a large import adds one SQL statement per row. The plan acknowledges the cost but supplies no performance gate. This is not a correctness blocker, but a benchmark would prevent a surprising import regression.

### Codex — Suggestions

- Change the guard so a zero proposed ID is always re-minted, including on an empty log. Prefer a query helper returning `(max ulid.ULID, found bool, error)`, or explicitly treat `env.EventID == ulid.Zero` as invalid/advisory and call `eventid.NewAfter(max)`. Add:

  - `TestInsertEvent_ZeroIDIntoEmptyStoreRemints`
  - An assertion that `LatestEventID` after that append is non-zero
  - The same case to `EventStoreAppendNeverLowersLatestEventID`

- Give `internal/eventid` a test-only isolated generator/state constructor, or structure its internals as a generator value with a package singleton used by production. Then test startup seeding against a genuinely fresh instance. Also assert the ID returned by `eventid.New()` immediately after `Initialize`—before calling `AppendEvent`—is above the persisted maximum, so the append guard cannot mask a missing seed.

- Add a focused benchmark for `AppendEventsBatch` with representative batch sizes, such as 1, 100, 1,000, and 10,000 events. It need not be a CI threshold initially; recording before/after timings in the summary is sufficient.

- Correct plan 01’s final `<done>` text, which still says the change ID names the “exact server state.” The revised mechanism and the rest of the plan correctly describe it as a lower bound.

### Codex — Risk Assessment

**MEDIUM.** The central concurrency design is correct and materially stronger than round 3: immediate transactions plus a guard in the single insert funnel close reverse commit ordering and arbitrary caller IDs without changing D-18’s ULID contract. The zero-ULID empty-store collision is a genuine TMPL-08 correctness hole, however, and should be fixed before execution. Once that case and the restart-test isolation are addressed, the plan set should be considered low risk and converged.

---

## pi Review

### pi — Summary

The round-4 change set is small and well-targeted: plan 09 replaces the round-2 "shared monotonic generator" claim with an in-transaction ordering guard at `insertEvent`, plus `eventid.Seed(LatestEventID)` at `Initialize`. I traced the guard against the actual code and it holds: every production append path (`AppendEvent` :21, `AppendEvents` :55, `AppendEventsBatch` :93, `CompactAggregate` :210) funnels through `insertEvent` (:313) inside a `sqlitex.ImmediateTransaction`, which takes the SQLite write lock up front, so the `MAX(event_id)` re-read cannot race a concurrent commit, and within one transaction it sees the transaction's own earlier inserts (making `AppendEvents`/batch correct). The mint-before-`submitWrite` reordering the user described is real (`internal/server/commands.go:115,119` before `:135`, and the same shape in `UpdateHost`/`DeleteHost`), and the guard is the right fix for it — no process-local generator could close it. `EventID`-as-advisory is safe: no production code reads back a caller-minted `EventID` after append (grep confirms only tests at `storagetest/suite.go:72` and `sqlite_test.go:85`, both of which the plan reroutes through `eventid.New()`). One factual overclaim and a few small items below; nothing blocking.

### pi — Strengths

- The guard placement is verifiably correct, not just plausible: single helper, all four call sites confirmed by reading `eventstore.go`, immediate-transaction semantics make the re-read race-free, and `event_id TEXT PRIMARY KEY` (`migrations/001_initial.sql`) makes both the `MAX` and the lexical-ordering assumption sound.
- The test design is genuinely deterministic: the reverse-commit test uses sequential calls with deliberately inverted IDs rather than goroutine timing luck, and the restart-seeding test uses a future-timestamped seed so it's RED-without-fix by construction rather than probabilistic. The "record the observed RED count out of 50" discipline (review L3) is a good correction to the earlier probabilistic test.
- `RollbackToSnapshot` (`service.go:769-852`) confirmed safe under the new regime: it builds envelopes via `PrepareAddEvent`/`PrepareDeleteEvent` (fresh mints via `newEnvelope`) and commits through `AppendEventsBatch`, so it passes through the guard and D-22's "rollback advances rather than regresses" claim survives.
- Re-mint vs. reject is the right call given no retry loop above `insertEvent`, and the compliance-case disjunction (error OR advance) correctly leaves future backends both options.
- The prohibition against a DB-owned sequence properly engages D-18 rather than relitigating it.

### pi — Concerns

- **MEDIUM — the "single INSERT funnel" claim is factually wrong; there is a second INSERT site the plan never mentions.** `internal/storage/sqlite/legacy_migration.go:183` inserts directly into `events` with preserved Rust-era `e.eventID` values, bypassing `insertEvent` entirely. Today this is safe: it runs inside `Initialize`'s `withConn` body (`sqlite.go:92-98`), i.e. *before* the proposed `eventid.Seed(LatestEventID)` at the end of `Initialize`, so the floor is raised above whatever it inserted; it is one-shot (drops legacy objects, guarded by `legacyMigrationVersion`); and it skips entirely when `events` is non-empty (`legacy_migration.go:43-49`). But plan 09's objective and Task 3 both assert `insertEvent` is "the single INSERT site every append path funnels through", and the acceptance criterion enumerates only the four service paths. If anyone later adds a funnel-count gate analogous to plan 06's notify-count gate, or reasons from the plan text, this site will surprise them. The plan should name it, state why it's safe (pre-seed, one-shot, idempotent-guarded), and note DEBT-01 will eventually remove it. There is also a residual edge it papers over: preserved Rust-era IDs with timestamps far in the future would pin `MAX(event_id)` — the seeding makes this harmless for new mints, which is exactly why the seeding order matters and deserves one sentence.
- **LOW — bulk-path guard cost is acknowledged only generically.** T-1-54 admits "one extra SELECT MAX per inserted row" but frames the write path as "operator-driven host mutations and periodic imports". `AppendEventsBatch` is also the rollback path (`service.go:836`): a rollback over N entries issues N indexed `MAX` seeks in one transaction. That's still trivial (PK seek on an open connection), so the cost is acceptable — but the user's specific question was whether the plan acknowledges it, and the acknowledgement exists without naming the batch/import/rollback paths. One clause in T-1-54 would close it.
- **LOW — `metrics_test.go:627` is left to "check, do not assume" but does append through the store.** It constructs an envelope with bare `ulid.Make()`; if the test appends multiple envelopes in one millisecond, the guard may legitimately re-mint one, and whether that breaks the test depends on whether it asserts read-back ID equality. The plan's own substitution discipline (applied to `suite.go` and `sqlite_test.go`) should either be applied there too or the plan should state why it's exempt, rather than delegating to the executor's compiler.

### pi — Suggestions

- Add one paragraph to plan 09 Task 3 documenting `legacy_migration.go:183` as the second INSERT site, its safety argument (runs before seeding, one-shot, skips on non-empty `events`), and its DEBT-01 removal horizon. Adjust the "single INSERT funnel" phrasing to "the single funnel for all post-migration appends".
- Amend T-1-54 to name the bulk paths explicitly: "`AppendEventsBatch` (import, rollback) pays one indexed `MAX` seek per event; at realistic batch sizes this is bounded by the write transaction it already holds."
- Decide `metrics_test.go:627` in the plan: either include it in the `ulid.Make()` → `eventid.New()` substitution set, or assert (after one read) that it never appends through a guarded path.

Nothing else of substance. The other round-3 revision items (compaction notify with the `EventsBefore > EventsAfter` guard — correctly a no-op on the `len(events) <= 1` early return at `eventstore.go:226-231`; the call-expression-scoped count-of-2 gate; `testEnv` retaining construction inputs; `Flags().Changed` precedence; `tickerDone`) all check out against the code they reference and I have no new findings on them.

### pi — Risk Assessment

**LOW.** The one MEDIUM finding is a documentation/claim-accuracy issue, not a correctness defect — the legacy-migration INSERT is safe under the plan's own seeding order, and I verified that order against `sqlite.go:74-115`. The guard mechanism, the advisory-ID contract, and the seeding all trace correctly against the real code, and the determinism of the new regression tests is a genuine improvement over round 3. This round looks like real convergence: the remaining items are one overclaim to correct and two small acknowledgements, not design changes.
