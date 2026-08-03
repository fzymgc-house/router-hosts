# Phase 2: Cursor-Based Lazy Storage Reads - Context

**Gathered:** 2026-08-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Give `storage.HostProjection` a keyset (aggregate-ID) cursor so a read pages
through host entries instead of materializing the whole inventory, wire
`ExportHosts` and `WatchHosts` to it, and prove the memory claim with a
measured benchmark rather than API-shape inspection.

**Requirements:** LAZY-01, LAZY-02 (amended — see D-01), LAZY-03, LAZY-04

**Explicitly NOT in this phase:**

- A materialized or indexed read model for sorted pagination
  (`REQUIREMENTS.md:123`, Out of Scope). A cross-call server-side cache or
  snapshot would reintroduce it by accident
- Generic multi-writer gap detection; exactly-once delivery guarantees
  (both Out of Scope, `REQUIREMENTS.md:124-125`)
- Migrating `CreateSnapshot`, `RollbackToSnapshot`, or the three regeneration
  writers to the cursor (D-04)
- Auto-compaction or any change to compaction policy — ADR `router-hosts-vl8`
  stands; manual compaction remains the remedy for a deep aggregate (D-06)

</domain>

<decisions>
## Implementation Decisions

### Requirement Accuracy (the premise correction)

- **D-01:** LAZY-02 and ROADMAP SC2 assert that peak memory "no longer scales
  with **total event-log size**". That claim was **already true before this
  phase began** and no benchmark can show it improving. `ListAll`
  (`internal/storage/sqlite/projection.go:19-45`) loops aggregate-by-aggregate,
  reassigning `events` each iteration, and `replayEvents` (`:154`) returns a
  single `*domain.HostEntry` retaining no reference to that slice — so the
  server has never held every aggregate's event log simultaneously. Actual peak
  is `O(aggregate IDs) + O(live HostEntry values) + O(one deepest aggregate's
  history)`. **The wording is amended to total entry count**, which is what the
  cursor genuinely bounds. Routed through the GSD verb surface with the user's
  sign-off per rule `01ygyqn0by` — no agent hand-edits `REQUIREMENTS.md`.
  Precedent is exact: TMPL-06 was publicly amended on 2026-07-31 for the same
  overreach. — **Reversibility:** one-way — the amended text becomes the
  public record of what this milestone claimed; reverting means retracting a
  published requirement a second time.

- **D-01a:** A second roadmap inaccuracy, corrected here so no downstream agent
  plans around it: the ROADMAP states that `ExportHosts`' `hosts` **and `json`**
  formats sort globally by IP-then-hostname. **`json` does not sort.**
  `service.go:702-727` builds `out` with a plain `for i, e := range entries`.
  `csv` (`:728`) does not sort either. The only global sort is
  `hostsfile.go:54` inside `FormatHostsFile`, and it sorts the **caller's slice
  in place**. The highest-risk requirement is therefore narrower than the
  roadmap believed — only `hosts` needs the global sort.

### ExportHosts Format Scope (LAZY-02's hard half)

- **D-02:** The `hosts` format is **descoped**: it drains the cursor to
  completion into a slice, sorts, and renders as today. The residual
  `O(N entries)` is named explicitly in the docs and in the benchmark record
  rather than left as an unstated caveat. `REQUIREMENTS.md:123` already
  sanctions exactly this — "the residual O(N entries) held for the
  `hosts`/`json` IP-then-hostname sort is not 'full event history' and is out of
  scope for v0.14.0".

- **D-03:** `json` and `csv` are **stream-rendered** page by page into a writer
  that flushes at the existing 64 KiB `exportChunkSize` boundary. Today each
  builds `out []jsonEntry` **and** `data []byte` on top of `entries` — three
  full copies of the inventory before `sendExportChunks` (`service.go:663`)
  frames anything. TMPL-06's chunking bounds the **wire**, not the **heap**;
  this is the change that bounds the heap. `csv.Writer` already takes an
  `io.Writer`. **`json` must reproduce `MarshalIndent(out, "", "  ")`'s exact
  two-space layout byte-for-byte or LAZY-04 fails** — that is the single real
  hazard in this decision, and it is pinned by a golden fixture (D-14).
  The empty-payload carve-out in `sendExportChunks` (review L14 — an empty
  inventory still sends exactly one message) MUST survive the rewrite.

- **D-04:** Migration scope is the two named consumers **plus three free wins**:
  - `internal/server/service.go:687` — `ExportHosts` (LAZY-02)
  - `internal/server/watch.go:97` — `sendSnapshot` / `WatchHosts` (LAZY-02).
    Already entry-at-a-time with no sort and no buffering; the easy consumer
  - `internal/server/service.go:200` — materializes every entry solely to call
    `len()` on it for a hook's entry count. A count, not a read
  - `internal/storage/sqlite/projection.go:78` — `FindByIPAndHostname`, and
    `:92` `Search`. Both drain `ListAll` then filter linearly, and both are
    already inside `HostProjection`, so converting them to streaming filters
    adds no new public surface and needs no new requirement

  **Not migrating:** `hostsfile.go:31`, `unboundconf.go:55`, `dnsmasqconf.go:46`
  (all sort globally before writing a whole file — under D-02's own logic they
  would be descoped-and-materialized anyway, so migrating them is churn with no
  measurable win); `service.go:765` `CreateSnapshot` and `:884`
  `RollbackToSnapshot` (need the full set by nature); `commands.go:451`
  (pending Q-04).

### Cursor API Shape and Granularity (LAZY-01, LAZY-03)

- **D-05:** The published interface gains a **stateless keyset page function**,
  shaped roughly
  `ListPage(ctx, after ulid.ULID, limit int) (entries []domain.HostEntry, next ulid.ULID, done bool, err error)`.
  Chosen over a stateful cursor object and over `iter.Seq2` range-over-func
  because LAZY-01 demands "a published interface change, not an internal
  optimization" — a page function is visibly a cursor, the caller owns page
  size, and it is resumable across a gRPC reconnect. The exact signature is
  Claude's discretion within that shape. — **Reversibility:** one-way — this is
  a published interface on `storage.HostProjection`; changing it later breaks
  every implementation and the `storagetest` conformance suite.

  **Accepted consequence:** `withConn` (`sqlite.go:220-227`) takes a connection
  from a 10-connection `sqlitex.Pool` and returns it per call, so consecutive
  pages run on different connections. A cross-page read snapshot is structurally
  unavailable to this shape. That trade is what D-09 documents.

- **D-06:** Pages are **per-aggregate and entry-counted** (a page is N entries).
  `loadEventsForAggregate` + `replayEvents` stay atomic within a single page
  fetch, so a reader can never be observed part-way through one aggregate's
  history — you cannot emit half a `HostEntry`.

  **Therefore LAZY-03's literal scenario ("a cursor sits inside its
  pre-compaction history") is unreachable by construction.** LAZY-03 is
  satisfied by documenting that impossibility **and** pinning the two variants
  that ARE reachable with tests:
  1. Compacting an aggregate the cursor has **not yet reached** → the reader
     sees that aggregate's `HostCompacted`-derived entry at the preserved OCC
     version (ADR `router-hosts-v5b`)
  2. Compacting an aggregate the cursor has **already passed** → invisible to
     this cursor; the reader keeps the pre-compaction value it already emitted

  Event-budgeted pages (ending at N entries *or* M events, whichever first)
  were considered and rejected for this phase: they would bound the one term
  paging leaves unbounded — a single deep aggregate's full history — but they
  complicate both the keyset arithmetic and D-11's asserted bound, and ADR
  `router-hosts-vl8` already names manual compaction as that term's remedy.

- **D-07:** `ListAll` **stays**, reimplemented as a thin drain loop over
  `ListPage`, with a doc comment steering new callers to the cursor. This makes
  the two paths' ordering definitionally identical, which supplies most of
  LAZY-04's byte-identity proof for free — there is only one read path to
  verify. Removing `ListAll` was rejected as contradicting D-04's scoping.

  **Consequence that must not be missed:** because `ListAll` becomes a wrapper,
  D-10's new explicit `ORDER BY` reaches **all seven untouched callers**, not
  just the migrated ones. D-14's golden fixtures must cover them.

- **D-08:** A page **fills to N live entries** — `ListPage` loops internally
  over aggregates until it has N live entries or the store is exhausted. A
  short page means, and only means, `done`. Returning "entries from N scanned
  aggregates" was rejected because it produces an empty-but-not-done page, and
  this repo has already paid for that bug shape once: `sendExportChunks` carries
  an explicit carve-out (review L14) because a naive loop sent zero messages for
  an empty payload and "silently breaks the client's drain loop".

### Mid-Stream Consistency (LAZY-03's neighborhood)

- **D-09:** The contract is **documented precisely rather than strengthened**:
  - Every aggregate present at cursor start is yielded **exactly once**, in
    ascending aggregate-ULID order. Aggregate IDs are immutable, so none is
    skipped or duplicated
  - An aggregate **created mid-read** sorts ahead of the cursor (ULIDs are
    time-ordered) and will normally be included. State this honestly: plain
    `ulid.Make()` gives no intra-millisecond monotonicity, so an aggregate
    created in the same millisecond the cursor sits on may land either side
  - An entry's **value** reflects the instant its page was fetched, not a
    single global instant. This is the real weakness — set membership is
    strong, value freshness is not

  This is continuous with the contract already chosen elsewhere: TMPL-08
  deliberately derives the change ID **before** the read so it is a **lower**
  bound on what was sent (`watch.go:84-95`), and the atomic
  `{entries, latestEventID}` read is already deferred as GitHub issue #401.
  Fencing with `LatestEventID` and holding a read snapshot were both considered;
  the latter would require reversing D-05.

- **D-10:** The keyset forces an explicit `ORDER BY aggregate_id` replacing
  today's bare `SELECT DISTINCT aggregate_id FROM events`
  (`projection.go:318`, no `ORDER BY`). Ascending aggregate-ULID order becomes a
  **documented contract** on `HostProjection`, pinned by a test. **Before
  landing, verify empirically that it matches today's de-facto order** — if
  SQLite's `DISTINCT` temp B-tree already yields ascending TEXT order, then
  `json`/`csv` output is unchanged and LAZY-04 is satisfied by measurement. If
  it does not match, that is a real byte-identity break and must surface during
  planning, not in review. See Q-01.

### Benchmark Rig and Asserted Bound (LAZY-02)

- **D-11:** The benchmark asserts a **ratio across two fixtures** (~1k and ~10k
  entries): the paged path's peak allocation stays flat within tolerance as
  entry count grows 10×, while the drained path scales roughly linearly. A
  relative assertion survives runner and Go-version differences and states
  D-01's amended claim directly. An absolute ceiling was rejected as a magic
  number someone bumps whenever it goes red.

- **D-12:** The fixture is **mixed-depth with deleted aggregates**: mostly
  shallow aggregates, a deliberate minority with deep histories, and a realistic
  share of deleted ones. The deep aggregates exercise the one term paging does
  not bound (D-06); the deleted ones exercise D-08's fill-to-N loop. These are
  the two places the design is weakest, and a benchmark that avoids its own weak
  spots proves little.

- **D-13:** The benchmark lives behind its **own build tag with its own CI job**
  folded into `ci-go-complete`, mirroring the tier pattern Phase 1 established.
  The deciding argument is technical: `task test` runs with `-race`, which both
  makes a 10k fixture slow and perturbs allocation accounting — the exact
  quantity being measured. **Proven RED on a Linux runner before acceptance**,
  per Phase 1 D-16 (any gate this phase writes must itself be demonstrated red)
  and memory `cq0rfk0qjc` (a green run on macOS proves nothing about Linux CI).

- **D-14:** LAZY-04 is proven by **golden fixtures captured before any behavior
  change**, in the phase's first plan, covering every rendered surface:
  - `ExportHosts`' `hosts`, `json`, and `csv`
  - the client-side v0.13.0 consumer-template rendering
  - the three regeneration writers — `hostsfile.go`, `unboundconf.go`,
    `dnsmasqconf.go` — because D-07's wrapper puts them downstream of D-10's
    new ordering even though they do not migrate

  Every later plan must keep them green. The goldens are the proof artifact,
  not a claim about one.

### Claude's Discretion

- The exact `ListPage` signature and option surface within D-05's shape
- Default page size, and whether it is a constant, a package var (the
  `renderDrainLimit` / `MaxTrackedSinks` precedent), or caller-only
- Whether the deleted-aggregate filter runs in SQL or in Go after replay (see
  Q-03) — an optimization, not a contract change
- The streaming writer's internal shape for D-03, provided the 64 KiB boundary
  and the empty-payload single-message behavior are preserved
- Build-tag name, runner profile, and timeout for D-13's job
- Whether `SnapshotComplete.Count` accumulates during paging or is derived —
  it has always meant "entries sent", and paging does not change that

</decisions>

<open_questions>
## Open Questions for Research

These are NOT decided. `gsd-phase-researcher` must resolve them.

- **Q-01 (blocks D-10):** Does `SELECT DISTINCT aggregate_id FROM events`
  currently return rows in ascending TEXT order in practice? Adding
  `ORDER BY aggregate_id` must be proven to preserve today's `json`/`csv` byte
  output, not assumed to. Per memory `b9gbp3bp20`, this is settled by execution,
  never by reading the query.

- **Q-02 (constrains D-09):** Does `sqlitex.NewPool` (`sqlite.go:42`,
  `PoolSize: 10`) open connections in WAL mode? No explicit `journal_mode`
  pragma appears in the non-test source. If WAL is active, a single-connection
  read transaction would give a true snapshot — which does not change D-05 but
  does change how D-09's contract should be worded, and whether a future
  strengthening is cheap.

- **Q-03 (informs Claude's discretion):** Can deleted aggregates be excluded
  **before** replay rather than after? `ListAll` currently loads and replays a
  deleted aggregate's full history only to discard the result. The deleted state
  is knowable from the latest event type, except for `HostCompacted` where it
  lives inside the JSON blob's `Deleted` flag. Partial exclusion may be
  possible; quantify the win before adding JSON introspection to a hot query.

- **Q-04 (blocks D-04's final scope):** What does `internal/server/commands.go:451`
  do with its `ListAll` result, and does D-10's ordering change affect it? It
  was the one call site not classified during discussion.

- **Q-05 (blocks D-03):** Can `json.MarshalIndent(out, "", "  ")`'s exact byte
  layout be reproduced by streaming per-element encoding with manual
  `[` / `,` / `]` framing — including the trailing-newline and empty-array
  cases? If not exactly reproducible, D-03's json half must fall back to
  buffered rendering and that residual must be named alongside D-02's.

- **Q-06 (informs D-11):** `testing.AllocsPerRun` versus `runtime.MemStats`
  deltas — which yields a more stable ratio across runners for this workload?
  What tolerance makes D-11's assertion honest without making it flaky?

</open_questions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Planning Artifacts

- `.planning/ROADMAP.md` § "Phase 2: Cursor-Based Lazy Storage Reads" — goal,
  the four success criteria, the highest-risk-requirement note on LAZY-02, and
  the explicit out-of-scope list. **Read D-01 and D-01a here first — two of the
  claims in that section are factually wrong about the current code**
- `.planning/REQUIREMENTS.md` lines 96–99 (LAZY-01…04), line 69 (TMPL-06 and
  its 2026-07-31 amendment — the precedent for D-01), lines 114–128 (Out of
  Scope, especially line 123 which sanctions D-02's residual)
- `.planning/STATE.md` § "Pending Todos" — the two Phase 2 items this
  discussion resolves (ExportHosts format scope → D-02/D-03; memory
  measurement rig → D-11/D-12/D-13)
- `.planning/PROJECT.md` § Locked Decisions — ADR `router-hosts-v5b`
  (`HostCompacted` seed at the preserved OCC version; D-06's target) and ADR
  `router-hosts-vl8` (manual compaction only; the named remedy for a deep
  aggregate)
- `.planning/phases/01-ci-gating-for-the-e2e-tiers/01-CONTEXT.md` — D-16 (a
  gate must be demonstrated RED before acceptance; governs D-13) and D-01/D-02
  (`ci-go-complete`'s `needs:` list and `!= "success"` comparison style, which
  D-13's job must follow)

### Storage Layer

- `internal/storage/storage.go:120-126` — the `HostProjection` interface
  LAZY-01 changes; `:141-150` — the deliberate CQRS read/write merge whose
  reasoning constrains any read-model temptation
- `internal/storage/sqlite/projection.go:19-45` — `ListAll`, the subject of
  D-01's correction; `:154` `replayEvents`; `:315-333`
  `getDistinctAggregateIDs` (the missing `ORDER BY`, D-10); `:336`
  `loadEventsForAggregate`; `:78` / `:92` (D-04's free wins)
- `internal/storage/sqlite/sqlite.go:42` `sqlitex.NewPool` / `:220-227`
  `withConn` — the per-call connection checkout behind D-05's accepted
  consequence and Q-02
- `internal/storage/storagetest/suite.go:550`, `:601`, `:879`, `:885` — the
  cross-backend conformance suite. Any `HostProjection` change must be
  reflected here, and it is also the precedent (memory `wrqshqtem4`) that a
  non-`_test.go` importable package may import `testing`

### Server / RPC Layer

- `internal/server/service.go:646-677` `sendExportChunks` and its 64 KiB
  `exportChunkSize` plus the review-L14 empty-payload carve-out D-03 must
  preserve; `:680-757` `ExportHosts` and its three format branches
- `internal/server/watch.go:84-137` `sendSnapshot` — already entry-at-a-time,
  and the TMPL-08 change-ID-before-read ordering (memory `6dv0kv09kh`) that
  D-09's contract wording builds on
- `internal/server/hostsfile.go:45-89` `FormatHostsFile` — the only global
  sort (`:54`), and note it sorts the caller's slice **in place**

### Project Conventions

- `CLAUDE.md` — `task` over direct `go` invocations; conventional commit types
  and scopes (`storage`, `server`, `test`); ≥80% coverage gate; `samber/oops`
  for wrapped errors; `pgregory.net/rapid` for property-based testing
- `.planning/codebase/TESTING.md` and `docs/contributing/testing.md` — testing
  strategy; the latter may need updating for D-13's new build tag
- `docs/contributing/architecture.md` — where D-09's consistency contract and
  D-10's ordering contract should be written down for operators

### Related Issues

- GitHub issue **#401** — the deferred atomic `{entries, latestEventID}`
  single-transaction read. D-09 is adjacent to it; planning should decide
  whether this work updates, references, or leaves it untouched

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`sendExportChunks` (`service.go:663`)** — the 64 KiB framing D-03 streams
  into already exists, along with its narrow `exportChunkSender` interface for
  testing against a fake. D-03 extends this rather than inventing new framing
- **`storagetest` conformance suite (`storagetest/suite.go`)** — an importable,
  untagged package that already asserts `HostProjection` behavior across
  backends. The natural home for a cursor conformance test
- **`WatchHosts` is already the easy consumer** — `sendSnapshot`
  (`watch.go:102-110`) sends one message per entry with no sort and no
  buffering. Only its `ListAll` call needs replacing
- **Package-var test seams** — `renderDrainLimit` and `MaxTrackedSinks` are both
  package vars rather than consts specifically so tests can shrink them instead
  of seeding huge fixtures. The established answer to D-12's fixture-size
  tension

### Established Patterns

- **Amend-the-requirement-publicly** — TMPL-06 was amended in place on
  2026-07-31 with the reason recorded inline. D-01 follows that exact shape
- **Negative controls before acceptance** — phase 08's chart RBAC assertions,
  plan 01-11's revert-and-observe, phase 1's four red proofs. D-13 continues it
- **Honest not-run recording** — plans 09-05, 01-08, and 01-05 recorded
  verifications as explicitly NOT-RUN rather than claiming completion
- **Prove by execution, never by grep** — memory `b9gbp3bp20`. Q-01 and Q-05
  are both execution questions

### Integration Points

- `storage.HostProjection` gains `ListPage`; `ListAll` is reimplemented over it
  (D-07), so **every one of the eleven call sites is downstream of the new
  ordering** whether or not it migrates
- `internal/storage/sqlite/projection.go` gains a keyset query; `storagetest`
  gains a conformance test
- `internal/server/service.go` `ExportHosts` gains streaming rendering for two
  of three formats
- `.github/workflows/ci-go.yml` gains one job and an extended `ci-go-complete`
  (D-13), following Phase 1's D-01/D-02 shape exactly
- `Taskfile.yml` gains a target for the new benchmark tier

</code_context>

<specifics>
## Specific Ideas

- **The premise correction is the most load-bearing output of this discussion.**
  `ListAll` was never O(total event log); it is O(total entries). Any downstream
  agent that plans against the roadmap's original wording will build a benchmark
  that cannot demonstrate what it claims — which is precisely how TMPL-06 ended
  up needing a public amendment. Recorded durably as engram memory
  `q72xvkvmgs`.
- **`json` and `csv` do not sort.** Only `FormatHostsFile` does. This is what
  makes D-03 possible at all, and it contradicts the ROADMAP's own text.
- **The empty-payload carve-out in `sendExportChunks` is load-bearing** and cost
  a review round (L14) to get right. D-03's rewrite must preserve it — an empty
  inventory still sends exactly one message.
- The user's standing position, carried from Phase 1 and reaffirmed by D-01's
  routing: **use GSD for what GSD does.** Artifacts GSD owns are written by
  GSD's verbs. The LAZY-02 amendment goes through the verb surface with
  sign-off, never by hand-editing `REQUIREMENTS.md` (rule `01ygyqn0by`).

</specifics>

<deferred>
## Deferred Ideas

- **Event-budgeted pages** (page ends at N entries *or* M events, whichever
  comes first) — would bound the single remaining unbounded term, a deep
  aggregate's full history. Rejected for this phase under D-06 as complexity
  that ADR `router-hosts-vl8`'s manual compaction already addresses. Revisit if
  a real deployment produces an aggregate deep enough to matter.
- **Two-pass key sort for the `hosts` format** — pass 1 collects only sort keys
  (IP, hostname, aggregate ID), pass 2 re-fetches in sorted order. A genuine
  peak reduction with no index and no materialized read model. Rejected under
  D-02 because the two passes can disagree if a write lands between them, which
  collides with D-09's contract. A candidate follow-up if the `hosts` residual
  ever becomes the binding constraint.
- **Stateful cursor object holding a read snapshot** — the only shape giving
  true cross-page consistency. Rejected under D-05/D-09. Reconsider only
  alongside issue #401's atomic read, since they solve overlapping problems.
- **Strengthening the consistency contract generally** — fencing with
  `LatestEventID` so a caller can detect a torn export. Considered under D-09
  and set aside; it is the cheapest available upgrade if operators report
  inconsistent exports.

</deferred>

---

*Phase: 2-Cursor-Based Lazy Storage Reads*
*Context gathered: 2026-08-03*
