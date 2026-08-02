# Architecture Research — v0.14.0 Verification & Lazy Reads

**Domain:** Integration architecture for three capabilities added to an existing, shipped Go CQRS/event-sourced control plane (router-hosts v0.13.0)
**Researched:** 2026-08-02
**Confidence:** HIGH — every claim below is grounded in the files read (listed in Sources); nothing in this document is inferred from training data about "typical" e2e/CI/cursor patterns without checking this codebase first.

This document does **not** re-derive the existing architecture (CQRS/event-sourcing, single-writer `WriteQueue`, SQLite-only storage, gRPC/mTLS). It answers exactly one question for each of the three v0.14.0 capabilities: how does it integrate with what is already there.

---

## Capability 1 — Wire the three e2e tiers into CI

### Current state (verified)

`.github/workflows/ci-go.yml` has seven jobs today: `lint`, `vuln`, `test`, `build`, `buf-check`, `manifests`, `docs`, aggregated by `ci-go-complete` (`needs: [...]`, `if: always()`, then a bash block that fails if any listed job did not report `success`). The `test` job runs `task test:coverage:ci` — `go test ./internal/...` with a coverage gate — **not** any of the three e2e tiers. `docs/contributing/testing.md` states this explicitly: "None of the three e2e tiers currently run in CI... This is a known limitation... tracked in issue #403."

The three tiers already exist and already pass locally (`.planning/PROJECT.md`: "all three e2e tiers... green as of the v0.13.0 audit"). This capability is **pure CI wiring** — no source code under `internal/` or `e2e/` needs to change; the tests already exist.

Taskfile targets (`Taskfile.yml`):

| Task | Build tag | Dependency | External requirement |
|------|-----------|------------|----------------------|
| `task test:e2e` | `e2e` | none | none (in-process, `bufconn`) |
| `task test:e2e:proc` | `proc_e2e` | `deps: ['build']` | none beyond Go toolchain (real OS processes, loopback only) |
| `task test:e2e:docker` | `docker_e2e` | `deps: ['docker:build']` | Docker daemon (`docker build -t {{.IMAGE_NAME}}:{{.IMAGE_TAG}} .`) |

### Integration points

- `.github/workflows/ci-go.yml` — add three new jobs, structurally identical to the existing `test` job (checkout, `setup-go`, `nscloud-cache-action` with `cache: go`, install `task`, run the target). Name them e.g. `e2e-inprocess`, `e2e-proc`, `e2e-docker`.
- `ci-go-complete`'s `needs:` list and its bash validation block — extend both to include the three new job names, exactly the same pattern already used for `lint`/`vuln`/`test`/`build`/`buf-check`/`manifests`/`docs`.
- No proto, storage, or server code changes.

### Tier ordering, caching, failure isolation

- **Ordering:** none of the four test-shaped jobs (`test`, `e2e-inprocess`, `e2e-proc`, `e2e-docker`) has a `needs:` dependency on another in the current workflow — GitHub Actions runs jobs without a `needs` edge between them in parallel. Do **not** add `needs: [test]` to the new jobs; doing so would serialize them and directly produce the "slow containerized tier kills the fast feedback loop" failure mode the question warns about. Keep all four as independent, parallel jobs; only `ci-go-complete` waits on all of them.
- **Caching:** reuse the existing `namespacelabs/nscloud-cache-action@...` with `cache: go` in each new job, identical to `lint`/`vuln`/`test`/`build`. This gives `e2e-inprocess` and `e2e-proc` the same Go build/module cache warm-start already proven in `test`. `e2e-docker`'s `docker build` step has **no** layer-caching mechanism anywhere in the current workflow (no `docker/build-push-action`, no BuildKit cache export) — every `docker_e2e` CI run will rebuild the image from scratch. This is the one caching gap worth flagging explicitly to the roadmapper, not assumed away.
- **Failure isolation:** because the four jobs are already parallel and already independent, isolation is structural, not something to design — a failing/slow `e2e-docker` job blocks `ci-go-complete` (which is correct: it should gate merge) but does **not** delay when `lint`, `test`, `e2e-inprocess`, or `e2e-proc` report their results back to the PR. Reviewers get fast signal from the cheap jobs regardless of Docker job duration.
- **Runner note (flagged, not asserted as fact):** all existing jobs run on `namespace-profile-linux-amd64-*` (Namespace Cloud runners). Whether these runners have a Docker daemon available out of the box was not verified by reading any file in this repo — confirm this during implementation rather than assuming it; if not available, `e2e-docker` needs a `docker:dind`-style service or a different runner profile.
- **Runtime budget (grounded, not estimated):** `Taskfile.yml` sets `-timeout 5m` on both `test:e2e:docker` and `test:e2e:proc`; `test:e2e` has no explicit timeout override. Existing `test`/`build`/`lint` jobs carry `timeout-minutes: 10–15` at the workflow level — the new jobs should get comparable per-job timeouts (`docker_e2e` realistically needs more than 10 minutes once image build time is added on top of the 5-minute test timeout).

### New vs modified

| Component | New / Modified | Notes |
|---|---|---|
| `.github/workflows/ci-go.yml` | Modified | Three new jobs + `ci-go-complete` `needs`/bash-check extension |
| `Taskfile.yml` | Unmodified | Targets already exist |
| `e2e/*_test.go` | Unmodified | Tests already exist and pass |

---

## Capability 2 — Containerized deployment-verification harness (unbound + two sinks)

### Current state (verified)

Three things already exist that this capability must relate to:

1. **`docker_e2e` tier** (`e2e/docker_e2e_test.go`): drives a **single** `router-hosts` server container via `os/exec` + `docker run`/`docker build` directly (no compose), with the gRPC **client still in-process** in the test binary. It proves the shipped Docker image runs the server correctly. It does not start a second container of any kind.
2. **`proc_e2e` tier** (`e2e/proc_harness_test.go`, documented in `docs/contributing/testing.md` under "Deferred: containerized two-node verification"): real OS processes on **both** sides of mTLS, including a real sink process (`startSinkProcess`, `router-hosts watch`). This is the tier the testing doc explicitly names as the one to extend, and it lists the concrete reasons the harness was built extensibly:
   - PKI is already N-party (`issueClientCert` takes a CN parameter; sink health is keyed by CN in `internal/server/watch.go`'s `sinkHealth.RecordStatus`).
   - Config generation is transport-agnostic (`writeServerConfigFile`/`writeClientConfigFile` take an address parameter, not hardcoded loopback).
   - Launch is the only container-specific seam (`startServerProcess`/`startSinkProcess` are small, swappable functions).
   - Observation is filesystem-based (`waitForFileContent`/`waitForSidecar` poll by path — a bind-mounted container volume satisfies the same assertion unchanged).
   - Multiple sinks are already expressible (`startSinkProcess` returns an independent handle per call).
3. **`docker-compose.yml`** at repo root is a **user-facing example**, not test infrastructure — it documents a single `router-hosts` service for end users (and has a stale comment referencing "DuckDB," a Rust-era artifact predating the Go/SQLite migration; do not treat it as current architecture documentation). It is not wired into any Taskfile target or test.
4. **`examples/templates/unbound.tmpl`** already exists as the Go template a `watch`-mode sink renders against to produce real unbound configuration — this is the artifact format the new harness's sink containers would render, not something to invent.

The blocking gap, per `docs/contributing/testing.md`: UAT test 42 needs "a real unbound host and a second machine," and the doc calls for "a process/container-level harness rather than the current fully in-process e2e suite... worth designing as one harness, not two." `.planning/PROJECT.md`'s Active item repeats this: "the same harness would cover the `proc_e2e` tier's container extension points."

### Does this extend an existing tier, or add a fourth?

**Extend the proc_e2e harness's design, but as a distinct test tier/build tag — not a fourth wholly-new architecture, and not folded into `docker_e2e`.** Grounding for each half of that:

- **Not folded into `docker_e2e`:** `docker_e2e` today is scoped to "does the shipped image run the server correctly" with an in-process client — a single-container concern. A real unbound container plus two sink containers plus cross-container networking plus a resolver-reload assertion is a materially different (and materially slower) thing to prove. Conflating them would make `docker_e2e` itself the "slow containerized tier" the CI question worries about, defeating capability 1's isolation goal.
- **Extends `proc_e2e`'s *design*, not its Go-process *runtime*:** `proc_e2e` proves CLI-flag/config-resolution behavior using real OS processes on loopback. The new harness needs real containers (unbound is not something to fake — the whole point is proving actual resolver behavior) and cross-container networking, which is a different runtime substrate than `os/exec` on one host. But the testing doc is explicit that the *harness design* — N-party PKI, transport-agnostic config generation, a swap-only launch seam, filesystem-based observation, multiple independently-addressable sinks — was built specifically so this new work reuses those patterns rather than rebuilding them. Concretely: `startServerProcess`/`startSinkProcess` are the functions to replace with container-launch equivalents; `issueClientCert`, `writeServerConfigFile`/`writeClientConfigFile`, and `waitForFileContent`/`waitForSidecar` should be reused or lightly adapted, not reinvented.
- **Distinct tier because it needs its own build tag, Taskfile target, and CI job:** a fourth tag (e.g. `convergence_e2e`) keeps this heavy, Docker/compose-dependent, multi-container suite opt-in and separately timed/gated from the three existing tiers, consistent with how `docker_e2e` and `proc_e2e` are already separated from `e2e` by build tag specifically so each tier's cost/value tradeoff is independently controllable.

### New components required

| Component | Purpose |
|---|---|
| Container orchestration definition (compose file or equivalent `os/exec`-driven multi-container launcher in a new `e2e/convergence_harness_test.go`-style file) | Stand up: router-hosts server container, a real unbound container, two sink containers |
| Unbound container image/config | A real resolver — likely an existing public unbound image, configured to load the rendered `unbound.tmpl` output and support a reload mechanism (`unbound-control reload` or SIGHUP) |
| Two sink container definitions | Reuse the **existing** `router-hosts` image (`Dockerfile`'s `ENTRYPOINT ["router-hosts"]`) with `command` overridden to `watch --config ... --template examples/templates/unbound.tmpl ...` per sink — no new binary or image needed, only new container *configuration* (distinct CN per sink cert, distinct output path per sink, matching `sinkHealth`'s CN-keyed model) |
| New build tag + Taskfile target | e.g. `task test:e2e:convergence` behind a `convergence_e2e` tag, mirroring `test:e2e:docker`'s `deps: ['docker:build']` pattern but adding compose/orchestration bring-up |
| New CI job | Wired the same way as capability 1's three jobs, added to `ci-go-complete`'s `needs` list once it exists — sequencing note below |

### Data flow for a two-node convergence assertion

```
mutation (CLI `host add` / RPC, driven by the test)
    → WriteQueue (internal/server/commands.go, single-writer serialization)
    → SQLite event append (internal/storage/sqlite/eventstore.go)
    → s.changes.Notify() (internal/server/changenotify.go, called from
       internal/server/service.go:162 and :1079 — the write path's own
       change-signal, unchanged by this capability)
    → BOTH sink containers' WatchHosts follow-mode streams wake
       (internal/server/watch.go: watchFollowSend, one goroutine per
       connected sink, each independently subscribed)
    → server calls sendSnapshot for EACH sink independently:
        - LatestEventID() read FIRST (the change ID, D-21 lower-bound
          ordering — see Capability 3 for why this order is load-bearing)
        - then store.ListAll(), streamed as per-entry WatchHostsResponse
          messages, terminated by SnapshotComplete{ChangeId: <that ID>}
    → each sink container template-renders its own unbound.conf artifact
      (atomic write, per docs/contributing/architecture.md's temp-file-
      plus-rename pattern) and runs its own post-render reload hook
      against ITS unbound container (D-12a: write success and reload
      success are independent outcomes — a reload failure retains the
      new artifact rather than rolling back)
    → convergence oracle (test assertions), TWO independent legs:
        (a) artifact/sidecar leg — poll each sink's sidecar file for
            rendered_change_id == the change ID captured at mutation
            time (this is exactly what proc_e2e's
            TestProcE2E_ChangeIDPropagatesToSidecar already asserts for
            ONE sink; this harness is that same assertion run against
            TWO independently-CN'd sinks concurrently)
        (b) resolver leg — query the real unbound container (dig/getent
            against its exposed port) to prove the reload actually took
            effect on the resolver process itself, not just that a file
            on disk changed
```

### Where the change-ID mechanism fits as the convergence oracle

The change ID (`LatestEventID`, `storage.ZeroChangeID`, `contract.TemplateVersion`'s sibling concept) is already the mechanism the codebase uses for exactly this purpose — this harness does not need a new "did it converge" primitive, it needs to **apply the existing one across two independent sinks and add a second, resolver-level leg on top of it**:

- `internal/storage/storage.go`'s `LatestEventID` doc comment and `internal/server/watch.go`'s `sendSnapshot` doc comment both describe the ID as a **lower bound**, deliberately (D-21: derived strictly before `ListAll`, so a mutation landing in the read window is never mislabeled as already-applied — see Capability 3 for the exact ordering hazard this protects against). A convergence harness must treat "sink's `rendered_change_id` == the ID recorded at the moment of the test's mutation" as sufficient proof for the artifact leg, consistent with how `TestProcE2E_ChangeIDPropagatesToSidecar` already uses it for a single sink.
- The ID is explicitly **not** a per-consumer resume token (`sinkStateFromStatus`'s doc comment: "a server-side skip is the forbidden half" of the optimization) — the harness must not use it to decide what the server sends, only to observe what a sink has rendered.
- Because write success and reload success are independent (D-12a), the change-ID check alone proves the **sink rendered the right content**; it does **not** prove unbound picked it up. That is why the resolver-level leg (querying the real unbound container) is a second, necessary assertion, not a redundant one — this is the actual gap UAT test 42 is blocked on, and the reason a container harness (real unbound) is required at all rather than another filesystem-only assertion.

### Relationship to Capability 3 (cursor-based reads)

None of this harness's data flow depends on how `store.ListAll` is implemented internally — `sendSnapshot` calls it once per sink per mutation regardless of whether that call is a full in-memory replay (today) or cursor-paginated (Capability 3). The wire messages, the change-ID ordering, and the convergence assertions above are unaffected either way. This is elaborated under Build Order below.

### New vs modified

| Component | New / Modified | Notes |
|---|---|---|
| New compose/orchestration definition + Dockerfile config for sink command overrides | New | Reuses existing `router-hosts` image; only container *configuration* is new |
| Unbound container definition | New | Real resolver, likely a public image |
| `e2e/convergence_harness_test.go` (or similar) + new build tag | New | Reuses `proc_e2e`'s helper *patterns* (PKI, config-as-data, filesystem observation); does not import `proc_e2e`'s in-process/OS-process launch functions directly — those get container-launch equivalents |
| `Taskfile.yml` | Modified | New `test:e2e:convergence`-style target |
| `.github/workflows/ci-go.yml` | Modified | New job, added after Capability 1's pattern is established |
| `internal/server/*`, `internal/storage/*` | Unmodified | This capability exercises existing WatchHosts/changeNotifier/sendSnapshot behavior; it does not require server-side code changes |

---

## Capability 3 — Cursor-based method on `storage.HostProjection`

### Current state (verified)

`internal/storage/storage.go`'s `HostProjection` interface (lines 120–126):

```go
type HostProjection interface {
    ListAll(ctx context.Context) ([]domain.HostEntry, error)
    GetByID(ctx context.Context, id ulid.ULID) (*domain.HostEntry, error)
    FindByIPAndHostname(ctx context.Context, ip, hostname string) (*domain.HostEntry, error)
    Search(ctx context.Context, filter domain.SearchFilter) ([]domain.HostEntry, error)
    GetAtTime(ctx context.Context, at time.Time) ([]domain.HostEntry, error)
}
```

`internal/storage/sqlite/projection.go`'s `ListAll` (the only implementation): `getDistinctAggregateIDs` (`SELECT DISTINCT aggregate_id FROM events`, no `ORDER BY`) then, per aggregate ID, `loadEventsForAggregate` (`SELECT ... WHERE aggregate_id = ? ORDER BY event_version ASC`, using the existing `idx_events_aggregate(aggregate_id, event_version)` index) then `replayEvents` to fold that aggregate's full event history into one `domain.HostEntry`. **Every** call materializes every aggregate's full event log in memory, for every call, with no cache and no materialized read model — this matches the milestone context exactly.

`events` table: `event_id TEXT PRIMARY KEY` (confirmed in `internal/storage/sqlite/eventstore.go`'s `selectLatestEventID` comment: "TEXT PRIMARY KEY..., so this is an indexed seek"), plus `idx_events_aggregate(aggregate_id, event_version)` and `idx_events_created_at(created_at)` (confirmed in `internal/storage/sqlite/snapshot_schema_migration_test.go`'s schema). There is **no** existing index or query ordering aggregate IDs globally — `getDistinctAggregateIDs` has no `ORDER BY` today.

Two callers of `ListAll` matter most for this capability:

- **`WatchHosts`'s `sendSnapshot`** (`internal/server/watch.go`): calls `store.LatestEventID(ctx)` **strictly before** `store.ListAll(ctx)` — this ordering is called out at length in the code as load-bearing (D-21/H1: the change ID must be a *lower bound* on the entry set, never an upper bound, or a client-side dedupe permanently strands a consumer on stale state). Entries are streamed to the client **unsorted**, one `WatchHostsResponse_Entry` per entry, terminated by one `SnapshotComplete{ChangeId, Count, ContractVersion}`. `watchFollowSend` calls `sendSnapshot` again on **every** `changeNotifier` wake — i.e., every mutation triggers a fresh full `ListAll` for every connected follow-mode sink.
- **`ExportHosts`** (`internal/server/service.go`): calls `store.ListAll(ctx)` once, then **fully formats** the result into one in-memory `[]byte` (three branches: `hosts` via `HostsFileGenerator.FormatHostsFile`, `json` via `json.MarshalIndent` on the whole slice, `csv` via a buffered `csv.Writer`), and only **then** frames that already-complete blob into `exportChunkSize = 64 * 1024`-byte windows via `sendExportChunks`. The 64 KiB framing is a post-hoc chunking of a fully materialized document, not a per-entry stream.

Critically, `FormatHostsFile` (`internal/server/hostsfile.go`) **sorts** the full entry slice by IP then hostname before rendering (`sort.Slice(entries, ...)`) — this is a **global** sort over the whole inventory, not a per-page operation.

### Minimal correct signature

Additive, not a replacement — `ListAll` must stay (see "What must not change," below, for why). Add one new method to `HostProjection`:

```go
// ListPage returns up to limit host entries in a stable, forward-only order,
// plus an opaque cursor to resume after the last entry returned. An empty
// nextCursor means there is no further page. cursor is the empty string to
// start from the beginning.
ListPage(ctx context.Context, cursor string, limit int) (entries []domain.HostEntry, nextCursor string, err error)
```

Cursor should be the last-returned aggregate ID's ULID string form, not an event ID or a row offset — reasoning below. Implementation shape in `internal/storage/sqlite/projection.go`: replace `getDistinctAggregateIDs`'s unordered `SELECT DISTINCT aggregate_id FROM events` with `SELECT DISTINCT aggregate_id FROM events WHERE aggregate_id > ? ORDER BY aggregate_id LIMIT ?`, then run the exact same per-aggregate `loadEventsForAggregate` + `replayEvents` loop as `ListAll` already does for the aggregates in that page. `aggregate_id` is the leading column of the existing `idx_events_aggregate` index, so this should be a usable range scan — confirm with `EXPLAIN QUERY PLAN` during implementation rather than assuming it; this document does not claim to have measured it.

### Interaction (a): events table ordering

ULIDs sort lexically in creation order, so `ORDER BY aggregate_id` over `DISTINCT aggregate_id` gives a **stable, deterministic, resumable** pagination order that has nothing to do with `event_version` (which only orders events *within* one aggregate, via `idx_events_aggregate`). The two orderings are orthogonal and don't conflict: cursor pagination walks aggregates in aggregate-ID order; within each aggregate, event replay still walks `event_version` order exactly as `loadEventsForAggregate` does today. No change to that inner loop is needed.

### Interaction (b): compaction rewriting an aggregate's history mid-stream

`CompactAggregate` (ADR `router-hosts-v5b`, `internal/storage/sqlite/eventstore.go`) atomically deletes all of one aggregate's events and inserts a single `HostCompacted` seed event **at the same `aggregate_id`**, preserving the high-water `event_version`. Because the cursor is keyed on `aggregate_id` (not `event_id` or a row offset), this is compaction-safe by construction:

- If compaction lands on an aggregate the cursor has **already passed**, the already-sent page is unaffected — this is the same eventual-consistency envelope `ListAll` already has today (no snapshot isolation across the whole scan).
- If compaction lands on an aggregate **not yet reached**, the next page's `loadEventsForAggregate` call re-reads fresh from the table and simply sees the already-folded `HostCompacted` event when it gets there — `replayEvents`'s existing `case domain.HostCompacted` branch handles this identically to how `ListAll` handles it today.
- No aggregate can be skipped or duplicated by a compaction racing the cursor scan, because compaction never changes an aggregate's `aggregate_id`, only its event content — the pagination key is untouched by the very operation the question is worried about.

### Interaction (c): 64 KiB framing and `changeNotifier` fan-out

This is the integration point most likely to be under-scoped if treated as "swap `ListAll` for `ListPage` and done." Grounded findings:

- **`WatchHosts`/`sendSnapshot` benefits fully and directly.** Entries are already sent unsorted, one at a time, as individual proto messages — a cursor loop inside `sendSnapshot` (call `ListPage` repeatedly until `nextCursor == ""`, sending each page's entries exactly as today) is a drop-in internal change. No proto shape, no `SnapshotComplete` semantics, no `changeNotifier` behavior needs to change. The `LatestEventID`-before-`ListAll` (now `ListPage`-loop) ordering must be preserved exactly — that D-21 invariant applies regardless of how the read is chunked internally, since it protects against a mutation landing *during* the read window, and a paginated read has a **longer** window than a single `ListAll` call, making this ordering guarantee more important to preserve carefully here, not less.
- **`ExportHosts`'s `hosts` and `json` formats do NOT get "for free" laziness from this interface change alone.** `FormatHostsFile` requires a **global sort** over the entire entry set before any output is written; `json.MarshalIndent` in the current code also operates on the whole slice at once. Cursor-paginating the *read* does not remove the need to buffer the *whole* set before that sort/marshal step, unless the milestone also accepts either (a) sorted-at-the-storage-layer pagination (a bigger change, likely out of scope for "add a cursor method to the interface"), or (b) dropping the global sort guarantee for the `hosts`/`json` export formats. This is the single most important scoping flag for whoever plans this phase: the interface change is **necessary** for the milestone's stated goal but **not sufficient**, on its own, to make `ExportHosts`'s `hosts`/`json` branches stream without full materialization. The `csv` branch is the one export format that could plausibly stream row-by-row today, since nothing in the current CSV code sorts.
- **The 64 KiB `exportChunkSize` wire framing is untouched either way.** `sendExportChunks` frames whatever `[]byte` it is handed; whether that `[]byte` was built from one `ListAll` call or assembled incrementally from several `ListPage` calls is invisible to it. No change to `exportChunkSize`, `sendExportChunks`, or the `ExportHostsResponse` proto shape is implied by this capability.
- **`changeNotifier` fan-out is unaffected.** `s.changes.Notify()`'s call sites (`internal/server/service.go:162`, `:1079`) and `watchFollowSend`'s subscribe-then-send loop don't know or care how `sendSnapshot` reads storage internally — the fan-out primitive wakes subscribers; what each subscriber does inside its own `sendSnapshot` call is orthogonal.

### What must NOT change (wire contract)

Given TMPL-01..08 shipped and consumers depend on the versioned template data contract (`contract.TemplateVersion`, `internal/contract`):

- **No proto message changes** — `WatchHostsResponse`, `SnapshotComplete`, `ExportHostsResponse` all stay exactly as they are. `ListPage` is a storage-interface addition consumed entirely inside `internal/server`; it never crosses the gRPC boundary as a distinct concept (no "give me a cursor" RPC parameter is implied by this capability, and none should be added — the wire-level pagination-vs-not question is separate from the storage-level one and out of scope here).
- **No change to the change-ID semantics** (D-18/D-20/D-21: ULID of the newest event, derived before the read, string-equality comparison, `ZeroChangeID` sentinel for an empty log) — this capability touches how the *entries* are read, never how the *change ID* is computed (`LatestEventID` is a separate `EventStore` method, untouched by this capability).
- **No change to `TemplateContractVersion`/`contract.TemplateVersion`** — the data fields a template sees per entry are unaffected; only the server-internal fetch path for those entries changes.
- **`ListAll` itself must not be removed** — `CreateSnapshot`, `RollbackToSnapshot`'s `currentEntries` computation, `FindByIPAndHostname`, and `Search` (per `internal/storage/sqlite/projection.go`) all call `ListAll` and all have correctness requirements (exact-match snapshotting, full-batch rollback, linear scan) that a paginated cursor does not obviously simplify and that are explicitly out of this milestone's stated scope (only `ExportHosts`/`WatchHosts` are named). Treat `ListPage` as additive.

### New vs modified

| Component | New / Modified | Notes |
|---|---|---|
| `internal/storage/storage.go` (`HostProjection` interface) | Modified | Add `ListPage`; `ListAll` and the other four methods unchanged |
| `internal/storage/sqlite/projection.go` | Modified | New `ListPage` implementation; `getDistinctAggregateIDs` gains an ordered/paginated variant (existing unordered one can stay for `ListAll`'s use, or be reused with `cursor=""`/`limit=∞` — an implementation choice, not an architectural one) |
| `internal/server/watch.go` (`sendSnapshot`) | Modified | Internal loop over `ListPage` instead of one `ListAll` call; change-ID-before-read ordering preserved |
| `internal/server/service.go` (`ExportHosts`) | Modified, **scope-limited** | `csv` branch can plausibly stream via `ListPage`; `hosts`/`json` branches need either a design decision to drop the global sort guarantee or a separate follow-up, per the "Interaction (c)" finding above — flag to the roadmapper rather than assume it's in scope |
| Proto definitions (`api/v1`) | Unmodified | No wire contract change |
| `internal/contract` | Unmodified | No template contract version bump |
| Any mock/fake `storage.Storage` implementations used in tests | Modified | Must implement the new interface method — check `internal/server/*_test.go` and `e2e/` fakes for compile breaks when the interface grows |

---

## Cross-cutting: are these three independent?

**Capability 1 (CI wiring) is independent of both 2 and 3.** It wires existing, passing tests; it requires no source changes in `internal/` or `e2e/`.

**Capability 3 (cursor) is independent of both 1 and 2 in terms of hard dependencies** — it is a self-contained storage/server change (`internal/storage/storage.go`, `internal/storage/sqlite/projection.go`, `internal/server/watch.go`, `internal/server/service.go`). It does not require the new CI jobs or the new harness to exist.

**Capability 2 (containerized harness) is independent of Capability 3's internals** — its data-flow assertions (change-ID-in-sidecar, resolver-level convergence) hold regardless of whether `sendSnapshot` reads via `ListAll` or `ListPage`, because the wire contract Capability 3 is constrained not to change is exactly what Capability 2 observes.

None of the three has a **hard** build dependency on another. The dependencies below are sequencing recommendations grounded in risk and rework avoidance, not architectural necessities.

## Suggested build order

1. **Capability 1 first (CI wiring for the three existing tiers).** Zero source-code risk, closes issue #403 immediately, and establishes the `ci-go-complete` extension pattern (add job → add to `needs` → add to bash check) that Capability 2's new tier will reuse. Doing this first also means Capability 3's changes (next) land under e2e coverage from day one — directly addressing the failure mode `docs/contributing/testing.md` documents (gap G-01-1: a CLI-flag defect shipped through a full phase of green e2e runs because no tier ran in CI).

2. **Capability 3 next (cursor-based `HostProjection` read).** Self-contained, now protected by the e2e tiers Capability 1 just wired in — a `WatchHosts`/`ExportHosts` regression introduced by the pagination refactor gets caught by CI rather than repeating the historical near-miss. Doing this before Capability 2 also means the new containerized harness (next) exercises the **final** shape of `sendSnapshot`/`ExportHosts`, not a version that changes again immediately after the harness is built and tuned against it.

3. **Capability 2 last (containerized deployment-verification harness).** The highest-effort item — new container/compose infrastructure, a real unbound container, a new build tag, a new CI job — and the one most naturally suited to build last: it validates end-state behavior (UAT test 42, the four deferred manual deployment checks) against the already-CI-gated, already-cursor-refactored server rather than a moving target. It also reuses the CI-job-wiring pattern Capability 1 established, so its own CI integration is mechanical once step 1 is done.

**If parallelizing across workstreams instead of sequencing:** Capabilities 2 and 3 touch disjoint file sets (2: new `e2e/` harness files, new compose/container config, `Taskfile.yml`, `ci-go.yml`; 3: `internal/storage/*`, `internal/server/watch.go`, `internal/server/service.go`) and could run concurrently without merge conflicts. The sequencing argument above is about risk and avoiding rework (harness built against a soon-to-change read path), not about avoiding a file collision.

---

## Sources

- `.planning/PROJECT.md` — milestone scope, ADRs (router-hosts-4w2, -bzg, -v5b, -vl8), Key Decisions (D-21, D-18/D-20, D-12a)
- `internal/storage/storage.go` — `HostProjection`/`EventStore` interfaces, `LatestEventID`/`ZeroChangeID` contracts
- `internal/storage/sqlite/projection.go` — `ListAll`, `GetByID`, `GetAtTime`, `replayEvents`, `getDistinctAggregateIDs`, `loadEventsForAggregate`
- `internal/storage/sqlite/eventstore.go` — `selectLatestEventID` (event_id TEXT PRIMARY KEY), insert-time ordering guard
- `internal/storage/sqlite/snapshot_schema_migration_test.go` — `events` table schema, `idx_events_aggregate`, `idx_events_created_at`
- `internal/server/watch.go` — `WatchHosts`, `sendSnapshot`, `watchFollow`/`watchFollowSend`/`watchFollowRecv`, change-ID ordering rationale
- `internal/server/changenotify.go` — `changeNotifier` fan-out semantics
- `internal/server/service.go` — `ExportHosts`, `sendExportChunks`, `exportChunkSize`, `CreateSnapshot`, `RollbackToSnapshot`
- `internal/server/hostsfile.go` — `FormatHostsFile` (global sort dependency)
- `docs/contributing/architecture.md` — system overview, package structure, atomic-write pattern
- `docs/contributing/testing.md` — three e2e tiers, `proc_e2e` extension seams, "Deferred: containerized two-node verification," CI integration gap
- `.github/workflows/ci-go.yml` — current CI job structure, `ci-go-complete` aggregator
- `Taskfile.yml` — `test:e2e`, `test:e2e:docker`, `test:e2e:proc`, `docker:build` task definitions
- `Dockerfile` — single multi-purpose image (`ENTRYPOINT ["router-hosts"]`, `CMD ["serve", ...]`), reusable for sink containers via command override
- `docker-compose.yml` — confirmed to be a user-facing example only, not test infrastructure (and contains a stale DuckDB reference from the pre-Go-migration era)
- `e2e/docker_e2e_test.go` — confirmed `docker_e2e` drives a single container via direct `docker` invocation, not compose
- `examples/templates/unbound.tmpl` — existing sink-render template target for the new harness

---
*Architecture research for: router-hosts v0.14.0 (Verification & Lazy Reads)*
*Researched: 2026-08-02*
