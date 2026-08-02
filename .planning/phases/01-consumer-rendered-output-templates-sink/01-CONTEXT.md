# Phase 1: Consumer-Rendered Output (templates + sink) - Context

**Gathered:** 2026-07-31
**Status:** Ready for planning

<domain>

## Phase Boundary

A consumer defines its own output format and keeps it current, so one stateful
server feeds N independent consumers and new resolver formats stop requiring an
upstream release.

Delivers TMPL-01 through TMPL-07: template-rendered output (one-shot and as a
continuous sink), a documented and versioned template data contract, fail-loud
rendering, atomic writes, lazy server-side streaming, and a bounded client-side
collection.

**Not in scope:** changes to `unbound_conf_path` (#349) or to the existing
`ExportHosts` format strings (`hosts` / `json` / `csv`). Both keep current
behavior, demonstrated by existing tests still passing.

</domain>

<decisions>

## Implementation Decisions

### Execution site

- **D-01:** Templates execute **client-side**. The server streams structured
  host data over the existing mTLS gRPC channel; the `router-hosts` CLI on each
  consumer renders it through the local template and writes the artifact. The
  server never executes caller-supplied template text. — **Reversibility:**
  one-way — moving execution server-side later means adding a template-execution
  sandbox (timeout, output cap, function allowlist) to a single-writer DNS
  control plane, and any consumer that came to rely on local-only rendering
  would need its trust assumptions revisited.
- **D-02:** One renderer still ships in one binary, which satisfies #364's
  objection to duplicating rendering logic per consumer. The cost accepted is
  that a consumer must run the CLI — acceptable because sink mode already
  implies a long-lived local process.

### Template data contract (TMPL-02)

- **D-03:** The template's top-level value is a **struct with `.Entries` plus
  metadata** (`.Count`, `.GeneratedAt`, `.ContractVersion`, `.ChangeID`), not a
  bare slice. (`.ChangeID` added 2026-07-31 — see D-18. It absorbed as a pure
  metadata addition, which is exactly the forward-compatibility this decision
  was rated one-way to protect.)
  Templates write `{{range .Entries}}`. — **Reversibility:** one-way — with a
  bare slice, `.` is permanently bound to the entry list, so adding any metadata
  field later silently changes what every existing consumer template means.
  Starting with the struct is the only forward-compatible shape.
- **D-04:** Per-entry fields exposed at minimum: `IPAddress`, `Hostname`,
  `Aliases`, `Tags`, `Comment` (per TMPL-02). The exposed field set is an
  explicit, documented contract — deliberately not "whatever the internal struct
  happens to have".
- **D-05:** A template **declares the contract version it targets**, and the CLI
  **refuses to run on mismatch**. This converts a field rename or removal from a
  silent wrong-render into a loud startup error. — **Reversibility:** costly —
  relaxing enforcement later is easy, but tightening it after consumers ship
  undeclared templates would break them all at once.

### Sink stream

- **D-06:** The sink stream carries a **full snapshot, coalesced**. Every change
  produces a complete entry set; rapid bursts collapse into one send. No deltas,
  no resume tokens, no server-side per-stream position. A reconnect is simply
  the next snapshot. Mirrors the coalescing the Phase 9 hook runner already does.
- **D-07:** The watch RPC is **bidirectional** — the sink reports status upstream
  on the same stream it already holds open (see D-09). `ImportHosts` is the
  existing bidi precedent in this proto.
- **D-08:** Client-initiated throughout, per #364: the server holds no
  registration, no retry state, and never needs to reach a consumer.

### Health and staleness

- **D-09:** Sink health is reported **upstream on the existing stream** and
  exposed by the server through its **existing OTel pipeline**, keyed by mTLS
  cert CN. This deliberately avoids standing up an OTel publisher (and collector
  reachability) at every consumer. Metrics include a **last-seen timestamp**,
  which converts stream absence into a measurable age and removes the
  clean-shutdown-vs-crash ambiguity.
- **D-10:** Last-seen state **survives the stream closing** (in-memory, one
  timestamp per CN, lost on server restart). This is a small, deliberate
  departure from #364's "server keeps no per-sink state" — recorded here rather
  than smuggled in. It stays inside the spirit of that constraint because the
  server still never initiates contact, holds no credentials for consumers, and
  carries no retry state. Absence of the metric after a restart correctly means
  "not seen since restart".
- **D-11:** A **local sidecar status file** ships alongside the artifact,
  written atomically, recording last-success timestamp, last error, consecutive
  failure count, and contract version. Rationale is specifically the
  **server-down** case: when the server is unreachable, server-side metrics are
  unavailable by definition while sinks keep serving their last-good artifacts —
  the local file is then the only health signal.
- **D-12:** On a **connection loss, render error, or write error** — every failure
  that occurs *before* the artifact is replaced — the previously written artifact
  is left **byte-identical**. Staleness is surfaced through the marker and
  metrics, never by truncating or removing the artifact. A silently stale but
  structurally valid zone is the 0.10.12 failure mode #364 was filed over.
- **D-12a (amended 2026-07-31, cross-AI review H3):** D-12 does **not** extend to
  a post-write hook failure, and a sink cycle therefore has **three** distinct
  outcomes, not two. The plans originally claimed hook errors also left the
  artifact untouched, which is impossible — by the time the hook runs the
  artifact has already been replaced.

  | Outcome | Artifact on disk | What is actually wrong |
  |---|---|---|
  | Render or write failed | **unchanged** (previous artifact) | New data never reached disk |
  | **Artifact written, hook failed** | **updated and retained** | File is current; the resolver may still be serving the old zone |
  | Connection lost | **unchanged** (previous artifact) | No new data to write; artifact is stale |

  The artifact is **never rolled back after the hook has run.** The hook is a
  resolver reload; on failure it is unknown whether the resolver already read the
  new file, so reverting could leave the on-disk file and the running resolver
  config actively disagreeing — strictly worse than retaining. The middle row is
  the operationally important one and must be distinguishable in both the sidecar
  and the upstream metrics: "your zone file is correct but your resolver did not
  pick it up" is a different page than "your zone file is old".
- **D-13:** Metric label cardinality is bounded by mTLS CN, not by
  consumer-supplied names. This repo already treats cardinality as a design
  constraint (Phase 6's compaction gauges were explicitly cardinality-safe).

### Bounded collection (TMPL-07)

- **D-14:** The client-side collection cap is **configurable with a safe
  default**, applied at every collecting call site. Exceeding it fails with a
  clear error naming the limit and how to raise it — **never** a silent
  truncation. A fixed compiled-in constant was rejected: an unfixable ceiling is
  the same upstream-dependency problem this milestone exists to remove.
- **D-15:** Note the interaction that makes D-14 load-bearing rather than
  theoretical: because `.Count` and `.GeneratedAt` are in the contract (D-03),
  the client must know the whole entry set **before** rendering. Go's
  `text/template` can `{{range}}` a channel, so a purely streaming render is
  possible in principle — but not while also exposing a total count up front.
  Full collection is therefore implied by D-03, and the cap is what bounds it.

### Post-write hook

- **D-16:** Because rendering is client-side (D-01), the Phase 9 server-side
  hook system does **not** fire for a consumer's write. A post-write exec hook
  on the CLI is therefore in scope as part of TMPL-05's "without operator
  intervention" — the consumer needs a way to reload its resolver after a
  successful write.

### Template escaping (added 2026-07-31, cross-AI review M1)

- **D-17:** The contract publishes a **sanitizing template function** in its
  FuncMap as part of **v1**, and the shipped examples use it wherever they emit
  `.Comment` or `.Tags`. — **Reversibility:** costly — adding FuncMap entries
  later is technically backward-compatible, but once examples ship without one,
  consumers copy the unsafe pattern and there is no way to recall the templates
  already in the wild.

  Rationale: D-01 moved rendering off the server, which moved escaping with it.
  All three server generators sanitize today — `sanitizeCommentField`
  (`internal/server/hostsfile.go:123-129`) collapses CR/LF to spaces, applied at
  `:106` and `:111` and reached by the unbound generator via `formatSuffix`. It
  exists because of a real review finding on #349 (`router-hosts-00b.2`), not as
  speculative hardening. `text/template` performs **no** escaping (that is
  `html/template`), so a consumer template doing `{{ .Comment }}` reproduces the
  exact bug #349 closed: a comment containing a newline terminates the `#` line
  and the following text becomes live resolver directives.

  This is reachable from cluster state, not just from a trusted operator at a
  CLI — the Kubernetes operator writes host entries from annotations. Leaving
  escaping to each consumer is precisely the "subtle rule re-derived per
  consumer, fails silently" outcome #364 was filed to prevent.

### Change identity (added 2026-07-31)

- **D-18:** Every snapshot carries a **change ID** identifying the server state
  it represents. It is the **ULID of the newest event in the log**
  (`MAX(event_id)`), not a value minted per transmission.
- **D-19:** The change ID identifies **state, not transmission.** The same state
  yields the same ID for every consumer — that is what makes cross-consumer
  convergence observable ("resolver-a and resolver-b are both at 01K…4F"), which
  the phase goal implies but nothing else in the design provides. A fresh ID per
  snapshot would make the field decorative.
- **D-20:** `MAX(event_id)` is sound **only because event IDs are monotonic**.
  `CommandHandler` holds a `*ulid.MonotonicEntropy` (`internal/server/commands.go:22`,
  constructed at `:32`/`:43`) and every append path mints its ID through
  `newID()` (`:56-61`) into `newEnvelope` (`:77`). With bare `ulid.Make()`, two
  events in the same millisecond could get suffixes `…FFFF` then `…0001`, leaving
  `MAX` pinned at the first — **the change ID would not advance even though state
  changed**, and a deduping client would skip a real update and serve a stale
  zone silently. Any change to ID generation must preserve monotonicity; the
  derivation site must carry a comment saying so. `event_id` is `TEXT PRIMARY KEY`
  (`001_initial.sql:3`), so `MAX()` is an indexed seek, not a scan.
- **D-21 (boundary — do not cross):** A client records the last change ID it
  rendered and **may skip a redundant render** when the incoming ID matches.
  The **server MUST NOT** use a client-reported change ID to decide whether to
  send. Client-side skip keeps the server stateless; server-side skip requires
  per-consumer position tracking, which is exactly the resume token D-06 and
  D-08 reject. These are the same optimization on opposite sides of the wire and
  only one is permitted — recorded explicitly because the forbidden half is a
  natural-sounding efficiency win someone will propose later.

  Guard the client-side skip on **ID matches AND the artifact still exists**, so
  an out-of-band deletion is not skipped into permanence.
- **D-22:** Known and accepted: compaction advances `MAX(event_id)` without
  changing host state (`CompactAggregate` replaces the log with a fresh
  `HostCompacted` seed), costing one redundant render per compaction. Compaction
  is manual-only under ADR `router-hosts-vl8`, so this is rare. An empty store
  makes `MAX` return NULL and needs a zero-ULID sentinel.

  Note `RollbackToSnapshot` is safe: it deletes and re-appends, and the
  re-appended events carry newer ULIDs, so the change ID advances rather than
  going backward.

### Claude's Discretion

- Template engine: `text/template` is the working assumption (no new dependency,
  and D-15 depends on its `{{range}}` semantics). The planner may choose
  otherwise with rationale.
- Exact default value for the D-14 cap, and whether it is expressed as an entry
  count or a byte budget.
- Concrete RPC and message names, and whether one-shot export reuses the watch
  RPC or gets its own.
- Where `atomicWriteFile` lands when it moves out of package `server` (see
  Integration Points).

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope and requirements

- `.planning/ROADMAP.md` § "v0.13.0 — Consumer-Owned Output (Phase Details)" — phase goal, the six success criteria, open planning questions
- `.planning/REQUIREMENTS.md` § "Consumer-Rendered Output (v0.13.0 Phase 1, approved)" — TMPL-01 through TMPL-07 verbatim
- `.planning/PROJECT.md` § "Locked Decisions (ADRs)" and § "Constraints" — four LOCKED ADRs, plus the mTLS-only / SQLite-only / WriteQueue constraints any new write path must respect
- GitHub issue #364 — the originating feature request; contains the rejected alternatives (server-push, per-consumer instances, out-of-band distribution) and the reasoning behind them

### Output generation (the pattern being extended)

- `internal/server/hostsfile.go` — `atomicWriteFile` at :133 (CreateTemp → WriteString → Sync → Close → Rename) and `HostsFileGenerator.Regenerate` at :30
- `internal/server/unboundconf.go` — generator with the `server:` clause header (GH #354); the subtle per-name `static` zone rule that motivated consumer-owned rendering
- `internal/server/dnsmasqconf.go` — third instance of the same generator shape
- `internal/server/service.go` :122 `regenerateOutputs` — how generators are wired and how hook success/failure is signalled

### Streaming and the proto contract

- `proto/router_hosts/v1/hosts.proto` :480-531 — existing RPCs; `ListHosts`/`SearchHosts`/`ExportHosts` are server-streaming, `ImportHosts` is the bidirectional precedent for D-07
- `internal/server/service.go` :602 `ExportHosts` — currently materializes the whole payload and sends one chunk at :678; this is the TMPL-06 target
- `internal/server/service.go` :319 `ListHosts` — note it ignores `req` entirely (tracked separately as #215)

### Bounded collection targets (TMPL-07)

- `internal/client/commands/host.go` :355 and :373 — unbounded `append` into a slice
- `internal/client/commands/snapshot.go` :219 — same pattern
- Note: #38 cites `:345`/`:363`; the current line numbers are `:355`/`:373`. Trust the code, not the issue text.

### Observability

- `internal/server/metrics.go` — 8 existing OTel instruments and the registration pattern D-09's new metrics should follow
- ADR `router-hosts-vl8` (in PROJECT.md) — precedent for cardinality-safe gauge design

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **`atomicWriteFile(path, content string) error`** — `internal/server/hostsfile.go:133`. Creates a temp file in the target directory, writes, fsyncs, closes, renames. Four existing tests cover new-file, overwrite, temp cleanup, and invalid-path. **TMPL-04 is effectively already implemented by this helper** — the work is relocation and reuse, not new machinery.
- **OTel instrument registration** — `internal/server/metrics.go`, 8 instruments already following a consistent pattern for D-09's additions.
- **Coalescing semantics** — the Phase 9 hook runner already implements "collapse a burst into one run" and counts superseded requests on `router_hosts_hook_runs_coalesced_total`. D-06 wants the same shape.

### Established Patterns

- **Generator interface** — three implementations (`HostsFileGenerator`, `DnsmasqConfGenerator`, `UnboundConfGenerator`) share `Regenerate(ctx context.Context, store storage.Storage) (int, error)` and all call `atomicWriteFile`. A template generator is a fourth instance of an established pattern.
- **Server-streaming RPCs** already exist and are wired; bidirectional streaming already exists via `ImportHosts`. D-07 is not a novel transport pattern here.
- **Single-writer WriteQueue** — all writes serialize through it; any new write path must be retry-safe and idempotent (PROJECT.md constraint).

### Integration Points

- **`atomicWriteFile` must move.** It is currently unexported in package `server`. D-01 puts rendering in the client, so it needs to live in a package both can import (e.g. an internal shared package) rather than being reimplemented client-side. Its four tests should move with it.
- **New RPC in `proto/router_hosts/v1/hosts.proto`** — additive; existing field numbers and methods are untouched, so older clients are unaffected. Requires `task proto:generate`.
- **Server metrics gain sink-health instruments** (D-09) alongside the existing 8.
- **CLI gains template/sink surface** in `internal/client/commands/` — one-shot and long-lived modes, plus the D-16 post-write exec hook.
- **`ExportHosts` becomes lazy** (TMPL-06) at `service.go:602-678`, which must not change its observable `hosts`/`json`/`csv` output.

</code_context>

<specifics>

## Specific Ideas

- The illustrative CLI shape from #364 remains the working mental model:
  `router-hosts export --template ./unbound.tmpl` for one-shot, and
  `router-hosts watch --template ./unbound.tmpl --out /etc/unbound/... --exec 'unbound-control reload'`
  for the sink. Final flag and command naming is the planner's call.
- The sidecar marker (D-11) was pictured as `<artifact>.status` holding
  `last_success`, `last_error`, `consecutive_failures`, and `contract_version`.
- Metric names sketched during discussion:
  `router_hosts_sink_last_seen_timestamp_seconds`,
  `router_hosts_sink_last_success_timestamp_seconds`,
  `router_hosts_sink_render_failures_total`, each labelled by consumer CN.
  Names are illustrative, not locked.
- The unbound rendering rule is the canonical worked example of "subtle enough
  that re-deriving it per consumer fails silently" — per-name `local-zone`
  entries deliberately **not** `typetransparent`, so unlisted RR types (notably
  type 65 / HTTPS) return NODATA rather than leaking to the public zone.

</specifics>

<deferred>

## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 1-Consumer-Rendered Output (templates + sink)*
*Context gathered: 2026-07-31*
