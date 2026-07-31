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
  metadata** (`.Count`, `.GeneratedAt`, `.ContractVersion`), not a bare slice.
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
- **D-12:** On any failure — connection loss, render error, write error — the
  previously written artifact is left **byte-identical**. Staleness is surfaced
  through the marker and metrics, never by truncating or removing the artifact.
  A silently stale but structurally valid zone is the 0.10.12 failure mode #364
  was filed over.
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
