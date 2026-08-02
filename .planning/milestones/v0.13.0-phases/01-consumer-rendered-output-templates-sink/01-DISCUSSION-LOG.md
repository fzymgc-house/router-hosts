# Phase 1: Consumer-Rendered Output (templates + sink) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-31
**Phase:** 1-Consumer-Rendered Output (templates + sink)
**Areas discussed:** Execution site, Template data contract, Contract versioning, Sink change-notification, Sink failure/staleness, Bounded collection, Health reporting

---

## Where the template executes

| Option | Description | Selected |
|--------|-------------|----------|
| Client-side (CLI renders locally) | Server streams structured data; CLI renders and atomic-writes. Server never executes caller code. Consumers must run the CLI. | ✓ |
| Server-side (upload template, server renders) | Thinnest consumer, any gRPC client works. Server executes arbitrary caller-supplied `text/template` in-process — needs timeout, output cap, function allowlist. | |
| Both — server renders, CLI wrapper | Maximum flexibility; full server-side security burden plus larger surface in one phase. | |

**User's choice:** Client-side (CLI renders locally)
**Notes:** Removes the server-side template execution surface entirely. Surfaced consequence: `atomicWriteFile` currently lives unexported in package `server` (`hostsfile.go:133`), so it must move to a shared package rather than be reimplemented client-side.

---

## Template data contract (TMPL-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Struct with `.Entries` + metadata | `{{range .Entries}}`, plus `.Count`, `.GeneratedAt`, `.ContractVersion`. Forward-compatible. | ✓ |
| Bare slice of entries | `{{range .}}` — simplest, but `.` is permanently bound to the entry list; no non-breaking way to add metadata later. | |
| Struct plus lookup indexes | Adds `.ByHostname` / `.ByTag`. More useful for complex zones; more permanent contract surface, which is the TMPL-02 risk. | |

**User's choice:** Struct with `.Entries` + metadata
**Notes:** Presented with the forward-compatibility argument made explicit — choosing a bare slice would make any later metadata addition a silent breaking change for every consumer template.

---

## Contract versioning

| Option | Description | Selected |
|--------|-------------|----------|
| Template declares, CLI refuses on mismatch | Turns a field rename into a loud startup error rather than a wrong render. | ✓ |
| Version exposed in data, documented only | Simpler; a stale template fails at render time or renders wrong. | |
| You decide at planning | Delegate enforcement, constrained by TMPL-03's fail-loud requirement. | |

**User's choice:** Template declares, CLI refuses on mismatch

---

## Sink change-notification

| Option | Description | Selected |
|--------|-------------|----------|
| Full snapshot, coalesced | Complete entry set per change, bursts collapsed. Idempotent; reconnect is just the next snapshot. No resume token, no server-side stream position. | ✓ |
| Deltas with resume token | Efficient at scale, but the server tracks per-stream position — the per-sink state #364 wanted to avoid — and a missed delta corrupts silently. | |
| Full snapshot, every change, no coalescing | Simplest semantics; a burst of N writes produces N renders, N writes, N reload hooks. | |

**User's choice:** Full snapshot, coalesced

---

## Sink failure + staleness

| Option | Description | Selected |
|--------|-------------|----------|
| Keep last good, retry forever with backoff | Artifact stays valid; risk of a silently stale zone (the 0.10.12 failure mode). | |
| Keep last good, exit non-zero after N retries | Supervisor sees the failure; staleness visible via process state. | |
| Keep last good, plus sidecar staleness marker | Artifact untouched; companion record of last-successful-sync for age-based alerting. | ✓ |

**User's choice:** Keep last good, plus a sidecar staleness marker
**Notes:** Superseded in part by the health-reporting discussion below, which added server-side metrics alongside the local marker.

---

## Bounded collection (TMPL-07)

| Option | Description | Selected |
|--------|-------------|----------|
| Configurable, safe default | Default cap raisable by config/flag, applied at every collecting site; fails clearly naming the limit. | ✓ |
| Fixed constant, no override | Simplest; a legitimate zone above the number is unfixable without a release — the upstream-dependency problem this milestone exists to remove. | |
| Byte budget instead of item count | Bounds memory more faithfully; less obvious to an operator reading the error. | |

**User's choice:** Configurable, safe default
**Notes:** Raised during discussion that this cap is load-bearing rather than theoretical: because `.Count` is in the contract, the client must collect the full set before rendering. `text/template` can `{{range}}` a channel, so streaming render is possible in principle — but not while exposing a total count up front.

---

## Health reporting

| Option | Description | Selected |
|--------|-------------|----------|
| Sidecar status file (original framing) | JSON beside the artifact; works with no scrape infrastructure. | |
| OTel metric from each sink process | Consistent with server observability; needs a collector reachable from every consumer. | |
| Both — file always, metric optional | Larger surface to build and test. | |

**User's choice:** Neither as originally framed — user redirected.
**Notes:** User asked: *"why not report the metric back to the server to avoid another otel publisher from every sink?"* This was a better option than any offered. The sink already holds an open mTLS stream, so status can flow upstream on it (making the watch RPC bidirectional, with `ImportHosts` as precedent), and the server exposes it through its existing OTel pipeline keyed by mTLS CN. One place shows all N resolvers; no publisher or collector per consumer.

Analysis returned to the user before re-asking:

- Compatible with #364's "no per-sink state" **only** while the state is ephemeral — learned from a client-opened stream, held while alive, never requiring the server to reach anyone.
- Blind spot: a fully dead sink cannot report that it is dead; the server sees only stream absence, which is ambiguous between clean shutdown, crash, and partition.
- Cardinality bounded by mTLS CN, consistent with the repo's cardinality-safe gauge precedent.

User then added: *"include a metric for when the client was last seen."* This closes the blind spot — absence becomes a measurable age. Flagged back that retaining last-seen past stream close is a small deliberate departure from #364 (one in-memory timestamp per CN, lost on restart), recorded in CONTEXT.md as D-10 rather than left implicit.

**Final:** upstream metrics including last-seen, **plus** a local sidecar file. The argument for the local file shifted during discussion — it is no longer about detecting sink death (last-seen covers that) but about the **server-down** case, where central metrics are unavailable by definition while sinks keep serving last-good artifacts.

---

## Claude's Discretion

- Template engine (`text/template` is the working assumption; the `{{range}}`-a-channel property is load-bearing for the D-15 reasoning)
- Exact default for the collection cap, and whether expressed as entry count or byte budget
- Concrete RPC and message names; whether one-shot export reuses the watch RPC
- Destination package for the relocated `atomicWriteFile`

## Deferred Ideas

None — discussion stayed within phase scope. No scope-creep redirects were needed.
