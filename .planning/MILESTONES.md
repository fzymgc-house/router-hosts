# Milestones

## v0.13.0 Consumer-Owned Output (Shipped: 2026-08-02)

**Phases completed:** 1 phases, 11 plans, 32 tasks

**Key accomplishments:**

- `router-hosts render --template <file>` streams host entries over a new bidirectional `WatchHosts` RPC, renders them client-side through a `text/template` struct contract with a lower-bound change ID, and writes the result atomically via a relocated `internal/atomicfile.Write` helper.
- A template lacking a declared contract version, or declaring one the server does not serve, is refused before any connection or write; contract v1 now publishes a shared sanitizing FuncMap and an authoritative reference page, backed by three worked examples that prove the contract by rendering against a pinned fixture.
- Every client-side stream-collection loop (`host list`, `host search`, `snapshot list`, `render`) now refuses — nil slice, actionable error, never a truncated result — the instant either a configurable entry-count ceiling or an independent byte budget is crossed, and a client config file that exists but is unusable now fails the process loudly instead of silently falling back to defaults.
- `ExportHosts` now frames its payload into bounded 64 KiB messages (byte-identical across hosts/json/csv, proven by full-stream reconstruction tests) alongside `WatchHosts`' existing per-entry send, and both server and client set explicit gRPC keepalive parameters, replacing grpc-go's two-hour default ping interval with 30s/20s pings.
- Three standalone, unit-tested primitives for sink health — verified mTLS common-name extraction, an in-memory per-consumer health registry with independent write/reload health and last-writer-wins duplicate-CN semantics, and seven OTel observable gauges projecting that state — with no `WatchHosts` wiring yet (deferred to plan 06).
- `WatchHosts` follow mode is now a real continuous sink: a `changeNotifier` fan-out primitive wakes every open watcher on any host mutation or real compaction, and a deliberately non-joining two-goroutine stream handler pushes coalesced snapshots while independently recording per-consumer status keyed by verified mTLS identity — with both reviewer-identified teardown deadlocks proven fixed by tests that were confirmed to hang under the pre-review shape.
- `router-hosts watch` is now a real sink: a long-lived, snapshot-boundary-rendering, self-reconnecting CLI command that reports its own health both upstream and to a local sidecar, distinguishes all three D-12a sink-cycle outcomes, and never rolls the artifact back once a hook has run.
- The Watch sink is now proven end to end over a real CA-verified mTLS connection — including a genuine server stop/restart — and documented for operators; the two deployment-scale manual checks are recorded as explicitly not-run.
- A shared `internal/eventid` generator plus an unconditional in-transaction ordering guard in sqlite's `insertEvent`, so `MAX(event_id)` can never fail to advance across a real state change — including the zero-ULID-into-empty-store edge case that a gated guard would have let through.
- `watch --config <path>` now loads exactly that file, bypasses XDG auto-discovery entirely, and fails loudly on a bad path instead of silently dialing whatever the search finds (closes gap G-01-1's plumbing half).
- A new `proc_e2e` test tier launches the shipped `router-hosts` binary as a real OS process on both sides of mTLS and proves `watch --config <path>` connects to the server named by `<path>` — the exact vantage point gap G-01-1 shipped through undetected.

---
