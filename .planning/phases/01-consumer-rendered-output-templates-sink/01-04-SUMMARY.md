---
phase: 01-consumer-rendered-output-templates-sink
plan: 04
subsystem: api
tags: [grpc, streaming, backpressure, keepalive, chunking]

requires:
  - phase: 01-consumer-rendered-output-templates-sink (plan 01, wave 1)
    provides: "WatchHosts bidirectional streaming RPC and the pre-existing ExportHosts server-streaming RPC this plan bounds"
provides:
  - "ExportHosts frames its formatted payload into bounded 64 KiB messages (exportChunkSize) via sendExportChunks, mirroring the client's importChunkSize"
  - "sendExportChunks: an empty payload still sends exactly one message with an empty chunk, never zero (review L14)"
  - "Three format-specific full-stream reconstruction tests (hosts/json/csv) proving concatenated bytes are byte-identical to the pre-chunking payload"
  - "WatchHosts per-entry streaming assertion: TestService_WatchHosts_StreamsPerEntry and the empty-store terminator-only case"
  - "internal/server.KeepaliveParams / KeepaliveEnforcementPolicy / KeepaliveServerOptions: 30s/10s server ping, 15s minimum client interval, PermitWithoutStream, no connection-lifetime limits"
  - "internal/client.KeepaliveParams: 20s/10s client ping with PermitWithoutStream, applied in NewClient (fleet-wide, not sink-specific)"
  - "docs/guides/operations.md \"Long-lived sink connections\" section documenting both sides' parameters, the MinTime invariant, and the fleet-wide scope/cost (review L12)"
affects: [01-06, 01-07, 01-08]

actuals:
  tokens: 6572
  tasks: 2
  commits: 4

tech-stack:
  added: []
  patterns:
    - "exportChunkSender: a narrow (Send-only) interface carved out of grpc.ServerStreamingServer[T] so chunking logic is unit-testable against a fake, without satisfying the full ServerStream interface"
    - "Length-only test fixtures for byte-boundary assertions: padded-comment helper computes a comment string that makes a formatted payload exactly N bytes, exploiting the hosts format's fixed-width embedded timestamp so length (not content) is deterministic across two separate FormatHostsFile calls"
    - "Keepalive constructors named KeepaliveParams/KeepaliveEnforcementPolicy per package (not Server-/Client-prefixed) to avoid golangci-lint's revive stutter check while keeping the two packages' functions distinguishable by import path"

key-files:
  modified:
    - internal/server/service.go
    - internal/server/service_test.go
    - internal/server/watch_test.go
    - internal/server/server.go
    - internal/server/server_test.go
    - internal/client/client.go
    - internal/client/client_test.go
    - docs/guides/operations.md

key-decisions:
  - "TMPL-06 (amended 2026-07-31) satisfied in full for this plan's scope: bounded wire messages + client backpressure on both ExportHosts and WatchHosts. Storage-layer laziness (store.ListAll materializing the full result set) remains deferred to issue #400, per the amendment; no artifact this plan writes claims constant server memory (verified: rg -c 'constant memory' docs/guides/operations.md == 0)"
  - "Renamed the plan's suggested ServerKeepaliveParams/ServerKeepaliveEnforcementPolicy/ClientKeepaliveParams to KeepaliveParams/KeepaliveEnforcementPolicy (server package) and KeepaliveParams (client package) to fix a golangci-lint revive 'stutters' warning (Rule 1 — lint is a build-blocking issue, not suppressible per CLAUDE.md's no-nolint-without-approval rule). No acceptance-criteria grep depended on the original names; only KeepaliveServerOptions (unchanged) and WithKeepaliveParams (grpc's own name) are grepped"
  - "sendExportChunks takes a narrow exportChunkSender interface (Send-only) rather than the full grpc.ServerStreamingServer[hostsv1.ExportHostsResponse], so the empty-data and boundary framing cases are unit-tested directly against a fake instead of only through the live RPC (where none of the three formats ever actually produce a zero-byte payload, since all three emit headers even for an empty store)"
  - "TestService_ExportHosts_EmptyInventorySendsOneChunk asserts message count == 1 through the real RPC (the true contract at that layer, since 'hosts' format headers make the payload non-empty even for zero entries); the literal zero-byte 'send exactly one empty chunk' case from review L14 is pinned separately and precisely by TestSendExportChunks_EmptyDataSendsOneEmptyChunk against the extracted helper"
  - "TestService_ExportHosts_RepeatedCallsAreIdentical and the JSON/CSV reconstruction tests use format=json/csv rather than hosts, because the hosts format embeds a 'Last updated' timestamp — exact byte-equality assertions against it would carry a (small, non-zero) clock-boundary flakiness risk that json/csv do not have"

patterns-established:
  - "TDD RED commits (test-only, confirmed to fail to compile/pass before the implementation exists) followed by GREEN commits, verified by stashing the implementation change and re-running the new tests to observe the actual failure before restoring it"

requirements-completed: [TMPL-06]

coverage:
  - id: D1
    description: "ExportHosts frames its response into bounded exportChunkSize (64 KiB) messages instead of one unbounded send, giving the client real gRPC flow-control backpressure"
    requirement: "TMPL-06"
    verification:
      - kind: unit
        ref: "internal/server/service_test.go#TestService_ExportHosts_ChunksLargePayloadHosts,TestService_ExportHosts_ChunksLargePayloadJSON,TestService_ExportHosts_ChunksLargePayloadCSV"
        status: pass
    human_judgment: false
  - id: D2
    description: "Byte identity of all three export formats is proven by full-stream reconstruction (concatenating every chunk equals the un-chunked payload), not inferred from tests that read only the first response"
    requirement: "TMPL-06"
    verification:
      - kind: unit
        ref: "internal/server/service_test.go#TestService_ExportHosts_ChunksLargePayloadHosts,TestService_ExportHosts_ChunksLargePayloadJSON,TestService_ExportHosts_ChunksLargePayloadCSV,TestService_ExportHosts_RepeatedCallsAreIdentical"
        status: pass
    human_judgment: false
  - id: D3
    description: "The empty-inventory single-message contract is preserved (never zero messages), and the exact chunk-boundary cases (exactly one chunk at the boundary, exactly two with a one-byte second chunk just past it) are pinned both through the live RPC and against the extracted sendExportChunks helper"
    requirement: "TMPL-06"
    verification:
      - kind: unit
        ref: "internal/server/service_test.go#TestService_ExportHosts_EmptyInventorySendsOneChunk,TestService_ExportHosts_ExactChunkBoundary,TestService_ExportHosts_OneByteOverBoundary,TestSendExportChunks_EmptyDataSendsOneEmptyChunk,TestSendExportChunks_ExactChunkBoundary,TestSendExportChunks_OneByteOverBoundary"
        status: pass
    human_judgment: false
  - id: D4
    description: "WatchHosts sends exactly one message per entry plus exactly one SnapshotComplete terminator, including on an empty store (zero entry messages, one terminator with count 0)"
    requirement: "TMPL-06"
    verification:
      - kind: unit
        ref: "internal/server/watch_test.go#TestService_WatchHosts_StreamsPerEntry,TestService_WatchHosts_EmptyStoreSendsTerminatorOnly"
        status: pass
    human_judgment: false
  - id: D5
    description: "gRPC keepalive is configured explicitly on both server (30s ping/10s timeout, no connection-lifetime limits, 15s minimum accepted client interval) and client (20s ping/10s timeout, pings without an active RPC), replacing grpc-go's two-hour default"
    requirement: "TMPL-06"
    verification:
      - kind: unit
        ref: "internal/server/server_test.go#TestKeepalive_ServerParams,TestKeepalive_ServerEnforcementPolicy,TestKeepalive_ServerOptionsCount; internal/client/client_test.go#TestKeepalive_ClientParams,TestKeepalive_ClientIntervalRespectsServerMinTime"
        status: pass
    human_judgment: false
  - id: D6
    description: "The operations guide documents both sides' keepalive parameters, the MinTime invariant, the deliberate absence of connection-lifetime limits, and that the client-side parameters apply fleet-wide (every CLI command) rather than only to sinks"
    verification:
      - kind: other
        ref: "docs/guides/operations.md § 'Long-lived sink connections' (manual read; no runnable assertion)"
        status: pass
    human_judgment: true
    rationale: "Documentation content quality (clarity, correct framing of fleet-wide scope) is a prose judgment, not something a unit test asserts beyond the keyword greps already run during execution."

duration: ~45min
completed: 2026-08-01
status: complete
---

# Phase 1 Plan 04: Lazy Wire Streaming and gRPC Keepalive Summary

**`ExportHosts` now frames its payload into bounded 64 KiB messages (byte-identical across hosts/json/csv, proven by full-stream reconstruction tests) alongside `WatchHosts`' existing per-entry send, and both server and client set explicit gRPC keepalive parameters, replacing grpc-go's two-hour default ping interval with 30s/20s pings.**

## Performance

- **Duration:** ~45 min
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- `sendExportChunks` frames `ExportHosts`' already-formatted payload into `exportChunkSize` (64 KiB) windows, sent one per gRPC message; the three format branches (`hosts`/`json`/`csv`) are untouched — only the terminal send changed.
- The empty-inventory case still sends exactly one message (never zero), pinned both through the live RPC and directly against the extracted `sendExportChunks` helper via a fake `exportChunkSender`.
- Three new full-stream reconstruction tests (one per format) prove concatenating every received chunk reproduces the un-chunked payload byte for byte, closing the gap left by the pre-existing tests that only read the first response (review L2).
- Exact chunk-boundary behavior (payload of exactly `exportChunkSize` bytes → one message; one byte more → two messages, second holding one byte) is pinned via a padded-comment test fixture that exploits the `hosts` format's fixed-width embedded timestamp for deterministic length control.
- `WatchHosts`' pre-existing per-entry send now has an explicit streaming assertion (`TestService_WatchHosts_StreamsPerEntry`) plus an empty-store terminator-only case (review L14).
- `internal/server.KeepaliveParams`/`KeepaliveEnforcementPolicy`/`KeepaliveServerOptions` set 30s/10s server ping parameters, a 15s minimum accepted client ping interval, and deliberately leave `MaxConnectionIdle`/`MaxConnectionAge`/`MaxConnectionAgeGrace` unset so no timer can kill a healthy long-lived sink.
- `internal/client.KeepaliveParams` sets 20s/10s client ping parameters with `PermitWithoutStream: true`, applied in `NewClient` — fleet-wide (every CLI command), not sink-specific.
- `docs/guides/operations.md` gained a "Long-lived sink connections" section documenting both sides' parameters, the `MinTime` invariant, the deliberate absence of connection-lifetime limits, and the fleet-wide scope/steady-state cost (review L12).

## Task Commits

Each task followed RED (failing tests) then GREEN (implementation), per `tdd="true"`:

1. **Task 1: Stream lazily on the wire — chunked ExportHosts, per-entry WatchHosts**
   - `c86de34` (test) — RED: failing tests for chunked export streaming
   - `7a16f4b` (perf) — GREEN: stream export payload in chunks
2. **Task 2: Configure gRPC keepalive on both sides and document it**
   - `9a51140` (test) — RED: failing tests for gRPC keepalive parameters
   - `f3ad348` (feat) — GREEN: configure gRPC keepalive both sides

RED was verified by stashing the implementation change and re-running the new tests to observe an actual compile failure (undefined symbols), not merely by inspection, before restoring the implementation and confirming GREEN.

## Files Created/Modified

- `internal/server/service.go` — `exportChunkSize` constant, `exportChunkSender` interface, `sendExportChunks` helper; `ExportHosts`' terminal send now calls it
- `internal/server/service_test.go` — 3 format reconstruction tests, empty/boundary/repeated-call tests, 3 unit tests against `sendExportChunks` directly via a fake sender
- `internal/server/watch_test.go` — `TestService_WatchHosts_StreamsPerEntry`, `TestService_WatchHosts_EmptyStoreSendsTerminatorOnly`
- `internal/server/server.go` — `KeepaliveParams`, `KeepaliveEnforcementPolicy`, `KeepaliveServerOptions`; `NewServer` inserts them ahead of caller-supplied `WithGRPCOptions`
- `internal/server/server_test.go` — `TestKeepalive_ServerParams`, `TestKeepalive_ServerEnforcementPolicy`, `TestKeepalive_ServerOptionsCount`
- `internal/client/client.go` — `KeepaliveParams`; `NewClient` passes `grpc.WithKeepaliveParams`
- `internal/client/client_test.go` — `TestKeepalive_ClientParams`, `TestKeepalive_ClientIntervalRespectsServerMinTime` (cross-package invariant against `internal/server`)
- `docs/guides/operations.md` — new "Long-lived sink connections" section

## Decisions Made

- **Renamed the plan's suggested `ServerKeepaliveParams`/`ServerKeepaliveEnforcementPolicy`/`ClientKeepaliveParams` to `KeepaliveParams`/`KeepaliveEnforcementPolicy` (per package)** to fix a golangci-lint `revive` "stutters" finding, per CLAUDE.md's requirement to fix lint properly rather than suppress it. Verified no acceptance-criteria grep depended on the literal original names — only `KeepaliveServerOptions` (kept) and `WithKeepaliveParams` (grpc's own API, unrelated) were checked.
- **`sendExportChunks` takes a narrow `Send`-only interface**, not the full `grpc.ServerStreamingServer[hostsv1.ExportHostsResponse]`, specifically so the empty-payload and chunk-boundary framing logic could be unit-tested directly against a fake — none of the three real export formats ever produce a literal zero-byte payload (all three emit headers even for an empty store), so the live-RPC-level empty-inventory test can only assert "exactly one message," not "carrying an empty chunk." The stronger claim is proven separately against the extracted helper.
- **Used `format=json`/`csv` (not `hosts`) for the repeated-calls-identical and reconstruction-timing-sensitive assertions** where feasible, since the `hosts` format embeds a "Last updated" timestamp that could in principle differ between two calls made at slightly different instants; `json`/`csv` carry no such field.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed golangci-lint `revive` stutter and `prealloc` findings**

- **Found during:** Task 2 (`task lint` after the keepalive implementation)
- **Issue:** `func ServerKeepaliveParams()` in package `server` (and the client/`ClientKeepaliveParams` equivalent) triggered `revive`'s exported-name-stutters check; a `grpcOpts := []grpc.ServerOption{...}` built via successive `append` calls triggered `prealloc`.
- **Fix:** Renamed the two flagged constructors per package to `KeepaliveParams`/`KeepaliveEnforcementPolicy` (dropping the redundant `Server`/`Client` prefix already implied by the package name); preallocated `grpcOpts` with `make([]grpc.ServerOption, 0, 1+len(keepaliveOpts)+len(s.grpcOptions))`.
- **Files modified:** `internal/server/server.go`, `internal/server/server_test.go`, `internal/client/client.go`, `internal/client/client_test.go`, `docs/guides/operations.md` (doc cross-references updated to match)
- **Verification:** `task lint` exits 0 with 0 issues; all `TestKeepalive_*` tests still pass under the renamed symbols.
- **Committed in:** `f3ad348` (Task 2 GREEN commit)

---

**Total deviations:** 1 auto-fixed (1 blocking — lint failure)
**Impact on plan:** Naming-only; no behavioral, architectural, or acceptance-criteria change. No `//nolint` directive was added.

## Issues Encountered

- **Pre-existing sandbox noise, not introduced by this plan:** `TestService_ExportHosts_HostsFormat`/`JSONFormat`/`CSVFormat` log an `ERROR hosts file regeneration failed ... create temp file: open /dev/null.tmp.* : operation not permitted` because the test environment's `HostsFileGenerator` points at `/dev/null`, which this sandbox cannot open a sibling temp file next to. This is pre-existing test-environment behavior (the hook/generator error is logged, not returned, so the RPC still succeeds) and unrelated to the chunking or keepalive changes; all affected tests still pass.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

Both `ExportHosts` and `WatchHosts` now bound per-message wire memory and give clients real gRPC backpressure; storage-layer laziness (`store.ListAll` still materializing the full result set before the first byte) remains tracked as issue #400, unchanged by this plan. Keepalive is configured fleet-wide, so plan 05's/06's sink-health "last-seen" signal (D-09/D-10) will detect a dead or partitioned connection within tens of seconds instead of grpc-go's two-hour default — no further wiring needed from this plan for that to hold.

No blockers. `go test -race -count=1 ./...` is green across the whole repository; `task lint` reports 0 issues; `task build` succeeds for both binaries.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-01*

## Self-Check: PASSED

- FOUND: `internal/server/service.go`
- FOUND: `internal/server/service_test.go`
- FOUND: `internal/server/watch_test.go`
- FOUND: `internal/server/server.go`
- FOUND: `internal/server/server_test.go`
- FOUND: `internal/client/client.go`
- FOUND: `internal/client/client_test.go`
- FOUND: `docs/guides/operations.md`
- FOUND: `c86de34` (test(01-04): add failing tests for chunked export streaming)
- FOUND: `7a16f4b` (perf(server): stream export payload in chunks)
- FOUND: `9a51140` (test(01-04): add failing tests for gRPC keepalive parameters)
- FOUND: `f3ad348` (feat(server): configure gRPC keepalive both sides)
