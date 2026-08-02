---
phase: 01-consumer-rendered-output-templates-sink
plan: 01
subsystem: api
tags: [grpc, protobuf, text-template, atomic-write, change-id, ulid, tracer]

requires:
  - phase: 01-consumer-rendered-output-templates-sink (plan 09, wave 1)
    provides: "internal/eventid monotonic generator, storage.EventStore.LatestEventID, storage.ZeroChangeID"
provides:
  - "WatchHosts bidirectional streaming RPC (proto3, additive) with WatchHostsRequest/Response, SinkStatus, SnapshotComplete messages"
  - "internal/contract: TemplateVersion constant, the neutral owner of the template data contract version"
  - "internal/server/watch.go: WatchHosts one-shot snapshot mode, change ID derived strictly before ListAll (H1)"
  - "internal/client/template: Data/Entry contract, Parse (missingkey=error), Render, FromProto"
  - "router-hosts render command: --template (required), --out (atomic write via internal/atomicfile)"
  - "internal/atomicfile.Write: the one write-and-rename implementation, relocated out of internal/server"
affects: [01-02, 01-03, 01-06, 01-07, 01-08]

actuals:
  tokens: 27300
  tasks: 3
  commits: 7

tech-stack:
  added: []
  patterns:
    - "Derive-before-read ordering: a change ID minted from LatestEventID strictly before the corresponding ListAll read, making the ID a lower bound rather than an upper bound on the entries it accompanies (H1)"
    - "Package-level var (not const) for a bound that a test needs to lower at runtime (renderDrainLimit)"
    - "Neutral contract package (internal/contract) imported by both server and client-template packages so neither owns the other's constant"

key-files:
  created:
    - internal/contract/contract.go
    - internal/server/watch.go
    - internal/server/watch_test.go
    - internal/client/template/template.go
    - internal/client/template/template_test.go
    - internal/client/commands/render.go
    - internal/client/commands/render_test.go
    - internal/atomicfile/atomicfile.go
    - internal/atomicfile/atomicfile_test.go
  modified:
    - proto/router_hosts/v1/hosts.proto
    - api/v1/router_hosts/v1/hosts.pb.go
    - api/v1/router_hosts/v1/hosts_grpc.pb.go
    - internal/client/commands/root.go
    - internal/server/hostsfile.go
    - internal/server/hostsfile_test.go
    - internal/server/unboundconf.go
    - internal/server/dnsmasqconf.go

key-decisions:
  - "Task 1 checkpoint (D-01 client-side execution, D-03 struct top-level value) resolved by the operator as proceed-as-locked; both one-way decisions confirmed, not revisited"
  - "Change ID (LatestEventID) is read strictly BEFORE ListAll in WatchHosts, making it a lower bound on the snapshot's entries — the reverse order was verified RED (see below) before being rejected"
  - "The atomic {entries, latestEventID} single-transaction read that would make the change ID exact rather than a lower bound is deliberately deferred; filed as GitHub issue #401 alongside #400"
  - "renderDrainLimit is a package-level var, not a const, so a test can lower it instead of seeding 50,000 host entries"
  - "internal/contract holds only TemplateVersion, imports nothing outside stdlib, so neither internal/server nor internal/client/template owns the other's constant"

patterns-established:
  - "Tracer task (type=\"tracer\") committed and its full <verify> automated suite re-run before expansion tasks proceeded, per the tracer feedback gate"

requirements-completed: [TMPL-01, TMPL-02, TMPL-03, TMPL-04, TMPL-08]

coverage:
  - id: D1
    description: "A caller runs `router-hosts render --template ./x.tmpl` and gets host data rendered through their own template, no upstream code change"
    requirement: "TMPL-01"
    verification:
      - kind: unit
        ref: "internal/client/commands/render_test.go#TestRender_TemplateEndToEnd"
        status: pass
    human_judgment: false
  - id: D2
    description: "Template top-level value is a struct exposing .Entries plus .Count, .GeneratedAt, .ContractVersion, .ChangeID, never a bare slice; each entry exposes IPAddress, Hostname, Aliases, Tags, Comment"
    requirement: "TMPL-02"
    verification:
      - kind: unit
        ref: "internal/client/template/template_test.go#TestTemplateRender_HappyPath,TestTemplateRender_CountAndGeneratedAt,TestTemplateRender_ChangeIDIsRenderable"
        status: pass
    human_judgment: false
  - id: D3
    description: "A template referencing a field that does not exist fails with a Go error instead of rendering empty"
    requirement: "TMPL-03"
    verification:
      - kind: unit
        ref: "internal/client/template/template_test.go#TestTemplateRender_UndefinedFieldFails"
        status: pass
    human_judgment: false
  - id: D4
    description: "--out writes the artifact through temp-file-plus-rename; a render failure leaves a pre-existing artifact byte-identical; internal/atomicfile.Write is the only write-and-rename helper reachable from internal/server"
    requirement: "TMPL-04"
    verification:
      - kind: unit
        ref: "internal/atomicfile/atomicfile_test.go#TestAtomicWrite_NewFile,TestAtomicWrite_OverwritesExisting,TestAtomicWrite_CleansUpTmp,TestAtomicWrite_InvalidPath; internal/client/commands/render_test.go#TestRender_WritesArtifactToOut,TestRender_FailurePreservesArtifact"
        status: pass
    human_judgment: false
  - id: D5
    description: "WatchHosts streams one HostEntry per entry then exactly one SnapshotComplete terminator; the change ID is derived strictly before ListAll (a lower bound), is stable for unchanged state, advances monotonically across mutations, and reports the zero-ULID sentinel on an empty store"
    requirement: "TMPL-08"
    verification:
      - kind: unit
        ref: "internal/server/watch_test.go#TestService_WatchHosts_OneShotSnapshot,TestService_WatchHosts_ChangeIDStableForUnchangedState,TestService_WatchHosts_ChangeIDAdvancesOnMutation,TestService_WatchHosts_ChangeIDEmptyStore,TestService_WatchHosts_FollowUnimplemented,TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries"
        status: pass
    human_judgment: false

duration: ~75min
completed: 2026-08-01
status: complete
---

# Phase 1 Plan 01: Tracer — End-to-End Consumer-Rendered Output Summary

**`router-hosts render --template <file>` streams host entries over a new bidirectional `WatchHosts` RPC, renders them client-side through a `text/template` struct contract with a lower-bound change ID, and writes the result atomically via a relocated `internal/atomicfile.Write` helper.**

## Performance

- **Duration:** ~75 min
- **Tasks:** 3
- **Files modified:** 17 (9 created, 8 modified)

## Accomplishments

- Additive `WatchHosts` bidirectional RPC (`WatchHostsRequest`/`Response`, `SinkStatus`, `SnapshotComplete`) with the D-21 boundary, the L4 follow-read-once contract, and the L7 int32-count-vs-50k-cap note all documented inline in the proto.
- `internal/contract.TemplateVersion` — the one owner of the template data contract version, imported by both the server and the client template package.
- `internal/server/watch.go`'s one-shot `WatchHosts`: `LatestEventID` read strictly before `ListAll` (H1), guarded `int32` count conversion (L7), follow mode returns `codes.Unimplemented` (plan 06's job).
- `internal/client/template`: `Data`/`Entry` struct contract (D-03/D-04), `Parse` with `missingkey=error` (TMPL-03), `Render` that never touches a file (D-12), `FromProto` mapping the wire terminator into the contract.
- `router-hosts render --template <file> [--out <path>]`: parses the template before opening any connection, drains `WatchHosts` bounded by a package-level `renderDrainLimit` (review L1/L8), writes to stdout or atomically to `--out`.
- `internal/atomicfile.Write`: the single write-and-rename implementation in the tree, relocated out of `internal/server` with its four tests; all three server generators (hosts, unbound, dnsmasq) now call it.
- Filed GitHub issue #401 tracking the deferred atomic `{entries, latestEventID}` single-transaction read, alongside #400.

## Task Commits

Each task was committed atomically (Task 2 is `type="tracer" tdd="true"`, Task 3 is `type="auto" tdd="true"` — both followed RED-then-GREEN):

1. **Task 1: Confirm the two one-way architecture locks (D-01, D-03)** — checkpoint:decision resolved by operator: `proceed-as-locked`. No commit (decision only).
2. **Task 2: End-to-end "render host data through my own template"**
   - `afcfe03` (feat) — proto: add WatchHosts streaming RPC
   - `a4fc887` (test) — RED: failing tests for WatchHosts render tracer
   - `c91b557` (feat) — GREEN: serve host snapshots over WatchHosts
   - `eb925e7` (feat) — GREEN: render host data through caller templates
3. **Task 3: Relocate the atomic-write helper and give render an atomic --out**
   - `6c12862` (test) — RED: failing tests for atomic write relocation
   - `0457433` (refactor) — GREEN: extract shared atomic file writer
   - `dd92cdc` (feat) — GREEN: write rendered artifact atomically

*Note: both tdd="true" tasks used one RED commit covering all layers touched by that task, followed by one or more GREEN commits, rather than a strict per-file RED/GREEN pair — the plan's own action text specified a 3-commit (proto/server/client) and 2-commit (refactor/feat) structure per task, so RED was inserted as a discrete step ahead of that structure rather than interleaved file-by-file.*

## Files Created/Modified

- `proto/router_hosts/v1/hosts.proto` — additive `WatchHosts` RPC + 4 new messages; `task proto:generate` idempotent, zero pre-existing lines removed
- `api/v1/router_hosts/v1/hosts.pb.go`, `hosts_grpc.pb.go` — regenerated stubs
- `internal/contract/contract.go` — `TemplateVersion = "1"`
- `internal/server/watch.go` — `WatchHosts`, `TemplateContractVersion`
- `internal/server/watch_test.go` — 6 tests including the H1 lower-bound decorator test
- `internal/client/template/template.go` — `Entry`, `Data`, `Parse`, `Render`, `FromProto`
- `internal/client/template/template_test.go` — 4 table-driven tests
- `internal/client/commands/render.go` — `newRenderCmd`, `renderDrainLimit`
- `internal/client/commands/render_test.go` — 4 tests (end-to-end, drain limit, writes-to-out, failure-preserves-artifact)
- `internal/client/commands/root.go` — registers `render`
- `internal/atomicfile/atomicfile.go` — `Write`, moved verbatim from `internal/server/hostsfile.go`
- `internal/atomicfile/atomicfile_test.go` — the 4 moved `TestAtomicWrite_*` tests
- `internal/server/hostsfile.go`, `hostsfile_test.go`, `unboundconf.go`, `dnsmasqconf.go` — `atomicWriteFile` deleted, 3 call sites updated to `atomicfile.Write`

## Decisions Made

- **Task 1 checkpoint:** operator selected `proceed-as-locked` for D-01 (client-side template execution) and D-03 (struct top-level value with `.ChangeID` metadata). Both one-way decisions confirmed, no re-planning triggered.
- **H1 derivation order verified RED against the reversed order** (see below), not merely asserted by a source-order grep — the plan required this and it was executed exactly as specified.
- **Follow-up issue #401 filed** for the deferred atomic `{entries, latestEventID}` read, per the plan's explicit action requirement.
- `renderDrainLimit` kept as a package-level `var` per review L1, confirmed testable via `TestRender_DrainLimitRefusesSnapshot`.

## H1 RED Verification (mandatory per plan)

`TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries` was run against the reversed order (temporarily swapping `LatestEventID` to run after `ListAll` in `internal/server/watch.go`):

```text
watch_test.go:211: "01KYZ6040DA2B7Q55JPW75Z5ER" is not less than "01KYZ6040DA2B7Q55JPW75Z5ER"
--- FAIL: TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries (0.00s)
```

The terminator's change ID equalled the post-mutation value while naming an entry set from before it — exactly the failure mode the correct ordering prevents. The order was then reverted to `LatestEventID` before `ListAll`, and all six `TestService_WatchHosts_*` tests passed.

## Deviations from Plan

### Auto-fixed Issues

None — plan executed as written. The only structural adaptation was the RED/GREEN commit granularity described in Task Commits above, which is a TDD-discipline decision (documented there), not a deviation rule (bug fix / missing functionality / blocker) under Rules 1–3.

**Total deviations:** 0
**Impact on plan:** None. No scope creep.

## Issues Encountered

- **`gofumpt -w .` (directory recursion) does not reformat the generated `api/v1/router_hosts/v1/*.pb.go` files** (it respects their `// Code generated ... DO NOT EDIT.` header and skips them during a directory walk), while the repo's `lefthook` pre-commit hook runs `gofumpt -l -d {staged_files}` against explicit staged file paths, which does NOT skip generated files. This is a pre-existing tooling inconsistency, not introduced by this plan. Worked around by running `gofumpt -w <explicit file path>` on the two generated files directly before each commit that touched them. No source change was needed; this is documented here so a future contributor regenerating the proto stubs is not surprised by the pre-commit hook rejecting `task fmt`'s output.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

The tracer proves the whole consumer-rendered-output path end to end: proto contract, server streaming handler, client template package, CLI command, and shared atomic-write helper are all wired through one path. Plans 02 (contract documentation + sanitizing FuncMap), 03 (configurable collection cap replacing `renderDrainLimit`), 06 (follow mode + `sendSnapshot`), 07 (sink client), and 08 (e2e) all build on this without needing to revisit D-01, D-03, or the H1 ordering.

GitHub issue #401 tracks the deferred atomic snapshot read; no blocker for this phase's remaining plans, which all describe the change ID as a lower bound per the current (accurate) semantics.

No blockers. `go test -race -count=1 ./...` is green across the whole repository; `task lint` reports 0 issues.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-01*

## Self-Check: PASSED

- FOUND: `internal/contract/contract.go`
- FOUND: `internal/server/watch.go`
- FOUND: `internal/server/watch_test.go`
- FOUND: `internal/client/template/template.go`
- FOUND: `internal/client/template/template_test.go`
- FOUND: `internal/client/commands/render.go`
- FOUND: `internal/client/commands/render_test.go`
- FOUND: `internal/atomicfile/atomicfile.go`
- FOUND: `internal/atomicfile/atomicfile_test.go`
- FOUND: `afcfe03` (feat(proto): add WatchHosts streaming RPC)
- FOUND: `a4fc887` (test(01-01): add failing tests for WatchHosts render tracer)
- FOUND: `c91b557` (feat(server): serve host snapshots over WatchHosts)
- FOUND: `eb925e7` (feat(client): render host data through caller templates)
- FOUND: `6c12862` (test(01-01): add failing tests for atomic write relocation)
- FOUND: `0457433` (refactor(server): extract shared atomic file writer)
- FOUND: `dd92cdc` (feat(client): write rendered artifact atomically)
