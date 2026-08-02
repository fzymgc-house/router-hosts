---
phase: 01-consumer-rendered-output-templates-sink
plan: 08
subsystem: testing
tags: [e2e, mtls, grpc, watch, sink-health, tls13, docs, operator-guide]

requires:
  - phase: 01-consumer-rendered-output-templates-sink (plan 06, wave 4)
    provides: "server-side WatchHosts follow mode, SinkHealth registry wiring (WithSinkHealth), change-notification fan-out"
  - phase: 01-consumer-rendered-output-templates-sink (plan 07, wave 5)
    provides: "router-hosts watch CLI, WatchPolicy/WithWatchPolicy exported timing seam, sidecar status file (sinkStatus)"
provides:
  - "e2e/helpers_test.go: server.WithSinkHealth wired into the harness service; stopServer/startServer split lifecycle (testEnv retains store/cfg/logger/sinkHealth so a restart rebuilds over the SAME store); TLS floor raised to 1.3; collectWatchSnapshot helper"
  - "e2e/e2e_test.go: TestE2E_WatchSnapshotOverMTLS, TestE2E_WatchPushesOnMutation, TestE2E_WatchSinkHealthKeyedByCN, TestE2E_WatchSinkSurvivesServerRestart — the first Watch coverage over a real CA-verified mTLS connection in this repo"
  - "docs/guides/consumer-rendered-output.md: end-to-end render/watch operator guide (sidecar status fields, change-ID convergence, D-12a reload-failure outcome, all seven sink gauges, one-CN-per-consumer requirement)"
  - "docs/reference/cli.md: render/watch command sections with every flag and default"
  - "01-VALIDATION.md: all four manual deployment verifications recorded as explicitly NOT-RUN, with reason, concrete steps, and existing automated coverage scoped per item"
affects: [milestone-v0.13.0-close, ship]

actuals:
  tokens: 9660
  tasks: 3
  commits: 2

tech-stack:
  added: []
  patterns:
    - "e2e harness lifecycle split into stopServer/startServer (idempotent stop; startServer rebinds the same address, rebuilds server+service over retained store/cfg/logger/sinkHealth, redials the client) so a real process stop-and-restart produces a genuinely observable outage window instead of one cancelled RPC on a live ClientConn"
    - "stopServer calls grpc.Server.Stop() directly rather than relying on context cancellation alone — Server.Run's ctx.Done() path drains for up to 30s (GracefulShutdownTimeout) before forcing anything, which would keep an open WatchHosts stream alive through the whole simulated outage"
    - "commands.NewRootCmd(commands.WithWatchPolicy(...)) is how an external test package (e2e is package e2e_test) drives the real router-hosts watch command with millisecond reconnect timing — the exported seam plan 07 built specifically for this"

key-files:
  created:
    - docs/guides/consumer-rendered-output.md
  modified:
    - e2e/e2e_test.go
    - e2e/helpers_test.go
    - docs/guides/index.md
    - docs/reference/cli.md
    - mkdocs.yml
    - .planning/phases/01-consumer-rendered-output-templates-sink/01-VALIDATION.md

key-decisions:
  - "stopServer uses grpc.Server.Stop() (immediate) instead of only cancelling Run's context, because the graceful-drain path server.go already implements would otherwise keep the test's open stream alive for up to 30s — silently defeating the review M4/M10 outage requirement rather than failing loudly"
  - "TestE2E_WatchSinkSurvivesServerRestart seeds one host before starting the sink, so the initial artifact is non-empty; an empty .Entries range legitimately renders empty content, which would have made the byte-identical-during-outage assertion vacuously true"
  - "The auto-regenerated docs/reference/cli.md (via task docs:build) was reverted in favor of a hand-maintained edit adding render/watch: the generator's own code-fence output fails rumdl (pre-existing, unrelated to this plan), filed as GitHub issue #402 rather than silently committing lint-failing generated content or bypassing the lint gate"
  - "docs/reference/api.md reverted after task docs:build per the plan's own instruction — known unrelated churn, same precedent phase 9 (09-05) set"
  - "All four manual-only deployment verifications (resolver reload, two-node convergence, restart/no-reload-storm, reload-failure diagnosis) recorded as explicitly NOT-RUN in 01-VALIDATION.md — no unbound host or second machine in this environment — each with its concrete steps and the existing automated coverage stated, mirroring phase 9's OTel-scrape precedent rather than claiming done or silently narrowing scope"

requirements-completed: [TMPL-01, TMPL-02, TMPL-03, TMPL-04, TMPL-05, TMPL-06, TMPL-07, TMPL-08]

coverage:
  - id: D1
    description: "The consumer-rendered path (Watch snapshot, follow-mode push, mTLS CN-keyed sink health, real server stop/restart with reconnect) is proven over a real, CA-verified TLS 1.3 connection, not only bufconn/insecure credentials"
    requirement: "TMPL-05"
    verification:
      - kind: e2e
        ref: "e2e/e2e_test.go#TestE2E_WatchSnapshotOverMTLS,TestE2E_WatchPushesOnMutation,TestE2E_WatchSinkHealthKeyedByCN,TestE2E_WatchSinkSurvivesServerRestart"
        status: pass
    human_judgment: false
  - id: D2
    description: "An operator-facing guide documents render/watch end to end: sidecar fields, change-ID convergence semantics, the D-12a reload-failure outcome, all seven sink gauges, and the one-CN-per-consumer deployment requirement; render/watch are added to the CLI reference"
    requirement: "TMPL-05"
    verification:
      - kind: other
        ref: "rumdl check docs/guides/consumer-rendered-output.md docs/reference/cli.md (exit 0); rg-based field/flag/gauge existence checks in 01-08-PLAN.md acceptance criteria (all satisfied)"
        status: pass
    human_judgment: false
  - id: D3
    description: "Two manual, deployment-level verifications (resolver reload, two-node convergence) plus the restart/no-reload-storm and reload-failure-diagnosis scenarios, which require a real unbound host and a second machine"
    verification: []
    human_judgment: true
    rationale: "This environment has no unbound host and no second machine. Recorded explicitly as NOT-RUN in 01-VALIDATION.md with reason, concrete steps, and the automated coverage that does exist for each, per operator decision at the Task 3 checkpoint (mirrors phase 9's OTel-scrape precedent)."

duration: 62min
completed: 2026-08-01
status: complete
---

# Phase 1 Plan 08: Real-mTLS E2E, Operator Guide, and Phase Verification Summary

**The Watch sink is now proven end to end over a real CA-verified mTLS connection — including a genuine server stop/restart — and documented for operators; the two deployment-scale manual checks are recorded as explicitly not-run.**

## Performance

- **Duration:** 62 min
- **Tasks:** 3 (2 executed, 1 checkpoint resolved by operator decision)
- **Files modified:** 6 (1 created, 5 modified) across the two executed tasks, plus this SUMMARY and STATE/ROADMAP/REQUIREMENTS

## Accomplishments

- Wired `server.WithSinkHealth` into the e2e harness so the mTLS-CN-keyed sink-health claim is actually checkable, not merely asserted — `TestE2E_WatchSinkHealthKeyedByCN` asserts the literal `e2e-test-client` key and that it is the *only* key.
- Split e2e server lifecycle into `stopServer`/`startServer`, retaining `store`/`cfg`/`logger`/`sinkHealth` on `testEnv` so a restart rebuilds a fresh server and service over the *same* store, and redialing the client connection on every start under a stated contract.
- `TestE2E_WatchSinkSurvivesServerRestart` drives the real `router-hosts watch` command (via `commands.NewRootCmd(commands.WithWatchPolicy(...))`) through a genuine process stop and restart: byte-identical artifact during the outage, rising failure count, automatic reconnect, a rewrite carrying genuinely new content, and the failure count returning to zero.
- Raised the harness TLS floor to 1.3, matching production client credentials, so the e2e suite no longer exercises a weaker policy than any real client.
- Added the `docs/guides/consumer-rendered-output.md` operator guide and `render`/`watch` entries in `docs/reference/cli.md`.
- Recorded all four manual, deployment-scale verifications in `01-VALIDATION.md` as explicitly **NOT-RUN** (no unbound host, no second machine in this environment), each with its concrete steps and the automated coverage that does exist, per the operator's checkpoint decision.

## Task Commits

1. **Task 1: Real-mTLS Watch round trip in the e2e suite** — `e19231e` (test)
2. **Task 2: Operator guide and CLI reference for consumer-rendered output** — `9040871` (docs)
3. **Task 3: Manual verification of the two deployment-level behaviors** — checkpoint; operator selected "record as not-run" (no unbound host / no second machine in this environment). No code commit for Task 3 itself; its output is `01-VALIDATION.md`'s new record plus this SUMMARY and the state/roadmap/requirements commit below.

## Files Created/Modified

- `e2e/helpers_test.go` — `WithSinkHealth` wiring, `stopServer`/`startServer`, `collectWatchSnapshot`, TLS 1.3 floor
- `e2e/e2e_test.go` — four new Watch tests over real mTLS
- `docs/guides/consumer-rendered-output.md` — new operator guide
- `docs/guides/index.md`, `mkdocs.yml` — guide registered in nav
- `docs/reference/cli.md` — `render`/`watch` sections
- `.planning/phases/01-consumer-rendered-output-templates-sink/01-VALIDATION.md` — manual verification record

## Decisions Made

- `stopServer` calls `grpc.Server.Stop()` directly instead of only cancelling `Run`'s context: cancellation alone routes through `gracefulStop`'s up-to-30s drain, which would have kept the test's open stream alive through the whole simulated outage — discovered by running the test and observing "server shutdown timed out" plus a false pass on the failure-count assertion.
- The restart test seeds one host before starting the sink so its initial artifact is non-empty; an empty `.Entries` range legitimately renders empty content, which silently made the first draft's byte-identity assertion trivially true.
- The auto-regenerated `docs/reference/cli.md` was reverted in favor of a hand-maintained edit: `task docs:build`'s generator produces code fences with no language tag, failing `rumdl` (pre-existing, unrelated to this plan's scope) — filed as [#402](https://github.com/fzymgc-house/router-hosts/issues/402) rather than committing lint-failing content or bypassing the gate.
- `docs/reference/api.md` was reverted after `task docs:build`, per the plan's own instruction (known unrelated churn, same precedent phase 9 set).
- All four manual verifications recorded as NOT-RUN rather than claimed done or narrowed into "covered by automated tests" — see `01-VALIDATION.md`'s new "Manual Verification Record" section for the full per-item scoping.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] `stopServer` relying on context cancellation alone did not produce a real outage**

- **Found during:** Task 1's own verification (`task test:e2e` on `TestE2E_WatchSinkSurvivesServerRestart`)
- **Issue:** `Server.Run`'s `ctx.Done()` path calls `gracefulStop`, which drains for up to `GracefulShutdownTimeout` (30s) before forcing anything — keeping the test's open `WatchHosts` stream alive well past the test's 10s failure-count wait, so the outage assertion failed (and would have silently passed if the wait were longer, defeating the whole scenario)
- **Fix:** `stopServer` calls `env.srv.Stop()` (immediate `grpc.Server.Stop`) before/alongside cancelling the context, matching what a real process stop actually does
- **Files modified:** `e2e/helpers_test.go`
- **Commit:** `e19231e` (Task 1 commit)

**2. [Rule 3 — Blocking] Generated `docs/reference/cli.md` fails `rumdl`**

- **Found during:** Task 2's own verification (`task docs:build` then `rumdl check`)
- **Issue:** `scripts/generate-cli-docs.sh`'s output wraps `--help` text in bare ` ``` ` code fences with no language tag, producing ~29 `rumdl` findings (MD040/MD012) — the plan's own acceptance criterion requires `rumdl check` to exit 0
- **Fix:** Reverted the auto-regenerated file and re-applied the hand-maintained `render`/`watch` table edit, which documents the same flags and passes `rumdl` cleanly; filed [#402](https://github.com/fzymgc-house/router-hosts/issues/402) to fix the generator so it can be regenerated normally in the future
- **Files modified:** `docs/reference/cli.md`
- **Commit:** `9040871` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking-but-package-manager-exempt-class workaround with a filed issue)
**Impact on plan:** Both fixes were necessary for the plan's own acceptance criteria to hold (a real outage window; a passing `rumdl` gate). No scope creep — no production behavior changed, no new dependencies.

## Issues Encountered

- Initial draft of `TestE2E_WatchSinkSurvivesServerRestart` did not seed any host data before starting the watch command; the resulting empty-`.Entries` render produced a legitimately empty (zero-length) artifact, so the "artifact appeared" wait succeeded trivially and the subsequent `require.NotEmpty` failed for the right reason but on the wrong turn of the test. Fixed by seeding one host before starting the sink.
- `task docs:build` regenerates both `docs/reference/api.md` and `docs/reference/cli.md`; only `api.md`'s churn was expected per the plan text. `cli.md`'s regeneration turned out to conflict with the repo's own lint gate — see Deviation 2 above.

## User Setup Required

None — no external service configuration required. Two of the four manual verification items describe real-infrastructure steps (a live unbound host, a second machine) that an operator with such infrastructure can execute later using the exact steps recorded in `01-VALIDATION.md`.

## Next Phase Readiness

Phase 01 (consumer-rendered-output-templates-sink) is now 9/9 plans complete. All eight TMPL requirements are implemented with automated coverage, including a real-mTLS e2e proof of the sink path added by this plan. `task ci`, `task test:coverage:ci` (86.2%), and `task test:e2e` are all green. The two deployment-scale behaviors requiring real infrastructure (resolver reload, two-node convergence, and the restart/no-reload-storm and reload-failure-diagnosis scenarios that ride along with them) are recorded as not-run in `01-VALIDATION.md` with concrete steps for a future operator, rather than claimed done. No blockers to closing the milestone.

---

*Phase: 01-consumer-rendered-output-templates-sink*
*Completed: 2026-08-01*
