---
phase: 01-consumer-rendered-output-templates-sink
verified: 2026-08-01T21:30:00Z
status: passed
score: 7/7 roadmap success criteria verified; 8/8 requirement IDs satisfied
behavior_unverified: 0
overrides_applied: 0
---

# Phase 1: Consumer-Rendered Output (templates + sink) Verification Report

**Phase Goal:** A consumer defines its own output format and keeps it current, so one
stateful server feeds N independent consumers and new resolver formats stop requiring
an upstream release.
**Verified:** 2026-08-01T21:30:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A caller supplies a template and receives host data rendered through it, with no code change to this project | VERIFIED | `internal/client/commands/render.go`, `internal/client/template/template.go` exist and are wired to `WatchHosts(follow=false)`; `render_test.go` exercises the full path. `task test` green. |
| 2 | Field set is documented/versioned; undefined-key reference fails loudly | VERIFIED | `docs/reference/template-contract.md` (nav-reachable from `mkdocs.yml:82` and `docs/reference/index.md:8`) documents `.Entries[].IPAddress/Hostname/Aliases/Tags/Comment`, `.Count`, `.GeneratedAt`, `.ContractVersion`, `.ChangeID`. `internal/client/template/template.go` uses `text/template.Option("missingkey=error")` semantics proven by `TestUndefinedKey*` in `template_test.go`. |
| 3 | Render/write failure leaves artifact byte-identical; concurrent reader never sees a partial file | VERIFIED | `internal/atomicfile/atomicfile.go` (temp-file + `os.Rename`), used by both server generators and client render/watch/sidecar paths (`sinkstatus.go`, `watch.go`). `TestWatch_HookFailureRetainsNewArtifact`, atomicfile tests pass. |
| 4 | Sink mode reflects a mutation without polling and recovers after connection interruption without a truncated artifact | VERIFIED | Server: `internal/server/changenotify.go` + `watch.go` wake watchers with no polling (`TestService_WatchHosts_...`). Client: `internal/client/commands/watch.go` reconnect/backoff (`runWatch`, policy-driven). End-to-end proof: `e2e/e2e_test.go:686 TestE2E_WatchSinkSurvivesServerRestart` — real mTLS, real server stop/restart, asserts byte-identical artifact during outage and automatic recovery. Orchestrator confirmed this test passes (`task test:e2e` exit 0). |
| 5 | Client cannot be driven OOM: bounded wire messages, client backpressure, refuses unbounded response; server-side materialization explicitly out of scope (amended TMPL-06, #400) | VERIFIED | `internal/server/watch.go` sends one entry per message; `internal/server/service.go:642-677` chunks `ExportHosts` at 64 KiB. `internal/client/client.go`/`commands/*.go` enforce `MaxStreamEntries`/`MaxStreamBytes` (check-before-append, refuse-not-truncate) — confirmed in `01-REVIEW.md` and by reading `client.go`. `docs/reference/template-contract.md:187-192` and `01-04-SUMMARY.md:44` explicitly disclaim "constant server memory"; grep for "O(1) memory" / "constant memory" across docs/summaries returns nothing that makes the claim itself (only the disclaiming text). Issue #400 exists, open, and correctly scoped to the deferred storage-layer half. |
| 6 | Every snapshot carries a change ID naming server state; consumers/convergence comparable | VERIFIED | `internal/eventid` + `internal/storage/sqlite/eventstore.go`'s in-transaction ordering guard (`insertEvent`) ensure `MAX(event_id)` is monotonic; `LatestEventID` is read strictly before `ListAll` in `sendSnapshot` (`internal/server/watch.go:88-101`), confirmed by direct code read and by running `TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries` (PASS). Sink health registry compares rendered vs. current change ID as a bounded gauge (`sinkmetrics.go`). e2e `TestE2E_WatchSnapshotOverMTLS` proves two requests over unchanged state return the same ID. |
| 7 | Existing `unbound_conf_path`/`ExportHosts` format behavior unchanged, proven by existing tests still passing | VERIFIED | `git log` shows only `internal/server/hostsfile_test.go` moved (atomic writer extraction, `0457433`) with no format-string edits to `unboundconf.go`/`dnsmasqconf.go`; targeted re-run `TestService_ExportHosts*` passes; full `task test` (16 packages) and `task test:coverage:ci` (86.2%) green per orchestrator run. |

**Score:** 7/7 roadmap success criteria verified. 0 behavior-unverified.

### Requirements Coverage (TMPL-01..08)

| Requirement | Source Plan(s) | Status | Evidence |
|---|---|---|---|
| TMPL-01 | 01-01, 01-08 | SATISFIED | `render` command + template pipeline exist and are exercised end-to-end (unit + e2e). |
| TMPL-02 | 01-01, 01-02, 01-08 | SATISFIED | Documented field set (`docs/reference/template-contract.md`), sanitizing FuncMap (`internal/sanitize`) wired to both server (`hostsfile.go:127` delegates to `sanitize.CommentField`) and client template FuncMap (`template.go:70`). |
| TMPL-03 | 01-01, 01-02, 01-07, 01-08 | SATISFIED | Undefined-key failure, contract-version gate before render, byte-identical-on-failure all covered by named passing tests. |
| TMPL-04 | 01-01, 01-08 | SATISFIED | `internal/atomicfile` is the single write-and-rename implementation shared by server generators and client. |
| TMPL-05 | 01-05 (primitives only, explicitly not marked), 01-06 (server half, explicitly not marked), 01-07 (client half, marked complete), 01-08 (e2e proof) | SATISFIED | Both 01-05 and 01-06 SUMMARYs explicitly decline to mark TMPL-05 complete, stating the other half is missing — confirmed by reading both SUMMARY.md files verbatim. 01-07 delivers `watch`, reconnect/backoff, sidecar status. Closing claim validated end-to-end by `TestE2E_WatchSinkSurvivesServerRestart` (real mTLS, real restart, byte-identical assertion) — this is not merely a ticked box, the behavior is proven by a passing behavioral test the verifier independently re-ran evidence for (test enumerated and present; orchestrator ran full e2e suite green). |
| TMPL-06 | 01-04, 01-06 | SATISFIED (as amended) | Requirement text in `REQUIREMENTS.md:74` matches the 2026-07-31 amendment (bounded wire messages + client backpressure; storage-layer laziness explicitly deferred to #400). No artifact inspected claims constant/O(1) server memory — the only occurrences of that phrase in the diff are the docs' explicit disclaimers. `store.ListAll` still folds full event history (`internal/storage/sqlite/projection.go:19`), consistent with the deferral. |
| TMPL-07 | 01-03 | SATISFIED | Entry-count + byte-budget caps enforced at all four collecting call sites, check-before-append (confirmed via `01-REVIEW.md` and direct read of `9f8c520`'s diff description); config-driven with safe defaults. |
| TMPL-08 | 01-09, 01-01, 01-05, 01-06, 01-07 | SATISFIED | Monotonic event-ID generator + in-transaction guard (`eventid.go`, `eventstore.go`); `LatestEventID` before `ListAll` ordering (H1) confirmed by direct code read; behavioral test `TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries` passes. Zero-ULID-on-empty-log sentinel confirmed (`storage.ZeroChangeID`). |

No orphaned requirements — all 8 IDs in `REQUIREMENTS.md`'s "Consumer-Rendered Output" section are claimed by at least one plan's frontmatter and traced above.

### Required Artifacts (spot-checked, all three levels)

| Artifact | Expected | Status | Details |
|---|---|---|---|
| `internal/client/template/template.go` | Template contract, version gate, sanitize FuncMap | VERIFIED | Exists, substantive, wired into `render.go`/`watch.go` |
| `internal/atomicfile/atomicfile.go` | Shared write-and-rename | VERIFIED | Exists, used by server generators + client render/watch/sidecar |
| `internal/server/watch.go` | WatchHosts RPC, snapshot + follow mode | VERIFIED | `sendSnapshot` confirmed deriving changeID before ListAll by direct read |
| `internal/server/changenotify.go` | Wake watchers on mutation, no polling | VERIFIED | Exists; `changenotify_test.go` covers coalescing behavior |
| `internal/client/commands/watch.go` | Sink CLI: reconnect, backoff, sidecar | VERIFIED | Backoff/jitter/policy code confirmed by direct read; e2e proves recovery |
| `internal/eventid/eventid.go`, `internal/storage/sqlite/eventstore.go` | Monotonic change ID | VERIFIED | In-transaction guard confirmed; named test passes |
| `docs/reference/template-contract.md` | Contract v1 docs | VERIFIED | Nav-reachable, contains lower-bound/amended-TMPL-06 language matching REQUIREMENTS.md |
| `internal/sanitize/sanitize.go` | Shared CR/LF sanitizer | VERIFIED | Single implementation, delegated to by both server and client |

### Key Link Verification

| From | To | Via | Status |
|---|---|---|---|
| `render`/`watch` command | `WatchHosts` RPC | gRPC stream, one-shot or follow | WIRED |
| `sendSnapshot` | `store.LatestEventID` → `store.ListAll` | Ordering confirmed in source (H1 invariant) | WIRED |
| `regenerateOutputs` / `CompactAggregates` | `changenotify` | Confirmed as the two notify call sites per `01-REVIEW.md` | WIRED |
| `template.Parse` FuncMap | `internal/sanitize.CommentField` | Same function server uses via `hostsfile.go:127` | WIRED |
| `docs/reference/template-contract.md` | mkdocs nav | `mkdocs.yml:82`, `docs/reference/index.md:8` | WIRED |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|---|---|---|---|
| Change-ID-before-ListAll ordering (H1) | `task test -- -run TestService_WatchHosts_ChangeIDIsLowerBoundOnEntries ./internal/server/...` | PASS | VERIFIED |
| D-21 redundant-render skip | `task test -- -run TestWatch_SkipsRedundantRenderOnSameChangeID ./internal/client/commands/...` | PASS | VERIFIED |
| Existing ExportHosts format regression | `task test -- -run TestService_ExportHosts ./internal/server/...` | PASS | VERIFIED |
| Full suite (already run by orchestrator, cited not re-run) | `task test`, `task test:coverage:ci`, `task test:e2e` | PASS / 86.2% / PASS | VERIFIED |

### Anti-Patterns Found

Scanned all 62 `.go` files changed in the phase (`git diff --name-only ac78ca3..HEAD -- '*.go'`) for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER` and "not yet implemented"/"coming soon"/"placeholder" phrasing. Zero hits in phase-modified code, except one pre-existing test comment (`internal/storage/sqlite/sqlite_test.go:351`, "Alias search is not yet implemented") describing an unrelated, out-of-phase-scope alias-search limitation, not a phase-1 stub. No debt markers requiring a gate.

One Info-level finding from `01-REVIEW.md` (IN-01: unused timestamp parameter in `recordReloadFailure`, documented as deliberate). Not a blocker.

### Skeptical-Brief Findings (explicit answers to each flagged concern)

1. **TMPL-05 closing claim** — genuinely true end-to-end. 01-05 and 01-06 both explicitly declined completion (verified by reading both SUMMARY.md verbatim); 01-07 delivers the client half; `TestE2E_WatchSinkSurvivesServerRestart` proves the full loop over real mTLS with a real server stop/restart.
2. **TMPL-06 amendment** — `REQUIREMENTS.md:74` text matches what shipped; no artifact claims constant/O(1) server memory; the docs and 01-04-SUMMARY explicitly disclaim it. Issue #400 exists and is correctly scoped.
3. **Four manual verifications recorded NOT-RUN** — confirmed honest in `01-VALIDATION.md` lines 103-234: each of the four items states "Status: NOT-RUN. Reason: no unbound host / no second machine available", lists concrete future-operator steps, and separately states what automated coverage DOES exist without claiming it substitutes. Not quietly reinterpreted as satisfied.
4. **01-03 RED/GREEN split** — confirmed violated. Commits `c66719e` (fix), `a32c5a1` (feat), `9f8c520` (fix) each contain both new tests and implementation in the same commit (diff stats show `_test.go` and non-test files changed together), unlike every other plan in the phase which pairs a standalone `test(...)` commit before its `feat/fix(...)` commit. This is a genuine TDD-gate miss; the gate didn't catch it because `tddPlans: 0` (no plan carries `type: tdd` frontmatter — all nine plans are `type: execute`). Not phase-goal-blocking (the code is tested, just not test-first), but noted per instructions.
5. **`.planning/WINDOWS.md`** — confirmed 1 open entry (id 1, phase 01, kind `deviation`, file `internal/client/commands/watch_test.go`, a test-file-location deviation from plan 01-07 Task 1→2). `open_count: 1` in frontmatter. `/gsd-ship` will block until waived or fixed — this is a process gate, not a goal-achievement gap, but it is called out here so it isn't missed before shipping.
6. **Deferred follow-up issues** — #400 (atomic-read... no, cursor-based lazy storage read), #401 (atomic `{entries, latestEventID}` snapshot read), #402 (CLI docs generator vs. rumdl) all confirmed real, OPEN, and their bodies match what the SUMMARYs/docs cite them for. #400 is also cross-referenced correctly in `docs/reference/template-contract.md` and `REQUIREMENTS.md`; #401 is cross-referenced correctly in `internal/server/watch.go:86`.

## Human Verification Required

None required to reach `passed` for phase-goal achievement — all roadmap success criteria and requirement IDs have direct code/test evidence. The four manual deployment verifications in `01-VALIDATION.md` remain legitimately NOT-RUN (real multi-host infrastructure unavailable in this environment) but are honestly recorded as such with concrete future-operator steps; they do not block phase completion since the phase's own validation plan scoped them as deployment-level properties outside a single-node test's reach, and this was an explicit, documented operator decision rather than an oversight.

## Process Notes (not goal blockers, but must not be missed before shipping)

- `.planning/WINDOWS.md` has `open_count: 1` — `/gsd-ship` blocks until it is waived (`gsd-tools windows waive 1 "<reason>"`) or fixed.
- Plan 01-03 did not follow the RED/GREEN commit-split convention despite `workflow.tdd_mode=true`; no plan in this phase carries `type: tdd` frontmatter, so the gate had no plan to check it against. Consider flagging for future phases if strict TDD commit splitting is required project-wide.
- ROADMAP.md's Phase 1 checkbox (line 58) and status table (line 132, "In Progress") have not yet been flipped to shipped/complete — expected, since that update normally follows a passing verification.

### Gaps Summary

No gaps found. All 7 roadmap success criteria and all 8 TMPL requirement IDs are backed by direct, independently-verified code and passing-test evidence, not merely SUMMARY.md narrative. The two process items above (WINDOWS.md open entry, missing `type: tdd` plan classification) are real but do not block phase-goal achievement — they are surfaced for the ship step.

---

_Verified: 2026-08-01T21:30:00Z_
_Verifier: Claude (gsd-verifier)_
