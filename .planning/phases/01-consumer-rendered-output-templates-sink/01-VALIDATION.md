---
phase: 1
slug: consumer-rendered-output-templates-sink
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-31
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Derived from `01-RESEARCH.md` § Validation Architecture.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Go stdlib `testing` + `stretchr/testify` (assert/require) + `pgregory.net/rapid` (property-based; already a direct dependency) |
| **Config file** | none — plain `go test`, invoked via Taskfile |
| **Quick run command** | `task test -- -run <TestName> ./internal/<pkg>/` |
| **Full suite command** | `task test` (== `go test -race -count=1 ./...`, `Taskfile.yml:21-26`) |
| **Estimated runtime** | full suite ~60–90s with `-race` |

> **Command discipline (memory `j8eyp0njgz`):** Go's `-run` is an **unanchored regex** over the
> test function name. A `Test<Noun>` pattern misses every `Test<Verb><Noun>` sibling — e.g.
> `-run 'TestTemplate'` does NOT match `TestRenderTemplate_...`. Before recording any quick-run
> command below as green, enumerate the inventory with `rg '^func Test' <pkg>/*_test.go`, run the
> candidate with `-v`, and confirm the `--- PASS` count equals the inventory count. Exit status
> proves nothing here — unmatched tests never run at all.

---

## Sampling Rate

- **After every task commit:** targeted `task test -- -run <TestName> <package>`
- **After every plan wave:** `task test` (full suite, `-race`)
- **Before `/gsd-verify-work`:** `task test:coverage:ci` green (80% threshold) **and** `task test:e2e`
  (build tag `e2e`, real mTLS, in-process) extended with at least one Watch-RPC round trip
- **Max feedback latency:** < 15s for targeted runs

---

## Per-Task Verification Map

Task IDs are assigned by the planner; this table maps requirements to their proving command and is
filled in per task during planning.

| Req ID | Behavior | Threat Ref | Test Type | Automated Command | File Exists | Status |
|--------|----------|------------|-----------|-------------------|-------------|--------|
| TMPL-01 | Template renders host data with no upstream code change | — | unit | `task test -- -run Template_Render ./internal/client/template/` | ❌ W0 | ⬜ pending |
| TMPL-02 | Documented/versioned field set exposed (`.Entries[].IPAddress/Hostname/Aliases/Tags/Comment`, `.Count`, `.GeneratedAt`, `.ContractVersion`) | — | unit | `task test -- -run TemplateData_FieldSet ./internal/client/template/` | ❌ W0 | ⬜ pending |
| TMPL-02 | Template declaring an incompatible contract version is refused **before** render (D-05) | — | unit | `task test -- -run ContractVersion ./internal/client/template/` | ❌ W0 | ⬜ pending |
| TMPL-03 | Undefined key fails loudly rather than rendering empty | — | unit | `task test -- -run UndefinedKey ./internal/client/template/` | ❌ W0 | ⬜ pending |
| TMPL-03 | Render or write failure leaves the prior artifact **byte-identical** (D-12) | T-1-03 | unit | `task test -- -run FailurePreservesArtifact ./internal/client/commands/` | ❌ W0 | ⬜ pending |
| TMPL-04 | Atomic write-and-rename; a concurrent reader never observes a partial file | — | unit | `task test -- -run AtomicWrite ./internal/atomicfile/` | ⚠️ exists at `internal/server/hostsfile_test.go:181-227`; **moves** this phase | ⬜ pending |
| TMPL-05 | Sink reflects a host mutation without polling | — | integration (bufconn) | `task test -- -run Watch ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-05 | Sink recovers after connection interruption without emitting a truncated artifact | T-1-02 | integration (bufconn) | `task test -- -run ReconnectNoTruncation ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-06 | Stream yields per-entry rather than materializing the whole payload | — | integration | `task test -- -run StreamsPerEntry ./internal/server/` | ❌ W0 | ⬜ pending |
| TMPL-07 | Bounded client collection; clear error past the cap, **never** silent truncation | T-1-01 | unit | `task test -- -run CapExceeded ./internal/client/commands/` | ❌ W0 | ⬜ pending |
| D-09/D-10 | Server exposes per-consumer last-seen keyed by mTLS CN; survives stream close | — | unit | `task test -- -run SinkLastSeen ./internal/server/` | ❌ W0 | ⬜ pending |
| (regression) | `unbound_conf_path` and existing `ExportHosts` format strings unchanged | — | unit | `task test -- -run ExportHosts ./internal/server/` | ✅ exists | ⬜ pending |
| (regression) | Existing `unbound`/`dnsmasq`/hosts generators unaffected by the `atomicWriteFile` move | — | unit | `task test ./internal/server/` | ✅ exists | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `internal/atomicfile/atomicfile_test.go` — relocated from `internal/server/hostsfile_test.go:181-227`; covers TMPL-04. The four existing tests (new-file, overwrite, temp cleanup, invalid path) move with the implementation.
- [ ] `internal/client/template/template_test.go` — new; covers TMPL-01, TMPL-02, TMPL-03 (struct-field typo failure, contract-version mismatch refusal, `.Count`/`.GeneratedAt` presence)
- [ ] `internal/server/watch_test.go` (or extend `service_test.go`) — new bufconn-based bidirectional test harness for TMPL-05 and TMPL-06
- [ ] `internal/client/commands/watch_test.go` — new; covers TMPL-07's cap error path and the D-12 byte-identical-on-failure guarantee at the CLI layer
- [ ] `e2e/` — extend with a real-mTLS Watch round trip (build tag `e2e`) once the Watch RPC exists

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Post-write exec hook actually reloads a real resolver | TMPL-05 / D-16 | Requires a live `unbound`/`dnsmasq` process; the automated suite asserts the hook is *invoked* with the right argv, not that a third-party daemon reloaded | Run the sink against a local unbound with `--exec 'unbound-control reload'`, mutate a host, confirm `dig` reflects the change without operator action |
| Two independent resolver nodes stay consistent | TMPL-01 / phase goal | Needs two hosts; the phase's success criterion is a deployment property, not a unit-testable one | Point two sinks at one server with the same template; mutate a host; confirm both artifacts converge and both resolvers answer identically |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or a Wave 0 dependency
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Every quick-run `-run` pattern empirically confirmed against its `rg '^func Test'` inventory (see Command discipline above)
- [ ] Feedback latency < 15s for targeted runs
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
