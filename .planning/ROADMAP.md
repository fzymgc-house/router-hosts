# Roadmap: router-hosts

## Overview

router-hosts is an event-sourced, mTLS-secured DNS control plane with a CLI/TUI
and a Kubernetes operator. Milestones v0.10.13 through v0.12.0 built the baseline
and drove toward the north star — operator / Gateway-API parity and hands-off
cluster integration — finishing with hook reliability. v0.13.0 opened a second
axis: output rendering moved from the server to the consumer, so one stateful
server feeds N independent consumers without accreting a per-resolver output
format for each.

**v0.14.0 does not open a third axis.** It finishes what v0.13.0 deliberately
deferred: make the three e2e tiers gate merges, containerize the deployment
verifications that needed a second physical machine and run them green, and stop
`store.ListAll` folding full event history into memory before the first byte
ships. Every requirement in this milestone closes a gap this project already
wrote down.

> **Phase numbering restarted at v0.13.0 and again at v0.14.0.** Milestones
> v0.10.13–v0.12.0 used a single continuous sequence (phases 1–9). Where an
> archived document says "Phase 1" it means Event-Sourced Host Core; in v0.13.0
> it means Consumer-Rendered Output; in this milestone it means CI Gating for
> the e2e Tiers. Historical phase detail and phase directories are archived
> under `milestones/<version>-ROADMAP.md` and `milestones/<version>-phases/`.

## Milestones

- ✅ **v0.10.13 — v1 Shipped Baseline** — Phases 1–6 (shipped pre-GSD, reconstructed 2026-07-07)
- ✅ **v0.11.0 — K8s-Native Automation** — Phases 7–8 (shipped 2026-07-30, PR #381)
- ✅ **v0.12.0 — Hook Reliability & Metrics** — Phase 9 (shipped 2026-07-31, PR #389)
- ✅ **v0.13.0 — Consumer-Owned Output** — Phase 1 (shipped 2026-08-02, PR #404)
- 🚧 **v0.14.0 — Verification & Lazy Reads** — Phases 1–3 (in progress, started 2026-08-02)

## Phases

<details>
<summary>✅ v0.10.13 — v1 Shipped Baseline (Phases 1–6) — SHIPPED</summary>

Archived: [`milestones/v0.10.13-ROADMAP.md`](milestones/v0.10.13-ROADMAP.md)

- [x] Phase 1: Event-Sourced Host Core
- [x] Phase 2: Certificate Lifecycle
- [x] Phase 3: Kubernetes Operator
- [x] Phase 4: Observability
- [x] Phase 5: Split-Horizon DNS Output
- [x] Phase 6: Aggregate Compaction

</details>

<details>
<summary>✅ v0.11.0 — K8s-Native Automation (Phases 7–8) — SHIPPED 2026-07-30</summary>

Archived: [`milestones/v0.11.0-ROADMAP.md`](milestones/v0.11.0-ROADMAP.md)

- [x] Phase 7: Gateway API Support (6/6 plans) — completed 2026-07-26
- [x] Phase 8: Service Controller (5/5 plans) — completed 2026-07-30

</details>

<details>
<summary>✅ v0.12.0 — Hook Reliability & Metrics (Phase 9) — SHIPPED 2026-07-31</summary>

Archived: [`milestones/v0.12.0-ROADMAP.md`](milestones/v0.12.0-ROADMAP.md)

- [x] Phase 9: Hook Reliability & Metrics (5/5 plans) — completed 2026-07-31

</details>

<details>
<summary>✅ v0.13.0 — Consumer-Owned Output (Phase 1) — SHIPPED 2026-08-02</summary>

Archived: [`milestones/v0.13.0-ROADMAP.md`](milestones/v0.13.0-ROADMAP.md)
Audit: [`milestones/v0.13.0-MILESTONE-AUDIT.md`](milestones/v0.13.0-MILESTONE-AUDIT.md)

- [x] Phase 1: Consumer-Rendered Output (templates + sink) (11/11 plans) — completed 2026-08-01

Caller-supplied templates rendered client-side, one-shot and as a continuous
sink, over a new `WatchHosts` RPC. Requirements TMPL-01 through TMPL-08, all
satisfied. Two gap-closure plans (01-10, 01-11) added after UAT found G-01-1.

</details>

### 🚧 v0.14.0 — Verification & Lazy Reads (Phases 1–3)

**Milestone Goal:** The three e2e tiers gate merges, the hardware-dependent
deployment verifications run green in containers on one machine, and streaming
reads stop materializing full event history server-side.

**Phase Numbering:**

- Numbering is milestone-local from v0.13.0 onward and restarts at 1 each milestone
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (1.1, 1.2): Urgent insertions (marked INSERTED)

**v0.14.0 phases:**

- [x] **Phase 1: CI Gating for the e2e Tiers** - All three tiers run in CI, gate merges, and are proven able to fail (completed 2026-08-03)
- [ ] **Phase 2: Cursor-Based Lazy Storage Reads** - `HostProjection` pages by aggregate ID so streaming stops folding full event history into memory
- [ ] **Phase 3: Containerized Deployment-Verification Harness** - Real unbound plus two sink containers run UAT 42 and the four blocked deployment checks green

## 🚧 v0.14.0 — Verification & Lazy Reads (Phase Details)

### Phase 1: CI Gating for the e2e Tiers

**Goal**: A change cannot reach `main` without all three e2e tiers having actually run against it — and each gate has been watched going red, so "never observed to fail" is ruled out.
**Depends on**: Nothing in this milestone. The three tiers already exist and pass from v0.13.0 Phase 1; this is wiring, not new test code.
**Requirements**: CI-01, CI-02, CI-03, CI-04, VRFY-05
**Success Criteria** (what must be TRUE):

1. Opening a PR runs the fast `e2e` tier, and merging to `main` is blocked until `docker_e2e` and `proc_e2e` have also run and passed — reported through a single aggregated required check that fails if any tier fails, so no merge can land on a tier nobody made required. `proc_e2e` is required because it is the only tier that observes the CLI-flag→config seam that G-01-1 shipped through
2. A container tier on a host without Docker fails the job loudly instead of skipping, and `proc_e2e` builds the binary fresh in the same job rather than restoring a cached `bin/` — so neither tier can report green while testing nothing
3. Each new gate has been demonstrated **red**: a deliberately reintroduced regression is pushed, the failing run is linked, and only then is the gate accepted
4. Every readiness wait in `e2e`, `docker_e2e`, and `proc_e2e` runs through one shared bounded-timeout polling helper — the bare `time.Sleep` synchronizations in `e2e/e2e_test.go` are gone, and a timeout is reported as a failure rather than falling through to an assertion

**Plans**: 5/5 plans executed

Plans:
**Wave 1**

- [x] 01-01-PLAN.md — Tracer: wait helper end-to-end through one call site, the e2e-fast job, and the aggregator, plus the e2e-tier set-equality invariant test

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 01-02-PLAN.md — Convert the remaining twelve readiness waits in e2e_test.go, proc_harness_test.go, and helpers_test.go; mark the intentional outage hold
- [x] 01-03-PLAN.md — Env-gated Docker precondition (dockergate + RH_E2E_REQUIRE_DOCKER), waitForDockerServer conversion, corrected testing docs

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 01-04-PLAN.md — Add the e2e-docker and e2e-proc jobs and complete ci-go-complete so one required check consumes all three tiers

**Wave 4** *(blocked on Wave 3 completion)*

- [x] 01-05-PLAN.md — Four negative controls proving each gate can go red, plus the out-of-repo [ci skip] follow-up decision

**Why first**: zero shipped-source risk, closes #403, and establishes the CI job
pattern the later phases reuse. It also puts the cursor refactor (Phase 2) under
e2e coverage that actually gates, rather than repeating the G-01-1 blind spot.

**VRFY-05 placement note**: the shared wait-strategy helper is a `VRFY-*`
requirement but lands here, not in Phase 3. Two of its three named consumers
(`docker_e2e`, `proc_e2e`) become merge gates in this phase, and the tree today
carries five separate ad-hoc pollers (`waitForServer`, `waitForDockerServer`,
`waitForProcAddr`, `waitForFileContent`, `waitForSidecar`) plus six bare
`time.Sleep` calls in the `e2e` tier. Building the helper in Phase 3 would mean
Phase 1 reinvents it first — exactly what the requirement forbids.

### Phase 2: Cursor-Based Lazy Storage Reads

**Goal**: A read of the host set no longer requires the server to replay every aggregate's full event log into memory before the first byte ships — and the memory claim is measured, not asserted.
**Depends on**: Phase 1 (not a build dependency — sequenced so this API-surface change lands under e2e tiers that actually gate merges)
**Requirements**: LAZY-01, LAZY-02, LAZY-03, LAZY-04
**Success Criteria** (what must be TRUE):

1. `storage.HostProjection` exposes a cursor-based read keyed on aggregate ID (keyset, never `OFFSET`), and a caller pages through the complete entry set without the store folding every aggregate's history into memory at once. This is a published interface change, not an internal optimization
2. A measured benchmark (`AllocsPerRun`/memstats) against a 10k+ entry fixture records a concrete number showing `ExportHosts`/`WatchHosts` peak allocation tracking page size rather than total event-log size. The claim is never made from API shape — TMPL-06 already had to be publicly amended for exactly that overreach
3. Compacting an aggregate while a cursor sits inside its pre-compaction history leaves the reader at that aggregate's `HostCompacted` seed event at the preserved OCC version (ADR router-hosts-v5b), documented and pinned by a test rather than left implicit
4. Rendered output is byte-identical before and after the change for every format, so no consumer template and no pinned fixture breaks

**Plans**: 6 plans

Plans:
**Wave 1**

- [ ] 02-01-PLAN.md — Capture every byte-identity golden before any behavior change

**Wave 2** *(blocked on Wave 1 completion)*

- [ ] 02-02-PLAN.md — Tracer: ListPage published on HostProjection, wired end-to-end through WatchHosts

**Wave 3** *(blocked on Wave 2 completion)*

- [ ] 02-03-PLAN.md — Compaction-vs-cursor conformance tests and the documented read contracts
- [ ] 02-04-PLAN.md — Stream-render ExportHosts json/csv; descope hosts; take the free-win migrations

**Wave 4** *(blocked on Wave 3 completion)*

- [ ] 02-05-PLAN.md — Amend the memory claim, then measure it with a peak-heap benchmark

**Wave 5** *(blocked on Wave 4 completion)*

- [ ] 02-06-PLAN.md — Gate the benchmark tier in CI and prove it RED on a Linux runner

**Highest-risk requirement**: LAZY-02. The cursor is necessary but not
sufficient — `ExportHosts`' `hosts` and `json` formats sort globally by
IP-then-hostname before rendering, so a cursor at the read layer does not by
itself bound their memory. Whether those formats are descoped (left materialized,
with the residual O(N entries) named explicitly) or the sort is restructured is a
**planning decision that must be made before the benchmark is written**, not
discovered while writing it.

**Explicitly out of scope**: a materialized or indexed read model for sorted
pagination, generic multi-writer gap detection, and exactly-once delivery
guarantees — all three are recorded Out of Scope in REQUIREMENTS.md. A
cross-call server-side cache or snapshot would reintroduce the first by
accident.

### Phase 3: Containerized Deployment-Verification Harness

**Goal**: The deployment verifications that needed a second physical machine run green on one machine, retiring v0.13.0 Phase 1's permanent `uat-passed: false`.
**Depends on**: Phase 1 (reuses the shared readiness helper and the CI job pattern), Phase 2 (validates a settled read path rather than a moving target)
**Requirements**: VRFY-01, VRFY-02, VRFY-03, VRFY-04
**Success Criteria** (what must be TRUE):

1. An operator runs the deployment-verification suite on a single machine — locally and in CI — against a real unbound container plus two independent sink containers on a shared Docker network, with no second physical host anywhere in the path
2. The resolver-reload check queries the running unbound container and asserts a **real DNS answer** for the regenerated name, and asserts that an unmanaged sibling name still resolves normally — no zone-wide NXDOMAIN leak, per ADR router-hosts-bzg. "The file changed" or "the container is healthy" does not satisfy this
3. The two-node convergence check forces a pre/post state difference and then asserts both sinks report the same monotonic change ID (TMPL-08), so "converged" is distinguishable from "never diverged" — and a timeout is recorded as a failure, never as success
4. UAT test 42 (resolver reload plus two-node convergence) and the four manual deployment checks from plan 01-08 have **executed and passed** in the harness, and v0.13.0 Phase 1 no longer reports `uat-passed: false`

**Plans**: TBD

Plans:

- [ ] TBD (run `/gsd-plan-phase 3`)

**The bar is green, not built.** Criterion 4 is the milestone's sharpest
acceptance line: a harness that exists and runs but has not retired v0.13.0
Phase 1's `uat-passed: false` leaves this milestone's stated goal unmet. The
predicate counts only `pass`/`passed`, so a recorded `not-run` still fails it.

**Explicitly out of scope**: a nightly-scheduled e2e cadence and a
flake-quarantine convention — both recorded Out of Scope in REQUIREMENTS.md.
Two gating events only (PR, merge to `main`).

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3. The three capabilities have no hard
build dependency on one another; this order is chosen to de-risk, not because it
is forced. CI wiring first (zero shipped-source risk, establishes the job
pattern), then the cursor refactor under real gating coverage, then the harness
against a settled read path.

**Current milestone (v0.14.0):**

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. CI Gating for the e2e Tiers | 5/5 | Complete    | 2026-08-03 |
| 2. Cursor-Based Lazy Storage Reads | 0/TBD | Not started | - |
| 3. Containerized Deployment-Verification Harness | 0/TBD | Not started | - |

**Shipped (previous milestones):**

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Event-Sourced Host Core | v0.10.13 | shipped | Complete | v0.10.13 |
| 2. Certificate Lifecycle | v0.10.13 | shipped | Complete | v0.10.13 |
| 3. Kubernetes Operator | v0.10.13 | shipped | Complete | v0.10.13 |
| 4. Observability | v0.10.13 | shipped | Complete | v0.10.13 |
| 5. Split-Horizon DNS Output | v0.10.13 | shipped | Complete | v0.10.13 |
| 6. Aggregate Compaction | v0.10.13 | shipped | Complete | v0.10.13 |
| 7. Gateway API Support | v0.11.0 | 6/6 | Complete | 2026-07-26 |
| 8. Service Controller | v0.11.0 | 5/5 | Complete | 2026-07-30 |
| 9. Hook Reliability & Metrics | v0.12.0 | 5/5 | Complete | 2026-07-31 |
| 1. Consumer-Rendered Output | v0.13.0 | 11/11 | Complete | 2026-08-01 |

## Backlog

Unsequenced items parked from the v0.13.0 milestone audit
(`.planning/milestones/v0.13.0-MILESTONE-AUDIT.md`) and imported from the GitHub
issue tracker. Promote with `/gsd-review-backlog`.

**Source tracking (normative).** Every backlog item carries a `**Source:**`
field naming the GitHub issue it came from, or `none` for items with no issue.
When a backlog item is completed, its source issue MUST be closed in the same
PR that lands the work — reference it with a closing keyword (`Closes #NNN`) so
the merge closes it automatically. A backlog item MUST NOT be marked complete
while its source issue remains open. There is no automatic sync in either
direction: the ROADMAP does not import new issues and closing an issue does not
update this file, so both edges are maintained by hand.

<!-- 999.1 (GH #403, wire the e2e tiers into CI), 999.2 (close the
     hardware-dependent verification gap), and 999.3 (GH #400/#401/#23,
     server-side lazy streaming) were PROMOTED into milestone v0.14.0 on
     2026-08-02 as Phases 1, 3, and 2 respectively. Their numbers are
     intentionally left unused rather than reclaimed — backlog numbers are
     published in GitHub issue comments, so renumbering would invalidate
     external references. Sparse numbering is expected here. -->

### Phase 999.4: Event store size monitoring and warnings (BACKLOG)

**Goal:** Warn operators before an event log becomes unmaintainable. Log the
event count at server startup, warn past a configurable threshold with
compaction guidance, and document the compaction strategy. Compaction itself
shipped in Phase 6; this is the observability half that tells an operator to
run it.
**Source:** GH #16 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.5: Document container deployment with a separate hosts file (BACKLOG)

**Goal:** Document the containerized deployment pattern that writes to a
dedicated file rather than `/etc/hosts`, so no deployment needs to `chown` the
system hosts file. The default `hosts_file_path` is already
`/etc/hosts.d/router-hosts`, so the code side is settled — the guide is what is
missing.
**Source:** GH #18 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.6: Document ACME and mTLS certificate interaction (BACKLOG)

**Goal:** Explain in `docs/guides/acme.md` how an ACME-issued *server*
certificate coexists with the mTLS requirement for a *client* CA — today the
guide mentions neither mTLS nor `ca_cert_path`, so the relationship is
undocumented.
**Source:** GH #19 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.7: host import --no-follow-symlinks flag (BACKLOG)

**Goal:** Add an opt-out flag to `host import` for callers who need imports to
refuse symlinked paths. Current behavior follows symlinks intentionally for CLI
usability; this adds the stricter mode without changing the default.
**Source:** GH #37 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.8: Document client TLS configuration for ACME certificates (BACKLOG)

**Goal:** Document how a client verifies a server certificate issued by a
public CA via ACME, and how that differs from the client-certificate side of
mTLS. Overlaps 999.6; the two may merge when planned.
**Source:** GH #133 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.9: Client info command for connection diagnostics (BACKLOG)

**Goal:** Add `router-hosts info` reporting client version, server version,
connection status, and client/server/CA certificate expiry — the single command
an operator runs first when a connection misbehaves.
**Source:** GH #177 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.10: Access logging for all gRPC operations (BACKLOG)

**Goal:** Log every RPC at INFO with mTLS client identity, method, request
summary, status, and duration. The interceptor chain seam already exists
(`WithGRPCOptions`); no access-logging interceptor is registered today.
**Source:** GH #178 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.11: Example server and client configuration files (BACKLOG)

**Goal:** Ship annotated `server.example.toml` and `client.example.toml`
covering every option with defaults and standalone/Docker/Kubernetes scenarios,
validated against the current config structs. No example files exist in the tree
today.
**Source:** GH #188 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.12: TLS certificate expiry metrics (BACKLOG)

**Goal:** Expose certificate expiry as OTel gauges so renewal failure is
alertable from the existing telemetry pipeline instead of an external file-mtime
check. `internal/acme` logs `not_after` but registers no metric.
**Source:** GH #236 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.13: Operator TLS error diagnostics (BACKLOG)

**Goal:** Make a TLS failure in the operator say so. A CA mismatch currently
surfaces as "server unreachable / transport error", which sends operators
hunting network policies and firewall rules; the readiness path should
categorize TLS errors distinctly and log certificate details.
**Source:** GH #249 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.14: Read-model lag wedges host UPDATE on version conflicts (BACKLOG)

**Goal:** Stop an aggregate from wedging permanently on optimistic-concurrency
conflicts. The read returns a stale version, every retry submits the same stale
expected version, and the gap never converges — across both operator and server
restarts.

Status as of 2026-08-02: the two amplifiers named in #330 are FIXED —
commit-on-timeout by PR #332 (pre-commit rollback guards in
`internal/storage/sqlite/eventstore.go`, pinned by three passing tests in
`pool_error_test.go`) and aggregate bloat by compaction (#336). What remains
unverified is the read-model lag itself: `CommandHandler.UpdateHost` still
derives current state from the projection (`internal/server/commands.go:176-177`,
`h.store.GetByID`), so the structural precondition for a stale-version read is
still present. Whether the wedge still reproduces could not be determined from
code alone — it needs an affected database. Start by trying to reproduce; this
may already be closed.
**Source:** GH #323 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

<!-- 999.15 (GH #330, commit-on-timeout) was withdrawn 2026-08-02: the defect was
     already fixed by PR #332 and is pinned by three passing regression tests in
     internal/storage/sqlite/pool_error_test.go. The number is intentionally left
     unused rather than reclaimed — backlog numbers are published in GitHub issue
     comments, so renumbering would invalidate external references. Sparse
     numbering is expected here (see add-backlog). -->

### Phase 999.16: IngressRoute finalizer wedges when host entry already deleted (BACKLOG)

**Goal:** Treat an already-absent host entry as a successful cleanup.
`reconcileDelete` counts `ErrHostNotFound` from `DeleteHost` as a failure
(`internal/operator/ingressroute_controller.go:325-329`), retains the ID, and
never releases the finalizer — leaving the IngressRoute in `Terminating` until
someone runs `kubectl patch`.
**Source:** GH #386 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.17: CI gate for Conventional Commit PR titles (BACKLOG)

**Goal:** Validate PR titles at merge time. The repo is squash-merge-only with
`squash_merge_commit_title: PR_TITLE`, so the PR title becomes the commit subject
on `main` and is release-please's only input — yet nothing checks it. `cog.toml`
and lefthook cover local commits only.
**Source:** GH #388 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.18: Fix operations guide SIGHUP description (BACKLOG)

**Goal:** Correct `docs/guides/operations.md:129`, which describes SIGHUP cert
reload as "graceful shutdown (30s drain), restart with new certs". The handler
swaps certificates in place; only SIGTERM/SIGINT reach `gracefulStop()`. The
surrounding "what is recreated" list needs the same correction.
**Source:** GH #392 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.19: generate-cli-docs.sh emits fences without a language tag (BACKLOG)

**Goal:** Make `task docs:build` produce lint-clean output.
`scripts/generate-cli-docs.sh` wraps `--help` output in bare fences (lines 37,
39, 86, 88), so the regenerated `docs/reference/cli.md` fails the repo's own
rumdl gate — which is why that file is currently hand-maintained.
**Source:** GH #402 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.20: ListHosts silently discards filter, limit, and offset (BACKLOG)

**Goal:** Make `host list --filter/--limit/--offset` do something. The whole path
is wired except the server: `ListHostsRequest` declares all three fields
(`proto/router_hosts/v1/hosts.proto:169-178`), the client populates them
(`internal/client/commands/host.go:258-267`), and then
`HostsServiceImpl.ListHosts` never reads `req` at all — it calls
`s.handler.ListHosts(stream.Context())` and streams everything
(`internal/server/service.go:360-373`). The flags are accepted and silently
dropped, so a user asking for 10 entries gets the full table. Either implement
server-side handling or reject the flags loudly; silent discard is the one
option that must not survive.
**Source:** GH #215 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)
