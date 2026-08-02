# Roadmap: router-hosts

## Overview

router-hosts is an event-sourced, mTLS-secured DNS control plane with a CLI/TUI
and a Kubernetes operator. Milestones v0.10.13 through v0.12.0 built the baseline
and drove toward the north star — operator / Gateway-API parity and hands-off
cluster integration — finishing with hook reliability. v0.13.0 opened a second
axis: output rendering moved from the server to the consumer, so one stateful
server feeds N independent consumers without accreting a per-resolver output
format for each.

> **Phase numbering restarted at v0.13.0.** Milestones v0.10.13–v0.12.0 used a
> single continuous sequence (phases 1–9). Where an archived document says
> "Phase 1" it means Event-Sourced Host Core; in v0.13.0 it means
> Consumer-Rendered Output. Historical phase detail and phase directories are
> archived under `milestones/<version>-ROADMAP.md` and
> `milestones/<version>-phases/`.

## Milestones

- ✅ **v0.10.13 — v1 Shipped Baseline** — Phases 1–6 (shipped pre-GSD, reconstructed 2026-07-07)
- ✅ **v0.11.0 — K8s-Native Automation** — Phases 7–8 (shipped 2026-07-30, PR #381)
- ✅ **v0.12.0 — Hook Reliability & Metrics** — Phase 9 (shipped 2026-07-31, PR #389)
- ✅ **v0.13.0 — Consumer-Owned Output** — Phase 1 (shipped 2026-08-02, PR #404)
- 📋 **Next milestone** — not yet defined (`/gsd-new-milestone`)

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

## Progress

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
(`.planning/v0.13.0-MILESTONE-AUDIT.md`) and imported from the GitHub issue
tracker. Promote with `/gsd-review-backlog`.

**Source tracking (normative).** Every backlog item carries a `**Source:**`
field naming the GitHub issue it came from, or `none` for items with no issue.
When a backlog item is completed, its source issue MUST be closed in the same
PR that lands the work — reference it with a closing keyword (`Closes #NNN`) so
the merge closes it automatically. A backlog item MUST NOT be marked complete
while its source issue remains open. There is no automatic sync in either
direction: the ROADMAP does not import new issues and closing an issue does not
update this file, so both edges are maintained by hand.

### Phase 999.1: Wire the three e2e tiers into CI (BACKLOG)

**Goal:** `e2e`, `docker_e2e`, and `proc_e2e` gate merges instead of being
developer-only. `proc_e2e` is the only tier that observes the CLI-flag to config
seam — the exact blind spot that let blocker G-01-1 ship green through 45 UAT
items — and it currently does not gate anything. Tracked as #403 (threat
T-01-G1-13, disposition accept).
**Source:** GH #403 — close on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.2: Close the hardware-dependent verification gap (BACKLOG)

**Goal:** Run the verifications this environment cannot: UAT test 42 (resolver
reload plus two-node convergence) and the four manual deployment checks from plan
01-08, all recorded NOT-RUN in `01-VALIDATION.md`. Needs a real unbound host and a
second machine. Until then phase 01 reports `uat-passed: false` permanently,
because the predicate counts only `pass`/`passed`.
**Source:** none — originated in the v0.13.0 milestone audit.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

### Phase 999.3: Server-side lazy streaming for store.ListAll (BACKLOG)

**Goal:** Finish the half of TMPL-06 that was explicitly descoped. The wire is
bounded and the client refuses an unbounded response, but `store.ListAll` still
enumerates every aggregate and replays its full event log into memory before the
first byte is sent. Needs a cursor-based `storage.HostProjection` method. Tracked
as #400 (absorbs #23's wire-layer half) and #401.
**Source:** GH #400, #401, #23 — close all three on completion.
**Requirements:** TBD
**Plans:** 0 plans

Plans:

- [ ] TBD (promote with /gsd-review-backlog when ready)

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
