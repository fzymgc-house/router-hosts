# GSD Inbox Triage — fzymgc-house/router-hosts

Generated: 2026-07-25 · Open issues at scan: 36 · Open PRs: 1 · **After actions: 29 open**

## Actions taken

Applied after the scan below, in the same session.

| Action | Items |
|---|---|
| Added `confirmed-bug` | #330, #323, #322, #348 (#348 also got `bug`, `high`) |
| Added type labels | #324 `dependencies`, #236 `enhancement`, #157 `enhancement` |
| Closed — moot after Rust → Go migration | #29, #41, #131, #132, #218 |
| Closed — already implemented in Go | #34, #66 |
| Kept open, annotated with live Go locations | #23, #38 |
| Approved as Phase 10 | #364 (`approved-feature`, `needs-review` removed) |

Verification behind the closures is in "Nine Rust-era leftovers" below — each was
checked against the Go tree rather than closed on the stale file reference alone.
Two of the nine turned out to be live defects and were **not** closed.

## Summary

| Issues | Count | PRs | Count |
|---|---|---|---|
| Enhancement-labeled | 20 | Feature PRs | 0 |
| Bug-labeled | 4 | Enhancement PRs | 0 |
| Documentation | 6 | Fix PRs | 0 |
| Maintenance/testing | 1 | Release automation | 1 |
| No type label | 5 | Gate violations | 0 |

## Headline finding: the template baseline starts now

The issue and PR templates landed **yesterday** (`89ad990`, 2026-07-25). Exactly one
open issue — **#364** — was filed after they existed, and it scores **100%**.

The other 35 issues predate the templates by 28 to 236 days. They score 0–14% against
the new forms purely because they were written before the forms existed, in a
consistent maintainer house style (`## Summary` ×22, `## Context` ×15, `## Impact` ×11).
Those scores measure calendar order, not submission quality.

**Do not run `/gsd-inbox --close-incomplete` against this backlog.** It would close 35
legitimate maintainer-authored issues. Template compliance applies to submissions from
2026-07-25 forward.

## Gate violations

**None.** No code PRs are open, so no PR can violate the issue-first rule.

Note that the approval-gate labels (`needs-review`, `needs-triage`, `approved-feature`,
`approved-enhancement`, `confirmed-bug`) now all exist on the repo, so the gate is live
rather than inert.

## Issues needing attention

### #364 — the one real gate decision

`feat: consumer-rendered output templates, one-shot and sink modes`
Labels: `enhancement`, `needs-review` · Age: 0d · Score: **100%**

Every required field of `feature_request.yml` is present and substantive: problem
statement grounded in a concrete HA-resolver migration, 4 user stories, 9 testable
acceptance criteria, an honest maintenance-burden section that argues against itself,
and 6 alternatives with reasons for rejection (including an interim fallback).

The blocker is not completeness — it is **scope**. `ROADMAP.md` has phases 7–9 as
Gateway API Support, Kubernetes Service Controller, and Hook Reliability & Metrics.
Consumer-rendered templates plus a streaming sink is a **new north-star surface** that
is not on the roadmap and is larger than any remaining phase.

Decision required (this is what `needs-review` is holding):

1. Approve as-is → add `approved-feature`, insert as a new phase (10, or 7.1 if urgent)
2. Approve the narrow interim only → the issue itself offers `ExportHosts --format unbound`
   as an unblocking fallback; that is enhancement-shaped, not feature-shaped
3. Defer → leave `needs-review`, revisit after phase 7

Related open issue: **#23** (lazy streaming for `ExportHosts`) touches the same export
path and should be linked or folded in either way.

### Untriaged bugs blocked by the new gate

These carry no `confirmed-bug` label, so under `CONTRIBUTING.md` **no fix PR can be
opened for them** until a maintainer triages. Three are high severity.

| Issue | Age | Labels | Needs |
|---|---|---|---|
| #348 server 0.10.7 boot crash-loop on Rust-migrated DB | 28d | *(none)* | `bug` + triage |
| #330 unbounded event-log growth → UpdateHost exceeds deadline | 30d | `bug,high,performance` | `confirmed-bug` |
| #323 read-model lag wedges aggregate on UPDATE | 30d | `bug,high` | `confirmed-bug` |
| #322 no mTLS cert reload → serves stale cert until restart | 30d | `bug,high,security` | `confirmed-bug` |
| #249 operator TLS error diagnostics | 167d | `bug` | `confirmed-bug` |
| #218 Prometheus recorder tests fail on global state | 205d | *(none)* | type label (likely moot — see below) |

Sharpest of these is #348: an unlabeled boot crash-loop report sitting 28 days.

### Rust-era issues, unverified against the Go codebase

Nine issues cite Rust source files, Cargo, tokio, or crates. The project is now pure Go
(`internal/`, `cmd/`), so their file references no longer resolve. The underlying
concern may or may not survive the migration — each needs revalidation, not blind closure.

Each was verified against the Go tree, not judged on the stale reference alone.

| Issue | Verdict | Evidence in the Go tree |
|---|---|---|
| #29 add `cargo audit` to CI | **Closed** — satisfied | `govulncheck ./...` runs as the "Vulnerability check" job in `ci-go.yml` |
| #41 migrate `dirs` → `directories` | **Closed** — moot | Both are Rust crates; Go uses `os.UserConfigDir` |
| #131 `JoinSet` for challenge connections | **Closed** — moot | Go ACME is DNS-01 only (`acme.go:138-143`); no HTTP-01 server exists |
| #132 challenge-store TTL sweep | **Closed** — moot | Same: lego holds no local challenge store |
| #218 Prometheus global recorder | **Closed** — moot | No Prometheus recorder; metrics are OpenTelemetry |
| #34 batch transaction for import | **Closed** — already done | `AppendEventsBatch` exists at `eventstore.go:93`, with atomicity + rollback tests |
| #66 batch host ops on rollback | **Closed** — already done | `RollbackToSnapshot` calls `regenerateOutputs` once at `service.go:850`, not per-op |
| #23 lazy `ExportHosts` streaming | **KEPT — live defect** | `service.go:609` still calls `store.ListAll` and builds the whole payload for all 3 formats |
| #38 client-side stream limits | **KEPT — live defect** | Unbounded `append` at `host.go:345`/`:363`, same in `snapshot.go`, `importexport.go`; no cap anywhere in `internal/client/` |

The two survivors had stale *file references* but intact *defects* — closing them on
the Rust citation alone would have discarded two real bugs. #23 is now folded into
Phase 10 as TMPL-06, since a long-lived sink over a non-lazy export would hold the
whole zone in memory per connected consumer.

### Label gaps

Five issues carry no type label at all: **#348**, **#324**, **#236**, **#218**, **#157**.

**#324** is the Renovate dependency dashboard — a bot-maintained tracker, not a work
item. It should be excluded from triage counts (pin it, or label it `dependencies`).

## PRs

### Ready to merge

**#358** `chore(main): release 0.10.14` — release-please automation, `autorelease: pending`

All 9 checks green: Lint, Vulnerability check, Test, Build, Buf lint & format, Manifests
up to date, Docs build (strict), CI (Go) Complete, Octopus Review. `mergeStateStatus: CLEAN`.

Exempt from the typed-PR templates and the issue-first rule — it is generated release
automation, not a contribution. Merging it ships the template/CLAUDE.md docs work.

Worth noting: the **`Vulnerability check` gate is green again**. It was previously
failing repo-wide and leaving every PR `BLOCKED`; `b5b1152` (x/text v0.39.0 + Go 1.26.5)
cleared it.

## Stale items

33 of 36 issues have had no activity in 30+ days. 30 of those have been untouched for
**5–8 months** (167–236 days).

Only #364 (0d) and #324 (bot, 0d) are active. This is a backlog that has been accumulating
rather than being worked — the Rust-era cohort above is roughly a third of it.

## Remaining next actions

Everything in the original recommendation list has been done except these.

1. **Merge #358** to ship 0.10.14 — all checks green, `mergeStateStatus: CLEAN`.
2. **`/gsd-discuss-phase 10`** — #364 is approved and scheduled; planning is the next step.
3. **#38** has no owner phase. It is a live client-side defense-in-depth gap that fits
   none of phases 7–10; either fold it into Phase 10 alongside #23 or file it as its own
   small phase.
4. **Do not** bulk-close on template score — the baseline starts 2026-07-25.
