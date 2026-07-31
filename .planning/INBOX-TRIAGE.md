# GSD Inbox Triage — fzymgc-house/router-hosts — 2026-07-31

Open issues at scan: 32 · Open PRs: 1 · **After actions: 23 open**
Previous run archived at `.planning/INBOX-TRIAGE-2026-07-25.md`.

## Actions taken

Applied after the scan, in the same session. Every closure was verified against
the Go tree first — no issue was closed on a stale file reference alone.

| Action | Items |
|---|---|
| Closed — **already fixed** | #322 (SIGHUP cert reload shipped in Phase 2) |
| Closed `wontfix` — premise removed by the Rust → Go port | #134, #140, #157, #136, #186 |
| Closed `wontfix` — low or negative value | #216, #135, #20 |
| Re-graded enhancement → **bug** | #215 (`--filter` accepted then silently discarded) |
| Labels applied | #392 `maintenance`+`needs-triage`, #249 `needs-triage` |
| CONTRIBUTING amended | Automated dependency PR carve-out + merge policy |

## Summary

| Issues (post-action) | n | | PRs | n |
|---|---|---|---|---|
| Feature | 1 | | Feature PRs | 0 |
| Enhancement | 9 | | Enhancement PRs | 0 |
| Bug | 6 | | Fix PRs | 0 |
| Chore / docs | 7 | | Renovate | 1 |
| **Open total** | **23** | | **Open total** | **1** |

**Framing that drove every call below:** the issue/PR templates and
`CONTRIBUTING.md` landed 2026-07-25 (`89ad990`). Only 4 of the 32 issues scanned
were created after that date. Template-compliance scores for the other 28 measure
*specification style*, not rule-breaking — so nothing was closed for a low score.
Everything closed was closed on **evidence from the codebase**.

## Closed as already fixed

**#322** `Server does not reload mTLS cert on change` — carried `high`, `security`,
`confirmed-bug`, and was fixed some time ago without anyone closing it. Phase 2
shipped the reload: SIGHUP handler at `internal/server/server.go:133-138`,
`reloadCert()` at `:222`, `GetCertificate` callback at `:206`. The issue's own
"Requested fix" listed SIGHUP as an acceptable alternative to file-watching.

Live caveat recorded on the issue: the renewal pipeline must actually *send*
the signal — the Vault Agent post-render hook needs `kill -HUP`, not just a file
write. The operations guide misdescribes this path; #392 tracks the correction.

## Closed wontfix — premise removed by the Rust → Go port

These did not become obsolete because they were fixed. Their foundations were
replaced, so the text no longer describes anything that exists.

| # | Evidence |
|---|---|
| #134 | Documents port-80 privilege for an HTTP-01 challenge server. Go has **no HTTP-01** — `internal/acme/` is lego DNS-01 (Cloudflare) only |
| #140 | Configurable propagation delay for the **webhook DNS provider**. `rg 'webhook' internal/acme/ internal/config/` → no matches; there is no `WebhookConfig` |
| #157 | Caches a central GC loop (`main.rs:395-470`). Go has no sweep — each controller owns entries via the `host-ids` annotation + finalizer, driven by the informer cache. The O(entries × resources) cost is gone by construction |
| #136 | Tracks expiry of `tests/pebble-ca.pem`. That file does not exist; Pebble stayed a plan doc (`docs/plans/2025-12-21-acme-pebble-testing-design.md`) |
| #186 | Benchmarks `test-coverage` against `clippy` on Rust runners. No `clippy` job exists in `ci-go.yml` |

## Closed wontfix — low or negative value

- **#216** short flags — the proposed table assigns `-f` to `--filter`, but `-f`
  is already bound to `--format` as a global persistent flag in
  `internal/client/commands/root.go` (alongside `-q`, `-v`; `-o` is taken on
  import/export). Adopting it either breaks `-f` for existing scripts or makes
  the same letter mean different things per subcommand.
- **#135** warn on non-standard ACME directory URL — would fire on every start
  for step-ca, Pebble, Vault, or an internal Boulder, all legitimate here. A
  warning that fires on correct configuration teaches operators to ignore
  warnings. The typo case it targets already fails loudly at account
  registration, and malformed URLs are rejected in `internal/config`.
- **#20** document "v1.0 has no compaction" — Phase 6 shipped compaction, so the
  requested text is now false. The live version of the concern is #330.

## Re-graded

**#215** `--filter for host list` — moved from `enhancement` to `bug`. The Rust
file refs were stale but the defect ported intact:

- CLI defines the flag — `internal/client/commands/host.go:283`
- Client sends it — `req.Filter = &filter` at `host.go:257`
- Server **ignores it** — `ListHosts` at `internal/server/service.go:319-320`
  calls `s.handler.ListHosts(stream.Context())` and never reads `req`

`--filter` is accepted, marshalled, transmitted, and discarded. The user gets an
unfiltered list with no error — worse than the flag not existing, because the
output looks filtered. The capability exists (`domain.SearchFilter` with
`Query`/`IPPattern`/`HostnamePattern`/`Tags`, used by `SearchHosts` at
`service.go:337-346`); it is simply not wired into `ListHosts`.

## Renovate — resolved

`CONTRIBUTING.md` documented **no** bot exemption, so every Renovate PR was a
standing violation of the repo's own written MUST (`rg -in 'renovate|dependabot|
bot|automated' CONTRIBUTING.md` → 0 hits). Fixed by amending the document rather
than the bot:

- Automated dependency PRs are exempt from issue-first and typed templates,
  tracked collectively by the Dependency Dashboard (#324)
- Conventional Commit PR titles still required (`squash_merge_commit_title:
  PR_TITLE` makes the title the commit subject on `main`)
- `patch`/`minor` MAY merge on green CI; `major` (`major-update`) requires the
  maintainer to read the upstream changelog first

**PR #395** (setup-uv v9) is the first PR under the new policy and is
`major-update`: all 10 checks pass, but v9 flips `prune-cache` to `false`, which
raises Actions cache usage and cost. Green CI is explicitly not sufficient here.

## Remaining backlog — kept

Bugs (6): #386, #392, #348, #330, #323, #249, #215. Of these, `confirmed-bug` is
carried by #348, #330, #323, and #386. Both #249 and #215 lack it and are
gate-blocked.

Issue #249 needs a rewrite before it is actionable — the problem (TLS failures
report as generic "transport error") is real and generic, but the entire analysis
is Rust (`hyper` → `h2` → `rustls` error chains) and does not transfer to grpc-go.

Enhancements now cheap because their infrastructure landed:

- **#236** TLS cert expiry metrics — `internal/server/metrics.go` has 8
  instruments and no cert gauge; the OTel plumbing is already there
- **#178** access logging — metrics interceptors exist at `metrics.go:417`
  and `:442`; no access-log interceptor alongside them

Still open and unchanged: #364 (approved, Phase 10), #38 (approved), #177, #65,
plus #64, #23 (absorbed into Phase 10 TMPL-06), #16, #18, #19, #133, #188, #388,
and #324.

## Remaining gate gap

11 of the 23 open issues still carry no approval or triage label. The approval
gate is the merge precondition in CONTRIBUTING, so as long as it sits unpopulated
the majority of the backlog cannot legally receive a mergeable PR. That is a
deliberate state now rather than an accident — but it is worth a `needs-review`
sweep or a `/gsd-review-backlog` pass before the next milestone.
