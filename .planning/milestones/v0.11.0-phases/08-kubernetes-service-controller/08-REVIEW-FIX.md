---
phase: 08-kubernetes-service-controller
fixed_at: 2026-07-29T19:07:59Z
review_path: .planning/phases/08-kubernetes-service-controller/08-REVIEW.md
iteration: 1
findings_in_scope: 4
fixed: 4
skipped: 0
status: all_fixed
---

# Phase 08: Code Review Fix Report

**Fixed at:** 2026-07-29T19:07:59Z
**Source review:** .planning/phases/08-kubernetes-service-controller/08-REVIEW.md
**Iteration:** 1

**Summary:**

- Findings in scope: 4 (WR-08-01 + IN-08-01, IN-08-02, IN-08-03; `--all` scope. IN-08-04 explicitly excluded per scope fence.)
- Fixed: 4
- Skipped: 0

## Fixed Issues

### WR-08-01: README Events table is now incomplete/stale after WR-01/WR-02

**Files modified:** `charts/router-hosts-operator/README.md`
**Commit:** `7738bc7`
**Applied fix:** Updated the Events subsection to list all five reasons
(`InvalidServiceType`, `MissingHostname`, `MissingIPAddress`,
`InvalidConfiguration`, `PendingLoadBalancer`) and added a sentence making the
absent-vs-unusable distinction explicit: `MissingIPAddress` fires when the
`ip-address` annotation is ABSENT; `InvalidConfiguration` fires when an
annotation is PRESENT but unusable (unparseable `ip-address`, or `aliases`
over the 50-alias cap). Also added the 50-alias cap to the `aliases` row of
the annotation reference table, per the review's "also consider" note.
Verified against current code (`service_controller.go:53-58`, `:429-451`) —
the surrounding prose (supported types, IP resolution, no-default-fallback,
cleanup) still matches behavior, no other staleness found. `rumdl check`
clean.

### IN-08-01 / IN-08-02: Duplicate computation of `serviceAliasCandidates` and `serviceIPOverride`

**Files modified:** `internal/operator/service_controller.go`, `internal/operator/service_controller_test.go`
**Commit:** `e44c97f`
**Applied fix:**

- `serviceDesiredAliases` now accepts `candidates []string` instead of
  `svc *corev1.Service` and re-deriving the list internally. The single
  call site in `syncService`'s default branch now computes `candidates`
  once and passes it to both `serviceAliasesExceedCap` and
  `serviceDesiredAliases`.
- The inner `syncService` switch now uses a switch-init statement
  (`switch override := serviceIPOverride(svc); { ... }`) to bind the
  annotation value once instead of re-reading/re-trimming it inside the
  `InvalidConfiguration` case body.
- Case order was preserved exactly (`isWaiting` -> `ip == "" && override !=
  ""` -> `ip == ""` -> default) — the load-bearing precedence called out in
  the task brief was not disturbed.
- Updated 9 test call sites in `service_controller_test.go` that called
  `serviceDesiredAliases(log, svc, canonical)` directly to
  `serviceDesiredAliases(log, serviceAliasCandidates(svc), canonical)`,
  since the signature change is a breaking API change for callers (not
  itself in the review's file scope, but required to keep the package
  compiling).
- Verified: `task build`, `task lint` (0 issues), and the full `-run
  'Service'` suite (20/20 top-level `--- PASS`, matching the pre-fix
  inventory) all pass. Behavior unchanged — readability/efficiency only,
  per the review's explicit note.

### IN-08-03: `serviceOwnsState` untested for `CreateFunc`/`DeleteFunc`/`GenericFunc`

**Files modified:** `internal/operator/service_controller_test.go`
**Commit:** `257628f`
**Applied fix:** Added four subtests to `TestServiceEnabledPredicate`:
`create_owns_state_but_opted_out`, `delete_owns_state_but_opted_out`, and
`generic_owns_state_but_opted_out` (each: a Service with no opt-in
annotation but carrying `serviceCleanupFinalizer`, asserting `pred.Create` /
`pred.Delete` / `pred.Generic` admit it), plus
`create_owns_state_via_host_ids_annotation` covering the alternate
ownership signal (non-empty `host-ids` annotation, no finalizer) through
`pred.Create`. All four predicate funcs (`Create`, `Update`, `Delete`,
`Generic`) now have owns-state-but-opted-out coverage; `Update` coverage
pre-existed via `update_deletion_of_opted_out_but_finalized`. Verified:
`go vet`, `task lint` (0 issues), and `-run 'Service'` (20/20 top-level
PASS, all new subtests individually confirmed passing).

## Verification Summary

- `task build`: pass
- `task lint`: pass (golangci-lint 0 issues, buf lint/format clean, generated
  manifests up to date)
- `task test:coverage:ci`: pass — 85.2% overall coverage (unchanged from
  baseline, well above the 80% threshold); `internal/operator` package at
  87.9%
- Test inventory check: `rg '^func Test' internal/operator/service_controller_test.go`
  enumerated 20 top-level functions both before and after the fixes;
  `go test ./internal/operator/... -run 'Service' -v` produced exactly 20
  top-level `--- PASS` lines both times (`-run` is an unanchored regex —
  `'Service'` was used, not `'TestService'`, per the task brief's warning).
  No discrepancy found.
- Scope fence: `internal/operator/ingressroute_controller.go` — confirmed
  untouched (`git diff` across all three fix commits: 0 lines). No changes
  to `internal/validation/`, `internal/server/`, `go.mod`, or `go.sum`.
- Signing: all three fix commits succeeded with normal SSH signing; no
  `--no-gpg-sign` fallback was needed.

## Skipped Issues

None — all four in-scope findings were fixed.

---

_Fixed: 2026-07-29T19:07:59Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
