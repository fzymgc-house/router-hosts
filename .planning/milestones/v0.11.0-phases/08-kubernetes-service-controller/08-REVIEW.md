---
phase: 08-kubernetes-service-controller
reviewed: 2026-07-29T00:00:00Z
depth: deep
files_reviewed: 8
files_reviewed_list:
  - internal/operator/service_controller.go
  - internal/operator/service_controller_test.go
  - cmd/operator/main.go
  - charts/router-hosts-operator/templates/clusterrole.yaml
  - charts/router-hosts-operator/templates/deployment.yaml
  - charts/router-hosts-operator/values.yaml
  - charts/router-hosts-operator/README.md
  - Taskfile.yml
findings:
  critical: 0
  warning: 1
  info: 4
  total: 5
status: issues_found
---

# Phase 08: Code Review Report

**Reviewed:** 2026-07-29T00:00:00Z
**Depth:** deep
**Files Reviewed:** 8
**Status:** issues_found

## Summary

This is a re-review of the six commits that landed in response to the prior
standard-depth review (preserved at git `c70df9f`): CR-01 (predicate admits
owned-but-opted-out Services), CR-02 (`DeleteHost` NotFound treated as success), WR-01
(client-side alias cap enforcement), and WR-02 (client-side ip-address validation).

All four fixes were traced against their stated intent and cross-checked line-by-line
against the commits (`fa47c6f`, `bc00c9b`, `79e78bc`, `4403ad1`) and their new
regression tests, not merely trusted because they were reviewed-then-fixed:

- **CR-01** (`serviceOwnsState` OR-ed into all four predicate funcs): traced the full
  admit matrix for every `(ip, waiting)` tuple `resolveServiceIP` can return, and every
  `Reconcile` path an admitted-but-opted-out Service can take. The predicate does not
  over-admit: `serviceOwnsState` can only ever be true for an object this controller
  itself previously wrote a finalizer or a host-ids annotation onto (both write paths
  are gated behind having reached `syncService` at least once, i.e. having opted in at
  least once), so no unrelated Service is pulled into reconcile traffic by this change.
  `Reconcile` handles the admitted-but-opted-out case correctly: it proceeds straight
  to `syncService`'s stale-cleanup pass (the finalizer is already present, so the
  finalizer-add early-return block at `service_controller.go:336-345` is skipped) and
  tears down every tracked entry without error.
- **CR-02** (`reconcileDelete`'s `errors.Is(err, ErrHostNotFound)` branch): verified the
  positive case (NotFound treated as success, finalizer released) and, per the review
  brief, the *opposite* case — a genuine, non-NotFound `DeleteHost` failure still sets
  `hadDeleteError`, retains the ID in `remainingIDs`, and leaves the finalizer in
  place. Both paths are exercised by dedicated tests
  (`host_not_found_during_cleanup_releases_finalizer` and
  `retains_ids_and_requeues_on_delete_failure`).
- **WR-02** (`serviceIPOverride` + `resolveServiceIP` validation + new
  `reasonInvalidConfiguration` branch): traced every reachable `(ip, waiting)` tuple
  through the now-five-way `syncService` switch and confirmed it is exhaustive and
  non-shadowed — an invalid override can only ever reach the
  `ip == "" && serviceIPOverride(svc) != ""` case, never the LoadBalancer-waiting or
  NodePort-missing cases, and never falls through to LoadBalancer status.
- **WR-01** (`serviceAliasCandidates` / `serviceAliasesExceedCap` aggregate check):
  confirmed this is the only call site that can ever trip `validation.go`'s
  `len(aliases) > MaxAliasesPerEntry` branch (per-alias calls in
  `serviceDesiredAliases` structurally cannot reach it), and confirmed the cap check
  runs *before* `AddHost`/`UpdateHost` on every path.
- **T-08-24 carry-forward**: verified the "retain previously-tracked ID" logic in both
  new `InvalidConfiguration` branches is correct in every combination, including the
  no-existing-entry case (no-op: nothing to retain, nothing to delete) and the
  simultaneous-hostname-change case (the *old* hostname's entry is correctly swept by
  the stale-cleanup pass, since the carry-forward is keyed to the *current* hostname —
  this is the intended "one code path handles every stop-managing transition"
  behavior, not a regression).
- **HostClient contract compliance**: all three sentinels (`ErrHostAlreadyExists`,
  `ErrHostNotFound` from `UpdateHost`, `ErrHostNotFound` from `DeleteHost`) are
  consumed via `errors.Is` in `service_controller.go` and none is silently swallowed
  or mis-branched.
- **Shared-helper cross-file check**: `getHostIDsAnnotation`/`setHostIDsAnnotation`/
  `hostIDsAnnotation` (defined in `ingressroute_controller.go`) now have a fourth
  caller in `service_controller.go`. Confirmed this cannot corrupt state another
  controller depends on: the annotation is written on the *object being reconciled
  itself* (a Service, IngressRoute, or Gateway route), never on a shared/cross-object
  record, and `HostMappingReconciler` does not use this annotation at all — so there is
  no cross-controller collision surface here.

No BLOCKER-tier defect was found in the six reviewed commits or their tests. The
findings below are a documentation-accuracy gap left behind by WR-01/WR-02, plus minor
code-duplication and test-coverage notes.

## Warnings

### WR-08-01: README Events table is now incomplete/stale after WR-01/WR-02

**File:** `charts/router-hosts-operator/README.md:314-318`
**Issue:** The "Events" subsection of the Service controller docs still reads:

> a Service owner may see four reasons via `kubectl describe service`:
> `InvalidServiceType`, `MissingHostname`, `MissingIPAddress` (all `Warning`), and
> `PendingLoadBalancer` (`Normal`, ...)

This was accurate before this review cycle, but the WR-02 and WR-01 fixes
(`79e78bc`, `4403ad1`) added a fifth reason, `InvalidConfiguration`, which fires for
both an unparseable `ip-address` override and an over-cap `aliases` annotation
(`service_controller.go:64`, `:429-451`). The README was not updated to mention it.

This directly reproduces the exact problem the fix was written to solve: the code
comment for `reasonInvalidConfiguration` (`service_controller.go:53-58`) explains at
length that `MissingIPAddress` and `InvalidConfiguration` must stay distinguishable
"in `kubectl describe service`" — but an operator who reaches for this README to
understand what `InvalidConfiguration` means (rather than reading Go source) will not
find it documented at all, only the four superseded reasons.

**Fix:**

```diff
 **Events**: a Service owner may see four reasons via
-`kubectl describe service`: `InvalidServiceType`, `MissingHostname`,
-`MissingIPAddress` (all `Warning`), and `PendingLoadBalancer` (`Normal`,
-while an IP is still provisioning). Success is logged by the operator
-rather than evented, to keep the event stream usable.
+`kubectl describe service`: `InvalidServiceType`, `MissingHostname`,
+`MissingIPAddress`, and `InvalidConfiguration` (all `Warning`), and
+`PendingLoadBalancer` (`Normal`, while an IP is still provisioning).
+`InvalidConfiguration` fires when the `ip-address` annotation is present but
+fails IP validation, or when `aliases` exceeds the 50-alias-per-entry cap —
+distinct from `MissingIPAddress`/absent annotations, so a typo is never
+indistinguishable from an omission. Success is logged by the operator
+rather than evented, to keep the event stream usable.
```

Also consider adding the 50-alias cap to the `aliases` row of the annotation
reference table (`README.md:291`), since it's now an enforced, user-visible limit
rather than dead validation code.

## Info

### IN-08-01: `serviceAliasCandidates` computed twice per reconcile on the sync path

**File:** `internal/operator/service_controller.go:442, 454, 280`
**Issue:** In `syncService`'s default branch, `candidates := serviceAliasCandidates(svc)`
is computed for the cap check (line 442), and then `serviceDesiredAliases(log, svc,
hostname)` (line 454) re-derives the identical candidate list internally by calling
`serviceAliasCandidates(svc)` again (line 280). The comma-split/trim/filter work is
duplicated on every reconcile of every alias-bearing Service. Correctness is
unaffected (performance is out of scope for this review), but it's needless
duplication introduced by the WR-01 fix that a small refactor removes.
**Fix:** Have `serviceDesiredAliases` accept the already-computed `candidates []string`
instead of re-deriving them from `svc`:

```go
func serviceDesiredAliases(log *slog.Logger, candidates []string, canonicalHostname string) []string {
    result := make([]string, 0, len(candidates))
    ...
}
// call site:
aliases := serviceDesiredAliases(log, candidates, hostname)
```

### IN-08-02: `serviceIPOverride(svc)` called twice in the InvalidConfiguration branch

**File:** `internal/operator/service_controller.go:429-430`
**Issue:**

```go
case ip == "" && serviceIPOverride(svc) != "":
    override := serviceIPOverride(svc)
```

`serviceIPOverride` re-reads and re-trims the annotation a second time in the same
branch it was already evaluated for in the `case` condition. Harmless (cheap,
deterministic), but avoidable.
**Fix:** Bind it once with a switch-init statement:

```go
switch override := serviceIPOverride(svc); {
case isWaiting:
    ...
case ip == "" && override != "":
    r.emitEvent(svc, corev1.EventTypeWarning, reasonInvalidConfiguration,
        "Service %s/%s has an invalid %s annotation value %q", svc.Namespace, svc.Name, serviceIPAddressAnnotation, override)
    ...
```

### IN-08-03: CR-01's `serviceOwnsState` path is untested for `CreateFunc`/`DeleteFunc`/`GenericFunc`

**File:** `internal/operator/service_controller_test.go:54-105`
**Issue:** `TestServiceEnabledPredicate` gained one new subtest for CR-01
(`update_deletion_of_opted_out_but_finalized`, covering `UpdateFunc`), but no subtest
exercises `serviceOwnsState` admitting an opted-out-but-owning object through
`CreateFunc`, `DeleteFunc`, or `GenericFunc`. The code comment added in the same
commit (`service_controller.go:126-129`) specifically calls out `CreateFunc` as
needing this for the informer-resync-after-restart scenario, but that scenario has no
regression test guarding it.
**Fix:** Add a subtest mirroring `update_deletion_of_opted_out_but_finalized` but for
`pred.Create`, e.g.:

```go
t.Run("create_owns_state_but_opted_out", func(t *testing.T) {
    svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
    svc.Finalizers = []string{serviceCleanupFinalizer}
    assert.True(t, pred.Create(event.CreateEvent{Object: svc}))
})
```

### IN-08-04: `ingressroute_controller.go`'s `reconcileDelete` still lacks the CR-02 fix

**File:** `internal/operator/ingressroute_controller.go:323-330` (not in this phase's
file scope — noted for cross-controller consistency only, not scored as a defect in
the reviewed files)
**Issue:** CR-02 established that this codebase's `HostClient` contract requires
`DeleteHost` returning `ErrHostNotFound` to be treated as success (already mirrored in
`gateway_controller.go:329` from an earlier phase). `ingressroute_controller.go`'s
`reconcileDelete` still does not check `errors.Is(err, ErrHostNotFound)` at all — any
`DeleteHost` failure, including NotFound, sets `hadDeleteError` and retains the
finalizer forever. This is the identical bug pattern CR-02 just fixed for Service,
left unfixed in the oldest of the three route/finalizer controllers. Not part of this
phase's diff, so not scored against these files, but the review brief specifically
asked for a comparison against IngressRoute's implementation of "the same contract,"
and this is what that comparison turned up — worth a follow-up ticket.
**Fix (follow-up, not this PR):** Port the same `errors.Is(err, ErrHostNotFound)` →
`continue` branch CR-02 added to `service_controller.go:651-659` into
`ingressroute_controller.go:325-329`.

---

*Reviewed: 2026-07-29T00:00:00Z*
*Reviewer: Claude (gsd-code-reviewer)*
*Depth: deep*
