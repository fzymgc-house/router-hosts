---
phase: 08-kubernetes-service-controller
reviewed: 2026-07-27T00:00:00Z
depth: standard
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
  critical: 2
  warning: 2
  info: 1
  total: 5
status: issues_found
---

# Phase 8: Code Review Report

**Reviewed:** 2026-07-27
**Depth:** standard
**Files Reviewed:** 8
**Status:** issues_found

## Summary

The chart, RBAC, `cmd/operator/main.go` wiring, and the adoption-gate
(`addOrAdoptService`/`hasServiceProvenance`) all match the locked D-01…D-28
decisions faithfully, and the test suite (`service_controller_test.go`) is
unusually disciplined — it deliberately uses `fakeHostStore` instead of a
duplicate-ID-issuing mock for the adoption tests (avoiding the exact trap
called out in the review brief), asserts `NotNil` + `Empty` rather than bare
`Empty` for the alias nil-vs-empty guard, and exercises all four D-17
"stop-managing" transitions plus the D-18 corrupt-annotation and
partial-failure paths.

Two BLOCKER-level defects were found, both in `service_controller.go`, both
around lifecycle edges the test suite does not exercise:

1. The opt-in/opt-out predicate (`serviceEnabledPredicate`) can permanently
   orphan the cleanup finalizer on a Service that was opted out before being
   deleted, wedging `kubectl delete service` forever with no self-heal.
2. `reconcileDelete`'s per-host delete loop does not treat a `DeleteHost`
   `NotFound` as success (unlike `syncService`'s own stale-cleanup loop two
   functions above it in the same file), so cleaning up a Service whose
   tracked entry was already removed out-of-band also wedges the finalizer.

Two WARNING-level gaps were found around unvalidated annotation input that
degrades to a silent, eventless, indefinite retry loop rather than a
terminal or operator-visible state. One INFO item notes a test-coverage gap
that let the two BLOCKERs ship undetected.

## Critical Issues

### CR-01: Opt-out-then-delete permanently orphans the cleanup finalizer, wedging `kubectl delete service` forever

**File:** `internal/operator/service_controller.go:96-105` (predicate) interacting with `:524-567` (`reconcileDelete`)

**Issue:** `serviceEnabledPredicate`'s `UpdateFunc` admits an event only when
`serviceEnabled(old) || serviceEnabled(new)` — i.e., only when the `enabled`
annotation is `"true"` on at least one side of the transition:

```go
UpdateFunc: func(e event.UpdateEvent) bool {
    return serviceEnabled(e.ObjectOld) || serviceEnabled(e.ObjectNew)
},
```

This correctly admits the D-05 opt-out transition itself (old carries
`enabled: "true"`, new does not — `TestServiceEnabledPredicate/update_annotation_removed`
covers exactly this). But it does **not** account for the object's
finalizer state, and `TestServiceEnabledPredicate/update_both_disabled`
explicitly locks in the opposite behavior as "correct": when *neither* old
nor new carries `enabled: "true"`, the event is rejected — always, with no
exception for an object that still carries `serviceCleanupFinalizer`.

Walk the full lifecycle:

1. Service opts in (`enabled: "true"`, `hostname: foo.example.com`) →
   `Reconcile` adds `serviceCleanupFinalizer` (`:253-262`) and creates a host
   entry.
2. Owner opts out (removes the `enabled` annotation). The opt-out Update
   event is admitted (old had `enabled: "true"`) → `syncService` deletes the
   host entry and clears the `host-ids` annotation via the stale-cleanup
   pass — but nothing in `Reconcile` or `syncService` ever removes the
   finalizer; only `reconcileDelete` does that, and it only runs when
   `DeletionTimestamp` is set. The finalizer is now permanently attached to
   an "at rest" Service with no annotation trace of ever having opted in.
3. Owner later runs `kubectl delete service foo`. Because the Service still
   carries a finalizer, the API server does **not** remove the object; it
   sets `metadata.deletionTimestamp` and emits an **Update** event (old =
   pre-deletion state, new = same object plus `deletionTimestamp`).
   Both `old` and `new` still lack the `enabled` annotation (nothing in step
   2 restored it) — the predicate's `UpdateFunc` evaluates
   `false || false` and **rejects the event**.
4. `Reconcile` (and therefore `reconcileDelete`) is never invoked for this
   Service again. The finalizer is never removed. The Service is stuck in
   `Terminating` indefinitely — there is no self-heal, because a later
   informer resync redelivers the *same* old/new annotation state and is
   rejected identically every time.

The common case (a Service deleted while still `enabled: "true"`) works
correctly, because `deletionTimestamp` doesn't touch annotations, so
`serviceEnabled(old)` stays true and the event is admitted. The bug is
specific to "opt out, then delete" (or any sequence that leaves the object
finalizer-bearing but currently `enabled != "true"` at delete time) — a
realistic pattern for teardown scripts, Helm/Kustomize value flips before
`kubectl delete`, or a CI pipeline that disables registration ahead of
decommissioning a Service.

This is a materially worse failure than the D-05 hazard the predicate was
built to close: D-05 was about a *DNS entry* being orphaned (self-heals on
the next relevant reconcile); this orphans the *Kubernetes object itself*,
requiring a human to `kubectl patch service foo -p '{"metadata":{"finalizers":[]}}' --type=merge`
to unstick it.

**Fix:** Admit the event whenever either side is currently deleting, or
either side still carries the cleanup finalizer — not only when the
`enabled` annotation is present:

```go
UpdateFunc: func(e event.UpdateEvent) bool {
    if e.ObjectNew.GetDeletionTimestamp() != nil {
        return true
    }
    return serviceEnabled(e.ObjectOld) || serviceEnabled(e.ObjectNew) ||
        controllerutil.ContainsFinalizer(e.ObjectOld, serviceCleanupFinalizer)
},
```

Add a regression test that constructs a Service carrying the finalizer but
*no* `enabled` annotation (simulating post-opt-out state), sets
`DeletionTimestamp`, and asserts `pred.Update` returns `true` — the current
`update_both_disabled` subtest asserts the opposite for a fixture that
never carries the finalizer, so it does not catch this.

---

### CR-02: `reconcileDelete` treats an already-gone host entry as a delete failure, wedging the finalizer

**File:** `internal/operator/service_controller.go:538-547`

**Issue:** `reconcileDelete`'s per-host cleanup loop does not distinguish
`ErrHostNotFound` from any other `DeleteHost` error:

```go
for hostname, id := range existingIDs {
    log.Info("deleting host entry for deleted Service", "hostname", hostname, "hostId", id)
    if err := r.HostClient.DeleteHost(ctx, id); err != nil {
        log.Error("failed to delete host entry during cleanup", "hostname", hostname, "hostId", id, "error", err)
        remainingIDs[hostname] = id
        hadDeleteError = true
    }
}
```

`grpcHostClient.DeleteHost` (`internal/operator/grpc_hostclient.go:149-158`)
wraps a server-side `NotFound` gRPC status into `ErrHostNotFound`, which is a
normal, expected outcome — the entry was already removed (manually via the
CLI, by a prior partially-successful cleanup, or by any other legitimate
out-of-band actor). `syncService`'s own stale-cleanup pass, two functions
above this one in the same file, gets this right:

```go
// syncService, :373-377
if err := r.HostClient.DeleteHost(ctx, id); err != nil {
    if errors.Is(err, ErrHostNotFound) {
        log.Info("stale host entry already gone", "hostname", existingHostname, "hostId", id)
        continue
    }
    ...
}
```

`reconcileDelete` has no equivalent branch. A `NotFound` on the
DeletionTimestamp cleanup path is misclassified as `hadDeleteError = true`,
so the ID is retained in `remainingIDs`, the finalizer is **not** released
(`:548-559`), and the reconcile requeues after `requeueDelayShort` — forever,
since the same `DeleteHost` call will return the same `NotFound` on every
retry. The Service is stuck in `Terminating` until a human intervenes,
exactly the outcome the review brief calls out: *"a `DeleteHost` NotFound
must be treated as SUCCESS, or the finalizer wedges forever and blocks
Service deletion cluster-wide"* (for the affected Service).

**Fix:** Mirror the `syncService` stale-cleanup branch:

```go
for hostname, id := range existingIDs {
    log.Info("deleting host entry for deleted Service", "hostname", hostname, "hostId", id)
    if err := r.HostClient.DeleteHost(ctx, id); err != nil {
        if errors.Is(err, ErrHostNotFound) {
            log.Info("host entry already gone during cleanup", "hostname", hostname, "hostId", id)
            continue
        }
        log.Error("failed to delete host entry during cleanup", "hostname", hostname, "hostId", id, "error", err)
        remainingIDs[hostname] = id
        hadDeleteError = true
    }
}
```

(Note: `ingressroute_controller.go:325-329`'s `reconcileDelete` has the
identical gap, so this may be worth fixing project-wide — but only
`service_controller.go` is in this phase's scope.)

## Warnings

### WR-01: Aliases annotation bypasses the 50-alias server-side cap, causing a silent, eventless, indefinite retry loop

**File:** `internal/operator/service_controller.go:191-218`

**Issue:** `serviceDesiredAliases` validates each alias individually:

```go
if errs := validation.ValidateAliases([]string{alias}, canonicalHostname); len(errs) > 0 {
```

`validation.ValidateAliases` enforces `MaxAliasesPerEntry` (50) by checking
`len(aliases) > MaxAliasesPerEntry` at the top of the function
(`internal/validation/validation.go:93`) — but because this controller
always calls it with a **one-element slice**, that check can never trigger
here, no matter how many comma-separated aliases the annotation carries.
The server enforces the same limit correctly on the *aggregate* slice
(`internal/server/commands.go:102,264,394`), so a Service whose `aliases`
annotation lists more than 50 entries will have every alias individually
pass client-side validation, then have the single `AddHost`/`UpdateHost`
call rejected server-side on every reconcile. `syncService` treats this as
`hadError = true` and requeues via `requeueDelayLong` — forever, since the
alias count never changes on its own. Unlike the four D-12 states
(`InvalidServiceType`, `MissingHostname`, `MissingIPAddress`,
`PendingLoadBalancer`), this failure mode emits no Kubernetes Event, so the
Service owner has no `kubectl describe service` signal at all — only an
operator-internal log line.

**Fix:** Cap or warn on the aggregate alias count before the per-alias loop,
e.g.:

```go
segments := strings.Split(svc.GetAnnotations()[serviceAliasesAnnotation], ",")
if len(segments) > validation.MaxAliasesPerEntry {
    log.Warn("aliases annotation exceeds maximum, truncating",
        "count", len(segments), "max", validation.MaxAliasesPerEntry)
    segments = segments[:validation.MaxAliasesPerEntry]
}
```

### WR-02: `ip-address` override annotation is never format-validated client-side

**File:** `internal/operator/service_controller.go:127-143` (`resolveServiceIP`)

**Issue:** The `ip-address` annotation value is read and returned verbatim
with no `net.ParseIP` (or equivalent) check:

```go
if override := svc.GetAnnotations()[serviceIPAddressAnnotation]; override != "" {
    return override, false
}
```

A malformed value (typo, trailing whitespace not caught by `TrimSpace`
since none is applied here unlike the hostname path, a hostname pasted by
mistake, etc.) flows straight into `AddHost`/`UpdateHost`, where
`validation.ValidateIPAddress` (`internal/server/commands.go:96,197,388`)
rejects it server-side. As with WR-01, the result is `hadError = true` and
an indefinite `requeueDelayLong` retry loop with no Kubernetes Event —
`MissingIPAddress` only fires when the annotation is *absent*, not when it
is present but invalid, so a NodePort Service with a typo'd IP looks
identical to a healthy one from `kubectl describe service`.

**Fix:** Validate with the same package used server-side (or a local
`net.ParseIP` check) and emit a `Warning` event (reusing
`reasonMissingIPAddress` or a new reason) when the override fails to parse,
so the failure is terminal-and-visible rather than silently perpetual.

## Info

### IN-01: No test exercises reconcileDelete's `ErrHostNotFound` path

**File:** `internal/operator/service_controller_test.go:1167-1264`

**Issue:** `TestReconcileService_DeleteRemovesHostsAndFinalizer` covers a
clean delete, a generic-error delete (`errors.New("boom")`), the no-finalizer
no-op, and the corrupt-annotation case — but no subtest calls `deleteHostFn`
with `ErrHostNotFound`. This is precisely the gap that let CR-02 ship: a
test asserting `DeleteHost` returning `ErrHostNotFound` still releases the
finalizer (mirroring the `syncService` stale-cleanup test coverage that
does not exist for this function either) would have failed against the
current code.

**Fix:** Add a subtest seeding `deleteHostFn` to return `ErrHostNotFound`
and asserting the finalizer is removed and no requeue occurs — the same
shape as `syncService`'s implicit coverage via
`TestSyncService_StopManaging` (which uses `nil`-returning deletes, not
`ErrHostNotFound`, so even that path lacks an explicit NotFound-during-cleanup
assertion; consider adding one there too for symmetry).

---

*Reviewed: 2026-07-27*
*Reviewer: Claude (gsd-code-reviewer)*
*Depth: standard*
