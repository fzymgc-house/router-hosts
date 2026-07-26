---
phase: 07-gateway-api-support
reviewed: 2026-07-26T00:00:00Z
depth: standard
files_reviewed: 12
files_reviewed_list:
  - internal/operator/gateway_controller.go
  - internal/operator/gateway_controller_test.go
  - internal/operator/ingressroute_controller.go
  - cmd/operator/main.go
  - charts/router-hosts-operator/templates/clusterrole.yaml
  - charts/router-hosts-operator/templates/deployment.yaml
  - charts/router-hosts-operator/values.yaml
  - charts/router-hosts-operator/README.md
  - Taskfile.yml
  - lefthook.yaml
  - .yamlfmt.yaml
  - go.mod
findings:
  critical: 4
  warning: 2
  info: 1
  total: 7
status: issues_found
---

# Phase 07: Code Review Report

**Reviewed:** 2026-07-26T00:00:00Z
**Depth:** standard
**Files Reviewed:** 12
**Status:** issues_found

## Summary

The Gateway API controller (`internal/operator/gateway_controller.go`) is well
documented and its happy-path behavior is thoroughly tested (68 test functions
in `gateway_controller_test.go`). However, tracing the interaction between
`syncRoute`/`reconcileDelete` and the `HostClient` error taxonomy
(`ErrHostNotFound`, `ErrHostAlreadyExists`) surfaced four correctness bugs, all
in un-happy-path territory that the existing test suite does not exercise:
`syncRoute`'s no-IP early return skips stale-entry cleanup indefinitely; a
`HostClient.AddHost` success followed by an annotation-persist failure creates
a permanently orphaned, un-adoptable host entry; and `ErrHostNotFound` from
`DeleteHost`/`UpdateHost` is never special-cased, so a transient API-server
write failure after a successful delete can wedge either the route's
finalizer (blocking object deletion forever) or its host-ids annotation
(permanently un-recreatable hostname) in a state that never self-heals.

The Helm/RBAC/tooling surface was checked against the specific concerns
raised for this phase and found correct: the `clusterrole.yaml` grants for
`httproutes;grpcroutes;tlsroutes` and the read-only `gateways` grant match the
`+kubebuilder:rbac` markers exactly (least-privilege, no over-grant); the
`lefthook.yaml` `exclude` glob-list form (`charts/**/templates/**`,
`mkdocs.yml`) was verified against lefthook 2.1.10's actual matcher
(`gobwas/glob`, compiled without a path separator, matching the local
toolchain version) and correctly continues to exclude only unrendered Helm
templates and the repo-root `mkdocs.yml` — it is in fact more precise than
the previous unanchored regex, which would also have matched any nested
`*/mkdocs.yml`; and the `Taskfile.yml` `TEST_ARGS: '{{.CLI_ARGS | default
"./..."}}'` change was confirmed against Task's documented `CLI_ARGS` special
variable to be behaviorally equivalent to the prior hardcoded `go test ./...
-race -count=1` for a no-argument invocation.

## Critical Issues

### CR-01: `syncRoute`'s no-IP early return skips stale-entry cleanup indefinitely

**File:** `internal/operator/gateway_controller.go:388-398`

**Issue:** `syncRoute` resolves the IP and, when it is empty, returns
immediately — *before* reading the host-ids annotation and before the
stale-cleanup delete pass runs:

```go
ip := r.resolveIP(ctx, log, obj)
if ip == "" {
    log.Warn("no IP resolved for route; requeuing without writing any host entry")
    return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
}

existingIDs, err := getHostIDsAnnotation(log, obj)
```

`HostClient.DeleteHost` takes only an ID, not an IP, so the stale-cleanup pass
(lines 452-465) does not need a resolved IP to run. But because it is
unreachable whenever `ip == ""`, any route whose hostnames are edited down
(or to zero) while its parent Gateway has no address *and* no `DefaultIP` is
configured leaves the removed hostnames' host entries live on the router
indefinitely — the reconciler requeues forever at `requeueDelayShort` without
ever revisiting the stale IDs, because it never gets past the `ip == ""`
guard to compare `existingIDs` against the (now smaller) `hostnames` set. The
entries only get cleaned up if the Gateway or `--default-ingress-ip` later
gains an IP, or the route object itself is deleted (which follows the
separate `reconcileDelete` path).

This is distinct from the documented D-16 rationale ("refuses to write any
entry when resolveIP yields no IP... writing an entry with no resolved IP
would publish wrong DNS") — that rationale justifies skipping *creates and
updates*, not skipping *deletes*, which carry no IP-correctness risk.

**Fix:** Read the annotation and run the stale-cleanup pass unconditionally;
only gate the create/update loop on `ip != ""`:

```go
func (r *GatewayRouteReconciler) syncRoute(ctx context.Context, log *slog.Logger, obj client.Object, hostnames []string) (ctrl.Result, error) {
	ip := r.resolveIP(ctx, log, obj)

	existingIDs, err := getHostIDsAnnotation(log, obj)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}
	newIDs := make(map[string]string, len(hostnames))

	var hadError bool
	if ip == "" {
		log.Warn("no IP resolved for route; skipping create/update, still pruning stale entries")
		hadError = true // ensure a requeue even if the stale pass below has nothing to do
	} else {
		// ... existing create/update loop unchanged, populating newIDs ...
	}

	// stale-cleanup pass now always runs
	for hostname, id := range existingIDs {
		if _, ok := newIDs[hostname]; ok {
			continue
		}
		// ... existing DeleteHost logic ...
	}
	// ... existing annotation-persist + result logic ...
}
```

Add a regression test asserting that a route with a shrinking `hostnames`
list and an unresolvable IP still issues `DeleteHost` for the removed
hostname.

---

### CR-02: Orphaned, un-adoptable host entry when `AddHost` succeeds but the annotation persist fails

**File:** `internal/operator/gateway_controller.go:434-444, 470-477`

**Issue:** In the create branch, `AddHost` is called and its returned ID is
recorded only in the in-memory `newIDs` map:

```go
id, err := r.HostClient.AddHost(ctx, ip, hostname, comment, nil, tags)
...
newIDs[hostname] = id
```

The map is persisted to the object's annotation only once, after the whole
batch, via `setHostIDsAnnotation` + `r.Update` (lines 470-477). If that
`r.Update` call fails (a routine possibility — resource-version conflict,
transient API server error, webhook timeout), the function returns an error
and the reconcile is requeued, but **the host entry already created by
`AddHost` was never recorded anywhere durable**.

On the retry, `getHostIDsAnnotation` reads the *old* annotation (still
missing this hostname), so the hostname is treated as "not yet tracked" and
`AddHost` is called again for the same `(ip, hostname)` pair. The server
enforces uniqueness on exactly that pair (`internal/server/commands.go:138-141`,
`FindByIPAndHostname`), so the retry gets back `ErrHostAlreadyExists`. Unlike
`ingressroute_controller.go`'s `syncHost`/`addOrAdopt` (lines 254-280 of that
file), which explicitly adopts a pre-existing entry on `AlreadyExists` via
`FindHost`, `syncRoute`'s create branch has **no adoption path** — this is
called out by its own comment at line 434 ("There is no adoption or
AlreadyExists retry path here"). The `AlreadyExists` error is therefore
treated like any other create failure: logged, `hadError = true`, and the
hostname is skipped with **no ID retained** (line 440-441, "No prior ID to
retain — a failed create has nothing to track.").

The result: the first entry created by `AddHost` is now permanently orphaned
on the router — invisible to this route's annotation, therefore never
reachable by the stale-cleanup pass or `reconcileDelete`, and every
subsequent reconcile fails to create it again (`AlreadyExists` forever) since
adoption is not implemented. Nothing short of manual server-side cleanup
recovers this.

**Fix:** Either (a) port `addOrAdopt` from `ingressroute_controller.go` into
the create branch so an `AlreadyExists` reply is adopted via `FindHost`
instead of treated as a fatal skip, or (b) persist the annotation
incrementally (e.g., immediately after each successful `AddHost`/`DeleteHost`
rather than batching to the end of the loop) so a later `r.Update` failure
cannot leave a created entry unrecorded. Option (a) is the smaller change and
matches the precedent already established in this package:

```go
id, err := r.addOrAdoptGatewayHost(ctx, log, ip, hostname, comment, tags)
if err != nil {
    log.Error("failed to add host entry", "hostname", hostname, "error", err)
    hadError = true
    continue
}
newIDs[hostname] = id
```

Add a regression test that simulates `AddHost` succeeding followed by
`r.Update` failing (via `interceptor.Funcs`, already used elsewhere in this
test file), then asserts the next reconcile adopts rather than orphans the
entry.

---

### CR-03: `DeleteHost` `NotFound` treated as a real failure in `reconcileDelete` → permanently stuck finalizer

**File:** `internal/operator/gateway_controller.go:308-315`

**Issue:**

```go
for hostname, id := range existingIDs {
    log.Info("deleting host entry for deleted route", "hostname", hostname, "hostId", id)
    if err := r.HostClient.DeleteHost(ctx, id); err != nil {
        log.Error("failed to delete host entry during cleanup", "hostname", hostname, "hostId", id, "error", err)
        remainingIDs[hostname] = id
        hadDeleteError = true
    }
}
```

`DeleteHost` returns an error wrapping `ErrHostNotFound`
(`grpc_hostclient.go:148-157`) when the ID no longer exists — a routine,
recoverable condition (the entry is already gone, which is the desired end
state), not a real failure. This loop does not special-case it: a `NotFound`
is folded into `remainingIDs` and `hadDeleteError` exactly like a genuine
delete failure.

Concretely: if all deletes succeed on reconcile N but the *subsequent*
`r.Update` (finalizer removal, lines 327-330) fails — a routine possibility —
the object retains its finalizer and its (still-full) `existingIDs`
annotation. On reconcile N+1, every one of those IDs is retried through
`DeleteHost`, but they were already deleted in reconcile N, so every call now
returns `ErrHostNotFound`. Every one is folded into `remainingIDs`,
`hadDeleteError` is set, and the finalizer is *never* removed. This repeats
on every subsequent reconcile: the route object is now permanently stuck
with a live finalizer and can never actually be deleted from Kubernetes
without manual `kubectl patch ... --type=merge -p '{"metadata":{"finalizers":[]}}'`
intervention.

The same out-of-band condition (someone deletes the host entry directly via
the CLI while the route object is also being deleted) reaches this same bug
without any annotation-persist race at all.

**Fix:** Treat `ErrHostNotFound` as a successful delete (the desired
end-state was already reached):

```go
for hostname, id := range existingIDs {
    log.Info("deleting host entry for deleted route", "hostname", hostname, "hostId", id)
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

Add a regression test with a `deleteHostFn` returning `ErrHostNotFound` for
one ID, asserting the finalizer is still removed and the object becomes
`NotFound` after `Reconcile`.

Note: `ingressroute_controller.go`'s `reconcileDelete` (lines 283-319 of that
file, unchanged in this phase's diff) has the identical gap — this is a
pre-existing, shared defect the phase's D-09 mirroring imported into the new
controller rather than one this phase introduced from scratch. Recommend
fixing both call sites, or extracting the shared delete-loop into one helper
so future kinds cannot reintroduce the gap.

---

### CR-04: `DeleteHost`/`UpdateHost` `NotFound` mishandling in `syncRoute` → permanently stuck annotation, un-recreatable hostname

**File:** `internal/operator/gateway_controller.go:409-431, 453-465`

**Issue:** This is `syncRoute`'s analogue of CR-03, with a worse failure mode
because `syncRoute` runs on every normal reconcile (not just deletion).

Stale-cleanup branch (lines 453-465): identical bug to CR-03 — a `NotFound`
from `DeleteHost` is folded into `newIDs` (line 460, "Retain the ID so it is
not orphaned from the annotation") exactly like a genuine failure. Trace the
consequence through the `maps.Equal` no-op-write guard (line 470): if a
hostname's `DeleteHost` succeeds on reconcile N but the batch's `r.Update`
fails, the annotation on-disk still lists it. On reconcile N+1, `DeleteHost`
for that (already-gone) ID returns `NotFound`, gets re-added to `newIDs`, and
`newIDs` now equals `existingIDs` again — so the `!maps.Equal` guard at line
470 evaluates false and **the annotation write is skipped entirely**. This
repeats forever: the annotation permanently and incorrectly claims the
hostname is still tracked, `hadError` is permanently true so the controller
requeues at `requeueDelayLong` forever, and there is no code path that ever
clears the stuck entry short of manually editing the annotation.

Update branch (lines 409-431) compounds this: `syncRoute` has no
vanished-entry self-heal, unlike `ingressroute_controller.go`'s `syncHost`
(which explicitly recreates via `AddHost` when `GetHost`/`UpdateHost`
reports `NotFound` — see `ingressroute_controller.go:228-236`). If a user
later re-adds the now-orphaned hostname to the route's `spec.hostnames`, it
is found in `existingIDs` (still holding the dead ID from the stuck
annotation above) and routed into the *update* branch, which calls
`UpdateHost` on a nonexistent ID. `UpdateHost` returns `ErrHostNotFound`
(`grpc_hostclient.go:118-145`), which is handled identically to any other
update failure (lines 421-429): the dead ID is retained in `newIDs`, and the
hostname can never successfully sync again for this route object.

**Fix:** Special-case `ErrHostNotFound` in both loops:

```go
// stale-cleanup pass
if err := r.HostClient.DeleteHost(ctx, id); err != nil {
    if errors.Is(err, ErrHostNotFound) {
        log.Info("stale host entry already gone", "hostname", hostname, "hostId", id)
        continue // do not retain in newIDs
    }
    log.Error("failed to delete stale host entry", "hostname", hostname, "hostId", id, "error", err)
    newIDs[hostname] = id
    hadError = true
    continue
}
```

```go
// update branch — recreate on vanished entry, mirroring ingressroute's syncHost
if err := r.HostClient.UpdateHost(ctx, id, ip, hostname, comment, nil, tags, ""); err != nil {
    if errors.Is(err, ErrHostNotFound) {
        log.Warn("host entry vanished before update; recreating", "hostname", hostname, "staleHostId", id)
        newID, addErr := r.HostClient.AddHost(ctx, ip, hostname, comment, nil, tags)
        if addErr != nil {
            log.Error("failed to recreate vanished host entry", "hostname", hostname, "error", addErr)
            hadError = true
            continue
        }
        newIDs[hostname] = newID
        continue
    }
    log.Error("failed to update host entry", "hostname", hostname, "hostId", id, "error", err)
    hadError = true
    newIDs[hostname] = id
    continue
}
```

Add regression tests: (1) `DeleteHost` returning `ErrHostNotFound` for a
stale ID must drop it from the annotation on that same reconcile, not retain
it; (2) `UpdateHost` returning `ErrHostNotFound` for a tracked hostname must
trigger a recreate via `AddHost`, not a permanent stuck update.

## Warnings

### WR-01: `--default-ingress-ip` empty-string warning names Gateway API controllers even when they are disabled

**File:** `cmd/operator/main.go:87-89`

**Issue:**

```go
if defaultIngressIP == "" {
    logger.Warn("--default-ingress-ip is empty; IngressRoute and Gateway API controllers will create hosts with no IP")
}
```

This fires unconditionally, before the `enableGateway` check at line 128. If
`--enable-gateway` is not set (the default), the Gateway API controllers are
never registered at all, so this warning is misleading — an operator running
only the IngressRoute controller with no Gateway CRDs in the cluster sees a
warning that references a feature they never enabled.

**Fix:**

```go
if defaultIngressIP == "" {
    msg := "--default-ingress-ip is empty; IngressRoute controller will create hosts with no IP"
    if enableGateway {
        msg = "--default-ingress-ip is empty; IngressRoute and Gateway API controllers will create hosts with no IP"
    }
    logger.Warn(msg)
}
```

### WR-02: `parentRefsOf`/`routeParentRefIndexFunc`/`resolveIP` do not filter on `ParentReference.Kind`

**File:** `internal/operator/gateway_controller.go:110-148, 346-368`

**Issue:** The Gateway API `ParentReference` type carries an optional `Kind`
field that defaults to `"Gateway"` but can name a different parent kind (for
example a Mesh `Service` parent under the GAMMA extension). None of
`parentRefsOf`, `routeParentRefIndexFunc`, or `resolveIP` check `ref.Kind`
before treating the reference as a Gateway name/namespace pair. In practice
this fails safe today — `resolveIP`'s `r.Get(...)` for a non-Gateway-shaped
name returns `NotFound` and is silently skipped — but it pollutes the
`parentRefIndexKey` field index with entries that can never produce a
`mapGatewayToRoutes` match, and wastes a `Get` call on every reconcile for
routes that use non-Gateway parents.

**Fix:** Skip refs whose `Kind` is set and not `"Gateway"`:

```go
func routeParentRefIndexFunc(obj client.Object) []string {
	refs := parentRefsOf(obj)
	keys := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref.Kind != nil && string(*ref.Kind) != "Gateway" {
			continue
		}
		...
	}
	return keys
}
```

Apply the same guard in `resolveIP`'s loop. Low priority — no route kind
this operator currently reconciles commonly uses non-Gateway parents.

## Info

### IN-01: `remainingIDs` map allocated even on the all-succeeded `reconcileDelete` path

**File:** `internal/operator/gateway_controller.go:306`

**Issue:** `remainingIDs := make(map[string]string, len(existingIDs))` is
allocated unconditionally, but only used inside the `if hadDeleteError`
branch. When every delete succeeds (the common case), the allocation is
wasted. Purely cosmetic; not worth a standalone change but worth folding in
if CR-03's fix touches this function anyway.

---

*Reviewed: 2026-07-26T00:00:00Z*
*Reviewer: Claude (gsd-code-reviewer)*
*Depth: standard*
