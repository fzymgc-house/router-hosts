# Phase 8: Kubernetes Service Controller - Pattern Map

**Mapped:** 2026-07-26
**Files analyzed:** 8 (2 new, 6 modified)
**Analogs found:** 8 / 8

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `internal/operator/service_controller.go` | controller (reconciler) | event-driven / CRUD (via gRPC) | `internal/operator/ingressroute_controller.go` (primary); `internal/operator/gateway_controller.go` (adoption rationale); `internal/operator/hostmapping_controller.go` (Recorder + predicate + consts) | role-match (composite — see WARNING below) |
| `internal/operator/service_controller_test.go` | test | table-driven / fake-client | `internal/operator/gateway_controller_test.go` (`fakeHostStore`, table structure) | exact |
| `cmd/operator/main.go` | config/wiring | request-response (flag parse + controller registration) | itself, `--enable-gateway` block (`:37,48,127-134`) | exact |
| `charts/router-hosts-operator/templates/clusterrole.yaml` | config (RBAC) | — | itself, the Gateway API rule block (`:16-25`) | exact |
| `charts/router-hosts-operator/values.yaml` | config | — | itself, `gateway:` key (`:47-56`) | exact (key name deliberately diverges — D-23) |
| `charts/router-hosts-operator/templates/deployment.yaml` | config (templating) | — | itself, `{{- if .Values.gateway.enabled }}` block (`:52-54`) | exact |
| `charts/router-hosts-operator/README.md` | docs | — | (no close analog read; follow existing annotation-reference tables for IngressRoute/Gateway sections) | role-match |
| `Taskfile.yml` (`test:chart`) | test (integration/helm) | batch (shell assertions) | itself, `test:chart` task (`:55-88`) | exact |

## Pattern Assignments

### `internal/operator/service_controller.go` (controller, event-driven)

**Analog:** `internal/operator/ingressroute_controller.go` (primary structural template) + `internal/operator/hostmapping_controller.go` (Recorder/predicate/consts) + `internal/operator/gateway_controller.go` (adoption-gate rationale)

**⚠️ CRITICAL — do NOT copy the watch mechanism from IngressRoute.** `ingressroute_controller.go` uses `unstructured.Unstructured` + `WatchesRawSource(source.Kind(mgr.GetCache(), obj, handler.TypedEnqueueRequestsFromMapFunc(...)))` (`:483-509`) because Traefik CRDs are not cleanly importable as a typed Go package. `corev1.Service` **is** typed and already in the scheme (D-01/D-02) — use the plain typed `For(&corev1.Service{}, builder.WithPredicates(...))` shape from `hostmapping_controller.go:473-478`, NOT `WatchesRawSource`/`source.Kind`. Getting this backwards is the single highest-risk copy-paste error available in this phase.

**Imports pattern** — combine the shape of `ingressroute_controller.go:1-27` (stdlib + `validation` + `oops` + controller-runtime) with `hostmapping_controller.go:1-24` (`corev1`, `k8s.io/client-go/tools/events`, `predicate`, `event`, `builder`) since Service needs both the typed corev1 API and the events/predicate machinery IngressRoute doesn't use:

```go
import (
	"context"
	"encoding/json" // if reusing getHostIDsAnnotation/setHostIDsAnnotation as-is (they're already in ingressroute_controller.go, same package — no re-import needed)
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/fzymgc-house/router-hosts/internal/validation"
	"github.com/samber/oops"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)
```

**Struct + Recorder field pattern** (source: `hostmapping_controller.go:32-44`):

```go
type HostMappingReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	HostClient HostClient
	Log        *slog.Logger

	// Recorder emits Kubernetes Events for corrective actions (e.g. recreating
	// a host deleted out-of-band). It may be nil in tests that do not assert on
	// events; event emission is best-effort telemetry, never control flow.
	Recorder events.EventRecorder
}
```

Mirror this shape for `ServiceReconciler`; add `DefaultTags []string` (mirroring `IngressRouteReconciler.DefaultTags`, `ingressroute_controller.go:76`) but do **not** add a `DefaultIP` field — D-11 explicitly forbids `--default-ingress-ip` as a Service fallback.

**Consts pattern** — new finalizer + package-scoped consts already available (source: `ingressroute_controller.go:29-32`, `hostmapping_controller.go:26-30`):

```go
const (
	ingressRouteCleanupFinalizer = "router-hosts.fzymgc.house/ingressroute-cleanup" // existing, for reference
	hostIDsAnnotation            = "router-hosts.fzymgc.house/host-ids"             // existing — REUSE verbatim (D-15)
)
const (
	hostCleanupFinalizer = "router-hosts.fzymgc.house/host-cleanup" // existing, for reference
	requeueDelayShort     = 5 * time.Second                          // existing — REUSE (D-18)
	requeueDelayLong      = 30 * time.Second                         // existing — REUSE (D-18)
)
// NEW for this phase (local to service_controller.go per Open Question #1 recommendation):
const (
	serviceCleanupFinalizer     = "router-hosts.fzymgc.house/service-cleanup" // D-16
	serviceEnabledAnnotation    = "router-hosts.fzymgc.house/enabled"
	serviceHostnameAnnotation   = "router-hosts.fzymgc.house/hostname"
	serviceAliasesAnnotation    = "router-hosts.fzymgc.house/aliases"
	serviceIPAddressAnnotation  = "router-hosts.fzymgc.house/ip-address"
)
```

**Reconcile head pattern** — mirror `ingressroute_controller.go:83-117` (Get → deletion check → finalizer-add-then-return → upsert), but using a typed Get, not unstructured:

```go
func (r *IngressRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("ingressroute", req.NamespacedName)

	obj := &unstructured.Unstructured{}   // <-- REPLACE with `svc := &corev1.Service{}` and r.Get(ctx, req.NamespacedName, svc)
	obj.SetGroupVersionKind(ingressRouteGVK)

	err := r.Get(ctx, req.NamespacedName, obj)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		...
	}

	// Handle deletion.
	if obj.GetDeletionTimestamp() != nil {
		return r.reconcileDelete(ctx, log, obj)
	}

	// Ensure finalizer. Return after adding so the next reconcile works
	// with a fresh object from the informer cache.
	if !controllerutil.ContainsFinalizer(obj, ingressRouteCleanupFinalizer) {
		controllerutil.AddFinalizer(obj, ingressRouteCleanupFinalizer)
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "adding finalizer to IngressRoute")
		}
		return ctrl.Result{}, nil
	}

	return r.reconcileUpsert(ctx, log, obj)
}
```

For Service, a plain `r.Get(ctx, req.NamespacedName, svc)` replaces the unstructured Get/GVK dance entirely (no `IsNotFound` fallback to a second kind needed — there's only one kind). Use `client.IgnoreNotFound(err)` (the `hostmapping_controller.go:55-56` idiom) instead of the manual `!apierrors.IsNotFound` branch, since Service has no TCP-variant fallback to special-case.

**Desired-set diff / no-early-return pattern (D-17)** — copy `reconcileUpsert` verbatim in shape (source: `ingressroute_controller.go:119-192`): compute `existingIDs` via `getHostIDsAnnotation`, build `newIDs` from the (possibly empty) desired set, loop `existingIDs` for stale deletes, persist only if `!maps.Equal(existingIDs, newIDs)`. **Do not gate this function on `len(hosts) == 0` the way IngressRoute's `reconcileUpsert` does at `:124-127`** — that early return is exactly the bug D-17 (Phase 7 07-04 fix) requires you not to reintroduce; for Service, a desired set of size 0 or 1 (never more — one hostname per Service, D-06) must still fall through to the stale-cleanup loop.

**syncHost read-before-write fail-closed guard (D-19)** — copy `syncHost` (`ingressroute_controller.go:216-253`) near-verbatim; the only behavioral change is the `aliases` argument to `UpdateHost`/`AddHost` — Service passes the real alias slice (never `nil` for "no change"; see Pitfall below), where IngressRoute passes `nil` at `:224,261`.

**addOrAdopt + provenance gate (D-21)** — copy `addOrAdopt` (`ingressroute_controller.go:260-301`) and `hasIngressProvenance` (`:307-309`) shape, renaming to `addOrAdoptService`/`hasServiceProvenance`. Single-kind like IngressRoute (no `KindName` parameter needed, per D-21 — unlike Gateway's `hasGatewayProvenance(tags, kindName)` at `gateway_controller.go:642-644`). Full rationale block to carry forward verbatim (comment):

```go
// T-07-02: adopt ONLY an entry this exact object previously created.
// FindHost matches on (ip, hostname) alone, which is not proof of ownership...
if existing.Comment != comment || !hasServiceProvenance(existing.Tags) {
	return "", oops.Errorf(
		"refusing to adopt host %s (id %s): owned by another object (comment %q tags %v, want comment %q with kubernetes + service)",
		hostname, existing.ID, existing.Comment, existing.Tags, comment,
	)
}
```

`hasServiceProvenance`:

```go
func hasServiceProvenance(tags []string) bool {
	return slices.Contains(tags, "service")
}
```

(D-20: tags are `DefaultTags + ["service"]` i.e. `["kubernetes","service"]`; checking `slices.Contains(tags, "service")` alone is sufficient since "kubernetes" is shared with all controllers via `DefaultTags` and is not discriminating — mirror the *reasoning* pattern from `gateway_controller.go:620-626` on why a single differentiator tag is chosen, even though the exact tag differs.)

**reconcileDelete pattern** — copy `reconcileDelete` (`ingressroute_controller.go:311-348`) verbatim in shape, swap the finalizer const to `serviceCleanupFinalizer`.

**getHostIDsAnnotation / setHostIDsAnnotation** — **reuse directly, zero changes** (`ingressroute_controller.go:415-457`). Already `client.Object`-typed; `*corev1.Service` satisfies it with no signature change (D-15).

**Predicate pattern (D-03/D-04/D-05)** — this is the one genuinely new piece; do **NOT** use `predicate.NewPredicateFuncs` (traps — see RESEARCH.md Pitfall 1) or copy `statusWriteFilter` (`hostmapping_controller.go:441-470`, wrong purpose — that filters status writes, this filters on annotation presence). Write a hand-rolled `predicate.Funcs{}` literal:

```go
// Shape only — verified correct in RESEARCH.md against pinned controller-runtime source.
func serviceEnabledPredicate() predicate.Predicate {
	isEnabled := func(obj client.Object) bool {
		return obj.GetAnnotations()[serviceEnabledAnnotation] == "true"
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return isEnabled(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return isEnabled(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return isEnabled(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			// D-05: admit when EITHER side carries the annotation.
			return isEnabled(e.ObjectOld) || isEnabled(e.ObjectNew)
		},
	}
}
```

**SetupWithManager pattern (typed, not unstructured)** — source: `hostmapping_controller.go:472-478`, NOT `ingressroute_controller.go:476-510`:

```go
func (r *HostMappingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1alpha1.HostMapping{}, builder.WithPredicates(statusWriteFilter())).
		Named("hostmapping").
		Complete(r)
}
```

Adapt directly: `For(&corev1.Service{}, builder.WithPredicates(serviceEnabledPredicate()))`, `.Named("service")`.

**Event emission pattern (D-12)** — source: `hostmapping_controller.go:328-330` (`recreateMissingHost`, exact `Eventf` call site/argument list) and confirmed against pinned `client-go` in RESEARCH.md:

```go
if err == nil && hm.Status.Phase == operatorv1alpha1.HostMappingPhaseSynced && hm.Status.HostID != "" && r.Recorder != nil {
	r.Recorder.Eventf(hm, nil, corev1.EventTypeNormal, "Recreated", "Recreate",
		"Recreated host entry %s after out-of-band deletion (previous id %q)", hm.Status.HostID, staleID)
}
```

Signature: `Eventf(regarding, related runtime.Object, eventtype, reason, action, note string, args ...interface{})`. For Service, the four reasons are `InvalidServiceType`/`MissingHostname`/`MissingIPAddress` (all `corev1.EventTypeWarning`) and `PendingLoadBalancer` (`corev1.EventTypeNormal`) — regarding=`svc`, related=`nil`. Always guard with `if r.Recorder != nil`.

**Error handling / requeue semantics (D-18)** — verbatim from `ingressroute_controller.go` throughout: `oops.Wrapf(err, "...")` for every fallible wrap, `ctrl.Result{RequeueAfter: requeueDelayShort}` on a corrupt annotation read error, `ctrl.Result{RequeueAfter: requeueDelayLong}` when `hadError` at the end of upsert, never `log.Fatal`/`os.Exit`.

**RBAC markers (D-24)** — source shape: `ingressroute_controller.go:79-80`, extended per RESEARCH.md's Code Examples section:

```go
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
```

---

### `internal/operator/service_controller_test.go` (test, table-driven)

**Analog:** `internal/operator/gateway_controller_test.go` (`fakeHostStore`, `:1339-1384`) + package-level `mockHostClient` (defined in `hostmapping_controller_test.go`, same package — do not re-declare)

**fakeHostStore pattern** (reuse directly, source `gateway_controller_test.go:1339-1384`):

```go
type fakeHostStore struct {
	entries map[string]*HostEntry // keyed by ip|hostname
	nextID  int
	deleted []string
}

func newFakeHostStore() *fakeHostStore { return &fakeHostStore{entries: map[string]*HostEntry{}} }
func (f *fakeHostStore) key(ip, hostname string) string { return ip + "|" + hostname }
func (f *fakeHostStore) seed(id, ip, hostname, comment string, tags []string) { ... }
func (f *fakeHostStore) client() *mockHostClient { ... } // returns AddHost/FindHost/DeleteHost closures
```

Use `store.client()` to construct `ServiceReconciler.HostClient` for adoption-collision tests (D-21's foreign-comment/foreign-tags refusal cases). Use the plain `mockHostClient{addHostFn: ..., updateHostFn: ..., ...}` literal directly (no store) for simple single-flow tests, exactly as `hostmapping_controller_test.go` and `gateway_controller_test.go` both do elsewhere.

**FakeRecorder pattern for D-28** (source: RESEARCH.md's Code Examples, verified against pinned `client-go@v0.36.1/tools/events/fake.go`):

```go
rec := events.NewFakeRecorder(10)
r := &ServiceReconciler{ /* ... */ Recorder: rec}
select {
case msg := <-rec.Events:
	assert.Contains(t, msg, "Warning MissingHostname ") // assert reason bracketed by spaces, not the message text
default:
	t.Fatal("expected an event")
}
```

**Fake client construction** — same pattern as `gateway_controller_test.go:1394-1395`:

```go
s := gatewayScheme(t) // for Service: use the manager's own scheme (clientgoscheme is enough; no gateway-api scheme needed per D-27)
k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(routeA, routeB).Build()
```

---

### `cmd/operator/main.go` (config/wiring, modify)

**Analog:** itself — the `--enable-gateway` flag + guarded registration block

**Flag declaration pattern** (`main.go:37,48`):

```go
enableGateway        bool
...
flag.BoolVar(&enableGateway, "enable-gateway", false, "Enable Gateway API HTTPRoute/GRPCRoute/TLSRoute controllers")
```

Add `enableService bool` / `flag.BoolVar(&enableService, "enable-service", false, "Enable the Kubernetes Service controller")` in the same block (D-03).

**Guarded registration pattern** (`main.go:127-134`):

```go
// Register Gateway API controllers (HTTPRoute/GRPCRoute/TLSRoute), opt-in only.
if enableGateway {
	if err := operator.SetupGatewayControllers(mgr, logger.With("controller", "gateway"),
		hostClient, defaultIngressIP, []string{"kubernetes"}); err != nil {
		logger.Error("unable to create Gateway API controllers", "error", err)
		return err
	}
}
```

Adapt for Service — a single reconciler, not a `SetupGatewayControllers` fan-out — closer in shape to the `HostMappingReconciler` registration at `main.go:104-113` (includes `Recorder: mgr.GetEventRecorder(...)`):

```go
if enableService {
	if err := (&operator.ServiceReconciler{
		Client:      mgr.GetClient(),
		HostClient:  hostClient,
		Log:         logger.With("controller", "service"),
		DefaultTags: []string{"kubernetes"},
		Recorder:    mgr.GetEventRecorder("service-controller"),
	}).SetupWithManager(mgr); err != nil {
		logger.Error("unable to create Service controller", "error", err)
		return err
	}
}
```

No scheme changes needed (D-01) — `corev1` is already registered via `clientgoscheme.AddToScheme` at `main.go:60`.

**`defaultIngressIPWarning` — D-26: do NOT touch its Service clause.** Source (`main.go:160-172`) — leave the function signature and both return strings exactly as-is. The Service controller does not consume `--default-ingress-ip` (D-11), so naming it here would repeat the exact WR-01 mistake this function exists to avoid.

---

### `charts/router-hosts-operator/templates/clusterrole.yaml` (RBAC, modify)

**Analog:** itself — the Gateway API rule block

**Rule shape to mirror** (`clusterrole.yaml:16-25`):

```yaml
  # Gateway API routes (gateway.networking.k8s.io). The controller writes a
  # finalizer + host-ids annotation, so update;patch are required.
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["httproutes", "grpcroutes", "tlsroutes"]
    verbs: ["get", "list", "watch", "update", "patch"]

  # Gateway resources are read-only (IP resolution from status.addresses).
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways"]
    verbs: ["get", "list", "watch"]
```

New rules per D-13/D-24 (add before `{{- end }}` at `:40`):

```yaml
  # v1/Service resources. The controller writes a finalizer + host-ids
  # annotation, so update;patch are required (D-24).
  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "list", "watch", "update", "patch"]

  # Kubernetes Events (D-12/D-13). No apiGroups: [""] events rule exists
  # anywhere in this chart's ClusterRole today — the only events rule is
  # namespace-scoped in role-leader-election.yaml. This also fixes
  # HostMappingReconciler's pre-existing Recorder as a side effect.
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]
```

The whole file is gated by `{{- if .Values.rbac.create -}}` / `{{- end }}` (`:1,40`) — new rules go inside that block, unconditional on `serviceController.enabled` (mirroring how the Gateway rules render unconditionally regardless of `gateway.enabled`, since RBAC additions are cheap and Helm doesn't currently template rule-level conditionals in this file).

---

### `charts/router-hosts-operator/values.yaml` (config, modify)

**Analog:** itself — the `gateway:` key block (`:47-56`)

```yaml
# Gateway API support (HTTPRoute/GRPCRoute/TLSRoute controllers).
# ...
gateway:
  enabled: false
```

**D-23 — do NOT name the new key `service:`.** Add a distinctly-named block, e.g.:

```yaml
# Kubernetes v1/Service controller support. When enabled, the operator
# additionally watches Services and syncs annotated LoadBalancer/NodePort
# Services the same way it syncs Traefik IngressRoutes. Deliberately NOT
# named `service:` — that key is the near-universal Helm convention for the
# chart's own Service resource; reusing it here would block ever adding one.
# NOTE: the shared informer caches every Service in the cluster regardless of
# opt-in annotation (see D-04/README for the memory-footprint tradeoff).
serviceController:
  enabled: false
```

---

### `charts/router-hosts-operator/templates/deployment.yaml` (config templating, modify)

**Analog:** itself — the `gateway.enabled` conditional arg (`:52-54`)

```yaml
            {{- if .Values.gateway.enabled }}
            - --enable-gateway
            {{- end }}
```

Add, in the same `args:` block:

```yaml
            {{- if .Values.serviceController.enabled }}
            - --enable-service
            {{- end }}
```

---

### `Taskfile.yml` `test:chart` (integration test, modify)

**Analog:** itself, the existing Gateway API assertion block (`:55-88`)

**⚠️ Do not copy the `grep -q` idiom forward as-is.** RESEARCH.md flags that these exit-status-only assertions went stale in Phase 7 while still exiting 0. Existing style to extend (structurally) but upgrade to explicit-count/content assertions:

```bash
if helm template "$CHART" | grep -q -- '--enable-gateway'; then
  echo "FAIL: --enable-gateway rendered with default values" >&2; exit 1
fi
if ! helm template "$CHART" --set gateway.enabled=true | grep -q -- '--enable-gateway'; then
  echo "FAIL: --enable-gateway missing when gateway.enabled=true" >&2; exit 1
fi
...
RENDERED=$(helm template "$CHART" --set gateway.enabled=true)
echo "$RENDERED" | grep -q 'gateway.networking.k8s.io' \
  || { echo "FAIL: Gateway API RBAC rules not rendered" >&2; exit 1; }
...
if helm template "$CHART" --set gateway.enabled=true --set rbac.create=false | grep -q 'kind: ClusterRole'; then
  echo "FAIL: ClusterRole rendered despite rbac.create=false" >&2; exit 1
fi
```

Add a parallel block for `--enable-service` / `serviceController.enabled=true` / `services` RBAC verbs / zero-ClusterRole-under-`rbac.create=false` (D-25). For the new `events` rule assertion specifically, RESEARCH.md's Validation Architecture section supplies the stronger idiom to use instead of bare `grep -q`:

```bash
helm template "$CHART" --set serviceController.enabled=true \
  | awk '/resources: \["events"\]/{f=1} f && /verbs:/{print; exit}' \
  | grep -q 'create' # then separately assert 'patch' present too — do not rely on exit status alone
```

## Shared Patterns

### Annotation + cleanup-finalizer lifecycle

**Source:** `internal/operator/ingressroute_controller.go` (whole-file shape), `internal/operator/gateway_controller.go`
**Apply to:** `service_controller.go` — finalizer add-then-return on first reconcile, finalizer removal only after all tracked entries are deleted in `reconcileDelete`.

### hostIDsAnnotation read/write (D-15)

**Source:** `internal/operator/ingressroute_controller.go:415-457` (`getHostIDsAnnotation`/`setHostIDsAnnotation`)
**Apply to:** `service_controller.go` — call directly, no modification, no re-declaration. Already `client.Object`-typed.

### Desired-set diff, no early return (D-17)

**Source:** `internal/operator/ingressroute_controller.go:119-192` minus the `len(hosts)==0` early return at `:124-127`
**Apply to:** `service_controller.go`'s upsert path — the stale-cleanup loop must always run.

### Provenance-gated adoption (D-21)

**Source:** `internal/operator/ingressroute_controller.go:260-309` (`addOrAdopt`/`hasIngressProvenance`), rationale doc-comment from `internal/operator/gateway_controller.go:601-644`
**Apply to:** `service_controller.go`'s `addOrAdoptService`/`hasServiceProvenance`.

### requeueDelayShort/Long + oops.Wrapf error semantics (D-18)

**Source:** `internal/operator/hostmapping_controller.go:26-29` (consts), pervasive `oops.Wrapf` usage throughout `ingressroute_controller.go`
**Apply to:** every fallible call in `service_controller.go`.

### events.EventRecorder wiring

**Source:** `internal/operator/hostmapping_controller.go:43` (field), `:328-330` (`Eventf` call site), `cmd/operator/main.go:109` (`mgr.GetEventRecorder(...)`)
**Apply to:** `ServiceReconciler.Recorder` field, its four `Eventf` call sites, and its `main.go` wiring.

### Hand-rolled predicate.Funcs for annotation-gated watches (D-05)

**Source:** RESEARCH.md Pattern 1 (verified against pinned `controller-runtime@v0.24.1` source); structurally similar in spirit to `internal/operator/hostmapping_controller.go:441-470`'s `statusWriteFilter` (different purpose, same "hand-roll predicate.Funcs, don't use NewPredicateFuncs" lesson).
**Apply to:** `service_controller.go`'s `serviceEnabledPredicate`.

### Chart toggle → flag templating

**Source:** `charts/router-hosts-operator/values.yaml:55-56` + `templates/deployment.yaml:52-54` (`gateway.enabled` → `--enable-gateway`)
**Apply to:** `serviceController.enabled` → `--enable-service`, with the D-23 key-name divergence intact.

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `charts/router-hosts-operator/README.md` | docs | — | Not read in this pass (out of scope for pattern extraction — no code excerpt to give); planner should follow the existing per-controller annotation-reference table convention already established for IngressRoute/Gateway sections and add the D-04 cache-footprint note plus the D-23 naming-asymmetry callout. |

## Metadata

**Analog search scope:** `internal/operator/*.go` (controllers + tests), `cmd/operator/main.go`, `charts/router-hosts-operator/**`, `Taskfile.yml`
**Files scanned:** `ingressroute_controller.go`, `gateway_controller.go`, `hostmapping_controller.go`, `hostclient.go`, `gateway_controller_test.go`, `main.go`, `clusterrole.yaml`, `values.yaml`, `deployment.yaml`, `Taskfile.yml`
**Pattern extraction date:** 2026-07-26
