# Phase 7: Gateway API Support - Pattern Map

**Mapped:** 2026-07-25
**Files analyzed:** 7 (2 create, 5 modify)
**Analogs found:** 7 / 7

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|----------------|
| `internal/operator/gateway_controller.go` | controller | event-driven (CRUD sync via reconcile) | `internal/operator/ingressroute_controller.go` (lifecycle/annotation) + `internal/operator/hostmapping_controller.go` (requeue constants, `SetupWithManager` builder shape) | role-match (composite) |
| `internal/operator/gateway_controller_test.go` | test | event-driven | `internal/operator/ingressroute_controller_test.go` (fake client + DeletionTimestamp pattern) + `internal/operator/hostmapping_controller_test.go` (`mockHostClient`, scheme helper) | role-match (composite) |
| `internal/operator/ingressroute_controller.go` (modify) | controller | request-response (helper signature widen) | itself — signature-only change to `getHostIDsAnnotation`/`setHostIDsAnnotation` | exact |
| `cmd/operator/main.go` (modify) | config/wiring | request-response (startup wiring) | itself — existing scheme/flag/controller-registration blocks | exact |
| `charts/router-hosts-operator/templates/clusterrole.yaml` (modify) | config | CRUD (RBAC rule addition) | itself — existing Traefik rule block | exact |
| `charts/router-hosts-operator/templates/deployment.yaml` (modify) | config | CRUD (arg templating) | itself — existing `--default-ingress-ip` conditional arg block | exact |
| `charts/router-hosts-operator/values.yaml` (modify) | config | CRUD (values addition) | itself — existing `rbac:`/`routerHosts:` top-level blocks | exact |
| `go.mod` / `go.sum` (modify) | config | N/A | N/A (mechanical, `go get`/`go mod tidy`) | n/a |

## Pattern Assignments

### `internal/operator/gateway_controller.go` (controller, event-driven)

**Analogs:** `internal/operator/ingressroute_controller.go` (annotation/finalizer lifecycle), `internal/operator/hostmapping_controller.go` (constants, predicate/builder pattern)

**Imports pattern** — from `ingressroute_controller.go:1-26`, adapted (drop `unstructured`/`regexp`/`source`/`types`, add `sigs.k8s.io/gateway-api/apis/v1` as `gatewayv1`, `k8s.io/apimachinery/pkg/api/meta`, `k8s.io/apimachinery/pkg/runtime/schema` already present pattern):

```go
import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "log/slog"
    "maps"

    "github.com/fzymgc-house/router-hosts/internal/validation"
    "github.com/samber/oops"
    apierrors "k8s.io/apimachinery/pkg/api/errors"
    apimeta "k8s.io/apimachinery/pkg/api/meta"
    "k8s.io/apimachinery/pkg/runtime/schema"
    gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
    ctrl "sigs.k8s.io/controller-runtime"
    "sigs.k8s.io/controller-runtime/pkg/client"
    "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
    "sigs.k8s.io/controller-runtime/pkg/handler"
)
```

**Finalizer + reconcile skeleton** (`ingressroute_controller.go:82-116`, `:283-319`) — copy the `Reconcile`/`reconcileDelete` control flow verbatim, substituting the GVK-based unstructured `Get` for a typed `r.newObject()` / `client.Object` Get:

```go
// Reconcile shape to mirror (ingressroute_controller.go:82-116):
func (r *IngressRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    log := r.Log.With("ingressroute", req.NamespacedName)
    obj := &unstructured.Unstructured{}
    obj.SetGroupVersionKind(ingressRouteGVK)
    err := r.Get(ctx, req.NamespacedName, obj)
    if err != nil {
        if !apierrors.IsNotFound(err) { return ctrl.Result{}, err }
        // ... fallback probe for second kind — NOT needed in gateway controller;
        // gateway controller is one-kind-per-reconciler-instance, so this branches away.
    }
    if obj.GetDeletionTimestamp() != nil {
        return r.reconcileDelete(ctx, log, obj)
    }
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

Gateway controller finalizer const to use (locked by D-09): `gatewayCleanupFinalizer = "router-hosts.fzymgc.house/gateway-cleanup"` — a new package-level const alongside the existing `ingressRouteCleanupFinalizer`/`hostCleanupFinalizer` in the same file group (do not touch the existing consts).

**Annotation read/write** — reuse `getHostIDsAnnotation`/`setHostIDsAnnotation` directly (after the D-11 widening below); no new annotation helpers needed. Call sites match `ingressroute_controller.go:128, 179-184, 288, 304-309` exactly:

```go
existingIDs, err := getHostIDsAnnotation(log, obj) // obj is now client.Object
...
if !maps.Equal(existingIDs, newIDs) {
    if err := setHostIDsAnnotation(obj, newIDs); err != nil {
        return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation")
    }
    if err := r.Update(ctx, obj); err != nil {
        return ctrl.Result{}, oops.Wrapf(err, "updating annotations")
    }
}
```

**Per-host error handling / no-abort-on-error batch loop** (`ingressroute_controller.go:141-172`) — copy verbatim shape: iterate hostnames, call `AddHost`/`UpdateHost` unconditionally per D-13 (no `GetHost`-before-`UpdateHost` idempotency check — this is a deliberate divergence from `syncHost`'s idempotency guard; do NOT port `syncHost`'s `GetHost` pre-check into the gateway path), accumulate `newIDs`, delete stale entries not in `newIDs`, track `hadError` for the final `ctrl.Result{RequeueAfter: requeueDelayLong}` vs `ctrl.Result{}`.

**Requeue constants** — reuse `requeueDelayShort`/`requeueDelayLong` from `hostmapping_controller.go:28-29` directly (package-scoped, no re-declaration).

**RESTMapper CRD-gating helper** (new, per D-04/D-05, research "Code Examples" section) — write as a small pure function, unit-testable without a manager:

```go
func gatewayKindPresent(mapper apimeta.RESTMapper, gvk schema.GroupVersionKind) bool {
    _, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
    return err == nil
}
```

**SetupWithManager / SetupGatewayControllers** — use the typed `For(...)` + gated `Watches(...)` builder (research "Code Examples: Gateway-presence-gated SetupWithManager"), NOT the `WatchesRawSource(source.Kind(...))` pattern from `ingressroute_controller.go:452-478` (that pattern exists only because IngressRoute watches `unstructured` objects — deliberate divergence per CONTEXT `code_context`). Gate the Gateway watch itself on `gatewayKindPresent(mapper, gatewayGVK)` (research Pitfall 1) — this is a correction to the stale plan doc, not present in ingressroute_controller.go, must be added fresh.

**Error handling / oops wrapping** — `oops.Wrapf(err, "...")` on every fallible call, matching `ingressroute_controller.go:110, 180, 183, 304, 307, 314`. No `log.Fatal`/`os.Exit` anywhere (matches file-wide convention).

---

### `internal/operator/gateway_controller_test.go` (test, event-driven)

**Analogs:** `internal/operator/ingressroute_controller_test.go` (fake client + delete pattern), `internal/operator/hostmapping_controller_test.go` (`mockHostClient` — reuse, do not duplicate)

**mockHostClient — exact shape to reuse from `hostmapping_controller_test.go:24-73`** (same package, `internal/operator`, already visible to a new `_test.go` file in the same package — no import needed beyond being in package `operator`):

```go
type mockHostClient struct {
    addHostFn    func(ctx context.Context, ip, hostname, comment string, aliases, tags []string) (string, error)
    updateHostFn func(ctx context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error
    deleteHostFn func(ctx context.Context, id string) error
    getHostFn    func(ctx context.Context, id string) (*HostEntry, error)
    findHostFn   func(ctx context.Context, ip, hostname string) (*HostEntry, error)
}
// AddHost -> "test-id-1", nil when addHostFn nil
// UpdateHost -> nil when updateHostFn nil
// DeleteHost -> nil when deleteHostFn nil
// GetHost -> &HostEntry{ID: id, IP: "192.168.1.10", Hostname: "test.local", Version: "v1"} when getHostFn nil
// FindHost -> nil, nil when findHostFn nil
// Close() -> nil always
```

Gateway controller only calls `AddHost`/`UpdateHost`/`DeleteHost` (no `GetHost`/`FindHost` per D-13's simpler unconditional-update design) — tests only need to set `addHostFn`/`updateHostFn`/`deleteHostFn`.

**Scheme construction — build a fresh helper, do NOT reuse `ingressRouteScheme`** (that one registers `unstructured` GVKs for Traefik CRDs — irrelevant here). Follow `hostmapping_controller_test.go:75-81`'s `testScheme` shape, adapted:

```go
func gatewayScheme(t *testing.T) *runtime.Scheme {
    t.Helper()
    s := runtime.NewScheme()
    require.NoError(t, gatewayv1.Install(s))
    return s
}
```

**Deletion-timestamp fake-client seeding pattern — reuse verbatim** from `ingressroute_controller_test.go:201-243` (`TestReconcile_IngressRoute_Delete`):

```go
obj.SetFinalizers([]string{gatewayCleanupFinalizer}) // finalizer FIRST
obj.SetDeletionTimestamp(&now)                        // then DeletionTimestamp
k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(obj).Build()
```

Do NOT use `.Create()` + `.Delete()` — the ordering above bypasses fake-client deletion-timestamp stripping (only applies to the live `.Create()` RPC path), already proven safe in this exact controller-runtime version by the existing IngressRoute test.

**Field-index test requirement (D-17)** — any test exercising the Gateway→route map function MUST build the fake client with `.WithIndex(...)`:

```go
k8sClient := fake.NewClientBuilder().
    WithScheme(s).
    WithObjects(route, gw).
    WithIndex(&gatewayv1.HTTPRoute{}, parentRefIndexKey, routeParentRefIndexFunc).
    Build()
```

A bare builder makes a field-selector `List` silently return zero results — this is the single most important test-scaffolding pitfall for this phase (research Pitfall 2 note / D-17).

**`gatewayKindPresent` RESTMapper unit-test pattern** (research "Code Examples" section, no manager needed):

```go
func TestGatewayKindPresent_UsesRESTMapper(t *testing.T) {
    present := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
    mapper := apimeta.NewDefaultRESTMapper(nil)
    mapper.Add(present, apimeta.RESTScopeNamespace)
    httpGVK := gatewayRouteKinds()[0].gvk
    tlsGVK := gatewayRouteKinds()[2].gvk
    assert.True(t, gatewayKindPresent(mapper, httpGVK))
    assert.False(t, gatewayKindPresent(mapper, tlsGVK))
}
```

**Coverage note (research Pitfall 3):** `SetupWithManager`/`SetupGatewayControllers` are expected to sit at 0% direct unit coverage — this is precedent, not a gap (`IngressRouteReconciler.SetupWithManager` and `HostMappingReconciler.SetupWithManager` are both already 0% in the accepted ≥80% baseline). Extract `gatewayKindPresent` and `routeParentRefIndexFunc` as pure functions and test those directly instead.

---

### `internal/operator/ingressroute_controller.go` (modify — D-11 widening)

**Current exact bodies to widen** (`:386-406`, `:408-428`):

```go
func getHostIDsAnnotation(log *slog.Logger, obj *unstructured.Unstructured) (map[string]string, error) {
    annotations := obj.GetAnnotations()
    if annotations == nil {
        return nil, nil
    }
    raw, ok := annotations[hostIDsAnnotation]
    if !ok || raw == "" {
        return nil, nil
    }
    var ids map[string]string
    if err := json.Unmarshal([]byte(raw), &ids); err != nil {
        log.Error("corrupt host-ids annotation, host entries may be orphaned",
            "error", err, "object", obj.GetName())
        return nil, err
    }
    return ids, nil
}

func setHostIDsAnnotation(obj *unstructured.Unstructured, ids map[string]string) error {
    if len(ids) == 0 {
        annotations := obj.GetAnnotations()
        delete(annotations, hostIDsAnnotation)
        obj.SetAnnotations(annotations)
        return nil
    }
    data, err := json.Marshal(ids)
    if err != nil {
        return oops.Wrapf(err, "marshaling host IDs annotation")
    }
    annotations := obj.GetAnnotations()
    if annotations == nil {
        annotations = make(map[string]string)
    }
    annotations[hostIDsAnnotation] = string(data)
    obj.SetAnnotations(annotations)
    return nil
}
```

**Required change:** replace both `*unstructured.Unstructured` parameter types with `client.Object` (requires adding `"sigs.k8s.io/controller-runtime/pkg/client"` import if not already present — it already is, line 21). Bodies are unchanged (`GetAnnotations`/`SetAnnotations`/`GetName` are all on the `client.Object`/`metav1.Object` interface, and `*unstructured.Unstructured` still satisfies `client.Object`). All existing call sites (`:128, 179, 288, 304` and the two test files) compile unchanged since they pass `*unstructured.Unstructured` values, which satisfy the widened parameter type.

---

### `cmd/operator/main.go` (modify)

**Analog:** itself — existing scheme install / flag / controller-registration blocks

**Scheme registration pattern** (`main.go:55-63`) — add one more `Install`/`AddToScheme` call in the same style:

```go
scheme := runtime.NewScheme()
if err := clientgoscheme.AddToScheme(scheme); err != nil { ... }
if err := operatorv1alpha1.AddToScheme(scheme); err != nil { ... }
// NEW:
if err := gatewayv1.Install(scheme); err != nil {
    logger.Error("failed to add gateway-api scheme", "error", err)
    return err
}
```

**Flag pattern** (`main.go:34, 44`) — add `--enable-gateway` bool flag alongside the existing block; also widen the `--default-ingress-ip` help text per D-07 (currently `"Default IP for hosts extracted from IngressRoutes"`):

```go
var enableGateway bool
flag.BoolVar(&enableGateway, "enable-gateway", false, "Enable Gateway API HTTPRoute/GRPCRoute/TLSRoute controllers")
flag.StringVar(&defaultIngressIP, "default-ingress-ip", "", "Default IP for hosts extracted from IngressRoutes and Gateway API routes")
```

**Controller registration pattern** (`main.go:107-117`, the `IngressRouteReconciler` block) — the new `SetupGatewayControllers` call follows the same shape but is gated behind `enableGateway` (D-06):

```go
if enableGateway {
    if err := operator.SetupGatewayControllers(mgr, logger.With("controller", "gateway"), hostClient, defaultIngressIP, []string{"kubernetes"}); err != nil {
        logger.Error("unable to create Gateway API controllers", "error", err)
        return err
    }
}
```

---

### `charts/router-hosts-operator/templates/clusterrole.yaml` (modify)

**Analog:** itself — existing Traefik rule block (`:9-14`), same file, same `{{- if .Values.rbac.create -}}` guard (`:1`)

**Insertion point:** between the Traefik block (ends line 14) and the HostMapping block (starts line 16) — i.e. immediately after line 14, before line 16. New block, matching existing comment-then-rule style exactly:

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

---

### `charts/router-hosts-operator/templates/deployment.yaml` (modify)

**Analog:** itself — existing `--default-ingress-ip` conditional arg block (`:49-51`)

**Insertion point:** immediately after the `--default-ingress-ip` block, before `--health-probe-bind-address` (`:52`):

```yaml
            {{- if .Values.gateway.enabled }}
            - --enable-gateway
            {{- end }}
```

---

### `charts/router-hosts-operator/values.yaml` (modify)

**Analog:** itself — existing top-level `rbac:`/`routerHosts:` sibling blocks

**New top-level block** (no ordering convention to preserve — insert anywhere at top level, e.g. after the `rbac:` block or before `routerHosts:`):

```yaml
# Kubernetes Gateway API controllers. Disabled by default. The Gateway API CRDs
# (gateway.networking.k8s.io) MUST be installed in the cluster; this chart does
# not bundle them.
gateway:
  # Enable the HTTPRoute/GRPCRoute/TLSRoute controllers. Controllers are only
  # started for kinds whose CRD is actually installed (per-kind RESTMapper gating).
  enabled: false
```

Per D-07, no new IP-fallback value needed — update only the existing `routerHosts.defaultIngressIP` comment (`values.yaml:114-117`) to mention Gateway API routes alongside IngressRoutes:

```yaml
  # Default IP assigned to hosts extracted from IngressRoutes and Gateway API
  # routes (--default-ingress-ip). Required for these controllers to create
  # usable entries; leave empty only if you exclusively use HostMappings.
  defaultIngressIP: ""
```

---

### `go.mod` / `go.sum` (modify)

No analog — mechanical dependency addition. Per D-03 (build-gate-first): `go get sigs.k8s.io/gateway-api@v1.6.1 && go mod tidy && task build`, green before any controller code is written. If `go mod tidy` proposes moving any `k8s.io/*` off v0.36.1, STOP per D-01/D-03.

## Shared Patterns

### Finalizer + annotation lifecycle

**Source:** `internal/operator/ingressroute_controller.go:82-191, 283-319`
**Apply to:** `gateway_controller.go`'s `Reconcile`/`reconcileUpsert`/`reconcileDelete`
Add-finalizer-then-return-early, per-host errors never abort the batch, partial IDs always persisted, skip `Update` when the ID map is unchanged (`maps.Equal`).

### Requeue constants

**Source:** `internal/operator/hostmapping_controller.go:28-29`
**Apply to:** all new requeue results in `gateway_controller.go` — `requeueDelayShort = 5 * time.Second`, `requeueDelayLong = 30 * time.Second`. Do not redeclare; reference the package-scoped consts directly.

### Error wrapping

**Source:** `internal/operator/ingressroute_controller.go` (every fallible call site) and `internal/operator/hostmapping_controller.go` (same)
**Apply to:** every fallible operation in `gateway_controller.go`: `oops.Wrapf(err, "<context>")`. No `log.Fatal`/`os.Exit` anywhere.

### mockHostClient

**Source:** `internal/operator/hostmapping_controller_test.go:24-73`
**Apply to:** `gateway_controller_test.go` — reuse directly (same package `operator`), do not declare a second mock type.

### Fake-client DeletionTimestamp seeding

**Source:** `internal/operator/ingressroute_controller_test.go:201-243` (`TestReconcile_IngressRoute_Delete`)
**Apply to:** all Gateway route delete-path tests: set `Finalizers` then `DeletionTimestamp`, then `WithObjects(...)`.

## No Analog Found

None — every file in this phase has at least a role-match or exact analog in the existing codebase.

## Metadata

**Analog search scope:** `internal/operator/`, `cmd/operator/`, `charts/router-hosts-operator/`
**Files scanned:** `ingressroute_controller.go`, `ingressroute_controller_test.go`, `hostmapping_controller.go`, `hostmapping_controller_test.go`, `hostclient.go`, `main.go`, `templates/clusterrole.yaml`, `templates/deployment.yaml`, `values.yaml`
**Pattern extraction date:** 2026-07-25
