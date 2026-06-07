# Kubernetes Gateway API Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Gateway API controller to the router-hosts operator that registers route hostnames as DNS host entries, resolving IPs from the parent Gateway's `status.addresses`.

**Architecture:** One controller per route kind (`HTTPRoute`, `GRPCRoute`, `TLSRoute`) sharing a `syncRoute` core via a `newObject` factory; each `For()`s its own typed object so a `ctrl.Request` maps to a single typed `Get`. Gateways are watched as a secondary input (parentRefs field-indexer + `Watches` map-func) for IP resolution only. Mirrors the existing IngressRoute controller's `host-ids` annotation + cleanup-finalizer lifecycle.

**Tech Stack:** Go 1.26, `sigs.k8s.io/gateway-api` v1.5.1, controller-runtime v0.23.1, `samber/oops`, testify, controller-runtime fake client.

**Design spec:** `docs/plans/2026-06-07-gateway-api-support-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/operator/gateway_controller.go` (create) | `GatewayRouteReconciler`, `syncRoute`, `Reconcile`, `reconcileDelete`, type-switch helpers (`hostnamesOf`, `parentRefsOf`), `extractHostnames`, `resolveIP`, field indexer + `mapGatewayToRoutes`, `SetupGatewayControllers` |
| `internal/operator/gateway_controller_test.go` (create) | Unit tests for all of the above |
| `internal/operator/ingressroute_controller.go` (modify) | Widen `getHostIDsAnnotation`/`setHostIDsAnnotation` params from `*unstructured.Unstructured` to `client.Object` |
| `cmd/operator/main.go` (modify) | Install gateway-api scheme, add `--enable-gateway` flag, call `SetupGatewayControllers` |
| `charts/router-hosts-operator/templates/clusterrole.yaml` (modify) | Add `gateway.networking.k8s.io` RBAC rules |
| `charts/router-hosts-operator/values.yaml` (modify) | Add `gateway` config block |
| `charts/router-hosts-operator/templates/deployment.yaml` (modify) | Template `--enable-gateway` arg |
| `go.mod` / `go.sum` (modify) | Add `sigs.k8s.io/gateway-api v1.5.1` |

**Grounded facts (verified against the codebase and the v1.5.1 module):**

- `HostClient` interface (`internal/operator/hostclient.go`): `AddHost(ctx, ip, hostname, comment string, aliases, tags []string) (string, error)`, `UpdateHost(ctx, id, ip, hostname, comment string, aliases, tags []string, version string) error`, `DeleteHost(ctx, id string) error`.
- Reusable package-level constants (same `operator` package): `requeueDelayShort = 5 * time.Second`, `requeueDelayLong = 30 * time.Second` (in `hostmapping_controller.go`); `hostIDsAnnotation = "router-hosts.fzymgc.house/host-ids"` (in `ingressroute_controller.go`).
- `validation.ValidateHostname(hostname string) error`.
- Test mock `mockHostClient` with `addHostFn`/`updateHostFn`/`deleteHostFn`/`getHostFn` fields is defined in `hostmapping_controller_test.go` (same package — reuse directly).
- gateway-api v1.5.1 types: `apis/v1` has `HTTPRoute`, `GRPCRoute`, `Gateway` (+ `…List`); `apis/v1alpha2` has `TLSRoute`. Both packages expose `Install` / `AddToScheme`. Routes embed `CommonRouteSpec` inline → `.Spec.Hostnames []gatewayv1.Hostname` (Hostname is `string`) and `.Spec.ParentRefs []gatewayv1.ParentReference`. `ParentReference.Name` is `ObjectName` (string), `.Namespace` is `*Namespace` (`*string`). `Gateway.Status.Addresses []gatewayv1.GatewayStatusAddress` → `.Type *AddressType`, `.Value string`; const `gatewayv1.IPAddressType AddressType = "IPAddress"`. v1alpha2 aliases `Hostname`/`ParentReference`/`CommonRouteSpec` to v1, so all three route kinds share one hostname/parentRef type.

---

## Task 1: Add the gateway-api dependency (build gate)

This task is a hard pass/fail gate. No controller code is written until `task build` is green with the dependency added.

**Files:**

- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the dependency at the pinned version**

Run:

```bash
go get sigs.k8s.io/gateway-api@v1.5.1
go mod tidy
```

Expected: `go.mod` gains `sigs.k8s.io/gateway-api v1.5.1`; no downgrade of `k8s.io/*` (they stay at `v0.35.1`). If `go mod tidy` reports a conflicting upgrade of `k8s.io/*`, STOP — the version pin is wrong; revisit the design's Dependency section before continuing.

- [ ] **Step 2: Verify the build is green**

Run: `task build`
Expected: PASS — all binaries build with the new module in the graph.

- [ ] **Step 3: Commit**

```bash
jj commit -m "build(operator): add sigs.k8s.io/gateway-api v1.5.1

Pinned to align with k8s.io/* v0.35.1. Refs: rh-9uc"
```

---

## Task 2: Generalize annotation helpers to `client.Object`

The Gateway controller reuses `getHostIDsAnnotation`/`setHostIDsAnnotation`, currently typed to `*unstructured.Unstructured`. Widen them to `client.Object` (which `*unstructured.Unstructured` satisfies) so both controllers share them. Zero behavioral change.

**Files:**

- Modify: `internal/operator/ingressroute_controller.go:299` and `:319`
- Test: existing `internal/operator/ingressroute_controller_test.go` (regression guard)

- [ ] **Step 1: Confirm the existing tests pass before changing anything**

Run: `task test -- -run 'IngressRoute' ./internal/operator/`
Expected: PASS (baseline).

- [ ] **Step 2: Widen `getHostIDsAnnotation`**

In `internal/operator/ingressroute_controller.go`, change the signature only (body unchanged):

```go
func getHostIDsAnnotation(log *slog.Logger, obj client.Object) (map[string]string, error) {
```

- [ ] **Step 3: Widen `setHostIDsAnnotation`**

```go
func setHostIDsAnnotation(obj client.Object, ids map[string]string) error {
```

The body already calls only `obj.GetAnnotations()` / `obj.SetAnnotations()`, both on `client.Object`. The `client` package is already imported in this file.

- [ ] **Step 4: Verify no regression**

Run: `task test -- -run 'IngressRoute' ./internal/operator/`
Expected: PASS — call sites pass `*unstructured.Unstructured`, which satisfies `client.Object`, so they compile and behave identically.

- [ ] **Step 5: Commit**

```bash
jj commit -m "refactor(operator): widen host-ids annotation helpers to client.Object

Lets the Gateway controller reuse the helpers; *unstructured.Unstructured
still satisfies client.Object so IngressRoute call sites are unchanged.
Refs: rh-9uc"
```

---

## Task 3: Hostname extraction (`hostnamesOf` + `extractHostnames`)

**Files:**

- Create: `internal/operator/gateway_controller.go`
- Test: `internal/operator/gateway_controller_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/operator/gateway_controller_test.go`:

```go
package operator

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func httpRoute(name, ns string, hostnames ...string) *gatewayv1.HTTPRoute {
	hs := make([]gatewayv1.Hostname, 0, len(hostnames))
	for _, h := range hostnames {
		hs = append(hs, gatewayv1.Hostname(h))
	}
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       gatewayv1.HTTPRouteSpec{Hostnames: hs},
	}
}

func TestHostnamesOf_AllKinds(t *testing.T) {
	grpc := &gatewayv1.GRPCRoute{Spec: gatewayv1.GRPCRouteSpec{
		Hostnames: []gatewayv1.Hostname{"grpc.example.com"}}}
	tls := &gatewayv1alpha2.TLSRoute{Spec: gatewayv1alpha2.TLSRouteSpec{
		Hostnames: []gatewayv1.Hostname{"tls.example.com"}}}

	assert.Equal(t, []string{"a.example.com"}, hostnamesOf(httpRoute("r", "default", "a.example.com")))
	assert.Equal(t, []string{"grpc.example.com"}, hostnamesOf(grpc))
	assert.Equal(t, []string{"tls.example.com"}, hostnamesOf(tls))
	assert.Nil(t, hostnamesOf(&gatewayv1.Gateway{})) // non-route → nil
}

func TestExtractHostnames_SkipsWildcardsAndInvalid(t *testing.T) {
	var obj client.Object = httpRoute("r", "default",
		"good.example.com", "*.wild.example.com", "bad_host", "good.example.com")
	got := extractHostnames(slog.Default(), obj)
	assert.Equal(t, []string{"good.example.com"}, got) // wildcard, invalid, and dup removed
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `task test -- -run 'TestHostnamesOf_AllKinds|TestExtractHostnames' ./internal/operator/`
Expected: FAIL (compile error — `hostnamesOf`/`extractHostnames` undefined).

- [ ] **Step 3: Write the minimal implementation**

Create `internal/operator/gateway_controller.go`:

```go
package operator

import (
	"log/slog"
	"strings"

	"github.com/fzymgc-house/router-hosts/internal/validation"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const gatewayCleanupFinalizer = "router-hosts.fzymgc.house/gateway-cleanup"

// hostnamesOf reads spec.hostnames from any supported Gateway API route kind.
// Non-route objects yield nil.
func hostnamesOf(obj client.Object) []string {
	var hs []gatewayv1.Hostname
	switch o := obj.(type) {
	case *gatewayv1.HTTPRoute:
		hs = o.Spec.Hostnames
	case *gatewayv1.GRPCRoute:
		hs = o.Spec.Hostnames
	case *gatewayv1alpha2.TLSRoute:
		hs = o.Spec.Hostnames
	default:
		return nil
	}
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		out = append(out, string(h))
	}
	return out
}

// parentRefsOf reads spec.parentRefs from any supported route kind.
func parentRefsOf(obj client.Object) []gatewayv1.ParentReference {
	switch o := obj.(type) {
	case *gatewayv1.HTTPRoute:
		return o.Spec.ParentRefs
	case *gatewayv1.GRPCRoute:
		return o.Spec.ParentRefs
	case *gatewayv1alpha2.TLSRoute:
		return o.Spec.ParentRefs
	default:
		return nil
	}
}

// extractHostnames returns the validated, de-duplicated, non-wildcard hostnames
// from a route. Wildcards (e.g. *.example.com) cannot be host entries and are
// skipped; invalid hostnames are logged and skipped.
func extractHostnames(log *slog.Logger, obj client.Object) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, h := range hostnamesOf(obj) {
		if strings.HasPrefix(h, "*") {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		if err := validation.ValidateHostname(h); err != nil {
			log.Warn("skipping invalid hostname from Gateway API route",
				"hostname", h, "error", err)
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `task test -- -run 'TestHostnamesOf_AllKinds|TestExtractHostnames' ./internal/operator/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj commit -m "feat(operator): add Gateway API route hostname extraction

Refs: rh-9uc"
```

---

## Task 4: IP resolution from the parent Gateway (`resolveIP`)

**Files:**

- Modify: `internal/operator/gateway_controller.go`
- Test: `internal/operator/gateway_controller_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/operator/gateway_controller_test.go`:

```go
import (
	// add to the existing import block:
	"context"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func gatewayScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(s))
	require.NoError(t, gatewayv1alpha2.Install(s))
	return s
}

func gatewayWithIP(name, ns, ip string) *gatewayv1.Gateway {
	t := gatewayv1.IPAddressType
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Type: &t, Value: ip}},
		},
	}
}

func routeWithParent(ns, gwNS, gwName string) *gatewayv1.HTTPRoute {
	r := httpRoute("r", ns, "app.example.com")
	ref := gatewayv1.ParentReference{Name: gatewayv1.ObjectName(gwName)}
	if gwNS != "" {
		n := gatewayv1.Namespace(gwNS)
		ref.Namespace = &n
	}
	r.Spec.ParentRefs = []gatewayv1.ParentReference{ref}
	return r
}

func TestResolveIP_FromParentGateway(t *testing.T) {
	s := gatewayScheme(t)
	gw := gatewayWithIP("gw", "infra", "10.1.2.3")
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(gw).Build()
	r := &GatewayRouteReconciler{Client: c, Log: slog.Default(), DefaultIP: "9.9.9.9"}

	route := routeWithParent("default", "infra", "gw")
	assert.Equal(t, "10.1.2.3", r.resolveIP(context.Background(), slog.Default(), route))
}

func TestResolveIP_FallsBackToFlagWhenGatewayMissing(t *testing.T) {
	s := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(s).Build()
	r := &GatewayRouteReconciler{Client: c, Log: slog.Default(), DefaultIP: "9.9.9.9"}

	route := routeWithParent("default", "infra", "absent")
	assert.Equal(t, "9.9.9.9", r.resolveIP(context.Background(), slog.Default(), route))
}

func TestResolveIP_SkipsHostnameTypeAddress(t *testing.T) {
	s := gatewayScheme(t)
	ht := gatewayv1.HostnameAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "infra"},
		Status: gatewayv1.GatewayStatus{Addresses: []gatewayv1.GatewayStatusAddress{
			{Type: &ht, Value: "lb.example.com"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(gw).Build()
	r := &GatewayRouteReconciler{Client: c, Log: slog.Default(), DefaultIP: "9.9.9.9"}
	// no IPAddress-typed address → fall back to flag
	assert.Equal(t, "9.9.9.9", r.resolveIP(context.Background(), slog.Default(), routeWithParent("default", "infra", "gw")))
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `task test -- -run 'TestResolveIP' ./internal/operator/`
Expected: FAIL (compile error — `GatewayRouteReconciler` and `resolveIP` undefined).

- [ ] **Step 3: Write the struct and `resolveIP`**

Append to `internal/operator/gateway_controller.go` (and add the new imports to the file's import block: `context`, `log/slog` already present, `github.com/samber/oops`, `apierrors "k8s.io/apimachinery/pkg/api/errors"`, `"k8s.io/apimachinery/pkg/types"`):

```go
// GatewayRouteReconciler reconciles one Gateway API route kind, syncing its
// hostnames to the router-hosts server. One instance is created per enabled
// route kind; all instances share this Reconcile and syncRoute logic.
type GatewayRouteReconciler struct {
	client.Client
	HostClient  HostClient
	Log         *slog.Logger
	KindName    string                   // "httproute" | "grpcroute" | "tlsroute"
	newObject   func() client.Object     // allocates this instance's typed route
	newList     func() client.ObjectList // for the Gateway map-func List
	DefaultIP   string                   // --default-ingress-ip fallback
	DefaultTags []string
}

// resolveIP returns the first IPAddress-typed status address of any parent
// Gateway, falling back to DefaultIP when no parent yields one.
func (r *GatewayRouteReconciler) resolveIP(ctx context.Context, log *slog.Logger, obj client.Object) string {
	for _, ref := range parentRefsOf(obj) {
		ns := obj.GetNamespace()
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		gw := &gatewayv1.Gateway{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: string(ref.Name)}, gw); err != nil {
			if !apierrors.IsNotFound(err) {
				log.Error("failed to get parent Gateway for IP resolution",
					"gateway", ns+"/"+string(ref.Name), "error", err)
			}
			continue
		}
		for _, addr := range gw.Status.Addresses {
			if addr.Type != nil && *addr.Type == gatewayv1.IPAddressType && addr.Value != "" {
				return addr.Value
			}
		}
	}
	return r.DefaultIP
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `task test -- -run 'TestResolveIP' ./internal/operator/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj commit -m "feat(operator): resolve Gateway API route IP from parent Gateway status

Refs: rh-9uc"
```

---

## Task 5: Reconcile + syncRoute core (create/update/delete + finalizer)

**Files:**

- Modify: `internal/operator/gateway_controller.go`
- Test: `internal/operator/gateway_controller_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/operator/gateway_controller_test.go` (add `ctrl "sigs.k8s.io/controller-runtime"` and `"k8s.io/apimachinery/pkg/types"` to imports):

```go
func newHTTPRouteReconciler(c client.Client, mock *mockHostClient) *GatewayRouteReconciler {
	return &GatewayRouteReconciler{
		Client:      c,
		HostClient:  mock,
		Log:         slog.Default(),
		KindName:    "httproute",
		newObject:   func() client.Object { return &gatewayv1.HTTPRoute{} },
		newList:     func() client.ObjectList { return &gatewayv1.HTTPRouteList{} },
		DefaultIP:   "10.0.0.1",
		DefaultTags: []string{"kubernetes"},
	}
}

func reconcileOnce(t *testing.T, r *GatewayRouteReconciler, name, ns string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name, Namespace: ns}})
	require.NoError(t, err)
	return res
}

func TestReconcile_HTTPRoute_CreatesHost(t *testing.T) {
	s := gatewayScheme(t)
	route := httpRoute("web", "default", "app.example.com")
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var added []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, _, tags []string) (string, error) {
			added = append(added, hostname)
			assert.Equal(t, "10.0.0.1", ip)
			assert.Equal(t, "k8s-gateway:default/web", comment)
			assert.Contains(t, tags, "gateway")
			assert.Contains(t, tags, "httproute")
			return "host-1", nil
		},
	}
	r := newHTTPRouteReconciler(c, mock)

	reconcileOnce(t, r, "web", "default")   // adds finalizer
	reconcileOnce(t, r, "web", "default")   // creates host
	assert.Equal(t, []string{"app.example.com"}, added)

	var got gatewayv1.HTTPRoute
	require.NoError(t, c.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &got))
	ids, err := getHostIDsAnnotation(slog.Default(), &got)
	require.NoError(t, err)
	assert.Equal(t, "host-1", ids["app.example.com"])
}

func TestReconcile_HTTPRoute_DeletesHostsOnFinalize(t *testing.T) {
	s := gatewayScheme(t)
	route := httpRoute("web", "default", "app.example.com")
	route.Finalizers = []string{gatewayCleanupFinalizer}
	route.Annotations = map[string]string{hostIDsAnnotation: `{"app.example.com":"host-1"}`}
	now := metav1.Now()
	route.DeletionTimestamp = &now
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var deleted []string
	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, id string) error { deleted = append(deleted, id); return nil },
	}
	r := newHTTPRouteReconciler(c, mock)

	reconcileOnce(t, r, "web", "default")
	assert.Equal(t, []string{"host-1"}, deleted)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `task test -- -run 'TestReconcile_HTTPRoute' ./internal/operator/`
Expected: FAIL (compile error — `Reconcile` undefined).

- [ ] **Step 3: Implement `Reconcile`, `syncRoute`, `reconcileDelete`**

Append to `internal/operator/gateway_controller.go` (add `"fmt"`, `ctrl "sigs.k8s.io/controller-runtime"`, `"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"` to imports):

```go
// Reconcile handles a single route of this controller's kind.
func (r *GatewayRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With(r.KindName, req.NamespacedName)

	obj := r.newObject()
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if obj.GetDeletionTimestamp() != nil {
		return r.reconcileDelete(ctx, log, obj)
	}

	if !controllerutil.ContainsFinalizer(obj, gatewayCleanupFinalizer) {
		controllerutil.AddFinalizer(obj, gatewayCleanupFinalizer)
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "adding finalizer to %s", r.KindName)
		}
		return ctrl.Result{}, nil
	}

	return r.syncRoute(ctx, log, obj, extractHostnames(log, obj))
}

// syncRoute creates/updates/deletes host entries to match the route's hostnames.
// It mirrors the IngressRoute controller: per-host errors don't abort the batch,
// partial IDs are always persisted, and failures requeue.
func (r *GatewayRouteReconciler) syncRoute(ctx context.Context, log *slog.Logger, obj client.Object, hostnames []string) (ctrl.Result, error) {
	if len(hostnames) == 0 {
		log.Debug("no hostnames extracted from route")
		return ctrl.Result{}, nil
	}

	ip := r.resolveIP(ctx, log, obj)
	if ip == "" {
		log.Warn("no IP resolved for route; requeueing", "route", obj.GetName())
		return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
	}

	existingIDs, err := getHostIDsAnnotation(log, obj)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}
	newIDs := make(map[string]string)

	comment := fmt.Sprintf("k8s-gateway:%s/%s", obj.GetNamespace(), obj.GetName())
	tags := make([]string, 0, len(r.DefaultTags)+2)
	tags = append(tags, r.DefaultTags...)
	tags = append(tags, "gateway", r.KindName)

	var hadError bool
	for _, hostname := range hostnames {
		if id, ok := existingIDs[hostname]; ok {
			if err := r.HostClient.UpdateHost(ctx, id, ip, hostname, comment, nil, tags, ""); err != nil {
				log.Error("failed to update host entry", "hostname", hostname, "error", err)
				newIDs[hostname] = id
				hadError = true
				continue
			}
			newIDs[hostname] = id
		} else {
			id, err := r.HostClient.AddHost(ctx, ip, hostname, comment, nil, tags)
			if err != nil {
				log.Error("failed to create host entry", "hostname", hostname, "error", err)
				hadError = true
				continue
			}
			newIDs[hostname] = id
			log.Info("host entry created from Gateway API route", "hostname", hostname, "hostId", id)
		}
	}

	for hostname, id := range existingIDs {
		if _, ok := newIDs[hostname]; !ok {
			if err := r.HostClient.DeleteHost(ctx, id); err != nil {
				log.Error("failed to delete stale host entry", "hostname", hostname, "error", err)
				newIDs[hostname] = id
				hadError = true
			} else {
				log.Info("stale host entry deleted", "hostname", hostname, "hostId", id)
			}
		}
	}

	if err := setHostIDsAnnotation(obj, newIDs); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation")
	}
	if err := r.Update(ctx, obj); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "updating route annotations")
	}

	if hadError {
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}
	return ctrl.Result{}, nil
}

// reconcileDelete removes all host entries tracked by this route, then the finalizer.
func (r *GatewayRouteReconciler) reconcileDelete(ctx context.Context, log *slog.Logger, obj client.Object) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(obj, gatewayCleanupFinalizer) {
		return ctrl.Result{}, nil
	}
	existingIDs, err := getHostIDsAnnotation(log, obj)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}
	remaining := make(map[string]string, len(existingIDs))
	var hadError bool
	for hostname, id := range existingIDs {
		if err := r.HostClient.DeleteHost(ctx, id); err != nil {
			log.Error("failed to delete host entry during cleanup", "hostname", hostname, "error", err)
			remaining[hostname] = id
			hadError = true
		}
	}
	if hadError {
		if err := setHostIDsAnnotation(obj, remaining); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation after partial delete")
		}
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "updating route after partial delete")
		}
		return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
	}
	controllerutil.RemoveFinalizer(obj, gatewayCleanupFinalizer)
	if err := r.Update(ctx, obj); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "removing finalizer from %s", r.KindName)
	}
	return ctrl.Result{}, nil
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `task test -- -run 'TestReconcile_HTTPRoute' ./internal/operator/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj commit -m "feat(operator): add Gateway API route reconcile and sync core

Refs: rh-9uc"
```

---

## Task 6: parentRefs field indexer + Gateway map function

**Files:**

- Modify: `internal/operator/gateway_controller.go`
- Test: `internal/operator/gateway_controller_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/operator/gateway_controller_test.go`:

```go
func TestRouteParentRefIndexFunc(t *testing.T) {
	r := routeWithParent("default", "infra", "gw")        // explicit parent ns
	assert.Equal(t, []string{"infra/gw"}, routeParentRefIndexFunc(r))

	r2 := routeWithParent("default", "", "gw")            // parent ns defaults to route ns
	assert.Equal(t, []string{"default/gw"}, routeParentRefIndexFunc(r2))
}

func TestMapGatewayToRoutes(t *testing.T) {
	s := gatewayScheme(t)
	match := routeWithParent("default", "infra", "gw")
	match.Name = "match"
	other := routeWithParent("default", "infra", "different")
	other.Name = "other"

	c := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(match, other).
		WithIndex(&gatewayv1.HTTPRoute{}, parentRefIndexKey, routeParentRefIndexFunc).
		Build()
	r := newHTTPRouteReconciler(c, &mockHostClient{})

	gw := &gatewayv1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "infra"}}
	reqs := r.mapGatewayToRoutes(context.Background(), gw)
	require.Len(t, reqs, 1)
	assert.Equal(t, "match", reqs[0].Name)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `task test -- -run 'TestRouteParentRefIndexFunc|TestMapGatewayToRoutes' ./internal/operator/`
Expected: FAIL (compile error — `routeParentRefIndexFunc`, `parentRefIndexKey`, `mapGatewayToRoutes` undefined).

- [ ] **Step 3: Implement the indexer and map function**

Append to `internal/operator/gateway_controller.go` (add `apimeta "k8s.io/apimachinery/pkg/api/meta"` and `"sigs.k8s.io/controller-runtime/pkg/reconcile"` to imports):

```go
const parentRefIndexKey = "spec.parentRefs.gateway"

// routeParentRefIndexFunc indexes a route by its parent Gateways, formatted
// "<namespace>/<name>" (parent namespace defaults to the route's namespace).
func routeParentRefIndexFunc(obj client.Object) []string {
	refs := parentRefsOf(obj)
	keys := make([]string, 0, len(refs))
	for _, ref := range refs {
		ns := obj.GetNamespace()
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		keys = append(keys, ns+"/"+string(ref.Name))
	}
	return keys
}

// mapGatewayToRoutes enqueues every route of this controller's kind that
// references the changed Gateway (so an address change re-resolves the IP).
func (r *GatewayRouteReconciler) mapGatewayToRoutes(ctx context.Context, gw client.Object) []reconcile.Request {
	list := r.newList()
	key := gw.GetNamespace() + "/" + gw.GetName()
	if err := r.List(ctx, list, client.MatchingFields{parentRefIndexKey: key}); err != nil {
		r.Log.Error("listing routes for changed Gateway", "gateway", key, "error", err)
		return nil
	}
	items, err := apimeta.ExtractList(list)
	if err != nil {
		r.Log.Error("extracting route list", "error", err)
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(items))
	for _, it := range items {
		o, ok := it.(client.Object)
		if !ok {
			continue
		}
		reqs = append(reqs, reconcile.Request{NamespacedName: types.NamespacedName{
			Namespace: o.GetNamespace(), Name: o.GetName()}})
	}
	return reqs
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `task test -- -run 'TestRouteParentRefIndexFunc|TestMapGatewayToRoutes' ./internal/operator/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj commit -m "feat(operator): index Gateway API routes by parentRef for re-enqueue

Refs: rh-9uc"
```

---

## Task 7: Per-kind setup with RESTMapper gating (`SetupGatewayControllers`)

**Files:**

- Modify: `internal/operator/gateway_controller.go`
- Test: `internal/operator/gateway_controller_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/operator/gateway_controller_test.go` (add `apimeta "k8s.io/apimachinery/pkg/api/meta"` and `"k8s.io/apimachinery/pkg/runtime/schema"` to imports):

```go
func TestGatewayKinds_ListsAllThree(t *testing.T) {
	kinds := gatewayRouteKinds()
	names := []string{}
	for _, k := range kinds {
		names = append(names, k.name)
		assert.NotNil(t, k.newObject())
		assert.NotNil(t, k.newList())
	}
	assert.Equal(t, []string{"httproute", "grpcroute", "tlsroute"}, names)
}

func TestGatewayKindPresent_UsesRESTMapper(t *testing.T) {
	// Mapper that knows only HTTPRoute.
	present := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	mapper := apimeta.NewDefaultRESTMapper(nil)
	mapper.Add(present, apimeta.RESTScopeNamespace)

	httpGVK := gatewayRouteKinds()[0].gvk
	tlsGVK := gatewayRouteKinds()[2].gvk
	assert.True(t, gatewayKindPresent(mapper, httpGVK))
	assert.False(t, gatewayKindPresent(mapper, tlsGVK))
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `task test -- -run 'TestGatewayKinds_ListsAllThree|TestGatewayKindPresent' ./internal/operator/`
Expected: FAIL (compile error — `gatewayRouteKinds`, `gatewayKindPresent` undefined).

- [ ] **Step 3: Implement the kinds table, presence check, setup, and per-instance `SetupWithManager`**

Append to `internal/operator/gateway_controller.go` (add `ctrlruntime "sigs.k8s.io/controller-runtime"` is already `ctrl`; add `"sigs.k8s.io/controller-runtime/pkg/handler"`, `"k8s.io/apimachinery/pkg/runtime/schema"`):

```go
type gatewayRouteKind struct {
	name      string
	gvk       schema.GroupVersionKind
	newObject func() client.Object
	newList   func() client.ObjectList
}

// gatewayRouteKinds returns the supported route kinds in priority order.
func gatewayRouteKinds() []gatewayRouteKind {
	return []gatewayRouteKind{
		{
			name:      "httproute",
			gvk:       gatewayv1.SchemeGroupVersion.WithKind("HTTPRoute"),
			newObject: func() client.Object { return &gatewayv1.HTTPRoute{} },
			newList:   func() client.ObjectList { return &gatewayv1.HTTPRouteList{} },
		},
		{
			name:      "grpcroute",
			gvk:       gatewayv1.SchemeGroupVersion.WithKind("GRPCRoute"),
			newObject: func() client.Object { return &gatewayv1.GRPCRoute{} },
			newList:   func() client.ObjectList { return &gatewayv1.GRPCRouteList{} },
		},
		{
			name:      "tlsroute",
			gvk:       gatewayv1alpha2.SchemeGroupVersion.WithKind("TLSRoute"),
			newObject: func() client.Object { return &gatewayv1alpha2.TLSRoute{} },
			newList:   func() client.ObjectList { return &gatewayv1alpha2.TLSRouteList{} },
		},
	}
}

// gatewayKindPresent reports whether the cluster has the CRD for gvk installed.
func gatewayKindPresent(mapper apimeta.RESTMapper, gvk schema.GroupVersionKind) bool {
	_, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil
}

// SetupGatewayControllers builds one controller per route kind whose CRD is
// installed. Absent kinds are skipped (logged). If no route CRDs are present,
// no controllers are built.
func SetupGatewayControllers(mgr ctrl.Manager, log *slog.Logger, hc HostClient, defaultIP string, defaultTags []string) error {
	mapper := mgr.GetRESTMapper()
	for _, k := range gatewayRouteKinds() {
		if !gatewayKindPresent(mapper, k.gvk) {
			log.Info("Gateway API CRD not installed; skipping controller", "kind", k.name)
			continue
		}
		rec := &GatewayRouteReconciler{
			Client:      mgr.GetClient(),
			HostClient:  hc,
			Log:         log.With("controller", "gateway-"+k.name),
			KindName:    k.name,
			newObject:   k.newObject,
			newList:     k.newList,
			DefaultIP:   defaultIP,
			DefaultTags: defaultTags,
		}
		if err := rec.SetupWithManager(mgr); err != nil {
			return oops.Wrapf(err, "setting up gateway controller for %s", k.name)
		}
		log.Info("Gateway API controller registered", "kind", k.name)
	}
	return nil
}

// SetupWithManager registers this route-kind controller: a parentRefs field
// index plus a route watch and a secondary Gateway watch for IP re-resolution.
func (r *GatewayRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), r.newObject(), parentRefIndexKey, routeParentRefIndexFunc); err != nil {
		return oops.Wrapf(err, "indexing %s parentRefs", r.KindName)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(r.newObject()).
		Named("gateway-" + r.KindName).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayToRoutes)).
		Complete(r)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `task test -- -run 'TestGatewayKinds_ListsAllThree|TestGatewayKindPresent' ./internal/operator/`
Expected: PASS.

- [ ] **Step 5: Run the full operator package tests and lint**

Run: `task test -- ./internal/operator/` then `golangci-lint run ./internal/operator/...`
Expected: PASS; no lint errors. Confirm coverage with `task test:coverage:ci`.

- [ ] **Step 6: Commit**

```bash
jj commit -m "feat(operator): wire per-kind Gateway controllers with CRD gating

Refs: rh-9uc"
```

---

## Task 8: Wire into `cmd/operator/main.go`

**Files:**

- Modify: `cmd/operator/main.go`

- [ ] **Step 1: Add the gateway-api scheme registration**

In `cmd/operator/main.go`, add imports:

```go
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
```

After the existing `operatorv1alpha1.AddToScheme(scheme)` block, add:

```go
	if err := gatewayv1.Install(scheme); err != nil {
		logger.Error("failed to add gateway-api v1 scheme", "error", err)
		return err
	}
	if err := gatewayv1alpha2.Install(scheme); err != nil {
		logger.Error("failed to add gateway-api v1alpha2 scheme", "error", err)
		return err
	}
```

- [ ] **Step 2: Add the `--enable-gateway` flag**

In the flag block, add the variable and flag:

```go
	var enableGateway bool
	flag.BoolVar(&enableGateway, "enable-gateway", false, "Enable the Kubernetes Gateway API controllers")
```

- [ ] **Step 3: Register the controllers when enabled**

After the IngressRoute controller registration block, add:

```go
	if enableGateway {
		if err := operator.SetupGatewayControllers(mgr, logger, hostClient, defaultIngressIP, []string{"kubernetes"}); err != nil {
			logger.Error("unable to set up Gateway API controllers", "error", err)
			return err
		}
	}
```

- [ ] **Step 4: Verify build and operator startup compiles**

Run: `task build`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
jj commit -m "feat(operator): register Gateway API controllers behind --enable-gateway

Refs: rh-9uc"
```

---

## Task 9: ClusterRole RBAC + kubebuilder markers

**Files:**

- Modify: `internal/operator/gateway_controller.go` (markers)
- Modify: `charts/router-hosts-operator/templates/clusterrole.yaml`

- [ ] **Step 1: Add kubebuilder RBAC markers**

Above the `GatewayRouteReconciler` type in `internal/operator/gateway_controller.go`, add:

```go
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes;grpcroutes;tlsroutes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch
```

- [ ] **Step 2: Add the ClusterRole rules**

In `charts/router-hosts-operator/templates/clusterrole.yaml`, after the Traefik IngressRoute rule block, add:

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

- [ ] **Step 3: Lint the chart templates**

Run: `helm lint charts/router-hosts-operator` (or `task lint` if it covers charts)
Expected: PASS — no template errors.

- [ ] **Step 4: Commit**

```bash
jj commit -m "feat(operator): add Gateway API RBAC to ClusterRole and markers

Refs: rh-9uc"
```

---

## Task 10: Helm values + deployment `--enable-gateway` wiring

**Files:**

- Modify: `charts/router-hosts-operator/values.yaml`
- Modify: `charts/router-hosts-operator/templates/deployment.yaml`

- [ ] **Step 1: Add the `gateway` config block to values**

In `charts/router-hosts-operator/values.yaml`, add a top-level block (near `routerHosts`):

```yaml
# Kubernetes Gateway API controllers. Disabled by default. The Gateway API CRDs
# (gateway.networking.k8s.io) MUST be installed in the cluster; this chart does
# not bundle them. TLSRoute additionally requires the experimental channel.
gateway:
  # Enable the HTTPRoute/GRPCRoute/TLSRoute controllers. Controllers are only
  # started for kinds whose CRD is actually installed.
  enabled: false
```

- [ ] **Step 2: Template the flag in the deployment args**

In `charts/router-hosts-operator/templates/deployment.yaml`, inside the `args:` list (after the `--metrics-bind-address` arg, before the leader-elect block), add:

```yaml
            {{- if .Values.gateway.enabled }}
            - --enable-gateway
            {{- end }}
```

- [ ] **Step 3: Verify the rendered output**

Run:

```bash
helm template charts/router-hosts-operator --set gateway.enabled=true | grep -- '--enable-gateway'
```

Expected: the `--enable-gateway` arg appears. Re-run without `--set` and confirm it is absent.

- [ ] **Step 4: Commit**

```bash
jj commit -m "feat(operator): add gateway.enabled chart value and deployment wiring

Refs: rh-9uc"
```

---

## Task 11: Documentation + final verification

**Files:**

- Modify: `README.md` (operator section), `docs/guides/operations.md` (if it documents controllers)

- [ ] **Step 1: Document Gateway API support**

In the operator/feature section of `README.md`, add a bullet noting Gateway API (`HTTPRoute`/`GRPCRoute`/`TLSRoute`) support with IP resolution from the parent Gateway's `status.addresses`, enabled via `--enable-gateway` / `gateway.enabled`, and that the Gateway API CRDs are a cluster prerequisite.

- [ ] **Step 2: Run the full local CI pipeline**

Run: `task ci`
Expected: PASS — lint, test (≥80% coverage), build, buf checks all green.

- [ ] **Step 3: Commit**

```bash
jj commit -m "docs(operator): document Gateway API support

Refs: rh-9uc"
```

---

## Spec Coverage Check

| Spec section | Task(s) |
|--------------|---------|
| Dependency pin (v1.5.1, build gate) | 1 |
| Decision 1 (typed client) | 1, 3 |
| Decision 2 (per-kind controllers, factory, type-switch) | 5, 7 |
| Decision 2a (parentRefs indexer + Gateway watch) | 6, 7 |
| Decision 3 (IP resolution + fallback) | 4 |
| Decision 4 (RESTMapper CRD gating) | 7 |
| Annotation helper widening | 2 |
| Reconcile flow + error handling | 5 |
| RBAC + kubebuilder markers | 9 |
| Helm values + deployment | 10 |
| Testing (extraction, IP, finalizer, diff, indexer, gating) | 3–7 |
| Docs | 11 |

IngressRoute RBAC drift: **not a task** — already resolved by the v0.10.0 chart modernization (#296).
