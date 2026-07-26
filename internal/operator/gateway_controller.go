package operator

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"strings"

	"github.com/samber/oops"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/fzymgc-house/router-hosts/internal/validation"
)

// gatewayCleanupFinalizer is the single finalizer applied to every Gateway
// API route kind (HTTPRoute, GRPCRoute, TLSRoute) this operator reconciles.
// It is deliberately distinct from ingressRouteCleanupFinalizer and
// hostCleanupFinalizer so the three controllers never contend for the same
// finalizer (D-09). This string is a one-way door once released: renaming it
// strands the old finalizer on every live route object.
const gatewayCleanupFinalizer = "router-hosts.fzymgc.house/gateway-cleanup"

// gatewayRouteKind describes one Gateway API route kind this operator can
// reconcile: its GVK (for CRD-presence detection) and typed object/list
// factories (so Reconcile can do a single unambiguous typed Get per request).
type gatewayRouteKind struct {
	name      string
	gvk       schema.GroupVersionKind
	newObject func() client.Object
	newList   func() client.ObjectList
}

// gatewayGroupVersionKind builds a schema.GroupVersionKind for the given kind
// name in the gatewayv1 group/version, using the non-deprecated
// gatewayv1.GroupVersion (metav1.GroupVersion has no WithKind method).
func gatewayGroupVersionKind(kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   gatewayv1.GroupVersion.Group,
		Version: gatewayv1.GroupVersion.Version,
		Kind:    kind,
	}
}

// gatewayRouteKinds returns the set of Gateway API route kinds this operator
// reconciles, in the order httproute, grpcroute, tlsroute. All three are
// served from sigs.k8s.io/gateway-api/apis/v1 (D-02): TLSRoute graduated to
// that package in v1.6.1 and is its storage version, so there is no
// apis/v1alpha2 surface to handle here.
func gatewayRouteKinds() []gatewayRouteKind {
	return []gatewayRouteKind{
		{
			name:      "httproute",
			gvk:       gatewayGroupVersionKind("HTTPRoute"),
			newObject: func() client.Object { return &gatewayv1.HTTPRoute{} },
			newList:   func() client.ObjectList { return &gatewayv1.HTTPRouteList{} },
		},
		{
			name:      "grpcroute",
			gvk:       gatewayGroupVersionKind("GRPCRoute"),
			newObject: func() client.Object { return &gatewayv1.GRPCRoute{} },
			newList:   func() client.ObjectList { return &gatewayv1.GRPCRouteList{} },
		},
		{
			name:      "tlsroute",
			gvk:       gatewayGroupVersionKind("TLSRoute"),
			newObject: func() client.Object { return &gatewayv1.TLSRoute{} },
			newList:   func() client.ObjectList { return &gatewayv1.TLSRouteList{} },
		},
	}
}

// hostnamesOf returns the hostnames declared on a Gateway API route object.
// Kinds not covered (e.g. Gateway) return nil.
func hostnamesOf(obj client.Object) []string {
	switch route := obj.(type) {
	case *gatewayv1.HTTPRoute:
		return hostnamesFrom(route.Spec.Hostnames)
	case *gatewayv1.GRPCRoute:
		return hostnamesFrom(route.Spec.Hostnames)
	case *gatewayv1.TLSRoute:
		return hostnamesFrom(route.Spec.Hostnames)
	default:
		return nil
	}
}

// hostnamesFrom converts a []gatewayv1.Hostname to []string. Shared by every
// hostnamesOf arm since the three route specs declare an identically shaped
// Hostnames field.
func hostnamesFrom(hostnames []gatewayv1.Hostname) []string {
	out := make([]string, 0, len(hostnames))
	for _, h := range hostnames {
		out = append(out, string(h))
	}
	return out
}

// parentRefsOf returns the parentRefs declared on a Gateway API route object.
// Kinds not covered (e.g. Gateway) return nil.
func parentRefsOf(obj client.Object) []gatewayv1.ParentReference {
	switch route := obj.(type) {
	case *gatewayv1.HTTPRoute:
		return route.Spec.ParentRefs
	case *gatewayv1.GRPCRoute:
		return route.Spec.ParentRefs
	case *gatewayv1.TLSRoute:
		return route.Spec.ParentRefs
	default:
		return nil
	}
}

// extractHostnames returns the hostnames declared on a route that are safe to
// become router DNS entries, in first-appearance order. This is the single
// hostname filter every route kind passes through before any HostClient
// call:
//
//  1. A `*`-prefixed wildcard is skipped — it cannot be a concrete entry
//     (D-18).
//  2. Duplicates are skipped, tracked by a seen set.
//  3. Each remaining name is validated with validation.ValidateHostname;
//     failures are logged and skipped, never fatal (D-18).
//  4. A dot-less (non-FQDN) name is accepted but logged at Warn, matching
//     HostMapping/IngressRoute behavior (D-19).
func extractHostnames(log *slog.Logger, obj client.Object) []string {
	seen := make(map[string]struct{})
	var hostnames []string
	for _, h := range hostnamesOf(obj) {
		if strings.HasPrefix(h, "*") {
			continue
		}
		if _, exists := seen[h]; exists {
			continue
		}
		seen[h] = struct{}{}

		if err := validation.ValidateHostname(h); err != nil {
			log.Warn("skipping invalid hostname extracted from Gateway API route", "hostname", h, "error", err)
			continue
		}

		if !strings.Contains(h, ".") {
			log.Warn("hostname has no dot; accepting as non-FQDN per D-19", "hostname", h)
		}

		hostnames = append(hostnames, h)
	}
	return hostnames
}

// GatewayRouteReconciler watches one Gateway API route kind (HTTPRoute,
// GRPCRoute, or TLSRoute) and syncs its declared hostnames to router-hosts
// host entries, resolving the target IP from the route's parent Gateway.
type GatewayRouteReconciler struct {
	client.Client
	HostClient HostClient
	Log        *slog.Logger

	// KindName identifies the route kind this reconciler instance handles
	// (e.g. "httproute"), used in logging, host tags, and controller naming.
	KindName string

	newObject func() client.Object
	newList   func() client.ObjectList

	// DefaultIP is the fallback IP used when no parent Gateway reports an
	// IPAddress-typed status address.
	DefaultIP string

	// DefaultTags are applied to all host entries created from Gateway API
	// routes, in addition to "gateway" and KindName.
	DefaultTags []string
}

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=httproutes;grpcroutes;tlsroutes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gateways,verbs=get;list;watch

// Reconcile handles a single Gateway API route resource of this reconciler's
// configured kind.
func (r *GatewayRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With(r.KindName, req.NamespacedName)

	obj := r.newObject()
	if err := r.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if obj.GetDeletionTimestamp() != nil {
		return r.reconcileDelete(ctx, log, obj)
	}

	// Ensure finalizer. Return after adding so the next reconcile works with
	// a fresh object from the informer cache.
	if !controllerutil.ContainsFinalizer(obj, gatewayCleanupFinalizer) {
		controllerutil.AddFinalizer(obj, gatewayCleanupFinalizer)
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "adding finalizer to %s", r.KindName)
		}
		return ctrl.Result{}, nil
	}

	return r.syncRoute(ctx, log, obj, extractHostnames(log, obj))
}

// reconcileDelete handles route deletion. Stubbed for the tracer; filled in
// with the full cleanup lifecycle in plan 04.
func (r *GatewayRouteReconciler) reconcileDelete(_ context.Context, _ *slog.Logger, _ client.Object) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

// resolveIP resolves the target IP for a route by walking its parentRefs in
// declaration order, reading each parent Gateway's status, and returning the
// first IPAddress-typed address found. Falls back to r.DefaultIP when no
// parent Gateway yields one. The error and fallback matrix (e.g. distinguishing
// "Gateway not found" from "Gateway has no address yet") is expanded in
// plan 03.
func (r *GatewayRouteReconciler) resolveIP(ctx context.Context, log *slog.Logger, obj client.Object) string {
	for _, ref := range parentRefsOf(obj) {
		ns := obj.GetNamespace()
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}

		gw := &gatewayv1.Gateway{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(ref.Name)}, gw); err != nil {
			log.Debug("failed to get parent Gateway", "namespace", ns, "name", ref.Name, "error", err)
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

// syncRoute is the tracer's happy path: it creates a host entry for every
// hostname not yet tracked in the host-ids annotation and persists the
// resulting map. The update/delete diff, per-host error accumulation, and
// requeue paths land in plan 04.
func (r *GatewayRouteReconciler) syncRoute(ctx context.Context, log *slog.Logger, obj client.Object, hostnames []string) (ctrl.Result, error) {
	if len(hostnames) == 0 {
		log.Debug("no hostnames extracted from route")
		return ctrl.Result{}, nil
	}

	ip := r.resolveIP(ctx, log, obj)

	existingIDs, err := getHostIDsAnnotation(log, obj)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}
	newIDs := make(map[string]string, len(hostnames))

	comment := fmt.Sprintf("k8s-gateway:%s/%s", obj.GetNamespace(), obj.GetName())

	// Copy DefaultTags to avoid mutating the shared backing array (D-12).
	tags := make([]string, 0, len(r.DefaultTags)+2)
	tags = append(tags, r.DefaultTags...)
	tags = append(tags, "gateway", r.KindName)

	for _, hostname := range hostnames {
		if id, ok := existingIDs[hostname]; ok {
			newIDs[hostname] = id
			continue
		}
		id, err := r.HostClient.AddHost(ctx, ip, hostname, comment, nil, tags)
		if err != nil {
			return ctrl.Result{RequeueAfter: requeueDelayLong}, oops.Wrapf(err, "adding host %s", hostname)
		}
		log.Info("host entry created from Gateway API route", "hostname", hostname, "hostId", id)
		newIDs[hostname] = id
	}

	// Persist the annotation only when the ID map actually changed, matching
	// the IngressRoute controller's no-op-write avoidance (D-13).
	if !maps.Equal(existingIDs, newIDs) {
		if err := setHostIDsAnnotation(obj, newIDs); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation")
		}
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "updating %s annotations", r.KindName)
		}
	}

	return ctrl.Result{}, nil
}

// gatewayKindPresent reports whether gvk is resolvable via mapper, used to
// gate controller setup on CRD presence (D-04/D-05) without a manager.
func gatewayKindPresent(mapper apimeta.RESTMapper, gvk schema.GroupVersionKind) bool {
	_, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil
}

// SetupGatewayControllers registers a GatewayRouteReconciler for every
// Gateway API route kind whose CRD is present in the cluster, skipping (and
// logging) any that are absent. The Gateway watch and field index land in
// plan 05.
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
			Log:         log.With("kind", k.name),
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

// SetupWithManager registers this reconciler with the controller manager.
// The parentRefs field index and the Gateway watch land in plan 05.
func (r *GatewayRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(r.newObject()).
		Named("gateway-" + r.KindName).
		Complete(r)
}
