package operator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/samber/oops"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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

// parentRefIndexKey is the field-index key registered on each route kind's
// parentRefs (D-17). routeParentRefIndexFunc is its extractor and
// mapGatewayToRoutes is its only reader (via client.MatchingFields); both
// must agree on the same "<namespace>/<name>" format and the same
// namespace-defaulting rule, or a Gateway change silently stops propagating
// to the routes that reference it.
const parentRefIndexKey = "spec.parentRefs.gateway"

// routeParentRefIndexFunc is the field-index extractor for parentRefIndexKey.
// It emits "<namespace>/<name>" for every Gateway-kind parentRef declared on
// obj, in declaration order, defaulting the namespace to obj's own namespace
// when a parentRef sets none — the same defaulting resolveIP already
// applies. It is a pure function over client.Object, so it is unit-testable
// without a manager (D-17), and always returns a non-nil (possibly empty)
// slice.
//
// WR-02: a parentRef whose Kind is set and not "Gateway" (e.g. a GAMMA-style
// Service mesh parent) is skipped — it can never name a Gateway object, so
// indexing it would only pollute the field index with an entry
// mapGatewayToRoutes can never match.
func routeParentRefIndexFunc(obj client.Object) []string {
	refs := parentRefsOf(obj)
	keys := make([]string, 0, len(refs))
	for _, ref := range refs {
		if !isGatewayKindRef(ref) {
			continue
		}
		ns := obj.GetNamespace()
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}
		keys = append(keys, ns+"/"+string(ref.Name))
	}
	return keys
}

// isGatewayKindRef reports whether ref names a Gateway-kind parent. Per the
// Gateway API spec, ParentReference.Kind defaults to "Gateway" when unset,
// so a nil Kind is treated as a Gateway reference.
func isGatewayKindRef(ref gatewayv1.ParentReference) bool {
	return ref.Kind == nil || string(*ref.Kind) == "Gateway"
}

// mapGatewayToRoutes is the handler.MapFunc that re-enqueues every route of
// this reconciler's kind whose parentRefs name gw (GW-02): a Gateway status
// change — most importantly a changed or newly-populated status.addresses —
// re-triggers a reconcile of every dependent route without polling, since
// syncRoute's UpdateHost call is unconditional (D-13) and simply resolves a
// fresh IP on that reconcile. Any List or list-extraction failure is logged
// and treated as "no routes to enqueue" (nil) rather than panicking or
// propagating the error to the caller, which controller-runtime does not
// expect a MapFunc to return.
func (r *GatewayRouteReconciler) mapGatewayToRoutes(ctx context.Context, gw client.Object) []reconcile.Request {
	key := gw.GetNamespace() + "/" + gw.GetName()

	list := r.newList()
	if err := r.List(ctx, list, client.MatchingFields{parentRefIndexKey: key}); err != nil {
		r.Log.Error("failed to list routes for Gateway re-enqueue", "gateway", key, "kind", r.KindName, "error", err)
		return nil
	}

	items, err := apimeta.ExtractList(list)
	if err != nil {
		r.Log.Error("failed to extract route list for Gateway re-enqueue", "gateway", key, "kind", r.KindName, "error", err)
		return nil
	}

	requests := make([]reconcile.Request, 0, len(items))
	for _, item := range items {
		obj, ok := item.(client.Object)
		if !ok {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
	}
	return requests
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

// reconcileDelete removes every host entry this route owns before releasing
// the finalizer, mirroring ingressroute_controller.go's reconcileDelete.
// Deletion always happens before the finalizer is dropped, never the other
// order: removing the finalizer first would let Kubernetes garbage-collect
// the object — and its host-ids annotation, the only record of what this
// controller created — while entries it still names are live on the
// router (D-09).
//
// A corrupt host-ids annotation returns an error and requeues after
// requeueDelayShort without deleting anything or touching the finalizer
// (D-14): proceeding on a partial view could treat a still-tracked hostname
// as unknown and either skip deleting it or, worse, drop the finalizer while
// entries the annotation could no longer describe remain live.
//
// A partial delete (some DeleteHost calls fail) persists the still-live IDs
// back to the annotation, keeps the finalizer, and requeues after
// requeueDelayShort so the next reconcile retries only the remainder
// (D-14) — no entry is ever orphaned by being forgotten. The finalizer is
// removed only once every tracked ID has been confirmed deleted.
func (r *GatewayRouteReconciler) reconcileDelete(ctx context.Context, log *slog.Logger, obj client.Object) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(obj, gatewayCleanupFinalizer) {
		return ctrl.Result{}, nil
	}

	existingIDs, err := getHostIDsAnnotation(log, obj)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}

	remainingIDs := make(map[string]string, len(existingIDs))
	var hadDeleteError bool
	for hostname, id := range existingIDs {
		log.Info("deleting host entry for deleted route", "hostname", hostname, "hostId", id)
		if err := r.HostClient.DeleteHost(ctx, id); err != nil {
			if errors.Is(err, ErrHostNotFound) {
				// CR-03: the entry is already gone — the desired end state
				// (no live entry for this ID) was already reached, whether
				// it was deleted on a prior reconcile whose finalizer-removal
				// r.Update then failed, or out-of-band via the CLI. Treating
				// this as a real failure would fold it into remainingIDs and
				// hadDeleteError forever, permanently wedging the finalizer.
				log.Info("host entry already gone during cleanup", "hostname", hostname, "hostId", id)
				continue
			}
			log.Error("failed to delete host entry during cleanup", "hostname", hostname, "hostId", id, "error", err)
			remainingIDs[hostname] = id
			hadDeleteError = true
		}
	}
	if hadDeleteError {
		// Persist remaining IDs so they are not orphaned on the next reconcile.
		if err := setHostIDsAnnotation(obj, remainingIDs); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation after partial delete")
		}
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "updating %s annotations after partial delete", r.KindName)
		}
		return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
	}

	controllerutil.RemoveFinalizer(obj, gatewayCleanupFinalizer)
	if err := r.Update(ctx, obj); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "removing finalizer from %s", r.KindName)
	}

	return ctrl.Result{}, nil
}

// resolveIP resolves the target IP for a route by walking its parentRefs in
// declaration order, reading each parent Gateway's status, and returning the
// first IPAddress-typed address found. Falls back to r.DefaultIP when no
// parent Gateway yields one (D-15).
//
// A parentRef whose Kind is set and not "Gateway" is skipped without a Get
// call (WR-02): it names some other parent kind (e.g. a GAMMA-style Service
// mesh parent), which today would only fail-safe with a wasted NotFound Get,
// but is now filtered explicitly and consistently with
// routeParentRefIndexFunc.
//
// A parent Gateway Get that fails with NotFound is an ordinary "parent not
// created yet" condition and is skipped silently; any other Get failure is
// logged at Error level naming the Gateway, but the walk still continues to
// the next parentRef either way. resolveIP never fails the reconcile itself —
// an unreachable parent must not prevent a later parent or r.DefaultIP from
// supplying an IP (D-16).
func (r *GatewayRouteReconciler) resolveIP(ctx context.Context, log *slog.Logger, obj client.Object) string {
	for _, ref := range parentRefsOf(obj) {
		if !isGatewayKindRef(ref) {
			continue
		}
		ns := obj.GetNamespace()
		if ref.Namespace != nil {
			ns = string(*ref.Namespace)
		}

		gw := &gatewayv1.Gateway{}
		if err := r.Get(ctx, client.ObjectKey{Namespace: ns, Name: string(ref.Name)}, gw); err != nil {
			if !apierrors.IsNotFound(err) {
				log.Error("failed to get parent Gateway", "namespace", ns, "name", ref.Name, "error", err)
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

// syncRoute converges router host entries with the route's currently
// declared hostnames: a hostname not yet tracked in the host-ids annotation
// is created, an already-tracked hostname is updated unconditionally
// (D-13), and a hostname no longer present in hostnames is deleted from both
// the router and the annotation (GW-01).
//
// It refuses to create or update any entry when resolveIP yields no IP
// (D-16) — writing an entry with no resolved IP would publish wrong DNS —
// but the annotation is still read and the stale-cleanup pass below still
// runs even then (CR-01): HostClient.DeleteHost takes only an ID, never an
// IP, so pruning hostnames the spec no longer declares carries none of the
// IP-correctness risk that gates creates and updates. Without this, a route
// whose hostnames were edited down while its parent Gateway had no address
// would leave the removed hostnames' entries live on the router forever.
//
// A per-host failure never aborts the batch: the failing hostname is logged
// and skipped for its own operation, the rest of the batch still runs, and
// the result requeues after requeueDelayLong instead of returning an error
// (D-14) — except the no-IP case, which requeues after the shorter
// requeueDelayShort so a Gateway that gains an address is picked up sooner.
// A corrupt host-ids annotation is the one failure that does abort
// immediately, returning an error and requeuing after requeueDelayShort
// without touching the router at all — proceeding on a partial view of the
// annotation could mistake a still-tracked hostname for a removed one and
// delete a live entry (D-14).
func (r *GatewayRouteReconciler) syncRoute(ctx context.Context, log *slog.Logger, obj client.Object, hostnames []string) (ctrl.Result, error) {
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

	noIP := ip == ""
	var hadError bool
	if noIP {
		// CR-01: no IP resolved — skip the create/update loop entirely
		// (D-16), but carry every currently-tracked, still-declared hostname
		// forward into newIDs so the stale-cleanup pass below only targets
		// hostnames actually absent from `hostnames`, not every tracked ID.
		log.Warn("no IP resolved for route; skipping create/update, still pruning stale entries")
		hadError = true
		for _, hostname := range hostnames {
			if id, ok := existingIDs[hostname]; ok {
				newIDs[hostname] = id
			}
		}
	} else {
		for _, hostname := range hostnames {
			if id, ok := existingIDs[hostname]; ok {
				// D-13: UpdateHost is issued unconditionally for every tracked
				// hostname, even when the resolved IP is unchanged from the
				// previous reconcile. This deliberately diverges from
				// ingressroute_controller.go's syncHost, which reads the
				// current entry first via GetHost and skips a no-op update —
				// that idempotency guard is NOT ported here. The unconditional
				// update is what propagates a changed Gateway IP without this
				// controller keeping any "last known IP" state of its own. Do
				// not "align" this with syncHost without re-deriving the
				// tradeoff recorded in D-13.
				if err := r.HostClient.UpdateHost(ctx, id, ip, hostname, comment, nil, tags, ""); err != nil {
					if errors.Is(err, ErrHostNotFound) {
						// CR-04: the tracked ID vanished out-of-band (e.g.
						// deleted directly via the CLI while still named in
						// this route's annotation). Recreate it, mirroring
						// ingressroute_controller.go's syncHost self-heal —
						// the spec is the source of truth — instead of
						// retaining a dead ID that can never successfully
						// update again and would wedge this hostname forever.
						log.Warn("host entry vanished before update; recreating", "hostname", hostname, "staleHostId", id)
						newID, addErr := r.addOrAdoptGatewayHost(ctx, log, ip, hostname, comment, tags)
						if addErr != nil {
							log.Error("failed to recreate vanished host entry", "hostname", hostname, "error", addErr)
							hadError = true
							// The stale ID is dead; nothing to retain.
							continue
						}
						newIDs[hostname] = newID
						continue
					}
					log.Error("failed to update host entry", "hostname", hostname, "hostId", id, "error", err)
					hadError = true
					// Retain the known ID so the stale-cleanup pass below does
					// not mistake this still-tracked hostname for a removed one
					// and issue a spurious DeleteHost (D-14).
					newIDs[hostname] = id
					continue
				}
				newIDs[hostname] = id
				continue
			}

			// Not yet tracked: create, adopting a pre-existing entry on
			// AlreadyExists (CR-02) rather than orphaning it — see
			// addOrAdoptGatewayHost.
			id, err := r.addOrAdoptGatewayHost(ctx, log, ip, hostname, comment, tags)
			if err != nil {
				log.Error("failed to add host entry", "hostname", hostname, "error", err)
				hadError = true
				// No prior ID to retain — a failed create has nothing to track.
				continue
			}
			newIDs[hostname] = id
		}
	}

	// Stale-cleanup pass: delete every entry this object owns that is no
	// longer among the current hostnames. Runs unconditionally, even when
	// ip == "" (CR-01), since HostClient.DeleteHost takes only an ID, never
	// an IP. Every deletion target comes from this object's own annotation —
	// never from a hostname lookup, an IP lookup, or a cross-object query —
	// so this can never delete an entry owned by another route, a
	// HostMapping, or an IngressRoute (threat T-07-02).
	for hostname, id := range existingIDs {
		if _, ok := newIDs[hostname]; ok {
			continue
		}
		if err := r.HostClient.DeleteHost(ctx, id); err != nil {
			if errors.Is(err, ErrHostNotFound) {
				// CR-04: already gone — the desired end state was already
				// reached. Drop it entirely; retaining it in newIDs would
				// make it indistinguishable from an in-sync entry on the
				// next reconcile's !maps.Equal check, permanently wedging
				// the annotation and the requeue loop.
				log.Info("stale host entry already gone", "hostname", hostname, "hostId", id)
				continue
			}
			log.Error("failed to delete stale host entry", "hostname", hostname, "hostId", id, "error", err)
			// Retain the ID so it is not orphaned from the annotation.
			newIDs[hostname] = id
			hadError = true
			continue
		}
		log.Info("stale host entry deleted from Gateway API route", "hostname", hostname, "hostId", id)
	}

	// Persist the annotation only when the ID map actually changed, matching
	// the IngressRoute controller's no-op-write avoidance (D-13). A no-op
	// Update bumps the resourceVersion and re-triggers the watch for nothing.
	if !maps.Equal(existingIDs, newIDs) {
		if err := setHostIDsAnnotation(obj, newIDs); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation")
		}
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "updating %s annotations", r.KindName)
		}
	}

	if hadError {
		if noIP {
			return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
		}
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}
	return ctrl.Result{}, nil
}

// addOrAdoptGatewayHost creates a host entry for (ip, hostname), adopting a
// pre-existing entry via FindHost when the server reports AlreadyExists,
// mirroring ingressroute_controller.go's addOrAdopt (CR-02).
//
// Without this, a create that races ahead of a persisted annotation — e.g.
// AddHost succeeds but the batch's later r.Update fails — leaves the created
// entry permanently orphaned: the next reconcile reads the still-stale
// annotation, treats the hostname as untracked, retries AddHost for the same
// (ip, hostname) pair, and gets AlreadyExists back forever with no path to
// recover the ID. Adopting the existing entry here closes that gap.
func (r *GatewayRouteReconciler) addOrAdoptGatewayHost(ctx context.Context, log *slog.Logger, ip, hostname, comment string, tags []string) (string, error) {
	id, err := r.HostClient.AddHost(ctx, ip, hostname, comment, nil, tags)
	if err == nil {
		log.Info("host entry created from Gateway API route", "hostname", hostname, "hostId", id)
		return id, nil
	}
	if !errors.Is(err, ErrHostAlreadyExists) {
		return "", oops.Wrapf(err, "creating host %s", hostname)
	}

	existing, findErr := r.HostClient.FindHost(ctx, ip, hostname)
	if findErr != nil {
		return "", oops.Wrapf(findErr, "finding host %s for adoption", hostname)
	}
	if existing == nil {
		// Race: the entry vanished between AddHost and FindHost. Surface an
		// error so the reconcile requeues and retries.
		return "", oops.Errorf("host %s reported AlreadyExists but was not found for adoption", hostname)
	}
	// T-07-02: adopt ONLY an entry this exact object previously created.
	// FindHost exact-matches on (ip, hostname) alone, which is NOT proof of
	// ownership: the server enforces uniqueness on that pair, so the conflicting
	// entry may belong to an IngressRoute, a HostMapping, or another route —
	// including another route of this same kind. Adopting it would write a
	// foreign ID into this object's host-ids annotation, and the stale-cleanup
	// and reconcileDelete passes would then legitimately DeleteHost it,
	// silently destroying another owner's live DNS entry.
	//
	// This is reachable in normal operation, not theoretical: --default-ingress-ip
	// is a single flag shared by the IngressRoute and Gateway controllers, so an
	// IngressRoute hostname and a Gateway route hostname routinely collide on the
	// same IP — exactly the Traefik-to-Gateway-API migration this phase enables.
	//
	// The comment is the per-object identity (k8s-gateway:<namespace>/<name>);
	// tags only identify the controller kind and cannot separate two routes of
	// the same kind. Both are checked: the comment establishes ownership, the
	// tags are defense in depth against a user-authored comment collision.
	if existing.Comment != comment || !hasGatewayProvenance(existing.Tags, r.KindName) {
		return "", oops.Errorf(
			"refusing to adopt host %s (id %s): owned by another object (comment %q tags %v, want comment %q with gateway + %s)",
			hostname, existing.ID, existing.Comment, existing.Tags, comment, r.KindName,
		)
	}
	log.Info("adopted existing host entry from Gateway API route", "hostname", hostname, "hostId", existing.ID)
	return existing.ID, nil
}

// hasGatewayProvenance reports whether tags identify a host entry created by
// the Gateway route controller for kindName. syncRoute stamps every entry it
// writes with "gateway" plus the reconciler's KindName, so requiring both
// excludes IngressRoute entries ("traefik", "ingress"), HostMapping entries,
// and entries owned by a Gateway route of a different kind.
func hasGatewayProvenance(tags []string, kindName string) bool {
	return slices.Contains(tags, "gateway") && slices.Contains(tags, kindName)
}

// gatewayKindPresent reports whether gvk is resolvable via mapper, used to
// gate controller setup on CRD presence (D-04/D-05) without a manager.
func gatewayKindPresent(mapper apimeta.RESTMapper, gvk schema.GroupVersionKind) bool {
	_, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	return err == nil
}

// gatewayGVK is the GroupVersionKind for the Gateway kind itself, resolved
// via the same non-deprecated gatewayGroupVersionKind helper the three route
// kinds use (not gatewayv1.SchemeGroupVersion, which staticcheck SA1019
// flags as deprecated). It gates the cross-object Gateway watch on CRD
// presence exactly like the route kinds are gated (D-04/D-05): unlike a
// route kind, an ungated Gateway watch can fail the manager's shared
// informer cache at startup even when every route CRD is installed, taking
// down the already-shipped HostMapping and IngressRoute controllers with it
// (research Pitfall 1).
var gatewayGVK = gatewayGroupVersionKind("Gateway")

// SetupGatewayControllers registers a GatewayRouteReconciler for every
// Gateway API route kind whose CRD is present in the cluster, skipping (and
// logging) any that are absent. The Gateway CRD's presence is resolved once,
// via the same RESTMapper and gatewayKindPresent helper, and threaded into
// every route controller's SetupWithManager so the Gateway watch clause is
// gated identically for all three kinds.
func SetupGatewayControllers(mgr ctrl.Manager, log *slog.Logger, hc HostClient, defaultIP string, defaultTags []string) error {
	mapper := mgr.GetRESTMapper()
	watchGateway := gatewayKindPresent(mapper, gatewayGVK)

	for _, k := range gatewayRouteKinds() {
		if !gatewayKindPresent(mapper, k.gvk) {
			log.Info("Gateway API CRD not installed; skipping controller",
				"kind", k.name, "requiredAPIVersion", "gateway.networking.k8s.io/v1")
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
		if err := rec.SetupWithManager(mgr, watchGateway); err != nil {
			return oops.Wrapf(err, "setting up gateway controller for %s", k.name)
		}
		log.Info("Gateway API controller registered", "kind", k.name, "watchesGateway", watchGateway)
	}
	return nil
}

// SetupWithManager registers this reconciler with the controller manager. It
// registers the parentRefs field index unconditionally — the route kind
// gate in SetupGatewayControllers has already confirmed this kind's CRD is
// installed before calling this method, so indexing it is always safe — and
// adds the cross-object Gateway watch only when watchGateway is true
// (research Pitfall 1): a route CRD being installed does not imply the
// Gateway CRD is, and an ungated Watches(&gatewayv1.Gateway{}, ...) clause
// fails the manager's shared informer cache at startup on such a cluster,
// taking every other controller down with it. When watchGateway is false,
// routes still reconcile and resolveIP falls back to --default-ingress-ip
// (D-16); only the event-driven re-enqueue on a Gateway status change is
// lost, and with no Gateway CRD there is no Gateway object to change anyway.
func (r *GatewayRouteReconciler) SetupWithManager(mgr ctrl.Manager, watchGateway bool) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), r.newObject(), parentRefIndexKey, routeParentRefIndexFunc); err != nil {
		return oops.Wrapf(err, "indexing %s parentRefs", r.KindName)
	}

	bldr := ctrl.NewControllerManagedBy(mgr).
		For(r.newObject()).
		Named("gateway-" + r.KindName)
	if watchGateway {
		bldr = bldr.Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayToRoutes))
	}
	return bldr.Complete(r)
}
