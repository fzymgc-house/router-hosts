package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/fzymgc-house/router-hosts/internal/validation"
	"github.com/samber/oops"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	ingressRouteCleanupFinalizer = "router-hosts.fzymgc.house/ingressroute-cleanup"
	hostIDsAnnotation            = "router-hosts.fzymgc.house/host-ids"
)

var (
	// hostRegex matches Host(`example.com`) patterns in Traefik match rules.
	hostRegex = regexp.MustCompile(`Host\(` + "`" + `([^` + "`" + `]+)` + "`" + `\)`)
	// hostSNIRegex matches HostSNI(`example.com`) patterns in Traefik match rules.
	hostSNIRegex = regexp.MustCompile(`HostSNI\(` + "`" + `([^` + "`" + `]+)` + "`" + `\)`)

	// Traefik CRD GroupVersionResources.
	ingressRouteGVR = schema.GroupVersionResource{
		Group:    "traefik.io",
		Version:  "v1alpha1",
		Resource: "ingressroutes",
	}
	ingressRouteTCPGVR = schema.GroupVersionResource{
		Group:    "traefik.io",
		Version:  "v1alpha1",
		Resource: "ingressroutetcps",
	}

	ingressRouteGVK = schema.GroupVersionKind{
		Group:   "traefik.io",
		Version: "v1alpha1",
		Kind:    "IngressRoute",
	}
	ingressRouteTCPGVK = schema.GroupVersionKind{
		Group:   "traefik.io",
		Version: "v1alpha1",
		Kind:    "IngressRouteTCP",
	}
)

// IngressRouteReconciler watches Traefik IngressRoute and IngressRouteTCP
// resources and syncs extracted host entries to the router-hosts server.
type IngressRouteReconciler struct {
	client.Client
	HostClient HostClient
	Log        *slog.Logger

	// DefaultIP is the IP address assigned to hosts extracted from
	// IngressRoute resources (typically the cluster ingress IP).
	DefaultIP string

	// DefaultTags are applied to all host entries created from IngressRoutes.
	DefaultTags []string
}

// +kubebuilder:rbac:groups=traefik.io,resources=ingressroutes,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=traefik.io,resources=ingressroutetcps,verbs=get;list;watch;update;patch

// Reconcile handles a single IngressRoute or IngressRouteTCP resource.
func (r *IngressRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("ingressroute", req.NamespacedName)

	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(ingressRouteGVK)

	err := r.Get(ctx, req.NamespacedName, obj)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		// Try IngressRouteTCP if IngressRoute not found.
		obj.SetGroupVersionKind(ingressRouteTCPGVK)
		if tcpErr := r.Get(ctx, req.NamespacedName, obj); tcpErr != nil {
			return ctrl.Result{}, client.IgnoreNotFound(tcpErr)
		}
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

// reconcileUpsert creates or updates host entries from the IngressRoute spec.
// It processes all hosts even when individual operations fail, persists the
// annotation with whatever IDs are known, and requeues on any failure.
func (r *IngressRouteReconciler) reconcileUpsert(ctx context.Context, log *slog.Logger, obj *unstructured.Unstructured) (ctrl.Result, error) {
	hosts := extractHosts(log, obj)
	if len(hosts) == 0 {
		log.Debug("no hosts extracted from IngressRoute")
		return ctrl.Result{}, nil
	}

	existingIDs, err := getHostIDsAnnotation(log, obj)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}
	newIDs := make(map[string]string) // hostname -> hostID

	comment := fmt.Sprintf("k8s-ingress:%s/%s", obj.GetNamespace(), obj.GetName())

	// Copy DefaultTags to avoid mutating the shared backing array.
	tags := make([]string, 0, len(r.DefaultTags)+2)
	tags = append(tags, r.DefaultTags...)
	tags = append(tags, "traefik", "ingress")

	var hadError bool
	for _, hostname := range hosts {
		if id, ok := existingIDs[hostname]; ok {
			// Update existing entry.
			if err := r.HostClient.UpdateHost(ctx, id, r.DefaultIP, hostname, comment, nil, tags, ""); err != nil {
				log.Error("failed to update host entry", "hostname", hostname, "error", err)
				newIDs[hostname] = id // retain existing ID so it's not lost
				hadError = true
				continue
			}
			newIDs[hostname] = id
		} else {
			// Create new entry.
			id, err := r.HostClient.AddHost(ctx, r.DefaultIP, hostname, comment, nil, tags)
			if err != nil {
				log.Error("failed to create host entry", "hostname", hostname, "error", err)
				hadError = true
				continue
			}
			newIDs[hostname] = id
			log.Info("host entry created from IngressRoute", "hostname", hostname, "hostId", id)
		}
	}

	// Delete entries for hosts no longer in the spec.
	for hostname, id := range existingIDs {
		if _, ok := newIDs[hostname]; !ok {
			if err := r.HostClient.DeleteHost(ctx, id); err != nil {
				log.Error("failed to delete stale host entry", "hostname", hostname, "error", err)
				// Retain the entry so it's not orphaned from the annotation.
				newIDs[hostname] = id
				hadError = true
			} else {
				log.Info("stale host entry deleted", "hostname", hostname, "hostId", id)
			}
		}
	}

	// Always persist the annotation so partially-created IDs are tracked.
	if err := setHostIDsAnnotation(obj, newIDs); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation")
	}
	if err := r.Update(ctx, obj); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "updating IngressRoute annotations")
	}

	if hadError {
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}
	return ctrl.Result{}, nil
}

// reconcileDelete removes all host entries associated with this IngressRoute.
func (r *IngressRouteReconciler) reconcileDelete(ctx context.Context, log *slog.Logger, obj *unstructured.Unstructured) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(obj, ingressRouteCleanupFinalizer) {
		return ctrl.Result{}, nil
	}

	existingIDs, err := getHostIDsAnnotation(log, obj)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}
	for hostname, id := range existingIDs {
		log.Info("deleting host entry for deleted IngressRoute", "hostname", hostname, "hostId", id)
		if err := r.HostClient.DeleteHost(ctx, id); err != nil {
			log.Error("failed to delete host entry during cleanup", "hostname", hostname, "error", err)
			return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
		}
	}

	controllerutil.RemoveFinalizer(obj, ingressRouteCleanupFinalizer)
	if err := r.Update(ctx, obj); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "removing finalizer from IngressRoute")
	}

	return ctrl.Result{}, nil
}

// extractHosts extracts hostnames from IngressRoute/IngressRouteTCP match
// rules. It looks for Host(`...`) and HostSNI(`...`) patterns in
// spec.routes[].match fields (IngressRoute) and spec.routes[].match
// (IngressRouteTCP). Hostnames that fail validation are logged and skipped.
func extractHosts(log *slog.Logger, obj *unstructured.Unstructured) []string {
	routes, found, err := unstructured.NestedSlice(obj.Object, "spec", "routes")
	if err != nil || !found {
		return nil
	}

	seen := make(map[string]struct{})
	var hosts []string

	for _, route := range routes {
		routeMap, ok := route.(map[string]interface{})
		if !ok {
			continue
		}
		matchStr, ok := routeMap["match"].(string)
		if !ok {
			continue
		}
		for _, h := range extractHostsFromMatch(matchStr) {
			if _, exists := seen[h]; exists {
				continue
			}
			if err := validation.ValidateHostname(h); err != nil {
				log.Warn("skipping invalid hostname extracted from IngressRoute match rule",
					"hostname", h, "error", err)
				continue
			}
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
	}

	return hosts
}

// extractHostsFromMatch parses Host() and HostSNI() patterns from a
// single Traefik match rule string.
func extractHostsFromMatch(match string) []string {
	var hosts []string
	for _, re := range []*regexp.Regexp{hostRegex, hostSNIRegex} {
		hosts = appendRegexMatches(hosts, re, match)
	}
	return hosts
}

// appendRegexMatches appends non-empty capture group 1 matches from re against
// s to dst and returns the result.
func appendRegexMatches(dst []string, re *regexp.Regexp, s string) []string {
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		if len(m) > 1 {
			if h := strings.TrimSpace(m[1]); h != "" {
				dst = append(dst, h)
			}
		}
	}
	return dst
}

// getHostIDsAnnotation reads the hostname -> hostID mapping from the
// object's annotations. It returns an error if the annotation is present
// but contains corrupt JSON, preventing callers from proceeding with an
// incomplete view of existing host IDs.
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

// setHostIDsAnnotation stores the hostname -> hostID mapping as a JSON
// annotation on the object.
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

// SetupWithManager registers the IngressRoute reconciler with the
// controller manager. It sets up watches on both IngressRoute and
// IngressRouteTCP unstructured resources.
func (r *IngressRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ingressRoute := &unstructured.Unstructured{}
	ingressRoute.SetGroupVersionKind(ingressRouteGVK)

	ingressRouteTCP := &unstructured.Unstructured{}
	ingressRouteTCP.SetGroupVersionKind(ingressRouteTCPGVK)

	return ctrl.NewControllerManagedBy(mgr).
		Named("ingressroute").
		WatchesRawSource(source.Kind(
			mgr.GetCache(),
			ingressRoute,
			handler.TypedEnqueueRequestsFromMapFunc(func(_ context.Context, obj *unstructured.Unstructured) []reconcile.Request {
				return []reconcile.Request{
					{NamespacedName: types.NamespacedName{
						Name:      obj.GetName(),
						Namespace: obj.GetNamespace(),
					}},
				}
			}),
		)).
		WatchesRawSource(source.Kind(
			mgr.GetCache(),
			ingressRouteTCP,
			handler.TypedEnqueueRequestsFromMapFunc(func(_ context.Context, obj *unstructured.Unstructured) []reconcile.Request {
				return []reconcile.Request{
					{NamespacedName: types.NamespacedName{
						Name:      obj.GetName(),
						Namespace: obj.GetNamespace(),
					}},
				}
			}),
		)).
		Complete(r)
}

// Exported GVRs for use in main.go or tests.
var (
	IngressRouteGVR    = ingressRouteGVR
	IngressRouteTCPGVR = ingressRouteTCPGVR
)

// requeueDelay constants are shared with the hostmapping controller via
// the same package; the constants requeueDelayShort and requeueDelayLong
// are defined in hostmapping_controller.go.
var _ time.Duration = requeueDelayShort // compile-time reference check
