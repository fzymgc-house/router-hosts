package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
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
		prevID := existingIDs[hostname] // "" when this host is not yet tracked
		newID, err := r.syncHost(ctx, log, prevID, hostname, comment, tags)
		if err != nil {
			log.Error("failed to sync host entry", "hostname", hostname, "error", err)
			hadError = true
			// Retain a known ID so the stale-cleanup pass below does not mistake
			// an in-spec host for a removed one (and issue a spurious DeleteHost),
			// and so the ID is not lost from the annotation. A failed create has
			// no prior ID to retain.
			if prevID != "" {
				newIDs[hostname] = prevID
			}
			continue
		}
		newIDs[hostname] = newID
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

	// Persist the annotation only when the ID map actually changed. A no-op
	// r.Update would bump the resourceVersion and re-trigger the watch for no
	// reason; newIDs is the complete desired tracking state, so equality with
	// existingIDs means the on-disk annotation is already correct.
	if !maps.Equal(existingIDs, newIDs) {
		if err := setHostIDsAnnotation(obj, newIDs); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation")
		}
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "updating IngressRoute annotations")
		}
	}

	if hadError {
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}
	return ctrl.Result{}, nil
}

// syncHost ensures a server-side host entry exists for (DefaultIP, hostname)
// with the desired tags and returns its ID. prevID is the ID currently tracked
// in the host-ids annotation, or "" when the host is not yet tracked.
//
// It resolves the IngressRoute idempotency and version-wedge bugs (#341) by
// porting the HostMapping reconcile pattern (#338/#339) to the per-host
// IngressRoute loop:
//   - Idempotency: when the existing entry already matches, it issues no
//     UpdateHost, so the server appends no event and the aggregate does not
//     re-bloat (#338). The server appends an event for any presented
//     comment/tags field without comparing its value, so a blind update is
//     never a no-op.
//   - Version self-heal: it reads the authoritative version first and uses it
//     as the optimistic-concurrency token, so a stale or empty version can no
//     longer wedge on "version conflict: expected 0, got N".
//   - Out-of-band delete self-heal: a missing entry is recreated from the spec,
//     which is the source of truth (#342).
//   - Adoption: AddHost reporting AlreadyExists adopts the pre-existing entry
//     rather than looping on "host already exists" (relates #313).
//
// On a non-NotFound pre-update read failure it fails closed (returns prevID and
// the error) rather than issuing a blind, event-appending update.
func (r *IngressRouteReconciler) syncHost(ctx context.Context, log *slog.Logger, prevID, hostname, comment string, tags []string) (string, error) {
	if prevID != "" {
		current, getErr := r.HostClient.GetHost(ctx, prevID)
		switch {
		case getErr == nil && current != nil:
			if ingressHostInSync(current, r.DefaultIP, hostname, tags) {
				return prevID, nil // already in sync — no UpdateHost, no event
			}
			err := r.HostClient.UpdateHost(ctx, prevID, r.DefaultIP, hostname, comment, nil, tags, current.Version)
			if err == nil {
				log.Info("host entry updated from IngressRoute", "hostname", hostname, "hostId", prevID)
				return prevID, nil
			}
			if !errors.Is(err, ErrHostNotFound) {
				return prevID, oops.Wrapf(err, "updating host %s", prevID)
			}
			// Vanished between the read and the write — recreate below.
			log.Warn("host entry vanished before update; recreating", "hostname", hostname, "staleHostId", prevID)
		case errors.Is(getErr, ErrHostNotFound):
			// Deleted out-of-band — recreate below. The spec is the source of
			// truth (#342).
			log.Warn("host entry not found on server; recreating", "hostname", hostname, "staleHostId", prevID)
		case getErr == nil && current == nil:
			// Server returned neither an entry nor an error. Fail closed (same
			// reasoning as the default branch) rather than treating it as a
			// delete-and-recreate, which a missing entry without a NotFound code
			// does not justify.
			return prevID, oops.Errorf("reading host %s before update: empty entry returned", prevID)
		default:
			// Fail closed on a non-NotFound read error: without current state we
			// can neither guarantee the no-op skip nor pick a safe OCC version;
			// a blind UpdateHost would re-append events (#338). Surface the error
			// so the caller retains the ID and requeues.
			return prevID, oops.Wrapf(getErr, "reading host %s before update", prevID)
		}
	}
	return r.addOrAdopt(ctx, log, hostname, comment, tags)
}

// addOrAdopt creates a host entry for (DefaultIP, hostname), adopting a
// pre-existing entry when the server reports AlreadyExists (relates #313). The
// adopted ID is tracked in the annotation; the entry converges to the desired
// tags on the next reconcile, which the adopting annotation write itself
// triggers.
func (r *IngressRouteReconciler) addOrAdopt(ctx context.Context, log *slog.Logger, hostname, comment string, tags []string) (string, error) {
	id, err := r.HostClient.AddHost(ctx, r.DefaultIP, hostname, comment, nil, tags)
	if err == nil {
		log.Info("host entry created from IngressRoute", "hostname", hostname, "hostId", id)
		return id, nil
	}
	if !errors.Is(err, ErrHostAlreadyExists) {
		return "", oops.Wrapf(err, "creating host %s", hostname)
	}

	existing, findErr := r.HostClient.FindHost(ctx, r.DefaultIP, hostname)
	if findErr != nil {
		return "", oops.Wrapf(findErr, "finding host %s for adoption", hostname)
	}
	if existing == nil {
		// Race: the entry vanished between AddHost and FindHost. Surface an error
		// so the reconcile requeues and retries.
		return "", oops.Errorf("host %s reported AlreadyExists but was not found for adoption", hostname)
	}
	log.Info("adopted existing host entry from IngressRoute", "hostname", hostname, "hostId", existing.ID)
	return existing.ID, nil
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
	remainingIDs := make(map[string]string, len(existingIDs))
	var hadDeleteError bool
	for hostname, id := range existingIDs {
		log.Info("deleting host entry for deleted IngressRoute", "hostname", hostname, "hostId", id)
		if err := r.HostClient.DeleteHost(ctx, id); err != nil {
			log.Error("failed to delete host entry during cleanup", "hostname", hostname, "error", err)
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
			return ctrl.Result{}, oops.Wrapf(err, "updating IngressRoute annotations after partial delete")
		}
		return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
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
	if err != nil {
		log.Warn("unexpected type for spec.routes", "namespace", obj.GetNamespace(), "name", obj.GetName(), "error", err)
	}
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

// ingressHostInSync reports whether a server-side host entry already matches the
// desired IngressRoute-derived state. Tags are compared order-insensitively
// (reusing equalStringSetsIgnoreOrder from the hostmapping controller). The
// comment is excluded — it is operator-derived and not carried on HostEntry —
// and aliases are excluded because the operator never sets aliases for
// IngressRoute-derived hosts.
func ingressHostInSync(entry *HostEntry, ip, hostname string, tags []string) bool {
	return entry.IP == ip &&
		entry.Hostname == hostname &&
		equalStringSetsIgnoreOrder(entry.Tags, tags)
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
