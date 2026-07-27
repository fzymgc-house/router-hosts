package operator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"

	"github.com/fzymgc-house/router-hosts/internal/validation"
	"github.com/samber/oops"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// Annotation keys and finalizer for the Service controller. Declared locally
// rather than folded into the shared block in ingressroute_controller.go, per
// 08-RESEARCH.md Open Question 1: a single-consumer key should not become a
// dumping ground shared by unrelated controllers.
const (
	// serviceCleanupFinalizer is a fourth, distinct finalizer alongside
	// host-cleanup, ingressroute-cleanup, and gateway-cleanup (D-16).
	//
	// Reversibility: one-way. Once a release carrying this string reaches a
	// user cluster, live Service objects hold it. Renaming it later migrates
	// nothing: the old finalizer stays on every existing Service, no
	// controller recognises it, and Kubernetes blocks deletion of those
	// Services until a human patches each one by hand.
	serviceCleanupFinalizer = "router-hosts.fzymgc.house/service-cleanup"

	serviceEnabledAnnotation   = "router-hosts.fzymgc.house/enabled"
	serviceHostnameAnnotation  = "router-hosts.fzymgc.house/hostname"
	serviceAliasesAnnotation   = "router-hosts.fzymgc.house/aliases"
	serviceIPAddressAnnotation = "router-hosts.fzymgc.house/ip-address"
)

// Kubernetes Event reasons for the operator-visible failure/waiting states
// (D-12), carried forward verbatim from the Rust-era design of record.
// InvalidServiceType, MissingHostname, and MissingIPAddress are terminal for
// now (D-14): the next Service update re-triggers reconcile naturally, so
// none of them sets a timed requeue. Only PendingLoadBalancer requeues.
const (
	reasonInvalidServiceType  = "InvalidServiceType"
	reasonMissingHostname     = "MissingHostname"
	reasonMissingIPAddress    = "MissingIPAddress"
	reasonPendingLoadBalancer = "PendingLoadBalancer"
)

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// ServiceReconciler watches v1/Service resources and, for those that opt in
// via annotation, syncs a resolved (IP, hostname) pair to the router-hosts
// server as a host entry.
type ServiceReconciler struct {
	client.Client
	HostClient HostClient
	Log        *slog.Logger

	// DefaultTags are applied to all host entries created from Services, in
	// addition to the literal "service" tag. Unlike IngressRouteReconciler
	// and GatewayRouteReconciler, there is deliberately no default-IP field
	// here: D-11 forbids --default-ingress-ip as a Service IP fallback.
	DefaultTags []string

	// Recorder emits Kubernetes Events for operator-visible failure/waiting
	// states (D-12). It may be nil in tests that do not assert on events;
	// event emission is best-effort telemetry, never control flow.
	Recorder events.EventRecorder
}

// serviceEnabled reports whether obj carries the opt-in annotation set to
// exactly the string "true".
func serviceEnabled(obj client.Object) bool {
	return obj.GetAnnotations()[serviceEnabledAnnotation] == "true"
}

// serviceEnabledPredicate gates the Service watch on the opt-in annotation
// (D-03, D-04). UpdateFunc deliberately inspects BOTH the old and the new
// object (D-05): a predicate that inspects only the new object cannot see an
// opt-out edit (annotation present -> absent), which would silently orphan
// that Service's DNS entry. Hand-rolled rather than built from
// predicate.NewPredicateFuncs, which threads only the new object into its
// UpdateFunc and therefore cannot express this. No generation-changed
// predicate is chained in front of it either: a Service has a status
// subresource, so an annotation-only write never bumps metadata.generation
// (RESEARCH Pattern 1).
func serviceEnabledPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return serviceEnabled(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return serviceEnabled(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return serviceEnabled(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return serviceEnabled(e.ObjectOld) || serviceEnabled(e.ObjectNew)
		},
	}
}

// resolveServiceIP resolves the IP to publish for svc across the full
// locked type matrix (D-09, D-10, D-11). waiting is true only for a
// LoadBalancer Service with no IP-bearing ingress entry yet — the caller
// should requeue rather than treat this as a terminal condition; every other
// case (unsupported type, NodePort with no override) is terminal and
// returns waiting=false alongside an empty ip.
//
// Evaluation order:
//  1. Reject unsupported types first. Anything other than LoadBalancer or
//     NodePort returns ("", false) immediately, so the ip-address annotation
//     cannot resurrect a ClusterIP or ExternalName Service.
//  2. Apply the ip-address annotation override. It wins over LoadBalancer
//     status when both are present and is the sole IP source for NodePort.
//  3. For LoadBalancer only, walk status.loadBalancer.ingress in order and
//     return the first entry with a non-empty IP field. Entries carrying
//     only a Hostname (AWS ELB style) are skipped, never resolved — a CNAME
//     target is not a host entry IP. Falling off the end means the load
//     balancer is still provisioning: return ("", true).
//  4. NodePort with no override returns ("", false): nothing will ever
//     supply an IP for it, so there is nothing to wait for.
func resolveServiceIP(svc *corev1.Service) (ip string, waiting bool) {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer && svc.Spec.Type != corev1.ServiceTypeNodePort {
		return "", false
	}
	if override := svc.GetAnnotations()[serviceIPAddressAnnotation]; override != "" {
		return override, false
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return "", false
	}
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		if ingress.IP != "" {
			return ingress.IP, false
		}
	}
	return "", true
}

// serviceDesiredHostname returns the trimmed, validated hostname annotation,
// or the empty string when the annotation is absent/blank or fails
// validation.ValidateHostname (D-06, D-08). An invalid hostname is logged at
// Warn and treated as absent — the caller's existing MissingHostname branch
// is the right operator-visible signal for it, matching the extractHostnames
// shape in gateway_controller.go and the extractHosts shape in
// ingressroute_controller.go. A dot-less (non-FQDN) hostname is accepted but
// logged at Warn (D-08): under locked ADR router-hosts-bzg a bare name makes
// unbound authoritative for a whole pseudo-TLD, but the IngressRoute,
// Gateway, and HostMapping controllers all accept it, and enforcing it in
// only this controller would make the operator inconsistent with itself.
func serviceDesiredHostname(log *slog.Logger, svc *corev1.Service) string {
	hostname := strings.TrimSpace(svc.GetAnnotations()[serviceHostnameAnnotation])
	if hostname == "" {
		return ""
	}

	if err := validation.ValidateHostname(hostname); err != nil {
		log.Warn("invalid hostname annotation", "hostname", hostname, "error", err)
		return ""
	}

	if !strings.Contains(hostname, ".") {
		log.Warn("hostname has no dot; accepting as non-FQDN per D-08", "hostname", hostname)
	}

	return hostname
}

// serviceDesiredAliases returns the validated, deduplicated alias list from
// the aliases annotation, mapped onto the host entry's native Aliases field
// (D-07). The result is ALWAYS non-nil, including when the annotation is
// absent or empty: grpcHostClient.UpdateHost only attaches the wire-level
// aliases update when the Go slice is non-nil
// (internal/operator/grpc_hostclient.go:131-133), so a nil result would
// silently mean "leave the server's aliases alone" instead of "clear them"
// and a Service whose aliases were removed would keep publishing them
// forever (RESEARCH Pitfall 2).
//
// The annotation is comma-split, each segment trimmed, and empty segments
// skipped. Each surviving alias is validated individually with
// validation.ValidateAliases (canonical-hostname match, IP-address
// rejection, hostname validity); an invalid alias is logged at Warn and
// dropped, never fatal (D-07). Because the per-alias call cannot see the
// other aliases, duplicates are deduplicated case-insensitively here, also
// logged at Warn.
func serviceDesiredAliases(log *slog.Logger, svc *corev1.Service, canonicalHostname string) []string {
	segments := strings.Split(svc.GetAnnotations()[serviceAliasesAnnotation], ",")
	result := make([]string, 0, len(segments))
	seen := make(map[string]struct{}, len(segments))

	for _, segment := range segments {
		alias := strings.TrimSpace(segment)
		if alias == "" {
			continue
		}

		if errs := validation.ValidateAliases([]string{alias}, canonicalHostname); len(errs) > 0 {
			log.Warn("skipping invalid alias annotation", "alias", alias, "error", errs[0])
			continue
		}

		lower := strings.ToLower(alias)
		if _, exists := seen[lower]; exists {
			log.Warn("skipping duplicate alias annotation", "alias", alias)
			continue
		}
		seen[lower] = struct{}{}

		result = append(result, alias)
	}

	return result
}

// emitEvent records a Kubernetes Event against svc when r.Recorder is set.
// It is a no-op when r.Recorder is nil, so tests that do not assert on
// events can leave it unset (event emission is best-effort telemetry, never
// control flow). action is always the literal "Reconcile", mirroring the
// HostMappingReconciler.recreateMissingHost call site.
func (r *ServiceReconciler) emitEvent(svc *corev1.Service, eventtype, reason, note string, args ...any) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(svc, nil, eventtype, reason, "Reconcile", note, args...)
}

// Reconcile handles a single reconciliation loop for a Service resource.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("service", req.NamespacedName)

	svc := &corev1.Service{}
	if err := r.Get(ctx, req.NamespacedName, svc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if svc.GetDeletionTimestamp() != nil {
		return r.reconcileDelete(ctx, log, svc)
	}

	// Ensure finalizer is present. Return after adding so the next reconcile
	// works with a fresh object from the informer cache.
	if !controllerutil.ContainsFinalizer(svc, serviceCleanupFinalizer) {
		controllerutil.AddFinalizer(svc, serviceCleanupFinalizer)
		if err := r.Update(ctx, svc); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "adding finalizer to Service")
		}
		return ctrl.Result{}, nil
	}

	// Re-check the opt-in annotation against the freshly-fetched object
	// rather than trusting the event payload: the predicate gates the queue,
	// not the reconcile. For the tracer an opted-out Service simply does not
	// act; plan 04 routes it through the desired-set diff so its entry is
	// cleaned up.
	if !serviceEnabled(svc) {
		return ctrl.Result{}, nil
	}

	return r.syncService(ctx, log, svc)
}

// syncService resolves the hostname and IP for svc and, if both are
// present, creates (or adopts) exactly one host entry and persists its ID
// to the host-ids annotation. Four operator-visible failure/waiting states
// short-circuit before any HostClient call, each emitting the matching
// Kubernetes Event (D-12) and creating nothing:
//
//   - unsupported Spec.Type -> InvalidServiceType (terminal, D-14)
//   - no hostname annotation -> MissingHostname (terminal, D-14)
//   - LoadBalancer still provisioning -> PendingLoadBalancer (requeues
//     after requeueDelayShort, D-09/D-14)
//   - NodePort with no ip-address annotation -> MissingIPAddress (terminal,
//     D-14)
//
// These early returns are provisional: plan 04 restructures syncService so
// the desired set is computed and diffed even when it is empty (D-17), at
// which point each terminal branch must still emit its event but fall
// through to the stale-cleanup pass instead of returning early.
//
// The update path for an already-tracked hostname is syncServiceHost;
// per-host error accumulation across a desired set larger than one entry and
// stale-cleanup diffing land in plan 04 (a Service produces at most one
// hostname, D-06/D-07, so there is nothing to accumulate errors across yet).
func (r *ServiceReconciler) syncService(ctx context.Context, log *slog.Logger, svc *corev1.Service) (ctrl.Result, error) {
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer && svc.Spec.Type != corev1.ServiceTypeNodePort {
		r.emitEvent(svc, corev1.EventTypeWarning, reasonInvalidServiceType,
			"Service %s/%s has type %s, which router-hosts does not support", svc.Namespace, svc.Name, svc.Spec.Type)
		log.Warn("unsupported Service type", "type", svc.Spec.Type)
		return ctrl.Result{}, nil
	}

	hostname := serviceDesiredHostname(log, svc)
	if hostname == "" {
		r.emitEvent(svc, corev1.EventTypeWarning, reasonMissingHostname,
			"Service %s/%s is missing the required %s annotation", svc.Namespace, svc.Name, serviceHostnameAnnotation)
		log.Warn("missing hostname annotation", "annotation", serviceHostnameAnnotation)
		return ctrl.Result{}, nil
	}

	ip, waiting := resolveServiceIP(svc)
	if waiting {
		r.emitEvent(svc, corev1.EventTypeNormal, reasonPendingLoadBalancer,
			"Waiting for a LoadBalancer IP for Service %s/%s", svc.Namespace, svc.Name)
		log.Info("waiting for LoadBalancer IP")
		return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
	}
	if ip == "" {
		r.emitEvent(svc, corev1.EventTypeWarning, reasonMissingIPAddress,
			"Service %s/%s is missing the required %s annotation", svc.Namespace, svc.Name, serviceIPAddressAnnotation)
		log.Warn("missing ip-address annotation", "annotation", serviceIPAddressAnnotation)
		return ctrl.Result{}, nil
	}

	existingIDs, err := getHostIDsAnnotation(log, svc)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}

	comment := fmt.Sprintf("k8s-service:%s/%s", svc.Namespace, svc.Name)
	aliases := serviceDesiredAliases(log, svc, hostname)

	// Copy DefaultTags to avoid mutating the shared backing array.
	tags := make([]string, 0, len(r.DefaultTags)+1)
	tags = append(tags, r.DefaultTags...)
	tags = append(tags, "service")

	prevID := existingIDs[hostname]
	id, err := r.syncServiceHost(ctx, log, prevID, ip, hostname, comment, aliases, tags)
	if err != nil {
		log.Error("failed to sync host entry", "hostname", hostname, "error", err)
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}
	newIDs := map[string]string{hostname: id}

	// Persist the annotation only when the ID map actually changed, so a
	// no-op Update does not bump the resourceVersion and re-trigger the
	// watch for no reason (D-19).
	if !maps.Equal(existingIDs, newIDs) {
		if err := setHostIDsAnnotation(svc, newIDs); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation")
		}
		if err := r.Update(ctx, svc); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "updating Service annotations")
		}
	}

	return ctrl.Result{}, nil
}

// syncServiceHost ensures a server-side host entry exists for (ip, hostname)
// with the desired aliases and tags and returns its ID. prevID is the ID
// currently tracked in the host-ids annotation, or "" when the host is not
// yet tracked.
//
// Modelled on IngressRouteReconciler.syncHost (ingressroute_controller.go:
// 216-253): a non-empty prevID is read first via GetHost, and the read's
// result is what supplies the optimistic-concurrency version and the
// fail-closed guard against a blind UpdateHost re-appending events (#338).
// Unlike syncHost, there is no "already in sync" early return: D-19 keeps
// UpdateHost unconditional for Services so a changed LoadBalancer IP or a
// changed alias set propagates without this controller keeping any
// last-known state.
func (r *ServiceReconciler) syncServiceHost(ctx context.Context, log *slog.Logger, prevID, ip, hostname, comment string, aliases, tags []string) (string, error) {
	if prevID == "" {
		return r.addOrAdoptService(ctx, log, ip, hostname, comment, aliases, tags)
	}

	current, getErr := r.HostClient.GetHost(ctx, prevID)
	switch {
	case getErr == nil && current != nil:
		err := r.HostClient.UpdateHost(ctx, prevID, ip, hostname, comment, aliases, tags, current.Version)
		if err == nil {
			log.Info("host entry updated from Service", "hostname", hostname, "hostId", prevID)
			return prevID, nil
		}
		if !errors.Is(err, ErrHostNotFound) {
			return prevID, oops.Wrapf(err, "updating host %s", prevID)
		}
		// Vanished between the read and the write — recreate below.
		log.Warn("host entry vanished before update; recreating", "hostname", hostname, "staleHostId", prevID)
	case errors.Is(getErr, ErrHostNotFound):
		// Deleted out-of-band — recreate below. The Service is the source of
		// truth.
		log.Warn("host entry not found on server; recreating", "hostname", hostname, "staleHostId", prevID)
	case getErr == nil && current == nil:
		// Server returned neither an entry nor an error. Fail closed rather
		// than treating it as a delete-and-recreate, which a missing entry
		// without a NotFound code does not justify.
		return prevID, oops.Errorf("reading host %s before update: empty entry returned", prevID)
	default:
		// Fail closed on a non-NotFound read error: without current state we
		// can neither pick a safe OCC version nor avoid re-appending events
		// (#338). Surface the error so the caller retains the ID and
		// requeues.
		return prevID, oops.Wrapf(getErr, "reading host %s before update", prevID)
	}

	return r.addOrAdoptService(ctx, log, ip, hostname, comment, aliases, tags)
}

// addOrAdoptService creates a host entry for (ip, hostname). For the tracer,
// an ErrHostAlreadyExists response is a hard error rather than an adoption:
// the provenance-gated adoption branch (D-21, mirroring addOrAdopt +
// hasIngressProvenance in ingressroute_controller.go) lands in plan 04 and
// MUST NOT be approximated here with a bare adopt, which would let this
// Service's annotation capture a foreign entry's ID.
func (r *ServiceReconciler) addOrAdoptService(ctx context.Context, log *slog.Logger, ip, hostname, comment string, aliases, tags []string) (string, error) {
	id, err := r.HostClient.AddHost(ctx, ip, hostname, comment, aliases, tags)
	if err == nil {
		log.Info("host entry created from Service", "hostname", hostname, "hostId", id)
		return id, nil
	}
	if !errors.Is(err, ErrHostAlreadyExists) {
		return "", oops.Wrapf(err, "creating host %s", hostname)
	}
	return "", oops.Errorf("host %s already exists on the server; Service adoption is not yet implemented", hostname)
}

// reconcileDelete is a stub for the tracer: it removes the finalizer when
// present. The full cleanup pass over tracked host IDs lands in plan 04.
func (r *ServiceReconciler) reconcileDelete(ctx context.Context, log *slog.Logger, svc *corev1.Service) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(svc, serviceCleanupFinalizer) {
		return ctrl.Result{}, nil
	}

	controllerutil.RemoveFinalizer(svc, serviceCleanupFinalizer)
	if err := r.Update(ctx, svc); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "removing finalizer from Service")
	}
	log.Info("service cleanup finalizer removed")
	return ctrl.Result{}, nil
}

// SetupWithManager registers the Service reconciler with the controller
// manager using the typed builder — corev1.Service is already registered in
// the manager scheme via clientgoscheme.AddToScheme (D-01, D-02), so there is
// no WatchesRawSource/source.Kind/unstructured dance to perform; that shape
// exists in ingressroute_controller.go only because Traefik CRDs are not
// cleanly importable. There is also no CRD-presence or RESTMapper gate:
// v1/Service is core Kubernetes and cannot be absent, so the Phase 7
// gatewayKindPresent machinery has no analogue here.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}, builder.WithPredicates(serviceEnabledPredicate())).
		Named("service").
		Complete(r)
}
