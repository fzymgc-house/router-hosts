package operator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
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

// serviceOwnsState reports whether obj carries evidence that this
// controller has previously acted on it — the cleanup finalizer or a
// non-empty host-ids annotation — independent of the current opt-in
// annotation. CR-01: a Service that opted out (annotation removed) before
// being deleted still carries serviceCleanupFinalizer, since only
// reconcileDelete ever removes it. If the watch predicate keeps gating
// solely on serviceEnabled, the deletionTimestamp Update that
// `kubectl delete service` produces for such a Service is rejected forever
// (neither old nor new carries `enabled: "true"`), Reconcile never runs,
// reconcileDelete never runs, and the finalizer wedges the object in
// Terminating with no self-heal. An object satisfying serviceOwnsState must
// always be admitted so Reconcile gets a chance to release the finalizer.
func serviceOwnsState(obj client.Object) bool {
	return controllerutil.ContainsFinalizer(obj, serviceCleanupFinalizer) ||
		obj.GetAnnotations()[hostIDsAnnotation] != ""
}

// serviceEnabledPredicate gates the Service watch on the opt-in annotation
// (D-03, D-04), OR-ed with serviceOwnsState (CR-01) so a Service this
// controller still owns cleanup state for is never silently dropped.
// UpdateFunc deliberately inspects BOTH the old and the new object (D-05): a
// predicate that inspects only the new object cannot see an opt-out edit
// (annotation present -> absent), which would silently orphan that
// Service's DNS entry. Hand-rolled rather than built from
// predicate.NewPredicateFuncs, which threads only the new object into its
// UpdateFunc and therefore cannot express this. No generation-changed
// predicate is chained in front of it either: a Service has a status
// subresource, so an annotation-only write never bumps metadata.generation
// (RESEARCH Pattern 1).
//
// CreateFunc and DeleteFunc are gated the same way as UpdateFunc (not just
// serviceEnabled) so an informer resync after an operator restart — which
// re-delivers pre-existing objects as Create events — still admits a
// Service mid-teardown that opted out before restart.
func serviceEnabledPredicate() predicate.Predicate {
	admit := func(obj client.Object) bool {
		return serviceEnabled(obj) || serviceOwnsState(obj)
	}
	return predicate.Funcs{
		CreateFunc:  func(e event.CreateEvent) bool { return admit(e.Object) },
		DeleteFunc:  func(e event.DeleteEvent) bool { return admit(e.Object) },
		GenericFunc: func(e event.GenericEvent) bool { return admit(e.Object) },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return admit(e.ObjectOld) || admit(e.ObjectNew)
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

	// Ensure finalizer is present, but only for a Service that is either
	// opted in or already tracking a host entry (D-17). A Service that is
	// opted out AND tracks nothing has no cleanup to guarantee, so it never
	// needs the finalizer; a Service that once opted in and still carries
	// the host-ids annotation DOES need it, even after opting out, or its
	// tracked entry could never be deleted via reconcileDelete. Return after
	// adding so the next reconcile works with a fresh object from the
	// informer cache.
	if !controllerutil.ContainsFinalizer(svc, serviceCleanupFinalizer) {
		if !serviceEnabled(svc) && svc.GetAnnotations()[hostIDsAnnotation] == "" {
			return ctrl.Result{}, nil
		}
		controllerutil.AddFinalizer(svc, serviceCleanupFinalizer)
		if err := r.Update(ctx, svc); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "adding finalizer to Service")
		}
		return ctrl.Result{}, nil
	}

	return r.syncService(ctx, log, svc)
}

// syncService computes the desired set for svc — at most one hostname,
// since a Service carries exactly one hostname (D-06/D-07) — diffs it
// against the host-ids annotation, and converges the router to match. There
// is deliberately NO early return on an empty desired set (D-17): the
// stale-cleanup pass at the end of this function must run even when the
// Service is opted out, has an unsupported type, or is missing its hostname
// annotation, so that every "stop managing this" transition — opt-out, type
// change, or hostname change — deletes the previously tracked entry through
// this ONE code path instead of several separately maintained ones. This is
// the Phase 7 07-04 fix carried forward: the early return at
// ingressroute_controller.go:124-127 is precisely the bug not to reproduce
// here.
//
// The four operator-visible failure/waiting states from the tracer still
// each emit their Kubernetes Event (D-12), but none of them return early
// any more:
//
//   - unsupported Spec.Type -> InvalidServiceType (terminal, D-14)
//   - no hostname annotation -> MissingHostname (terminal, D-14)
//   - LoadBalancer still provisioning -> PendingLoadBalancer (requeues
//     after requeueDelayShort, D-09/D-14). This is the one case where an
//     already-tracked hostname is NOT dropped from the desired set: the
//     entry is still wanted, just not yet resolvable, so its previous ID is
//     carried forward into newIDs rather than deleted by the stale-cleanup
//     pass.
//   - NodePort with no ip-address annotation -> MissingIPAddress (terminal,
//     D-14)
//   - opted out (serviceEnabled false) -> no event; opting out is not an
//     error, just an empty desired set.
func (r *ServiceReconciler) syncService(ctx context.Context, log *slog.Logger, svc *corev1.Service) (ctrl.Result, error) {
	existingIDs, err := getHostIDsAnnotation(log, svc)
	if err != nil {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}

	comment := fmt.Sprintf("k8s-service:%s/%s", svc.Namespace, svc.Name)

	// Copy DefaultTags to avoid mutating the shared backing array.
	tags := make([]string, 0, len(r.DefaultTags)+1)
	tags = append(tags, r.DefaultTags...)
	tags = append(tags, "service")

	newIDs := make(map[string]string, len(existingIDs))
	var hadError, waiting bool
	var hostname string

	switch {
	case !serviceEnabled(svc):
		// Opted out: desired set stays empty, no event — falls through to
		// the stale-cleanup pass below.
	case svc.Spec.Type != corev1.ServiceTypeLoadBalancer && svc.Spec.Type != corev1.ServiceTypeNodePort:
		r.emitEvent(svc, corev1.EventTypeWarning, reasonInvalidServiceType,
			"Service %s/%s has type %s, which router-hosts does not support", svc.Namespace, svc.Name, svc.Spec.Type)
		log.Warn("unsupported Service type", "type", svc.Spec.Type)
	default:
		hostname = serviceDesiredHostname(log, svc)
		if hostname == "" {
			r.emitEvent(svc, corev1.EventTypeWarning, reasonMissingHostname,
				"Service %s/%s is missing the required %s annotation", svc.Namespace, svc.Name, serviceHostnameAnnotation)
			log.Warn("missing hostname annotation", "annotation", serviceHostnameAnnotation)
			break
		}

		ip, isWaiting := resolveServiceIP(svc)
		switch {
		case isWaiting:
			r.emitEvent(svc, corev1.EventTypeNormal, reasonPendingLoadBalancer,
				"Waiting for a LoadBalancer IP for Service %s/%s", svc.Namespace, svc.Name)
			log.Info("waiting for LoadBalancer IP")
			waiting = true
			if id, ok := existingIDs[hostname]; ok {
				newIDs[hostname] = id
			}
		case ip == "":
			r.emitEvent(svc, corev1.EventTypeWarning, reasonMissingIPAddress,
				"Service %s/%s is missing the required %s annotation", svc.Namespace, svc.Name, serviceIPAddressAnnotation)
			log.Warn("missing ip-address annotation", "annotation", serviceIPAddressAnnotation)
		default:
			aliases := serviceDesiredAliases(log, svc, hostname)
			prevID := existingIDs[hostname]
			id, syncErr := r.syncServiceHost(ctx, log, prevID, ip, hostname, comment, aliases, tags)
			if syncErr != nil {
				log.Error("failed to sync host entry", "hostname", hostname, "error", syncErr)
				hadError = true
				if prevID != "" {
					// Retain the known ID so the stale-cleanup pass below
					// does not mistake this still-desired hostname for a
					// removed one and issue a spurious DeleteHost.
					newIDs[hostname] = prevID
				}
			} else {
				newIDs[hostname] = id
			}
		}
	}

	// Stale-cleanup pass, always reached (D-17): delete every entry this
	// Service owns that is no longer in the desired set. Every deletion
	// target comes from this Service's own annotation — never from a
	// hostname lookup or a cross-object query — so this can never delete an
	// entry owned by another Service, IngressRoute, Gateway route, or
	// HostMapping.
	for existingHostname, id := range existingIDs {
		if _, ok := newIDs[existingHostname]; ok {
			continue
		}
		if err := r.HostClient.DeleteHost(ctx, id); err != nil {
			if errors.Is(err, ErrHostNotFound) {
				log.Info("stale host entry already gone", "hostname", existingHostname, "hostId", id)
				continue
			}
			log.Error("failed to delete stale host entry", "hostname", existingHostname, "hostId", id, "error", err)
			// Retain the ID so it is not orphaned from the annotation.
			newIDs[existingHostname] = id
			hadError = true
			continue
		}
		log.Info("stale host entry deleted from Service", "hostname", existingHostname, "hostId", id)
	}

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

	if waiting {
		return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
	}
	if hadError {
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
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

// addOrAdoptService creates a host entry for (ip, hostname), adopting a
// pre-existing entry via FindHost when the server reports AlreadyExists,
// mirroring ingressroute_controller.go's addOrAdopt (T-08-01, D-21).
//
// FindHost matches on (ip, hostname) alone, which is NOT proof of
// ownership: the server enforces uniqueness on that pair, so the
// conflicting entry may belong to a HostMapping, an IngressRoute, or a
// Gateway route — including another Service. Adopting it would write a
// foreign ID into this Service's host-ids annotation, after which the
// stale-cleanup pass and reconcileDelete would legitimately DeleteHost it,
// silently destroying another owner's live DNS entry.
//
// D-11 keeps this controller off the shared --default-ingress-ip, which
// makes such collisions less routine here than for the IngressRoute and
// Gateway controllers (a Service's IP comes from its own status or its own
// annotation, not a shared flag) — but that does not make the check
// optional: the collision is still reachable whenever a Service's resolved
// (ip, hostname) happens to match an entry already owned by something else.
//
// BOTH halves of the gate below are load-bearing; neither is decoration.
func (r *ServiceReconciler) addOrAdoptService(ctx context.Context, log *slog.Logger, ip, hostname, comment string, aliases, tags []string) (string, error) {
	id, err := r.HostClient.AddHost(ctx, ip, hostname, comment, aliases, tags)
	if err == nil {
		log.Info("host entry created from Service", "hostname", hostname, "hostId", id)
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
	if existing.Comment != comment || !hasServiceProvenance(existing.Tags) {
		return "", oops.Errorf(
			"refusing to adopt host %s (id %s): owned by another object (comment %q tags %v, want comment %q with service)",
			hostname, existing.ID, existing.Comment, existing.Tags, comment,
		)
	}
	log.Info("adopted existing host entry from Service", "hostname", hostname, "hostId", existing.ID)
	return existing.ID, nil
}

// hasServiceProvenance reports whether tags identify a host entry created
// by the Service controller. syncService stamps every entry it writes with
// the literal "service" tag in addition to DefaultTags, so checking only
// that one tag is sufficient — "kubernetes" comes from the shared
// DefaultTags and is therefore not discriminating (the same reasoning
// recorded at gateway_controller.go:620-626). Unlike
// hasGatewayProvenance, one kind means no KindName parameter is needed.
func hasServiceProvenance(tags []string) bool {
	return slices.Contains(tags, "service")
}

// reconcileDelete deletes every host entry tracked in svc's host-ids
// annotation and only then releases the cleanup finalizer, mirroring
// ingressroute_controller.go:311-348 (D-16). The ordering is the whole
// point: the finalizer is the only thing guaranteeing the operator gets a
// chance to clean up, so it is released last, and only on full success.
func (r *ServiceReconciler) reconcileDelete(ctx context.Context, log *slog.Logger, svc *corev1.Service) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(svc, serviceCleanupFinalizer) {
		// Another controller's deletion path, nothing to do.
		return ctrl.Result{}, nil
	}

	existingIDs, err := getHostIDsAnnotation(log, svc)
	if err != nil {
		// The ownership record is unreadable: releasing the finalizer here
		// would strand every entry it named as an unowned leak in router
		// DNS (D-18). Do not touch the finalizer.
		return ctrl.Result{RequeueAfter: requeueDelayShort}, err
	}

	remainingIDs := make(map[string]string, len(existingIDs))
	var hadDeleteError bool
	for hostname, id := range existingIDs {
		log.Info("deleting host entry for deleted Service", "hostname", hostname, "hostId", id)
		if err := r.HostClient.DeleteHost(ctx, id); err != nil {
			log.Error("failed to delete host entry during cleanup", "hostname", hostname, "hostId", id, "error", err)
			remainingIDs[hostname] = id
			hadDeleteError = true
		}
	}
	if hadDeleteError {
		// Persist remaining IDs so they are not orphaned on the next
		// reconcile, and leave the finalizer in place so Kubernetes keeps
		// the object alive for the retry.
		if err := setHostIDsAnnotation(svc, remainingIDs); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "setting host IDs annotation after partial delete")
		}
		if err := r.Update(ctx, svc); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "updating Service annotations after partial delete")
		}
		return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
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
