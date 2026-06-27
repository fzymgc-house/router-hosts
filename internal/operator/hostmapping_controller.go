package operator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/samber/oops"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	operatorv1alpha1 "github.com/fzymgc-house/router-hosts/api/operator/v1alpha1"
)

const (
	hostCleanupFinalizer = "router-hosts.fzymgc.house/host-cleanup"
	requeueDelayShort    = 5 * time.Second
	requeueDelayLong     = 30 * time.Second
)

// HostMappingReconciler reconciles HostMapping objects by syncing host
// entries to the router-hosts server via gRPC.
type HostMappingReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	HostClient HostClient
	Log        *slog.Logger
}

// +kubebuilder:rbac:groups=router-hosts.fzymgc.house,resources=hostmappings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=router-hosts.fzymgc.house,resources=hostmappings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=router-hosts.fzymgc.house,resources=hostmappings/finalizers,verbs=update

// Reconcile handles a single reconciliation loop for a HostMapping resource.
func (r *HostMappingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("hostmapping", req.NamespacedName)

	var hm operatorv1alpha1.HostMapping
	if err := r.Get(ctx, req.NamespacedName, &hm); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Handle deletion via finalizer.
	if !hm.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, log, &hm)
	}

	// Ensure finalizer is present. Return after adding so the next reconcile
	// works with a fresh object from the informer cache.
	if !controllerutil.ContainsFinalizer(&hm, hostCleanupFinalizer) {
		controllerutil.AddFinalizer(&hm, hostCleanupFinalizer)
		if err := r.Update(ctx, &hm); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "adding finalizer")
		}
		return ctrl.Result{}, nil
	}

	// Create or update the host entry.
	return r.reconcileUpsert(ctx, log, &hm)
}

// reconcileUpsert creates a new host entry or updates an existing one.
func (r *HostMappingReconciler) reconcileUpsert(ctx context.Context, log *slog.Logger, hm *operatorv1alpha1.HostMapping) (ctrl.Result, error) {
	if hm.Status.HostID == "" {
		return r.reconcileCreate(ctx, log, hm)
	}
	return r.reconcileUpdate(ctx, log, hm)
}

// reconcileCreate creates a new host entry on the router-hosts server.
// When the server returns AlreadyExists, it delegates to adoptExistingHost
// to find and adopt the pre-existing entry, breaking the hot-loop.
func (r *HostMappingReconciler) reconcileCreate(ctx context.Context, log *slog.Logger, hm *operatorv1alpha1.HostMapping) (ctrl.Result, error) {
	log.Info("creating host entry")

	comment := fmt.Sprintf("k8s:%s/%s", hm.Namespace, hm.Name)
	id, err := r.HostClient.AddHost(ctx, hm.Spec.IP, hm.Spec.Hostname, comment, hm.Spec.Aliases, hm.Spec.Tags)
	if err != nil {
		if errors.Is(err, ErrHostAlreadyExists) {
			return r.adoptExistingHost(ctx, log, hm)
		}
		log.Error("failed to create host entry", "error", err)
		r.setStatus(hm, operatorv1alpha1.HostMappingPhaseError, err.Error(), "")
		r.setSyncedCondition(hm, metav1.ConditionFalse, "CreateFailed", err.Error())
		if statusErr := r.Status().Update(ctx, hm); statusErr != nil {
			log.Error("failed to update status", "error", statusErr)
		}
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}

	// Fetch the created entry to get the version.
	entry, err := r.HostClient.GetHost(ctx, id)
	if err != nil {
		log.Warn("host created but could not fetch version", "id", id, "error", err)
		hm.Status.HostVersion = "" // clear to avoid stale version on next update
		r.setStatus(hm, operatorv1alpha1.HostMappingPhaseSynced, "Created (version unknown)", id)
	} else {
		hm.Status.HostVersion = entry.Version
		r.setStatus(hm, operatorv1alpha1.HostMappingPhaseSynced, "Created", id)
	}

	r.setSyncedCondition(hm, metav1.ConditionTrue, "Created", "Host entry created on server")
	now := metav1.Now()
	hm.Status.LastSyncTime = &now

	if err := r.Status().Update(ctx, hm); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "updating status after create")
	}

	log.Info("host entry created", "hostId", id)
	return ctrl.Result{}, nil
}

// adoptExistingHost handles the AlreadyExists case: it looks up the existing
// host entry by exact IP+hostname, records the ID and version on the status,
// then delegates to reconcileUpdate so the entry converges to the desired spec
// in the same reconcile pass. If the lookup fails or finds nothing (e.g. a
// race where the host was deleted between AddHost and FindHost), it falls back
// to the standard error/requeue path.
func (r *HostMappingReconciler) adoptExistingHost(ctx context.Context, log *slog.Logger, hm *operatorv1alpha1.HostMapping) (ctrl.Result, error) {
	log.Info("host already exists, attempting adoption", "ip", hm.Spec.IP, "hostname", hm.Spec.Hostname)

	existing, err := r.HostClient.FindHost(ctx, hm.Spec.IP, hm.Spec.Hostname)
	if err != nil {
		log.Error("failed to find existing host for adoption", "error", err)
		r.setStatus(hm, operatorv1alpha1.HostMappingPhaseError, err.Error(), "")
		r.setSyncedCondition(hm, metav1.ConditionFalse, "AdoptionFailed", err.Error())
		if statusErr := r.Status().Update(ctx, hm); statusErr != nil {
			log.Error("failed to update status", "error", statusErr)
		}
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}
	if existing == nil {
		// Race: deleted between AddHost and FindHost — requeue to try again.
		msg := "host entry not found during adoption (possible race); will retry"
		log.Warn(msg, "ip", hm.Spec.IP, "hostname", hm.Spec.Hostname)
		r.setStatus(hm, operatorv1alpha1.HostMappingPhaseError, msg, "")
		r.setSyncedCondition(hm, metav1.ConditionFalse, "AdoptionFailed", msg)
		if statusErr := r.Status().Update(ctx, hm); statusErr != nil {
			log.Error("failed to update status", "error", statusErr)
		}
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}

	log.Info("adopting existing host entry", "existingID", existing.ID, "ip", hm.Spec.IP, "hostname", hm.Spec.Hostname)
	hm.Status.HostID = existing.ID
	hm.Status.HostVersion = existing.Version

	// Delegate to reconcileUpdate to converge the entry to the desired spec.
	return r.reconcileUpdate(ctx, log, hm)
}

// reconcileUpdate converges the server-side host entry to the desired spec.
//
// It fetches the current server state first, which serves two purposes:
//   - Idempotency: when the server already matches the desired spec, it skips
//     UpdateHost entirely. The server appends an event for any comment/tags/
//     aliases field that is *presented* on the request, without comparing its
//     value (only IP and hostname are diffed server-side; an update presenting
//     no fields appends nothing). The operator always sends a comment
//     ("k8s:ns/name") and sends aliases/tags whenever the spec has them, so a
//     redundant reconcile would append spurious events — skipping the call when
//     already in sync is what prevents the hot-loop from re-bloating the
//     aggregate (GH #338, relates #330).
//   - Version self-heal: it uses the authoritative current version as the
//     optimistic-concurrency token, so a stale or empty Status.HostVersion can
//     no longer wedge the CR on "version conflict: expected 0, got N" (#338).
//
// If the pre-update read fails, the reconcile requeues rather than issuing a
// blind UpdateHost: without current state it can neither guarantee the no-op
// skip nor pick a safe version, and a blind write would re-append events,
// silently re-introducing the Bug 1 hot-loop.
func (r *HostMappingReconciler) reconcileUpdate(ctx context.Context, log *slog.Logger, hm *operatorv1alpha1.HostMapping) (ctrl.Result, error) {
	comment := fmt.Sprintf("k8s:%s/%s", hm.Namespace, hm.Name)

	current, getErr := r.HostClient.GetHost(ctx, hm.Status.HostID)
	if getErr != nil || current == nil {
		// Fail closed: without current state we cannot uphold idempotency or
		// pick a safe version, so requeue instead of a blind, event-appending
		// update. GetHost and UpdateHost hit the same server, so if reads are
		// failing a write would most likely fail too. Surface the degraded
		// state on the CR so the stall is observable — a silent requeue would
		// otherwise keep reporting Synced while never converging.
		msg := "could not fetch current host state"
		if getErr != nil {
			msg = getErr.Error()
		}
		log.Error("could not fetch current host before update; requeuing", "error", getErr)
		r.setStatus(hm, operatorv1alpha1.HostMappingPhaseError, msg, hm.Status.HostID)
		r.setSyncedCondition(hm, metav1.ConditionFalse, "PreflightReadFailed", msg)
		if statusErr := r.Status().Update(ctx, hm); statusErr != nil {
			log.Error("failed to update status", "error", statusErr)
		}
		return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
	}

	if hostEntryMatchesSpec(current, hm.Spec) {
		// Already in sync — do not call UpdateHost, so no event is appended.
		hm.Status.HostVersion = current.Version
		r.setStatus(hm, operatorv1alpha1.HostMappingPhaseSynced, "Already in sync", hm.Status.HostID)
		r.setSyncedCondition(hm, metav1.ConditionTrue, "AlreadyInSync", "Host entry already matches desired state")
		// Intentionally do NOT bump LastSyncTime: nothing changed.
		if err := r.Status().Update(ctx, hm); err != nil {
			return ctrl.Result{}, oops.Wrapf(err, "updating status after no-op sync")
		}
		log.Info("host entry already in sync", "hostId", hm.Status.HostID)
		return ctrl.Result{}, nil
	}

	log.Info("updating host entry", "hostId", hm.Status.HostID)

	err := r.HostClient.UpdateHost(ctx, hm.Status.HostID, hm.Spec.IP, hm.Spec.Hostname, comment, hm.Spec.Aliases, hm.Spec.Tags, current.Version)
	if err != nil {
		log.Error("failed to update host entry", "error", err)
		r.setStatus(hm, operatorv1alpha1.HostMappingPhaseError, err.Error(), hm.Status.HostID)
		r.setSyncedCondition(hm, metav1.ConditionFalse, "UpdateFailed", err.Error())
		if statusErr := r.Status().Update(ctx, hm); statusErr != nil {
			log.Error("failed to update status", "error", statusErr)
		}
		return ctrl.Result{RequeueAfter: requeueDelayLong}, nil
	}

	// Fetch updated entry for new version.
	entry, err := r.HostClient.GetHost(ctx, hm.Status.HostID)
	if err != nil {
		log.Warn("host updated but could not fetch version", "error", err)
		hm.Status.HostVersion = "" // clear stale version to avoid concurrency loop
	} else {
		hm.Status.HostVersion = entry.Version
	}

	r.setStatus(hm, operatorv1alpha1.HostMappingPhaseSynced, "Updated", hm.Status.HostID)
	r.setSyncedCondition(hm, metav1.ConditionTrue, "Updated", "Host entry updated on server")
	now := metav1.Now()
	hm.Status.LastSyncTime = &now

	if err := r.Status().Update(ctx, hm); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "updating status after update")
	}

	log.Info("host entry updated", "hostId", hm.Status.HostID)
	return ctrl.Result{}, nil
}

// reconcileDelete handles CR deletion by cleaning up the server-side host entry.
func (r *HostMappingReconciler) reconcileDelete(ctx context.Context, log *slog.Logger, hm *operatorv1alpha1.HostMapping) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(hm, hostCleanupFinalizer) {
		return ctrl.Result{}, nil
	}

	if hm.Status.HostID != "" {
		log.Info("deleting host entry", "hostId", hm.Status.HostID)
		if err := r.HostClient.DeleteHost(ctx, hm.Status.HostID); err != nil {
			log.Error("failed to delete host entry", "error", err)
			r.setStatus(hm, operatorv1alpha1.HostMappingPhaseError, err.Error(), hm.Status.HostID)
			r.setSyncedCondition(hm, metav1.ConditionFalse, "DeleteFailed", err.Error())
			if statusErr := r.Status().Update(ctx, hm); statusErr != nil {
				log.Error("failed to update status", "error", statusErr)
			}
			return ctrl.Result{RequeueAfter: requeueDelayShort}, nil
		}
		log.Info("host entry deleted", "hostId", hm.Status.HostID)
	}

	controllerutil.RemoveFinalizer(hm, hostCleanupFinalizer)
	if err := r.Update(ctx, hm); err != nil {
		return ctrl.Result{}, oops.Wrapf(err, "removing finalizer")
	}

	return ctrl.Result{}, nil
}

// setStatus updates the status fields on the HostMapping (in memory only).
func (r *HostMappingReconciler) setStatus(hm *operatorv1alpha1.HostMapping, phase operatorv1alpha1.HostMappingPhase, message, hostID string) {
	hm.Status.Phase = phase
	hm.Status.Message = message
	if hostID != "" {
		hm.Status.HostID = hostID
	}
}

// setSyncedCondition sets the standard "Synced" condition on the HostMapping.
func (r *HostMappingReconciler) setSyncedCondition(hm *operatorv1alpha1.HostMapping, status metav1.ConditionStatus, reason, message string) {
	now := metav1.Now()
	condition := metav1.Condition{
		Type:               operatorv1alpha1.ConditionSynced,
		Status:             status,
		ObservedGeneration: hm.Generation,
		LastTransitionTime: now,
		Reason:             reason,
		Message:            message,
	}

	// Replace existing condition of the same type, or append.
	for i, c := range hm.Status.Conditions {
		if c.Type == operatorv1alpha1.ConditionSynced {
			// Only update LastTransitionTime when status actually changes.
			if c.Status == status {
				condition.LastTransitionTime = c.LastTransitionTime
			}
			hm.Status.Conditions[i] = condition
			return
		}
	}
	hm.Status.Conditions = append(hm.Status.Conditions, condition)
}

// hostEntryMatchesSpec reports whether a server-side host entry already equals
// the desired HostMapping spec. Aliases and tags are compared order-insensitively
// because the server does not guarantee element order. The comment is
// intentionally excluded: it is operator-derived ("k8s:ns/name"), not part of
// the spec, and HostEntry does not carry it.
func hostEntryMatchesSpec(entry *HostEntry, spec operatorv1alpha1.HostMappingSpec) bool {
	return entry.IP == spec.IP &&
		entry.Hostname == spec.Hostname &&
		equalStringSetsIgnoreOrder(entry.Aliases, spec.Aliases) &&
		equalStringSetsIgnoreOrder(entry.Tags, spec.Tags)
}

// equalStringSetsIgnoreOrder reports whether two string slices contain the same
// elements regardless of order, treating nil and empty as equal. Comparison is
// multiset-correct (duplicates count).
func equalStringSetsIgnoreOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

// statusWriteFilter drops pure status-subresource writes so the operator's own
// status updates do not re-trigger reconcile and hot-loop (GH #338). Events that
// must still be reconciled all pass: spec changes (generation bump), finalizer
// changes (bootstrap add / cleanup remove), deletion requests (deletionTimestamp),
// and periodic informer resyncs (identical ResourceVersion). Plain
// GenerationChangedPredicate is unsafe here: it would also drop deletion events
// (which leave generation unchanged), stranding finalizer cleanup.
func statusWriteFilter() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			if e.ObjectOld == nil || e.ObjectNew == nil {
				return true
			}
			// Resync re-delivers the same object — allow drift correction.
			if e.ObjectOld.GetResourceVersion() == e.ObjectNew.GetResourceVersion() {
				return true
			}
			if e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration() {
				return true
			}
			if !e.ObjectOld.GetDeletionTimestamp().Equal(e.ObjectNew.GetDeletionTimestamp()) {
				return true
			}
			if !equalStringSetsIgnoreOrder(e.ObjectOld.GetFinalizers(), e.ObjectNew.GetFinalizers()) {
				return true
			}
			return false
		},
	}
}

// SetupWithManager registers the HostMapping reconciler with the controller manager.
func (r *HostMappingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1alpha1.HostMapping{}, builder.WithPredicates(statusWriteFilter())).
		Named("hostmapping").
		Complete(r)
}
