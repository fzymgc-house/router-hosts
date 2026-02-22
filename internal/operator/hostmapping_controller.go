package operator

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/samber/oops"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

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
func (r *HostMappingReconciler) reconcileCreate(ctx context.Context, log *slog.Logger, hm *operatorv1alpha1.HostMapping) (ctrl.Result, error) {
	log.Info("creating host entry")

	comment := fmt.Sprintf("k8s:%s/%s", hm.Namespace, hm.Name)
	id, err := r.HostClient.AddHost(ctx, hm.Spec.IP, hm.Spec.Hostname, comment, hm.Spec.Aliases, hm.Spec.Tags)
	if err != nil {
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

// reconcileUpdate updates the host entry when the spec has changed.
func (r *HostMappingReconciler) reconcileUpdate(ctx context.Context, log *slog.Logger, hm *operatorv1alpha1.HostMapping) (ctrl.Result, error) {
	log.Info("updating host entry", "hostId", hm.Status.HostID)

	comment := fmt.Sprintf("k8s:%s/%s", hm.Namespace, hm.Name)
	err := r.HostClient.UpdateHost(ctx, hm.Status.HostID, hm.Spec.IP, hm.Spec.Hostname, comment, hm.Spec.Aliases, hm.Spec.Tags, hm.Status.HostVersion)
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

// SetupWithManager registers the HostMapping reconciler with the controller manager.
func (r *HostMappingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1alpha1.HostMapping{}).
		Named("hostmapping").
		Complete(r)
}
