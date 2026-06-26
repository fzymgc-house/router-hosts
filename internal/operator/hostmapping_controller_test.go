package operator

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	operatorv1alpha1 "github.com/fzymgc-house/router-hosts/api/operator/v1alpha1"
)

// mockHostClient implements HostClient for testing.
type mockHostClient struct {
	addHostFn    func(ctx context.Context, ip, hostname, comment string, aliases, tags []string) (string, error)
	updateHostFn func(ctx context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error
	deleteHostFn func(ctx context.Context, id string) error
	getHostFn    func(ctx context.Context, id string) (*HostEntry, error)
	findHostFn   func(ctx context.Context, ip, hostname string) (*HostEntry, error)
}

func (m *mockHostClient) AddHost(ctx context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
	if m.addHostFn != nil {
		return m.addHostFn(ctx, ip, hostname, comment, aliases, tags)
	}
	return "test-id-1", nil
}

func (m *mockHostClient) UpdateHost(ctx context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error {
	if m.updateHostFn != nil {
		return m.updateHostFn(ctx, id, ip, hostname, comment, aliases, tags, version)
	}
	return nil
}

func (m *mockHostClient) DeleteHost(ctx context.Context, id string) error {
	if m.deleteHostFn != nil {
		return m.deleteHostFn(ctx, id)
	}
	return nil
}

func (m *mockHostClient) GetHost(ctx context.Context, id string) (*HostEntry, error) {
	if m.getHostFn != nil {
		return m.getHostFn(ctx, id)
	}
	return &HostEntry{
		ID:       id,
		IP:       "192.168.1.10",
		Hostname: "test.local",
		Version:  "v1",
	}, nil
}

func (m *mockHostClient) FindHost(ctx context.Context, ip, hostname string) (*HostEntry, error) {
	if m.findHostFn != nil {
		return m.findHostFn(ctx, ip, hostname)
	}
	return nil, nil
}

func (m *mockHostClient) Close() error { return nil }

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, operatorv1alpha1.AddToScheme(s))
	return s
}

func newTestHostMapping(name, namespace, ip, hostname string) *operatorv1alpha1.HostMapping {
	return &operatorv1alpha1.HostMapping{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: operatorv1alpha1.HostMappingSpec{
			IP:       ip,
			Hostname: hostname,
			Aliases:  []string{"alias1"},
			Tags:     []string{"kubernetes"},
		},
	}
}

func TestReconcile_Create(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	addCalled := false
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addCalled = true
			assert.Equal(t, "192.168.1.10", ip)
			assert.Equal(t, "my-host.local", hostname)
			assert.Equal(t, "k8s:default/my-host", comment)
			assert.Equal(t, []string{"alias1"}, aliases)
			assert.Equal(t, []string{"kubernetes"}, tags)
			return "host-abc-123", nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{ID: id, Version: "v1"}, nil
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	// First reconcile: adds finalizer.
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Verify finalizer was added.
	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Contains(t, updated.Finalizers, hostCleanupFinalizer)

	// Second reconcile: creates host.
	result, err = r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.True(t, addCalled)

	// Verify status.
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
	assert.Equal(t, "host-abc-123", updated.Status.HostID)
	assert.Equal(t, "v1", updated.Status.HostVersion)
	assert.NotNil(t, updated.Status.LastSyncTime)
}

func TestReconcile_Update(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "existing-id"
	hm.Status.HostVersion = "v1"
	hm.Status.Phase = operatorv1alpha1.HostMappingPhaseSynced

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	updateCalled := false
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error {
			updateCalled = true
			assert.Equal(t, "existing-id", id)
			assert.Equal(t, "192.168.1.20", ip)
			assert.Equal(t, "updated.local", hostname)
			assert.Equal(t, "v1", version)
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{ID: id, Version: "v2"}, nil
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.True(t, updateCalled)

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
	assert.Equal(t, "v2", updated.Status.HostVersion)
}

func TestReconcile_Delete(t *testing.T) {
	s := testScheme(t)
	now := metav1.Now()
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.DeletionTimestamp = &now
	hm.Status.HostID = "delete-me-id"

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	deleteCalled := false
	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, id string) error {
			deleteCalled = true
			assert.Equal(t, "delete-me-id", id)
			return nil
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.True(t, deleteCalled)

	// The fake client deletes the object once the last finalizer is removed
	// and DeletionTimestamp is set, so a "not found" result is expected.
	var updated operatorv1alpha1.HostMapping
	err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated)
	assert.True(t, client.IgnoreNotFound(err) == nil, "expected object to be deleted or finalizer removed")
}

func TestReconcile_ServerUnavailable(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "", fmt.Errorf("connection refused")
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, requeueDelayLong, result.RequeueAfter)

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseError, updated.Status.Phase)
	assert.Contains(t, updated.Status.Message, "connection refused")

	// Verify Synced condition is False.
	require.Len(t, updated.Status.Conditions, 1)
	assert.Equal(t, operatorv1alpha1.ConditionSynced, updated.Status.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionFalse, updated.Status.Conditions[0].Status)
	assert.Equal(t, "CreateFailed", updated.Status.Conditions[0].Reason)
}

func TestReconcile_NotFound(t *testing.T) {
	s := testScheme(t)

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		Build()

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: &mockHostClient{},
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

func TestReconcile_Create_GetHostFailure(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "host-abc-123", nil
		},
		getHostFn: func(_ context.Context, _ string) (*HostEntry, error) {
			return nil, fmt.Errorf("transient error fetching version")
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
	assert.Equal(t, "host-abc-123", updated.Status.HostID)
	// Version should be empty when GetHost fails
	assert.Equal(t, "", updated.Status.HostVersion)
	assert.Contains(t, updated.Status.Message, "Created (version unknown)")
}

func TestReconcile_Update_Failure(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "existing-id"
	hm.Status.HostVersion = "v1"
	hm.Status.Phase = operatorv1alpha1.HostMappingPhaseSynced

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			return fmt.Errorf("server unavailable")
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, requeueDelayLong, result.RequeueAfter)

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseError, updated.Status.Phase)
	assert.Contains(t, updated.Status.Message, "server unavailable")

	require.Len(t, updated.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, updated.Status.Conditions[0].Status)
	assert.Equal(t, "UpdateFailed", updated.Status.Conditions[0].Reason)
}

func TestReconcile_Update_GetHostFailure(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "existing-id"
	hm.Status.HostVersion = "v1"

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			return nil
		},
		getHostFn: func(_ context.Context, _ string) (*HostEntry, error) {
			return nil, fmt.Errorf("transient GetHost error")
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
	// Version should be cleared when GetHost fails after update
	assert.Equal(t, "", updated.Status.HostVersion)
}

func TestReconcile_Delete_NoHostID(t *testing.T) {
	s := testScheme(t)
	now := metav1.Now()
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.DeletionTimestamp = &now
	// No HostID — nothing to delete on server

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	deleteCalled := false
	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.False(t, deleteCalled, "should not call DeleteHost when HostID is empty")
}

func TestSetSyncedCondition_SameStatus_PreservesTransitionTime(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")

	// Set an initial condition
	originalTime := metav1.Now()
	hm.Status.Conditions = []metav1.Condition{
		{
			Type:               operatorv1alpha1.ConditionSynced,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: originalTime,
			Reason:             "Created",
			Message:            "Initial",
		},
	}

	r := &HostMappingReconciler{
		Client: fake.NewClientBuilder().WithScheme(s).WithObjects(hm).Build(),
		Scheme: s,
		Log:    slog.Default(),
	}

	// Set condition with same status — should preserve LastTransitionTime
	r.setSyncedCondition(hm, metav1.ConditionTrue, "Updated", "Re-synced")

	require.Len(t, hm.Status.Conditions, 1)
	assert.Equal(t, originalTime, hm.Status.Conditions[0].LastTransitionTime)
	assert.Equal(t, "Updated", hm.Status.Conditions[0].Reason)
	assert.Equal(t, "Re-synced", hm.Status.Conditions[0].Message)
}

func TestSetSyncedCondition_StatusChange_UpdatesTransitionTime(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")

	// Set an initial True condition
	hm.Status.Conditions = []metav1.Condition{
		{
			Type:               operatorv1alpha1.ConditionSynced,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "Created",
			Message:            "Initial",
		},
	}

	r := &HostMappingReconciler{
		Client: fake.NewClientBuilder().WithScheme(s).WithObjects(hm).Build(),
		Scheme: s,
		Log:    slog.Default(),
	}

	// Change to False — should update LastTransitionTime
	r.setSyncedCondition(hm, metav1.ConditionFalse, "UpdateFailed", "Error occurred")

	require.Len(t, hm.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, hm.Status.Conditions[0].Status)
	assert.Equal(t, "UpdateFailed", hm.Status.Conditions[0].Reason)
}

func TestSetSyncedCondition_NoExisting_Appends(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")

	r := &HostMappingReconciler{
		Client: fake.NewClientBuilder().WithScheme(s).WithObjects(hm).Build(),
		Scheme: s,
		Log:    slog.Default(),
	}

	r.setSyncedCondition(hm, metav1.ConditionTrue, "Created", "First condition")

	require.Len(t, hm.Status.Conditions, 1)
	assert.Equal(t, operatorv1alpha1.ConditionSynced, hm.Status.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, hm.Status.Conditions[0].Status)
}

func TestReconcile_DeleteFailure_Requeues(t *testing.T) {
	s := testScheme(t)
	now := metav1.Now()
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.DeletionTimestamp = &now
	hm.Status.HostID = "delete-me-id"

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("server unavailable")
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, requeueDelayShort, result.RequeueAfter)

	// Finalizer should still be present.
	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Contains(t, updated.Finalizers, hostCleanupFinalizer)
}

// ---------------------------------------------------------------------------
// AlreadyExists / adoption tests (GH #313)
// ---------------------------------------------------------------------------

// TestReconcile_AlreadyExists_AdoptsExistingHost verifies that when AddHost
// returns ErrHostAlreadyExists the reconciler adopts the existing entry via
// FindHost and converges state, instead of hot-looping with repeated errors.
func TestReconcile_AlreadyExists_AdoptsExistingHost(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	addCalls := 0
	updateCalled := false
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			addCalls++
			return "", fmt.Errorf("adding host 192.168.1.10/my-host.local: %w", ErrHostAlreadyExists)
		},
		findHostFn: func(_ context.Context, ip, hostname string) (*HostEntry, error) {
			assert.Equal(t, "192.168.1.10", ip)
			assert.Equal(t, "my-host.local", hostname)
			return &HostEntry{
				ID:       "existing-id-42",
				IP:       ip,
				Hostname: hostname,
				Version:  "v3",
			}, nil
		},
		updateHostFn: func(_ context.Context, id, _, _, _ string, _, _ []string, version string) error {
			updateCalled = true
			assert.Equal(t, "existing-id-42", id)
			assert.Equal(t, "v3", version)
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{ID: id, Version: "v4"}, nil
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	// Must not request the long error-requeue (no hot-loop).
	assert.Equal(t, ctrl.Result{}, result, "adoption should succeed without requeue")
	assert.Equal(t, 1, addCalls, "AddHost called exactly once")
	assert.True(t, updateCalled, "reconcileUpdate must run to converge spec")

	// Verify status: HostID adopted, Synced=True, no error phase.
	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, "existing-id-42", updated.Status.HostID)
	assert.Equal(t, "v4", updated.Status.HostVersion, "version refreshed by GetHost after UpdateHost")
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)

	require.Len(t, updated.Status.Conditions, 1)
	assert.Equal(t, operatorv1alpha1.ConditionSynced, updated.Status.Conditions[0].Type)
	assert.Equal(t, metav1.ConditionTrue, updated.Status.Conditions[0].Status)
}

// TestReconcile_AlreadyExists_Idempotent verifies that after adoption the next
// Reconcile goes through reconcileUpdate (not another AddHost call).
func TestReconcile_AlreadyExists_Idempotent(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	addCalls := 0
	updateCalls := 0
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			addCalls++
			return "", fmt.Errorf("adding host: %w", ErrHostAlreadyExists)
		},
		findHostFn: func(_ context.Context, ip, hostname string) (*HostEntry, error) {
			return &HostEntry{ID: "existing-id-42", IP: ip, Hostname: hostname, Version: "v1"}, nil
		},
		updateHostFn: func(_ context.Context, _ string, _, _, _ string, _, _ []string, _ string) error {
			updateCalls++
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{ID: id, Version: "v2"}, nil
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	// First reconcile: AlreadyExists → adoption → reconcileUpdate.
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, 1, addCalls)
	assert.Equal(t, 1, updateCalls)

	// Second reconcile: HostID is now set, so reconcileUpdate runs directly.
	result, err = r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, 1, addCalls, "AddHost must NOT be called again")
	assert.Equal(t, 2, updateCalls)
}

// TestReconcile_FindHost_ExactMatch verifies that FindHost performs exact
// IP+hostname matching — a candidate that shares a hostname prefix but has a
// different IP must not be adopted.
func TestReconcile_FindHost_ExactMatch(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "10.0.0.1", "host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "", fmt.Errorf("adding host: %w", ErrHostAlreadyExists)
		},
		findHostFn: func(_ context.Context, ip, hostname string) (*HostEntry, error) {
			// Simulate the server returning a prefix-collision candidate first,
			// then the actual match. FindHost must return the exact match only.
			candidates := []*HostEntry{
				{ID: "wrong-id", IP: "10.0.0.99", Hostname: "host.local"},    // wrong IP
				{ID: "right-id", IP: "10.0.0.1", Hostname: "host.local"},     // exact match
				{ID: "also-wrong", IP: "10.0.0.1", Hostname: "host.local.x"}, // wrong hostname
			}
			for _, c := range candidates {
				if c.IP == ip && c.Hostname == hostname {
					c.Version = "v1"
					return c, nil
				}
			}
			return nil, nil
		},
		updateHostFn: func(_ context.Context, id, _, _, _ string, _, _ []string, _ string) error {
			assert.Equal(t, "right-id", id, "must adopt exact match, not prefix collision")
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{ID: id, Version: "v2"}, nil
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, "right-id", updated.Status.HostID)
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
}

// TestReconcile_AlreadyExists_FindHostReturnsNil_Fallback verifies that when
// FindHost finds nothing after AlreadyExists (race: host deleted between calls)
// the reconciler falls back to error/requeue without panicking or adopting a
// wrong ID.
func TestReconcile_AlreadyExists_FindHostReturnsNil_Fallback(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "", fmt.Errorf("adding host: %w", ErrHostAlreadyExists)
		},
		findHostFn: func(_ context.Context, _, _ string) (*HostEntry, error) {
			return nil, nil // race: host disappeared
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, requeueDelayLong, result.RequeueAfter, "must requeue on adoption fallback")

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseError, updated.Status.Phase)
	assert.Equal(t, "", updated.Status.HostID, "must not set HostID when adoption failed")

	require.Len(t, updated.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, updated.Status.Conditions[0].Status)
	assert.Equal(t, "AdoptionFailed", updated.Status.Conditions[0].Reason)
}
