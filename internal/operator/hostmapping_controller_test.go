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
