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
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"

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
	getCalls := 0
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error {
			updateCalled = true
			assert.Equal(t, "existing-id", id)
			assert.Equal(t, "192.168.1.20", ip)
			assert.Equal(t, "updated.local", hostname)
			// Version comes from the pre-update GetHost (authoritative), not the
			// stale Status.HostVersion.
			assert.Equal(t, "v1", version)
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			getCalls++
			if getCalls == 1 {
				// Pre-update fetch: IP/hostname match but aliases/tags absent,
				// so the spec diverges and an update is required.
				return &HostEntry{ID: id, IP: "192.168.1.20", Hostname: "updated.local", Version: "v1"}, nil
			}
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

// TestReconcile_Update_PostUpdateGetHostFailure verifies that when the
// post-update version refresh fails, the version is cleared (avoiding a stale
// concurrency token). The pre-update fetch succeeds and diverges, so the update
// runs.
func TestReconcile_Update_PostUpdateGetHostFailure(t *testing.T) {
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

	getCalls := 0
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			getCalls++
			if getCalls == 1 {
				// Pre-update fetch succeeds but diverges (no aliases), so the
				// update proceeds.
				return &HostEntry{ID: id, IP: "192.168.1.20", Hostname: "updated.local", Version: "v1"}, nil
			}
			// Post-update refresh fails.
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
	// Version should be cleared when the post-update GetHost fails.
	assert.Equal(t, "", updated.Status.HostVersion)
}

// TestReconcile_Update_PreflightGetHostFailure_Requeues verifies the fail-closed
// behavior: when the pre-update GetHost read fails, the reconciler requeues
// instead of issuing a blind UpdateHost that would re-append events and silently
// re-introduce the Bug 1 hot-loop.
func TestReconcile_Update_PreflightGetHostFailure_Requeues(t *testing.T) {
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

	updateCalled := false
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			updateCalled = true
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
	assert.Equal(t, requeueDelayShort, result.RequeueAfter, "must requeue when current state is unreadable")
	assert.False(t, updateCalled, "must NOT issue a blind UpdateHost when GetHost failed (would re-bloat)")

	// The degraded state must be observable on the CR, not a silent loop.
	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseError, updated.Status.Phase)
	require.Len(t, updated.Status.Conditions, 1)
	assert.Equal(t, metav1.ConditionFalse, updated.Status.Conditions[0].Status)
	assert.Equal(t, "PreflightReadFailed", updated.Status.Conditions[0].Reason)
}

// TestReconcile_Update_NoOpFixedPoint composes the two halves of the fix: after
// convergence, a second reconcile must remain a fixed point — no UpdateHost, and
// the status it writes must be one statusWriteFilter drops (so the real manager
// would not re-enqueue). This directly guards the #338 hot-loop regression.
func TestReconcile_Update_NoOpFixedPoint(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "existing-id"
	hm.Status.HostVersion = "v7"
	hm.Status.Phase = operatorv1alpha1.HostMappingPhaseSynced

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	updateCalls := 0
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			updateCalls++
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{
				ID:       id,
				IP:       "192.168.1.20",
				Hostname: "updated.local",
				Aliases:  []string{"alias1"},
				Tags:     []string{"kubernetes"},
				Version:  "v7",
			}, nil
		},
	}

	r := &HostMappingReconciler{
		Client:     k8sClient,
		Scheme:     s,
		HostClient: mock,
		Log:        slog.Default(),
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"}}

	_, err := r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	var first operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), req.NamespacedName, &first))

	_, err = r.Reconcile(context.Background(), req)
	require.NoError(t, err)
	var second operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), req.NamespacedName, &second))

	assert.Equal(t, 0, updateCalls, "in-sync host must never call UpdateHost across repeated reconciles")
	assert.Nil(t, second.Status.LastSyncTime, "no-op reconcile must not bump LastSyncTime")
	// Generation unchanged + same condition transition time → statusWriteFilter
	// drops the status write, so the real manager would not re-enqueue.
	assert.Equal(t, first.Generation, second.Generation)
	require.Len(t, second.Status.Conditions, 1)
	assert.Equal(t,
		first.Status.Conditions[0].LastTransitionTime,
		second.Status.Conditions[0].LastTransitionTime,
		"Synced condition transition time must be stable across no-op reconciles")
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
	getCalls := 0
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
			getCalls++
			if getCalls == 1 {
				// Pre-update fetch: existing host shares IP/hostname but lacks
				// the spec's aliases/tags, so adoption must still converge it.
				return &HostEntry{ID: id, IP: "192.168.1.10", Hostname: "my-host.local", Version: "v3"}, nil
			}
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

// ---------------------------------------------------------------------------
// Idempotency + version self-heal tests (GH #338)
// ---------------------------------------------------------------------------

// TestReconcile_Update_NoOpWhenInSync verifies that when the server already
// matches the desired spec, reconcileUpdate does NOT call UpdateHost — so the
// event-sourced server appends no event and the aggregate cannot bloat. This
// is the core fix for the reconcile hot-loop (Bug 1).
func TestReconcile_Update_NoOpWhenInSync(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	// Multi-element aliases/tags so the no-op decision genuinely exercises the
	// order-insensitive comparison (a regression to order-sensitive compare
	// would re-trigger UpdateHost every reconcile — the #338 failure mode).
	hm.Spec.Aliases = []string{"a1", "a2"}
	hm.Spec.Tags = []string{"t1", "t2"}
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
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			updateCalled = true
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			// Server state equals the desired spec but returns aliases/tags in
			// a DIFFERENT order — must still be treated as in sync.
			return &HostEntry{
				ID:       id,
				IP:       "192.168.1.20",
				Hostname: "updated.local",
				Aliases:  []string{"a2", "a1"},
				Tags:     []string{"t2", "t1"},
				Version:  "v7",
			}, nil
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
	assert.False(t, updateCalled, "UpdateHost must not be called when server already matches spec (no event appended)")

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
	assert.Equal(t, "v7", updated.Status.HostVersion, "version refreshed from server even on no-op")
	assert.Nil(t, updated.Status.LastSyncTime, "LastSyncTime must not be bumped on a no-op sync")
}

// TestReconcile_Update_EmptyVersion_SelfHeals reproduces Bug 2: a HostMapping
// with HostID set but HostVersion empty must self-heal instead of wedging on
// "version conflict: expected 0, got N". The operator re-derives the current
// version from the server rather than sending an empty expected version.
func TestReconcile_Update_EmptyVersion_SelfHeals(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "01KTW2TC"
	hm.Status.HostVersion = "" // wedged: empty version → server reads expected 0
	hm.Status.Phase = operatorv1alpha1.HostMappingPhaseSynced

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	updateCalled := false
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			updateCalled = true
			return nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{
				ID:       id,
				IP:       "192.168.1.20",
				Hostname: "updated.local",
				Aliases:  []string{"alias1"},
				Tags:     []string{"kubernetes"},
				Version:  "91178",
			}, nil
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
	assert.Equal(t, ctrl.Result{}, result, "must not error-requeue — wedge resolved")
	assert.False(t, updateCalled, "in-sync host needs no update; empty version must not cause a version conflict")

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
	assert.Equal(t, "91178", updated.Status.HostVersion, "empty version self-healed from server")
}

// TestReconcile_Update_StaleVersion_UsesFreshServerVersion verifies that when
// the spec genuinely diverges, UpdateHost is sent with the freshly-fetched
// server version — not the stale Status.HostVersion that would conflict.
func TestReconcile_Update_StaleVersion_UsesFreshServerVersion(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "existing-id"
	hm.Status.HostVersion = "stale-0" // stale token the operator must not trust

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	getCalls := 0
	var sentVersion string
	mock := &mockHostClient{
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			getCalls++
			if getCalls == 1 {
				// Pre-update fetch: IP/hostname match but aliases differ, so
				// the spec genuinely diverges and an update is required.
				return &HostEntry{ID: id, IP: "192.168.1.20", Hostname: "updated.local", Version: "91178"}, nil
			}
			return &HostEntry{ID: id, Version: "91179"}, nil
		},
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, version string) error {
			sentVersion = version
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
	assert.Equal(t, "91178", sentVersion, "UpdateHost must use the freshly-fetched server version, not the stale token")

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, "91179", updated.Status.HostVersion)
}

// ---------------------------------------------------------------------------
// statusWriteFilter predicate tests (GH #338)
// ---------------------------------------------------------------------------

// TestStatusWriteFilter verifies the predicate drops pure status-subresource
// writes (which would hot-loop) while still passing spec changes, finalizer
// changes, deletions, and informer resyncs.
func TestStatusWriteFilter(t *testing.T) {
	base := func(rv string, gen int64) *operatorv1alpha1.HostMapping {
		return &operatorv1alpha1.HostMapping{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "my-host",
				Namespace:       "default",
				ResourceVersion: rv,
				Generation:      gen,
				Finalizers:      []string{hostCleanupFinalizer},
			},
		}
	}

	withDeletion := func(hm *operatorv1alpha1.HostMapping) *operatorv1alpha1.HostMapping {
		now := metav1.Now()
		hm.DeletionTimestamp = &now
		return hm
	}
	withoutFinalizers := func(hm *operatorv1alpha1.HostMapping) *operatorv1alpha1.HostMapping {
		hm.Finalizers = nil
		return hm
	}

	pred := statusWriteFilter()

	tests := []struct {
		name string
		old  *operatorv1alpha1.HostMapping
		new  *operatorv1alpha1.HostMapping
		want bool
	}{
		{
			name: "spec change (generation bump) passes",
			old:  base("1", 1),
			new:  base("2", 2),
			want: true,
		},
		{
			name: "status-only write (generation unchanged) is dropped",
			old:  base("1", 1),
			new:  base("2", 1),
			want: false,
		},
		{
			name: "finalizer bootstrap passes",
			old:  withoutFinalizers(base("1", 1)),
			new:  base("2", 1),
			want: true,
		},
		{
			name: "finalizer removal (cleanup) passes",
			old:  base("1", 1),
			new:  withoutFinalizers(base("2", 1)),
			want: true,
		},
		{
			name: "deletion request passes",
			old:  base("1", 1),
			new:  withDeletion(base("2", 1)),
			want: true,
		},
		{
			name: "informer resync (identical ResourceVersion) passes",
			old:  base("1", 1),
			new:  base("1", 1),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pred.Update(event.UpdateEvent{ObjectOld: tc.old, ObjectNew: tc.new})
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestEqualStringSetsIgnoreOrder locks in the comparator properties the no-op
// skip depends on. A regression here (e.g. switching to an order-sensitive
// compare) would make every reconcile see a false diff and re-bloat the
// aggregate — the #338 failure mode.
func TestEqualStringSetsIgnoreOrder(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{name: "both nil", a: nil, b: nil, want: true},
		{name: "nil vs empty", a: nil, b: []string{}, want: true},
		{name: "empty vs nil", a: []string{}, b: nil, want: true},
		{name: "same order", a: []string{"a", "b"}, b: []string{"a", "b"}, want: true},
		{name: "different order", a: []string{"a", "b"}, b: []string{"b", "a"}, want: true},
		{name: "different length", a: []string{"a"}, b: []string{"a", "b"}, want: false},
		{name: "disjoint same length", a: []string{"a", "b"}, b: []string{"a", "c"}, want: false},
		{name: "multiset distinguishes duplicates", a: []string{"a", "a", "b"}, b: []string{"a", "b", "b"}, want: false},
		{name: "multiset equal duplicates", a: []string{"a", "a", "b"}, b: []string{"b", "a", "a"}, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, equalStringSetsIgnoreOrder(tc.a, tc.b))
		})
	}
}

// TestHostEntryMatchesSpec verifies the spec-equality check used to skip no-op
// updates, including order-insensitive aliases/tags and nil-vs-empty.
func TestHostEntryMatchesSpec(t *testing.T) {
	spec := operatorv1alpha1.HostMappingSpec{
		IP:       "10.0.0.1",
		Hostname: "host.local",
		Aliases:  []string{"a1", "a2"},
		Tags:     []string{"t1", "t2"},
	}

	tests := []struct {
		name  string
		entry *HostEntry
		want  bool
	}{
		{
			name:  "exact match",
			entry: &HostEntry{IP: "10.0.0.1", Hostname: "host.local", Aliases: []string{"a1", "a2"}, Tags: []string{"t1", "t2"}},
			want:  true,
		},
		{
			name:  "aliases/tags reordered still match",
			entry: &HostEntry{IP: "10.0.0.1", Hostname: "host.local", Aliases: []string{"a2", "a1"}, Tags: []string{"t2", "t1"}},
			want:  true,
		},
		{
			name:  "different IP",
			entry: &HostEntry{IP: "10.0.0.2", Hostname: "host.local", Aliases: []string{"a1", "a2"}, Tags: []string{"t1", "t2"}},
			want:  false,
		},
		{
			name:  "different hostname",
			entry: &HostEntry{IP: "10.0.0.1", Hostname: "other.local", Aliases: []string{"a1", "a2"}, Tags: []string{"t1", "t2"}},
			want:  false,
		},
		{
			name:  "missing alias",
			entry: &HostEntry{IP: "10.0.0.1", Hostname: "host.local", Aliases: []string{"a1"}, Tags: []string{"t1", "t2"}},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hostEntryMatchesSpec(tc.entry, spec))
		})
	}
}

// TestHostEntryMatchesSpec_NilVsEmpty verifies a nil spec slice matches an empty
// server slice — gRPC commonly returns []string{} where a K8s spec field is nil;
// treating them as different would mark an in-sync host as perpetually diverged.
func TestHostEntryMatchesSpec_NilVsEmpty(t *testing.T) {
	spec := operatorv1alpha1.HostMappingSpec{IP: "10.0.0.1", Hostname: "host.local"} // Aliases/Tags nil
	entry := &HostEntry{IP: "10.0.0.1", Hostname: "host.local", Aliases: []string{}, Tags: []string{}}
	assert.True(t, hostEntryMatchesSpec(entry, spec))
}

// ---------------------------------------------------------------------------
// NotFound -> recreate / delete tests (follow-up from #338)
// ---------------------------------------------------------------------------

// TestReconcile_Update_GetHostNotFound_Recreates verifies that when the
// server-side host was deleted out-of-band (pre-update GetHost returns
// ErrHostNotFound), the operator clears the stale HostID and recreates the
// entry instead of looping on a missing ID.
func TestReconcile_Update_GetHostNotFound_Recreates(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "stale-deleted-id"
	hm.Status.HostVersion = "v1"
	hm.Status.Phase = operatorv1alpha1.HostMappingPhaseSynced

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	addCalled := false
	mock := &mockHostClient{
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			if id == "stale-deleted-id" {
				return nil, fmt.Errorf("getting host %s: %w", id, ErrHostNotFound)
			}
			// Post-recreate version fetch.
			return &HostEntry{ID: id, Version: "v1"}, nil
		},
		addHostFn: func(_ context.Context, ip, hostname, _ string, _, _ []string) (string, error) {
			addCalled = true
			assert.Equal(t, "192.168.1.20", ip)
			assert.Equal(t, "updated.local", hostname)
			return "recreated-id", nil
		},
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			t.Error("UpdateHost must not be called when the host was deleted out-of-band")
			return nil
		},
	}

	r := &HostMappingReconciler{Client: k8sClient, Scheme: s, HostClient: mock, Log: slog.Default()}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result, "recreate must succeed without an error requeue")
	assert.True(t, addCalled, "must recreate the host via AddHost")

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, "recreated-id", updated.Status.HostID, "stale HostID replaced with the recreated entry")
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
}

// TestReconcile_Update_UpdateHostNotFound_Recreates verifies that when the host
// vanishes between the successful pre-update read and the write (UpdateHost
// returns ErrHostNotFound), the operator recreates it rather than erroring.
func TestReconcile_Update_UpdateHostNotFound_Recreates(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "vanishing-id"
	hm.Status.HostVersion = "v1"

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	addCalled := false
	mock := &mockHostClient{
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			if id == "vanishing-id" {
				// Pre-update fetch succeeds but diverges (no aliases) → update runs.
				return &HostEntry{ID: id, IP: "192.168.1.20", Hostname: "updated.local", Version: "v1"}, nil
			}
			return &HostEntry{ID: id, Version: "v9"}, nil
		},
		updateHostFn: func(_ context.Context, id, _, _, _ string, _, _ []string, _ string) error {
			assert.Equal(t, "vanishing-id", id)
			return fmt.Errorf("updating host %s: %w", id, ErrHostNotFound)
		},
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			addCalled = true
			return "recreated-id", nil
		},
	}

	r := &HostMappingReconciler{Client: k8sClient, Scheme: s, HostClient: mock, Log: slog.Default()}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.True(t, addCalled, "must recreate when UpdateHost returns NotFound")

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, "recreated-id", updated.Status.HostID)
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)
}

// TestReconcile_Delete_HostNotFound_RemovesFinalizer verifies that when the
// host was already deleted out-of-band, DeleteHost returning NotFound is treated
// as a completed delete — the finalizer is removed instead of the CR wedging in
// Terminating on a perpetual NotFound.
func TestReconcile_Delete_HostNotFound_RemovesFinalizer(t *testing.T) {
	s := testScheme(t)
	now := metav1.Now()
	hm := newTestHostMapping("my-host", "default", "192.168.1.10", "my-host.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.DeletionTimestamp = &now
	hm.Status.HostID = "already-gone-id"

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, id string) error {
			return fmt.Errorf("deleting host %s: %w", id, ErrHostNotFound)
		},
	}

	r := &HostMappingReconciler{Client: k8sClient, Scheme: s, HostClient: mock, Log: slog.Default()}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result, "must not requeue — deletion goal already satisfied")

	// Finalizer removed → object is gone (fake client deletes once last
	// finalizer is removed under a deletion timestamp).
	var updated operatorv1alpha1.HostMapping
	getErr := k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated)
	assert.True(t, client.IgnoreNotFound(getErr) == nil, "finalizer must be removed (CR not wedged in Terminating)")
}

// TestReconcile_Update_GetHostNotFound_RecreateAdoptsOnAlreadyExists exercises
// the bounded recreate cycle: GetHost NotFound -> reconcileCreate -> AddHost
// AlreadyExists -> adoptExistingHost -> reconcileUpdate. It must converge to
// Synced in a single pass without looping.
func TestReconcile_Update_GetHostNotFound_RecreateAdoptsOnAlreadyExists(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "stale-deleted-id"
	hm.Status.HostVersion = "v1"

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	getCalls := 0
	mock := &mockHostClient{
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			getCalls++
			if id == "stale-deleted-id" {
				// First read: the stale entry is gone.
				return nil, fmt.Errorf("getting host %s: %w", id, ErrHostNotFound)
			}
			// Post-adoption read of the existing entry already matches the spec,
			// so the bounce converges with no further UpdateHost.
			return &HostEntry{
				ID:       id,
				IP:       "192.168.1.20",
				Hostname: "updated.local",
				Aliases:  []string{"alias1"},
				Tags:     []string{"kubernetes"},
				Version:  "v9",
			}, nil
		},
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			// Recreate races a concurrent create → AlreadyExists triggers adopt.
			return "", fmt.Errorf("adding host: %w", ErrHostAlreadyExists)
		},
		findHostFn: func(_ context.Context, ip, hostname string) (*HostEntry, error) {
			return &HostEntry{ID: "adopted-id", IP: ip, Hostname: hostname, Aliases: []string{"alias1"}, Tags: []string{"kubernetes"}, Version: "v9"}, nil
		},
	}

	rec := events.NewFakeRecorder(10)
	r := &HostMappingReconciler{Client: k8sClient, Scheme: s, HostClient: mock, Log: slog.Default(), Recorder: rec}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result, "recreate->adopt must converge without an error requeue")

	var updated operatorv1alpha1.HostMapping
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-host", Namespace: "default"}, &updated))
	assert.Equal(t, "adopted-id", updated.Status.HostID, "must adopt the existing entry")
	assert.Equal(t, operatorv1alpha1.HostMappingPhaseSynced, updated.Status.Phase)

	// The previously-missing host was restored (via adoption of a concurrently
	// recreated entry), so the Recreated event still fires — pins the documented
	// adopt-path behavior of recreateMissingHost.
	events := drainEvents(rec)
	require.Len(t, events, 1, "adopt-after-missing is a recovery; one Recreated event expected")
	assert.Contains(t, events[0], "Recreated")
}

// drainEvents collects all events currently buffered on a FakeRecorder without
// blocking once the channel is empty.
func drainEvents(rec *events.FakeRecorder) []string {
	var events []string
	for {
		select {
		case e := <-rec.Events:
			events = append(events, e)
		default:
			return events
		}
	}
}

// TestReconcile_Update_GetHostNotFound_EmitsRecreatedEvent verifies that when a
// host deleted out-of-band is recreated (pre-update GetHost returns
// ErrHostNotFound), the controller emits a Normal "Recreated" Kubernetes Event
// so the corrective action is visible in kubectl, distinct from a first-time
// create (follow-up #342).
func TestReconcile_Update_GetHostNotFound_EmitsRecreatedEvent(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "stale-deleted-id"
	hm.Status.HostVersion = "v1"
	hm.Status.Phase = operatorv1alpha1.HostMappingPhaseSynced

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			if id == "stale-deleted-id" {
				return nil, fmt.Errorf("getting host %s: %w", id, ErrHostNotFound)
			}
			return &HostEntry{ID: id, Version: "v1"}, nil
		},
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "recreated-id", nil
		},
	}

	rec := events.NewFakeRecorder(10)
	r := &HostMappingReconciler{Client: k8sClient, Scheme: s, HostClient: mock, Log: slog.Default(), Recorder: rec}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)

	events := drainEvents(rec)
	require.Len(t, events, 1, "exactly one event expected")
	assert.Contains(t, events[0], "Normal")
	assert.Contains(t, events[0], "Recreated")
}

// TestReconcile_Update_UpdateHostNotFound_EmitsRecreatedEvent verifies the
// Recreated event also fires on the second recreate path: the host vanishes
// between the pre-update read and the write (UpdateHost returns ErrHostNotFound).
func TestReconcile_Update_UpdateHostNotFound_EmitsRecreatedEvent(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "updated.local")
	hm.Finalizers = []string{hostCleanupFinalizer}
	hm.Status.HostID = "vanishing-id"
	hm.Status.HostVersion = "v1"

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			if id == "vanishing-id" {
				return &HostEntry{ID: id, IP: "192.168.1.20", Hostname: "updated.local", Version: "v1"}, nil
			}
			return &HostEntry{ID: id, Version: "v9"}, nil
		},
		updateHostFn: func(_ context.Context, id, _, _, _ string, _, _ []string, _ string) error {
			return fmt.Errorf("updating host %s: %w", id, ErrHostNotFound)
		},
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "recreated-id", nil
		},
	}

	rec := events.NewFakeRecorder(10)
	r := &HostMappingReconciler{Client: k8sClient, Scheme: s, HostClient: mock, Log: slog.Default(), Recorder: rec}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)

	events := drainEvents(rec)
	require.Len(t, events, 1, "exactly one event expected")
	assert.Contains(t, events[0], "Recreated")
}

// TestReconcile_Create_NoRecreatedEvent verifies a genuine first-time create
// does NOT emit a Recreated event — the event is reserved for corrective
// recreation of an out-of-band-deleted host.
func TestReconcile_Create_NoRecreatedEvent(t *testing.T) {
	s := testScheme(t)
	hm := newTestHostMapping("my-host", "default", "192.168.1.20", "new.local")
	hm.Finalizers = []string{hostCleanupFinalizer}

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(hm).
		WithStatusSubresource(hm).
		Build()

	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "new-id", nil
		},
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{ID: id, Version: "v1"}, nil
		},
	}

	rec := events.NewFakeRecorder(10)
	r := &HostMappingReconciler{Client: k8sClient, Scheme: s, HostClient: mock, Log: slog.Default(), Recorder: rec}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-host", Namespace: "default"},
	})
	require.NoError(t, err)

	events := drainEvents(rec)
	assert.Empty(t, events, "first-time create must not emit a Recreated event")
}
