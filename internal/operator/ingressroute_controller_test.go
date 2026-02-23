package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestExtractHosts_HostRule(t *testing.T) {
	obj := newIngressRoute("test-ir", "default", []map[string]interface{}{
		{"match": "Host(`example.com`)"},
	})

	hosts := extractHosts(slog.Default(), obj)
	assert.Equal(t, []string{"example.com"}, hosts)
}

func TestExtractHosts_MultipleHosts(t *testing.T) {
	obj := newIngressRoute("test-ir", "default", []map[string]interface{}{
		{"match": "Host(`a.com`) || Host(`b.com`)"},
	})

	hosts := extractHosts(slog.Default(), obj)
	assert.Equal(t, []string{"a.com", "b.com"}, hosts)
}

func TestExtractHosts_HostSNI(t *testing.T) {
	obj := newIngressRoute("test-ir", "default", []map[string]interface{}{
		{"match": "HostSNI(`secure.example.com`)"},
	})

	hosts := extractHosts(slog.Default(), obj)
	assert.Equal(t, []string{"secure.example.com"}, hosts)
}

func TestExtractHosts_MixedHostAndHostSNI(t *testing.T) {
	obj := newIngressRoute("test-ir", "default", []map[string]interface{}{
		{"match": "Host(`web.example.com`) && PathPrefix(`/api`)"},
		{"match": "HostSNI(`secure.example.com`)"},
	})

	hosts := extractHosts(slog.Default(), obj)
	assert.Equal(t, []string{"web.example.com", "secure.example.com"}, hosts)
}

func TestExtractHosts_Deduplication(t *testing.T) {
	obj := newIngressRoute("test-ir", "default", []map[string]interface{}{
		{"match": "Host(`example.com`)"},
		{"match": "Host(`example.com`) && PathPrefix(`/v2`)"},
	})

	hosts := extractHosts(slog.Default(), obj)
	assert.Equal(t, []string{"example.com"}, hosts)
}

func TestExtractHosts_NoRoutes(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "traefik.io/v1alpha1",
			"kind":       "IngressRoute",
			"metadata": map[string]interface{}{
				"name":      "empty",
				"namespace": "default",
			},
			"spec": map[string]interface{}{},
		},
	}

	hosts := extractHosts(slog.Default(), obj)
	assert.Empty(t, hosts)
}

func TestExtractHosts_NoMatchField(t *testing.T) {
	obj := newIngressRoute("test-ir", "default", []map[string]interface{}{
		{"priority": int64(10)},
	})

	hosts := extractHosts(slog.Default(), obj)
	assert.Empty(t, hosts)
}

func TestExtractHostsFromMatch(t *testing.T) {
	tests := []struct {
		name     string
		match    string
		expected []string
	}{
		{
			name:     "single host",
			match:    "Host(`example.com`)",
			expected: []string{"example.com"},
		},
		{
			name:     "host with path",
			match:    "Host(`example.com`) && PathPrefix(`/api`)",
			expected: []string{"example.com"},
		},
		{
			name:     "multiple hosts OR",
			match:    "Host(`a.com`) || Host(`b.com`)",
			expected: []string{"a.com", "b.com"},
		},
		{
			name:     "hostsni",
			match:    "HostSNI(`secure.example.com`)",
			expected: []string{"secure.example.com"},
		},
		{
			name:     "mixed host and hostsni",
			match:    "Host(`web.com`) && HostSNI(`secure.web.com`)",
			expected: []string{"web.com", "secure.web.com"},
		},
		{
			name:     "no host pattern",
			match:    "PathPrefix(`/api`)",
			expected: nil,
		},
		{
			name:     "empty string",
			match:    "",
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractHostsFromMatch(tc.match)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestReconcile_IngressRoute_Create(t *testing.T) {
	s := ingressRouteScheme(t)
	obj := newIngressRoute("my-ir", "default", []map[string]interface{}{
		{"match": "Host(`app.example.com`)"},
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	var addedHosts []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addedHosts = append(addedHosts, hostname)
			assert.Equal(t, "10.0.0.1", ip)
			assert.Contains(t, tags, "traefik")
			assert.Contains(t, tags, "ingress")
			return "ingress-host-1", nil
		},
	}

	r := &IngressRouteReconciler{
		Client:      k8sClient,
		HostClient:  mock,
		Log:         slog.Default(),
		DefaultIP:   "10.0.0.1",
		DefaultTags: []string{"kubernetes"},
	}

	// First reconcile: adds finalizer.
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Second reconcile: creates hosts.
	result, err = r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, []string{"app.example.com"}, addedHosts)

	// Verify annotation was set.
	var updated unstructured.Unstructured
	updated.SetGroupVersionKind(ingressRouteGVK)
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-ir", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(slog.Default(), &updated)
	require.NoError(t, err)
	assert.Equal(t, "ingress-host-1", ids["app.example.com"])
}

func TestReconcile_IngressRoute_Delete(t *testing.T) {
	s := ingressRouteScheme(t)
	now := metav1.Now()

	hostIDs := map[string]string{"app.example.com": "host-to-delete"}
	idsJSON, _ := json.Marshal(hostIDs)

	obj := newIngressRoute("my-ir", "default", []map[string]interface{}{
		{"match": "Host(`app.example.com`)"},
	})
	obj.SetFinalizers([]string{ingressRouteCleanupFinalizer})
	obj.SetDeletionTimestamp(&now)
	obj.SetAnnotations(map[string]string{
		hostIDsAnnotation: string(idsJSON),
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	deletedIDs := make(map[string]bool)
	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, id string) error {
			deletedIDs[id] = true
			return nil
		},
	}

	r := &IngressRouteReconciler{
		Client:     k8sClient,
		HostClient: mock,
		Log:        slog.Default(),
		DefaultIP:  "10.0.0.1",
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.True(t, deletedIDs["host-to-delete"])
}

func TestReconcile_IngressRoute_StaleHostCleanup(t *testing.T) {
	s := ingressRouteScheme(t)

	// Previously had two hosts; now only one.
	existingIDs := map[string]string{
		"keep.example.com":   "keep-id",
		"remove.example.com": "remove-id",
	}
	idsJSON, _ := json.Marshal(existingIDs)

	obj := newIngressRoute("my-ir", "default", []map[string]interface{}{
		{"match": "Host(`keep.example.com`)"},
	})
	obj.SetFinalizers([]string{ingressRouteCleanupFinalizer})
	obj.SetAnnotations(map[string]string{
		hostIDsAnnotation: string(idsJSON),
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	deletedIDs := make(map[string]bool)
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, id, _, _, _ string, _, _ []string, _ string) error {
			return nil
		},
		deleteHostFn: func(_ context.Context, id string) error {
			deletedIDs[id] = true
			return nil
		},
	}

	r := &IngressRouteReconciler{
		Client:      k8sClient,
		HostClient:  mock,
		Log:         slog.Default(),
		DefaultIP:   "10.0.0.1",
		DefaultTags: []string{"kubernetes"},
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// The stale host should have been deleted.
	assert.True(t, deletedIDs["remove-id"], "stale host entry should be deleted")
	assert.False(t, deletedIDs["keep-id"], "kept host entry should not be deleted")

	// Verify annotation only has the kept host.
	var updated unstructured.Unstructured
	updated.SetGroupVersionKind(ingressRouteGVK)
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-ir", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(slog.Default(), &updated)
	require.NoError(t, err)
	assert.Equal(t, "keep-id", ids["keep.example.com"])
	_, hasRemoved := ids["remove.example.com"]
	assert.False(t, hasRemoved)
}

func TestReconcile_IngressRoute_ServerError_Requeues(t *testing.T) {
	s := ingressRouteScheme(t)
	obj := newIngressRoute("my-ir", "default", []map[string]interface{}{
		{"match": "Host(`fail.example.com`)"},
	})
	obj.SetFinalizers([]string{ingressRouteCleanupFinalizer})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "", fmt.Errorf("connection refused")
		},
	}

	r := &IngressRouteReconciler{
		Client:     k8sClient,
		HostClient: mock,
		Log:        slog.Default(),
		DefaultIP:  "10.0.0.1",
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, requeueDelayLong, result.RequeueAfter)
}

func TestReconcile_IngressRoute_NotFound(t *testing.T) {
	s := ingressRouteScheme(t)

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		Build()

	r := &IngressRouteReconciler{
		Client:     k8sClient,
		HostClient: &mockHostClient{},
		Log:        slog.Default(),
		DefaultIP:  "10.0.0.1",
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

func TestHostIDsAnnotation_RoundTrip(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{}}

	// Empty initially.
	ids, err := getHostIDsAnnotation(slog.Default(), obj)
	require.NoError(t, err)
	assert.Nil(t, ids)

	// Set and read back.
	require.NoError(t, setHostIDsAnnotation(obj, map[string]string{
		"a.com": "id-1",
		"b.com": "id-2",
	}))
	ids, err = getHostIDsAnnotation(slog.Default(), obj)
	require.NoError(t, err)
	assert.Equal(t, "id-1", ids["a.com"])
	assert.Equal(t, "id-2", ids["b.com"])

	// Clear.
	require.NoError(t, setHostIDsAnnotation(obj, nil))
	ids, err = getHostIDsAnnotation(slog.Default(), obj)
	require.NoError(t, err)
	assert.Nil(t, ids)
}

func TestReconcile_IngressRoute_Delete_Failure_Requeues(t *testing.T) {
	s := ingressRouteScheme(t)
	now := metav1.Now()

	hostIDs := map[string]string{"app.example.com": "host-fail-delete"}
	idsJSON, _ := json.Marshal(hostIDs)

	obj := newIngressRoute("my-ir", "default", []map[string]interface{}{
		{"match": "Host(`app.example.com`)"},
	})
	obj.SetFinalizers([]string{ingressRouteCleanupFinalizer})
	obj.SetDeletionTimestamp(&now)
	obj.SetAnnotations(map[string]string{
		hostIDsAnnotation: string(idsJSON),
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("server unavailable")
		},
	}

	r := &IngressRouteReconciler{
		Client:     k8sClient,
		HostClient: mock,
		Log:        slog.Default(),
		DefaultIP:  "10.0.0.1",
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, requeueDelayShort, result.RequeueAfter)

	// Finalizer should still be present
	var updated unstructured.Unstructured
	updated.SetGroupVersionKind(ingressRouteGVK)
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-ir", Namespace: "default"}, &updated))
	assert.Contains(t, updated.GetFinalizers(), ingressRouteCleanupFinalizer)
}

func TestReconcile_IngressRoute_UpdateFailure_Requeues(t *testing.T) {
	s := ingressRouteScheme(t)

	existingIDs := map[string]string{"app.example.com": "existing-id"}
	idsJSON, _ := json.Marshal(existingIDs)

	obj := newIngressRoute("my-ir", "default", []map[string]interface{}{
		{"match": "Host(`app.example.com`)"},
	})
	obj.SetFinalizers([]string{ingressRouteCleanupFinalizer})
	obj.SetAnnotations(map[string]string{
		hostIDsAnnotation: string(idsJSON),
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			return fmt.Errorf("update failed")
		},
	}

	r := &IngressRouteReconciler{
		Client:     k8sClient,
		HostClient: mock,
		Log:        slog.Default(),
		DefaultIP:  "10.0.0.1",
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, requeueDelayLong, result.RequeueAfter)

	// Should retain the existing ID in annotations despite update failure
	var updated unstructured.Unstructured
	updated.SetGroupVersionKind(ingressRouteGVK)
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-ir", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(slog.Default(), &updated)
	require.NoError(t, err)
	assert.Equal(t, "existing-id", ids["app.example.com"])
}

func TestReconcile_IngressRoute_StaleDeleteFailure(t *testing.T) {
	s := ingressRouteScheme(t)

	existingIDs := map[string]string{
		"keep.example.com":   "keep-id",
		"remove.example.com": "remove-id",
	}
	idsJSON, _ := json.Marshal(existingIDs)

	obj := newIngressRoute("my-ir", "default", []map[string]interface{}{
		{"match": "Host(`keep.example.com`)"},
	})
	obj.SetFinalizers([]string{ingressRouteCleanupFinalizer})
	obj.SetAnnotations(map[string]string{
		hostIDsAnnotation: string(idsJSON),
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			return nil
		},
		deleteHostFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("delete failed")
		},
	}

	r := &IngressRouteReconciler{
		Client:      k8sClient,
		HostClient:  mock,
		Log:         slog.Default(),
		DefaultIP:   "10.0.0.1",
		DefaultTags: []string{"kubernetes"},
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, requeueDelayLong, result.RequeueAfter)

	// Both IDs should be retained when stale delete fails
	var updated unstructured.Unstructured
	updated.SetGroupVersionKind(ingressRouteGVK)
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-ir", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(slog.Default(), &updated)
	require.NoError(t, err)
	assert.Equal(t, "keep-id", ids["keep.example.com"])
	assert.Equal(t, "remove-id", ids["remove.example.com"])
}

func TestReconcile_IngressRoute_NoHosts(t *testing.T) {
	s := ingressRouteScheme(t)

	// IngressRoute with no Host() patterns in match rules
	obj := newIngressRoute("my-ir", "default", []map[string]interface{}{
		{"match": "PathPrefix(`/api`)"},
	})
	obj.SetFinalizers([]string{ingressRouteCleanupFinalizer})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	mock := &mockHostClient{}

	r := &IngressRouteReconciler{
		Client:     k8sClient,
		HostClient: mock,
		Log:        slog.Default(),
		DefaultIP:  "10.0.0.1",
	}

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}

func TestGetHostIDsAnnotation_InvalidJSON(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	obj.SetAnnotations(map[string]string{
		hostIDsAnnotation: "not valid json",
	})

	ids, err := getHostIDsAnnotation(slog.Default(), obj)
	assert.Error(t, err)
	assert.Nil(t, ids)
}

func TestGetHostIDsAnnotation_EmptyValue(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	obj.SetAnnotations(map[string]string{
		hostIDsAnnotation: "",
	})

	ids, err := getHostIDsAnnotation(slog.Default(), obj)
	require.NoError(t, err)
	assert.Nil(t, ids)
}

func TestExtractHosts_InvalidRouteType(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "traefik.io/v1alpha1",
			"kind":       "IngressRoute",
			"metadata": map[string]interface{}{
				"name":      "test",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"routes": []interface{}{
					"not-a-map",
				},
			},
		},
	}

	hosts := extractHosts(slog.Default(), obj)
	assert.Empty(t, hosts)
}

func TestReconcile_IngressRouteTCP_Create(t *testing.T) {
	s := ingressRouteScheme(t)
	obj := newIngressRouteTCP("my-tcp-ir", "default", []map[string]interface{}{
		{"match": "HostSNI(`tcp.example.com`)"},
	})

	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(obj).
		Build()

	var addedHosts []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addedHosts = append(addedHosts, hostname)
			assert.Equal(t, "10.0.0.1", ip)
			assert.Contains(t, tags, "traefik")
			assert.Contains(t, tags, "ingress")
			return "tcp-ingress-host-1", nil
		},
	}

	r := &IngressRouteReconciler{
		Client:      k8sClient,
		HostClient:  mock,
		Log:         slog.Default(),
		DefaultIP:   "10.0.0.1",
		DefaultTags: []string{"kubernetes"},
	}

	// First reconcile: adds finalizer.
	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-tcp-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Second reconcile: creates hosts.
	result, err = r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "my-tcp-ir", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, []string{"tcp.example.com"}, addedHosts)

	// Verify annotation was set on the TCP object.
	var updated unstructured.Unstructured
	updated.SetGroupVersionKind(ingressRouteTCPGVK)
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "my-tcp-ir", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(slog.Default(), &updated)
	require.NoError(t, err)
	assert.Equal(t, "tcp-ingress-host-1", ids["tcp.example.com"])
}

// --- helpers ---

func ingressRouteScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()

	// Register the unstructured types for the fake client.
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "IngressRoute"},
		&unstructured.Unstructured{},
	)
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "IngressRouteList"},
		&unstructured.UnstructuredList{},
	)
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "IngressRouteTCP"},
		&unstructured.Unstructured{},
	)
	s.AddKnownTypeWithName(
		schema.GroupVersionKind{Group: "traefik.io", Version: "v1alpha1", Kind: "IngressRouteTCPList"},
		&unstructured.UnstructuredList{},
	)
	return s
}

func newIngressRoute(name, namespace string, routes []map[string]interface{}) *unstructured.Unstructured {
	routeInterfaces := make([]interface{}, len(routes))
	for i, r := range routes {
		routeInterfaces[i] = r
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "traefik.io/v1alpha1",
			"kind":       "IngressRoute",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"routes": routeInterfaces,
			},
		},
	}
	return obj
}

func newIngressRouteTCP(name, namespace string, routes []map[string]interface{}) *unstructured.Unstructured {
	routeInterfaces := make([]interface{}, len(routes))
	for i, r := range routes {
		routeInterfaces[i] = r
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "traefik.io/v1alpha1",
			"kind":       "IngressRouteTCP",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": namespace,
			},
			"spec": map[string]interface{}{
				"routes": routeInterfaces,
			},
		},
	}
	return obj
}
