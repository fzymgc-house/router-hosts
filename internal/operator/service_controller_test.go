package operator

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// newServiceReconciler builds a ServiceReconciler for tests, wired to k8sClient
// and hc, with DefaultTags matching the operator's real wiring in main.go.
func newServiceReconciler(t *testing.T, k8sClient client.Client, hc HostClient) *ServiceReconciler {
	t.Helper()
	return &ServiceReconciler{
		Client:      k8sClient,
		HostClient:  hc,
		Log:         slog.Default(),
		DefaultTags: []string{"kubernetes"},
	}
}

// newTrackedService builds a Service fixture with the given type and
// annotations. It carries no finalizer and no status; callers add those as
// needed for the scenario under test.
func newTrackedService(name, namespace string, svcType corev1.ServiceType, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type: svcType,
		},
	}
}

func TestServiceEnabledPredicate(t *testing.T) {
	pred := serviceEnabledPredicate()

	enabled := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation: "true",
	})
	enabledFalse := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation: "false",
	})
	disabled := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)

	t.Run("create_enabled", func(t *testing.T) {
		assert.True(t, pred.Create(event.CreateEvent{Object: enabled}))
	})
	t.Run("create_disabled", func(t *testing.T) {
		assert.False(t, pred.Create(event.CreateEvent{Object: disabled}))
	})
	t.Run("create_enabled_false", func(t *testing.T) {
		assert.False(t, pred.Create(event.CreateEvent{Object: enabledFalse}))
	})
	t.Run("update_annotation_added", func(t *testing.T) {
		assert.True(t, pred.Update(event.UpdateEvent{ObjectOld: disabled, ObjectNew: enabled}))
	})
	t.Run("update_annotation_removed", func(t *testing.T) {
		// D-05 hazard: a predicate that inspects only the new object returns
		// false here. This must observe the old object too.
		assert.True(t, pred.Update(event.UpdateEvent{ObjectOld: enabled, ObjectNew: disabled}))
	})
	t.Run("update_both_disabled", func(t *testing.T) {
		assert.False(t, pred.Update(event.UpdateEvent{ObjectOld: disabled, ObjectNew: disabled}))
	})
	t.Run("delete_enabled", func(t *testing.T) {
		assert.True(t, pred.Delete(event.DeleteEvent{Object: enabled}))
	})
}

func TestReconcileService_AddsFinalizerAndReturns(t *testing.T) {
	s := testScheme(t)
	svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation:  "true",
		serviceHostnameAnnotation: "web.example.com",
	})

	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(svc).Build()

	var addHostCalled bool
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			addHostCalled = true
			return "should-not-be-called", nil
		},
	}

	r := newServiceReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.False(t, addHostCalled, "the finalizer-add reconcile must not sync hosts")

	var updated corev1.Service
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
	assert.Contains(t, updated.Finalizers, serviceCleanupFinalizer)
}

func TestReconcileService_LoadBalancerCreatesHost(t *testing.T) {
	s := testScheme(t)
	svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation:  "true",
		serviceHostnameAnnotation: "web.example.com",
	})
	svc.Finalizers = []string{serviceCleanupFinalizer}
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{IP: "10.0.0.7"},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(svc).Build()

	var addHostCalls int
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addHostCalls++
			assert.Equal(t, "10.0.0.7", ip)
			assert.Equal(t, "web.example.com", hostname)
			assert.Equal(t, "k8s-service:default/web", comment)
			assert.Nil(t, aliases)
			assert.ElementsMatch(t, []string{"kubernetes", "service"}, tags)
			return "svc-host-1", nil
		},
	}

	r := newServiceReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, 1, addHostCalls)

	var updated corev1.Service
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(slog.Default(), &updated)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"web.example.com": "svc-host-1"}, ids)
}
