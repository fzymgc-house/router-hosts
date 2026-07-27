package operator

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
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

func TestResolveServiceIP(t *testing.T) {
	t.Run("loadbalancer_first_ip", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "10.0.0.7", ip)
		assert.False(t, waiting)
	})

	t.Run("loadbalancer_hostname_only_skipped", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{Hostname: "elb.aws.example"}}
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "", ip)
		assert.True(t, waiting)
	})

	t.Run("loadbalancer_hostname_then_ip", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{Hostname: "elb.aws.example"},
			{IP: "10.0.0.9"},
		}
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "10.0.0.9", ip)
		assert.False(t, waiting)
	})

	t.Run("loadbalancer_entry_with_both_fields", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{IP: "10.0.0.3", Hostname: "elb.aws.example"},
		}
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "10.0.0.3", ip)
		assert.False(t, waiting)
	})

	t.Run("loadbalancer_empty_status", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "", ip)
		assert.True(t, waiting)
	})

	t.Run("nodeport_with_annotation", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeNodePort, map[string]string{
			serviceIPAddressAnnotation: "192.168.1.50",
		})
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "192.168.1.50", ip)
		assert.False(t, waiting)
	})

	t.Run("nodeport_without_annotation", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeNodePort, nil)
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "", ip)
		assert.False(t, waiting)
	})

	t.Run("annotation_overrides_loadbalancer_status", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceIPAddressAnnotation: "192.168.1.50",
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "192.168.1.50", ip)
		assert.False(t, waiting)
	})

	t.Run("clusterip_unsupported", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeClusterIP, map[string]string{
			serviceIPAddressAnnotation: "192.168.1.50",
		})
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "", ip)
		assert.False(t, waiting)
	})

	t.Run("externalname_unsupported", func(t *testing.T) {
		svc := newTrackedService("web", "default", corev1.ServiceTypeExternalName, nil)
		ip, waiting := resolveServiceIP(svc)
		assert.Equal(t, "", ip)
		assert.False(t, waiting)
	})
}

func TestServiceDesiredHostname(t *testing.T) {
	t.Run("missing_annotation", func(t *testing.T) {
		log := slog.New(&recordingHandler{})
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		assert.Equal(t, "", serviceDesiredHostname(log, svc))
	})

	t.Run("empty_annotation", func(t *testing.T) {
		log := slog.New(&recordingHandler{})
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnameAnnotation: "",
		})
		assert.Equal(t, "", serviceDesiredHostname(log, svc))
	})

	t.Run("whitespace_trimmed", func(t *testing.T) {
		log := slog.New(&recordingHandler{})
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnameAnnotation: "  web.example.com  ",
		})
		assert.Equal(t, "web.example.com", serviceDesiredHostname(log, svc))
	})

	t.Run("valid_fqdn", func(t *testing.T) {
		h := &recordingHandler{}
		log := slog.New(h)
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnameAnnotation: "web.example.com",
		})
		assert.Equal(t, "web.example.com", serviceDesiredHostname(log, svc))
		assert.False(t, h.hasWarnRecordContaining("web.example.com"))
	})

	t.Run("invalid_dropped", func(t *testing.T) {
		h := &recordingHandler{}
		log := slog.New(h)
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnameAnnotation: "-bad.example.com",
		})
		assert.Equal(t, "", serviceDesiredHostname(log, svc))
		assert.True(t, h.hasWarnRecordContaining("-bad.example.com"))
	})

	t.Run("dotless_accepted_with_warning", func(t *testing.T) {
		h := &recordingHandler{}
		log := slog.New(h)
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnameAnnotation: "router",
		})
		assert.Equal(t, "router", serviceDesiredHostname(log, svc))
		assert.True(t, h.hasWarnRecordContaining("router"))
	})
}

func TestServiceDesiredAliases(t *testing.T) {
	const canonical = "web.example.com"

	t.Run("absent_annotation_returns_empty_non_nil", func(t *testing.T) {
		log := slog.New(&recordingHandler{})
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Empty(t, aliases)
	})

	t.Run("empty_annotation_returns_empty_non_nil", func(t *testing.T) {
		log := slog.New(&recordingHandler{})
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceAliasesAnnotation: "",
		})
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Empty(t, aliases)
	})

	t.Run("single_alias", func(t *testing.T) {
		log := slog.New(&recordingHandler{})
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceAliasesAnnotation: "www.example.com",
		})
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Equal(t, []string{"www.example.com"}, aliases)
	})

	t.Run("comma_separated_trimmed", func(t *testing.T) {
		log := slog.New(&recordingHandler{})
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceAliasesAnnotation: " www.example.com , api.example.com ",
		})
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Equal(t, []string{"www.example.com", "api.example.com"}, aliases)
	})

	t.Run("empty_segments_ignored", func(t *testing.T) {
		log := slog.New(&recordingHandler{})
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceAliasesAnnotation: "www.example.com,,api.example.com,",
		})
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Equal(t, []string{"www.example.com", "api.example.com"}, aliases)
	})

	t.Run("invalid_alias_dropped", func(t *testing.T) {
		h := &recordingHandler{}
		log := slog.New(h)
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceAliasesAnnotation: "www.example.com,-bad.example.com",
		})
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Equal(t, []string{"www.example.com"}, aliases)
		assert.True(t, h.hasWarnRecordContaining("-bad.example.com"))
	})

	t.Run("ip_address_alias_dropped", func(t *testing.T) {
		h := &recordingHandler{}
		log := slog.New(h)
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceAliasesAnnotation: "www.example.com,10.0.0.5",
		})
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Equal(t, []string{"www.example.com"}, aliases)
		assert.True(t, h.hasWarnRecordContaining("10.0.0.5"))
	})

	t.Run("alias_matching_hostname_dropped", func(t *testing.T) {
		h := &recordingHandler{}
		log := slog.New(h)
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceAliasesAnnotation: "web.example.com,www.example.com",
		})
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Equal(t, []string{"www.example.com"}, aliases)
		assert.True(t, h.hasWarnRecordContaining("web.example.com"))
	})

	t.Run("duplicate_alias_deduped", func(t *testing.T) {
		h := &recordingHandler{}
		log := slog.New(h)
		svc := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceAliasesAnnotation: "www.example.com,WWW.example.com",
		})
		aliases := serviceDesiredAliases(log, svc, canonical)
		assert.NotNil(t, aliases)
		assert.Equal(t, []string{"www.example.com"}, aliases)
		assert.True(t, h.hasWarnRecordContaining("WWW.example.com"))
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
			assert.NotNil(t, aliases)
			assert.Empty(t, aliases)
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

// newReadySvc builds a Service fixture that already carries the cleanup
// finalizer, so Reconcile proceeds straight to syncService instead of
// stopping after the finalizer-add early return.
func newReadySvc(name string, svcType corev1.ServiceType, annotations map[string]string) *corev1.Service {
	svc := newTrackedService(name, "default", svcType, annotations)
	svc.Finalizers = []string{serviceCleanupFinalizer}
	return svc
}

// noAddHostMock fails the test if AddHost is ever called; the four
// failure/waiting reasons under test must all create nothing.
func noAddHostMock(t *testing.T) *mockHostClient {
	t.Helper()
	return &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			t.Fatal("AddHost must not be called for this fixture")
			return "", nil
		},
	}
}

func TestSyncService_Events(t *testing.T) {
	t.Run("InvalidServiceType", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeClusterIP, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "web.example.com",
		})
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		rec := events.NewFakeRecorder(10)
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))
		r.Recorder = rec

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		select {
		case msg := <-rec.Events:
			assert.Contains(t, msg, "Warning InvalidServiceType ")
		default:
			t.Fatal("expected an event")
		}
	})

	t.Run("MissingHostname", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation: "true",
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		rec := events.NewFakeRecorder(10)
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))
		r.Recorder = rec

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		select {
		case msg := <-rec.Events:
			assert.Contains(t, msg, "Warning MissingHostname ")
		default:
			t.Fatal("expected an event")
		}
	})

	t.Run("MissingHostname_when_invalid", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "-bad.example.com",
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		rec := events.NewFakeRecorder(10)
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))
		r.Recorder = rec

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		select {
		case msg := <-rec.Events:
			assert.Contains(t, msg, "Warning MissingHostname ")
		default:
			t.Fatal("expected an event")
		}
	})

	t.Run("MissingIPAddress", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeNodePort, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "web.example.com",
		})
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		rec := events.NewFakeRecorder(10)
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))
		r.Recorder = rec

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		select {
		case msg := <-rec.Events:
			assert.Contains(t, msg, "Warning MissingIPAddress ")
		default:
			t.Fatal("expected an event")
		}
	})

	t.Run("PendingLoadBalancer", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "web.example.com",
		})
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		rec := events.NewFakeRecorder(10)
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))
		r.Recorder = rec

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		select {
		case msg := <-rec.Events:
			assert.Contains(t, msg, "Normal PendingLoadBalancer ")
		default:
			t.Fatal("expected an event")
		}
	})

	t.Run("no_success_event_on_create", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "web.example.com",
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		rec := events.NewFakeRecorder(10)
		mock := &mockHostClient{
			addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
				return "svc-host-1", nil
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)
		r.Recorder = rec

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		select {
		case msg := <-rec.Events:
			t.Fatalf("expected no event on the success path, got %q", msg)
		default:
		}
	})

	t.Run("nil_recorder_is_safe", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation: "true",
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))
		require.Nil(t, r.Recorder)

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
	})
}

func TestSyncService_TerminalConditionsDoNotRequeue(t *testing.T) {
	t.Run("invalid_service_type", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeClusterIP, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "web.example.com",
		})
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))

		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})

	t.Run("missing_hostname", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation: "true",
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))

		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})

	t.Run("missing_ip_address", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeNodePort, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "web.example.com",
		})
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))

		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
	})

	t.Run("pending_load_balancer_requeues_short", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "web.example.com",
		})
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		r := newServiceReconciler(t, k8sClient, noAddHostMock(t))

		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, requeueDelayShort, result.RequeueAfter)
	})
}

// TestSyncService_AliasesClearedSendsEmptySlice is the Pitfall 2 regression
// guard: a Service already tracked with aliases on the server, but no
// aliases annotation on the object, must send UpdateHost a non-nil empty
// slice — never nil, which grpcHostClient.UpdateHost treats as "leave
// untouched" and would leak the stale alias forever.
func TestSyncService_AliasesClearedSendsEmptySlice(t *testing.T) {
	svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation:  "true",
		serviceHostnameAnnotation: "web.example.com",
	})
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
	require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"web.example.com": "id-1"}))

	k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

	var updateCalls int
	var captured []string
	mock := &mockHostClient{
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{ID: id, Aliases: []string{"www.example.com"}, Version: "v1"}, nil
		},
		updateHostFn: func(_ context.Context, _, _, _, _ string, aliases, _ []string, _ string) error {
			updateCalls++
			captured = aliases
			return nil
		},
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			t.Fatal("AddHost must not be called when the hostname is already tracked")
			return "", nil
		},
	}
	r := newServiceReconciler(t, k8sClient, mock)

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
	require.NoError(t, err)
	assert.Equal(t, 1, updateCalls)
	assert.NotNil(t, captured)
	assert.Empty(t, captured)
}

// TestSyncService_AliasesSentOnCreate verifies a fresh Service's aliases
// annotation is threaded through to AddHost in order.
func TestSyncService_AliasesSentOnCreate(t *testing.T) {
	svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation:  "true",
		serviceHostnameAnnotation: "web.example.com",
		serviceAliasesAnnotation:  "www.example.com,api.example.com",
	})
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}

	k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

	var captured []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, aliases, _ []string) (string, error) {
			captured = aliases
			return "svc-host-1", nil
		},
	}
	r := newServiceReconciler(t, k8sClient, mock)

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"www.example.com", "api.example.com"}, captured)
}

// TestSyncService_UpdatePath exercises syncServiceHost's read-before-write
// fail-closed guard directly (D-18, D-19).
func TestSyncService_UpdatePath(t *testing.T) {
	t.Run("passes_version_from_get", func(t *testing.T) {
		var gotVersion string
		mock := &mockHostClient{
			getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
				return &HostEntry{ID: id, Version: "v7"}, nil
			},
			updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, version string) error {
				gotVersion = version
				return nil
			},
		}
		r := newServiceReconciler(t, fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), mock)

		id, err := r.syncServiceHost(context.Background(), slog.Default(), "id-1", "10.0.0.7", "web.example.com",
			"k8s-service:default/web", []string{}, []string{"kubernetes", "service"})
		require.NoError(t, err)
		assert.Equal(t, "id-1", id)
		assert.Equal(t, "v7", gotVersion)
	})

	t.Run("recreates_when_get_reports_not_found", func(t *testing.T) {
		var addHostCalls int
		mock := &mockHostClient{
			getHostFn: func(_ context.Context, _ string) (*HostEntry, error) {
				return nil, ErrHostNotFound
			},
			updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
				t.Fatal("UpdateHost must not be called when the entry vanished")
				return nil
			},
			addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
				addHostCalls++
				return "new-id", nil
			},
		}
		r := newServiceReconciler(t, fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), mock)

		id, err := r.syncServiceHost(context.Background(), slog.Default(), "stale-id", "10.0.0.7", "web.example.com",
			"k8s-service:default/web", []string{}, []string{"kubernetes", "service"})
		require.NoError(t, err)
		assert.Equal(t, 1, addHostCalls)
		assert.Equal(t, "new-id", id)
	})

	t.Run("fails_closed_on_read_error", func(t *testing.T) {
		mock := &mockHostClient{
			getHostFn: func(_ context.Context, _ string) (*HostEntry, error) {
				return nil, errors.New("boom")
			},
			updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
				t.Fatal("UpdateHost must not be called on a read error")
				return nil
			},
		}
		r := newServiceReconciler(t, fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), mock)

		id, err := r.syncServiceHost(context.Background(), slog.Default(), "id-1", "10.0.0.7", "web.example.com",
			"k8s-service:default/web", []string{}, []string{"kubernetes", "service"})
		require.Error(t, err)
		assert.Equal(t, "id-1", id, "the previously tracked ID must be retained on a fail-closed error")
	})

	t.Run("fails_closed_on_empty_entry", func(t *testing.T) {
		mock := &mockHostClient{
			getHostFn: func(_ context.Context, _ string) (*HostEntry, error) {
				return nil, nil
			},
			updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
				t.Fatal("UpdateHost must not be called on an empty entry")
				return nil
			},
		}
		r := newServiceReconciler(t, fake.NewClientBuilder().WithScheme(testScheme(t)).Build(), mock)

		_, err := r.syncServiceHost(context.Background(), slog.Default(), "id-1", "10.0.0.7", "web.example.com",
			"k8s-service:default/web", []string{}, []string{"kubernetes", "service"})
		require.Error(t, err)
	})
}
