package operator

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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
	t.Run("update_deletion_of_opted_out_but_finalized", func(t *testing.T) {
		// CR-01: a Service that opted out (annotation removed) before being
		// deleted still carries serviceCleanupFinalizer, since only
		// reconcileDelete removes it. kubectl delete then produces an Update
		// where NEITHER old nor new carries `enabled: "true"` — this must
		// still be admitted, or Reconcile never runs and the finalizer
		// wedges the object in Terminating forever.
		optedOutFinalized := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		optedOutFinalized.Finalizers = []string{serviceCleanupFinalizer}

		deleting := newTrackedService("web", "default", corev1.ServiceTypeLoadBalancer, nil)
		deleting.Finalizers = []string{serviceCleanupFinalizer}
		now := metav1.Now()
		deleting.DeletionTimestamp = &now

		assert.True(t, pred.Update(event.UpdateEvent{ObjectOld: optedOutFinalized, ObjectNew: deleting}))
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

// TestSyncService_StopManaging covers the four D-17 "stop managing this"
// transitions: each seeds a Service already tracking
// {"web.example.com": "id-1"} and asserts the stale-cleanup pass deletes it
// through the SAME code path, regardless of which signal caused the desired
// set to become empty (or to point at a different hostname).
func TestSyncService_StopManaging(t *testing.T) {
	t.Run("enabled_flipped_false", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation:  "false",
			serviceHostnameAnnotation: "web.example.com",
		})
		require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"web.example.com": "id-1"}))

		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

		var deleted []string
		mock := &mockHostClient{
			addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
				t.Fatal("AddHost must not be called when opting out")
				return "", nil
			},
			deleteHostFn: func(_ context.Context, id string) error {
				deleted = append(deleted, id)
				return nil
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, []string{"id-1"}, deleted)

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		ids, err := getHostIDsAnnotation(slog.Default(), &updated)
		require.NoError(t, err)
		assert.Empty(t, ids)
	})

	t.Run("type_changed_to_clusterip", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeClusterIP, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "web.example.com",
		})
		require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"web.example.com": "id-1"}))

		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

		var deleted []string
		rec := events.NewFakeRecorder(10)
		mock := &mockHostClient{
			addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
				t.Fatal("AddHost must not be called for an unsupported type")
				return "", nil
			},
			deleteHostFn: func(_ context.Context, id string) error {
				deleted = append(deleted, id)
				return nil
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)
		r.Recorder = rec

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, []string{"id-1"}, deleted)

		select {
		case msg := <-rec.Events:
			assert.Contains(t, msg, "Warning InvalidServiceType ")
		default:
			t.Fatal("expected an InvalidServiceType event")
		}

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		ids, err := getHostIDsAnnotation(slog.Default(), &updated)
		require.NoError(t, err)
		assert.Empty(t, ids)
	})

	t.Run("hostname_annotation_changed", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: "api.example.com",
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.9"}}
		require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"web.example.com": "id-1"}))

		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

		var deleted []string
		var addHostCalls int
		mock := &mockHostClient{
			addHostFn: func(_ context.Context, ip, hostname, _ string, _, _ []string) (string, error) {
				addHostCalls++
				assert.Equal(t, "10.0.0.9", ip)
				assert.Equal(t, "api.example.com", hostname)
				return "id-2", nil
			},
			deleteHostFn: func(_ context.Context, id string) error {
				deleted = append(deleted, id)
				return nil
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, 1, addHostCalls)
		assert.Equal(t, []string{"id-1"}, deleted)

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		ids, err := getHostIDsAnnotation(slog.Default(), &updated)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"api.example.com": "id-2"}, ids)
	})

	t.Run("enabled_annotation_removed", func(t *testing.T) {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceHostnameAnnotation: "web.example.com",
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
		require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"web.example.com": "id-1"}))

		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

		var deleted []string
		mock := &mockHostClient{
			addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
				t.Fatal("AddHost must not be called when the opt-in annotation is absent")
				return "", nil
			},
			deleteHostFn: func(_ context.Context, id string) error {
				deleted = append(deleted, id)
				return nil
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, []string{"id-1"}, deleted)

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		ids, err := getHostIDsAnnotation(slog.Default(), &updated)
		require.NoError(t, err)
		assert.Empty(t, ids)
	})
}

// TestSyncService_SkipsUpdateWhenUnchanged is the D-19 no-op-write guard: a
// second reconcile with an unchanged spec must not bump the Service's
// ResourceVersion, even though UpdateHost may still be called every time.
func TestSyncService_SkipsUpdateWhenUnchanged(t *testing.T) {
	svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation:  "true",
		serviceHostnameAnnotation: "web.example.com",
	})
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
	require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"web.example.com": "id-1"}))

	k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

	mock := &mockHostClient{
		getHostFn: func(_ context.Context, id string) (*HostEntry, error) {
			return &HostEntry{ID: id, Version: "v1"}, nil
		},
	}
	r := newServiceReconciler(t, k8sClient, mock)
	ctx := context.Background()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}}

	_, err := r.Reconcile(ctx, req)
	require.NoError(t, err)

	var first corev1.Service
	require.NoError(t, k8sClient.Get(ctx, req.NamespacedName, &first))
	rv := first.ResourceVersion
	require.NotEmpty(t, rv)

	_, err = r.Reconcile(ctx, req)
	require.NoError(t, err)

	var second corev1.Service
	require.NoError(t, k8sClient.Get(ctx, req.NamespacedName, &second))
	assert.Equal(t, rv, second.ResourceVersion, "no object Update should be issued when the annotation is unchanged")
}

// TestSyncService_CorruptAnnotationRequeues is the D-18 fail-closed gate: an
// unparseable host-ids annotation must stop the reconcile before any
// HostClient call, never be treated as empty.
func TestSyncService_CorruptAnnotationRequeues(t *testing.T) {
	svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation:  "true",
		serviceHostnameAnnotation: "web.example.com",
		hostIDsAnnotation:         "{not json",
	})
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}

	k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

	var calls int
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			calls++
			return "unexpected", nil
		},
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			calls++
			return nil
		},
		deleteHostFn: func(_ context.Context, _ string) error {
			calls++
			return nil
		},
	}
	r := newServiceReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
	require.Error(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayShort}, result)
	assert.Zero(t, calls)
}

// TestSyncService_PartialFailureRetainsIDs exercises the D-18 retention rule
// through the stale-cleanup pass: a hostname the Service no longer declares
// fails to delete, so its ID must stay in the annotation rather than being
// silently dropped, alongside the newly created entry for the now-desired
// hostname.
func TestSyncService_PartialFailureRetainsIDs(t *testing.T) {
	svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
		serviceEnabledAnnotation:  "true",
		serviceHostnameAnnotation: "web.example.com",
	})
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.0.7"}}
	require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"old.example.com": "id-old"}))

	k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "id-new", nil
		},
		deleteHostFn: func(_ context.Context, _ string) error {
			return errors.New("boom")
		},
	}
	r := newServiceReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayLong}, result)

	var updated corev1.Service
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(slog.Default(), &updated)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"old.example.com": "id-old", "web.example.com": "id-new"}, ids)
}

// TestSyncService_AdoptionRefused is the T-08-01/D-21 dual-provenance gate:
// a conflicting entry at the Service's own (ip, hostname) is adopted only
// when BOTH its comment and its tags identify it as this Service's own
// prior entry. Uses newFakeHostStore (gateway_controller_test.go) rather
// than a bare mockHostClient literal — a mock that hands out a fresh ID per
// AddHost models a server that accepts duplicate (ip, hostname) pairs,
// which internal/server/commands.go rejects, so it would never reach the
// adoption branch at all.
func TestSyncService_AdoptionRefused(t *testing.T) {
	const ip = "10.0.0.5"
	const hostname = "web.example.com"
	const wantComment = "k8s-service:default/web"

	newCandidate := func() *corev1.Service {
		svc := newReadySvc("web", corev1.ServiceTypeLoadBalancer, map[string]string{
			serviceEnabledAnnotation:  "true",
			serviceHostnameAnnotation: hostname,
		})
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: ip}}
		return svc
	}

	t.Run("foreign_comment", func(t *testing.T) {
		store := newFakeHostStore()
		store.seed("foreign-id", ip, hostname, "k8s-ingress:default/other", []string{"kubernetes", "service"})

		svc := newCandidate()
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		r := newServiceReconciler(t, k8sClient, store.client())

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		assert.Contains(t, store.entries, store.key(ip, hostname), "the seeded entry must still be present")
		assert.Empty(t, store.deleted)

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		ids, err := getHostIDsAnnotation(slog.Default(), &updated)
		require.NoError(t, err)
		assert.NotContains(t, ids, hostname, "the foreign ID must never enter this Service's annotation")
	})

	t.Run("foreign_tags", func(t *testing.T) {
		store := newFakeHostStore()
		store.seed("foreign-id", ip, hostname, wantComment, []string{"kubernetes", "traefik", "ingress"})

		svc := newCandidate()
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		r := newServiceReconciler(t, k8sClient, store.client())

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		assert.Contains(t, store.entries, store.key(ip, hostname), "the seeded entry must still be present")
		assert.Empty(t, store.deleted)

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		ids, err := getHostIDsAnnotation(slog.Default(), &updated)
		require.NoError(t, err)
		assert.NotContains(t, ids, hostname, "the foreign ID must never enter this Service's annotation")
	})

	t.Run("own_entry_adopted", func(t *testing.T) {
		store := newFakeHostStore()
		store.seed("own-id", ip, hostname, wantComment, []string{"kubernetes", "service"})

		svc := newCandidate()
		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()
		r := newServiceReconciler(t, k8sClient, store.client())

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		ids, err := getHostIDsAnnotation(slog.Default(), &updated)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{hostname: "own-id"}, ids)
	})
}

// TestHasServiceProvenance is table-driven: only a tag set containing
// "service" identifies an entry as Service-controller-owned. "kubernetes"
// alone is not discriminating — it comes from the shared DefaultTags.
func TestHasServiceProvenance(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		want bool
	}{
		{"service_tag_present", []string{"kubernetes", "service"}, true},
		{"ingress_tags", []string{"kubernetes", "traefik", "ingress"}, false},
		{"gateway_tags", []string{"kubernetes", "gateway", "httproute"}, false},
		{"kubernetes_only", []string{"kubernetes"}, false},
		{"nil_tags", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasServiceProvenance(tt.tags))
		})
	}
}

// newDeletingSvc builds a Service fixture carrying a non-nil
// DeletionTimestamp, so Reconcile routes straight to reconcileDelete. The
// fake client refuses to seed an object with a DeletionTimestamp and no
// finalizers at all (mirroring the real API server, which would already
// have removed such an object) — when withFinalizer is false, a foreign
// finalizer this reconciler does not own is seeded instead, so
// ContainsFinalizer(serviceCleanupFinalizer) is still false and
// reconcileDelete's no-op guard is genuinely exercised.
func newDeletingSvc(name string, annotations map[string]string, withFinalizer bool) *corev1.Service {
	svc := newTrackedService(name, "default", corev1.ServiceTypeLoadBalancer, annotations)
	if withFinalizer {
		svc.Finalizers = []string{serviceCleanupFinalizer}
	} else {
		svc.Finalizers = []string{"other.example/finalizer"}
	}
	now := metav1.Now()
	svc.DeletionTimestamp = &now
	return svc
}

// TestReconcileService_DeleteRemovesHostsAndFinalizer covers the D-16/D-18
// reconcileDelete cleanup: every tracked entry is deleted before the
// cleanup finalizer is released, a delete failure retains the remaining IDs
// and requeues with the finalizer intact, a Service without the finalizer
// is a no-op, and a corrupt annotation never releases the finalizer.
func TestReconcileService_DeleteRemovesHostsAndFinalizer(t *testing.T) {
	t.Run("deletes_tracked_entries_and_releases_finalizer", func(t *testing.T) {
		svc := newDeletingSvc("web", nil, true)
		require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"web.example.com": "id-1"}))

		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

		var deleted []string
		mock := &mockHostClient{
			deleteHostFn: func(_ context.Context, id string) error {
				deleted = append(deleted, id)
				return nil
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)

		_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, []string{"id-1"}, deleted)

		var updated corev1.Service
		getErr := k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated)
		if getErr == nil {
			assert.False(t, controllerutil.ContainsFinalizer(&updated, serviceCleanupFinalizer))
		} else {
			assert.True(t, apierrors.IsNotFound(getErr))
		}
	})

	t.Run("retains_ids_and_requeues_on_delete_failure", func(t *testing.T) {
		svc := newDeletingSvc("web", nil, true)
		require.NoError(t, setHostIDsAnnotation(svc, map[string]string{"web.example.com": "id-1"}))

		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

		mock := &mockHostClient{
			deleteHostFn: func(_ context.Context, _ string) error {
				return errors.New("boom")
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)

		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayShort}, result)

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		assert.True(t, controllerutil.ContainsFinalizer(&updated, serviceCleanupFinalizer))
		ids, err := getHostIDsAnnotation(slog.Default(), &updated)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"web.example.com": "id-1"}, ids)
	})

	t.Run("no_finalizer_is_a_noop", func(t *testing.T) {
		svc := newDeletingSvc("web", nil, false)

		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

		var calls int
		mock := &mockHostClient{
			deleteHostFn: func(_ context.Context, _ string) error {
				calls++
				return nil
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)

		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)
		assert.Zero(t, calls)
	})

	t.Run("corrupt_annotation_requeues_without_deleting", func(t *testing.T) {
		svc := newDeletingSvc("web", map[string]string{hostIDsAnnotation: "{not json"}, true)

		k8sClient := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(svc).Build()

		var calls int
		mock := &mockHostClient{
			deleteHostFn: func(_ context.Context, _ string) error {
				calls++
				return nil
			},
		}
		r := newServiceReconciler(t, k8sClient, mock)

		result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "web", Namespace: "default"}})
		require.Error(t, err)
		assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayShort}, result)
		assert.Zero(t, calls)

		var updated corev1.Service
		require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "web", Namespace: "default"}, &updated))
		assert.True(t, controllerutil.ContainsFinalizer(&updated, serviceCleanupFinalizer))
	})
}
