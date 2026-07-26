package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// recordingHandler is a minimal slog.Handler that captures every record
// emitted through it, used to assert on warn-level log output without
// depending on a specific logging library beyond the standard slog package.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// hasWarnRecordContaining reports whether any captured warn-level record's
// message or attributes mention needle.
func (h *recordingHandler) hasWarnRecordContaining(needle string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Level != slog.LevelWarn {
			continue
		}
		if strings.Contains(r.Message, needle) {
			return true
		}
		found := false
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Value.String(), needle) {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// gatewayScheme builds a scheme registering only the Gateway API v1 kinds
// (HTTPRoute, GRPCRoute, TLSRoute, Gateway). Do not reuse ingressRouteScheme,
// which registers unrelated Traefik unstructured GVKs.
func gatewayScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, gatewayv1.Install(s))
	return s
}

func newHTTPRouteReconciler(t *testing.T, k8sClient client.Client, hc HostClient) *GatewayRouteReconciler {
	t.Helper()
	return &GatewayRouteReconciler{
		Client:      k8sClient,
		HostClient:  hc,
		Log:         slog.Default(),
		KindName:    "httproute",
		newObject:   func() client.Object { return &gatewayv1.HTTPRoute{} },
		newList:     func() client.ObjectList { return &gatewayv1.HTTPRouteList{} },
		DefaultIP:   "0.0.0.0",
		DefaultTags: []string{"kubernetes"},
	}
}

func TestHostnamesOf_HTTPRoute(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"a.example.com"},
		},
	}
	assert.Equal(t, []string{"a.example.com"}, hostnamesOf(route))
	assert.Nil(t, hostnamesOf(&gatewayv1.Gateway{}))
}

func TestResolveIP_FromParentGateway(t *testing.T) {
	ipType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "infra"},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{
				{Type: &ipType, Value: "10.1.2.3"},
			},
		},
	}

	parentNS := gatewayv1.Namespace("infra")
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: "default"},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw", Namespace: &parentNS},
				},
			},
		},
	}

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gw).Build()

	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})
	ip := r.resolveIP(context.Background(), r.Log, route)
	assert.Equal(t, "10.1.2.3", ip)
}

// newGateway builds a Gateway with the given namespace, name, and status
// addresses, for resolveIP test fixtures.
func newGateway(namespace, name string, addrs ...gatewayv1.GatewayStatusAddress) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Status:     gatewayv1.GatewayStatus{Addresses: addrs},
	}
}

// newRouteWithParentRefs builds an HTTPRoute in the given namespace with the
// given parentRefs, for resolveIP test fixtures.
func newRouteWithParentRefs(namespace string, refs ...gatewayv1.ParentReference) *gatewayv1.HTTPRoute {
	return &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route1", Namespace: namespace},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: refs},
		},
	}
}

func ipAddr(v string) gatewayv1.GatewayStatusAddress {
	t := gatewayv1.IPAddressType
	return gatewayv1.GatewayStatusAddress{Type: &t, Value: v}
}

func hostnameAddr(v string) gatewayv1.GatewayStatusAddress {
	t := gatewayv1.HostnameAddressType
	return gatewayv1.GatewayStatusAddress{Type: &t, Value: v}
}

func nsPtr(ns string) *gatewayv1.Namespace {
	n := gatewayv1.Namespace(ns)
	return &n
}

func TestResolveIP_SkipsHostnameTypeAddress(t *testing.T) {
	gw := newGateway("default", "gw", hostnameAddr("lb.example.com"))
	route := newRouteWithParentRefs("default", gatewayv1.ParentReference{Name: "gw"})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gw).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})
	r.DefaultIP = "0.0.0.0"

	assert.Equal(t, "0.0.0.0", r.resolveIP(context.Background(), r.Log, route))
}

func TestResolveIP_PrefersFirstIPAddressWithinOneGateway(t *testing.T) {
	gw := newGateway("default", "gw", hostnameAddr("lb.example.com"), ipAddr("10.1.2.3"), ipAddr("10.9.9.9"))
	route := newRouteWithParentRefs("default", gatewayv1.ParentReference{Name: "gw"})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gw).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})

	assert.Equal(t, "10.1.2.3", r.resolveIP(context.Background(), r.Log, route))
}

func TestResolveIP_MultipleParentsFirstWins(t *testing.T) {
	gwA := newGateway("default", "gw-a", ipAddr("10.0.0.1"))
	gwB := newGateway("default", "gw-b", ipAddr("10.0.0.2"))

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gwA, gwB).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})

	route := newRouteWithParentRefs("default",
		gatewayv1.ParentReference{Name: "gw-a"}, gatewayv1.ParentReference{Name: "gw-b"})
	for i := 0; i < 10; i++ {
		assert.Equal(t, "10.0.0.1", r.resolveIP(context.Background(), r.Log, route))
	}

	reversed := newRouteWithParentRefs("default",
		gatewayv1.ParentReference{Name: "gw-b"}, gatewayv1.ParentReference{Name: "gw-a"})
	assert.Equal(t, "10.0.0.2", r.resolveIP(context.Background(), r.Log, reversed))
}

func TestResolveIP_SkipsEarlierParentWithoutIP(t *testing.T) {
	gwHostnameOnly := newGateway("default", "gw-hostname-only", hostnameAddr("lb.example.com"))
	gwWithIP := newGateway("default", "gw-with-ip", ipAddr("10.5.5.5"))

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gwHostnameOnly, gwWithIP).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})

	route := newRouteWithParentRefs("default",
		gatewayv1.ParentReference{Name: "gw-hostname-only"}, gatewayv1.ParentReference{Name: "gw-with-ip"})

	assert.Equal(t, "10.5.5.5", r.resolveIP(context.Background(), r.Log, route))
}

func TestResolveIP_DefaultsParentNamespaceToRoute(t *testing.T) {
	gwApps := newGateway("apps", "gw", ipAddr("10.1.1.1"))
	gwInfra := newGateway("infra", "gw", ipAddr("10.2.2.2"))

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gwApps, gwInfra).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})

	route := newRouteWithParentRefs("apps", gatewayv1.ParentReference{Name: "gw"})

	assert.Equal(t, "10.1.1.1", r.resolveIP(context.Background(), r.Log, route))
}

func TestResolveIP_HonorsExplicitParentNamespace(t *testing.T) {
	gwApps := newGateway("apps", "gw", ipAddr("10.1.1.1"))
	gwInfra := newGateway("infra", "gw", ipAddr("10.2.2.2"))

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gwApps, gwInfra).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})

	route := newRouteWithParentRefs("apps", gatewayv1.ParentReference{Name: "gw", Namespace: nsPtr("infra")})

	assert.Equal(t, "10.2.2.2", r.resolveIP(context.Background(), r.Log, route))
}

func TestResolveIP_IgnoresEmptyAddressValue(t *testing.T) {
	gw := newGateway("default", "gw", ipAddr(""), ipAddr("10.3.3.3"))
	route := newRouteWithParentRefs("default", gatewayv1.ParentReference{Name: "gw"})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gw).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})

	assert.Equal(t, "10.3.3.3", r.resolveIP(context.Background(), r.Log, route))
}

func TestGatewayKindPresent_UsesRESTMapper(t *testing.T) {
	present := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"}
	absent := schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GRPCRoute"}

	mapper := apimeta.NewDefaultRESTMapper(nil)
	mapper.Add(present, apimeta.RESTScopeNamespace)

	assert.True(t, gatewayKindPresent(mapper, present))
	assert.False(t, gatewayKindPresent(mapper, absent))
}

func TestReconcile_HTTPRoute_CreatesHost(t *testing.T) {
	ipType := gatewayv1.IPAddressType
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "infra"},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{
				{Type: &ipType, Value: "10.1.2.3"},
			},
		},
	}

	parentNS := gatewayv1.Namespace("infra")
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "route1",
			Namespace:  "default",
			Finalizers: []string{gatewayCleanupFinalizer},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "gw", Namespace: &parentNS},
				},
			},
			Hostnames: []gatewayv1.Hostname{"app.example.com"},
		},
	}

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route, gw).Build()

	var addedHosts []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addedHosts = append(addedHosts, hostname)
			assert.Equal(t, "10.1.2.3", ip)
			assert.Equal(t, "k8s-gateway:default/route1", comment)
			assert.Nil(t, aliases)
			assert.Contains(t, tags, "kubernetes")
			assert.Contains(t, tags, "gateway")
			assert.Contains(t, tags, "httproute")
			return "gw-host-1", nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "route1", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, []string{"app.example.com"}, addedHosts)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(slog.Default(), &updated)
	require.NoError(t, err)
	assert.Equal(t, "gw-host-1", ids["app.example.com"])
}

func TestReconcile_HTTPRoute_AddsFinalizerAndReturns(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "route1",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"app.example.com"},
		},
	}

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var addHostCalled bool
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addHostCalled = true
			return "unexpected", nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "route1", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.False(t, addHostCalled)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	assert.Contains(t, updated.Finalizers, gatewayCleanupFinalizer)
}

func TestHostnamesOf_AllKinds(t *testing.T) {
	httpRoute := &gatewayv1.HTTPRoute{
		Spec: gatewayv1.HTTPRouteSpec{Hostnames: []gatewayv1.Hostname{"a.example.com"}},
	}
	grpcRoute := &gatewayv1.GRPCRoute{
		Spec: gatewayv1.GRPCRouteSpec{Hostnames: []gatewayv1.Hostname{"grpc.example.com"}},
	}
	tlsRoute := &gatewayv1.TLSRoute{
		Spec: gatewayv1.TLSRouteSpec{Hostnames: []gatewayv1.Hostname{"tls.example.com"}},
	}

	assert.Equal(t, []string{"a.example.com"}, hostnamesOf(httpRoute))
	assert.Equal(t, []string{"grpc.example.com"}, hostnamesOf(grpcRoute))
	assert.Equal(t, []string{"tls.example.com"}, hostnamesOf(tlsRoute))
	assert.Nil(t, hostnamesOf(&gatewayv1.Gateway{}))
}

func TestParentRefsOf_AllKinds(t *testing.T) {
	ref := gatewayv1.ParentReference{Name: "gw"}

	httpRoute := &gatewayv1.HTTPRoute{
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{ref}},
		},
	}
	grpcRoute := &gatewayv1.GRPCRoute{
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{ref}},
		},
	}
	tlsRoute := &gatewayv1.TLSRoute{
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{ref}},
		},
	}

	assert.Equal(t, []gatewayv1.ParentReference{ref}, parentRefsOf(httpRoute))
	assert.Equal(t, []gatewayv1.ParentReference{ref}, parentRefsOf(grpcRoute))
	assert.Equal(t, []gatewayv1.ParentReference{ref}, parentRefsOf(tlsRoute))
	assert.Nil(t, parentRefsOf(&gatewayv1.Gateway{}))
}

func TestGatewayRouteKinds_CoversThreeKinds(t *testing.T) {
	kinds := gatewayRouteKinds()
	require.Len(t, kinds, 3)

	wantNames := []string{"httproute", "grpcroute", "tlsroute"}
	for i, k := range kinds {
		assert.Equal(t, wantNames[i], k.name)
		assert.Equal(t, "gateway.networking.k8s.io", k.gvk.Group)
		assert.Equal(t, "v1", k.gvk.Version)
	}

	assert.IsType(t, &gatewayv1.HTTPRoute{}, kinds[0].newObject())
	assert.IsType(t, &gatewayv1.HTTPRouteList{}, kinds[0].newList())
	assert.IsType(t, &gatewayv1.GRPCRoute{}, kinds[1].newObject())
	assert.IsType(t, &gatewayv1.GRPCRouteList{}, kinds[1].newList())
	assert.IsType(t, &gatewayv1.TLSRoute{}, kinds[2].newObject())
	assert.IsType(t, &gatewayv1.TLSRouteList{}, kinds[2].newList())
}

func TestGatewayScheme_InstallsAllRouteKinds(t *testing.T) {
	s := gatewayScheme(t)

	for _, gvk := range []schema.GroupVersionKind{
		{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRoute"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "HTTPRouteList"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GRPCRoute"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GRPCRouteList"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "TLSRoute"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "TLSRouteList"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "Gateway"},
		{Group: "gateway.networking.k8s.io", Version: "v1", Kind: "GatewayList"},
	} {
		assert.True(t, s.Recognizes(gvk), "scheme does not recognize %s", gvk)
	}
}

func TestExtractHostnames_SkipsWildcards(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"*.example.com", "ok.example.com"},
		},
	}
	assert.Equal(t, []string{"ok.example.com"}, extractHostnames(slog.Default(), route))
}

func TestExtractHostnames_SkipsInvalid(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		Spec: gatewayv1.HTTPRouteSpec{
			// "-bad.example.com" fails validation.ValidateHostname (leading hyphen).
			Hostnames: []gatewayv1.Hostname{"-bad.example.com", "good.example.com"},
		},
	}
	assert.Equal(t, []string{"good.example.com"}, extractHostnames(slog.Default(), route))
}

func TestExtractHostnames_DeDuplicates(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"a.example.com", "a.example.com", "b.example.com"},
		},
	}
	assert.Equal(t, []string{"a.example.com", "b.example.com"}, extractHostnames(slog.Default(), route))
}

func TestExtractHostnames_AcceptsDotlessWithWarning(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"router"},
		},
	}

	handler := &recordingHandler{}
	log := slog.New(handler)

	assert.Equal(t, []string{"router"}, extractHostnames(log, route))
	assert.True(t, handler.hasWarnRecordContaining("router"), "expected a warn-level record naming the dot-less hostname")
}

func TestExtractHostnames_AllSkipped(t *testing.T) {
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "route1",
			Namespace:  "default",
			Finalizers: []string{gatewayCleanupFinalizer},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: []gatewayv1.Hostname{"*.example.com"},
		},
	}

	assert.Empty(t, extractHostnames(slog.Default(), route))

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var addHostCalled bool
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addHostCalled = true
			return "unexpected", nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.False(t, addHostCalled)
}

func TestResolveIP_FallsBackToFlagWhenGatewayMissing(t *testing.T) {
	route := newRouteWithParentRefs("default", gatewayv1.ParentReference{Name: "does-not-exist"})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})
	r.DefaultIP = "0.0.0.0"

	assert.Equal(t, "0.0.0.0", r.resolveIP(context.Background(), r.Log, route))
}

func TestResolveIP_FallsBackWhenNoParentRefs(t *testing.T) {
	route := newRouteWithParentRefs("default")

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})
	r.DefaultIP = "0.0.0.0"

	assert.Equal(t, "0.0.0.0", r.resolveIP(context.Background(), r.Log, route))
}

func TestResolveIP_ContinuesPastFailedGet(t *testing.T) {
	gwWithIP := newGateway("default", "gw-with-ip", ipAddr("10.7.7.7"))

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gwWithIP).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})

	route := newRouteWithParentRefs("default",
		gatewayv1.ParentReference{Name: "missing-gw"}, gatewayv1.ParentReference{Name: "gw-with-ip"})

	assert.Equal(t, "10.7.7.7", r.resolveIP(context.Background(), r.Log, route))
}

func TestResolveIP_ReturnsEmptyWhenNoIPAndNoDefault(t *testing.T) {
	gwHostnameOnly := newGateway("default", "gw", hostnameAddr("lb.example.com"))
	route := newRouteWithParentRefs("default", gatewayv1.ParentReference{Name: "gw"})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(gwHostnameOnly).Build()
	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})
	r.DefaultIP = ""

	assert.Equal(t, "", r.resolveIP(context.Background(), r.Log, route))
}

func TestSyncRoute_RequeuesShortAndCreatesNothingWithoutIP(t *testing.T) {
	gwHostnameOnly := newGateway("default", "gw", hostnameAddr("lb.example.com"))
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "route1",
			Namespace:  "default",
			Finalizers: []string{gatewayCleanupFinalizer},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Hostnames: []gatewayv1.Hostname{"app.example.com"},
		},
	}

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route, gwHostnameOnly).Build()

	var addCalls, updateCalls, deleteCalls int
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addCalls++
			return "unexpected", nil
		},
		updateHostFn: func(_ context.Context, id, ip, hostname, comment string, aliases, tags []string, version string) error {
			updateCalls++
			return nil
		},
		deleteHostFn: func(_ context.Context, id string) error {
			deleteCalls++
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = ""

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayShort}, result)
	assert.Zero(t, addCalls)
	assert.Zero(t, updateCalls)
	assert.Zero(t, deleteCalls)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	assert.NotContains(t, updated.Annotations, hostIDsAnnotation)
}

func TestSyncRoute_NoIPStillPrunesStaleEntries(t *testing.T) {
	// CR-01 regression: syncRoute's no-IP early return used to skip the
	// stale-cleanup pass entirely (it returned before the annotation was
	// even read), leaving a removed hostname's host entry live on the
	// router forever whenever the route's parent Gateway has no address and
	// no DefaultIP is configured. The stale-cleanup pass must run
	// regardless of whether an IP resolved — only the create/update loop is
	// gated on ip != "" (D-16).
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, map[string]string{
		"a.example.com": "id-a",
		"b.example.com": "id-b",
	})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var addCalls, updateCalls int
	var deletedIDs []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			addCalls++
			return "unexpected", nil
		},
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			updateCalls++
			return nil
		},
		deleteHostFn: func(_ context.Context, id string) error {
			deletedIDs = append(deletedIDs, id)
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "" // no parent Gateway seeded either, so resolveIP yields ""

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayShort}, result)
	assert.Zero(t, addCalls)
	assert.Zero(t, updateCalls)
	assert.Equal(t, []string{"id-b"}, deletedIDs)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(r.Log, &updated)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a.example.com": "id-a"}, ids)
}

func TestSyncRoute_UsesDefaultIPWhenParentHasNone(t *testing.T) {
	gwHostnameOnly := newGateway("default", "gw", hostnameAddr("lb.example.com"))
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "route1",
			Namespace:  "default",
			Finalizers: []string{gatewayCleanupFinalizer},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}},
			},
			Hostnames: []gatewayv1.Hostname{"app.example.com"},
		},
	}

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route, gwHostnameOnly).Build()

	var addedIPs []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, ip, hostname, comment string, aliases, tags []string) (string, error) {
			addedIPs = append(addedIPs, ip)
			return "gw-host-1", nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "9.9.9.9"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, []string{"9.9.9.9"}, addedIPs)
}

// hostnamesToGateway converts []string to []gatewayv1.Hostname, for building
// route fixtures from plain string slices.
func hostnamesToGateway(hostnames []string) []gatewayv1.Hostname {
	out := make([]gatewayv1.Hostname, len(hostnames))
	for i, h := range hostnames {
		out[i] = gatewayv1.Hostname(h)
	}
	return out
}

// newHTTPRouteTracking builds an HTTPRoute with the gatewayCleanupFinalizer
// already present (so syncRoute can be exercised directly, matching how
// Reconcile calls it after the finalizer-add branch), the given spec
// hostnames, and — when existingIDs is non-empty — a host-ids annotation
// seeded from it, for syncRoute diff test fixtures.
func newHTTPRouteTracking(name, namespace string, hostnames []string, existingIDs map[string]string) *gatewayv1.HTTPRoute {
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Namespace:  namespace,
			Finalizers: []string{gatewayCleanupFinalizer},
		},
		Spec: gatewayv1.HTTPRouteSpec{
			Hostnames: hostnamesToGateway(hostnames),
		},
	}
	if len(existingIDs) > 0 {
		data, _ := json.Marshal(existingIDs)
		route.Annotations = map[string]string{hostIDsAnnotation: string(data)}
	}
	return route
}

func TestSyncRoute_CreatesNewHostnames(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com", "b.example.com"}, nil)

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	nextID := 1
	var addedHosts []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, hostname, _ string, _, _ []string) (string, error) {
			addedHosts = append(addedHosts, hostname)
			id := fmt.Sprintf("id-%d", nextID)
			nextID++
			return id, nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.ElementsMatch(t, []string{"a.example.com", "b.example.com"}, addedHosts)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(r.Log, &updated)
	require.NoError(t, err)
	assert.Equal(t, "id-1", ids["a.example.com"])
	assert.Equal(t, "id-2", ids["b.example.com"])
}

func TestSyncRoute_AdoptsExistingHostOnAlreadyExists(t *testing.T) {
	// CR-02 regression: when AddHost reports AlreadyExists for an
	// untracked hostname, syncRoute must adopt the existing entry via
	// FindHost (addOrAdoptGatewayHost) rather than treating the reply as a
	// fatal create failure with no ID retained — which would permanently
	// orphan the pre-existing entry (invisible to this route's annotation,
	// therefore never reachable by stale-cleanup or reconcileDelete, and
	// every future AddHost for the same pair fails identically forever).
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, nil)

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var findCalls int
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "", oops.Wrapf(ErrHostAlreadyExists, "adding host")
		},
		findHostFn: func(_ context.Context, ip, hostname string) (*HostEntry, error) {
			findCalls++
			assert.Equal(t, "10.0.0.1", ip)
			assert.Equal(t, "a.example.com", hostname)
			return &HostEntry{ID: "orphaned-id", IP: ip, Hostname: hostname}, nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, 1, findCalls)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(r.Log, &updated)
	require.NoError(t, err)
	assert.Equal(t, "orphaned-id", ids["a.example.com"])
}

// TestSyncRoute_RecoversFromCreateSucceedsThenAnnotationUpdateFails is the
// full CR-02 scenario end to end: AddHost succeeds and creates a real
// server-side entry, but the batch's annotation-persisting r.Update then
// fails, so the ID is never recorded anywhere durable. On the very next
// reconcile, getHostIDsAnnotation still reports the hostname as untracked,
// so syncRoute calls AddHost again for the same (ip, hostname) pair — which
// the server (enforcing uniqueness on that pair) rejects with
// AlreadyExists. Without adoption, that second reconcile would also fail to
// record any ID, permanently orphaning the entry created by the first
// AddHost. With addOrAdoptGatewayHost, it is adopted instead.
func TestSyncRoute_RecoversFromCreateSucceedsThenAnnotationUpdateFails(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, nil)

	s := gatewayScheme(t)
	var failUpdate bool
	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(route).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
				if failUpdate {
					return errors.New("resource version conflict")
				}
				return c.Update(ctx, o, opts...)
			},
		}).
		Build()

	// The first AddHost call "succeeds" server-side (a real entry is
	// created with ID "orphan-1"), but the reconcile's later annotation
	// r.Update fails, so that ID is never persisted. Every subsequent
	// AddHost call for the same pair reports AlreadyExists, and FindHost
	// returns the entry adoption should recover.
	var addCalls int
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			addCalls++
			if addCalls == 1 {
				return "orphan-1", nil
			}
			return "", oops.Wrapf(ErrHostAlreadyExists, "adding host")
		},
		findHostFn: func(_ context.Context, ip, hostname string) (*HostEntry, error) {
			return &HostEntry{ID: "orphan-1", IP: ip, Hostname: hostname}, nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	// Reconcile 1: AddHost succeeds, but the annotation write fails — the
	// created entry is not recorded anywhere.
	failUpdate = true
	_, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.Error(t, err)
	assert.Equal(t, 1, addCalls)

	var afterFirst gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &afterFirst))
	firstIDs, err := getHostIDsAnnotation(r.Log, &afterFirst)
	require.NoError(t, err)
	assert.NotContains(t, firstIDs, "a.example.com", "annotation write failed; nothing should be recorded yet")

	// Reconcile 2: getHostIDsAnnotation still reports the hostname as
	// untracked, so AddHost is retried and gets AlreadyExists back. Adoption
	// must recover "orphan-1" rather than skipping it.
	failUpdate = false
	result, err := r.syncRoute(context.Background(), r.Log, &afterFirst, extractHostnames(r.Log, &afterFirst))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, 2, addCalls)

	var afterSecond gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &afterSecond))
	secondIDs, err := getHostIDsAnnotation(r.Log, &afterSecond)
	require.NoError(t, err)
	assert.Equal(t, "orphan-1", secondIDs["a.example.com"], "the entry created by the first AddHost must be adopted, not orphaned")
}

func TestSyncRoute_UpdatesTrackedHostnames(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, map[string]string{"a.example.com": "id-1"})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var updateCalls, addCalls int
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, id, ip, hostname, comment string, aliases, tags []string, _ string) error {
			updateCalls++
			assert.Equal(t, "id-1", id)
			assert.Equal(t, "10.0.0.1", ip)
			assert.Equal(t, "a.example.com", hostname)
			assert.Equal(t, "k8s-gateway:default/route1", comment)
			assert.Nil(t, aliases)
			assert.Contains(t, tags, "gateway")
			assert.Contains(t, tags, "httproute")
			return nil
		},
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			addCalls++
			return "unexpected", nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, 1, updateCalls)
	assert.Zero(t, addCalls)
}

func TestSyncRoute_UpdatesEvenWhenIPUnchanged(t *testing.T) {
	// D-13: UpdateHost is issued unconditionally for every tracked hostname
	// on every reconcile that reaches syncRoute, even when the resolved IP
	// is identical to the previous reconcile's. This is the intentional
	// mechanism that propagates a changed Gateway IP without the controller
	// keeping any extra "last known IP" state. Do not "fix" this into a
	// no-op when the IP looks unchanged — see D-13.
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, map[string]string{"a.example.com": "id-1"})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var updateCalls int
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			updateCalls++
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	_, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, 1, updateCalls)
}

func TestSyncRoute_DeletesRemovedHostnames(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, map[string]string{
		"a.example.com": "id-a",
		"b.example.com": "id-b",
	})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var deletedIDs []string
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error { return nil },
		deleteHostFn: func(_ context.Context, id string) error {
			deletedIDs = append(deletedIDs, id)
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, []string{"id-b"}, deletedIDs)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(r.Log, &updated)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a.example.com": "id-a"}, ids)
}

func TestSyncRoute_SkipsUpdateWhenNothingChanged(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, nil)

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			return "id-1", nil
		},
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	ctx := context.Background()
	var obj gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route1", Namespace: "default"}, &obj))
	_, err := r.syncRoute(ctx, r.Log, &obj, extractHostnames(r.Log, &obj))
	require.NoError(t, err)

	var afterFirst gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route1", Namespace: "default"}, &afterFirst))
	rvAfterFirst := afterFirst.ResourceVersion

	_, err = r.syncRoute(ctx, r.Log, &afterFirst, extractHostnames(r.Log, &afterFirst))
	require.NoError(t, err)

	var afterSecond gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route1", Namespace: "default"}, &afterSecond))
	assert.Equal(t, rvAfterFirst, afterSecond.ResourceVersion)
}

func TestSyncRoute_PerHostErrorDoesNotAbortBatch(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com", "b.example.com", "c.example.com"}, nil)

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var created []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, hostname, _ string, _, _ []string) (string, error) {
			if hostname == "a.example.com" {
				return "", errors.New("boom")
			}
			created = append(created, hostname)
			return "id-" + hostname, nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayLong}, result)
	assert.ElementsMatch(t, []string{"b.example.com", "c.example.com"}, created)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(r.Log, &updated)
	require.NoError(t, err)
	assert.NotContains(t, ids, "a.example.com")
	assert.Contains(t, ids, "b.example.com")
	assert.Contains(t, ids, "c.example.com")
}

func TestSyncRoute_RetainsPriorIDOnUpdateFailure(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, map[string]string{"a.example.com": "id-1"})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var deleteCalls int
	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error {
			return errors.New("boom")
		},
		deleteHostFn: func(_ context.Context, _ string) error {
			deleteCalls++
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayLong}, result)
	assert.Zero(t, deleteCalls)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(r.Log, &updated)
	require.NoError(t, err)
	assert.Equal(t, "id-1", ids["a.example.com"])
}

func TestSyncRoute_RetainsIDOnStaleDeleteFailure(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"keep.example.com"}, map[string]string{
		"keep.example.com":  "id-keep",
		"stale.example.com": "id-stale",
	})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	mock := &mockHostClient{
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error { return nil },
		deleteHostFn: func(_ context.Context, _ string) error {
			return errors.New("boom")
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayLong}, result)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	ids, err := getHostIDsAnnotation(r.Log, &updated)
	require.NoError(t, err)
	assert.Equal(t, "id-stale", ids["stale.example.com"])
}

func TestSyncRoute_NeverDeletesUntrackedID(t *testing.T) {
	s := gatewayScheme(t)

	everHeldIDs := make(map[string]bool)
	var deletedIDs []string
	nextID := 1
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			id := fmt.Sprintf("id-%d", nextID)
			nextID++
			everHeldIDs[id] = true
			return id, nil
		},
		updateHostFn: func(_ context.Context, _, _, _, _ string, _, _ []string, _ string) error { return nil },
		deleteHostFn: func(_ context.Context, id string) error {
			deletedIDs = append(deletedIDs, id)
			return nil
		},
	}

	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, nil)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()
	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	ctx := context.Background()

	// Create.
	var obj gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route1", Namespace: "default"}, &obj))
	_, err := r.syncRoute(ctx, r.Log, &obj, extractHostnames(r.Log, &obj))
	require.NoError(t, err)

	// Edit: add a second hostname.
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route1", Namespace: "default"}, &obj))
	obj.Spec.Hostnames = append(obj.Spec.Hostnames, "b.example.com")
	require.NoError(t, k8sClient.Update(ctx, &obj))
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route1", Namespace: "default"}, &obj))
	_, err = r.syncRoute(ctx, r.Log, &obj, extractHostnames(r.Log, &obj))
	require.NoError(t, err)

	// Removal: drop both hostnames.
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route1", Namespace: "default"}, &obj))
	obj.Spec.Hostnames = nil
	require.NoError(t, k8sClient.Update(ctx, &obj))
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route1", Namespace: "default"}, &obj))
	_, err = r.syncRoute(ctx, r.Log, &obj, extractHostnames(r.Log, &obj))
	require.NoError(t, err)

	for _, id := range deletedIDs {
		assert.True(t, everHeldIDs[id], "deleted ID %s was never held by this object's annotation", id)
	}
	assert.NotEmpty(t, deletedIDs)
}

func TestSyncRoute_CorruptAnnotationRequeuesWithoutWriting(t *testing.T) {
	route := newHTTPRouteTracking("route1", "default", []string{"a.example.com"}, nil)
	route.Annotations = map[string]string{hostIDsAnnotation: "not valid json"}

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

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

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	result, err := r.syncRoute(context.Background(), r.Log, route, extractHostnames(r.Log, route))
	require.Error(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayShort}, result)
	assert.Zero(t, calls)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	assert.Equal(t, "not valid json", updated.Annotations[hostIDsAnnotation])
}

func TestSyncRoute_DuplicateHostnameAcrossRoutesDoesNotCrossDelete(t *testing.T) {
	routeA := newHTTPRouteTracking("route-a", "default", []string{"shared.example.com"}, nil)
	routeB := newHTTPRouteTracking("route-b", "default", []string{"shared.example.com"}, nil)

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(routeA, routeB).Build()

	nextID := 1
	var deletedIDs []string
	mock := &mockHostClient{
		addHostFn: func(_ context.Context, _, _, _ string, _, _ []string) (string, error) {
			id := fmt.Sprintf("id-%d", nextID)
			nextID++
			return id, nil
		},
		deleteHostFn: func(_ context.Context, id string) error {
			deletedIDs = append(deletedIDs, id)
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)
	r.DefaultIP = "10.0.0.1"

	ctx := context.Background()

	var a gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route-a", Namespace: "default"}, &a))
	_, err := r.syncRoute(ctx, r.Log, &a, extractHostnames(r.Log, &a))
	require.NoError(t, err)

	var b gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route-b", Namespace: "default"}, &b))
	_, err = r.syncRoute(ctx, r.Log, &b, extractHostnames(r.Log, &b))
	require.NoError(t, err)

	// Remove the hostname from route B only.
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route-b", Namespace: "default"}, &b))
	bIDsBefore, err := getHostIDsAnnotation(r.Log, &b)
	require.NoError(t, err)
	bID := bIDsBefore["shared.example.com"]
	require.NotEmpty(t, bID)

	b.Spec.Hostnames = nil
	require.NoError(t, k8sClient.Update(ctx, &b))
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route-b", Namespace: "default"}, &b))
	_, err = r.syncRoute(ctx, r.Log, &b, extractHostnames(r.Log, &b))
	require.NoError(t, err)

	assert.Equal(t, []string{bID}, deletedIDs)

	var updatedA gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(ctx, types.NamespacedName{Name: "route-a", Namespace: "default"}, &updatedA))
	aIDs, err := getHostIDsAnnotation(r.Log, &updatedA)
	require.NoError(t, err)
	assert.Contains(t, aIDs, "shared.example.com")
}

// newDeletingHTTPRoute builds an HTTPRoute already marked for deletion, for
// reconcileDelete test fixtures. Finalizers are set before DeletionTimestamp,
// mirroring the exact seeding order ingressroute_controller_test.go's
// TestReconcile_IngressRoute_Delete uses — the fake client's resourceVersion
// semantics depend on this order rather than a Create-then-Delete round-trip.
func newDeletingHTTPRoute(t *testing.T, name, namespace string, finalizers []string, existingIDs map[string]string) *gatewayv1.HTTPRoute {
	t.Helper()
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
	route.SetFinalizers(finalizers)
	now := metav1.Now()
	route.SetDeletionTimestamp(&now)
	if len(existingIDs) > 0 {
		data, err := json.Marshal(existingIDs)
		require.NoError(t, err)
		route.SetAnnotations(map[string]string{hostIDsAnnotation: string(data)})
	}
	return route
}

// TestReconcile_Route_DeleteTreatsNotFoundAsSuccess is the CR-03 regression:
// DeleteHost returning ErrHostNotFound (e.g. the entry was already deleted
// on a prior reconcile whose finalizer-removal r.Update then failed, or was
// deleted out-of-band via the CLI) must be treated as the desired end state
// having already been reached, not folded into remainingIDs/hadDeleteError
// like a real failure — which would permanently wedge the finalizer, since
// every retry of an already-deleted ID returns NotFound again forever.
func TestReconcile_Route_DeleteTreatsNotFoundAsSuccess(t *testing.T) {
	route := newDeletingHTTPRoute(t, "route1", "default", []string{gatewayCleanupFinalizer}, map[string]string{
		"gone.example.com": "id-gone",
	})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, _ string) error {
			return oops.Wrapf(ErrHostNotFound, "deleting host")
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "route1", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// The finalizer must be removed and the object gone — a NotFound entry
	// must not wedge the finalizer forever.
	var updated gatewayv1.HTTPRoute
	err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated)
	assert.True(t, apierrors.IsNotFound(err), "expected object to be gone after finalizer removal, got err=%v", err)
}

func TestReconcile_HTTPRoute_DeletesHostsOnFinalize(t *testing.T) {
	route := newDeletingHTTPRoute(t, "route1", "default", []string{gatewayCleanupFinalizer}, map[string]string{
		"a.example.com": "id-a",
		"b.example.com": "id-b",
	})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var deletedIDs []string
	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, id string) error {
			deletedIDs = append(deletedIDs, id)
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "route1", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.ElementsMatch(t, []string{"id-a", "id-b"}, deletedIDs)

	// Once the finalizer is removed, the fake client (mirroring the real API
	// server) actually deletes the object rather than leaving a finalizer-less
	// husk behind — so a NotFound Get here is the positive confirmation that
	// the finalizer was released, not a test bug.
	var updated gatewayv1.HTTPRoute
	err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated)
	assert.True(t, apierrors.IsNotFound(err), "expected object to be gone after finalizer removal, got err=%v", err)
}

func TestReconcile_Route_DeleteWithoutFinalizerIsNoOp(t *testing.T) {
	// The fake client refuses to seed an object with a DeletionTimestamp and
	// no finalizers at all (mirroring the real API server's behavior: such
	// an object would already be gone). Seed a finalizer this reconciler
	// does not own, so ContainsFinalizer(gatewayCleanupFinalizer) is still
	// false and reconcileDelete's no-op guard is genuinely exercised.
	route := newDeletingHTTPRoute(t, "route1", "default", []string{"other.example/finalizer"}, nil)

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var calls int
	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, _ string) error {
			calls++
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "route1", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Zero(t, calls)
}

func TestReconcile_Route_PartialDeleteKeepsFinalizerAndRequeues(t *testing.T) {
	route := newDeletingHTTPRoute(t, "route1", "default", []string{gatewayCleanupFinalizer}, map[string]string{
		"ok.example.com":   "id-ok",
		"fail.example.com": "id-fail",
	})

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, id string) error {
			if id == "id-fail" {
				return errors.New("boom")
			}
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "route1", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayShort}, result)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	assert.Contains(t, updated.Finalizers, gatewayCleanupFinalizer)

	ids, err := getHostIDsAnnotation(r.Log, &updated)
	require.NoError(t, err)
	assert.NotContains(t, ids, "ok.example.com")
	assert.Equal(t, "id-fail", ids["fail.example.com"])
}

func TestReconcile_Route_DeleteCorruptAnnotationRequeues(t *testing.T) {
	route := newDeletingHTTPRoute(t, "route1", "default", []string{gatewayCleanupFinalizer}, nil)
	route.Annotations = map[string]string{hostIDsAnnotation: "not valid json"}

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(route).Build()

	var calls int
	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, _ string) error {
			calls++
			return nil
		},
	}

	r := newHTTPRouteReconciler(t, k8sClient, mock)

	result, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "route1", Namespace: "default"},
	})
	require.Error(t, err)
	assert.Equal(t, ctrl.Result{RequeueAfter: requeueDelayShort}, result)
	assert.Zero(t, calls)

	var updated gatewayv1.HTTPRoute
	require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Name: "route1", Namespace: "default"}, &updated))
	assert.Contains(t, updated.Finalizers, gatewayCleanupFinalizer)
}

func TestReconcile_Route_DeleteAllThreeKinds(t *testing.T) {
	s := gatewayScheme(t)
	now := metav1.Now()

	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "groute", Namespace: "default"},
	}
	grpcRoute.SetFinalizers([]string{gatewayCleanupFinalizer})
	grpcRoute.SetDeletionTimestamp(&now)
	grpcIDsJSON, err := json.Marshal(map[string]string{"grpc.example.com": "id-grpc"})
	require.NoError(t, err)
	grpcRoute.SetAnnotations(map[string]string{hostIDsAnnotation: string(grpcIDsJSON)})

	tlsRoute := &gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "troute", Namespace: "default"},
	}
	tlsRoute.SetFinalizers([]string{gatewayCleanupFinalizer})
	tlsRoute.SetDeletionTimestamp(&now)
	tlsIDsJSON, err := json.Marshal(map[string]string{"tls.example.com": "id-tls"})
	require.NoError(t, err)
	tlsRoute.SetAnnotations(map[string]string{hostIDsAnnotation: string(tlsIDsJSON)})

	k8sClient := fake.NewClientBuilder().WithScheme(s).WithObjects(grpcRoute, tlsRoute).Build()

	var deletedIDs []string
	mock := &mockHostClient{
		deleteHostFn: func(_ context.Context, id string) error {
			deletedIDs = append(deletedIDs, id)
			return nil
		},
	}

	grpcReconciler := &GatewayRouteReconciler{
		Client:     k8sClient,
		HostClient: mock,
		Log:        slog.Default(),
		KindName:   "grpcroute",
		newObject:  func() client.Object { return &gatewayv1.GRPCRoute{} },
		newList:    func() client.ObjectList { return &gatewayv1.GRPCRouteList{} },
	}
	tlsReconciler := &GatewayRouteReconciler{
		Client:     k8sClient,
		HostClient: mock,
		Log:        slog.Default(),
		KindName:   "tlsroute",
		newObject:  func() client.Object { return &gatewayv1.TLSRoute{} },
		newList:    func() client.ObjectList { return &gatewayv1.TLSRouteList{} },
	}

	result, err := grpcReconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "groute", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	result, err = tlsReconciler.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "troute", Namespace: "default"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	assert.ElementsMatch(t, []string{"id-grpc", "id-tls"}, deletedIDs)

	// Once the finalizer is removed, the fake client (mirroring the real API
	// server) deletes the object outright — a NotFound Get is the positive
	// confirmation that the finalizer was released for each kind.
	var updatedGRPC gatewayv1.GRPCRoute
	err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "groute", Namespace: "default"}, &updatedGRPC)
	assert.True(t, apierrors.IsNotFound(err), "expected GRPCRoute to be gone after finalizer removal, got err=%v", err)

	var updatedTLS gatewayv1.TLSRoute
	err = k8sClient.Get(context.Background(), types.NamespacedName{Name: "troute", Namespace: "default"}, &updatedTLS)
	assert.True(t, apierrors.IsNotFound(err), "expected TLSRoute to be gone after finalizer removal, got err=%v", err)
}

// ---------------------------------------------------------------------------
// Plan 05: parentRef field index and Gateway map-func re-enqueue (D-17)
// ---------------------------------------------------------------------------

func TestRouteParentRefIndexFunc_ExplicitNamespace(t *testing.T) {
	route := newRouteWithParentRefs("default", gatewayv1.ParentReference{Name: "gw", Namespace: nsPtr("infra")})
	assert.Equal(t, []string{"infra/gw"}, routeParentRefIndexFunc(route))
}

func TestRouteParentRefIndexFunc_DefaultsToRouteNamespace(t *testing.T) {
	route := newRouteWithParentRefs("default", gatewayv1.ParentReference{Name: "gw"})
	assert.Equal(t, []string{"default/gw"}, routeParentRefIndexFunc(route))
}

func TestRouteParentRefIndexFunc_MultipleAndEmpty(t *testing.T) {
	route := newRouteWithParentRefs(
		"default",
		gatewayv1.ParentReference{Name: "gw-a"},
		gatewayv1.ParentReference{Name: "gw-b", Namespace: nsPtr("infra")},
	)
	assert.Equal(t, []string{"default/gw-a", "infra/gw-b"}, routeParentRefIndexFunc(route))

	empty := newRouteWithParentRefs("default")
	keys := routeParentRefIndexFunc(empty)
	assert.Empty(t, keys)
	assert.NotNil(t, keys, "expected an empty non-nil slice for a route with no parentRefs")

	assert.Empty(t, routeParentRefIndexFunc(&gatewayv1.Gateway{}))
}

func TestMapGatewayToRoutes_EnqueuesReferencingRoutes(t *testing.T) {
	routeA := newRouteWithParentRefs("infra", gatewayv1.ParentReference{Name: "gw"})
	routeA.Name = "route-a"
	routeB := newRouteWithParentRefs("infra", gatewayv1.ParentReference{Name: "gw"})
	routeB.Name = "route-b"
	routeC := newRouteWithParentRefs("infra", gatewayv1.ParentReference{Name: "other"})
	routeC.Name = "route-c"

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(routeA, routeB, routeC).
		WithIndex(&gatewayv1.HTTPRoute{}, parentRefIndexKey, routeParentRefIndexFunc).
		Build()

	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})
	gw := newGateway("infra", "gw")

	requests := r.mapGatewayToRoutes(context.Background(), gw)
	got := make([]types.NamespacedName, len(requests))
	for i, req := range requests {
		got[i] = req.NamespacedName
	}
	assert.ElementsMatch(t, []types.NamespacedName{
		{Namespace: "infra", Name: "route-a"},
		{Namespace: "infra", Name: "route-b"},
	}, got)
}

func TestMapGatewayToRoutes_NoMatches(t *testing.T) {
	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithIndex(&gatewayv1.HTTPRoute{}, parentRefIndexKey, routeParentRefIndexFunc).
		Build()

	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})
	gw := newGateway("infra", "gw")

	requests := r.mapGatewayToRoutes(context.Background(), gw)
	assert.Empty(t, requests)
}

func TestMapGatewayToRoutes_ListErrorReturnsNil(t *testing.T) {
	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithIndex(&gatewayv1.HTTPRoute{}, parentRefIndexKey, routeParentRefIndexFunc).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(_ context.Context, _ client.WithWatch, _ client.ObjectList, _ ...client.ListOption) error {
				return errors.New("boom")
			},
		}).
		Build()

	r := newHTTPRouteReconciler(t, k8sClient, &mockHostClient{})
	gw := newGateway("infra", "gw")

	requests := r.mapGatewayToRoutes(context.Background(), gw)
	assert.Nil(t, requests)
}

func TestMapGatewayToRoutes_PerKind(t *testing.T) {
	httpRoute := newRouteWithParentRefs("infra", gatewayv1.ParentReference{Name: "gw"})
	httpRoute.Name = "http-route"

	grpcRoute := &gatewayv1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "grpc-route", Namespace: "infra"},
		Spec: gatewayv1.GRPCRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{{Name: "gw"}}},
		},
	}

	s := gatewayScheme(t)
	k8sClient := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(httpRoute, grpcRoute).
		WithIndex(&gatewayv1.HTTPRoute{}, parentRefIndexKey, routeParentRefIndexFunc).
		WithIndex(&gatewayv1.GRPCRoute{}, parentRefIndexKey, routeParentRefIndexFunc).
		Build()

	r := &GatewayRouteReconciler{
		Client:     k8sClient,
		HostClient: &mockHostClient{},
		Log:        slog.Default(),
		KindName:   "grpcroute",
		newObject:  func() client.Object { return &gatewayv1.GRPCRoute{} },
		newList:    func() client.ObjectList { return &gatewayv1.GRPCRouteList{} },
	}

	gw := newGateway("infra", "gw")
	requests := r.mapGatewayToRoutes(context.Background(), gw)
	require.Len(t, requests, 1)
	assert.Equal(t, types.NamespacedName{Namespace: "infra", Name: "grpc-route"}, requests[0].NamespacedName)
}

// ---------------------------------------------------------------------------
// Plan 05: per-route-kind CRD-presence gating (D-04/D-05)
// ---------------------------------------------------------------------------

func gatewayGVKAt(kind, version string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: "gateway.networking.k8s.io", Version: version, Kind: kind}
}

func TestGatewayKindPresent_AllRouteKindsPresent(t *testing.T) {
	mapper := apimeta.NewDefaultRESTMapper(nil)
	for _, k := range gatewayRouteKinds() {
		mapper.Add(k.gvk, apimeta.RESTScopeNamespace)
	}
	for _, k := range gatewayRouteKinds() {
		assert.True(t, gatewayKindPresent(mapper, k.gvk), "expected %s present", k.name)
	}
}

func TestGatewayKindPresent_PartiallyInstalled(t *testing.T) {
	mapper := apimeta.NewDefaultRESTMapper(nil)
	mapper.Add(gatewayGVKAt("HTTPRoute", "v1"), apimeta.RESTScopeNamespace)

	for _, k := range gatewayRouteKinds() {
		want := k.name == "httproute"
		assert.Equal(t, want, gatewayKindPresent(mapper, k.gvk), "kind %s", k.name)
	}
}

func TestGatewayKindPresent_AllAbsent(t *testing.T) {
	mapper := apimeta.NewDefaultRESTMapper(nil)
	for _, k := range gatewayRouteKinds() {
		assert.False(t, gatewayKindPresent(mapper, k.gvk), "kind %s", k.name)
	}
}

func TestGatewayKindPresent_WrongVersion(t *testing.T) {
	mapper := apimeta.NewDefaultRESTMapper(nil)
	mapper.Add(gatewayGVKAt("TLSRoute", "v1alpha2"), apimeta.RESTScopeNamespace)

	assert.False(t, gatewayKindPresent(mapper, gatewayGVKAt("TLSRoute", "v1")))
}

// ---------------------------------------------------------------------------
// Plan 05: Gateway watch gated on Gateway CRD presence (research Pitfall 1)
// ---------------------------------------------------------------------------

func TestGatewayKindPresent_GatewayGVKPresent(t *testing.T) {
	mapper := apimeta.NewDefaultRESTMapper(nil)
	mapper.Add(gatewayGVK, apimeta.RESTScopeNamespace)
	assert.True(t, gatewayKindPresent(mapper, gatewayGVK))
}

func TestGatewayKindPresent_GatewayGVKAbsent(t *testing.T) {
	mapper := apimeta.NewDefaultRESTMapper(nil)
	for _, k := range gatewayRouteKinds() {
		mapper.Add(k.gvk, apimeta.RESTScopeNamespace)
	}

	for _, k := range gatewayRouteKinds() {
		assert.True(t, gatewayKindPresent(mapper, k.gvk), "kind %s", k.name)
	}
	assert.False(t, gatewayKindPresent(mapper, gatewayGVK))
}

// TestSetupWithManager_WatchGatewayFlagIsThreaded asserts the wiring contract
// without a real ctrl.Manager: SetupWithManager's signature carries the
// watchGateway bool (a compile-time assertion via method-value assignment,
// which binds the receiver but never invokes the method), and gatewayGVK is
// built from the non-deprecated gatewayGroupVersionKind helper rather than
// the deprecated gatewayv1.SchemeGroupVersion. The informer-startup behavior
// this flag ultimately gates (whether the Gateway watch's informer is ever
// registered) is covered by the manual cluster verification in
// 07-VALIDATION.md, per research Pitfall 3 — SetupWithManager needs a real
// manager to exercise beyond this signature/wiring check, and this package's
// two existing controllers' SetupWithManager methods are precedent for
// staying at 0% direct coverage here.
// setupWithManagerFunc names the exact signature SetupWithManager must carry
// so the assignment below is a genuine, non-redundant type assertion (a bare
// `var setup func(...) error = ...` gets flagged by staticcheck as an
// inferable, and therefore removable, type annotation).
type setupWithManagerFunc func(ctrl.Manager, bool) error

func TestSetupWithManager_WatchGatewayFlagIsThreaded(t *testing.T) {
	assert.Equal(t, gatewayGroupVersionKind("Gateway"), gatewayGVK)

	var setup setupWithManagerFunc = (&GatewayRouteReconciler{}).SetupWithManager
	assert.NotNil(t, setup)
}
