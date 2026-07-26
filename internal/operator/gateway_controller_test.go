package operator

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
