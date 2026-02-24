package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"

	"github.com/fzymgc-house/router-hosts/internal/config"
)

// newTestMetrics creates a Metrics backed by a ManualReader for assertions.
func newTestMetrics(t *testing.T) (*Metrics, *metric.ManualReader) {
	t.Helper()
	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	m, err := NewMetrics(provider)
	require.NoError(t, err)
	return m, reader
}

// collectMetrics collects all recorded metrics from the manual reader.
func collectMetrics(t *testing.T, reader *metric.ManualReader) metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	err := reader.Collect(context.Background(), &rm)
	require.NoError(t, err)
	return rm
}

// findMetric searches scope metrics for a metric with the given name.
func findMetric(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

// extractAttrs converts a data point's attribute set to a string map for assertions.
func extractAttrs(dp metricdata.DataPoint[int64]) map[string]string {
	m := make(map[string]string)
	for _, attr := range dp.Attributes.ToSlice() {
		m[string(attr.Key)] = attr.Value.AsString()
	}
	return m
}

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	m, err := NewMetrics(provider)

	require.NoError(t, err)
	assert.NotNil(t, m)
	assert.NotNil(t, m.requestsTotal)
	assert.NotNil(t, m.requestDuration)
	assert.NotNil(t, m.storageOpsTotal)
	assert.NotNil(t, m.storageDuration)
	assert.NotNil(t, m.hookExecsTotal)
	assert.NotNil(t, m.hookDuration)
	assert.NotNil(t, m.hostEntriesGauge)
	assert.NotNil(t, m.meterProvider)
}

func TestDisabledMetrics(t *testing.T) {
	t.Parallel()

	m := DisabledMetrics()
	require.NotNil(t, m)

	// All recording methods must not panic on no-op instruments.
	ctx := context.Background()
	m.RecordRequest(ctx, "AddHost", "ok", 100*time.Millisecond)
	m.RecordStorageOperation(ctx, "insert", "ok", 50*time.Millisecond)
	m.RecordHookExecution(ctx, "notify-slack", "post_create", "ok", 10*time.Millisecond)
	m.SetHostEntriesCount(ctx, 42)

	assert.Nil(t, m.meterProvider)
}

func TestRecordRequest(t *testing.T) {
	t.Parallel()

	m, reader := newTestMetrics(t)
	ctx := context.Background()

	m.RecordRequest(ctx, "AddHost", "ok", 150*time.Millisecond)
	m.RecordRequest(ctx, "GetHost", "error", 20*time.Millisecond)

	rm := collectMetrics(t, reader)

	counter := findMetric(rm, "router_hosts_requests_total")
	require.NotNil(t, counter, "requests_total metric not found")

	histogram := findMetric(rm, "router_hosts_request_duration_seconds")
	require.NotNil(t, histogram, "request_duration_seconds metric not found")

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok, "expected Sum[int64] data type")
	assert.Len(t, sum.DataPoints, 2, "expected 2 data points (one per method/status combo)")
}

func TestRecordStorageOperation(t *testing.T) {
	t.Parallel()

	m, reader := newTestMetrics(t)
	ctx := context.Background()

	m.RecordStorageOperation(ctx, "insert", "ok", 5*time.Millisecond)
	m.RecordStorageOperation(ctx, "select", "ok", 2*time.Millisecond)
	m.RecordStorageOperation(ctx, "insert", "error", 100*time.Millisecond)

	rm := collectMetrics(t, reader)

	counter := findMetric(rm, "router_hosts_storage_operations_total")
	require.NotNil(t, counter, "storage_operations_total metric not found")

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	// 3 distinct attribute combos: (insert,ok), (select,ok), (insert,error)
	assert.Len(t, sum.DataPoints, 3)

	histogram := findMetric(rm, "router_hosts_storage_duration_seconds")
	require.NotNil(t, histogram, "storage_duration_seconds metric not found")
}

func TestRecordHookExecution(t *testing.T) {
	t.Parallel()

	m, reader := newTestMetrics(t)
	ctx := context.Background()

	m.RecordHookExecution(ctx, "notify-slack", "post_create", "ok", 200*time.Millisecond)
	m.RecordHookExecution(ctx, "update-dns", "pre_delete", "error", 5*time.Second)

	rm := collectMetrics(t, reader)

	counter := findMetric(rm, "router_hosts_hook_executions_total")
	require.NotNil(t, counter, "hook_executions_total metric not found")

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	assert.Len(t, sum.DataPoints, 2)

	histogram := findMetric(rm, "router_hosts_hook_duration_seconds")
	require.NotNil(t, histogram, "hook_duration_seconds metric not found")
}

func TestSetHostEntriesCount(t *testing.T) {
	t.Parallel()

	m, reader := newTestMetrics(t)
	ctx := context.Background()

	// Set to 42, then update to 10 — a true gauge reports the last value.
	m.SetHostEntriesCount(ctx, 42)
	m.SetHostEntriesCount(ctx, 10)

	rm := collectMetrics(t, reader)

	gauge := findMetric(rm, "router_hosts_hosts_entries")
	require.NotNil(t, gauge, "hosts_entries metric not found")

	data, ok := gauge.Data.(metricdata.Gauge[int64])
	require.True(t, ok, "expected Gauge[int64] data type, got %T", gauge.Data)
	require.Len(t, data.DataPoints, 1)
	// True gauge: reports 10 (last recorded value), not 52 (accumulated sum).
	assert.Equal(t, int64(10), data.DataPoints[0].Value)
}

func TestUnaryMetricsInterceptor(t *testing.T) {
	t.Parallel()

	m, reader := newTestMetrics(t)
	interceptor := UnaryMetricsInterceptor(m)

	info := &grpc.UnaryServerInfo{
		FullMethod: "/router_hosts.v1.HostsService/AddHost",
	}

	handler := func(_ context.Context, _ any) (any, error) {
		return "response", nil
	}

	resp, err := interceptor(context.Background(), "request", info, handler)
	require.NoError(t, err)
	assert.Equal(t, "response", resp)

	rm := collectMetrics(t, reader)
	counter := findMetric(rm, "router_hosts_requests_total")
	require.NotNil(t, counter)

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1), sum.DataPoints[0].Value)

	attrs := extractAttrs(sum.DataPoints[0])
	assert.Equal(t, "AddHost", attrs["method"], "method attribute")
	assert.Equal(t, "ok", attrs["status"], "status attribute")
}

func TestUnaryMetricsInterceptor_Error(t *testing.T) {
	t.Parallel()

	m, reader := newTestMetrics(t)
	interceptor := UnaryMetricsInterceptor(m)

	info := &grpc.UnaryServerInfo{
		FullMethod: "/router_hosts.v1.HostsService/GetHost",
	}

	handler := func(_ context.Context, _ any) (any, error) {
		return nil, errors.New("not found")
	}

	resp, err := interceptor(context.Background(), "request", info, handler)
	require.Error(t, err)
	assert.Nil(t, resp)

	rm := collectMetrics(t, reader)
	counter := findMetric(rm, "router_hosts_requests_total")
	require.NotNil(t, counter)

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, sum.DataPoints, 1)

	attrs := extractAttrs(sum.DataPoints[0])
	assert.Equal(t, "error", attrs["status"], "status attribute")
	assert.Equal(t, "GetHost", attrs["method"], "method attribute")
}

// mockServerStream implements grpc.ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context { return m.ctx }

func TestStreamMetricsInterceptor(t *testing.T) {
	t.Parallel()

	m, reader := newTestMetrics(t)
	interceptor := StreamMetricsInterceptor(m)

	info := &grpc.StreamServerInfo{
		FullMethod: "/router_hosts.v1.HostsService/ListHosts",
	}

	stream := &mockServerStream{ctx: context.Background()}

	handler := func(_ any, _ grpc.ServerStream) error {
		return nil
	}

	err := interceptor(nil, stream, info, handler)
	require.NoError(t, err)

	rm := collectMetrics(t, reader)
	counter := findMetric(rm, "router_hosts_requests_total")
	require.NotNil(t, counter)

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, sum.DataPoints, 1)

	attrs := extractAttrs(sum.DataPoints[0])
	assert.Equal(t, "ListHosts", attrs["method"], "method attribute")
	assert.Equal(t, "ok", attrs["status"], "status attribute")
}

func TestStreamMetricsInterceptor_Error(t *testing.T) {
	t.Parallel()

	m, reader := newTestMetrics(t)
	interceptor := StreamMetricsInterceptor(m)

	info := &grpc.StreamServerInfo{
		FullMethod: "/router_hosts.v1.HostsService/SearchHosts",
	}

	stream := &mockServerStream{ctx: context.Background()}

	handler := func(_ any, _ grpc.ServerStream) error {
		return errors.New("stream error")
	}

	err := interceptor(nil, stream, info, handler)
	require.Error(t, err)

	rm := collectMetrics(t, reader)
	counter := findMetric(rm, "router_hosts_requests_total")
	require.NotNil(t, counter)

	sum, ok := counter.Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, sum.DataPoints, 1)

	attrs := extractAttrs(sum.DataPoints[0])
	assert.Equal(t, "error", attrs["status"], "status attribute")
	assert.Equal(t, "SearchHosts", attrs["method"], "method attribute")
}

func TestNewMetricsFromConfig_ResourceCreation(t *testing.T) {
	t.Parallel()

	// This test exercises the full NewMetricsFromConfig happy path including
	// resource.Merge(resource.Default(), ...) which will fail if the semconv
	// schema URL doesn't match the SDK's built-in schema URL.
	cfg := &config.OTelConfig{
		Endpoint:    "localhost:4317",
		Insecure:    true,
		ServiceName: "test-service",
	}

	m, err := NewMetricsFromConfig(cfg)
	require.NoError(t, err, "NewMetricsFromConfig should succeed — schema URL mismatch?")
	require.NotNil(t, m)
	assert.NotNil(t, m.meterProvider, "expected real meter provider")

	// Clean up — shutdown may fail to flush since no collector is running,
	// but the resource creation (the real assertion) already succeeded.
	shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = m.Shutdown(shutCtx)
}

func TestNewMetricsFromConfig_Nil(t *testing.T) {
	t.Parallel()

	m, err := NewMetricsFromConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Nil(t, m.meterProvider)

	// Recording should not panic.
	ctx := context.Background()
	m.RecordRequest(ctx, "AddHost", "ok", time.Millisecond)
}

func TestNewMetricsFromConfig_ExportDisabled(t *testing.T) {
	t.Parallel()

	exportFalse := false
	cfg := &config.OTelConfig{
		Endpoint:      "localhost:4317",
		ExportMetrics: &exportFalse,
	}

	m, err := NewMetricsFromConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Nil(t, m.meterProvider, "expected disabled metrics when export_metrics=false")
}

func TestBuildOTelTLSConfig_NoFields(t *testing.T) {
	t.Parallel()

	cfg := &config.OTelConfig{Endpoint: "localhost:4317"}
	tlsCfg, err := buildOTelTLSConfig(cfg)
	require.NoError(t, err)
	assert.Nil(t, tlsCfg, "expected nil TLS config when no TLS fields set")
}

func TestBuildOTelTLSConfig_CAOnly(t *testing.T) {
	t.Parallel()

	certs := generateTestCerts(t)

	cfg := &config.OTelConfig{
		Endpoint:   "localhost:4317",
		CACertFile: certs.CACertPath,
	}
	tlsCfg, err := buildOTelTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	assert.NotNil(t, tlsCfg.RootCAs, "expected custom CA pool")
	assert.Empty(t, tlsCfg.Certificates, "no client certs expected")
}

func TestBuildOTelTLSConfig_InvalidCAFile(t *testing.T) {
	t.Parallel()

	cfg := &config.OTelConfig{
		Endpoint:   "localhost:4317",
		CACertFile: "/nonexistent/ca.pem",
	}
	_, err := buildOTelTLSConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read OTel CA cert")
}

func TestBuildOTelTLSConfig_InvalidCAPEM(t *testing.T) {
	t.Parallel()

	badCA := filepath.Join(t.TempDir(), "bad-ca.pem")
	require.NoError(t, os.WriteFile(badCA, []byte("not a certificate"), 0o600))

	cfg := &config.OTelConfig{
		Endpoint:   "localhost:4317",
		CACertFile: badCA,
	}
	_, err := buildOTelTLSConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certificates")
}

func TestBuildOTelTLSConfig_MutualTLS(t *testing.T) {
	t.Parallel()

	certs := generateTestCerts(t)

	cfg := &config.OTelConfig{
		Endpoint:       "localhost:4317",
		CACertFile:     certs.CACertPath,
		ClientCertFile: certs.ClientCertPath,
		ClientKeyFile:  certs.ClientKeyPath,
	}
	tlsCfg, err := buildOTelTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
	assert.NotNil(t, tlsCfg.RootCAs, "expected custom CA pool")
	assert.Len(t, tlsCfg.Certificates, 1, "expected client certificate")
}

func TestBuildOTelTLSConfig_InvalidClientCert(t *testing.T) {
	t.Parallel()

	cfg := &config.OTelConfig{
		Endpoint:       "localhost:4317",
		ClientCertFile: "/nonexistent/client.pem",
		ClientKeyFile:  "/nonexistent/client-key.pem",
	}
	_, err := buildOTelTLSConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load OTel client cert")
}

func TestShutdown(t *testing.T) {
	t.Parallel()

	t.Run("disabled metrics", func(t *testing.T) {
		t.Parallel()
		m := DisabledMetrics()
		err := m.Shutdown(context.Background())
		assert.NoError(t, err)
	})

	t.Run("real provider", func(t *testing.T) {
		t.Parallel()
		reader := metric.NewManualReader()
		provider := metric.NewMeterProvider(metric.WithReader(reader))
		m, err := NewMetrics(provider)
		require.NoError(t, err)

		err = m.Shutdown(context.Background())
		assert.NoError(t, err)
	})
}

func TestSanitizeGRPCEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"bare host:port", "localhost:4317", "localhost:4317"},
		{"http scheme", "http://localhost:4317", "localhost:4317"},
		{"https scheme", "https://otel-collector:4317", "otel-collector:4317"},
		{"http with IP", "http://127.0.0.1:4317", "127.0.0.1:4317"},
		{"no port", "http://otel-collector", "otel-collector"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, sanitizeGRPCEndpoint(tt.input))
		})
	}
}

func TestExtractMethodName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		fullMethod string
		want       string
	}{
		{
			name:       "standard gRPC method",
			fullMethod: "/router_hosts.v1.HostsService/AddHost",
			want:       "AddHost",
		},
		{
			name:       "different service",
			fullMethod: "/grpc.health.v1.Health/Check",
			want:       "Check",
		},
		{
			name:       "no slash",
			fullMethod: "AddHost",
			want:       "AddHost",
		},
		{
			name:       "single slash prefix",
			fullMethod: "/AddHost",
			want:       "AddHost",
		},
		{
			name:       "empty string",
			fullMethod: "",
			want:       "",
		},
		{
			name:       "trailing slash",
			fullMethod: "/service/",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractMethodName(tt.fullMethod)
			assert.Equal(t, tt.want, got)
		})
	}
}
