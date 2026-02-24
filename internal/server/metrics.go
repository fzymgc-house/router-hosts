package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"time"

	"github.com/samber/oops"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc"
	grpccreds "google.golang.org/grpc/credentials"

	"github.com/fzymgc-house/router-hosts/internal/config"
)

// histogramBuckets defines bucket boundaries suitable for subsecond RPC and
// storage durations (unit: seconds).
var histogramBuckets = otelmetric.WithExplicitBucketBoundaries(
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)

// Metrics holds all OTel metric instruments for the server.
type Metrics struct {
	requestsTotal    otelmetric.Int64Counter
	requestDuration  otelmetric.Float64Histogram
	storageOpsTotal  otelmetric.Int64Counter
	storageDuration  otelmetric.Float64Histogram
	hookExecsTotal   otelmetric.Int64Counter
	hookDuration     otelmetric.Float64Histogram
	hostEntriesGauge otelmetric.Int64Gauge

	meterProvider *metric.MeterProvider
}

// NewMetrics creates all metric instruments from the given meter provider.
func NewMetrics(meterProvider *metric.MeterProvider) (*Metrics, error) {
	meter := meterProvider.Meter("router-hosts")

	requestsTotal, err := meter.Int64Counter("router_hosts_requests_total",
		otelmetric.WithDescription("Total number of gRPC requests"),
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create requests_total counter")
	}

	requestDuration, err := meter.Float64Histogram("router_hosts_request_duration_seconds",
		otelmetric.WithDescription("Duration of gRPC requests in seconds"),
		otelmetric.WithUnit("s"),
		histogramBuckets,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create request_duration histogram")
	}

	storageOpsTotal, err := meter.Int64Counter("router_hosts_storage_operations_total",
		otelmetric.WithDescription("Total number of storage operations"),
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create storage_operations_total counter")
	}

	storageDuration, err := meter.Float64Histogram("router_hosts_storage_duration_seconds",
		otelmetric.WithDescription("Duration of storage operations in seconds"),
		otelmetric.WithUnit("s"),
		histogramBuckets,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create storage_duration histogram")
	}

	hookExecsTotal, err := meter.Int64Counter("router_hosts_hook_executions_total",
		otelmetric.WithDescription("Total number of hook executions"),
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create hook_executions_total counter")
	}

	hookDuration, err := meter.Float64Histogram("router_hosts_hook_duration_seconds",
		otelmetric.WithDescription("Duration of hook executions in seconds"),
		otelmetric.WithUnit("s"),
		histogramBuckets,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create hook_duration histogram")
	}

	hostEntriesGauge, err := meter.Int64Gauge("router_hosts_hosts_entries",
		otelmetric.WithDescription("Current number of host entries"),
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create hosts_entries gauge")
	}

	return &Metrics{
		requestsTotal:    requestsTotal,
		requestDuration:  requestDuration,
		storageOpsTotal:  storageOpsTotal,
		storageDuration:  storageDuration,
		hookExecsTotal:   hookExecsTotal,
		hookDuration:     hookDuration,
		hostEntriesGauge: hostEntriesGauge,
		meterProvider:    meterProvider,
	}, nil
}

// NewMetricsFromConfig creates an OTLP exporter, meter provider, and all
// instruments from the given OTel configuration. Returns disabled/no-op metrics
// if cfg is nil or export_metrics is false.
func NewMetricsFromConfig(cfg *config.OTelConfig) (*Metrics, error) {
	if cfg == nil {
		return DisabledMetrics(), nil
	}
	if cfg.ExportMetrics != nil && !*cfg.ExportMetrics {
		return DisabledMetrics(), nil
	}

	ctx := context.Background()

	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
	}

	if cfg.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	} else {
		tlsCfg, err := buildOTelTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		if tlsCfg != nil {
			opts = append(opts, otlpmetricgrpc.WithTLSCredentials(grpccreds.NewTLS(tlsCfg)))
		}
	}

	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(cfg.Headers))
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, oops.Wrapf(err, "create OTLP metric exporter")
	}

	interval := time.Duration(cfg.ExportIntervalSec) * time.Second
	if interval == 0 {
		interval = time.Duration(config.DefaultExportIntervalSecs) * time.Second
	}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = "router-hosts"
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, oops.Wrapf(err, "create OTel resource")
	}

	provider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(exporter,
			metric.WithInterval(interval),
		)),
		metric.WithResource(res),
	)

	return NewMetrics(provider)
}

// DisabledMetrics returns a Metrics struct with no-op instruments. Safe to call
// recording methods on without side effects.
func DisabledMetrics() *Metrics {
	noopMeter := noop.Meter{}

	// These calls on the noop meter never return errors.
	requestsTotal, _ := noopMeter.Int64Counter("router_hosts_requests_total")
	requestDuration, _ := noopMeter.Float64Histogram("router_hosts_request_duration_seconds")
	storageOpsTotal, _ := noopMeter.Int64Counter("router_hosts_storage_operations_total")
	storageDuration, _ := noopMeter.Float64Histogram("router_hosts_storage_duration_seconds")
	hookExecsTotal, _ := noopMeter.Int64Counter("router_hosts_hook_executions_total")
	hookDuration, _ := noopMeter.Float64Histogram("router_hosts_hook_duration_seconds")
	hostEntriesGauge, _ := noopMeter.Int64Gauge("router_hosts_hosts_entries")

	return &Metrics{
		requestsTotal:    requestsTotal,
		requestDuration:  requestDuration,
		storageOpsTotal:  storageOpsTotal,
		storageDuration:  storageDuration,
		hookExecsTotal:   hookExecsTotal,
		hookDuration:     hookDuration,
		hostEntriesGauge: hostEntriesGauge,
	}
}

// RecordRequest records a gRPC request counter increment and duration histogram
// observation. The duration histogram intentionally omits the status label to
// match the Rust implementation and avoid cardinality explosion.
func (m *Metrics) RecordRequest(ctx context.Context, method, status string, duration time.Duration) {
	attrs := otelmetric.WithAttributes(
		attribute.String("method", method),
		attribute.String("status", status),
	)
	m.requestsTotal.Add(ctx, 1, attrs)
	m.requestDuration.Record(ctx, duration.Seconds(),
		otelmetric.WithAttributes(attribute.String("method", method)),
	)
}

// RecordStorageOperation records a storage operation counter increment and
// duration histogram observation. The duration histogram intentionally omits
// the status label to match the Rust implementation.
func (m *Metrics) RecordStorageOperation(ctx context.Context, operation, status string, duration time.Duration) {
	attrs := otelmetric.WithAttributes(
		attribute.String("operation", operation),
		attribute.String("status", status),
	)
	m.storageOpsTotal.Add(ctx, 1, attrs)
	m.storageDuration.Record(ctx, duration.Seconds(),
		otelmetric.WithAttributes(attribute.String("operation", operation)),
	)
}

// RecordHookExecution records a hook execution counter increment and duration
// histogram observation. The duration histogram intentionally omits the status
// label to match the Rust implementation.
func (m *Metrics) RecordHookExecution(ctx context.Context, name, hookType, status string, duration time.Duration) {
	counterAttrs := otelmetric.WithAttributes(
		attribute.String("name", name),
		attribute.String("type", hookType),
		attribute.String("status", status),
	)
	m.hookExecsTotal.Add(ctx, 1, counterAttrs)
	m.hookDuration.Record(ctx, duration.Seconds(),
		otelmetric.WithAttributes(
			attribute.String("name", name),
			attribute.String("type", hookType),
		),
	)
}

// SetHostEntriesCount records the current host entry count as an absolute value.
func (m *Metrics) SetHostEntriesCount(ctx context.Context, count int64) {
	m.hostEntriesGauge.Record(ctx, count)
}

// Shutdown gracefully shuts down the meter provider, flushing any pending
// metric exports. Returns nil if the provider is nil (disabled metrics).
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m.meterProvider == nil {
		return nil
	}
	if err := m.meterProvider.Shutdown(ctx); err != nil {
		return oops.Wrapf(err, "shutdown meter provider")
	}
	return nil
}

// buildOTelTLSConfig creates a TLS config from OTel config fields.
// Returns nil if no TLS fields are set (uses system defaults).
func buildOTelTLSConfig(cfg *config.OTelConfig) (*tls.Config, error) {
	if cfg.CACertFile == "" && cfg.ClientCertFile == "" {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.CACertFile != "" {
		caPEM, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, oops.Wrapf(err, "read OTel CA cert %s", cfg.CACertFile)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, oops.Errorf("no valid certificates in OTel CA file %s", cfg.CACertFile)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCertFile != "" && cfg.ClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, oops.Wrapf(err, "load OTel client cert")
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// extractMethodName extracts the short method name from a gRPC full method
// string. For example, "/router_hosts.v1.HostsService/AddHost" returns
// "AddHost". Returns the full string unchanged if the format is unexpected.
func extractMethodName(fullMethod string) string {
	if idx := strings.LastIndex(fullMethod, "/"); idx >= 0 {
		return fullMethod[idx+1:]
	}
	return fullMethod
}

// UnaryMetricsInterceptor returns a gRPC unary server interceptor that records
// request metrics (counter and duration) for each RPC.
func UnaryMetricsInterceptor(m *Metrics) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		method := extractMethodName(info.FullMethod)
		start := time.Now()

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		status := "ok"
		if err != nil {
			status = "error"
		}
		m.RecordRequest(ctx, method, status, duration)

		return resp, err
	}
}

// StreamMetricsInterceptor returns a gRPC stream server interceptor that
// records request metrics (counter and duration) for each streaming RPC.
func StreamMetricsInterceptor(m *Metrics) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		method := extractMethodName(info.FullMethod)
		start := time.Now()

		err := handler(srv, ss)

		duration := time.Since(start)
		status := "ok"
		if err != nil {
			status = "error"
		}
		m.RecordRequest(ss.Context(), method, status, duration)

		return err
	}
}
