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
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"google.golang.org/grpc"
	grpccreds "google.golang.org/grpc/credentials"

	"github.com/fzymgc-house/router-hosts/internal/config"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)

// histogramBuckets defines bucket boundaries suitable for subsecond RPC and
// storage durations (unit: seconds).
var histogramBuckets = otelmetric.WithExplicitBucketBoundaries(
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)

// Metrics holds all OTel metric instruments for the server.
type Metrics struct {
	requestsTotal          otelmetric.Int64Counter
	requestDuration        otelmetric.Float64Histogram
	storageOpsTotal        otelmetric.Int64Counter
	storageDuration        otelmetric.Float64Histogram
	hookExecsTotal         otelmetric.Int64Counter
	hookDuration           otelmetric.Float64Histogram
	hookRunsCoalescedTotal otelmetric.Int64Counter
	hostEntriesGauge       otelmetric.Int64Gauge

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

	hookRunsCoalescedTotal, err := meter.Int64Counter("router_hosts_hook_runs_coalesced_total",
		otelmetric.WithDescription("Total number of hook run batches superseded before executing"),
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create hook_runs_coalesced_total counter")
	}

	hostEntriesGauge, err := meter.Int64Gauge("router_hosts_hosts_entries",
		otelmetric.WithDescription("Current number of host entries"),
	)
	if err != nil {
		return nil, oops.Wrapf(err, "create hosts_entries gauge")
	}

	return &Metrics{
		requestsTotal:          requestsTotal,
		requestDuration:        requestDuration,
		storageOpsTotal:        storageOpsTotal,
		storageDuration:        storageDuration,
		hookExecsTotal:         hookExecsTotal,
		hookDuration:           hookDuration,
		hookRunsCoalescedTotal: hookRunsCoalescedTotal,
		hostEntriesGauge:       hostEntriesGauge,
		meterProvider:          meterProvider,
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

	endpoint := sanitizeGRPCEndpoint(cfg.Endpoint)

	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(endpoint),
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

// enabled reports whether m is backed by a real meter provider (constructed
// via NewMetrics/NewMetricsFromConfig) rather than DisabledMetrics()'s no-op
// instruments, which never set meterProvider.
func (m *Metrics) enabled() bool {
	return m != nil && m.meterProvider != nil
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
	hookRunsCoalescedTotal, _ := noopMeter.Int64Counter("router_hosts_hook_runs_coalesced_total")
	hostEntriesGauge, _ := noopMeter.Int64Gauge("router_hosts_hosts_entries")

	return &Metrics{
		requestsTotal:          requestsTotal,
		requestDuration:        requestDuration,
		storageOpsTotal:        storageOpsTotal,
		storageDuration:        storageDuration,
		hookExecsTotal:         hookExecsTotal,
		hookDuration:           hookDuration,
		hookRunsCoalescedTotal: hookRunsCoalescedTotal,
		hostEntriesGauge:       hostEntriesGauge,
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

// RecordHookRunCoalesced records a coalesced hook run batch — a batch that
// was superseded by a newer trigger before it ever started executing. This
// counter deliberately does NOT increment router_hosts_hook_executions_total:
// a coalesced run never invoked a hook command, so counting it there would
// make the execution counter overstate work actually performed.
func (m *Metrics) RecordHookRunCoalesced(ctx context.Context, hookType string) {
	m.hookRunsCoalescedTotal.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("type", hookType),
	))
}

// SetHostEntriesCount records the current host entry count as an absolute value.
func (m *Metrics) SetHostEntriesCount(ctx context.Context, count int64) {
	m.hostEntriesGauge.Record(ctx, count)
}

// DefaultAggregateEventsWarnThreshold is the default per-aggregate event count
// above which an aggregate is counted by router_hosts_aggregates_over_threshold.
const DefaultAggregateEventsWarnThreshold int64 = 1000

// RegisterAggregateEventGauges registers two observable gauges that report
// per-aggregate event growth, pulled at scrape time. No-op when metrics are
// disabled (nil meter provider). The callback iterates ListAggregateIDs +
// CountEvents; acceptable at this deployment's scale.
func (m *Metrics) RegisterAggregateEventGauges(store storage.EventStore, warnThreshold int64) error {
	if m.meterProvider == nil || store == nil {
		return nil
	}
	meter := m.meterProvider.Meter("router-hosts")

	maxGauge, err := meter.Int64ObservableGauge("router_hosts_aggregate_events_max",
		otelmetric.WithDescription("Maximum event count across all aggregates"),
	)
	if err != nil {
		return oops.Wrapf(err, "create aggregate_events_max gauge")
	}
	overGauge, err := meter.Int64ObservableGauge("router_hosts_aggregates_over_threshold",
		otelmetric.WithDescription("Number of aggregates whose event count exceeds the warn threshold"),
	)
	if err != nil {
		return oops.Wrapf(err, "create aggregates_over_threshold gauge")
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o otelmetric.Observer) error {
			ids, listErr := store.ListAggregateIDs(ctx)
			if listErr != nil {
				return listErr
			}
			var maxCount, over int64
			for _, id := range ids {
				c, cErr := store.CountEvents(ctx, id)
				if cErr != nil {
					return cErr
				}
				if c > maxCount {
					maxCount = c
				}
				if c > warnThreshold {
					over++
				}
			}
			o.ObserveInt64(maxGauge, maxCount)
			o.ObserveInt64(overGauge, over)
			return nil
		},
		maxGauge, overGauge,
	)
	if err != nil {
		return oops.Wrapf(err, "register aggregate-event gauge callback")
	}
	return nil
}

// RegisterSinkGauges registers seven observable gauges that project a
// SinkHealth registry's per-consumer state through the server's existing
// OTel pipeline, pulled at scrape time — mirroring
// RegisterAggregateEventGauges's shape. No-op when metrics are disabled
// (nil meter provider) or when health is nil. The callback only reads from
// health; it never mutates the registry, which is what makes D-10's
// survives-close retention compatible with OTel's pull model.
//
// Every instrument this function registers has a real observation point in
// the callback below — none is created and left permanently unobserved.
// router_hosts_sink_consecutive_failures is a gauge, not a counter,
// specifically because it carries consumer-reported standing state:
// re-reporting the same failure count on every status tick must not
// double-count.
func (m *Metrics) RegisterSinkGauges(health *SinkHealth) error {
	if m.meterProvider == nil || health == nil {
		return nil
	}
	meter := m.meterProvider.Meter("router-hosts")

	lastSeenGauge, err := meter.Int64ObservableGauge("router_hosts_sink_last_seen_timestamp_seconds",
		otelmetric.WithDescription("Unix timestamp (seconds) of the last time this consumer's stream was seen"),
	)
	if err != nil {
		return oops.Wrapf(err, "create sink_last_seen_timestamp_seconds gauge")
	}
	lastSuccessGauge, err := meter.Int64ObservableGauge("router_hosts_sink_last_success_timestamp_seconds",
		otelmetric.WithDescription("Unix timestamp (seconds) of this consumer's last successful artifact write"),
	)
	if err != nil {
		return oops.Wrapf(err, "create sink_last_success_timestamp_seconds gauge")
	}
	consecutiveFailuresGauge, err := meter.Int64ObservableGauge("router_hosts_sink_consecutive_failures",
		otelmetric.WithDescription("Consumer-reported count of consecutive render/write failures since its last success"),
	)
	if err != nil {
		return oops.Wrapf(err, "create sink_consecutive_failures gauge")
	}
	// D-12a: 1 when the consumer's last post-write reload hook failed. The
	// artifact on that consumer is current while its resolver may not be —
	// a different alert from a stale artifact, which is why this is a
	// field separate from the last-success timestamp above.
	reloadFailedGauge, err := meter.Int64ObservableGauge("router_hosts_sink_reload_failed",
		otelmetric.WithDescription("1 when the consumer's last post-write reload hook failed; the artifact is current but its resolver may not be (D-12a)"),
	)
	if err != nil {
		return oops.Wrapf(err, "create sink_reload_failed gauge")
	}
	convergedGauge, err := meter.Int64ObservableGauge("router_hosts_sink_converged",
		otelmetric.WithDescription("1 when the consumer's last rendered change ID equals the server's current change ID"),
	)
	if err != nil {
		return oops.Wrapf(err, "create sink_converged gauge")
	}
	connectedGauge, err := meter.Int64ObservableGauge("router_hosts_sinks_connected",
		otelmetric.WithDescription("Current number of connected sink streams"),
	)
	if err != nil {
		return oops.Wrapf(err, "create sinks_connected gauge")
	}
	// review L11: a stream whose peer certificate identity could not be
	// extracted still counts toward sinks_connected (deliberately — see
	// SinkHealth.Connect), which means a broken authentication path can
	// otherwise hide behind a healthy-looking connection count. This gauge
	// carries no attributes because there is no verified identity to
	// attribute the failure to — attributing it to caller-supplied data
	// would be the exact substitution D-13 forbids. A non-zero value means
	// connections are being accepted and counted while no per-consumer
	// health record can be created for them, so sinks_connected will
	// exceed the number of tracked identities.
	identityFailuresGauge, err := meter.Int64ObservableGauge("router_hosts_sink_identity_failures",
		otelmetric.WithDescription("Number of streams whose peer certificate identity could not be extracted since process start; no attributes, since there is no verified identity to attribute it to"),
	)
	if err != nil {
		return oops.Wrapf(err, "create sink_identity_failures gauge")
	}

	_, err = meter.RegisterCallback(
		func(ctx context.Context, o otelmetric.Observer) error {
			snap := health.Snapshot()
			for cn, st := range snap.States {
				// Observing nothing for a zero time rather than reporting
				// a 1970 timestamp.
				if !st.LastSeen.IsZero() {
					o.ObserveInt64(lastSeenGauge, st.LastSeen.Unix(),
						otelmetric.WithAttributes(attribute.String("cn", cn)))
				}
				if !st.LastSuccess.IsZero() {
					o.ObserveInt64(lastSuccessGauge, st.LastSuccess.Unix(),
						otelmetric.WithAttributes(attribute.String("cn", cn)))
				}
				o.ObserveInt64(consecutiveFailuresGauge, st.ConsecutiveFailures,
					otelmetric.WithAttributes(attribute.String("cn", cn)))

				reloadFailed := int64(0)
				if st.ReloadFailed {
					reloadFailed = 1
				}
				o.ObserveInt64(reloadFailedGauge, reloadFailed,
					otelmetric.WithAttributes(attribute.String("cn", cn)))

				// The change ID itself is never emitted as a label (D-13,
				// review M6): a value that changes on every mutation
				// would be unbounded cardinality by construction, which
				// is the opposite of D-13. It is compared here only to
				// produce a bounded 0/1 gauge. Operators who need the
				// exact ULID read it from the consumer's sidecar status
				// file or the server's structured logs, neither of which
				// has a cardinality budget.
				converged := int64(0)
				if st.RenderedChangeID != "" && st.RenderedChangeID == snap.ServerChangeID {
					converged = 1
				}
				o.ObserveInt64(convergedGauge, converged,
					otelmetric.WithAttributes(attribute.String("cn", cn)))
			}
			// Label-free: no identity is attached to a connection count or
			// an identity-extraction failure count.
			o.ObserveInt64(connectedGauge, snap.Connected)
			o.ObserveInt64(identityFailuresGauge, snap.IdentityFailures)
			return nil
		},
		lastSeenGauge, lastSuccessGauge, consecutiveFailuresGauge, reloadFailedGauge,
		convergedGauge, connectedGauge, identityFailuresGauge,
	)
	if err != nil {
		return oops.Wrapf(err, "register sink gauge callback")
	}
	return nil
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

// sanitizeGRPCEndpoint strips http:// or https:// scheme prefixes from an
// endpoint string. The gRPC exporter's WithEndpoint expects bare host:port,
// but users and documentation commonly include the scheme (matching the
// OTEL_EXPORTER_OTLP_ENDPOINT env var format).
func sanitizeGRPCEndpoint(endpoint string) string {
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")
	return endpoint
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
