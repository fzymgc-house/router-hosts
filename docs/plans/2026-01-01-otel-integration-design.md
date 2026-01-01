# OpenTelemetry Integration Design

**Issue:** #219
**Date:** 2026-01-01
**Status:** Approved

## Summary

Add full OpenTelemetry support for distributed tracing and metrics export, with trace context propagation to access logs.

## Goals

1. Export traces and metrics to OTEL collector via OTLP/gRPC
2. Propagate W3C Trace Context from incoming gRPC requests
3. Include trace_id/span_id in access logs automatically
4. Support baggage propagation and custom span attributes
5. Graceful degradation when no collector configured

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         gRPC Request                             │
│              (with traceparent/tracestate headers)               │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    tonic Interceptor                             │
│         Extract W3C Trace Context → Create parent span           │
└──────────────────────────┬──────────────────────────────────────┘
                           │
          ┌────────────────┴────────────────┐
          ▼                                 ▼
┌──────────────────┐              ┌──────────────────┐
│  Request Span    │              │   Access Log     │
│  (e.g., AddHost) │              │  (inherits ctx)  │
└────────┬─────────┘              └──────────────────┘
         │
         ▼
┌──────────────────┐
│  Storage Span    │
│  (child span)    │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│              OpenTelemetry SDK (BatchSpanProcessor)              │
│                           ↓                                      │
│              OTLP/gRPC Exporter → Collector (if configured)      │
└──────────────────────────────────────────────────────────────────┘
```

## Design Decisions

### Propagation Format

**Decision:** W3C Trace Context only (`traceparent`/`tracestate` headers)

**Rationale:** Modern OTEL standard, simpler implementation. B3 (Zipkin) support can be added later if needed.

### Initialization

**Decision:** Configure at server startup only

**Rationale:** OTEL endpoints rarely change. SIGHUP is specifically for TLS cert rotation. Hot-reloading OTEL would add complexity for minimal benefit.

### Span Granularity

**Decision:** Request + storage spans

- Request span: One per gRPC call (e.g., `AddHost`, `GetHost`)
- Storage span: Child span for database operations

**Rationale:** Provides visibility into where time is spent without over-instrumentation. Hooks can be added later if needed.

### Exporter Protocol

**Decision:** OTLP/gRPC only

**Rationale:** Already have `opentelemetry-otlp` with `grpc-tonic` feature. Matches existing gRPC stack. HTTP can be added later.

### Metrics Export

**Decision:** Dual export - both Prometheus and OTEL

**Rationale:** Prometheus for existing scrape-based monitoring, OTEL for push-based collectors. Both can be enabled simultaneously.

## Configuration

```toml
[metrics]
prometheus_bind = "0.0.0.0:9090"  # Optional - Prometheus scrape endpoint

[metrics.otel]
endpoint = "http://otel-collector:4317"
service_name = "router-hosts"      # Optional, defaults to "router-hosts"
export_metrics = true              # Optional, defaults to true
export_traces = true               # Optional, defaults to true
# headers = { "Authorization" = "Bearer token" }  # Optional
```

### Config Structure

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct OtelConfig {
    /// OTLP gRPC endpoint (e.g., "http://otel-collector:4317")
    pub endpoint: String,

    /// Service name for traces/metrics (default: "router-hosts")
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Export metrics via OTLP (default: true)
    #[serde(default = "default_true")]
    pub export_metrics: bool,

    /// Export traces via OTLP (default: true)
    #[serde(default = "default_true")]
    pub export_traces: bool,

    /// Optional headers for authentication
    #[serde(default)]
    pub headers: HashMap<String, String>,
}
```

### Graceful Degradation

- No `[metrics.otel]` config → no OTEL layers, zero overhead
- Invalid endpoint → log warning at startup, continue without OTEL
- Collector unavailable at runtime → SDK handles retry/backoff internally

## Implementation

### Tracing Subscriber Setup

```rust
fn init_tracing(otel_config: Option<&OtelConfig>) -> Result<()> {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false);

    let env_filter = EnvFilter::from_default_env()
        .add_directive("router_hosts=info".parse()?);

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    if let Some(config) = otel_config {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&config.endpoint)
            .build()?;

        let tracer = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(Resource::new(vec![
                KeyValue::new("service.name", config.service_name.clone()),
            ]))
            .build();

        let otel_layer = tracing_opentelemetry::layer()
            .with_tracer(tracer.tracer("router-hosts"));

        subscriber.with(otel_layer).init();
    } else {
        subscriber.init();
    }

    Ok(())
}
```

### Trace Context Extraction

```rust
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;

/// Extract W3C trace context from gRPC metadata
fn extract_context(metadata: &MetadataMap) -> opentelemetry::Context {
    let propagator = TraceContextPropagator::new();
    let extractor = MetadataExtractor(metadata);
    propagator.extract(&extractor)
}
```

### Storage Instrumentation

```rust
use tracing::instrument;

impl StorageBackend {
    #[instrument(skip(self), level = "debug")]
    pub async fn get_host(&self, id: Ulid) -> Result<HostEntry, StorageError> {
        // Existing implementation unchanged
    }

    #[instrument(skip(self, entry), level = "debug")]
    pub async fn insert_host(&self, entry: &HostEntry) -> Result<(), StorageError> {
        // ...
    }
}
```

### Baggage Propagation

```rust
use opentelemetry::baggage::BaggageExt;

// Extract baggage alongside trace context
let propagator = opentelemetry_sdk::propagation::BaggagePropagator::new();
let baggage = propagator.extract(&extractor);
```

### Custom Span Attributes

Standard attributes set automatically:
- `rpc.method` - gRPC method name
- `rpc.service` - "router_hosts.v1.HostsService"
- `rpc.system` - "grpc"
- `net.peer.name` - Client certificate CN (if mTLS)

Custom attributes can be added in handlers:
```rust
use tracing_opentelemetry::OpenTelemetrySpanExt;

Span::current().set_attribute("host.count", entries.len() as i64);
```

## Access Log Integration

The `tracing-opentelemetry` layer automatically injects trace context into log events. No changes needed to `TimedOperation`.

Updated log format:

| Field | Description | When Present |
|-------|-------------|--------------|
| `trace_id` | OTEL trace ID (32 hex chars) | OTEL configured |
| `span_id` | OTEL span ID (16 hex chars) | OTEL configured |

## Files to Modify

| File | Change |
|------|--------|
| `crates/router-hosts/src/server/config.rs` | Add `OtelConfig` struct |
| `crates/router-hosts/src/server/metrics/mod.rs` | Initialize OTEL exporters |
| `crates/router-hosts/src/server/metrics/otel.rs` | New - OTEL setup helpers |
| `crates/router-hosts/src/server/tracing.rs` | New - Subscriber setup |
| `crates/router-hosts/src/server/service/mod.rs` | Add tracing layer |
| `crates/router-hosts-storage/src/lib.rs` | Add `#[instrument]` to storage methods |
| `docs/guides/operations.md` | Add OTEL configuration section |
| `docs/guides/kubernetes.md` | Add collector sidecar example |

## Testing

```rust
#[test]
fn test_otel_disabled_when_no_config() {
    // No [metrics.otel] → no OTEL layers, zero overhead
}

#[test]
fn test_graceful_degradation_on_invalid_endpoint() {
    // Bad endpoint → warning log, continues without OTEL
}

#[test]
fn test_metrics_dual_export() {
    // Both Prometheus and OTEL receive same counter increments
}

#[tokio::test]
async fn test_trace_context_propagation() {
    // traceparent header → spans have correct parent
}

#[tokio::test]
async fn test_baggage_propagation() {
    // baggage header → context available in handlers
}

#[tokio::test]
async fn test_span_attributes_set() {
    // Custom attributes appear on exported spans
}
```

## Acceptance Criteria

- [ ] Access logs include `trace_id` and `span_id` when OTEL configured
- [ ] Traces exported to OTLP collector with correct parent context
- [ ] Metrics exported via both Prometheus and OTLP
- [ ] Baggage propagated from incoming requests
- [ ] Custom span attributes can be set in handlers
- [ ] No performance regression when OTEL not configured
- [ ] Graceful degradation on missing/invalid collector
- [ ] Documentation updated with OTEL configuration guide
