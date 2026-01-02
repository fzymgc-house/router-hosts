# Metrics Instrumentation Design

Issue: #167

## Overview

Add Prometheus and OpenTelemetry metrics/tracing instrumentation to router-hosts.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Feature flags | None - always included | Simpler build, avoids feature matrix |
| OTEL scope | Metrics + traces | Debugging latency without log complexity |
| Prometheus endpoint | Separate plaintext HTTP | Standard internal scraping pattern |
| Default state | Opt-in (disabled) | Secure default, no surprise ports |

## Configuration

```toml
# Metrics disabled by default - add this section to enable
[metrics]
# Prometheus endpoint (plaintext HTTP)
prometheus_bind = "0.0.0.0:9090"  # Enables /metrics endpoint

# Optional: OpenTelemetry export
[metrics.otel]
endpoint = "http://otel-collector:4317"  # gRPC endpoint
# service_name defaults to "router-hosts"
```

**Behavior:**
- No `[metrics]` section → no metrics collection, no open ports
- `prometheus_bind` set → starts HTTP server exposing `/metrics`
- `[metrics.otel]` present → exports metrics AND traces to collector
- Both can be enabled simultaneously (dual export)

## Metrics Definitions

### Request Metrics (gRPC layer)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `router_hosts_requests_total` | Counter | `method`, `status` | Total gRPC requests |
| `router_hosts_request_duration_seconds` | Histogram | `method` | Request latency |
| `router_hosts_active_connections` | Gauge | - | Current open connections |

### Storage Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `router_hosts_storage_operations_total` | Counter | `operation`, `status` | DB operations count |
| `router_hosts_storage_duration_seconds` | Histogram | `operation` | DB operation latency |

### Hook Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `router_hosts_hook_executions_total` | Counter | `name`, `type`, `status` | Hook execution count |
| `router_hosts_hook_duration_seconds` | Histogram | `name`, `type` | Hook execution time |

### Health Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `router_hosts_cert_expiry_seconds` | Gauge | `cert` | Seconds until cert expires |
| `router_hosts_hosts_entries` | Gauge | - | Current host entry count |

**Histogram buckets:** Default Prometheus buckets (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10)

## Distributed Tracing

### Trace Spans

| Span Name | Location | Attributes |
|-----------|----------|------------|
| `grpc.request` | gRPC interceptor | `method`, `peer_addr` |
| `storage.operation` | Storage trait | `operation`, `backend` |
| `hook.execute` | HookExecutor | `hook_name`, `type` |
| `hosts_file.write` | HostsFileGenerator | `entry_count` |

### Propagation

- W3C Trace Context headers for incoming gRPC requests
- Parent-child relationships preserved across async boundaries
- Errors recorded as span events with stack context

### Integration

- Uses `tracing` crate spans (already in codebase)
- `tracing-opentelemetry` bridges to OTEL exporter
- Traces only exported when `[metrics.otel]` is configured
- Prometheus endpoint does NOT export traces (metrics only)

### Sampling

- Default: 100% sampling (all requests traced)
- Future: configurable sampling rate via `otel.sample_rate`

## Architecture

### Module Structure

```
crates/router-hosts/src/
├── server/
│   ├── metrics/
│   │   ├── mod.rs          # MetricsRegistry, init logic
│   │   ├── prometheus.rs   # HTTP server for /metrics
│   │   └── otel.rs         # OTEL exporter setup
│   └── ...
```

### Initialization Flow

1. Parse config → check for `[metrics]` section
2. If present, create `MetricsRegistry` (shared state)
3. If `prometheus_bind` set → spawn HTTP server task
4. If `[metrics.otel]` set → install OTEL exporter + tracer
5. Pass registry to gRPC server, storage, hook executor

### Key Types

```rust
pub struct MetricsConfig {
    pub prometheus_bind: Option<SocketAddr>,
    pub otel: Option<OtelConfig>,
}

pub struct OtelConfig {
    pub endpoint: String,
    pub service_name: Option<String>,  // defaults to "router-hosts"
}

pub struct MetricsRegistry {
    // Holds metric handles for increment/observe
}
```

### Dependencies

- `metrics` + `metrics-exporter-prometheus`
- `opentelemetry` + `opentelemetry-otlp`
- `tracing-opentelemetry`
- `hyper` (for HTTP metrics server)

## Testing

| Test Type | Coverage |
|-----------|----------|
| Unit tests | MetricsConfig validation, registry creation |
| Integration tests | Prometheus endpoint returns valid metrics format |
| Integration tests | Metrics increment correctly on operations |
| E2E tests | Full flow with Prometheus scrape (optional, docker) |

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Prometheus port already in use | Server startup fails with clear error |
| OTEL collector unreachable | Log warning, continue without export (non-blocking) |
| OTEL export fails mid-operation | Log error, buffer/retry with backoff |
| Invalid config values | Fail fast at config load time |

## Graceful Shutdown

- Prometheus HTTP server: immediate shutdown on SIGTERM
- OTEL exporter: flush pending spans/metrics before exit (5s timeout)

## No Metrics Configured

- Zero runtime overhead - no collectors instantiated
- No background tasks spawned
