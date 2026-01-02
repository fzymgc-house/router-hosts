# OpenTelemetry Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add full OpenTelemetry support with distributed tracing, metrics export, and trace context propagation.

**Architecture:** Layer-based approach using `tracing-opentelemetry` to bridge `tracing` spans to OTEL. Dual metrics export (Prometheus + OTLP). Graceful degradation when no collector configured.

**Tech Stack:** `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp`, `tracing-opentelemetry`

---

## Task 1: Expand OtelConfig

**Files:**
- Modify: `crates/router-hosts/src/server/config.rs:353-369`
- Test: `crates/router-hosts/src/server/config.rs` (existing test module)

**Step 1: Write the test for expanded config**

Add to the test module at the end of config.rs:

```rust
#[test]
fn test_otel_config_full() {
    let toml_str = r#"
        [server]
        bind_address = "0.0.0.0:50051"
        hosts_file_path = "/etc/hosts"

        [database]
        url = "sqlite://:memory:"

        [tls]
        cert_path = "/cert.pem"
        key_path = "/key.pem"
        ca_cert_path = "/ca.pem"

        [metrics.otel]
        endpoint = "http://otel-collector:4317"
        service_name = "my-service"
        export_metrics = true
        export_traces = false
        headers = { "Authorization" = "Bearer token123" }
    "#;

    let config: Config = toml::from_str(toml_str).unwrap();
    let otel = config.metrics.unwrap().otel.unwrap();
    assert_eq!(otel.endpoint, "http://otel-collector:4317");
    assert_eq!(otel.service_name(), "my-service");
    assert!(otel.export_metrics);
    assert!(!otel.export_traces);
    assert_eq!(otel.headers.get("Authorization").unwrap(), "Bearer token123");
}

#[test]
fn test_otel_config_defaults() {
    let toml_str = r#"
        [server]
        bind_address = "0.0.0.0:50051"
        hosts_file_path = "/etc/hosts"

        [database]
        url = "sqlite://:memory:"

        [tls]
        cert_path = "/cert.pem"
        key_path = "/key.pem"
        ca_cert_path = "/ca.pem"

        [metrics.otel]
        endpoint = "http://localhost:4317"
    "#;

    let config: Config = toml::from_str(toml_str).unwrap();
    let otel = config.metrics.unwrap().otel.unwrap();
    assert_eq!(otel.service_name(), "router-hosts");
    assert!(otel.export_metrics); // default true
    assert!(otel.export_traces);  // default true
    assert!(otel.headers.is_empty());
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration && cargo test -p router-hosts config::tests::test_otel_config_full -- --nocapture`

Expected: FAIL with field not found errors

**Step 3: Expand OtelConfig struct**

Replace lines 353-369 in config.rs:

```rust
use std::collections::HashMap;

/// OpenTelemetry exporter configuration
#[derive(Debug, Deserialize, Clone)]
pub struct OtelConfig {
    /// gRPC endpoint for OTEL collector (e.g., "http://otel-collector:4317")
    pub endpoint: String,

    /// Service name for traces/metrics (defaults to "router-hosts")
    #[serde(default)]
    pub service_name: Option<String>,

    /// Export metrics via OTLP (default: true)
    #[serde(default = "default_true")]
    pub export_metrics: bool,

    /// Export traces via OTLP (default: true)
    #[serde(default = "default_true")]
    pub export_traces: bool,

    /// Optional headers for authentication (e.g., Authorization)
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl OtelConfig {
    /// Get the service name, defaulting to "router-hosts"
    pub fn service_name(&self) -> &str {
        self.service_name.as_deref().unwrap_or("router-hosts")
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration && cargo test -p router-hosts config::tests::test_otel_config -- --nocapture`

Expected: PASS

**Step 5: Commit**

```bash
cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration
git add crates/router-hosts/src/server/config.rs
git commit -m "feat(config): expand OtelConfig with export flags and headers

Add export_metrics, export_traces, and headers fields to OtelConfig.
Both export flags default to true for backward compatibility.
Headers support enables authentication to collectors."
```

---

## Task 2: Create OTEL Module with Exporter Setup

**Files:**
- Create: `crates/router-hosts/src/server/metrics/otel.rs`
- Modify: `crates/router-hosts/src/server/metrics/mod.rs:19`

**Step 1: Create otel.rs module**

Create `crates/router-hosts/src/server/metrics/otel.rs`:

```rust
//! OpenTelemetry exporter setup
//!
//! Provides trace and metrics export via OTLP/gRPC to an OpenTelemetry collector.

use crate::server::config::OtelConfig;
use crate::server::metrics::MetricsError;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    resource::{EnvResourceDetector, SdkProvidedResourceDetector, TelemetryResourceDetector},
    trace::SdkTracerProvider,
    Resource,
};
use std::time::Duration;
use tracing::info;

/// OTEL resource with service name and standard attributes
fn build_resource(service_name: &str) -> Resource {
    let detectors: Vec<Box<dyn opentelemetry_sdk::resource::ResourceDetector>> = vec![
        Box::new(SdkProvidedResourceDetector),
        Box::new(EnvResourceDetector::default()),
        Box::new(TelemetryResourceDetector),
    ];

    let detected = Resource::from_detectors(Duration::from_secs(5), detectors);
    let service = Resource::new(vec![opentelemetry::KeyValue::new(
        "service.name",
        service_name.to_string(),
    )]);

    detected.merge(&service)
}

/// Initialize OTEL trace exporter
///
/// Returns a tracer provider that exports spans to the configured endpoint.
/// Returns None if export_traces is false.
pub fn init_tracer(config: &OtelConfig) -> Result<Option<SdkTracerProvider>, MetricsError> {
    if !config.export_traces {
        info!("OTEL trace export disabled by configuration");
        return Ok(None);
    }

    let mut exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint);

    // Add headers if configured
    for (key, value) in &config.headers {
        exporter = exporter.with_metadata(key, value.parse().map_err(|e| {
            MetricsError::OtelInit(format!("Invalid header value for '{}': {}", key, e))
        })?);
    }

    let exporter = exporter.build().map_err(|e| {
        MetricsError::OtelInit(format!("Failed to build OTLP span exporter: {}", e))
    })?;

    let resource = build_resource(config.service_name());

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    info!(
        endpoint = %config.endpoint,
        service_name = %config.service_name(),
        "OTEL trace exporter initialized"
    );

    Ok(Some(provider))
}

/// Initialize OTEL metrics exporter
///
/// Returns a periodic reader that exports metrics to the configured endpoint.
/// Returns None if export_metrics is false.
pub fn init_metrics(
    config: &OtelConfig,
) -> Result<Option<opentelemetry_sdk::metrics::SdkMeterProvider>, MetricsError> {
    if !config.export_metrics {
        info!("OTEL metrics export disabled by configuration");
        return Ok(None);
    }

    let mut exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint);

    // Add headers if configured
    for (key, value) in &config.headers {
        exporter = exporter.with_metadata(key, value.parse().map_err(|e| {
            MetricsError::OtelInit(format!("Invalid header value for '{}': {}", key, e))
        })?);
    }

    let exporter = exporter.build().map_err(|e| {
        MetricsError::OtelInit(format!("Failed to build OTLP metrics exporter: {}", e))
    })?;

    let resource = build_resource(config.service_name());

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(60))
        .build();

    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(resource)
        .build();

    info!(
        endpoint = %config.endpoint,
        service_name = %config.service_name(),
        "OTEL metrics exporter initialized"
    );

    Ok(Some(provider))
}

/// Shutdown OTEL exporters gracefully
pub fn shutdown() {
    opentelemetry::global::shutdown_tracer_provider();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_resource_includes_service_name() {
        let resource = build_resource("test-service");
        let attrs: Vec<_> = resource.iter().collect();
        assert!(attrs.iter().any(|(k, v)| k.as_str() == "service.name"
            && v.as_str() == "test-service"));
    }

    #[test]
    fn test_disabled_tracer_returns_none() {
        let config = OtelConfig {
            endpoint: "http://localhost:4317".to_string(),
            service_name: None,
            export_metrics: true,
            export_traces: false,
            headers: Default::default(),
        };
        let result = init_tracer(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_disabled_metrics_returns_none() {
        let config = OtelConfig {
            endpoint: "http://localhost:4317".to_string(),
            service_name: None,
            export_metrics: false,
            export_traces: true,
            headers: Default::default(),
        };
        let result = init_metrics(&config).unwrap();
        assert!(result.is_none());
    }
}
```

**Step 2: Add module to mod.rs**

Add after line 19 in `metrics/mod.rs`:

```rust
pub mod otel;
```

**Step 3: Run tests**

Run: `cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration && cargo test -p router-hosts metrics::otel -- --nocapture`

Expected: PASS

**Step 4: Commit**

```bash
cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration
git add crates/router-hosts/src/server/metrics/otel.rs crates/router-hosts/src/server/metrics/mod.rs
git commit -m "feat(metrics): add OTEL exporter module

Implements OTLP/gRPC exporters for traces and metrics.
Supports header-based authentication for collectors.
Graceful degradation when export flags are disabled."
```

---

## Task 3: Create Tracing Subscriber Setup

**Files:**
- Create: `crates/router-hosts/src/server/tracing.rs`
- Modify: `crates/router-hosts/src/server/mod.rs`

**Step 1: Create tracing.rs module**

Create `crates/router-hosts/src/server/tracing.rs`:

```rust
//! Tracing subscriber setup with optional OpenTelemetry integration
//!
//! Configures the global tracing subscriber with:
//! - Console output (fmt layer)
//! - Optional OTEL trace export (via tracing-opentelemetry)

use crate::server::config::OtelConfig;
use crate::server::metrics::otel;
use crate::server::metrics::MetricsError;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Handle for the tracing subsystem
///
/// Holds ownership of the OTEL tracer provider. Dropping this handle
/// will flush and shutdown the tracer provider.
pub struct TracingHandle {
    tracer_provider: Option<SdkTracerProvider>,
}

impl TracingHandle {
    /// Gracefully shutdown tracing subsystem
    pub fn shutdown(self) {
        if self.tracer_provider.is_some() {
            otel::shutdown();
            info!("OTEL tracer provider shut down");
        }
    }
}

/// Initialize tracing with optional OTEL export
///
/// Must be called once at startup before any tracing macros are used.
///
/// # Arguments
/// * `otel_config` - Optional OTEL configuration. If None, only console logging is enabled.
///
/// # Returns
/// A handle that must be kept alive for the duration of the program.
pub fn init(otel_config: Option<&OtelConfig>) -> Result<TracingHandle, MetricsError> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,router_hosts=debug"));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    let tracer_provider = if let Some(config) = otel_config {
        match otel::init_tracer(config)? {
            Some(provider) => {
                let tracer = provider.tracer("router-hosts");
                let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
                registry.with(otel_layer).init();
                info!("Tracing initialized with OTEL export");
                Some(provider)
            }
            None => {
                registry.init();
                info!("Tracing initialized (OTEL traces disabled)");
                None
            }
        }
    } else {
        registry.init();
        info!("Tracing initialized (no OTEL config)");
        None
    };

    Ok(TracingHandle { tracer_provider })
}

#[cfg(test)]
mod tests {
    // Integration tests would require careful setup due to global subscriber
    // Unit tests for configuration parsing are in config.rs
}
```

**Step 2: Update server/mod.rs**

Add the module declaration and update the tracing init call.

Find line 163 (`tracing_subscriber::fmt::init();`) and replace with a call to the new module:

```rust
pub mod tracing;
// ... at initialization point:
let _tracing_handle = tracing::init(config.metrics.as_ref().and_then(|m| m.otel.as_ref()))?;
```

Note: This requires updating the function signature to return the handle and propagate errors. The exact integration depends on the current structure.

**Step 3: Run full test suite**

Run: `cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration && task test`

Expected: PASS

**Step 4: Commit**

```bash
cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration
git add crates/router-hosts/src/server/tracing.rs crates/router-hosts/src/server/mod.rs
git commit -m "feat(tracing): add OTEL-aware subscriber setup

Creates tracing module with layered subscriber:
- EnvFilter for log level control
- fmt layer for console output
- Optional tracing-opentelemetry layer for trace export

Trace context (trace_id, span_id) automatically propagates
to log events when OTEL is enabled."
```

---

## Task 4: Integrate OTEL Metrics Export

**Files:**
- Modify: `crates/router-hosts/src/server/metrics/mod.rs`

**Step 1: Update MetricsHandle to include OTEL provider**

Modify `MetricsHandle` struct:

```rust
pub struct MetricsHandle {
    prometheus_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    otel_meter_provider: Option<opentelemetry_sdk::metrics::SdkMeterProvider>,
}
```

**Step 2: Update init() to initialize OTEL metrics**

In the `init()` function, after the Prometheus setup block, add:

```rust
// Initialize OTEL metrics if configured
if let Some(otel_config) = &config.otel {
    match otel::init_metrics(otel_config)? {
        Some(provider) => {
            handle.otel_meter_provider = Some(provider);
            tracing::info!(
                endpoint = %otel_config.endpoint,
                "OTEL metrics export initialized"
            );
        }
        None => {
            tracing::debug!("OTEL metrics export disabled");
        }
    }
}
```

**Step 3: Update shutdown() to flush OTEL**

```rust
pub async fn shutdown(mut self) {
    if let Some(tx) = self.prometheus_shutdown.take() {
        if tx.send(()).is_err() {
            tracing::warn!("Prometheus server already shut down");
        }
    }
    if let Some(provider) = self.otel_meter_provider.take() {
        if let Err(e) = provider.shutdown() {
            tracing::warn!(error = %e, "Failed to shutdown OTEL meter provider");
        }
    }
}
```

**Step 4: Run tests**

Run: `cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration && task test`

Expected: PASS

**Step 5: Commit**

```bash
cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration
git add crates/router-hosts/src/server/metrics/mod.rs
git commit -m "feat(metrics): integrate OTEL metrics export

MetricsHandle now manages both Prometheus and OTEL exporters.
Dual export allows gradual migration from Prometheus to OTEL.
Graceful shutdown flushes pending OTEL metrics."
```

---

## Task 5: Add Storage Instrumentation

**Files:**
- Modify: `crates/router-hosts-storage/src/backends/sqlite.rs`
- Modify: `crates/router-hosts-storage/src/backends/duckdb.rs`
- Modify: `crates/router-hosts-storage/src/backends/postgres.rs`

**Step 1: Add tracing dependency to storage crate**

Check if `tracing` is already a dependency. If not, add to `crates/router-hosts-storage/Cargo.toml`:

```toml
tracing = { workspace = true }
```

**Step 2: Add #[instrument] to key storage methods**

For each backend (sqlite.rs, duckdb.rs, postgres.rs), add `#[instrument]` to:
- `list_all`
- `get_by_id`
- `search`
- `append_event`
- `save_snapshot`
- `health_check`

Example for sqlite.rs:

```rust
use tracing::instrument;

#[async_trait]
impl HostProjection for SqliteBackend {
    #[instrument(skip(self), level = "debug")]
    async fn list_all(&self) -> Result<Vec<HostEntry>, StorageError> {
        // existing implementation
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_by_id(&self, id: Ulid) -> Result<HostEntry, StorageError> {
        // existing implementation
    }

    #[instrument(skip(self, filter), level = "debug")]
    async fn search(&self, filter: HostFilter) -> Result<Vec<HostEntry>, StorageError> {
        // existing implementation
    }
}
```

**Step 3: Run tests**

Run: `cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration && task test`

Expected: PASS

**Step 4: Commit**

```bash
cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration
git add crates/router-hosts-storage/
git commit -m "feat(storage): add tracing instrumentation

Add #[instrument] to key storage operations for automatic
span creation. Creates child spans under request spans for
visibility into database operation timing."
```

---

## Task 6: Add Trace Context Propagation

**Files:**
- Modify: `crates/router-hosts/src/server/service/mod.rs`
- Create: `crates/router-hosts/src/server/propagation.rs`

**Step 1: Create propagation module**

Create `crates/router-hosts/src/server/propagation.rs`:

```rust
//! W3C Trace Context propagation for gRPC requests
//!
//! Extracts trace context from incoming gRPC metadata and creates
//! parent spans for distributed tracing.

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tonic::metadata::MetadataMap;

/// Extract trace context from gRPC metadata
pub struct MetadataExtractor<'a>(pub &'a MetadataMap);

impl<'a> opentelemetry::propagation::Extractor for MetadataExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0
            .keys()
            .filter_map(|k| match k {
                tonic::metadata::KeyRef::Ascii(k) => Some(k.as_str()),
                _ => None,
            })
            .collect()
    }
}

/// Extract W3C trace context from gRPC metadata
///
/// Returns an OpenTelemetry context with parent span information
/// if traceparent header is present.
pub fn extract_context(metadata: &MetadataMap) -> opentelemetry::Context {
    let propagator = TraceContextPropagator::new();
    let extractor = MetadataExtractor(metadata);
    propagator.extract(&extractor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_empty_metadata() {
        let metadata = MetadataMap::new();
        let ctx = extract_context(&metadata);
        // Should return empty context without panic
        assert!(!ctx.has_active_span());
    }

    #[test]
    fn test_extract_with_traceparent() {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                .parse()
                .unwrap(),
        );
        let ctx = extract_context(&metadata);
        // Context should have span info (though may not be "active" in test)
        let span_ctx = ctx.span().span_context();
        assert!(span_ctx.is_valid());
    }
}
```

**Step 2: Integrate propagation in service handlers**

In each gRPC handler, extract context at the start:

```rust
use crate::server::propagation;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub async fn handle_add_host(&self, request: Request<AddHostRequest>) -> ... {
    let parent_cx = propagation::extract_context(request.metadata());
    let span = tracing::info_span!("AddHost");
    span.set_parent(parent_cx);
    let _guard = span.enter();

    // ... existing implementation
}
```

**Step 3: Run tests**

Run: `cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration && task test`

Expected: PASS

**Step 4: Commit**

```bash
cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration
git add crates/router-hosts/src/server/propagation.rs crates/router-hosts/src/server/mod.rs crates/router-hosts/src/server/service/
git commit -m "feat(server): add W3C trace context propagation

Extract traceparent/tracestate headers from incoming gRPC requests.
Creates proper parent-child relationships for distributed traces.
Enables end-to-end tracing across service boundaries."
```

---

## Task 7: Update Documentation

**Files:**
- Modify: `docs/guides/operations.md`

**Step 1: Add OTEL configuration section**

Add after the Prometheus Metrics section (~line 337):

```markdown
## OpenTelemetry Integration

### Configuration

Enable OTEL export alongside Prometheus:

```toml
[metrics]
prometheus_bind = "0.0.0.0:9090"

[metrics.otel]
endpoint = "http://otel-collector:4317"
service_name = "router-hosts"     # Optional, defaults to "router-hosts"
export_metrics = true             # Optional, defaults to true
export_traces = true              # Optional, defaults to true
# headers = { "Authorization" = "Bearer token" }  # Optional
```

### Trace Context Propagation

Incoming gRPC requests with W3C Trace Context headers (`traceparent`, `tracestate`) are automatically linked to distributed traces.

### Graceful Degradation

- No `[metrics.otel]` config → no OTEL layers, zero overhead
- Invalid endpoint → warning at startup, continues without OTEL
- Collector unavailable at runtime → SDK handles retry/backoff

### Kubernetes Collector Sidecar

Example collector sidecar configuration:

```yaml
containers:
  - name: otel-collector
    image: otel/opentelemetry-collector:latest
    ports:
      - containerPort: 4317
    volumeMounts:
      - name: otel-config
        mountPath: /etc/otelcol
volumes:
  - name: otel-config
    configMap:
      name: otel-collector-config
```
```

**Step 2: Commit**

```bash
cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration
git add docs/guides/operations.md
git commit -m "docs(operations): add OTEL configuration guide

Document OTEL configuration options, trace context propagation,
graceful degradation behavior, and Kubernetes sidecar example."
```

---

## Task 8: Final Integration Testing

**Step 1: Run full test suite**

Run: `cd /Volumes/Code/github.com/fzymgc-house/router-hosts/.worktrees/otel-integration && task ci`

Expected: All tests pass, coverage ≥80%

**Step 2: Manual verification**

1. Build and run with OTEL config pointing to a local collector
2. Make gRPC requests with traceparent header
3. Verify traces appear in collector output

**Step 3: Final commit if any fixes needed**

---

## Summary

| Task | Component | Files Changed |
|------|-----------|---------------|
| 1 | OtelConfig expansion | config.rs |
| 2 | OTEL exporter module | metrics/otel.rs, metrics/mod.rs |
| 3 | Tracing subscriber | tracing.rs, mod.rs |
| 4 | OTEL metrics integration | metrics/mod.rs |
| 5 | Storage instrumentation | backends/*.rs |
| 6 | Trace propagation | propagation.rs, service/*.rs |
| 7 | Documentation | operations.md |
| 8 | Integration testing | - |

**Estimated commits:** 7-8 atomic commits
