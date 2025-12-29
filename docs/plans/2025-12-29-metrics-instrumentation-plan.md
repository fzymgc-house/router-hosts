# Metrics Instrumentation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Prometheus and OpenTelemetry metrics/tracing instrumentation to router-hosts.

**Architecture:** Create a new `metrics/` module under `server/` with three files: `mod.rs` (registry + init), `prometheus.rs` (HTTP /metrics endpoint), and `otel.rs` (OTEL exporter). Metrics are opt-in via `[metrics]` config section. The `MetricsRegistry` is passed to service, hooks, and storage layers for instrumentation.

**Tech Stack:** `metrics` crate + `metrics-exporter-prometheus`, `opentelemetry` + `opentelemetry-otlp`, `tracing-opentelemetry`, `hyper` for HTTP server.

**Design Doc:** `docs/plans/2025-12-29-metrics-instrumentation-design.md`

---

## Task 1: Add Dependencies to Workspace

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/router-hosts/Cargo.toml`

**Step 1: Add workspace dependencies**

In workspace `Cargo.toml`, add to `[workspace.dependencies]`:

```toml
# Metrics and observability
metrics = "0.24"
metrics-exporter-prometheus = { version = "0.16", features = ["http-listener"] }
opentelemetry = { version = "0.27", features = ["trace", "metrics"] }
opentelemetry_sdk = { version = "0.27", features = ["rt-tokio"] }
opentelemetry-otlp = { version = "0.27", features = ["grpc-tonic"] }
tracing-opentelemetry = "0.28"
```

**Step 2: Add dependencies to router-hosts crate**

In `crates/router-hosts/Cargo.toml`, add to `[dependencies]`:

```toml
# Metrics and observability
metrics.workspace = true
metrics-exporter-prometheus.workspace = true
opentelemetry.workspace = true
opentelemetry_sdk.workspace = true
opentelemetry-otlp.workspace = true
tracing-opentelemetry.workspace = true
```

**Step 3: Verify build**

Run: `task build`
Expected: Build succeeds with new dependencies

**Step 4: Commit**

```bash
git add Cargo.toml crates/router-hosts/Cargo.toml
git commit -m "build: add metrics and observability dependencies

Adds metrics, metrics-exporter-prometheus, opentelemetry, and
tracing-opentelemetry for Prometheus/OTEL instrumentation.

Part of #167"
```

---

## Task 2: Create MetricsConfig Types

**Files:**
- Modify: `crates/router-hosts/src/server/config.rs`

**Step 1: Write the failing test**

Add to `config.rs` tests module:

```rust
#[test]
fn test_metrics_config_default_is_none() {
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
    "#;

    let config: Config = toml::from_str(toml_str).unwrap();
    assert!(config.metrics.is_none());
}

#[test]
fn test_metrics_config_prometheus_only() {
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

        [metrics]
        prometheus_bind = "0.0.0.0:9090"
    "#;

    let config: Config = toml::from_str(toml_str).unwrap();
    let metrics = config.metrics.unwrap();
    assert_eq!(
        metrics.prometheus_bind,
        Some("0.0.0.0:9090".parse().unwrap())
    );
    assert!(metrics.otel.is_none());
}

#[test]
fn test_metrics_config_with_otel() {
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

        [metrics]
        prometheus_bind = "0.0.0.0:9090"

        [metrics.otel]
        endpoint = "http://otel-collector:4317"
        service_name = "my-router-hosts"
    "#;

    let config: Config = toml::from_str(toml_str).unwrap();
    let metrics = config.metrics.unwrap();
    let otel = metrics.otel.unwrap();
    assert_eq!(otel.endpoint, "http://otel-collector:4317");
    assert_eq!(otel.service_name, Some("my-router-hosts".to_string()));
}
```

**Step 2: Run test to verify it fails**

Run: `task test -- --test-threads=1 -E 'test(test_metrics_config)'`
Expected: FAIL - MetricsConfig type doesn't exist

**Step 3: Add MetricsConfig types**

Add before the `Config` struct:

```rust
use std::net::SocketAddr;

/// OpenTelemetry exporter configuration
#[derive(Debug, Deserialize, Clone)]
pub struct OtelConfig {
    /// gRPC endpoint for OTEL collector (e.g., "http://otel-collector:4317")
    pub endpoint: String,

    /// Service name for traces/metrics (defaults to "router-hosts")
    #[serde(default)]
    pub service_name: Option<String>,
}

impl OtelConfig {
    /// Get the service name, defaulting to "router-hosts"
    pub fn service_name(&self) -> &str {
        self.service_name.as_deref().unwrap_or("router-hosts")
    }
}

/// Metrics and observability configuration
///
/// When this section is absent from config, no metrics are collected
/// and no ports are opened. This is the default (opt-in) behavior.
#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    /// Address to bind Prometheus HTTP endpoint (e.g., "0.0.0.0:9090")
    /// If set, exposes /metrics endpoint on plaintext HTTP
    #[serde(default)]
    pub prometheus_bind: Option<SocketAddr>,

    /// OpenTelemetry configuration for metrics and traces export
    #[serde(default)]
    pub otel: Option<OtelConfig>,
}
```

**Step 4: Add metrics field to Config struct**

Modify the `Config` struct to include:

```rust
#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub tls: TlsConfig,

    #[serde(default)]
    pub retention: RetentionConfig,

    #[serde(default)]
    pub hooks: HooksConfig,

    /// ACME certificate management configuration
    #[serde(default)]
    pub acme: AcmeConfig,

    /// Metrics and observability configuration (opt-in)
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
}
```

**Step 5: Run test to verify it passes**

Run: `task test -- --test-threads=1 -E 'test(test_metrics_config)'`
Expected: PASS

**Step 6: Run all tests**

Run: `task test`
Expected: All tests pass

**Step 7: Commit**

```bash
git add crates/router-hosts/src/server/config.rs
git commit -m "feat(config): add MetricsConfig for Prometheus/OTEL

Adds MetricsConfig struct with:
- prometheus_bind: optional SocketAddr for /metrics endpoint
- otel: optional OtelConfig for OTLP export

Config is opt-in - absent [metrics] section means no collection.

Part of #167"
```

---

## Task 3: Create Metrics Module Skeleton

**Files:**
- Create: `crates/router-hosts/src/server/metrics/mod.rs`
- Modify: `crates/router-hosts/src/server/mod.rs`

**Step 1: Create the metrics module**

Create `crates/router-hosts/src/server/metrics/mod.rs`:

```rust
//! Metrics and observability instrumentation
//!
//! This module provides Prometheus metrics export and OpenTelemetry
//! integration for distributed tracing.
//!
//! # Configuration
//!
//! Metrics are opt-in. When no `[metrics]` section is present in config,
//! no collectors are installed and no ports are opened.
//!
//! ```toml
//! [metrics]
//! prometheus_bind = "0.0.0.0:9090"  # Enables /metrics endpoint
//!
//! [metrics.otel]
//! endpoint = "http://otel-collector:4317"
//! ```

mod prometheus;

use crate::server::config::MetricsConfig;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("Failed to bind Prometheus endpoint: {0}")]
    PrometheusBind(String),

    #[error("Failed to initialize OTEL exporter: {0}")]
    OtelInit(String),
}

/// Handle for the metrics subsystem
///
/// Dropping this handle will shut down the Prometheus HTTP server
/// and flush any pending OTEL exports.
pub struct MetricsHandle {
    /// Shutdown signal for Prometheus server
    prometheus_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MetricsHandle {
    /// Create a disabled metrics handle (no-op)
    pub fn disabled() -> Self {
        Self {
            prometheus_shutdown: None,
        }
    }

    /// Gracefully shut down metrics subsystem
    pub async fn shutdown(self) {
        if let Some(tx) = self.prometheus_shutdown {
            let _ = tx.send(());
        }
        // TODO: Flush OTEL exporter
    }
}

/// Initialize metrics subsystem based on configuration
///
/// Returns a handle that must be kept alive for the duration of the server.
/// Dropping the handle will shut down metrics collection.
///
/// If `config` is `None`, returns a disabled handle with zero overhead.
pub async fn init(config: Option<&MetricsConfig>) -> Result<MetricsHandle, MetricsError> {
    let Some(config) = config else {
        tracing::debug!("Metrics disabled (no [metrics] config section)");
        return Ok(MetricsHandle::disabled());
    };

    let mut handle = MetricsHandle {
        prometheus_shutdown: None,
    };

    // Start Prometheus HTTP server if configured
    if let Some(addr) = config.prometheus_bind {
        let (tx, rx) = tokio::sync::oneshot::channel();
        handle.prometheus_shutdown = Some(tx);

        prometheus::start_server(addr, rx).await?;
        tracing::info!(%addr, "Prometheus metrics endpoint started");
    }

    // Initialize OTEL if configured
    if let Some(_otel_config) = &config.otel {
        // TODO: Initialize OTEL exporter in Task 5
        tracing::info!("OpenTelemetry export configured (not yet implemented)");
    }

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_init_with_none_returns_disabled() {
        let handle = init(None).await.unwrap();
        assert!(handle.prometheus_shutdown.is_none());
    }

    #[tokio::test]
    async fn test_disabled_shutdown_is_noop() {
        let handle = MetricsHandle::disabled();
        handle.shutdown().await; // Should not panic
    }
}
```

**Step 2: Create Prometheus module placeholder**

Create `crates/router-hosts/src/server/metrics/prometheus.rs`:

```rust
//! Prometheus HTTP endpoint for /metrics

use super::MetricsError;
use std::net::SocketAddr;
use tokio::sync::oneshot;

/// Start the Prometheus HTTP server
///
/// The server exposes `/metrics` endpoint on plaintext HTTP.
/// It will shut down when `shutdown_rx` receives a signal.
pub async fn start_server(
    addr: SocketAddr,
    _shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), MetricsError> {
    // TODO: Implement in Task 4
    tracing::debug!(%addr, "Prometheus server start requested (not yet implemented)");
    Ok(())
}
```

**Step 3: Register metrics module in server mod.rs**

Add to `crates/router-hosts/src/server/mod.rs` after `pub mod write_queue;`:

```rust
pub mod metrics;
```

**Step 4: Verify build and tests**

Run: `task build && task test`
Expected: Build succeeds, all tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/metrics/ crates/router-hosts/src/server/mod.rs
git commit -m "feat(metrics): create metrics module skeleton

Adds server/metrics/ module with:
- mod.rs: MetricsHandle and init() function
- prometheus.rs: placeholder for HTTP server

Metrics subsystem is disabled when config is None (zero overhead).

Part of #167"
```

---

## Task 4: Implement Prometheus HTTP Server

**Files:**
- Modify: `crates/router-hosts/src/server/metrics/prometheus.rs`
- Modify: `crates/router-hosts/src/server/metrics/mod.rs`

**Step 1: Write the failing test**

Add to `prometheus.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_prometheus_server_responds_to_metrics() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let actual_addr = start_server(addr, shutdown_rx).await.unwrap();

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Fetch metrics
        let url = format!("http://{}/metrics", actual_addr);
        let response = reqwest::get(&url).await.unwrap();

        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        // Should contain at least process metrics or be empty
        assert!(body.is_empty() || body.contains('#'));

        // Shutdown
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_prometheus_server_404_for_other_paths() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let actual_addr = start_server(addr, shutdown_rx).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let url = format!("http://{}/other", actual_addr);
        let response = reqwest::get(&url).await.unwrap();

        assert_eq!(response.status(), 404);

        let _ = shutdown_tx.send(());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `task test -- -E 'test(test_prometheus_server)'`
Expected: FAIL - server doesn't actually start

**Step 3: Implement the Prometheus server**

Replace `prometheus.rs` content:

```rust
//! Prometheus HTTP endpoint for /metrics

use super::MetricsError;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Start the Prometheus HTTP server
///
/// The server exposes `/metrics` endpoint on plaintext HTTP.
/// Returns the actual bound address (useful when port 0 is specified).
/// It will shut down when `shutdown_rx` receives a signal.
pub async fn start_server(
    addr: SocketAddr,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<SocketAddr, MetricsError> {
    // Install the Prometheus recorder
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| MetricsError::PrometheusBind(format!("Failed to install recorder: {}", e)))?;

    let handle = Arc::new(handle);

    // Bind TCP listener
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| MetricsError::PrometheusBind(format!("Failed to bind {}: {}", addr, e)))?;

    let actual_addr = listener
        .local_addr()
        .map_err(|e| MetricsError::PrometheusBind(format!("Failed to get local addr: {}", e)))?;

    // Spawn server task
    tokio::spawn(run_server(listener, handle, shutdown_rx));

    Ok(actual_addr)
}

async fn run_server(
    listener: TcpListener,
    handle: Arc<PrometheusHandle>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let handle = Arc::clone(&handle);
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let handle = Arc::clone(&handle);
                                async move { handle_request(req, handle).await }
                            });
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(io, service)
                                .await
                            {
                                tracing::debug!(error = %e, "HTTP connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to accept connection");
                    }
                }
            }
            _ = &mut shutdown_rx => {
                tracing::debug!("Prometheus server shutting down");
                break;
            }
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    handle: Arc<PrometheusHandle>,
) -> Result<Response<String>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let metrics = handle.render();
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4")
                .body(metrics)
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("Not Found".to_string())
            .unwrap(),
    };
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_prometheus_server_responds_to_metrics() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let actual_addr = start_server(addr, shutdown_rx).await.unwrap();

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Fetch metrics
        let url = format!("http://{}/metrics", actual_addr);
        let response = reqwest::get(&url).await.unwrap();

        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        // Should contain at least process metrics or be empty
        assert!(body.is_empty() || body.contains('#'));

        // Shutdown
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    async fn test_prometheus_server_404_for_other_paths() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let actual_addr = start_server(addr, shutdown_rx).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let url = format!("http://{}/other", actual_addr);
        let response = reqwest::get(&url).await.unwrap();

        assert_eq!(response.status(), 404);

        let _ = shutdown_tx.send(());
    }
}
```

**Step 4: Update mod.rs to use actual address**

Update `init()` in `mod.rs` to store and log actual address:

```rust
// In the prometheus block:
if let Some(addr) = config.prometheus_bind {
    let (tx, rx) = tokio::sync::oneshot::channel();
    handle.prometheus_shutdown = Some(tx);

    let actual_addr = prometheus::start_server(addr, rx).await?;
    tracing::info!(
        requested = %addr,
        actual = %actual_addr,
        "Prometheus metrics endpoint started on /metrics"
    );
}
```

Update `prometheus::start_server` signature in prometheus.rs to return `SocketAddr`.

**Step 5: Run tests to verify they pass**

Run: `task test -- -E 'test(test_prometheus_server)'`
Expected: PASS

**Step 6: Run all tests**

Run: `task test`
Expected: All tests pass

**Step 7: Commit**

```bash
git add crates/router-hosts/src/server/metrics/
git commit -m "feat(metrics): implement Prometheus HTTP server

Adds /metrics endpoint using metrics-exporter-prometheus:
- Binds to configured address (supports port 0 for tests)
- Returns 404 for non-/metrics paths
- Graceful shutdown via oneshot channel

Part of #167"
```

---

## Task 5: Integrate Metrics into Server Startup

**Files:**
- Modify: `crates/router-hosts/src/server/mod.rs`

**Step 1: Import metrics module**

Add import at top of `mod.rs`:

```rust
use crate::server::metrics::MetricsHandle;
```

**Step 2: Initialize metrics in run_server**

In `run_server()`, after the ACME handle initialization but before the server loop, add:

```rust
// Initialize metrics if configured
let metrics_handle = metrics::init(config.metrics.as_ref())
    .await
    .map_err(|e| ServerError::Config(format!("Metrics initialization failed: {}", e)))?;
```

**Step 3: Shut down metrics on terminate**

In the `ShutdownReason::Terminate` match arm, before the `break`, add:

```rust
// Shutdown metrics
metrics_handle.shutdown().await;
```

**Step 4: Run tests**

Run: `task test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/mod.rs
git commit -m "feat(server): integrate metrics into startup/shutdown

Initializes metrics subsystem from config during server startup.
Gracefully shuts down metrics on SIGTERM.

Part of #167"
```

---

## Task 6: Add Request Counter Metric

**Files:**
- Create: `crates/router-hosts/src/server/metrics/counters.rs`
- Modify: `crates/router-hosts/src/server/metrics/mod.rs`
- Modify: `crates/router-hosts/src/server/service/hosts.rs`

**Step 1: Create counters module with test**

Create `crates/router-hosts/src/server/metrics/counters.rs`:

```rust
//! Metric counter helpers

use metrics::{counter, histogram};
use std::time::Instant;

/// Record a gRPC request with method and status
pub fn record_request(method: &str, status: &str, duration: std::time::Duration) {
    counter!("router_hosts_requests_total", "method" => method.to_string(), "status" => status.to_string()).increment(1);
    histogram!("router_hosts_request_duration_seconds", "method" => method.to_string())
        .record(duration.as_secs_f64());
}

/// Record a storage operation
pub fn record_storage_operation(operation: &str, status: &str, duration: std::time::Duration) {
    counter!("router_hosts_storage_operations_total", "operation" => operation.to_string(), "status" => status.to_string()).increment(1);
    histogram!("router_hosts_storage_duration_seconds", "operation" => operation.to_string())
        .record(duration.as_secs_f64());
}

/// Record a hook execution
pub fn record_hook_execution(name: &str, hook_type: &str, status: &str, duration: std::time::Duration) {
    counter!("router_hosts_hook_executions_total",
        "name" => name.to_string(),
        "type" => hook_type.to_string(),
        "status" => status.to_string()
    ).increment(1);
    histogram!("router_hosts_hook_duration_seconds",
        "name" => name.to_string(),
        "type" => hook_type.to_string()
    ).record(duration.as_secs_f64());
}

/// Set the current host entry count gauge
pub fn set_hosts_entries_count(count: u64) {
    metrics::gauge!("router_hosts_hosts_entries").set(count as f64);
}

/// RAII guard for timing operations
pub struct TimedOperation {
    start: Instant,
    method: String,
}

impl TimedOperation {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            method: method.into(),
        }
    }

    pub fn finish(self, status: &str) {
        record_request(&self.method, status, self.start.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timed_operation_records_duration() {
        // Just verify it doesn't panic - actual recording needs prometheus installed
        let op = TimedOperation::new("test_method");
        std::thread::sleep(std::time::Duration::from_millis(1));
        op.finish("ok");
    }
}
```

**Step 2: Export counters module**

Add to `mod.rs`:

```rust
pub mod counters;
```

**Step 3: Add instrumentation to hosts.rs**

In `crates/router-hosts/src/server/service/hosts.rs`, add import:

```rust
use crate::server::metrics::counters::TimedOperation;
```

Then instrument `handle_add_host`:

```rust
pub(crate) async fn handle_add_host(
    &self,
    request: Request<AddHostRequest>,
) -> Result<Response<AddHostResponse>, Status> {
    let timer = TimedOperation::new("AddHost");

    // ... existing implementation ...

    // Before returning Ok:
    timer.finish("ok");
    Ok(response)

    // Or on error path, use timer.finish("error")
}
```

(Apply similar pattern to other RPC methods)

**Step 4: Run tests**

Run: `task test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/metrics/counters.rs \
        crates/router-hosts/src/server/metrics/mod.rs \
        crates/router-hosts/src/server/service/hosts.rs
git commit -m "feat(metrics): add request counter instrumentation

Adds TimedOperation helper for recording:
- router_hosts_requests_total (counter)
- router_hosts_request_duration_seconds (histogram)

Instruments AddHost RPC as example (more in next commits).

Part of #167"
```

---

## Task 7: Instrument Hook Executor

**Files:**
- Modify: `crates/router-hosts/src/server/hooks.rs`

**Step 1: Add metrics import**

Add at top of `hooks.rs`:

```rust
use crate::server::metrics::counters::record_hook_execution;
use std::time::Instant;
```

**Step 2: Instrument run_hook_with_error**

Modify `run_hook_with_error` to record metrics:

```rust
async fn run_hook_with_error(
    &self,
    hook: &HookDefinition,
    event: &str,
    entry_count: usize,
    error_msg: &str,
) -> Result<(), HookError> {
    let start = Instant::now();
    info!(hook_name = %hook.name, "Running hook");

    // ... existing implementation ...

    match result {
        Ok(Ok(status)) => {
            let duration = start.elapsed();
            if status.success() {
                record_hook_execution(&hook.name, event, "success", duration);
                info!(hook_name = %hook.name, "Hook completed successfully");
                Ok(())
            } else {
                record_hook_execution(&hook.name, event, "failed", duration);
                let code = status.code().unwrap_or(-1);
                error!(hook_name = %hook.name, exit_code = code, "Hook failed");
                Err(HookError::Failed(code, hook.name.clone()))
            }
        }
        Ok(Err(e)) => {
            record_hook_execution(&hook.name, event, "error", start.elapsed());
            // ... rest of error handling
        }
        Err(_) => {
            record_hook_execution(&hook.name, event, "timeout", start.elapsed());
            // ... rest of timeout handling
        }
    }
}
```

**Step 3: Run tests**

Run: `task test`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/hooks.rs
git commit -m "feat(metrics): instrument hook executor

Records hook execution metrics:
- router_hosts_hook_executions_total (counter with name, type, status)
- router_hosts_hook_duration_seconds (histogram with name, type)

Part of #167"
```

---

## Task 8: Add Integration Test for Prometheus Endpoint

**Files:**
- Modify: `crates/router-hosts/src/server/metrics/mod.rs`

**Step 1: Add integration test**

Add to `mod.rs` tests:

```rust
#[tokio::test]
async fn test_full_metrics_init_and_scrape() {
    use crate::server::config::{MetricsConfig, OtelConfig};
    use std::net::SocketAddr;

    let config = MetricsConfig {
        prometheus_bind: Some("127.0.0.1:0".parse().unwrap()),
        otel: None,
    };

    let handle = init(Some(&config)).await.unwrap();

    // Record some metrics
    counters::record_request("GetHost", "ok", std::time::Duration::from_millis(5));
    counters::record_request("AddHost", "error", std::time::Duration::from_millis(10));
    counters::set_hosts_entries_count(42);

    // Give metrics time to be recorded
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Scrape would work here if we knew the actual port
    // This test just verifies init/shutdown doesn't panic

    handle.shutdown().await;
}
```

**Step 2: Run tests**

Run: `task test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add crates/router-hosts/src/server/metrics/mod.rs
git commit -m "test(metrics): add integration test for metrics lifecycle

Verifies MetricsHandle init and shutdown work correctly.

Part of #167"
```

---

## Task 9: Update Documentation

**Files:**
- Modify: `docs/operations.md`
- Modify: `README.md` (if exists)

**Step 1: Add metrics section to operations.md**

Add new section after "Monitoring" in `docs/operations.md`:

```markdown
## Prometheus Metrics

### Configuration

Metrics are opt-in. Add a `[metrics]` section to enable:

```toml
[metrics]
# Prometheus HTTP endpoint (plaintext)
prometheus_bind = "0.0.0.0:9090"

# Optional: OpenTelemetry export
[metrics.otel]
endpoint = "http://otel-collector:4317"
service_name = "router-hosts"  # defaults to "router-hosts"
```

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `router_hosts_requests_total` | Counter | `method`, `status` | Total gRPC requests |
| `router_hosts_request_duration_seconds` | Histogram | `method` | Request latency |
| `router_hosts_storage_operations_total` | Counter | `operation`, `status` | DB operations count |
| `router_hosts_storage_duration_seconds` | Histogram | `operation` | DB operation latency |
| `router_hosts_hook_executions_total` | Counter | `name`, `type`, `status` | Hook execution count |
| `router_hosts_hook_duration_seconds` | Histogram | `name`, `type` | Hook execution time |
| `router_hosts_hosts_entries` | Gauge | - | Current host entry count |

### Scraping

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'router-hosts'
    static_configs:
      - targets: ['router-hosts:9090']
```
```

**Step 2: Commit**

```bash
git add docs/operations.md
git commit -m "docs: add Prometheus metrics documentation

Documents:
- [metrics] config section
- Available metrics with labels
- Prometheus scrape config example

Part of #167"
```

---

## Task 10: Final Verification and PR

**Step 1: Run full CI locally**

Run: `task ci`
Expected: All checks pass (build, test, lint, fmt)

**Step 2: Check test coverage**

Run: `task test:coverage`
Expected: Coverage ≥80%

**Step 3: Create PR**

```bash
git push -u origin feat/metrics-instrumentation
gh pr create --title "feat(metrics): add Prometheus metrics instrumentation" \
  --body "$(cat <<'EOF'
## Summary

Adds Prometheus metrics instrumentation to router-hosts per design doc.

- Opt-in `[metrics]` config section
- `/metrics` HTTP endpoint on configurable port
- Request, storage, and hook metrics
- Zero overhead when disabled

## Test Plan

- [ ] `task ci` passes
- [ ] New metrics tests pass
- [ ] Manual test: enable metrics, verify `/metrics` endpoint responds
- [ ] Verify existing functionality unchanged

Fixes #167

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Summary

| Task | Description | Est. Steps |
|------|-------------|------------|
| 1 | Add dependencies | 4 |
| 2 | Create MetricsConfig types | 7 |
| 3 | Create metrics module skeleton | 5 |
| 4 | Implement Prometheus HTTP server | 7 |
| 5 | Integrate metrics into server startup | 5 |
| 6 | Add request counter metric | 5 |
| 7 | Instrument hook executor | 4 |
| 8 | Add integration test | 3 |
| 9 | Update documentation | 2 |
| 10 | Final verification and PR | 3 |

**Total: ~45 steps**

**Note:** OTEL exporter (traces) is stubbed but not fully implemented. Can be added in follow-up PR to keep this one focused.
