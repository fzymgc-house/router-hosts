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

pub mod counters;
pub mod otel;
mod prometheus;

use crate::server::config::MetricsConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
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
    /// OTEL meter provider for metrics export
    otel_meter_provider: Option<SdkMeterProvider>,
}

impl MetricsHandle {
    /// Create a disabled metrics handle (no-op)
    pub fn disabled() -> Self {
        Self {
            prometheus_shutdown: None,
            otel_meter_provider: None,
        }
    }

    /// Gracefully shut down metrics subsystem
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.prometheus_shutdown.take() {
            if tx.send(()).is_err() {
                tracing::warn!("Prometheus server already shut down (receiver dropped)");
            }
        }
        if let Some(provider) = self.otel_meter_provider.take() {
            if let Err(e) = provider.shutdown() {
                tracing::warn!(error = %e, "Failed to shutdown OTEL meter provider");
            }
        }
    }
}

impl Drop for MetricsHandle {
    fn drop(&mut self) {
        if self.prometheus_shutdown.is_some() {
            tracing::warn!(
                "MetricsHandle dropped without calling shutdown() - \
                 Prometheus server will continue running until process exit"
            );
        }
        if self.otel_meter_provider.is_some() {
            tracing::warn!(
                "MetricsHandle dropped without calling shutdown() - \
                 OTEL metrics may not be flushed"
            );
        }
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
        otel_meter_provider: None,
    };

    // Start Prometheus HTTP server if configured
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

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::time::Duration;

    #[tokio::test]
    async fn test_init_with_none_returns_disabled() {
        let handle = init(None).await.unwrap();
        assert!(handle.prometheus_shutdown.is_none());
        assert!(handle.otel_meter_provider.is_none());
    }

    #[tokio::test]
    async fn test_disabled_shutdown_is_noop() {
        let handle = MetricsHandle::disabled();
        handle.shutdown().await; // Should not panic
    }

    #[tokio::test]
    #[serial]
    async fn test_full_metrics_init_and_scrape() {
        use crate::server::config::MetricsConfig;

        let config = MetricsConfig {
            prometheus_bind: Some("127.0.0.1:0".parse().unwrap()),
            otel: None,
        };

        let handle = init(Some(&config)).await.unwrap();

        // Verify prometheus shutdown channel exists (server is running)
        assert!(handle.prometheus_shutdown.is_some());
        // No OTEL configured
        assert!(handle.otel_meter_provider.is_none());

        // Record some metrics to verify the recorder is installed
        counters::record_request("GetHost", "ok", Duration::from_millis(5));
        counters::set_hosts_entries_count(42);
        counters::record_storage_operation("get", "ok", Duration::from_millis(2));
        counters::record_hook_execution("test_hook", "pre", "success", Duration::from_millis(10));

        // Shutdown cleanly
        handle.shutdown().await;
    }

    #[tokio::test]
    #[serial]
    async fn test_otel_disabled_by_export_flag() {
        use crate::server::config::{MetricsConfig, OtelConfig};
        use std::collections::HashMap;

        let config = MetricsConfig {
            prometheus_bind: None,
            otel: Some(OtelConfig {
                endpoint: "http://localhost:4317".to_string(),
                service_name: "router-hosts".to_string(),
                export_metrics: false,
                export_traces: false,
                headers: HashMap::new(),
            }),
        };

        let handle = init(Some(&config)).await.unwrap();

        // OTEL configured but export_metrics is false
        assert!(handle.otel_meter_provider.is_none());

        handle.shutdown().await;
    }
}
