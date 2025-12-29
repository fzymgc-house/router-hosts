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
