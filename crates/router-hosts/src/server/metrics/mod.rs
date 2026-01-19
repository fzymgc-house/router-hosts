//! Metrics and observability instrumentation
//!
//! This module provides OpenTelemetry integration for metrics and distributed tracing.
//! All metrics recorded via `counter!()`, `histogram!()`, and `gauge!()` macros are
//! exported to an OTEL collector via OTLP/gRPC.
//!
//! # Configuration
//!
//! Metrics are opt-in. Add a `[metrics.otel]` section to enable:
//!
//! ```toml
//! [metrics.otel]
//! endpoint = "http://otel-collector:4317"
//! service_name = "router-hosts"  # Optional, defaults to "router-hosts"
//! export_metrics = true          # Optional, defaults to true
//! export_traces = true           # Optional, defaults to true
//! ```

pub mod counters;
pub mod otel;

use crate::server::config::MetricsConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("Failed to initialize OTEL exporter: {0}")]
    OtelInit(String),
}

/// Handle for the metrics subsystem
///
/// Dropping this handle will flush any pending OTEL exports.
pub struct MetricsHandle {
    /// OTEL meter provider for metrics export
    otel_meter_provider: Option<SdkMeterProvider>,
}

impl MetricsHandle {
    /// Create a disabled metrics handle (no-op)
    pub fn disabled() -> Self {
        Self {
            otel_meter_provider: None,
        }
    }

    /// Gracefully shut down metrics subsystem
    ///
    /// Returns an error if OTEL provider shutdown fails (metrics may not have been flushed).
    /// Callers should log the error but may choose to continue server shutdown.
    pub async fn shutdown(mut self) -> Result<(), MetricsError> {
        if let Some(provider) = self.otel_meter_provider.take() {
            provider.shutdown().map_err(|e| {
                MetricsError::OtelInit(format!("Failed to shutdown OTEL meter provider: {}", e))
            })?;
        }
        Ok(())
    }
}

impl Drop for MetricsHandle {
    fn drop(&mut self) {
        if self.otel_meter_provider.is_some() {
            tracing::warn!(
                target: "router_hosts::metrics",
                "MetricsHandle dropped without calling shutdown(). \
                 OTEL metrics may not be flushed. \
                 Ensure MetricsHandle::shutdown() is awaited during graceful server shutdown \
                 (see server/mod.rs shutdown sequence)."
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
        otel_meter_provider: None,
    };

    // Initialize OTEL metrics if configured
    if let Some(otel_config) = &config.otel {
        match otel::init_metrics(otel_config)? {
            Some(provider) => {
                handle.otel_meter_provider = Some(provider);
                tracing::info!(
                    endpoint = %otel_config.endpoint,
                    "OTEL metrics export initialized (all metrics routed via OTEL)"
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

    #[tokio::test]
    async fn test_init_with_none_returns_disabled() {
        let handle = init(None).await.unwrap();
        assert!(handle.otel_meter_provider.is_none());
    }

    #[tokio::test]
    async fn test_disabled_shutdown_is_noop() {
        let handle = MetricsHandle::disabled();
        handle.shutdown().await.unwrap(); // Should not panic or error
    }

    #[tokio::test]
    #[serial]
    async fn test_otel_disabled_by_export_flag() {
        use crate::server::config::{MetricsConfig, OtelConfig};
        use std::collections::HashMap;

        let config = MetricsConfig {
            otel: Some(OtelConfig {
                endpoint: "http://localhost:4317".to_string(),
                service_name: "router-hosts".to_string(),
                export_metrics: false,
                export_traces: false,
                export_interval_secs: 60,
                headers: HashMap::new(),
            }),
        };

        let handle = init(Some(&config)).await.unwrap();

        // OTEL configured but export_metrics is false
        assert!(handle.otel_meter_provider.is_none());

        handle.shutdown().await.unwrap();
    }
}
