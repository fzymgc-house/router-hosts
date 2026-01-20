//! Tracing subscriber setup with optional OpenTelemetry integration
//!
//! Configures the global tracing subscriber with:
//! - Console output (fmt layer)
//! - Optional OTEL trace export (via tracing-opentelemetry)

use crate::server::config::OtelConfig;
use crate::server::metrics::otel;
use crate::server::metrics::MetricsError;
use opentelemetry::trace::TracerProvider;
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
    ///
    /// Returns an error if OTEL provider shutdown fails (traces may not have been flushed).
    /// Callers should log the error but may choose to continue server shutdown.
    pub fn shutdown(mut self) -> Result<(), MetricsError> {
        if let Some(provider) = self.tracer_provider.take() {
            provider.shutdown().map_err(|e| {
                MetricsError::OtelInit(format!("Failed to shutdown OTEL tracer provider: {:?}", e))
            })?;
            info!("OTEL tracer provider shut down");
        }
        Ok(())
    }
}

impl Drop for TracingHandle {
    fn drop(&mut self) {
        if self.tracer_provider.is_some() {
            tracing::warn!(
                "TracingHandle dropped without calling shutdown() - \
                 OTEL traces may not be flushed"
            );
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
    // Integration tests would require careful setup due to global subscriber.
    // The tracing subscriber can only be set once per process.
    // Unit tests for configuration parsing are in config.rs.
    // Full integration testing is done in E2E tests.
}
