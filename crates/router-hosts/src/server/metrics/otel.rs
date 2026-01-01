//! OpenTelemetry exporter setup
//!
//! Provides trace and metrics export via OTLP/gRPC to an OpenTelemetry collector.

use crate::server::config::OtelConfig;
use crate::server::metrics::MetricsError;
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{metrics::SdkMeterProvider, trace::SdkTracerProvider, Resource};
use std::time::Duration;
use tonic::metadata::{MetadataKey, MetadataMap};
use tracing::info;

/// Build OTEL resource with service name and standard attributes
fn build_resource(service_name: &str) -> Resource {
    Resource::builder()
        .with_service_name(service_name.to_string())
        .build()
}

/// Build metadata map from config headers
fn build_metadata(
    headers: &std::collections::HashMap<String, String>,
) -> Result<MetadataMap, MetricsError> {
    let mut metadata = MetadataMap::with_capacity(headers.len());
    for (key, value) in headers {
        let metadata_key: MetadataKey<_> = key
            .parse()
            .map_err(|e| MetricsError::OtelInit(format!("Invalid header key '{}': {}", key, e)))?;
        let parsed_value = value.parse().map_err(|e| {
            MetricsError::OtelInit(format!("Invalid header value for '{}': {}", key, e))
        })?;
        metadata.insert(metadata_key, parsed_value);
    }
    Ok(metadata)
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

    let metadata = build_metadata(&config.headers)?;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .with_metadata(metadata)
        .build()
        .map_err(|e| {
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
/// Returns a meter provider that exports metrics to the configured endpoint.
/// Returns None if export_metrics is false.
pub fn init_metrics(config: &OtelConfig) -> Result<Option<SdkMeterProvider>, MetricsError> {
    if !config.export_metrics {
        info!("OTEL metrics export disabled by configuration");
        return Ok(None);
    }

    let metadata = build_metadata(&config.headers)?;

    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(&config.endpoint)
        .with_metadata(metadata)
        .build()
        .map_err(|e| {
            MetricsError::OtelInit(format!("Failed to build OTLP metrics exporter: {}", e))
        })?;

    let resource = build_resource(config.service_name());

    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(60))
        .build();

    let provider = SdkMeterProvider::builder()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_build_resource_includes_service_name() {
        let resource = build_resource("test-service");
        let attrs: Vec<_> = resource.iter().collect();
        assert!(attrs
            .iter()
            .any(|(k, v)| k.as_str() == "service.name" && v.as_str() == "test-service"));
    }

    #[test]
    fn test_build_metadata_empty() {
        let headers = HashMap::new();
        let metadata = build_metadata(&headers).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_build_metadata_with_headers() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer token123".to_string());
        headers.insert("x-custom".to_string(), "value".to_string());

        let metadata = build_metadata(&headers).unwrap();
        assert_eq!(metadata.len(), 2);
    }

    #[test]
    fn test_disabled_tracer_returns_none() {
        let config = OtelConfig {
            endpoint: "http://localhost:4317".to_string(),
            service_name: "router-hosts".to_string(),
            export_metrics: true,
            export_traces: false,
            headers: HashMap::new(),
        };
        let result = init_tracer(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_disabled_metrics_returns_none() {
        let config = OtelConfig {
            endpoint: "http://localhost:4317".to_string(),
            service_name: "router-hosts".to_string(),
            export_metrics: false,
            export_traces: true,
            headers: HashMap::new(),
        };
        let result = init_metrics(&config).unwrap();
        assert!(result.is_none());
    }
}
