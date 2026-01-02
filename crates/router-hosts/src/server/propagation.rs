//! W3C Trace Context propagation for gRPC requests
//!
//! Extracts trace context from incoming gRPC metadata and creates
//! parent spans for distributed tracing.

use opentelemetry::propagation::TextMapPropagator;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tonic::metadata::MetadataMap;

/// Extract trace context from gRPC metadata
pub struct MetadataExtractor<'a>(pub &'a MetadataMap);

impl opentelemetry::propagation::Extractor for MetadataExtractor<'_> {
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
    use opentelemetry::propagation::Extractor;
    use opentelemetry::trace::TraceContextExt;

    #[test]
    fn test_extract_empty_metadata() {
        let metadata = MetadataMap::new();
        let ctx = extract_context(&metadata);
        // Should return empty context without panic
        let span = ctx.span();
        let span_ctx = span.span_context();
        assert!(!span_ctx.is_valid());
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
        let span = ctx.span();
        let span_ctx = span.span_context();
        assert!(span_ctx.is_valid());
        assert_eq!(
            span_ctx.trace_id().to_string(),
            "0af7651916cd43dd8448eb211c80319c"
        );
    }

    #[test]
    fn test_extract_with_tracestate() {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
                .parse()
                .unwrap(),
        );
        metadata.insert("tracestate", "vendor=value".parse().unwrap());
        let ctx = extract_context(&metadata);
        let span = ctx.span();
        let span_ctx = span.span_context();
        assert!(span_ctx.is_valid());
        // Tracestate is preserved in the context - check header count
        assert!(span_ctx.trace_state().header().len() > 0);
    }

    #[test]
    fn test_metadata_extractor_keys() {
        let mut metadata = MetadataMap::new();
        metadata.insert("traceparent", "test".parse().unwrap());
        metadata.insert("custom-header", "value".parse().unwrap());

        let extractor = MetadataExtractor(&metadata);
        let keys = extractor.keys();

        assert!(keys.contains(&"traceparent"));
        assert!(keys.contains(&"custom-header"));
    }
}
