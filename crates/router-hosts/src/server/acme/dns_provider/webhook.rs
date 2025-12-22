//! Generic webhook DNS provider implementation
//!
//! Provides a flexible HTTP webhook interface for custom DNS APIs that don't
//! have native provider support. This allows integration with any DNS service
//! that can expose a simple REST API.
//!
//! # Webhook Protocol
//!
//! ## Create Record
//!
//! ```text
//! POST {create_url}
//! Content-Type: application/json
//! {custom headers}
//!
//! {
//!     "type": "TXT",
//!     "name": "_acme-challenge.example.com",
//!     "content": "challenge-digest-value"
//! }
//! ```
//!
//! Expected response (200 OK):
//! ```json
//! {
//!     "id": "record-identifier"
//! }
//! ```
//!
//! ## Delete Record
//!
//! ```text
//! DELETE {delete_url with {record_id} replaced}
//! {custom headers}
//! ```
//!
//! Expected response: 200-299 status code

use super::{DnsProvider, DnsProviderError, DnsRecord};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};

/// Default propagation delay for webhook providers (conservative)
const WEBHOOK_PROPAGATION_DELAY: Duration = Duration::from_secs(120);

/// Default request timeout
#[allow(dead_code)] // Used in with_defaults() which is part of public API
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Generic webhook DNS provider
///
/// Manages TXT records via custom HTTP endpoints for ACME DNS-01 challenges.
pub struct WebhookProvider {
    client: reqwest::Client,
    create_url: String,
    delete_url: String,
    headers: HashMap<String, String>,
    propagation_delay: Duration,
}

impl WebhookProvider {
    /// Create a new webhook provider
    ///
    /// # Arguments
    ///
    /// * `create_url` - URL to POST for creating TXT records
    /// * `delete_url` - URL template to DELETE records (use `{record_id}` placeholder)
    /// * `headers` - Custom headers to include in requests (e.g., Authorization)
    /// * `timeout` - Request timeout
    pub fn new(
        create_url: String,
        delete_url: String,
        headers: HashMap<String, String>,
        timeout: Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("failed to build HTTP client");

        Self {
            client,
            create_url,
            delete_url,
            headers,
            propagation_delay: WEBHOOK_PROPAGATION_DELAY,
        }
    }

    /// Create provider with default timeout
    #[allow(dead_code)] // Public API for simplified construction
    pub fn with_defaults(
        create_url: String,
        delete_url: String,
        headers: HashMap<String, String>,
    ) -> Self {
        Self::new(create_url, delete_url, headers, DEFAULT_TIMEOUT)
    }

    /// Set custom propagation delay
    ///
    /// Use this if you know your DNS provider propagates faster than 120 seconds.
    #[allow(dead_code)] // Public API for custom propagation delay
    pub fn with_propagation_delay(mut self, delay: Duration) -> Self {
        self.propagation_delay = delay;
        self
    }

    /// Build custom headers for requests
    fn build_headers(&self) -> Result<HeaderMap, DnsProviderError> {
        let mut header_map = HeaderMap::new();
        header_map.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        for (key, value) in &self.headers {
            let header_name = HeaderName::try_from(key.as_str()).map_err(|e| {
                DnsProviderError::Config(format!("invalid header name '{}': {}", key, e))
            })?;
            let header_value = HeaderValue::from_str(value).map_err(|e| {
                DnsProviderError::Config(format!("invalid header value for '{}': {}", key, e))
            })?;
            header_map.insert(header_name, header_value);
        }

        Ok(header_map)
    }
}

#[async_trait]
impl DnsProvider for WebhookProvider {
    async fn create_txt_record(
        &self,
        name: &str,
        content: &str,
    ) -> Result<DnsRecord, DnsProviderError> {
        debug!(name = %name, url = %self.create_url, "Creating TXT record via webhook");

        let request_body = WebhookCreateRequest {
            record_type: "TXT".to_string(),
            name: name.to_string(),
            content: content.to_string(),
        };

        let headers = self.build_headers()?;

        let response = self
            .client
            .post(&self.create_url)
            .headers(headers)
            .json(&request_body)
            .send()
            .await?;

        let status = response.status();

        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_string());
            return Err(DnsProviderError::Api {
                status: status.as_u16(),
                message: body,
            });
        }

        let body: WebhookCreateResponse = response.json().await.map_err(|e| {
            DnsProviderError::Parse(format!("failed to parse create response: {}", e))
        })?;

        debug!(record_id = %body.id, "Created TXT record via webhook");

        Ok(DnsRecord {
            record_id: body.id,
            name: name.to_string(),
        })
    }

    async fn delete_txt_record(&self, record: &DnsRecord) -> Result<(), DnsProviderError> {
        // Substitute {record_id} in delete URL
        let url = self.delete_url.replace("{record_id}", &record.record_id);

        debug!(
            record_id = %record.record_id,
            name = %record.name,
            url = %url,
            "Deleting TXT record via webhook"
        );

        let headers = self.build_headers()?;

        let response = self.client.delete(&url).headers(headers).send().await?;

        let status = response.status();

        // 404 is acceptable - record may have been cleaned up already
        if status == reqwest::StatusCode::NOT_FOUND {
            debug!(record_id = %record.record_id, "Record already deleted");
            return Ok(());
        }

        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read body>".to_string());
            // Log but don't necessarily fail - cleanup is best-effort
            warn!(status = %status, body = %body, "Webhook delete returned non-success status");
            return Err(DnsProviderError::Api {
                status: status.as_u16(),
                message: body,
            });
        }

        debug!(record_id = %record.record_id, "Deleted TXT record via webhook");
        Ok(())
    }

    fn propagation_delay(&self) -> Duration {
        self.propagation_delay
    }

    fn name(&self) -> &'static str {
        "webhook"
    }
}

// ============================================================================
// Webhook Protocol Types
// ============================================================================

/// Request body for creating a TXT record
#[derive(Debug, Serialize)]
struct WebhookCreateRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
}

/// Expected response from create endpoint
#[derive(Debug, Deserialize)]
struct WebhookCreateResponse {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_provider_name() {
        let provider = WebhookProvider::with_defaults(
            "http://create".into(),
            "http://delete".into(),
            HashMap::new(),
        );
        assert_eq!(provider.name(), "webhook");
    }

    #[test]
    fn test_webhook_propagation_delay_default() {
        let provider = WebhookProvider::with_defaults(
            "http://create".into(),
            "http://delete".into(),
            HashMap::new(),
        );
        assert_eq!(provider.propagation_delay(), Duration::from_secs(120));
    }

    #[test]
    fn test_webhook_propagation_delay_custom() {
        let provider = WebhookProvider::with_defaults(
            "http://create".into(),
            "http://delete".into(),
            HashMap::new(),
        )
        .with_propagation_delay(Duration::from_secs(30));
        assert_eq!(provider.propagation_delay(), Duration::from_secs(30));
    }

    #[test]
    fn test_delete_url_substitution() {
        let delete_url = "https://api.example.com/dns/records/{record_id}";
        let record_id = "rec_abc123";
        let url = delete_url.replace("{record_id}", record_id);
        assert_eq!(url, "https://api.example.com/dns/records/rec_abc123");
    }

    #[test]
    fn test_build_headers_valid() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token123".to_string());
        headers.insert("X-Custom".to_string(), "value".to_string());

        let provider =
            WebhookProvider::with_defaults("http://create".into(), "http://delete".into(), headers);

        let result = provider.build_headers();
        assert!(result.is_ok());

        let header_map = result.unwrap();
        assert!(header_map.contains_key("authorization"));
        assert!(header_map.contains_key("x-custom"));
        assert!(header_map.contains_key("content-type"));
    }

    // Integration tests with mock server are in tests/dns_provider_test.rs
}
