//! DNS provider abstraction for ACME DNS-01 challenges
//!
//! This module provides a trait-based abstraction for DNS providers that can
//! manage TXT records for ACME DNS-01 challenge validation. Implementations
//! are provided for:
//!
//! - **Cloudflare** - Built-in support via REST API v4
//! - **Webhook** - Generic HTTP webhook for custom DNS APIs
//!
//! # DNS-01 Challenge Flow
//!
//! 1. ACME server provides a token for the challenge
//! 2. Client computes digest: `base64url(sha256(key_authorization))`
//! 3. Client creates TXT record at `_acme-challenge.<domain>`
//! 4. Client waits for DNS propagation
//! 5. Client notifies ACME server the challenge is ready
//! 6. ACME server validates the TXT record
//! 7. Client cleans up the TXT record
//!
//! # Example
//!
//! ```ignore
//! use router_hosts::server::acme::dns_provider::{DnsProvider, CloudflareProvider};
//!
//! let provider = CloudflareProvider::new(api_token, zone_id);
//! let record = provider.create_txt_record("_acme-challenge.example.com", digest).await?;
//! provider.wait_for_propagation().await;
//! // ... ACME validation happens ...
//! provider.delete_txt_record(&record).await?;
//! ```

mod cloudflare;
mod webhook;

pub use cloudflare::CloudflareProvider;
pub use webhook::WebhookProvider;

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// Default propagation delay for providers that don't specify one
const DEFAULT_PROPAGATION_DELAY: Duration = Duration::from_secs(10);

/// Errors that can occur during DNS provider operations
#[derive(Debug, Error)]
pub enum DnsProviderError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    /// DNS API returned an error
    #[error("DNS API error: {status} - {message}")]
    Api { status: u16, message: String },

    /// Failed to parse API response
    #[error("failed to parse API response: {0}")]
    Parse(String),

    /// Zone not found for domain
    #[error("zone not found for domain: {0}")]
    ZoneNotFound(String),

    /// No DNS provider configured
    #[error("no DNS provider configured")]
    #[allow(dead_code)] // Will be used when DNS provider factory is implemented
    NoProviderConfigured,

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),
}

/// Result of creating a DNS TXT record
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Provider-specific record identifier for cleanup
    pub record_id: String,
    /// The full record name (e.g., "_acme-challenge.example.com")
    pub name: String,
}

/// Trait for DNS providers that can manage ACME challenge TXT records
///
/// Implementations must be thread-safe (`Send + Sync`) to allow concurrent
/// use across async tasks.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create a TXT record for ACME DNS-01 challenge
    ///
    /// # Arguments
    ///
    /// * `name` - Full record name (e.g., "_acme-challenge.example.com")
    /// * `content` - The challenge digest value
    ///
    /// # Returns
    ///
    /// A `DnsRecord` containing the record ID for later cleanup
    async fn create_txt_record(
        &self,
        name: &str,
        content: &str,
    ) -> Result<DnsRecord, DnsProviderError>;

    /// Delete a previously created TXT record
    ///
    /// This is best-effort cleanup - errors are logged but should not
    /// fail the overall certificate request.
    async fn delete_txt_record(&self, record: &DnsRecord) -> Result<(), DnsProviderError>;

    /// Wait for DNS propagation
    ///
    /// Different providers have different propagation times. Cloudflare is
    /// typically fast (10s), while generic webhooks may need longer (120s).
    async fn wait_for_propagation(&self) {
        tokio::time::sleep(self.propagation_delay()).await;
    }

    /// Get the propagation delay for this provider
    ///
    /// Override this to customize the delay for specific providers.
    fn propagation_delay(&self) -> Duration {
        DEFAULT_PROPAGATION_DELAY
    }

    /// Get provider name for logging
    fn name(&self) -> &'static str;
}

/// Compute the DNS-01 challenge digest
///
/// Per RFC 8555 Section 8.4, the TXT record value is:
/// `base64url(sha256(key_authorization))`
///
/// The key authorization is provided by the ACME client and is:
/// `token.account_thumbprint`
pub fn compute_dns01_digest(key_authorization: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let hash = Sha256::digest(key_authorization.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_compute_dns01_digest() {
        // Test vector from RFC 8555 examples
        // The digest should be a base64url-encoded SHA256 hash
        let key_auth = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.nKr0aEKSHVgvr5zjKjKz1dNWLcGjT1VFJrCeaLqI3vk";
        let digest = compute_dns01_digest(key_auth);

        // Verify it's valid base64url (no padding, URL-safe characters)
        assert!(!digest.contains('='), "digest should not contain padding");
        assert!(!digest.contains('+'), "digest should use URL-safe encoding");
        assert!(!digest.contains('/'), "digest should use URL-safe encoding");

        // Verify length (SHA256 = 32 bytes = 43 base64url chars without padding)
        assert_eq!(digest.len(), 43);
    }

    #[test]
    fn test_compute_dns01_digest_consistency() {
        // Same input should always produce same output
        let key_auth = "test-token.test-thumbprint";
        let digest1 = compute_dns01_digest(key_auth);
        let digest2 = compute_dns01_digest(key_auth);
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_dns_record_clone() {
        let record = DnsRecord {
            record_id: "abc123".to_string(),
            name: "_acme-challenge.example.com".to_string(),
        };
        let cloned = record.clone();
        assert_eq!(cloned.record_id, record.record_id);
        assert_eq!(cloned.name, record.name);
    }

    #[test]
    fn test_dns_provider_error_display() {
        let err = DnsProviderError::ZoneNotFound("example.com".to_string());
        assert!(err.to_string().contains("example.com"));

        let err = DnsProviderError::Api {
            status: 403,
            message: "forbidden".to_string(),
        };
        assert!(err.to_string().contains("403"));
        assert!(err.to_string().contains("forbidden"));
    }

    proptest! {
        /// Property-based test for compute_dns01_digest
        ///
        /// Verifies:
        /// - Output is always 43 characters (base64url of SHA256 without padding)
        /// - Output contains only valid base64url characters
        /// - Same input always produces same output (deterministic)
        #[test]
        fn proptest_compute_dns01_digest(input in ".*") {
            let digest = compute_dns01_digest(&input);

            // SHA256 = 32 bytes = 43 base64url chars without padding
            prop_assert_eq!(digest.len(), 43);

            // Must be valid base64url (no padding, URL-safe characters)
            prop_assert!(!digest.contains('='), "digest should not contain padding");
            prop_assert!(!digest.contains('+'), "digest should use URL-safe encoding");
            prop_assert!(!digest.contains('/'), "digest should use URL-safe encoding");

            // All characters must be valid base64url
            for c in digest.chars() {
                prop_assert!(
                    c.is_ascii_alphanumeric() || c == '-' || c == '_',
                    "invalid base64url character: {}",
                    c
                );
            }

            // Deterministic: same input produces same output
            let digest2 = compute_dns01_digest(&input);
            prop_assert_eq!(digest, digest2);
        }
    }
}
