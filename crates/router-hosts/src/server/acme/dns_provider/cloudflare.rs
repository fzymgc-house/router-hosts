//! Cloudflare DNS provider implementation
//!
//! Uses Cloudflare REST API v4 to manage DNS TXT records for ACME challenges.
//!
//! # API Endpoints Used
//!
//! - `GET /zones?name={domain}` - Look up zone ID from domain
//! - `POST /zones/{zone_id}/dns_records` - Create TXT record
//! - `DELETE /zones/{zone_id}/dns_records/{record_id}` - Delete record
//!
//! # Required Permissions
//!
//! The API token must have `Zone:DNS:Edit` permission for the target zone.

use super::{DnsProvider, DnsProviderError, DnsRecord};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, warn};

/// Cloudflare API base URL
const CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare DNS propagation delay (typically very fast)
const CLOUDFLARE_PROPAGATION_DELAY: Duration = Duration::from_secs(10);

/// Default DNS record TTL for ACME challenge records (minimum allowed by Cloudflare)
const CLOUDFLARE_DNS_TTL: u32 = 60;

/// Cloudflare DNS provider
///
/// Manages TXT records via Cloudflare's REST API for ACME DNS-01 challenges.
#[derive(Debug)]
pub struct CloudflareProvider {
    client: reqwest::Client,
    #[allow(dead_code)] // Used in auth_headers(), needed for Debug
    api_token: String,
    zone_id: String,
}

impl CloudflareProvider {
    /// Create a new Cloudflare provider with explicit zone ID
    ///
    /// Use this when the zone ID is known (e.g., from configuration).
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built or if the API token
    /// contains invalid header characters.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = CloudflareProvider::new(
    ///     "my-api-token".to_string(),
    ///     "zone123abc".to_string(),
    /// )?;
    /// ```
    pub fn new(api_token: String, zone_id: String) -> Result<Self, DnsProviderError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| DnsProviderError::Config(format!("failed to build HTTP client: {}", e)))?;

        // Validate API token can be used in headers (fail early)
        HeaderValue::from_str(&format!("Bearer {}", api_token)).map_err(|_| {
            DnsProviderError::Config("API token contains invalid characters".to_string())
        })?;

        Ok(Self {
            client,
            api_token,
            zone_id,
        })
    }

    /// Create a new Cloudflare provider with auto-detected zone ID
    ///
    /// Looks up the zone ID from the domain name using the Cloudflare API.
    /// This is useful when only the domain is known.
    ///
    /// # Arguments
    ///
    /// * `api_token` - Cloudflare API token with Zone:Read permission
    /// * `domain` - Domain name to look up (e.g., "example.com")
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built, if the API token
    /// is invalid, or if the zone cannot be found.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let provider = CloudflareProvider::with_auto_zone(
    ///     "my-api-token".to_string(),
    ///     "example.com",
    /// ).await?;
    /// ```
    pub async fn with_auto_zone(api_token: String, domain: &str) -> Result<Self, DnsProviderError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| DnsProviderError::Config(format!("failed to build HTTP client: {}", e)))?;

        // Validate API token can be used in headers (fail early)
        HeaderValue::from_str(&format!("Bearer {}", api_token)).map_err(|_| {
            DnsProviderError::Config("API token contains invalid characters".to_string())
        })?;

        let zone_id = Self::lookup_zone_id(&client, &api_token, domain).await?;

        Ok(Self {
            client,
            api_token,
            zone_id,
        })
    }

    /// Look up zone ID from domain name
    ///
    /// Extracts the registrable domain (e.g., "sub.example.com" -> "example.com")
    /// and queries Cloudflare for matching zones.
    async fn lookup_zone_id(
        client: &reqwest::Client,
        api_token: &str,
        domain: &str,
    ) -> Result<String, DnsProviderError> {
        // Try progressively shorter domain suffixes to find the zone
        // e.g., for "sub.example.com": try "sub.example.com", then "example.com"
        let parts: Vec<&str> = domain.split('.').collect();

        for i in 0..parts.len().saturating_sub(1) {
            let zone_name = parts[i..].join(".");

            debug!(zone_name = %zone_name, "Looking up Cloudflare zone");

            let url = format!("{}/zones?name={}", CLOUDFLARE_API_URL, zone_name);
            let response = client
                .get(&url)
                .header(AUTHORIZATION, format!("Bearer {}", api_token))
                .send()
                .await?;

            let status = response.status();
            let body: CloudflareResponse<Vec<Zone>> = response.json().await?;

            if !body.success {
                let errors = body
                    .errors
                    .iter()
                    .map(|e| format!("{}: {}", e.code, e.message))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(DnsProviderError::Api {
                    status: status.as_u16(),
                    message: errors,
                });
            }

            // Find exact match for zone name to avoid returning wrong zone
            // when multiple zones could match (e.g., example.com and sub.example.com)
            if let Some(zone) = body.result.into_iter().find(|z| z.name == zone_name) {
                debug!(zone_id = %zone.id, zone_name = %zone.name, "Found Cloudflare zone");
                return Ok(zone.id);
            }
        }

        Err(DnsProviderError::ZoneNotFound(domain.to_string()))
    }

    /// Build authorization headers for API requests
    ///
    /// Since we validate the token in the constructor, this should never fail.
    fn auth_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        // Token was validated in constructor, so this unwrap is safe
        if let Ok(value) = HeaderValue::from_str(&format!("Bearer {}", self.api_token)) {
            headers.insert(AUTHORIZATION, value);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn create_txt_record(
        &self,
        name: &str,
        content: &str,
    ) -> Result<DnsRecord, DnsProviderError> {
        debug!(name = %name, "Creating Cloudflare TXT record");

        let url = format!("{}/zones/{}/dns_records", CLOUDFLARE_API_URL, self.zone_id);

        let request_body = CreateDnsRecord {
            record_type: "TXT".to_string(),
            name: name.to_string(),
            content: content.to_string(),
            ttl: CLOUDFLARE_DNS_TTL,
        };

        let response = self
            .client
            .post(&url)
            .headers(self.auth_headers())
            .json(&request_body)
            .send()
            .await?;

        let status = response.status();
        let body: CloudflareResponse<DnsRecordResponse> = response.json().await?;

        if !body.success {
            let errors = body
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(DnsProviderError::Api {
                status: status.as_u16(),
                message: errors,
            });
        }

        debug!(record_id = %body.result.id, "Created Cloudflare TXT record");

        Ok(DnsRecord {
            record_id: body.result.id,
            name: name.to_string(),
        })
    }

    async fn delete_txt_record(&self, record: &DnsRecord) -> Result<(), DnsProviderError> {
        debug!(record_id = %record.record_id, name = %record.name, "Deleting Cloudflare TXT record");

        let url = format!(
            "{}/zones/{}/dns_records/{}",
            CLOUDFLARE_API_URL, self.zone_id, record.record_id
        );

        let response = self
            .client
            .delete(&url)
            .headers(self.auth_headers())
            .send()
            .await?;

        let status = response.status();

        // 404 is acceptable - record may have been cleaned up already
        if status == reqwest::StatusCode::NOT_FOUND {
            debug!(record_id = %record.record_id, "Record already deleted");
            return Ok(());
        }

        let body: CloudflareResponse<DeleteResponse> = response.json().await?;

        if !body.success {
            let errors = body
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.code, e.message))
                .collect::<Vec<_>>()
                .join(", ");
            // Log but don't fail - cleanup is best-effort
            warn!(errors = %errors, "Failed to delete Cloudflare TXT record");
            return Err(DnsProviderError::Api {
                status: status.as_u16(),
                message: errors,
            });
        }

        debug!(record_id = %record.record_id, "Deleted Cloudflare TXT record");
        Ok(())
    }

    fn propagation_delay(&self) -> Duration {
        CLOUDFLARE_PROPAGATION_DELAY
    }

    fn name(&self) -> &'static str {
        "cloudflare"
    }
}

// ============================================================================
// Cloudflare API Types
// ============================================================================

/// Standard Cloudflare API response wrapper
#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CloudflareError>,
    result: T,
}

/// Cloudflare API error
#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: i32,
    message: String,
}

/// Zone information from Cloudflare API
#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
    name: String,
}

/// Request body for creating a DNS record
#[derive(Debug, Serialize)]
struct CreateDnsRecord {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

/// Response from creating a DNS record
#[derive(Debug, Deserialize)]
struct DnsRecordResponse {
    id: String,
}

/// Response from deleting a DNS record
#[derive(Debug, Deserialize)]
struct DeleteResponse {
    #[allow(dead_code)]
    id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_provider_name() {
        let provider = CloudflareProvider::new("token".to_string(), "zone123".to_string())
            .expect("valid token");
        assert_eq!(provider.name(), "cloudflare");
    }

    #[test]
    fn test_cloudflare_propagation_delay() {
        let provider = CloudflareProvider::new("token".to_string(), "zone123".to_string())
            .expect("valid token");
        assert_eq!(provider.propagation_delay(), Duration::from_secs(10));
    }

    #[test]
    fn test_cloudflare_provider_invalid_token() {
        // API tokens with invalid header characters should fail
        let result =
            CloudflareProvider::new("token\x00with\x00nulls".to_string(), "zone123".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DnsProviderError::Config(_)));
    }

    // Integration tests with mock server are in tests/dns_provider_test.rs
}
