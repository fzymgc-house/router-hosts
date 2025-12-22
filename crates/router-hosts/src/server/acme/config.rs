//! ACME configuration types and parsing
//!
//! This module defines the configuration schema for ACME certificate management.
//! Configuration values support environment variable expansion via `${VAR}` syntax.

use super::env_expand::{expand_env_vars, EnvExpandError};
use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during ACME configuration parsing
#[derive(Debug, Error)]
pub enum AcmeConfigError {
    /// Environment variable expansion failed
    #[error("failed to expand environment variable: {0}")]
    EnvExpand(#[from] EnvExpandError),

    /// Invalid configuration value
    #[error("invalid configuration: {0}")]
    Invalid(String),

    /// Missing required configuration field
    #[error("missing required field: {0}")]
    MissingField(String),
}

/// ACME challenge type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum ChallengeType {
    /// HTTP-01 challenge - requires port 80 accessible
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    /// DNS-01 challenge - requires DNS API access
    #[serde(rename = "dns-01")]
    Dns01,
}

/// Top-level ACME configuration
///
/// # Example Configuration
///
/// ```toml
/// [acme]
/// enabled = true
/// directory_url = "https://acme-v02.api.letsencrypt.org/directory"
/// email = "admin@example.com"
/// domains = ["router.example.com"]
/// challenge_type = "http-01"
/// credentials_path = "/var/lib/router-hosts/acme-account.json"
///
/// [acme.http]
/// bind_address = "0.0.0.0:80"
///
/// # OR for DNS-01:
/// [acme.dns.cloudflare]
/// api_token = "${CLOUDFLARE_API_TOKEN}"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[allow(dead_code)] // Fields will be used in ACME client implementation
pub struct AcmeConfig {
    /// Whether ACME is enabled (default: false)
    pub enabled: bool,

    /// ACME directory URL
    /// Default: Let's Encrypt production
    #[serde(default = "default_directory_url")]
    pub directory_url: String,

    /// Contact email for ACME account
    pub email: Option<String>,

    /// Domains to request certificates for
    #[serde(default)]
    pub domains: Vec<String>,

    /// Challenge type to use
    #[serde(default)]
    pub challenge_type: ChallengeType,

    /// Path to store ACME account credentials
    /// Default: /var/lib/router-hosts/acme-account.json
    #[serde(default = "default_credentials_path")]
    pub credentials_path: std::path::PathBuf,

    /// HTTP-01 challenge configuration
    pub http: Option<HttpChallengeConfig>,

    /// DNS-01 challenge configuration
    pub dns: Option<DnsConfig>,

    /// Renewal configuration
    #[serde(default)]
    pub renewal: RenewalConfig,
}

/// Default path for ACME account credentials
///
/// **Note:** This default is Unix-specific. On Windows, operators must explicitly
/// set `credentials_path` to a valid Windows path (e.g., `C:\ProgramData\router-hosts\acme-account.json`).
fn default_credentials_path() -> std::path::PathBuf {
    // NOTE: This path is Unix-specific. Windows users must configure this explicitly.
    std::path::PathBuf::from("/var/lib/router-hosts/acme-account.json")
}

fn default_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory_url: default_directory_url(),
            email: None,
            domains: Vec::new(),
            challenge_type: ChallengeType::Http01,
            credentials_path: default_credentials_path(),
            http: None,
            dns: None,
            renewal: RenewalConfig::default(),
        }
    }
}

impl AcmeConfig {
    /// Validate the configuration and expand environment variables
    ///
    /// This should be called after deserializing from TOML to:
    /// 1. Expand `${VAR}` patterns in string fields
    /// 2. Validate required fields based on challenge type
    pub fn validate_and_expand(&mut self) -> Result<(), AcmeConfigError> {
        if !self.enabled {
            return Ok(());
        }

        // Expand directory URL (unlikely to have env vars, but supported)
        self.directory_url = expand_env_vars(&self.directory_url)?;

        // Expand email if present
        if let Some(email) = &self.email {
            self.email = Some(expand_env_vars(email)?);
        }

        // Expand domains in-place to avoid unnecessary clones
        for domain in &mut self.domains {
            *domain = expand_env_vars(domain)?;
        }

        // Validate domains are specified
        if self.domains.is_empty() {
            return Err(AcmeConfigError::MissingField(
                "acme.domains (at least one domain required)".to_string(),
            ));
        }

        // Validate challenge-specific configuration
        match self.challenge_type {
            ChallengeType::Http01 => {
                if let Some(http) = &mut self.http {
                    http.validate_and_expand()?;
                }
                // HTTP config is optional - defaults are fine
            }
            ChallengeType::Dns01 => {
                let dns = self.dns.as_mut().ok_or_else(|| {
                    AcmeConfigError::MissingField(
                        "acme.dns (required for dns-01 challenge type)".to_string(),
                    )
                })?;
                dns.validate_and_expand()?;
            }
        }

        Ok(())
    }
}

/// HTTP-01 challenge configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpChallengeConfig {
    /// Address to bind HTTP server for challenges
    /// Default: "0.0.0.0:80"
    #[serde(default = "default_http_bind")]
    pub bind_address: String,
}

fn default_http_bind() -> String {
    "0.0.0.0:80".to_string()
}

impl Default for HttpChallengeConfig {
    fn default() -> Self {
        Self {
            bind_address: default_http_bind(),
        }
    }
}

impl HttpChallengeConfig {
    fn validate_and_expand(&mut self) -> Result<(), AcmeConfigError> {
        self.bind_address = expand_env_vars(&self.bind_address)?;
        Ok(())
    }
}

/// DNS-01 challenge configuration
///
/// Only one provider should be configured at a time.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Cloudflare DNS provider
    pub cloudflare: Option<CloudflareConfig>,

    /// Generic webhook DNS provider
    pub webhook: Option<WebhookConfig>,
}

impl DnsConfig {
    fn validate_and_expand(&mut self) -> Result<(), AcmeConfigError> {
        let mut providers_configured = 0;

        if let Some(cf) = &mut self.cloudflare {
            cf.validate_and_expand()?;
            providers_configured += 1;
        }

        if let Some(wh) = &mut self.webhook {
            wh.validate_and_expand()?;
            providers_configured += 1;
        }

        if providers_configured == 0 {
            return Err(AcmeConfigError::MissingField(
                "acme.dns.cloudflare or acme.dns.webhook (at least one DNS provider required)"
                    .to_string(),
            ));
        }

        if providers_configured > 1 {
            return Err(AcmeConfigError::Invalid(
                "only one DNS provider should be configured".to_string(),
            ));
        }

        Ok(())
    }
}

/// Cloudflare DNS provider configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CloudflareConfig {
    /// Cloudflare API token with DNS edit permissions
    /// Typically provided via environment variable: `${CLOUDFLARE_API_TOKEN}`
    pub api_token: String,

    /// Zone ID (optional - auto-detected from domain if not specified)
    pub zone_id: Option<String>,
}

impl CloudflareConfig {
    fn validate_and_expand(&mut self) -> Result<(), AcmeConfigError> {
        self.api_token = expand_env_vars(&self.api_token)?;

        if let Some(zone_id) = &self.zone_id {
            self.zone_id = Some(expand_env_vars(zone_id)?);
        }

        if self.api_token.is_empty() {
            return Err(AcmeConfigError::Invalid(
                "cloudflare.api_token cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

/// Generic webhook DNS provider configuration
///
/// This allows integration with custom DNS APIs by providing
/// create and delete endpoints for TXT records.
#[derive(Debug, Clone, Deserialize)]
pub struct WebhookConfig {
    /// URL to POST for creating TXT records
    /// Request body: `{"type": "TXT", "name": "_acme-challenge.domain", "content": "token"}`
    /// Expected response: `{"id": "record-id"}`
    pub create_url: String,

    /// URL to DELETE for removing TXT records
    /// `{record_id}` in the URL will be replaced with the record ID from create response
    pub delete_url: String,

    /// Optional headers to include in requests
    /// Commonly used for Authorization headers
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Request timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    30
}

impl WebhookConfig {
    fn validate_and_expand(&mut self) -> Result<(), AcmeConfigError> {
        self.create_url = expand_env_vars(&self.create_url)?;
        self.delete_url = expand_env_vars(&self.delete_url)?;

        // Expand environment variables in header values
        let mut expanded_headers = HashMap::new();
        for (key, value) in &self.headers {
            expanded_headers.insert(key.clone(), expand_env_vars(value)?);
        }
        self.headers = expanded_headers;

        if self.create_url.is_empty() {
            return Err(AcmeConfigError::Invalid(
                "webhook.create_url cannot be empty".to_string(),
            ));
        }

        if self.delete_url.is_empty() {
            return Err(AcmeConfigError::Invalid(
                "webhook.delete_url cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

/// Certificate renewal configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[allow(dead_code)] // Fields will be used in renewal loop implementation
pub struct RenewalConfig {
    /// Days before expiry to start renewal attempts
    /// Default: 30 days (Let's Encrypt certs are 90 days)
    #[serde(default = "default_renewal_days")]
    pub days_before_expiry: u32,

    /// Hours between retry attempts on failure
    /// Default: 12 hours
    #[serde(default = "default_retry_hours")]
    pub retry_interval_hours: u32,

    /// Random jitter in minutes to add to renewal checks
    /// Helps avoid thundering herd with multiple servers
    /// Default: 60 minutes (±30 minutes)
    #[serde(default = "default_jitter_minutes")]
    pub jitter_minutes: u32,
}

fn default_renewal_days() -> u32 {
    30
}

fn default_retry_hours() -> u32 {
    12
}

fn default_jitter_minutes() -> u32 {
    60
}

impl Default for RenewalConfig {
    fn default() -> Self {
        Self {
            days_before_expiry: default_renewal_days(),
            retry_interval_hours: default_retry_hours(),
            jitter_minutes: default_jitter_minutes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_config_default() {
        let config = AcmeConfig::default();
        assert!(!config.enabled);
        assert!(config.directory_url.contains("letsencrypt"));
        assert_eq!(config.challenge_type, ChallengeType::Http01);
    }

    #[test]
    fn test_acme_config_disabled_validates() {
        let mut config = AcmeConfig::default();
        assert!(config.validate_and_expand().is_ok());
    }

    #[test]
    fn test_acme_config_enabled_requires_domains() {
        let mut config = AcmeConfig {
            enabled: true,
            ..Default::default()
        };
        let result = config.validate_and_expand();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("domains"));
    }

    #[test]
    fn test_acme_config_dns01_requires_dns_config() {
        // DNS-01 requires a DNS provider configuration
        let mut config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".to_string()],
            challenge_type: ChallengeType::Dns01,
            ..Default::default()
        };
        let result = config.validate_and_expand();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("acme.dns"),
            "Expected 'acme.dns' missing field error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_acme_config_dns01_with_cloudflare_validates() {
        std::env::set_var("TEST_DNS01_CF_TOKEN", "test_token_123");

        let mut config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".to_string()],
            challenge_type: ChallengeType::Dns01,
            dns: Some(DnsConfig {
                cloudflare: Some(CloudflareConfig {
                    api_token: "${TEST_DNS01_CF_TOKEN}".to_string(),
                    zone_id: None,
                }),
                webhook: None,
            }),
            ..Default::default()
        };
        assert!(config.validate_and_expand().is_ok());
        assert_eq!(
            config
                .dns
                .as_ref()
                .unwrap()
                .cloudflare
                .as_ref()
                .unwrap()
                .api_token,
            "test_token_123"
        );

        std::env::remove_var("TEST_DNS01_CF_TOKEN");
    }

    #[test]
    fn test_acme_config_http01_validates() {
        let mut config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".to_string()],
            challenge_type: ChallengeType::Http01,
            ..Default::default()
        };
        assert!(config.validate_and_expand().is_ok());
    }

    #[test]
    fn test_cloudflare_config_expands_env_var() {
        std::env::set_var("TEST_CF_TOKEN", "my_secret_token");

        let mut config = CloudflareConfig {
            api_token: "${TEST_CF_TOKEN}".to_string(),
            zone_id: None,
        };

        config.validate_and_expand().unwrap();
        assert_eq!(config.api_token, "my_secret_token");

        std::env::remove_var("TEST_CF_TOKEN");
    }

    #[test]
    fn test_cloudflare_config_missing_env_var() {
        std::env::remove_var("TEST_CF_MISSING");

        let mut config = CloudflareConfig {
            api_token: "${TEST_CF_MISSING}".to_string(),
            zone_id: None,
        };

        let result = config.validate_and_expand();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("TEST_CF_MISSING"));
    }

    #[test]
    fn test_webhook_config_expands_headers() {
        std::env::set_var("TEST_WEBHOOK_TOKEN", "bearer_token");

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            "Bearer ${TEST_WEBHOOK_TOKEN}".to_string(),
        );

        let mut config = WebhookConfig {
            create_url: "https://api.example.com/create".to_string(),
            delete_url: "https://api.example.com/delete/{record_id}".to_string(),
            headers,
            timeout_seconds: 30,
        };

        config.validate_and_expand().unwrap();
        assert_eq!(
            config.headers.get("Authorization").unwrap(),
            "Bearer bearer_token"
        );

        std::env::remove_var("TEST_WEBHOOK_TOKEN");
    }

    #[test]
    fn test_dns_config_requires_provider() {
        let mut config = DnsConfig::default();
        let result = config.validate_and_expand();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DNS provider"));
    }

    #[test]
    fn test_dns_config_rejects_multiple_providers() {
        std::env::set_var("TEST_MULTI_TOKEN", "token");

        let mut config = DnsConfig {
            cloudflare: Some(CloudflareConfig {
                api_token: "${TEST_MULTI_TOKEN}".to_string(),
                zone_id: None,
            }),
            webhook: Some(WebhookConfig {
                create_url: "https://api.example.com/create".to_string(),
                delete_url: "https://api.example.com/delete".to_string(),
                headers: HashMap::new(),
                timeout_seconds: 30,
            }),
        };

        let result = config.validate_and_expand();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("only one"));

        std::env::remove_var("TEST_MULTI_TOKEN");
    }

    #[test]
    fn test_renewal_config_default() {
        let config = RenewalConfig::default();
        assert_eq!(config.days_before_expiry, 30);
        assert_eq!(config.retry_interval_hours, 12);
        assert_eq!(config.jitter_minutes, 60);
    }

    #[test]
    fn test_challenge_type_deserialize() {
        let http: ChallengeType = serde_json::from_str(r#""http-01""#).unwrap();
        assert_eq!(http, ChallengeType::Http01);

        let dns: ChallengeType = serde_json::from_str(r#""dns-01""#).unwrap();
        assert_eq!(dns, ChallengeType::Dns01);
    }

    #[test]
    fn test_full_acme_config_parse() {
        let toml_str = r#"
            enabled = true
            directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
            email = "admin@example.com"
            domains = ["example.com", "www.example.com"]
            challenge_type = "http-01"

            [http]
            bind_address = "0.0.0.0:8080"

            [renewal]
            days_before_expiry = 14
        "#;

        let mut config: AcmeConfig = toml::from_str(toml_str).unwrap();
        config.validate_and_expand().unwrap();

        assert!(config.enabled);
        assert!(config.directory_url.contains("staging"));
        assert_eq!(config.domains.len(), 2);
        assert_eq!(config.challenge_type, ChallengeType::Http01);
        assert_eq!(config.http.unwrap().bind_address, "0.0.0.0:8080");
        assert_eq!(config.renewal.days_before_expiry, 14);
    }

    #[test]
    fn test_acme_config_error_display() {
        let err = AcmeConfigError::MissingField("test.field".to_string());
        assert!(err.to_string().contains("test.field"));

        let err = AcmeConfigError::Invalid("bad value".to_string());
        assert!(err.to_string().contains("bad value"));
    }
}
