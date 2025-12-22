//! ACME client implementation using instant-acme
//!
//! This module provides the core ACME protocol client for certificate management.

use super::config::{AcmeConfig, ChallengeType};
use http_body_util::Full;
use hyper::body::Bytes;
use instant_acme::{
    Account, AccountCredentials, ChallengeType as AcmeChallengeType, HttpClient, Identifier,
    NewAccount, NewOrder, Order,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Interval for polling certificate availability after order finalization
const CERT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Wrapper around Arc<dyn HttpClient> that implements HttpClient
///
/// This allows us to store a shared HTTP client and clone it for each ACME request.
struct SharedHttpClient(Arc<dyn HttpClient>);

impl HttpClient for SharedHttpClient {
    fn request(
        &self,
        req: hyper::Request<Full<Bytes>>,
    ) -> Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        self.0.request(req)
    }
}

/// Errors that can occur during ACME operations
#[derive(Debug, Error)]
#[allow(dead_code)] // Variants will be used as ACME implementation progresses
pub enum AcmeError {
    /// Failed to create or load ACME account
    #[error("ACME account error: {0}")]
    Account(String),

    /// Failed to create certificate order
    #[error("order creation failed: {0}")]
    OrderCreation(String),

    /// Challenge authorization failed
    #[error("authorization failed: {0}")]
    Authorization(String),

    /// Certificate issuance failed
    #[error("certificate issuance failed: {0}")]
    Issuance(String),

    /// HTTP challenge server error
    #[error("HTTP challenge server error: {0}")]
    HttpChallenge(String),

    /// DNS challenge error
    #[error("DNS challenge error: {0}")]
    DnsChallenge(String),

    /// Certificate generation error
    #[error("certificate generation error: {0}")]
    CertGeneration(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),
}

/// Result of a successful certificate order
#[derive(Debug)]
#[allow(dead_code)] // Will be used when certificate writing is implemented
pub struct CertificateBundle {
    /// PEM-encoded certificate chain
    pub certificate_chain: String,

    /// PEM-encoded private key
    pub private_key: String,
}

/// ACME client state
///
/// Provides methods for managing ACME certificates, including:
/// - Account creation and management
/// - Certificate ordering and CSR generation
/// - Challenge handling
#[allow(dead_code)] // Will be used when ACME integration is complete in the renewal loop
pub struct AcmeClient {
    /// ACME account
    account: RwLock<Option<Account>>,

    /// ACME configuration
    config: AcmeConfig,

    /// Custom HTTP client for ACME protocol (used for testing with Pebble)
    /// If None, uses instant-acme's default HTTP client
    acme_http_client: Option<Arc<dyn HttpClient>>,
}

#[allow(dead_code)] // Methods will be used when ACME integration is complete
impl AcmeClient {
    /// Create a new ACME client with default HTTP client
    ///
    /// Uses instant-acme's default HTTP client which trusts system root certificates.
    /// The account is not created/loaded until `ensure_account` is called.
    pub fn new(config: AcmeConfig) -> Result<Self, AcmeError> {
        Ok(Self {
            account: RwLock::new(None),
            config,
            acme_http_client: None,
        })
    }

    /// Create a new ACME client with a custom HTTP client
    ///
    /// This is primarily used for testing with Pebble (Let's Encrypt test server)
    /// where we need to trust Pebble's self-signed CA certificate.
    ///
    /// The account is not created/loaded until `ensure_account` is called.
    pub fn with_http_client(
        config: AcmeConfig,
        http_client: Box<dyn HttpClient>,
    ) -> Result<Self, AcmeError> {
        Ok(Self {
            account: RwLock::new(None),
            config,
            acme_http_client: Some(Arc::from(http_client)),
        })
    }

    /// Ensure we have a valid ACME account
    ///
    /// Creates a new account if credentials file doesn't exist,
    /// or loads existing account from credentials file.
    pub async fn ensure_account(&self, credentials_path: &Path) -> Result<(), AcmeError> {
        let mut account_guard = self.account.write().await;

        // Check if we already have an account
        if account_guard.is_some() {
            return Ok(());
        }

        // Try to load existing credentials
        if credentials_path.exists() {
            info!("Loading existing ACME account from {:?}", credentials_path);
            let credentials_json = tokio::fs::read_to_string(credentials_path)
                .await
                .map_err(|e| AcmeError::Account(format!("failed to read credentials: {}", e)))?;

            let credentials: AccountCredentials = serde_json::from_str(&credentials_json)
                .map_err(|e| AcmeError::Account(format!("failed to parse credentials: {}", e)))?;

            // Use custom HTTP client if provided, otherwise use default
            let account = if let Some(ref http) = self.acme_http_client {
                Account::from_credentials_and_http(
                    credentials,
                    Box::new(SharedHttpClient(http.clone())),
                )
                .await
                .map_err(|e| AcmeError::Account(format!("failed to restore account: {}", e)))?
            } else {
                Account::from_credentials(credentials)
                    .await
                    .map_err(|e| AcmeError::Account(format!("failed to restore account: {}", e)))?
            };

            *account_guard = Some(account);
            return Ok(());
        }

        // Create new account
        info!("Creating new ACME account");

        let contact: Vec<String> = self
            .config
            .email
            .as_ref()
            .map(|email| vec![format!("mailto:{}", email)])
            .unwrap_or_default();

        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        // Use custom HTTP client if provided, otherwise use default
        let (account, credentials) = if let Some(ref http) = self.acme_http_client {
            Account::create_with_http(
                &new_account,
                &self.config.directory_url,
                None,
                Box::new(SharedHttpClient(http.clone())),
            )
            .await
            .map_err(|e| AcmeError::Account(format!("failed to create account: {}", e)))?
        } else {
            Account::create(&new_account, &self.config.directory_url, None)
                .await
                .map_err(|e| AcmeError::Account(format!("failed to create account: {}", e)))?
        };

        // Save credentials
        let credentials_json = serde_json::to_string_pretty(&credentials)
            .map_err(|e| AcmeError::Account(format!("failed to serialize credentials: {}", e)))?;

        // Ensure parent directory exists
        if let Some(parent) = credentials_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                AcmeError::Account(format!("failed to create credentials directory: {}", e))
            })?;
        }

        // Write atomically with secure permissions (0600) to avoid TOCTOU race condition.
        // On Unix, we create the file with mode 0o600 from the start using OpenOptions,
        // preventing any window where the file exists with insecure permissions.
        let temp_path = credentials_path.with_extension("tmp");

        // Write to temp file with secure permissions from creation
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600) // Set permissions at creation time - no TOCTOU window
                .open(&temp_path)
                .map_err(|e| {
                    AcmeError::Account(format!("failed to create credentials file: {}", e))
                })?;

            file.write_all(credentials_json.as_bytes()).map_err(|e| {
                let _ = std::fs::remove_file(&temp_path);
                AcmeError::Account(format!("failed to write credentials: {}", e))
            })?;

            file.sync_all().map_err(|e| {
                let _ = std::fs::remove_file(&temp_path);
                AcmeError::Account(format!("failed to sync credentials: {}", e))
            })?;
        }

        #[cfg(not(unix))]
        {
            tokio::fs::write(&temp_path, &credentials_json)
                .await
                .map_err(|e| AcmeError::Account(format!("failed to write credentials: {}", e)))?;
        }

        // Atomic rename to final path
        tokio::fs::rename(&temp_path, credentials_path)
            .await
            .map_err(|e| {
                // Clean up temp file on error
                let _ = std::fs::remove_file(&temp_path);
                AcmeError::Account(format!("failed to finalize credentials file: {}", e))
            })?;

        info!("ACME account created and credentials saved");
        *account_guard = Some(account);
        Ok(())
    }

    /// Create a new certificate order
    ///
    /// Returns the order and the list of authorizations that need to be completed.
    pub async fn create_order(&self) -> Result<Order, AcmeError> {
        let account_guard = self.account.read().await;
        let account = account_guard
            .as_ref()
            .ok_or_else(|| AcmeError::Account("account not initialized".to_string()))?;

        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|domain| Identifier::Dns(domain.clone()))
            .collect();

        let new_order = NewOrder {
            identifiers: &identifiers,
        };

        let order = account
            .new_order(&new_order)
            .await
            .map_err(|e| AcmeError::OrderCreation(format!("failed to create order: {}", e)))?;

        Ok(order)
    }

    /// Get challenge type based on configuration
    pub fn challenge_type(&self) -> AcmeChallengeType {
        match self.config.challenge_type {
            ChallengeType::Http01 => AcmeChallengeType::Http01,
            ChallengeType::Dns01 => AcmeChallengeType::Dns01,
        }
    }

    /// Generate a certificate signing request (CSR) for the configured domains
    pub fn generate_csr(&self) -> Result<(Vec<u8>, KeyPair), AcmeError> {
        let key_pair = KeyPair::generate().map_err(|e| {
            AcmeError::CertGeneration(format!("failed to generate key pair: {}", e))
        })?;

        let mut params = CertificateParams::default();

        // Set the first domain as the common name
        if let Some(first_domain) = self.config.domains.first() {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, first_domain.clone());
            params.distinguished_name = dn;
        }

        // Add all domains as SANs
        // In rcgen 0.14, use try_into() to convert strings to the internal SAN type
        params.subject_alt_names = self
            .config
            .domains
            .iter()
            .filter_map(|d| d.clone().try_into().ok().map(SanType::DnsName))
            .collect();

        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| AcmeError::CertGeneration(format!("failed to create CSR: {}", e)))?;

        Ok((csr.der().to_vec(), key_pair))
    }

    /// Finalize an order and get the certificate
    pub async fn finalize_order(&self, order: &mut Order, csr: &[u8]) -> Result<String, AcmeError> {
        order
            .finalize(csr)
            .await
            .map_err(|e| AcmeError::Issuance(format!("failed to finalize order: {}", e)))?;

        // Poll for certificate
        let cert = loop {
            match order.certificate().await {
                Ok(Some(cert)) => break cert,
                Ok(None) => {
                    debug!("Certificate not ready yet, waiting...");
                    tokio::time::sleep(CERT_POLL_INTERVAL).await;
                }
                Err(e) => {
                    return Err(AcmeError::Issuance(format!(
                        "failed to get certificate: {}",
                        e
                    )));
                }
            }
        };

        Ok(cert)
    }

    /// Get the ACME configuration
    pub fn config(&self) -> &AcmeConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_client_new() {
        let config = AcmeConfig {
            enabled: true,
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
            email: Some("test@example.com".to_string()),
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };

        let client = AcmeClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_challenge_type_http01() {
        let config = AcmeConfig {
            enabled: true,
            challenge_type: ChallengeType::Http01,
            ..Default::default()
        };

        let client = AcmeClient::new(config).unwrap();
        assert!(matches!(client.challenge_type(), AcmeChallengeType::Http01));
    }

    #[test]
    fn test_challenge_type_dns01() {
        let config = AcmeConfig {
            enabled: true,
            challenge_type: ChallengeType::Dns01,
            ..Default::default()
        };

        let client = AcmeClient::new(config).unwrap();
        assert!(matches!(client.challenge_type(), AcmeChallengeType::Dns01));
    }

    #[test]
    fn test_generate_csr() {
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            ..Default::default()
        };

        let client = AcmeClient::new(config).unwrap();
        let result = client.generate_csr();
        assert!(result.is_ok());

        let (csr, _key_pair) = result.unwrap();
        assert!(!csr.is_empty());
    }

    #[test]
    fn test_generate_csr_with_wildcard() {
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".to_string(), "*.example.com".to_string()],
            ..Default::default()
        };

        let client = AcmeClient::new(config).unwrap();
        let result = client.generate_csr();
        assert!(result.is_ok());
    }
}
