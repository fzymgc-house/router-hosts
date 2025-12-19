//! ACME certificate renewal loop
//!
//! This module provides the main renewal loop that orchestrates certificate
//! management via ACME. It handles:
//!
//! - Checking certificate expiry
//! - Creating new orders
//! - Solving challenges (HTTP-01 or DNS-01)
//! - Writing certificates to disk
//! - Triggering server reload via SIGHUP
//!
//! # Current Status
//!
//! This module provides the framework for ACME renewal. Full integration with
//! the server will be completed in a future phase.

use super::cert_writer::{trigger_reload_async, write_certificate};
use super::client::AcmeClient;
use super::config::{AcmeConfig, ChallengeType};
use super::http_challenge::{ChallengeStore, HttpChallengeServer};
use instant_acme::{ChallengeType as AcmeChallengeType, Identifier};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// Extract domain value from Identifier enum
fn identifier_value(id: &Identifier) -> &str {
    match id {
        Identifier::Dns(domain) => domain.as_str(),
    }
}

/// Errors that can occur during renewal
#[derive(Debug, Error)]
#[allow(dead_code)] // Variants will be used as implementation progresses
pub enum RenewalError {
    /// ACME client error
    #[error("ACME error: {0}")]
    Acme(#[from] super::client::AcmeError),

    /// HTTP challenge server error
    #[error("HTTP challenge error: {0}")]
    HttpChallenge(#[from] super::http_challenge::HttpChallengeError),

    /// Certificate writing error
    #[error("certificate write error: {0}")]
    CertWrite(#[from] super::cert_writer::CertWriteError),

    /// Challenge validation failed
    #[error("challenge validation failed: {0}")]
    Challenge(String),

    /// Certificate parsing error
    #[error("certificate parsing error: {0}")]
    Parse(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),
}

/// TLS certificate paths for writing renewed certificates
#[derive(Debug, Clone)]
#[allow(dead_code)] // Will be used when renewal loop writes certs
pub struct TlsPaths {
    /// Path to server certificate
    pub cert_path: PathBuf,
    /// Path to private key
    pub key_path: PathBuf,
    /// Path to ACME account credentials
    pub credentials_path: PathBuf,
}

/// Handle for controlling a running renewal loop
#[allow(dead_code)] // Will be used when renewal loop is integrated
pub struct RenewalHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: tokio::task::JoinHandle<()>,
}

#[allow(dead_code)] // Methods will be used when renewal loop is integrated
impl RenewalHandle {
    /// Shutdown the renewal loop gracefully
    pub async fn shutdown(self) {
        debug!("Shutting down ACME renewal loop");
        let _ = self.shutdown_tx.send(());
        let _ = self.join_handle.await;
    }
}

/// ACME certificate renewal loop
///
/// Manages the lifecycle of TLS certificates using ACME:
/// 1. Initial certificate acquisition if none exists
/// 2. Periodic renewal checks (daily)
/// 3. Automatic renewal before expiry
#[allow(dead_code)] // Will be used when ACME is integrated into server
pub struct AcmeRenewalLoop {
    /// ACME client
    client: Arc<AcmeClient>,
    /// ACME configuration
    config: AcmeConfig,
    /// TLS file paths
    tls_paths: TlsPaths,
    /// Challenge store for HTTP-01
    challenge_store: Arc<ChallengeStore>,
}

#[allow(dead_code)] // Methods will be used when ACME is integrated
impl AcmeRenewalLoop {
    /// Create a new renewal loop
    ///
    /// Initializes the ACME client and ensures an account exists.
    pub async fn new(config: AcmeConfig, tls_paths: TlsPaths) -> Result<Self, RenewalError> {
        let client = AcmeClient::new(config.clone())?;

        // Ensure we have an account
        client.ensure_account(&tls_paths.credentials_path).await?;

        Ok(Self {
            client: Arc::new(client),
            config,
            tls_paths,
            challenge_store: Arc::new(ChallengeStore::new()),
        })
    }

    /// Start the renewal loop
    ///
    /// Returns a handle that can be used to shut down the loop.
    pub async fn start(self) -> Result<RenewalHandle, RenewalError> {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let join_handle = tokio::spawn(async move {
            // Check for initial certificate
            if !self.certificate_exists() {
                info!("No certificate found, requesting initial certificate");
                if let Err(e) = self.request_certificate().await {
                    error!(error = %e, "Failed to request initial certificate");
                }
            }

            // Main renewal loop
            let check_interval = Duration::from_secs(24 * 60 * 60); // Daily
            let mut interval = tokio::time::interval(check_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if self.should_renew().await {
                            info!("Certificate renewal needed");
                            if let Err(e) = self.request_certificate().await {
                                error!(error = %e, "Failed to renew certificate");
                            }
                        } else {
                            debug!("Certificate renewal not needed");
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("ACME renewal loop shutting down");
                        break;
                    }
                }
            }
        });

        Ok(RenewalHandle {
            shutdown_tx,
            join_handle,
        })
    }

    /// Check if certificate file exists
    fn certificate_exists(&self) -> bool {
        self.tls_paths.cert_path.exists() && self.tls_paths.key_path.exists()
    }

    /// Check if certificate should be renewed
    ///
    /// Returns true if:
    /// - Certificate doesn't exist
    /// - Certificate will expire within configured renewal window
    async fn should_renew(&self) -> bool {
        if !self.certificate_exists() {
            return true;
        }

        match self.days_until_expiry().await {
            Ok(days) => {
                let threshold = self.config.renewal.days_before_expiry;
                debug!(
                    days_until_expiry = days,
                    renewal_threshold = threshold,
                    "Checking certificate expiry"
                );
                days <= threshold as i64
            }
            Err(e) => {
                warn!(error = %e, "Failed to check certificate expiry, will renew");
                true
            }
        }
    }

    /// Get days until certificate expiry
    async fn days_until_expiry(&self) -> Result<i64, RenewalError> {
        let cert_pem = tokio::fs::read_to_string(&self.tls_paths.cert_path)
            .await
            .map_err(|e| RenewalError::Parse(format!("failed to read certificate: {}", e)))?;

        // Parse the first certificate in the chain
        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| RenewalError::Parse(format!("failed to parse PEM: {:?}", e)))?;

        let cert = pem
            .parse_x509()
            .map_err(|e| RenewalError::Parse(format!("failed to parse X509: {:?}", e)))?;

        let not_after = cert.validity().not_after;
        let expiry_ts = not_after.timestamp();
        let now_ts = chrono::Utc::now().timestamp();
        let days = (expiry_ts - now_ts) / (24 * 60 * 60);

        Ok(days)
    }

    /// Request a new certificate via ACME
    ///
    /// This method orchestrates the full ACME flow:
    /// 1. Create order for configured domains
    /// 2. Get authorizations and solve challenges
    /// 3. Generate CSR and finalize order
    /// 4. Write certificate to disk
    /// 5. Trigger server reload
    async fn request_certificate(&self) -> Result<(), RenewalError> {
        info!(domains = ?self.config.domains, "Requesting ACME certificate");

        // Create order
        let mut order = self.client.create_order().await?;

        // Get authorizations
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| RenewalError::Challenge(format!("failed to get authorizations: {}", e)))?;

        // Start challenge server if HTTP-01
        let http_handle = if self.config.challenge_type == ChallengeType::Http01 {
            let bind_addr = self
                .config
                .http
                .as_ref()
                .map(|h| h.bind_address.as_str())
                .unwrap_or("0.0.0.0:80");
            let addr: SocketAddr = bind_addr.parse().map_err(|e| {
                RenewalError::Config(format!("invalid HTTP bind address '{}': {}", bind_addr, e))
            })?;

            let server = HttpChallengeServer::new(addr, self.challenge_store.clone());
            Some(server.start().await?)
        } else {
            None
        };

        // Process each authorization
        let challenge_type = self.client.challenge_type();
        for auth in &authorizations {
            // Find the appropriate challenge
            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.r#type == challenge_type)
                .ok_or_else(|| {
                    RenewalError::Challenge(format!(
                        "no {:?} challenge available for {}",
                        challenge_type,
                        identifier_value(&auth.identifier)
                    ))
                })?;

            match challenge_type {
                AcmeChallengeType::Http01 => {
                    // Get key authorization from order
                    let key_auth = order.key_authorization(challenge);

                    // Add to challenge store
                    self.challenge_store
                        .add_challenge(&challenge.token, key_auth.as_str())
                        .await;

                    // Notify ACME server we're ready
                    order
                        .set_challenge_ready(&challenge.url)
                        .await
                        .map_err(|e| {
                            RenewalError::Challenge(format!("failed to set challenge ready: {}", e))
                        })?;

                    // Wait for authorization to become valid
                    self.wait_for_order_ready(&mut order, auth.identifier.clone())
                        .await?;
                }
                AcmeChallengeType::Dns01 => {
                    return Err(RenewalError::Config(
                        "DNS-01 challenge not yet implemented".to_string(),
                    ));
                }
                _ => {
                    return Err(RenewalError::Config(format!(
                        "unsupported challenge type: {:?}",
                        challenge_type
                    )));
                }
            }
        }

        // Generate CSR and finalize
        let (csr, key_pair) = self.client.generate_csr()?;
        let cert_chain = self.client.finalize_order(&mut order, &csr).await?;

        // Stop HTTP challenge server
        if let Some(handle) = http_handle {
            handle.shutdown().await;
        }

        // Clear challenge store
        self.challenge_store.clear().await;

        // Write certificate to disk
        let key_pem = key_pair.serialize_pem();
        write_certificate(
            &cert_chain,
            &key_pem,
            &self.tls_paths.cert_path,
            &self.tls_paths.key_path,
        )?;

        // Trigger reload
        trigger_reload_async().await;

        info!("Certificate successfully renewed and server reloaded");

        Ok(())
    }

    /// Wait for an order's authorization to become ready
    async fn wait_for_order_ready(
        &self,
        order: &mut instant_acme::Order,
        identifier: Identifier,
    ) -> Result<(), RenewalError> {
        let max_attempts = 30;
        let poll_interval = Duration::from_secs(2);
        let domain = identifier_value(&identifier);

        for attempt in 1..=max_attempts {
            tokio::time::sleep(poll_interval).await;

            // Refresh order state
            let state = order.state();

            match state.status {
                instant_acme::OrderStatus::Ready | instant_acme::OrderStatus::Valid => {
                    debug!(
                        domain = domain,
                        attempts = attempt,
                        "Authorization validated"
                    );
                    return Ok(());
                }
                instant_acme::OrderStatus::Invalid => {
                    return Err(RenewalError::Challenge(format!(
                        "authorization for {} failed",
                        domain
                    )));
                }
                instant_acme::OrderStatus::Pending | instant_acme::OrderStatus::Processing => {
                    debug!(
                        domain = domain,
                        attempt = attempt,
                        max_attempts = max_attempts,
                        status = ?state.status,
                        "Waiting for authorization"
                    );
                    // Refresh order to get updated status
                    order.refresh().await.map_err(|e| {
                        RenewalError::Challenge(format!("failed to refresh order: {}", e))
                    })?;
                }
            }
        }

        Err(RenewalError::Challenge(format!(
            "authorization for {} timed out after {} attempts",
            domain, max_attempts
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_paths_clone() {
        let paths = TlsPaths {
            cert_path: PathBuf::from("/etc/certs/server.crt"),
            key_path: PathBuf::from("/etc/certs/server.key"),
            credentials_path: PathBuf::from("/etc/certs/acme.json"),
        };

        let cloned = paths.clone();
        assert_eq!(cloned.cert_path, paths.cert_path);
        assert_eq!(cloned.key_path, paths.key_path);
    }

    #[test]
    fn test_renewal_error_display() {
        let err = RenewalError::Challenge("timeout".to_string());
        assert!(err.to_string().contains("challenge"));
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_renewal_error_from_acme() {
        let acme_err = super::super::client::AcmeError::Account("test".to_string());
        let renewal_err: RenewalError = acme_err.into();
        assert!(renewal_err.to_string().contains("ACME"));
    }

    #[test]
    fn test_identifier_value() {
        let id = Identifier::Dns("example.com".to_string());
        assert_eq!(identifier_value(&id), "example.com");
    }

    // Integration tests would require a real ACME server (like Pebble)
    // Those will be added as E2E tests in a separate PR
}
