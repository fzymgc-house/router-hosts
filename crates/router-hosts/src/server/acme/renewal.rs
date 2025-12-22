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
use super::config::{AcmeConfig, ChallengeType, DnsConfig};
use super::dns_provider::{
    compute_dns01_digest, CloudflareProvider, DnsProvider, DnsProviderError, DnsRecord,
    WebhookProvider,
};
use super::http_challenge::{ChallengeStore, HttpChallengeServer};
use instant_acme::{ChallengeType as AcmeChallengeType, Identifier};
use rand::Rng;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

// ============================================================================
// Constants
// ============================================================================

/// Base interval between renewal checks (24 hours)
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Number of consecutive failures before emitting CRITICAL alert
const FAILURE_ALERT_THRESHOLD: u32 = 3;

/// Initial interval for polling ACME order status during challenge validation
const ORDER_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum interval for order polling (caps exponential backoff)
const ORDER_POLL_MAX_INTERVAL: Duration = Duration::from_secs(30);

/// Number of attempts before doubling the poll interval (for exponential backoff)
const ORDER_POLL_BACKOFF_STEP: u32 = 10;

/// Maximum number of polling attempts before timeout
/// With exponential backoff starting at 2s and capped at 30s, this gives
/// approximately 10-15 minutes of total wait time.
const ORDER_POLL_MAX_ATTEMPTS: u32 = 150;

/// Timeout for HTTP challenge server shutdown
const HTTP_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

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

    /// DNS provider error
    #[error("DNS provider error: {0}")]
    DnsProvider(#[from] DnsProviderError),

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
#[cfg(not(tarpaulin_include))] // Requires running renewal loop, tested via E2E (#127)
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
    /// DNS provider for DNS-01 (initialized lazily if configured)
    dns_provider: Option<Arc<dyn DnsProvider>>,
}

#[allow(dead_code)] // Methods will be used when ACME is integrated
#[cfg(not(tarpaulin_include))] // Network-dependent ACME protocol, requires Pebble setup in CI (#127)
impl AcmeRenewalLoop {
    /// Create a new renewal loop
    ///
    /// Initializes the ACME client and ensures an account exists.
    /// If DNS-01 challenge type is configured, initializes the DNS provider.
    pub async fn new(config: AcmeConfig, tls_paths: TlsPaths) -> Result<Self, RenewalError> {
        let client = AcmeClient::new(config.clone())?;

        // Ensure we have an account
        client.ensure_account(&tls_paths.credentials_path).await?;

        // Initialize DNS provider if DNS-01 is configured
        let dns_provider = if config.challenge_type == ChallengeType::Dns01 {
            let dns_config = config.dns.as_ref().ok_or_else(|| {
                RenewalError::Config("DNS-01 challenge requires dns configuration".to_string())
            })?;

            // Get first domain for zone auto-detection
            let first_domain = config.domains.first().ok_or_else(|| {
                RenewalError::Config("at least one domain is required".to_string())
            })?;

            Some(Self::create_dns_provider(dns_config, first_domain).await?)
        } else {
            None
        };

        Ok(Self {
            client: Arc::new(client),
            config,
            tls_paths,
            challenge_store: Arc::new(ChallengeStore::new()),
            dns_provider,
        })
    }

    /// Create a DNS provider from configuration
    async fn create_dns_provider(
        config: &DnsConfig,
        domain: &str,
    ) -> Result<Arc<dyn DnsProvider>, RenewalError> {
        if let Some(cf) = &config.cloudflare {
            let provider = if let Some(zone_id) = &cf.zone_id {
                CloudflareProvider::new(cf.api_token.clone(), zone_id.clone())?
            } else {
                CloudflareProvider::with_auto_zone(cf.api_token.clone(), domain).await?
            };
            return Ok(Arc::new(provider));
        }

        if let Some(wh) = &config.webhook {
            let provider = WebhookProvider::new(
                wh.create_url.clone(),
                wh.delete_url.clone(),
                wh.headers.clone(),
                Duration::from_secs(wh.timeout_seconds),
            )?;
            return Ok(Arc::new(provider));
        }

        Err(RenewalError::Config(
            "no DNS provider configured".to_string(),
        ))
    }

    /// Start the renewal loop
    ///
    /// Returns a handle that can be used to shut down the loop.
    pub async fn start(self) -> Result<RenewalHandle, RenewalError> {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let join_handle = tokio::spawn(async move {
            // Failure tracking for observability
            let mut consecutive_failures: u32 = 0;

            // Check for initial certificate
            if !self.certificate_exists() {
                info!("No certificate found, requesting initial certificate");
                match self.request_certificate().await {
                    Ok(()) => {
                        consecutive_failures = 0;
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        error!(
                            error = %e,
                            consecutive_failures = consecutive_failures,
                            "Failed to request initial certificate"
                        );
                    }
                }
            }

            // Main renewal loop with jitter to prevent thundering herd
            // when multiple servers check at the same time.
            // Jitter is recalculated each iteration to prevent convergence over time.
            let jitter_minutes = self.config.renewal.jitter_minutes;

            debug!(
                base_interval_hours = RENEWAL_CHECK_INTERVAL.as_secs() / 3600,
                max_jitter_minutes = jitter_minutes,
                "ACME renewal loop starting"
            );

            loop {
                // Calculate fresh jitter for each sleep cycle
                let jitter_secs = if jitter_minutes > 0 {
                    rand::thread_rng().gen_range(0..(jitter_minutes as u64 * 60))
                } else {
                    0
                };
                let check_interval = RENEWAL_CHECK_INTERVAL + Duration::from_secs(jitter_secs);
                debug!(
                    next_check_hours = check_interval.as_secs() / 3600,
                    jitter_minutes = jitter_secs / 60,
                    "Sleeping until next renewal check"
                );

                tokio::select! {
                    _ = tokio::time::sleep(check_interval) => {
                        if self.should_renew().await {
                            info!("Certificate renewal needed");
                            match self.request_certificate().await {
                                Ok(()) => {
                                    consecutive_failures = 0;
                                    info!("Certificate renewed successfully");
                                }
                                Err(e) => {
                                    consecutive_failures += 1;
                                    error!(
                                        error = %e,
                                        consecutive_failures = consecutive_failures,
                                        "Failed to renew certificate"
                                    );

                                    // Alert on repeated failures with operator guidance
                                    if consecutive_failures >= FAILURE_ALERT_THRESHOLD {
                                        error!(
                                            consecutive_failures = consecutive_failures,
                                            threshold = FAILURE_ALERT_THRESHOLD,
                                            "CRITICAL: Certificate renewal has failed {} consecutive times. \
                                             Troubleshooting steps: \
                                             1) Verify DNS records point to this server (for HTTP-01), \
                                             2) Ensure port 80 is accessible from the internet, \
                                             3) Check Let's Encrypt rate limits at https://letsencrypt.org/docs/rate-limits/, \
                                             4) Review earlier log entries for specific error details. \
                                             Manual intervention may be required.",
                                            consecutive_failures
                                        );
                                    }
                                }
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

        // Parse the first certificate in the chain (the leaf/end-entity cert).
        // We intentionally only check the leaf cert's expiry since that's what
        // determines when the certificate needs renewal. Intermediate certs in
        // the chain typically have much longer validity periods.
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

    /// Overall timeout for certificate request operations.
    /// This prevents indefinite hangs if ACME server is unresponsive.
    const REQUEST_CERTIFICATE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

    /// Request a new certificate via ACME
    ///
    /// This method orchestrates the full ACME flow:
    /// 1. Create order for configured domains
    /// 2. Get authorizations and solve challenges
    /// 3. Generate CSR and finalize order
    /// 4. Write certificate to disk
    /// 5. Trigger server reload
    ///
    /// The entire operation has a 5-minute timeout to prevent indefinite hangs.
    async fn request_certificate(&self) -> Result<(), RenewalError> {
        match tokio::time::timeout(
            Self::REQUEST_CERTIFICATE_TIMEOUT,
            self.request_certificate_inner(),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(RenewalError::Challenge(format!(
                "certificate request timed out after {:?}",
                Self::REQUEST_CERTIFICATE_TIMEOUT
            ))),
        }
    }

    /// Inner implementation of certificate request (called with timeout)
    async fn request_certificate_inner(&self) -> Result<(), RenewalError> {
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

        // Track created DNS records for cleanup
        let mut dns_records: Vec<DnsRecord> = Vec::new();

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

                    // Add to challenge store (may fail if store is at capacity)
                    if !self
                        .challenge_store
                        .add_challenge(&challenge.token, key_auth.as_str())
                        .await
                    {
                        return Err(RenewalError::Challenge(
                            "challenge store at capacity".to_string(),
                        ));
                    }

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
                    let dns_provider = self.dns_provider.as_ref().ok_or_else(|| {
                        RenewalError::Config("DNS-01 challenge requires DNS provider".to_string())
                    })?;

                    let domain = identifier_value(&auth.identifier);

                    // Compute DNS-01 digest from key authorization
                    let key_auth = order.key_authorization(challenge);
                    let digest = compute_dns01_digest(key_auth.as_str());

                    // Create TXT record name: _acme-challenge.<domain>
                    let record_name = format!("_acme-challenge.{}", domain);

                    debug!(
                        domain = %domain,
                        record_name = %record_name,
                        provider = dns_provider.name(),
                        "Creating DNS-01 challenge TXT record"
                    );

                    // Create TXT record
                    let record = dns_provider
                        .create_txt_record(&record_name, &digest)
                        .await?;
                    dns_records.push(record);

                    // Wait for DNS propagation
                    debug!(
                        delay_secs = dns_provider.propagation_delay().as_secs(),
                        "Waiting for DNS propagation"
                    );
                    dns_provider.wait_for_propagation().await;

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

        // Stop HTTP challenge server with timeout to prevent indefinite blocking
        if let Some(handle) = http_handle {
            if tokio::time::timeout(HTTP_SERVER_SHUTDOWN_TIMEOUT, handle.shutdown())
                .await
                .is_err()
            {
                warn!(
                    "HTTP challenge server shutdown timed out after {:?}",
                    HTTP_SERVER_SHUTDOWN_TIMEOUT
                );
            }
        }

        // Clear challenge store
        self.challenge_store.clear().await;

        // Clean up DNS records (best-effort, don't fail on error)
        if !dns_records.is_empty() {
            if let Some(dns_provider) = &self.dns_provider {
                for record in &dns_records {
                    debug!(
                        record_id = %record.record_id,
                        name = %record.name,
                        "Cleaning up DNS challenge record"
                    );
                    if let Err(e) = dns_provider.delete_txt_record(record).await {
                        warn!(
                            error = %e,
                            record_name = %record.name,
                            "Failed to clean up DNS challenge record"
                        );
                    }
                }
            }
        }

        // Write certificate to disk
        let key_pem = key_pair.serialize_pem();
        write_certificate(
            &cert_chain,
            &key_pem,
            &self.tls_paths.cert_path,
            &self.tls_paths.key_path,
        )?;

        // Trigger reload - log but don't fail renewal if reload fails
        // The certificate is already written, and reload may fail for various
        // reasons (e.g., platform doesn't support SIGHUP, reload already in progress)
        if let Err(e) = trigger_reload_async().await {
            warn!(error = %e, "Failed to trigger certificate reload via SIGHUP");
        }

        info!("Certificate successfully renewed and server reloaded");

        Ok(())
    }

    /// Wait for an order's authorization to become ready
    ///
    /// Polls the ACME server for authorization status. Let's Encrypt recommends
    /// allowing up to 5 minutes for validation to complete, especially during
    /// high load periods.
    async fn wait_for_order_ready(
        &self,
        order: &mut instant_acme::Order,
        identifier: Identifier,
    ) -> Result<(), RenewalError> {
        let domain = identifier_value(&identifier);

        // Pre-calculate the attempt threshold where we hit max interval to avoid
        // redundant min() comparisons. With ORDER_POLL_INTERVAL=2s, ORDER_POLL_MAX_INTERVAL=30s,
        // and ORDER_POLL_BACKOFF_STEP=10, we hit max at 2^4=16x (32s capped to 30s) after 40 attempts.
        let max_interval_attempt = {
            let ratio = ORDER_POLL_MAX_INTERVAL.as_secs() / ORDER_POLL_INTERVAL.as_secs();
            // Find smallest power of 2 >= ratio, then multiply by step
            let power = (ratio as f64).log2().ceil() as u32;
            power * ORDER_POLL_BACKOFF_STEP
        };

        for attempt in 1..=ORDER_POLL_MAX_ATTEMPTS {
            // Use exponential backoff to reduce load during long validations
            // Interval doubles every ORDER_POLL_BACKOFF_STEP attempts, capped at max
            let poll_interval = if attempt >= max_interval_attempt {
                ORDER_POLL_MAX_INTERVAL
            } else {
                let backoff_multiplier = 2u32.pow(attempt / ORDER_POLL_BACKOFF_STEP);
                ORDER_POLL_INTERVAL * backoff_multiplier
            };
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
                        max_attempts = ORDER_POLL_MAX_ATTEMPTS,
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
            domain, ORDER_POLL_MAX_ATTEMPTS
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
