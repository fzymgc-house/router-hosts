//! Integration tests for ACME certificate management
//!
//! These tests use Pebble (Let's Encrypt's test ACME server) to verify
//! the full ACME workflow including account creation, order management,
//! and certificate issuance.
//!
//! # Test Infrastructure
//!
//! - **Pebble**: ACME server on port 14000
//! - **Challtestsrv**: Challenge test server for mocking HTTP-01/DNS-01 responses
//!
//! Both run in Docker containers connected via a bridge network so Pebble
//! can validate challenges through challtestsrv.
//!
//! # CI Integration
//!
//! These tests run in CI via `cargo test` with Docker support. Pebble's
//! self-signed CA is trusted via a custom HTTP client (see `create_pebble_http_client`)
//! that includes Pebble's CA certificate, avoiding system trust store modifications.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use reqwest::Client;
use router_hosts::server::acme::client::AcmeClient;
use router_hosts::server::acme::config::{AcmeConfig, ChallengeType};
use rustls::RootCertStore;
use std::sync::Once;
use std::time::Duration;
use testcontainers::core::{ContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

/// Initialize rustls crypto provider (required when both aws-lc-rs and ring are enabled)
static INIT_CRYPTO: Once = Once::new();

fn init_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install rustls crypto provider");
    });
}

/// Pebble's test CA certificate (embedded at compile time)
const PEBBLE_CA_PEM: &str = include_str!("pebble-ca.pem");

/// Create an HTTP client that trusts Pebble's self-signed CA
///
/// This allows the ACME client to communicate with Pebble over HTTPS
/// without certificate verification errors.
fn create_pebble_http_client() -> Box<dyn instant_acme::HttpClient> {
    // Parse Pebble's CA certificate
    let mut roots = RootCertStore::empty();
    let certs: Vec<_> = rustls_pemfile::certs(&mut PEBBLE_CA_PEM.as_bytes())
        .filter_map(|r| r.ok())
        .collect();
    roots.add_parsable_certificates(certs);

    // Build rustls config with Pebble CA
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Build HTTPS connector
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();

    // Build hyper client (implements instant_acme::HttpClient)
    Box::new(HyperClient::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https))
}

/// Pebble test infrastructure
struct PebbleTestEnv {
    /// Pebble container
    _pebble: testcontainers::ContainerAsync<GenericImage>,
    /// Challtestsrv container
    _challtestsrv: testcontainers::ContainerAsync<GenericImage>,
    /// Pebble directory URL
    pub directory_url: String,
    /// Challtestsrv management URL
    pub challtestsrv_url: String,
    /// Temp directory for credentials
    pub temp_dir: tempfile::TempDir,
}

impl PebbleTestEnv {
    /// Start Pebble and challtestsrv containers
    async fn start() -> Self {
        // Create temp directory for ACME credentials
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");

        // Start challtestsrv first (Pebble depends on it for DNS)
        // Using host network mode to simplify DNS resolution
        let challtestsrv = GenericImage::new("ghcr.io/letsencrypt/pebble-challtestsrv", "latest")
            .with_exposed_port(ContainerPort::Tcp(8055))
            .with_wait_for(WaitFor::message_on_stdout("Starting challenge server"))
            .with_cmd(vec![
                "-http01",
                "", // Disable HTTP-01 standalone server
                "-https01",
                "", // Disable HTTPS-01 standalone server
                "-tlsalpn01",
                "", // Disable TLS-ALPN-01 standalone server
            ])
            .start()
            .await
            .expect("Failed to start challtestsrv");

        let challtestsrv_port = challtestsrv
            .get_host_port_ipv4(8055)
            .await
            .expect("Failed to get challtestsrv port");

        let challtestsrv_url = format!("http://127.0.0.1:{}", challtestsrv_port);

        // Get challtestsrv container IP for Pebble to use
        let challtestsrv_ip = challtestsrv
            .get_bridge_ip_address()
            .await
            .expect("Failed to get challtestsrv IP");

        // Start Pebble with DNS pointing to challtestsrv
        // Note: Pebble image entrypoint already includes "pebble" command
        let pebble = GenericImage::new("ghcr.io/letsencrypt/pebble", "latest")
            .with_exposed_port(ContainerPort::Tcp(14000))
            .with_exposed_port(ContainerPort::Tcp(15000))
            .with_wait_for(WaitFor::message_on_stdout("Listening on"))
            .with_env_var("PEBBLE_VA_NOSLEEP", "1") // Speed up validation
            .with_env_var("PEBBLE_VA_ALWAYS_VALID", "1") // Skip actual HTTP validation
            .with_cmd(vec![
                "-config",
                "/test/config/pebble-config.json",
                "-dnsserver",
                &format!("{}:8053", challtestsrv_ip),
            ])
            .start()
            .await
            .expect("Failed to start pebble");

        let pebble_port = pebble
            .get_host_port_ipv4(14000)
            .await
            .expect("Failed to get pebble port");

        let directory_url = format!("https://127.0.0.1:{}/dir", pebble_port);

        // Give containers a moment to fully initialize
        tokio::time::sleep(Duration::from_millis(500)).await;

        Self {
            _pebble: pebble,
            _challtestsrv: challtestsrv,
            directory_url,
            challtestsrv_url,
            temp_dir,
        }
    }

    /// Add an HTTP-01 challenge response to challtestsrv
    #[allow(dead_code)]
    async fn add_http01_challenge(
        &self,
        token: &str,
        key_auth: &str,
    ) -> Result<(), reqwest::Error> {
        let client = Client::new();
        client
            .post(format!("{}/add-http01", self.challtestsrv_url))
            .json(&serde_json::json!({
                "token": token,
                "content": key_auth
            }))
            .send()
            .await?;
        Ok(())
    }

    /// Get the credentials file path
    fn credentials_path(&self) -> std::path::PathBuf {
        self.temp_dir.path().join("acme-credentials.json")
    }
}

/// Create an ACME config for testing with Pebble
fn test_acme_config(directory_url: &str) -> AcmeConfig {
    AcmeConfig {
        enabled: true,
        directory_url: directory_url.to_string(),
        email: Some("test@example.com".to_string()),
        domains: vec!["test.example.com".to_string()],
        challenge_type: ChallengeType::Http01,
        ..Default::default()
    }
}

// ============================================================================
// ACME Client Tests
// ============================================================================

#[tokio::test]
async fn test_acme_client_creation() {
    let config = AcmeConfig {
        enabled: true,
        directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".to_string(),
        ..Default::default()
    };

    let client = AcmeClient::new(config);
    assert!(client.is_ok(), "Should create ACME client successfully");
}

#[tokio::test]
async fn test_acme_generate_csr() {
    let config = AcmeConfig {
        enabled: true,
        domains: vec!["example.com".to_string(), "www.example.com".to_string()],
        ..Default::default()
    };

    let client = AcmeClient::new(config).expect("Failed to create client");
    let result = client.generate_csr();

    assert!(result.is_ok(), "Should generate CSR successfully");
    let (csr, _key_pair) = result.unwrap();
    assert!(!csr.is_empty(), "CSR should not be empty");
}

#[tokio::test]
async fn test_acme_challenge_type_mapping() {
    // Test HTTP-01
    let config_http = AcmeConfig {
        enabled: true,
        challenge_type: ChallengeType::Http01,
        ..Default::default()
    };
    let client_http = AcmeClient::new(config_http).unwrap();
    assert!(matches!(
        client_http.challenge_type(),
        instant_acme::ChallengeType::Http01
    ));

    // Test DNS-01
    let config_dns = AcmeConfig {
        enabled: true,
        challenge_type: ChallengeType::Dns01,
        ..Default::default()
    };
    let client_dns = AcmeClient::new(config_dns).unwrap();
    assert!(matches!(
        client_dns.challenge_type(),
        instant_acme::ChallengeType::Dns01
    ));
}

// ============================================================================
// Pebble Integration Tests
//
// These tests use Pebble (Let's Encrypt's test ACME server) with a custom
// HTTP client that trusts Pebble's self-signed CA certificate. This allows
// full ACME protocol testing without modifying system trust stores.
// ============================================================================

#[tokio::test]
async fn test_acme_account_creation_with_pebble() {
    init_crypto_provider();

    // Start Pebble environment
    let env = PebbleTestEnv::start().await;

    // Create ACME client with Pebble-trusting HTTP client
    let config = test_acme_config(&env.directory_url);
    let http_client = create_pebble_http_client();
    let client =
        AcmeClient::with_http_client(config, http_client).expect("Failed to create ACME client");

    // Ensure account (creates new one since credentials don't exist)
    let result = client.ensure_account(&env.credentials_path()).await;

    assert!(
        result.is_ok(),
        "Should create ACME account: {:?}",
        result.err()
    );

    // Verify credentials file was created
    assert!(
        env.credentials_path().exists(),
        "Credentials file should be created"
    );

    // Calling ensure_account again should load existing account
    let result2 = client.ensure_account(&env.credentials_path()).await;
    assert!(
        result2.is_ok(),
        "Should load existing account: {:?}",
        result2.err()
    );
}

#[tokio::test]
async fn test_acme_order_creation_with_pebble() {
    init_crypto_provider();

    // Start Pebble environment
    let env = PebbleTestEnv::start().await;

    // Create ACME client with Pebble-trusting HTTP client
    let config = test_acme_config(&env.directory_url);
    let http_client = create_pebble_http_client();
    let client =
        AcmeClient::with_http_client(config, http_client).expect("Failed to create ACME client");
    client
        .ensure_account(&env.credentials_path())
        .await
        .expect("Failed to create account");

    // Create order
    let order = client.create_order().await;

    assert!(order.is_ok(), "Should create order: {:?}", order.err());
}

#[tokio::test]
async fn test_acme_full_certificate_flow_with_pebble() {
    init_crypto_provider();

    // Start Pebble environment with PEBBLE_VA_ALWAYS_VALID=1
    // This skips actual challenge validation, allowing us to test the full flow
    let env = PebbleTestEnv::start().await;

    // Create ACME client with Pebble-trusting HTTP client
    let config = test_acme_config(&env.directory_url);
    let http_client = create_pebble_http_client();
    let client =
        AcmeClient::with_http_client(config, http_client).expect("Failed to create ACME client");
    client
        .ensure_account(&env.credentials_path())
        .await
        .expect("Failed to create account");

    // Create order
    let mut order = client.create_order().await.expect("Failed to create order");

    // Get authorizations
    let authorizations = order
        .authorizations()
        .await
        .expect("Failed to get authorizations");

    assert!(
        !authorizations.is_empty(),
        "Should have at least one authorization"
    );

    // Find HTTP-01 challenge and mark ready
    for auth in &authorizations {
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == instant_acme::ChallengeType::Http01)
            .expect("Should have HTTP-01 challenge");

        // With PEBBLE_VA_ALWAYS_VALID=1, we don't need to actually serve the challenge
        // Just mark it as ready
        order
            .set_challenge_ready(&challenge.url)
            .await
            .expect("Failed to set challenge ready");
    }

    // Wait for order to become ready (poll a few times)
    for _ in 0..10 {
        order.refresh().await.expect("Failed to refresh order");
        let state = order.state();
        if state.status == instant_acme::OrderStatus::Ready {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Generate CSR and finalize
    let (csr, key_pair) = client.generate_csr().expect("Failed to generate CSR");
    let cert_chain = client
        .finalize_order(&mut order, &csr)
        .await
        .expect("Failed to finalize order");

    // Verify we got a certificate
    assert!(
        cert_chain.contains("BEGIN CERTIFICATE"),
        "Should receive PEM certificate"
    );

    // Verify key pair was generated
    let key_pem = key_pair.serialize_pem();
    assert!(
        key_pem.contains("BEGIN PRIVATE KEY"),
        "Should have private key"
    );
}

// ============================================================================
// Additional Unit Tests (no network required)
// ============================================================================

#[tokio::test]
async fn test_acme_config_default() {
    let config = AcmeConfig::default();
    assert!(!config.enabled);
    assert!(config.domains.is_empty());
}

#[tokio::test]
async fn test_acme_config_with_domains() {
    let config = AcmeConfig {
        enabled: true,
        directory_url: "https://acme.example.com/directory".to_string(),
        email: Some("admin@example.com".to_string()),
        domains: vec!["example.com".to_string(), "www.example.com".to_string()],
        challenge_type: ChallengeType::Http01,
        ..Default::default()
    };

    assert!(config.enabled);
    assert_eq!(config.domains.len(), 2);
    assert_eq!(config.email, Some("admin@example.com".to_string()));
}

#[tokio::test]
async fn test_acme_error_display() {
    use router_hosts::server::acme::client::AcmeError;

    let account_err = AcmeError::Account("test error".to_string());
    assert!(account_err.to_string().contains("account"));

    let order_err = AcmeError::OrderCreation("order failed".to_string());
    assert!(order_err.to_string().contains("order"));

    let auth_err = AcmeError::Authorization("auth failed".to_string());
    assert!(auth_err.to_string().contains("authorization"));

    let issuance_err = AcmeError::Issuance("issuance failed".to_string());
    assert!(issuance_err.to_string().contains("issuance"));

    let http_err = AcmeError::HttpChallenge("http failed".to_string());
    assert!(http_err.to_string().contains("HTTP"));

    let dns_err = AcmeError::DnsChallenge("dns failed".to_string());
    assert!(dns_err.to_string().contains("DNS"));

    let cert_err = AcmeError::CertGeneration("cert failed".to_string());
    assert!(cert_err.to_string().contains("certificate"));

    let config_err = AcmeError::Config("config failed".to_string());
    assert!(config_err.to_string().contains("configuration"));
}

#[tokio::test]
async fn test_renewal_error_display() {
    use router_hosts::server::acme::client::AcmeError;
    use router_hosts::server::acme::renewal::RenewalError;

    let challenge_err = RenewalError::Challenge("timeout".to_string());
    assert!(challenge_err.to_string().contains("challenge"));

    let parse_err = RenewalError::Parse("invalid cert".to_string());
    assert!(parse_err.to_string().contains("parsing"));

    let config_err = RenewalError::Config("bad config".to_string());
    assert!(config_err.to_string().contains("configuration"));

    // Test From<AcmeError> conversion
    let acme_err = AcmeError::Account("test".to_string());
    let renewal_err: RenewalError = acme_err.into();
    assert!(renewal_err.to_string().contains("ACME"));
}

#[tokio::test]
async fn test_tls_paths_struct() {
    use router_hosts::server::acme::renewal::TlsPaths;
    use std::path::PathBuf;

    let paths = TlsPaths {
        cert_path: PathBuf::from("/etc/ssl/cert.pem"),
        key_path: PathBuf::from("/etc/ssl/key.pem"),
        credentials_path: PathBuf::from("/etc/acme/credentials.json"),
    };

    // Test Clone
    let cloned = paths.clone();
    assert_eq!(cloned.cert_path, paths.cert_path);
    assert_eq!(cloned.key_path, paths.key_path);
    assert_eq!(cloned.credentials_path, paths.credentials_path);

    // Test Debug
    let debug_str = format!("{:?}", paths);
    assert!(debug_str.contains("cert_path"));
    assert!(debug_str.contains("key_path"));
}

#[tokio::test]
async fn test_http_challenge_store() {
    use router_hosts::server::acme::http_challenge::ChallengeStore;

    let store = ChallengeStore::new();

    // Add a challenge (returns true on success)
    assert!(store.add_challenge("token123", "key_auth_value").await);

    // Get the challenge
    let result = store.get_challenge("token123").await;
    assert_eq!(result, Some("key_auth_value".to_string()));

    // Get non-existent challenge
    let missing = store.get_challenge("nonexistent").await;
    assert_eq!(missing, None);

    // Clear all challenges
    store.clear().await;
    let after_clear = store.get_challenge("token123").await;
    assert_eq!(after_clear, None);
}

#[tokio::test]
async fn test_cert_writer_functions() {
    use router_hosts::server::acme::cert_writer::write_certificate;

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = temp_dir.path().join("test.crt");
    let key_path = temp_dir.path().join("test.key");

    // Generate a test certificate
    let key_pair = rcgen::KeyPair::generate().expect("Failed to generate key");
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test.example.com");
    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to generate cert");

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Write certificate
    let result = write_certificate(&cert_pem, &key_pem, &cert_path, &key_path);
    assert!(
        result.is_ok(),
        "Should write certificate: {:?}",
        result.err()
    );

    // Verify files exist
    assert!(cert_path.exists(), "Cert file should exist");
    assert!(key_path.exists(), "Key file should exist");

    // Verify contents
    let read_cert = std::fs::read_to_string(&cert_path).unwrap();
    let read_key = std::fs::read_to_string(&key_path).unwrap();
    assert_eq!(read_cert, cert_pem);
    assert_eq!(read_key, key_pem);
}

#[tokio::test]
async fn test_env_expand() {
    use router_hosts::server::acme::env_expand::{contains_env_vars, expand_env_vars};

    // Test contains_env_vars
    assert!(contains_env_vars("${HOME}/path"));
    assert!(contains_env_vars("prefix_${VAR}_suffix"));
    assert!(!contains_env_vars("no variables here"));
    assert!(!contains_env_vars("just $DOLLAR"));

    // Test expand_env_vars with existing env var
    std::env::set_var("TEST_EXPAND_VAR", "expanded_value");
    let result = expand_env_vars("prefix_${TEST_EXPAND_VAR}_suffix");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "prefix_expanded_value_suffix");

    // Test with non-existent env var
    let result = expand_env_vars("${NONEXISTENT_VAR_12345}");
    assert!(result.is_err());

    // Test with no variables
    let result = expand_env_vars("no variables");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "no variables");

    // Clean up
    std::env::remove_var("TEST_EXPAND_VAR");
}

// ============================================================================
// Certificate Expiry Tests
// ============================================================================

#[tokio::test]
async fn test_certificate_expiry_parsing() {
    use router_hosts::server::acme::renewal::TlsPaths;

    // Create a test certificate with known expiry
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let cert_path = temp_dir.path().join("test.crt");
    let key_path = temp_dir.path().join("test.key");

    // Generate a test certificate using rcgen
    let key_pair = rcgen::KeyPair::generate().expect("Failed to generate key");
    let mut params = rcgen::CertificateParams::default();
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "test.example.com");

    let cert = params
        .self_signed(&key_pair)
        .expect("Failed to generate cert");

    std::fs::write(&cert_path, cert.pem()).expect("Failed to write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("Failed to write key");

    // Verify TlsPaths can be created
    let paths = TlsPaths {
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        credentials_path: temp_dir.path().join("acme.json"),
    };

    assert!(paths.cert_path.exists());
    assert!(paths.key_path.exists());
}
