//! Server module for router-hosts gRPC server
//!
//! This module implements the server-side functionality including:
//! - gRPC service with mTLS
//! - Storage abstraction with event sourcing
//! - /etc/hosts file generation
//! - ACME certificate management

pub mod acme;
pub mod commands;
pub mod config;
pub mod export;
pub mod hooks;
pub mod hosts_file;
pub mod import;
pub mod metrics;
pub mod propagation;
pub mod service;
pub mod tracing_setup;
pub mod write_queue;

use crate::server::acme::renewal::{AcmeRenewalLoop, RenewalHandle, TlsPaths};
use crate::server::commands::CommandHandler;
use crate::server::config::Config;
use crate::server::hooks::HookExecutor;
use crate::server::hosts_file::HostsFileGenerator;
use crate::server::service::HostsServiceImpl;
use crate::server::write_queue::WriteQueue;
use anyhow::Result;
use clap::Parser;
use router_hosts_common::proto::hosts_service_server::HostsServiceServer;
use router_hosts_storage::{create_storage, StorageConfig, StorageError};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::signal;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("TLS setup failed: {0}")]
    Tls(String),

    #[error("Storage initialization failed: {0}")]
    Storage(#[from] StorageError),

    #[error("Server transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ACME error: {0}")]
    Acme(#[from] crate::server::acme::renewal::RenewalError),
}

/// Reason the server is shutting down
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// SIGTERM or Ctrl+C - exit completely
    Terminate,
    /// SIGHUP - reload certificates and restart
    Reload,
}

/// Maximum time to wait for in-flight requests during graceful shutdown
const GRACEFUL_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Validate TLS configuration by checking files exist and are valid PEM
///
/// This is called before initiating graceful shutdown on SIGHUP to avoid
/// restarting with invalid certificates.
///
/// # What We Validate
/// - Files exist and are readable
/// - Valid PEM format for cert, key, and CA
/// - Private key can be parsed (but not that it matches cert - tonic does that)
///
/// # What We Don't Validate
/// - Certificate expiry (server should start even with expired certs)
/// - CA chain validity (client verification handles this at connection time)
/// - Key/cert match (tonic validates this when creating Identity)
pub fn validate_tls_config(tls_config: &config::TlsConfig) -> Result<(), String> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;

    // Read and validate server certificate
    let cert_data = std::fs::read(&tls_config.cert_path)
        .map_err(|e| format!("failed to read cert file {:?}: {}", tls_config.cert_path, e))?;

    let mut cert_reader = BufReader::new(cert_data.as_slice());
    let cert_chain: Vec<_> = certs(&mut cert_reader).collect();
    if cert_chain.is_empty() {
        return Err(format!(
            "no valid certificates found in {:?}",
            tls_config.cert_path
        ));
    }
    for (i, cert_result) in cert_chain.iter().enumerate() {
        if let Err(e) = cert_result {
            return Err(format!(
                "invalid certificate at index {} in {:?}: {}",
                i, tls_config.cert_path, e
            ));
        }
    }

    // Read and validate private key
    let key_data = std::fs::read(&tls_config.key_path)
        .map_err(|e| format!("failed to read key file {:?}: {}", tls_config.key_path, e))?;

    let mut key_reader = BufReader::new(key_data.as_slice());
    let key = private_key(&mut key_reader)
        .map_err(|e| format!("failed to parse key file {:?}: {}", tls_config.key_path, e))?
        .ok_or_else(|| format!("no private key found in {:?}", tls_config.key_path))?;

    // Verify key is not empty (basic sanity check)
    if key.secret_der().is_empty() {
        return Err(format!("empty private key in {:?}", tls_config.key_path));
    }

    // Read and validate CA certificate
    let ca_data = std::fs::read(&tls_config.ca_cert_path).map_err(|e| {
        format!(
            "failed to read CA file {:?}: {}",
            tls_config.ca_cert_path, e
        )
    })?;

    let mut ca_reader = BufReader::new(ca_data.as_slice());
    let ca_certs: Vec<_> = certs(&mut ca_reader).collect();
    if ca_certs.is_empty() {
        return Err(format!(
            "no valid CA certificates found in {:?}",
            tls_config.ca_cert_path
        ));
    }
    for (i, cert_result) in ca_certs.iter().enumerate() {
        if let Err(e) = cert_result {
            return Err(format!(
                "invalid CA certificate at index {} in {:?}: {}",
                i, tls_config.ca_cert_path, e
            ));
        }
    }

    Ok(())
}

#[derive(Parser)]
#[command(name = "router-hosts server")]
#[command(about = "Router hosts file management server", long_about = None)]
struct ServerCli {
    /// Path to config file
    #[arg(short, long)]
    config: Option<String>,
}

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Parse server-specific arguments (skip program name and "server" argument)
    let args: Vec<String> = std::env::args().skip(2).collect();
    let cli = ServerCli::parse_from(std::iter::once("server".to_string()).chain(args));

    info!("router-hosts server starting");

    // Load configuration
    let config_path = cli
        .config
        .as_deref()
        .unwrap_or("/etc/router-hosts/server.toml");
    info!("Loading configuration from: {}", config_path);

    let config = Config::from_file(config_path)
        .map_err(|e| anyhow::anyhow!("Failed to load config: {}", e))?;

    // Run the server
    run_server(config)
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}

/// Load TLS configuration from files
///
/// Returns the ServerTlsConfig ready to use with tonic Server.
async fn load_tls(tls_config: &config::TlsConfig) -> Result<ServerTlsConfig, ServerError> {
    let cert = tokio::fs::read(&tls_config.cert_path).await.map_err(|e| {
        ServerError::Tls(format!(
            "Failed to read server cert from {:?}: {}",
            tls_config.cert_path, e
        ))
    })?;

    let key = tokio::fs::read(&tls_config.key_path).await.map_err(|e| {
        ServerError::Tls(format!(
            "Failed to read server key from {:?}: {}",
            tls_config.key_path, e
        ))
    })?;

    let ca_cert = tokio::fs::read(&tls_config.ca_cert_path)
        .await
        .map_err(|e| {
            ServerError::Tls(format!(
                "Failed to read CA cert from {:?}: {}",
                tls_config.ca_cert_path, e
            ))
        })?;

    let identity = Identity::from_pem(&cert, &key);
    let client_ca = Certificate::from_pem(&ca_cert);

    Ok(ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca))
}

/// Run the gRPC server with the given configuration
///
/// The server runs in a loop to support certificate reload via SIGHUP:
/// 1. Load TLS certificates
/// 2. Start gRPC server
/// 3. Wait for shutdown signal
/// 4. If SIGHUP with valid new certs: graceful shutdown, loop continues
/// 5. If SIGTERM/Ctrl+C: graceful shutdown, exit loop
async fn run_server(config: Config) -> Result<(), ServerError> {
    // Parse listen address (once, doesn't change on reload)
    let addr: SocketAddr = config
        .server
        .bind_address
        .parse()
        .map_err(|e| ServerError::Config(format!("Invalid bind address: {}", e)))?;

    // Get storage URL from config (once, doesn't change on reload)
    let storage_url = config
        .database
        .storage_url()
        .map_err(|e| ServerError::Config(format!("Invalid database config: {}", e)))?;

    let storage_config = StorageConfig::from_url(&storage_url)
        .map_err(|e| ServerError::Config(format!("Invalid storage URL: {}", e)))?;

    info!(
        "Initializing storage: {:?} ({})",
        storage_config.backend, storage_url
    );

    // Create storage (once, persists across reloads)
    let storage = create_storage(&storage_config).await?;

    // Create hook executor (once)
    let hooks = Arc::new(HookExecutor::new(
        config.hooks.on_success.clone(),
        config.hooks.on_failure.clone(),
        30,
    ));

    // Create hosts file generator (once)
    let hosts_file = Arc::new(HostsFileGenerator::new(
        config.server.hosts_file_path.clone(),
    ));

    // Create command handler (once)
    let commands = Arc::new(CommandHandler::new(
        Arc::clone(&storage),
        Arc::clone(&hosts_file),
        Arc::clone(&hooks),
        Arc::new(config.clone()),
    ));

    // Set up signal handlers once (Unix only)
    #[cfg(unix)]
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    #[cfg(unix)]
    let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup())
        .expect("Failed to install SIGHUP handler");

    #[cfg(not(unix))]
    tracing::warn!(
        "Certificate reload via SIGHUP not supported on this platform. \
         Restart server to load new certificates."
    );

    // Start ACME renewal loop if enabled
    let mut acme_handle: Option<RenewalHandle> = if config.acme.enabled {
        info!("ACME certificate management enabled");

        let tls_paths = TlsPaths {
            cert_path: PathBuf::from(&config.tls.cert_path),
            key_path: PathBuf::from(&config.tls.key_path),
            credentials_path: config.acme.credentials_path.clone(),
        };

        match AcmeRenewalLoop::new(config.acme.clone(), tls_paths).await {
            Ok(renewal_loop) => match renewal_loop.start().await {
                Ok(handle) => {
                    info!(
                        domains = ?config.acme.domains,
                        challenge_type = ?config.acme.challenge_type,
                        "ACME renewal loop started"
                    );
                    Some(handle)
                }
                Err(e) => {
                    error!(error = %e, "Failed to start ACME renewal loop");
                    warn!("Server will continue without ACME - manual certificate management required");
                    None
                }
            },
            Err(e) => {
                error!(error = %e, "Failed to initialize ACME client");
                warn!("Server will continue without ACME - manual certificate management required");
                None
            }
        }
    } else {
        None
    };

    // Initialize metrics if configured
    let metrics_handle = metrics::init(config.metrics.as_ref())
        .await
        .map_err(|e| ServerError::Config(format!("Metrics initialization failed: {}", e)))?;

    // Server loop
    loop {
        info!("Loading TLS certificates");
        let tls_config = load_tls(&config.tls).await?;

        let write_queue = WriteQueue::new(Arc::clone(&commands));
        let tls_cert_path = if config.acme.enabled {
            Some(config.tls.cert_path.clone())
        } else {
            None
        };
        let service = HostsServiceImpl::new(
            write_queue,
            Arc::clone(&commands),
            Arc::clone(&storage),
            Arc::clone(&hooks),
            config.acme.enabled,
            tls_cert_path,
        );

        info!("Starting gRPC server on {}", addr);

        let shutdown_notify = Arc::new(tokio::sync::Notify::new());
        let shutdown_notify_clone = Arc::clone(&shutdown_notify);

        let server = Server::builder()
            .tls_config(tls_config)?
            .add_service(HostsServiceServer::new(service))
            .serve_with_shutdown(addr, async move {
                shutdown_notify_clone.notified().await;
            });

        tokio::pin!(server);

        // Wait for server completion or signal
        // server_needs_drain: true if we signaled shutdown but server hasn't finished yet
        let (reason, server_needs_drain): (ShutdownReason, bool) = loop {
            #[cfg(not(unix))]
            let select_result = tokio::select! {
                result = &mut server => {
                    result?;
                    // Server exited without signal (shouldn't happen normally)
                    Some((ShutdownReason::Terminate, false))
                },
                _ = signal::ctrl_c() => {
                    info!("Received Ctrl+C, initiating graceful shutdown");
                    shutdown_notify.notify_one();
                    Some((ShutdownReason::Terminate, true))
                }
            };

            #[cfg(unix)]
            let select_result = tokio::select! {
                result = &mut server => {
                    result?;
                    // Server exited without signal (shouldn't happen normally)
                    Some((ShutdownReason::Terminate, false))
                },
                _ = signal::ctrl_c() => {
                    info!("Received Ctrl+C, initiating graceful shutdown");
                    shutdown_notify.notify_one();
                    Some((ShutdownReason::Terminate, true))
                },
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown");
                    shutdown_notify.notify_one();
                    Some((ShutdownReason::Terminate, true))
                },
                _ = sighup.recv() => {
                    info!("Received SIGHUP, validating certificates for reload...");
                    match validate_tls_config(&config.tls) {
                        Ok(()) => {
                            info!("Certificates validated successfully, initiating graceful shutdown for reload");
                            shutdown_notify.notify_one();
                            Some((ShutdownReason::Reload, true))
                        }
                        Err(e) => {
                            tracing::error!(
                                "Certificate validation failed: {}. Server continues with current certificates.",
                                e
                            );
                            // Don't shut down - wait for next signal
                            None
                        }
                    }
                }
            };

            if let Some(result) = select_result {
                break result;
            }
        };

        // If we signaled shutdown, wait for server to drain with timeout
        if server_needs_drain {
            info!(
                "Waiting up to {:?} for in-flight requests to complete...",
                GRACEFUL_SHUTDOWN_TIMEOUT
            );
            match tokio::time::timeout(GRACEFUL_SHUTDOWN_TIMEOUT, server).await {
                Ok(result) => {
                    // Server finished within timeout
                    if let Err(e) = result {
                        tracing::warn!("Server shutdown completed with error: {}", e);
                    }
                }
                Err(_) => {
                    // Timeout expired - force shutdown
                    tracing::warn!(
                        "Graceful shutdown timeout ({:?}) expired, forcing shutdown. \
                         Some requests may have been interrupted.",
                        GRACEFUL_SHUTDOWN_TIMEOUT
                    );
                    // Server future is dropped here, closing connections
                }
            }
        }

        match reason {
            ShutdownReason::Terminate => {
                // Shutdown ACME renewal loop if running
                if let Some(handle) = acme_handle.take() {
                    info!("Shutting down ACME renewal loop");
                    handle.shutdown().await;
                }

                // Shutdown metrics
                info!("Shutting down metrics");
                metrics_handle.shutdown().await;

                info!("Server shutdown complete");
                break;
            }
            ShutdownReason::Reload => {
                info!("Restarting server with new certificates...");
                // Loop continues, will reload TLS at top
                // Note: ACME renewal loop continues running - it doesn't need reload
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_tls_config_missing_cert_file() {
        let config = config::TlsConfig {
            cert_path: "/nonexistent/cert.pem".into(),
            key_path: "/nonexistent/key.pem".into(),
            ca_cert_path: "/nonexistent/ca.pem".into(),
        };

        let result = validate_tls_config(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("cert"), "Error should mention cert: {}", err);
    }

    #[test]
    fn test_validate_tls_config_invalid_pem() {
        // Create temp file with invalid PEM content
        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(b"not a valid PEM file").unwrap();
        cert_file.flush().unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(b"not a key").unwrap();
        key_file.flush().unwrap();

        let mut ca_file = NamedTempFile::new().unwrap();
        ca_file.write_all(b"not a CA").unwrap();
        ca_file.flush().unwrap();

        let config = config::TlsConfig {
            cert_path: cert_file.path().to_path_buf(),
            key_path: key_file.path().to_path_buf(),
            ca_cert_path: ca_file.path().to_path_buf(),
        };

        let result = validate_tls_config(&config);
        assert!(result.is_err());
        // Should fail on cert (first file checked)
        assert!(
            result.as_ref().unwrap_err().contains("certificate"),
            "Error should mention certificate: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_tls_config_valid_certs() {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };

        // Generate test certificates at runtime (like E2E tests do)
        // rcgen 0.14 API: signed_by(subject_key, &Issuer::from_params(&ca_params, &ca_key))
        let ca_key = KeyPair::generate().expect("Failed to generate CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("Failed to generate CA cert");

        let server_key = KeyPair::generate().expect("Failed to generate server key");
        let mut server_params = CertificateParams::default();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params
            .signed_by(&server_key, &Issuer::from_params(&ca_params, &ca_key))
            .expect("Failed to generate server cert");

        // Write certs to temp files
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let ca_path = temp_dir.path().join("ca.pem");
        let cert_path = temp_dir.path().join("server.pem");
        let key_path = temp_dir.path().join("server-key.pem");

        std::fs::write(&ca_path, ca_cert.pem()).expect("Failed to write CA cert");
        std::fs::write(&cert_path, server_cert.pem()).expect("Failed to write server cert");
        std::fs::write(&key_path, server_key.serialize_pem()).expect("Failed to write server key");

        let config = config::TlsConfig {
            cert_path,
            key_path,
            ca_cert_path: ca_path,
        };

        let result = validate_tls_config(&config);
        assert!(result.is_ok(), "Valid certs should pass: {:?}", result);
    }
}
