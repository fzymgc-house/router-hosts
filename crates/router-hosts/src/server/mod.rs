//! Server module for router-hosts gRPC server
//!
//! This module implements the server-side functionality including:
//! - gRPC service with mTLS
//! - Storage abstraction with event sourcing
//! - /etc/hosts file generation

pub mod commands;
pub mod config;
pub mod export;
pub mod hooks;
pub mod hosts_file;
pub mod import;
pub mod service;
pub mod write_queue;

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
use std::sync::Arc;
use thiserror::Error;
use tokio::signal;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;

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
}

/// Reason the server is shutting down
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// SIGTERM or Ctrl+C - exit completely
    Terminate,
    /// SIGHUP - reload certificates and restart
    Reload,
}

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
#[allow(dead_code)] // Used in later tasks (Task 5)
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

/// Run the gRPC server with the given configuration
async fn run_server(config: Config) -> Result<(), ServerError> {
    // Parse listen address
    let addr: SocketAddr = config
        .server
        .bind_address
        .parse()
        .map_err(|e| ServerError::Config(format!("Invalid bind address: {}", e)))?;

    // Get storage URL from config and parse into StorageConfig
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

    // Create storage using the factory function (handles initialization)
    let storage = create_storage(&storage_config).await?;

    // Create hook executor (timeout in seconds, default 30s)
    let hooks = Arc::new(HookExecutor::new(
        config.hooks.on_success.clone(),
        config.hooks.on_failure.clone(),
        30, // 30 second timeout per CLAUDE.md
    ));

    // Create hosts file generator
    let hosts_file = Arc::new(HostsFileGenerator::new(
        config.server.hosts_file_path.clone(),
    ));

    // Create command handler
    let commands = Arc::new(CommandHandler::new(
        Arc::clone(&storage),
        Arc::clone(&hosts_file),
        Arc::clone(&hooks),
        Arc::new(config.clone()),
    ));

    // Create write queue for serialized mutation operations
    let write_queue = WriteQueue::new(Arc::clone(&commands));

    // Create service implementation
    let service = HostsServiceImpl::new(write_queue, Arc::clone(&commands), Arc::clone(&storage));

    // Load TLS certificates
    info!("Loading TLS certificates");
    let cert = tokio::fs::read(&config.tls.cert_path).await.map_err(|e| {
        ServerError::Tls(format!(
            "Failed to read server cert from {:?}: {}",
            config.tls.cert_path, e
        ))
    })?;

    let key = tokio::fs::read(&config.tls.key_path).await.map_err(|e| {
        ServerError::Tls(format!(
            "Failed to read server key from {:?}: {}",
            config.tls.key_path, e
        ))
    })?;

    let ca_cert = tokio::fs::read(&config.tls.ca_cert_path)
        .await
        .map_err(|e| {
            ServerError::Tls(format!(
                "Failed to read CA cert from {:?}: {}",
                config.tls.ca_cert_path, e
            ))
        })?;

    // Configure mTLS
    let identity = Identity::from_pem(&cert, &key);
    let client_ca = Certificate::from_pem(&ca_cert);

    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    info!("Starting gRPC server on {}", addr);

    // Build and run server
    Server::builder()
        .tls_config(tls_config)?
        .add_service(HostsServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            shutdown_signal().await;
        })
        .await?;

    info!("Server shutdown complete");
    Ok(())
}

/// Wait for shutdown signal and return the reason
///
/// Returns `ShutdownReason::Terminate` for SIGTERM/Ctrl+C (exit)
/// Returns `ShutdownReason::Reload` for SIGHUP (reload certs)
async fn shutdown_signal() -> ShutdownReason {
    use signal::unix::SignalKind;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        ShutdownReason::Terminate
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
        ShutdownReason::Terminate
    };

    #[cfg(unix)]
    let sighup = async {
        signal::unix::signal(SignalKind::hangup())
            .expect("Failed to install SIGHUP handler")
            .recv()
            .await;
        ShutdownReason::Reload
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<ShutdownReason>();

    #[cfg(not(unix))]
    let sighup = std::future::pending::<ShutdownReason>();

    tokio::select! {
        reason = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown");
            reason
        }
        reason = sigterm => {
            info!("Received SIGTERM, initiating graceful shutdown");
            reason
        }
        reason = sighup => {
            info!("Received SIGHUP, checking certificates for reload...");
            reason
        }
    }
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
        // Use the test certificates from E2E test fixtures
        let cert_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/router-hosts-e2e/fixtures/certs");

        // Skip test if fixtures don't exist (CI might not have them)
        if !cert_dir.exists() {
            eprintln!(
                "Skipping test - E2E cert fixtures not found at {:?}",
                cert_dir
            );
            return;
        }

        let config = config::TlsConfig {
            cert_path: cert_dir.join("server.crt"),
            key_path: cert_dir.join("server.key"),
            ca_cert_path: cert_dir.join("ca.crt"),
        };

        let result = validate_tls_config(&config);
        assert!(result.is_ok(), "Valid certs should pass: {:?}", result);
    }
}
