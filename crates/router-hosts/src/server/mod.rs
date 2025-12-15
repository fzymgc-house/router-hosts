//! Server module for router-hosts gRPC server
//!
//! This module implements the server-side functionality including:
//! - gRPC service with mTLS
//! - Storage abstraction with event sourcing
//! - /etc/hosts file generation

pub mod commands;
pub mod config;
pub mod db;
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
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;

    info!("Server shutdown complete");
    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}
