//! End-to-end acceptance tests for router-hosts
//!
//! This crate provides test infrastructure for running E2E tests against
//! a real server in Docker with mTLS authentication.

pub mod certs;
pub mod cli;
pub mod container;

/// Get the Docker image to use for the server
pub fn server_image() -> String {
    std::env::var("ROUTER_HOSTS_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/fzymgc-house/router-hosts:latest".to_string())
}

/// Get the path to the CLI binary
pub fn cli_binary() -> std::path::PathBuf {
    std::env::var("ROUTER_HOSTS_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("router-hosts"))
}
