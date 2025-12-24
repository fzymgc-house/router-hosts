//! Router-hosts library crate
//!
//! This library exposes the main entry point and modules for the router-hosts binary.
//! It can be used as a dependency by variant binaries (e.g., router-hosts-duckdb).

pub mod client;
pub mod server;

#[cfg(test)]
pub mod test_utils;

use anyhow::Result;
use std::env;
use std::process::ExitCode;

/// Initialize the rustls crypto provider.
///
/// Must be called before any TLS operations. Safe to call multiple times.
pub fn init_crypto_provider() {
    // The only possible error is "provider already installed" which is benign
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Main entry point for router-hosts.
///
/// Parses command line arguments and runs in either server or client mode.
pub async fn run() -> Result<ExitCode> {
    init_crypto_provider();

    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "server" {
        server::run().await?;
        Ok(ExitCode::SUCCESS)
    } else {
        client::run().await
    }
}
