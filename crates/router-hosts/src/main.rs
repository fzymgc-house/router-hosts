mod client;
mod server;

use anyhow::Result;
use std::env;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    // Install the rustls crypto provider before any TLS operations.
    // Required when both aws-lc-rs and ring features are enabled.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Check if first argument is "server"
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "server" {
        // Server mode - remove "server" from args and run server
        server::run().await?;
        Ok(ExitCode::SUCCESS)
    } else {
        // Client mode (default)
        client::run().await
    }
}
