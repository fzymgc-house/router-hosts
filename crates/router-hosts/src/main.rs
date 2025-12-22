mod client;
mod server;

use anyhow::Result;
use std::env;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    // Install the rustls crypto provider before any TLS operations.
    // Required when both aws-lc-rs and ring features are enabled.
    //
    // The only possible error is "provider already installed" (returns the existing
    // Arc<CryptoProvider>), which is benign and expected in test scenarios where
    // multiple tests run in the same process. We use fallible installation to
    // avoid panic in these cases.
    //
    // Note: Cannot use tracing here as subscriber isn't initialized yet.
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        // Provider already installed - this is expected in tests, safe to continue
        eprintln!("Note: rustls crypto provider already installed, continuing");
    }

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
