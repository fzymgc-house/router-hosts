mod client;
mod server;

use anyhow::Result;
use std::env;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
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
