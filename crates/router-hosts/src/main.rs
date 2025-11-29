mod client;
mod server;

use anyhow::Result;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Check if first argument is "server"
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "server" {
        // Server mode - remove "server" from args and run server
        server::run().await
    } else {
        // Client mode (default)
        client::run().await
    }
}
