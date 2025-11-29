mod config;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("router-hosts-server starting");

    // TODO: Load config, start gRPC server

    Ok(())
}
