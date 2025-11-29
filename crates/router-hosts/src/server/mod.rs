mod config;
pub mod db;

use anyhow::Result;
use clap::Parser;
use tracing::info;

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
    info!("Config: {:?}", cli.config);

    // TODO: Load config, start gRPC server

    Ok(())
}
