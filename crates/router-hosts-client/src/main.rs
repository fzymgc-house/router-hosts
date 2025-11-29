mod config;

use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(name = "router-hosts")]
#[command(about = "Router hosts file management CLI", long_about = None)]
struct Cli {
    /// Path to config file
    #[arg(short, long)]
    config: Option<String>,

    /// Server address (overrides config)
    #[arg(short, long)]
    server: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new host entry
    Add {
        /// IP address (IPv4 or IPv6)
        #[arg(long)]
        ip: String,

        /// Hostname
        #[arg(long)]
        hostname: String,

        /// Optional comment
        #[arg(long)]
        comment: Option<String>,

        /// Optional tags (can be specified multiple times)
        #[arg(long)]
        tag: Vec<String>,
    },

    /// List all host entries
    List,

    /// Get a specific host entry
    Get {
        /// Host entry ID
        id: String,
    },

    /// Start an edit session
    StartEdit,

    /// Finish an edit session
    FinishEdit {
        /// Edit token
        token: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("router-hosts-client");
    println!("Config: {:?}", cli.config);
    println!("Command: {:?}", std::mem::discriminant(&cli.command));

    // TODO: Implement actual commands

    Ok(())
}
