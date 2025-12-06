// Allow dead_code and unused_imports until command handlers are connected in Task 6
#![allow(dead_code, unused_imports)]

mod config;
mod grpc;

pub use config::ClientConfig;
pub use grpc::Client;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Csv,
}

#[derive(Parser)]
#[command(name = "router-hosts")]
#[command(about = "Router hosts file management CLI", long_about = None)]
pub struct Cli {
    /// Path to config file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Server address (host:port)
    #[arg(short, long, global = true)]
    pub server: Option<String>,

    /// Client certificate path
    #[arg(long, global = true)]
    pub cert: Option<PathBuf>,

    /// Client key path
    #[arg(long, global = true)]
    pub key: Option<PathBuf>,

    /// CA certificate path
    #[arg(long, global = true)]
    pub ca: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output format
    #[arg(long, global = true, default_value = "table")]
    pub format: OutputFormat,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage host entries
    Host(HostArgs),
    /// Manage snapshots
    Snapshot(SnapshotArgs),
    /// Show effective configuration
    Config,
}

#[derive(Args)]
pub struct HostArgs {
    #[command(subcommand)]
    pub command: HostCommand,
}

#[derive(Subcommand)]
pub enum HostCommand {
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
        /// Tags (can be specified multiple times)
        #[arg(long = "tag")]
        tags: Vec<String>,
    },
    /// Get a host entry by ID
    Get {
        /// Host entry ID
        id: String,
    },
    /// Update an existing host entry
    Update {
        /// Host entry ID
        id: String,
        /// New IP address
        #[arg(long)]
        ip: Option<String>,
        /// New hostname
        #[arg(long)]
        hostname: Option<String>,
        /// New comment (empty string to clear)
        #[arg(long)]
        comment: Option<String>,
        /// Replace all tags
        #[arg(long = "tag")]
        tags: Option<Vec<String>>,
        /// Expected version for optimistic concurrency
        #[arg(long)]
        version: Option<String>,
    },
    /// Delete a host entry
    Delete {
        /// Host entry ID
        id: String,
    },
    /// List all host entries
    List {
        /// Filter expression
        #[arg(long)]
        filter: Option<String>,
        /// Maximum entries to return
        #[arg(long)]
        limit: Option<i32>,
        /// Number of entries to skip
        #[arg(long)]
        offset: Option<i32>,
    },
    /// Search host entries
    Search {
        /// Search query
        query: String,
    },
    /// Import hosts from file
    Import {
        /// Path to import file
        file: PathBuf,
        /// Import format: hosts, json, csv
        #[arg(long, default_value = "hosts")]
        format: String,
        /// Conflict mode: skip, replace, strict
        #[arg(long, default_value = "skip")]
        conflict_mode: String,
    },
    /// Export hosts to stdout
    Export {
        /// Export format: hosts, json, csv
        #[arg(long, default_value = "hosts")]
        format: String,
    },
}

#[derive(Args)]
pub struct SnapshotArgs {
    #[command(subcommand)]
    pub command: SnapshotCommand,
}

#[derive(Subcommand)]
pub enum SnapshotCommand {
    /// Create a new snapshot
    Create,
    /// List all snapshots
    List,
    /// Rollback to a snapshot
    Rollback {
        /// Snapshot ID to restore
        snapshot_id: String,
    },
    /// Delete a snapshot
    Delete {
        /// Snapshot ID to delete
        snapshot_id: String,
    },
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Host(args) => {
            eprintln!("Host command: {:?}", std::mem::discriminant(&args.command));
        }
        Commands::Snapshot(args) => {
            eprintln!(
                "Snapshot command: {:?}",
                std::mem::discriminant(&args.command)
            );
        }
        Commands::Config => {
            eprintln!("Config command");
        }
    }

    // TODO: Implement actual command handlers
    Ok(())
}
