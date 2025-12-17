//! Client CLI for router-hosts gRPC server.
//!
//! This module provides a complete CLI client for managing host entries and snapshots
//! via gRPC with mTLS authentication. Configuration is loaded from CLI args, environment
//! variables, or config file with proper precedence (CLI > env > file).

mod commands;
mod config;
mod error;
mod grpc;
mod output;

pub use config::ClientConfig;
pub use error::{exit_code_for_status, format_grpc_error, EXIT_ERROR, EXIT_USAGE};
pub use grpc::Client;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Csv,
}

/// File format for import/export operations.
///
/// This enum provides compile-time validation for file formats,
/// eliminating runtime string parsing errors.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum FileFormat {
    /// Standard /etc/hosts format: `IP hostname [hostname...]`
    #[default]
    Hosts,
    /// JSON array of host entry objects
    Json,
    /// CSV with columns: ip_address, hostname, comment, tags
    Csv,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileFormat::Hosts => write!(f, "hosts"),
            FileFormat::Json => write!(f, "json"),
            FileFormat::Csv => write!(f, "csv"),
        }
    }
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

    /// Non-interactive mode: fail immediately on conflicts without prompting
    #[arg(long, global = true)]
    pub non_interactive: bool,

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
        /// Aliases (can be specified multiple times)
        #[arg(long = "alias")]
        aliases: Vec<String>,
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
        tags: Vec<String>,
        /// Replace all aliases
        #[arg(long = "alias")]
        aliases: Vec<String>,
        /// Clear all tags
        #[arg(long)]
        clear_tags: bool,
        /// Clear all aliases
        #[arg(long)]
        clear_aliases: bool,
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
        /// Input file format
        #[arg(long, value_enum, default_value_t = FileFormat::Hosts)]
        input_format: FileFormat,
        /// Conflict mode: skip, replace, strict
        #[arg(long, default_value = "skip")]
        conflict_mode: String,
    },
    /// Export hosts to stdout
    Export {
        /// Output format for export
        #[arg(long, value_enum, default_value_t = FileFormat::Hosts)]
        export_format: FileFormat,
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

pub async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    // Handle Config command early (doesn't need connection)
    if matches!(cli.command, Commands::Config) {
        // Show what config would be used (without actually connecting)
        match ClientConfig::load(
            cli.config.as_ref(),
            cli.server.as_deref(),
            cli.cert.as_ref(),
            cli.key.as_ref(),
            cli.ca.as_ref(),
        ) {
            Ok(config) => {
                println!("Server: {}", config.server_address);
                println!("Certificate: {:?}", config.cert_path);
                println!("Key: {:?}", config.key_path);
                println!("CA: {:?}", config.ca_cert_path);
                return Ok(ExitCode::SUCCESS);
            }
            Err(e) => {
                eprintln!("Configuration error: {}", e);
                return Ok(ExitCode::from(EXIT_USAGE as u8));
            }
        }
    }

    // Load configuration
    let config = match ClientConfig::load(
        cli.config.as_ref(),
        cli.server.as_deref(),
        cli.cert.as_ref(),
        cli.key.as_ref(),
        cli.ca.as_ref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            return Ok(ExitCode::from(EXIT_USAGE as u8));
        }
    };

    // Connect to server
    let mut client = match Client::connect(&config).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Connection error: {}", e);
            return Ok(ExitCode::from(EXIT_ERROR as u8));
        }
    };

    // Execute command
    let result = match cli.command {
        Commands::Host(args) => {
            commands::host::handle(
                &mut client,
                args.command,
                cli.format,
                cli.quiet,
                cli.non_interactive,
            )
            .await
        }
        Commands::Snapshot(args) => {
            commands::snapshot::handle(&mut client, args.command, cli.format, cli.quiet).await
        }
        Commands::Config => unreachable!(), // Handled above
    };

    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) => {
            if let Some(status) = e.downcast_ref::<tonic::Status>() {
                eprintln!("{}", format_grpc_error(status));
                Ok(ExitCode::from(exit_code_for_status(status) as u8))
            } else {
                eprintln!("Error: {}", e);
                Ok(ExitCode::from(EXIT_ERROR as u8))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parse_host_add() {
        let cli = Cli::try_parse_from([
            "router-hosts",
            "host",
            "add",
            "--ip",
            "192.168.1.1",
            "--hostname",
            "test.local",
        ])
        .unwrap();

        match cli.command {
            Commands::Host(args) => match args.command {
                HostCommand::Add { ip, hostname, .. } => {
                    assert_eq!(ip, "192.168.1.1");
                    assert_eq!(hostname, "test.local");
                }
                _ => panic!("Expected Add command"),
            },
            _ => panic!("Expected Host command"),
        }
    }

    #[test]
    fn test_cli_parse_host_add_with_tags() {
        let cli = Cli::try_parse_from([
            "router-hosts",
            "host",
            "add",
            "--ip",
            "10.0.0.1",
            "--hostname",
            "server.local",
            "--tag",
            "prod",
            "--tag",
            "web",
        ])
        .unwrap();

        if let Commands::Host(args) = cli.command {
            if let HostCommand::Add { tags, .. } = args.command {
                assert_eq!(tags, vec!["prod", "web"]);
            }
        }
    }

    #[test]
    fn test_cli_parse_snapshot_rollback() {
        let cli =
            Cli::try_parse_from(["router-hosts", "snapshot", "rollback", "01JXXXXXXXXXX"]).unwrap();

        match cli.command {
            Commands::Snapshot(args) => match args.command {
                SnapshotCommand::Rollback { snapshot_id } => {
                    assert_eq!(snapshot_id, "01JXXXXXXXXXX");
                }
                _ => panic!("Expected Rollback command"),
            },
            _ => panic!("Expected Snapshot command"),
        }
    }

    #[test]
    fn test_cli_parse_global_options() {
        let cli = Cli::try_parse_from([
            "router-hosts",
            "--server",
            "localhost:50051",
            "--format",
            "json",
            "-q",
            "host",
            "list",
        ])
        .unwrap();

        assert_eq!(cli.server, Some("localhost:50051".to_string()));
        assert!(matches!(cli.format, OutputFormat::Json));
        assert!(cli.quiet);
    }

    #[test]
    fn test_cli_parse_config_command() {
        let cli = Cli::try_parse_from(["router-hosts", "config"]).unwrap();
        assert!(matches!(cli.command, Commands::Config));
    }

    #[test]
    fn test_cli_parse_host_import_with_format() {
        // Regression test for issue #69: format argument conflict
        let cli = Cli::try_parse_from([
            "router-hosts",
            "host",
            "import",
            "/tmp/test.txt",
            "--input-format",
            "json",
        ])
        .unwrap();

        match cli.command {
            Commands::Host(args) => match args.command {
                HostCommand::Import { input_format, .. } => {
                    assert!(matches!(input_format, FileFormat::Json));
                }
                _ => panic!("Expected Import command"),
            },
            _ => panic!("Expected Host command"),
        }
    }

    #[test]
    fn test_cli_parse_host_export_with_format() {
        // Regression test for issue #69: format argument conflict
        let cli = Cli::try_parse_from(["router-hosts", "host", "export", "--export-format", "csv"])
            .unwrap();

        match cli.command {
            Commands::Host(args) => match args.command {
                HostCommand::Export { export_format } => {
                    assert!(matches!(export_format, FileFormat::Csv));
                }
                _ => panic!("Expected Export command"),
            },
            _ => panic!("Expected Host command"),
        }
    }

    #[test]
    fn test_cli_global_format_does_not_conflict() {
        // Verify global --format (output) and command-specific formats coexist
        let cli = Cli::try_parse_from([
            "router-hosts",
            "--format",
            "json",
            "host",
            "import",
            "/tmp/test.txt",
            "--input-format",
            "hosts",
        ])
        .unwrap();

        assert!(matches!(cli.format, OutputFormat::Json));
        match cli.command {
            Commands::Host(args) => match args.command {
                HostCommand::Import { input_format, .. } => {
                    assert!(matches!(input_format, FileFormat::Hosts));
                }
                _ => panic!("Expected Import command"),
            },
            _ => panic!("Expected Host command"),
        }
    }
}
