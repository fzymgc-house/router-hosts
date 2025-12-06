# Client CLI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement a full-featured CLI client that connects to the router-hosts gRPC server.

**Architecture:** Layered design with CLI parsing (clap) → command handlers → gRPC client wrapper → proto types. Config loaded from CLI > env > file precedence.

**Tech Stack:** clap (CLI), tonic (gRPC client), rustls (TLS), serde/toml (config), anyhow (errors)

---

## Phase 1: Foundation

### Task 1: Restructure CLI with Subcommand Groups

**Files:**
- Modify: `crates/router-hosts/src/client/mod.rs`

**Step 1: Replace the current CLI stub with proper subcommand groups**

Replace the entire contents of `client/mod.rs`:

```rust
mod config;

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
            eprintln!("Snapshot command: {:?}", std::mem::discriminant(&args.command));
        }
        Commands::Config => {
            eprintln!("Config command");
        }
    }

    // TODO: Implement actual command handlers
    Ok(())
}
```

**Step 2: Build and verify CLI parses correctly**

Run: `cargo build -p router-hosts`
Expected: Builds successfully

**Step 3: Test CLI help output**

Run: `cargo run -- --help`
Expected: Shows router-hosts with host, snapshot, config subcommands

Run: `cargo run -- host --help`
Expected: Shows host subcommands (add, get, update, delete, list, search, import, export)

**Step 4: Commit**

```bash
git add crates/router-hosts/src/client/mod.rs
git commit -m "feat(client): restructure CLI with subcommand groups

Replace flat command structure with nested subcommands:
- host: add, get, update, delete, list, search, import, export
- snapshot: create, list, rollback, delete
- config: show effective configuration

Refs #11"
```

---

### Task 2: Configuration Loading with Precedence

**Files:**
- Modify: `crates/router-hosts/src/client/config.rs`
- Create: `crates/router-hosts/src/client/config_test.rs` (inline tests)

**Step 1: Write test for config file loading**

Add to `config.rs`:

```rust
use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::PathBuf;

/// Client configuration with all connection settings
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_address: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

/// Configuration file structure
#[derive(Debug, Deserialize)]
struct ConfigFile {
    server: Option<ServerSection>,
    tls: Option<TlsSection>,
}

#[derive(Debug, Deserialize)]
struct ServerSection {
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TlsSection {
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    ca_cert_path: Option<PathBuf>,
}

impl ClientConfig {
    /// Load configuration with precedence: CLI > env > file
    pub fn load(
        config_path: Option<&PathBuf>,
        cli_server: Option<&str>,
        cli_cert: Option<&PathBuf>,
        cli_key: Option<&PathBuf>,
        cli_ca: Option<&PathBuf>,
    ) -> Result<Self> {
        // Load from file if specified or default location
        let file_config = Self::load_from_file(config_path)?;

        // Build config with precedence: CLI > env > file
        let server_address = cli_server
            .map(String::from)
            .or_else(|| std::env::var("ROUTER_HOSTS_SERVER").ok())
            .or(file_config.as_ref().and_then(|f| {
                f.server.as_ref().and_then(|s| s.address.clone())
            }))
            .ok_or_else(|| anyhow!("Server address required: use --server, ROUTER_HOSTS_SERVER, or config file"))?;

        let cert_path = cli_cert
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_CERT").ok().map(PathBuf::from))
            .or(file_config.as_ref().and_then(|f| {
                f.tls.as_ref().and_then(|t| t.cert_path.clone())
            }))
            .map(|p| Self::expand_tilde(p))
            .ok_or_else(|| anyhow!("Client certificate required: use --cert, ROUTER_HOSTS_CERT, or config file"))?;

        let key_path = cli_key
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_KEY").ok().map(PathBuf::from))
            .or(file_config.as_ref().and_then(|f| {
                f.tls.as_ref().and_then(|t| t.key_path.clone())
            }))
            .map(|p| Self::expand_tilde(p))
            .ok_or_else(|| anyhow!("Client key required: use --key, ROUTER_HOSTS_KEY, or config file"))?;

        let ca_cert_path = cli_ca
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_CA").ok().map(PathBuf::from))
            .or(file_config.as_ref().and_then(|f| {
                f.tls.as_ref().and_then(|t| t.ca_cert_path.clone())
            }))
            .map(|p| Self::expand_tilde(p))
            .ok_or_else(|| anyhow!("CA certificate required: use --ca, ROUTER_HOSTS_CA, or config file"))?;

        Ok(Self {
            server_address,
            cert_path,
            key_path,
            ca_cert_path,
        })
    }

    fn load_from_file(path: Option<&PathBuf>) -> Result<Option<ConfigFile>> {
        let config_path = match path {
            Some(p) => p.clone(),
            None => {
                // Try default location
                let default = Self::default_config_path();
                if !default.exists() {
                    return Ok(None);
                }
                default
            }
        };

        if !config_path.exists() {
            if path.is_some() {
                // Explicitly specified path must exist
                return Err(anyhow!("Config file not found: {:?}", config_path));
            }
            return Ok(None);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let config: ConfigFile = toml::from_str(&content)?;
        Ok(Some(config))
    }

    fn default_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("router-hosts")
            .join("client.toml")
    }

    fn expand_tilde(path: PathBuf) -> PathBuf {
        if let Some(path_str) = path.to_str() {
            if path_str.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(&path_str[2..]);
                }
            }
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_from_cli_args() {
        let cert = PathBuf::from("/tmp/cert.pem");
        let key = PathBuf::from("/tmp/key.pem");
        let ca = PathBuf::from("/tmp/ca.pem");

        let config = ClientConfig::load(
            None,
            Some("localhost:50051"),
            Some(&cert),
            Some(&key),
            Some(&ca),
        )
        .unwrap();

        assert_eq!(config.server_address, "localhost:50051");
        assert_eq!(config.cert_path, cert);
    }

    #[test]
    fn test_load_from_config_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[server]
address = "router.local:50051"

[tls]
cert_path = "/etc/certs/client.crt"
key_path = "/etc/certs/client.key"
ca_cert_path = "/etc/certs/ca.crt"
"#
        )
        .unwrap();

        let config = ClientConfig::load(
            Some(&file.path().to_path_buf()),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(config.server_address, "router.local:50051");
        assert_eq!(config.cert_path, PathBuf::from("/etc/certs/client.crt"));
    }

    #[test]
    fn test_cli_overrides_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[server]
address = "router.local:50051"

[tls]
cert_path = "/file/cert.crt"
key_path = "/file/key.key"
ca_cert_path = "/file/ca.crt"
"#
        )
        .unwrap();

        let cli_cert = PathBuf::from("/cli/cert.crt");
        let config = ClientConfig::load(
            Some(&file.path().to_path_buf()),
            Some("cli-server:9999"),
            Some(&cli_cert),
            None,
            None,
        )
        .unwrap();

        assert_eq!(config.server_address, "cli-server:9999");
        assert_eq!(config.cert_path, cli_cert);
        assert_eq!(config.key_path, PathBuf::from("/file/key.key"));
    }

    #[test]
    fn test_missing_required_fields() {
        let result = ClientConfig::load(None, None, None, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Server address required"));
    }
}
```

**Step 2: Add dirs dependency to Cargo.toml**

Add to `crates/router-hosts/Cargo.toml` under `[dependencies]`:

```toml
dirs = "5"
```

**Step 3: Run tests**

Run: `cargo test -p router-hosts config`
Expected: All 4 tests pass

**Step 4: Commit**

```bash
git add crates/router-hosts/Cargo.toml crates/router-hosts/src/client/config.rs
git commit -m "feat(client): implement config loading with CLI > env > file precedence

Add ClientConfig::load() with:
- CLI argument priority
- Environment variable fallback
- Config file support with tilde expansion
- Proper error messages for missing required fields

Refs #11"
```

---

### Task 3: gRPC Client Wrapper with mTLS

**Files:**
- Create: `crates/router-hosts/src/client/grpc.rs`
- Modify: `crates/router-hosts/src/client/mod.rs`

**Step 1: Create the gRPC client wrapper**

Create `crates/router-hosts/src/client/grpc.rs`:

```rust
use anyhow::{Context, Result};
use router_hosts_common::proto::{
    hosts_service_client::HostsServiceClient, AddHostRequest, AddHostResponse,
    DeleteHostRequest, DeleteHostResponse, GetHostRequest, GetHostResponse,
    ListHostsRequest, ListHostsResponse, SearchHostsRequest, SearchHostsResponse,
    UpdateHostRequest, UpdateHostResponse,
    CreateSnapshotRequest, CreateSnapshotResponse,
    ListSnapshotsRequest, ListSnapshotsResponse,
    RollbackToSnapshotRequest, RollbackToSnapshotResponse,
    DeleteSnapshotRequest, DeleteSnapshotResponse,
    ExportHostsRequest, ExportHostsResponse,
    ImportHostsRequest, ImportHostsResponse,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use super::config::ClientConfig;

/// gRPC client wrapper with mTLS support
pub struct Client {
    inner: HostsServiceClient<Channel>,
}

impl Client {
    /// Connect to the server with mTLS
    pub async fn connect(config: &ClientConfig) -> Result<Self> {
        // Load client identity (cert + key)
        let cert_pem = tokio::fs::read(&config.cert_path)
            .await
            .with_context(|| format!("Failed to read client certificate: {:?}", config.cert_path))?;
        let key_pem = tokio::fs::read(&config.key_path)
            .await
            .with_context(|| format!("Failed to read client key: {:?}", config.key_path))?;
        let identity = Identity::from_pem(cert_pem, key_pem);

        // Load CA certificate
        let ca_pem = tokio::fs::read(&config.ca_cert_path)
            .await
            .with_context(|| format!("Failed to read CA certificate: {:?}", config.ca_cert_path))?;
        let ca_cert = Certificate::from_pem(ca_pem);

        // Configure TLS
        let tls_config = ClientTlsConfig::new()
            .identity(identity)
            .ca_certificate(ca_cert);

        // Build channel
        let endpoint = format!("https://{}", config.server_address);
        let channel = Channel::from_shared(endpoint)?
            .tls_config(tls_config)?
            .connect()
            .await
            .context("Failed to connect to server")?;

        Ok(Self {
            inner: HostsServiceClient::new(channel),
        })
    }

    // Host operations

    pub async fn add_host(&mut self, request: AddHostRequest) -> Result<AddHostResponse> {
        let response = self.inner.add_host(request).await?;
        Ok(response.into_inner())
    }

    pub async fn get_host(&mut self, request: GetHostRequest) -> Result<GetHostResponse> {
        let response = self.inner.get_host(request).await?;
        Ok(response.into_inner())
    }

    pub async fn update_host(&mut self, request: UpdateHostRequest) -> Result<UpdateHostResponse> {
        let response = self.inner.update_host(request).await?;
        Ok(response.into_inner())
    }

    pub async fn delete_host(&mut self, request: DeleteHostRequest) -> Result<DeleteHostResponse> {
        let response = self.inner.delete_host(request).await?;
        Ok(response.into_inner())
    }

    pub async fn list_hosts(&mut self, request: ListHostsRequest) -> Result<Vec<ListHostsResponse>> {
        let mut stream = self.inner.list_hosts(request).await?.into_inner();
        let mut results = Vec::new();
        while let Some(response) = stream.message().await? {
            results.push(response);
        }
        Ok(results)
    }

    pub async fn search_hosts(&mut self, request: SearchHostsRequest) -> Result<Vec<SearchHostsResponse>> {
        let mut stream = self.inner.search_hosts(request).await?.into_inner();
        let mut results = Vec::new();
        while let Some(response) = stream.message().await? {
            results.push(response);
        }
        Ok(results)
    }

    // Snapshot operations

    pub async fn create_snapshot(&mut self, request: CreateSnapshotRequest) -> Result<CreateSnapshotResponse> {
        let response = self.inner.create_snapshot(request).await?;
        Ok(response.into_inner())
    }

    pub async fn list_snapshots(&mut self, request: ListSnapshotsRequest) -> Result<Vec<ListSnapshotsResponse>> {
        let mut stream = self.inner.list_snapshots(request).await?.into_inner();
        let mut results = Vec::new();
        while let Some(response) = stream.message().await? {
            results.push(response);
        }
        Ok(results)
    }

    pub async fn rollback_to_snapshot(&mut self, request: RollbackToSnapshotRequest) -> Result<RollbackToSnapshotResponse> {
        let response = self.inner.rollback_to_snapshot(request).await?;
        Ok(response.into_inner())
    }

    pub async fn delete_snapshot(&mut self, request: DeleteSnapshotRequest) -> Result<DeleteSnapshotResponse> {
        let response = self.inner.delete_snapshot(request).await?;
        Ok(response.into_inner())
    }

    // Export operation

    pub async fn export_hosts(&mut self, request: ExportHostsRequest) -> Result<Vec<u8>> {
        let mut stream = self.inner.export_hosts(request).await?.into_inner();
        let mut data = Vec::new();
        while let Some(response) = stream.message().await? {
            data.extend_from_slice(&response.chunk);
        }
        Ok(data)
    }

    // Import operation (returns final status)

    pub async fn import_hosts<F>(
        &mut self,
        chunks: Vec<ImportHostsRequest>,
        mut on_progress: F,
    ) -> Result<ImportHostsResponse>
    where
        F: FnMut(&ImportHostsResponse),
    {
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        // Send chunks
        tokio::spawn(async move {
            for chunk in chunks {
                if tx.send(chunk).await.is_err() {
                    break;
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let mut response_stream = self.inner.import_hosts(stream).await?.into_inner();

        let mut last_response = None;
        while let Some(response) = response_stream.message().await? {
            on_progress(&response);
            last_response = Some(response);
        }

        last_response.ok_or_else(|| anyhow::anyhow!("No response from import"))
    }
}
```

**Step 2: Update client/mod.rs to export grpc module**

Add at top of `client/mod.rs`:

```rust
mod config;
mod grpc;

pub use config::ClientConfig;
pub use grpc::Client;
```

**Step 3: Add tokio-stream dependency**

Add to `crates/router-hosts/Cargo.toml`:

```toml
tokio-stream = "0.1"
```

**Step 4: Build to verify**

Run: `cargo build -p router-hosts`
Expected: Builds successfully

**Step 5: Commit**

```bash
git add crates/router-hosts/Cargo.toml crates/router-hosts/src/client/grpc.rs crates/router-hosts/src/client/mod.rs
git commit -m "feat(client): add gRPC client wrapper with mTLS

Implement Client struct wrapping HostsServiceClient with:
- mTLS connection using client cert/key and CA
- Wrapper methods for all RPC operations
- Streaming support for list/search/export
- Bidirectional streaming for import with progress callback

Refs #11"
```

---

## Phase 2: Output Formatting

### Task 4: Output Formatting Module

**Files:**
- Create: `crates/router-hosts/src/client/output.rs`
- Modify: `crates/router-hosts/src/client/mod.rs`

**Step 1: Create output formatting module**

Create `crates/router-hosts/src/client/output.rs`:

```rust
use router_hosts_common::proto::{HostEntry, Snapshot};
use serde::Serialize;

use super::OutputFormat;

/// Trait for types that can be displayed in table format
pub trait TableDisplay {
    fn headers() -> Vec<&'static str>;
    fn row(&self) -> Vec<String>;
}

impl TableDisplay for HostEntry {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "IP", "HOSTNAME", "COMMENT", "TAGS"]
    }

    fn row(&self) -> Vec<String> {
        let id_display = if self.id.len() > 12 {
            format!("{}...", &self.id[..12])
        } else {
            self.id.clone()
        };

        vec![
            id_display,
            self.ip_address.clone(),
            self.hostname.clone(),
            self.comment.clone().unwrap_or_default(),
            self.tags.join(","),
        ]
    }
}

impl TableDisplay for Snapshot {
    fn headers() -> Vec<&'static str> {
        vec!["ID", "CREATED", "ENTRIES", "TRIGGER"]
    }

    fn row(&self) -> Vec<String> {
        let id_display = if self.snapshot_id.len() > 12 {
            format!("{}...", &self.snapshot_id[..12])
        } else {
            self.snapshot_id.clone()
        };

        let created = self
            .created_at
            .as_ref()
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "invalid".to_string())
            })
            .unwrap_or_default();

        vec![
            id_display,
            created,
            self.entry_count.to_string(),
            self.trigger.clone(),
        ]
    }
}

/// Print items in the specified format
pub fn print_items<T>(items: &[T], format: OutputFormat)
where
    T: TableDisplay + Serialize,
{
    match format {
        OutputFormat::Table => print_table(items),
        OutputFormat::Json => print_json(items),
        OutputFormat::Csv => print_csv(items),
    }
}

/// Print a single item
pub fn print_item<T>(item: &T, format: OutputFormat)
where
    T: TableDisplay + Serialize,
{
    print_items(&[item], format);
}

fn print_table<T: TableDisplay>(items: &[T]) {
    if items.is_empty() {
        return;
    }

    let headers = T::headers();
    let rows: Vec<Vec<String>> = items.iter().map(|i| i.row()).collect();

    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }

    // Print header
    let header_line: Vec<String> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| format!("{:width$}", h, width = widths[i]))
        .collect();
    println!("{}", header_line.join("  "));

    // Print rows
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let width = widths.get(i).copied().unwrap_or(0);
                format!("{:width$}", cell, width = width)
            })
            .collect();
        println!("{}", line.join("  "));
    }
}

fn print_json<T: Serialize>(items: &[T]) {
    match serde_json::to_string_pretty(items) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error serializing to JSON: {}", e),
    }
}

fn print_csv<T: TableDisplay>(items: &[T]) {
    let headers = T::headers();
    println!("{}", headers.join(","));

    for item in items {
        let row = item.row();
        let escaped: Vec<String> = row
            .iter()
            .map(|cell| {
                if cell.contains(',') || cell.contains('"') || cell.contains('\n') {
                    format!("\"{}\"", cell.replace('"', "\"\""))
                } else {
                    cell.clone()
                }
            })
            .collect();
        println!("{}", escaped.join(","));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_entry_row() {
        let entry = HostEntry {
            id: "01JXXXXXXXXXXXXXXXXX".to_string(),
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: Some("Test host".to_string()),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            created_at: None,
            updated_at: None,
            version: "1".to_string(),
        };

        let row = entry.row();
        assert_eq!(row[0], "01JXXXXXXXXX...");
        assert_eq!(row[1], "192.168.1.1");
        assert_eq!(row[2], "test.local");
        assert_eq!(row[3], "Test host");
        assert_eq!(row[4], "tag1,tag2");
    }

    #[test]
    fn test_csv_escaping() {
        let entry = HostEntry {
            id: "01J".to_string(),
            ip_address: "1.1.1.1".to_string(),
            hostname: "test".to_string(),
            comment: Some("Has, comma".to_string()),
            tags: vec![],
            created_at: None,
            updated_at: None,
            version: "1".to_string(),
        };

        let row = entry.row();
        // The comment should be escaped when printed
        assert!(row[3].contains(','));
    }
}
```

**Step 2: Add chrono dependency**

Add to `crates/router-hosts/Cargo.toml`:

```toml
chrono = "0.4"
```

**Step 3: Update mod.rs to export output module**

Update exports in `client/mod.rs`:

```rust
mod config;
mod grpc;
mod output;

pub use config::ClientConfig;
pub use grpc::Client;
pub use output::{print_item, print_items, TableDisplay};
```

**Step 4: Run tests**

Run: `cargo test -p router-hosts output`
Expected: Tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/Cargo.toml crates/router-hosts/src/client/output.rs crates/router-hosts/src/client/mod.rs
git commit -m "feat(client): add output formatting (table, json, csv)

Implement TableDisplay trait and print functions:
- Plain aligned column table output
- JSON pretty-printed output
- CSV with proper escaping
- Support for HostEntry and Snapshot types

Refs #11"
```

---

## Phase 3: Command Handlers

### Task 5: Error Handling Module

**Files:**
- Create: `crates/router-hosts/src/client/error.rs`
- Modify: `crates/router-hosts/src/client/mod.rs`

**Step 1: Create error handling module**

Create `crates/router-hosts/src/client/error.rs`:

```rust
use tonic::{Code, Status};

/// Exit codes following Unix conventions
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_CONFLICT: i32 = 3;

/// Convert gRPC status to user-friendly error message
pub fn format_grpc_error(status: &Status) -> String {
    match status.code() {
        Code::InvalidArgument => format!("Invalid input: {}", status.message()),
        Code::NotFound => format!("Not found: {}", status.message()),
        Code::AlreadyExists => format!("Already exists: {}", status.message()),
        Code::Aborted => "Version conflict: entry was modified. Re-fetch and try again.".to_string(),
        Code::PermissionDenied => "Permission denied: check TLS certificates".to_string(),
        Code::Unavailable => "Server unavailable: check address and connectivity".to_string(),
        Code::Unauthenticated => "Authentication failed: check TLS certificates".to_string(),
        _ => format!("Server error: {}", status.message()),
    }
}

/// Get exit code for gRPC status
pub fn exit_code_for_status(status: &Status) -> i32 {
    match status.code() {
        Code::InvalidArgument => EXIT_USAGE,
        Code::Aborted => EXIT_CONFLICT,
        _ => EXIT_ERROR,
    }
}
```

**Step 2: Update mod.rs exports**

Add to `client/mod.rs`:

```rust
mod error;

pub use error::{format_grpc_error, exit_code_for_status, EXIT_SUCCESS, EXIT_ERROR, EXIT_USAGE, EXIT_CONFLICT};
```

**Step 3: Commit**

```bash
git add crates/router-hosts/src/client/error.rs crates/router-hosts/src/client/mod.rs
git commit -m "feat(client): add error handling with exit codes

Map gRPC status codes to user-friendly messages:
- InvalidArgument -> EXIT_USAGE (2)
- Aborted (version conflict) -> EXIT_CONFLICT (3)
- Other errors -> EXIT_ERROR (1)

Refs #11"
```

---

### Task 6: Host Command Handlers

**Files:**
- Create: `crates/router-hosts/src/client/commands/mod.rs`
- Create: `crates/router-hosts/src/client/commands/host.rs`
- Modify: `crates/router-hosts/src/client/mod.rs`

**Step 1: Create commands directory and host.rs**

Create `crates/router-hosts/src/client/commands/mod.rs`:

```rust
pub mod host;
pub mod snapshot;
```

Create `crates/router-hosts/src/client/commands/host.rs`:

```rust
use anyhow::Result;
use router_hosts_common::proto::{
    AddHostRequest, DeleteHostRequest, GetHostRequest, ListHostsRequest,
    SearchHostsRequest, UpdateHostRequest, ExportHostsRequest, ImportHostsRequest,
};
use std::io::{self, Write};
use std::path::Path;

use crate::client::{Client, HostCommand, OutputFormat, print_item, print_items};

const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

pub async fn handle(client: &mut Client, command: HostCommand, format: OutputFormat, quiet: bool) -> Result<()> {
    match command {
        HostCommand::Add { ip, hostname, comment, tags } => {
            let request = AddHostRequest {
                ip_address: ip,
                hostname,
                comment,
                tags,
            };
            let response = client.add_host(request).await?;
            if !quiet {
                if let Some(entry) = response.entry {
                    print_item(&entry, format);
                }
            }
        }

        HostCommand::Get { id } => {
            let request = GetHostRequest { id };
            let response = client.get_host(request).await?;
            if let Some(entry) = response.entry {
                print_item(&entry, format);
            }
        }

        HostCommand::Update { id, ip, hostname, comment, tags, version } => {
            let request = UpdateHostRequest {
                id,
                ip_address: ip,
                hostname,
                comment,
                tags: tags.unwrap_or_default(),
                expected_version: version,
            };
            let response = client.update_host(request).await?;
            if !quiet {
                if let Some(entry) = response.entry {
                    print_item(&entry, format);
                }
            }
        }

        HostCommand::Delete { id } => {
            let request = DeleteHostRequest { id };
            let response = client.delete_host(request).await?;
            if !quiet {
                if response.success {
                    eprintln!("Deleted successfully");
                }
            }
        }

        HostCommand::List { filter, limit, offset } => {
            let request = ListHostsRequest { filter, limit, offset };
            let responses = client.list_hosts(request).await?;
            let entries: Vec<_> = responses.into_iter().filter_map(|r| r.entry).collect();
            print_items(&entries, format);
        }

        HostCommand::Search { query } => {
            let request = SearchHostsRequest { query };
            let responses = client.search_hosts(request).await?;
            let entries: Vec<_> = responses.into_iter().filter_map(|r| r.entry).collect();
            print_items(&entries, format);
        }

        HostCommand::Export { format: export_format } => {
            let request = ExportHostsRequest { format: export_format };
            let data = client.export_hosts(request).await?;
            io::stdout().write_all(&data)?;
        }

        HostCommand::Import { file, format: import_format, conflict_mode } => {
            let chunks = read_file_chunks(&file, &import_format, &conflict_mode)?;

            let final_response = client
                .import_hosts(chunks, |progress| {
                    if !quiet {
                        eprint!(
                            "\rProcessed: {}, Created: {}, Updated: {}, Skipped: {}, Failed: {}",
                            progress.processed,
                            progress.created,
                            progress.updated,
                            progress.skipped,
                            progress.failed
                        );
                    }
                })
                .await?;

            if !quiet {
                eprintln!(); // New line after progress
                eprintln!(
                    "Import complete: {} processed, {} created, {} updated, {} skipped, {} failed",
                    final_response.processed,
                    final_response.created,
                    final_response.updated,
                    final_response.skipped,
                    final_response.failed
                );

                for error in &final_response.validation_errors {
                    eprintln!("  {}", error);
                }
            }
        }
    }
    Ok(())
}

fn read_file_chunks(path: &Path, format: &str, conflict_mode: &str) -> Result<Vec<ImportHostsRequest>> {
    let data = std::fs::read(path)?;
    let mut chunks = Vec::new();
    let total_chunks = (data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;

    for (i, chunk_data) in data.chunks(CHUNK_SIZE).enumerate() {
        let is_last = i == total_chunks - 1;
        chunks.push(ImportHostsRequest {
            chunk: chunk_data.to_vec(),
            last_chunk: is_last,
            format: if i == 0 { Some(format.to_string()) } else { None },
            conflict_mode: if i == 0 { Some(conflict_mode.to_string()) } else { None },
        });
    }

    Ok(chunks)
}
```

**Step 2: Create snapshot.rs stub**

Create `crates/router-hosts/src/client/commands/snapshot.rs`:

```rust
use anyhow::Result;
use router_hosts_common::proto::{
    CreateSnapshotRequest, DeleteSnapshotRequest, ListSnapshotsRequest,
    RollbackToSnapshotRequest,
};

use crate::client::{Client, OutputFormat, SnapshotCommand, print_items};

pub async fn handle(client: &mut Client, command: SnapshotCommand, format: OutputFormat, quiet: bool) -> Result<()> {
    match command {
        SnapshotCommand::Create => {
            let request = CreateSnapshotRequest {};
            let response = client.create_snapshot(request).await?;
            if !quiet {
                eprintln!("Created snapshot: {}", response.snapshot_id);
            }
        }

        SnapshotCommand::List => {
            let request = ListSnapshotsRequest {};
            let responses = client.list_snapshots(request).await?;
            let snapshots: Vec<_> = responses.into_iter().filter_map(|r| r.snapshot).collect();
            print_items(&snapshots, format);
        }

        SnapshotCommand::Rollback { snapshot_id } => {
            let request = RollbackToSnapshotRequest { snapshot_id };
            let response = client.rollback_to_snapshot(request).await?;
            if !quiet {
                if response.success {
                    eprintln!("Rolled back successfully");
                    eprintln!("Backup snapshot created: {}", response.new_snapshot_id);
                }
            }
        }

        SnapshotCommand::Delete { snapshot_id } => {
            let request = DeleteSnapshotRequest { snapshot_id };
            let response = client.delete_snapshot(request).await?;
            if !quiet {
                if response.success {
                    eprintln!("Deleted snapshot successfully");
                }
            }
        }
    }
    Ok(())
}
```

**Step 3: Update mod.rs to wire up commands**

Replace the run() function in `client/mod.rs`:

```rust
mod commands;
mod config;
mod error;
mod grpc;
mod output;

pub use config::ClientConfig;
pub use error::{exit_code_for_status, format_grpc_error, EXIT_CONFLICT, EXIT_ERROR, EXIT_SUCCESS, EXIT_USAGE};
pub use grpc::Client;
pub use output::{print_item, print_items, TableDisplay};

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

// ... (keep all the CLI struct definitions from Task 1)

pub async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

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
            commands::host::handle(&mut client, args.command, cli.format, cli.quiet).await
        }
        Commands::Snapshot(args) => {
            commands::snapshot::handle(&mut client, args.command, cli.format, cli.quiet).await
        }
        Commands::Config => {
            println!("Server: {}", config.server_address);
            println!("Certificate: {:?}", config.cert_path);
            println!("Key: {:?}", config.key_path);
            println!("CA: {:?}", config.ca_cert_path);
            Ok(())
        }
    };

    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) => {
            // Check if it's a gRPC error
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
```

**Step 4: Update main.rs to use ExitCode**

Modify `crates/router-hosts/src/main.rs` client call:

```rust
// In the else branch for client mode:
match client::run().await {
    Ok(code) => std::process::exit(code.into()),
    Err(e) => {
        eprintln!("Fatal error: {}", e);
        std::process::exit(1);
    }
}
```

**Step 5: Build to verify**

Run: `cargo build -p router-hosts`
Expected: Builds successfully

**Step 6: Commit**

```bash
git add crates/router-hosts/src/client/commands/ crates/router-hosts/src/client/mod.rs crates/router-hosts/src/main.rs
git commit -m "feat(client): implement all command handlers

Add command handlers for:
- host: add, get, update, delete, list, search, import, export
- snapshot: create, list, rollback, delete
- config: show effective configuration

Wire up CLI -> config -> client -> commands flow with proper
error handling and exit codes.

Refs #11"
```

---

## Phase 4: Integration Testing

### Task 7: Client Integration Tests

**Files:**
- Modify: `crates/router-hosts/tests/integration_test.rs`

**Step 1: Add CLI integration tests**

Add to end of `integration_test.rs`:

```rust
// CLI Integration Tests

#[tokio::test]
async fn test_cli_host_add_and_get() {
    let fixture = TestFixture::new().await;
    let server_addr = fixture.addr.clone();

    // Start server in background
    let server_handle = tokio::spawn(async move {
        fixture.run_server().await;
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Test add command
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_router-hosts"))
        .args([
            "--server", &server_addr,
            "--cert", "test-certs/client.crt",
            "--key", "test-certs/client.key",
            "--ca", "test-certs/ca.crt",
            "--format", "json",
            "host", "add",
            "--ip", "192.168.1.100",
            "--hostname", "cli-test.local",
        ])
        .output()
        .expect("Failed to run CLI");

    assert!(output.status.success(), "CLI add failed: {:?}", String::from_utf8_lossy(&output.stderr));

    server_handle.abort();
}
```

**Note:** This test requires test certificates to be set up. The existing integration tests already have certificate generation - reuse that infrastructure.

**Step 2: Run integration tests**

Run: `cargo test -p router-hosts --test integration_test cli`
Expected: Test passes (or skip if cert setup not ready)

**Step 3: Commit**

```bash
git add crates/router-hosts/tests/integration_test.rs
git commit -m "test(client): add CLI integration test

Verify CLI can add and retrieve hosts via gRPC.

Refs #11"
```

---

## Final Steps

### Task 8: Final Cleanup and Documentation

**Step 1: Run full test suite**

Run: `cargo test --workspace`
Expected: All tests pass

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No warnings

**Step 3: Format code**

Run: `cargo fmt`

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore(client): final cleanup and formatting

Refs #11"
```

---

## Summary

This plan implements the client CLI in 8 tasks:

1. **CLI Structure** - Subcommand groups with clap
2. **Configuration** - Load with CLI > env > file precedence
3. **gRPC Client** - Wrapper with mTLS support
4. **Output Formatting** - Table, JSON, CSV output
5. **Error Handling** - User-friendly messages and exit codes
6. **Command Handlers** - All host and snapshot commands
7. **Integration Tests** - CLI end-to-end tests
8. **Cleanup** - Final polish and documentation

Each task follows TDD with small, focused commits.
