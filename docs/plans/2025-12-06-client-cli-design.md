# Client CLI Design

**Date:** 2025-12-06
**Status:** Active
**Issue:** #11

## Overview

Implement the client CLI to interact with the router-hosts gRPC server. The server is complete; this design covers the client that makes it usable.

### Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Output format | Plain aligned columns | Simple, works everywhere, like kubectl/gh |
| Version conflicts | Fail-and-retry | Simple for v1.0; interactive resolution can come later |
| Import progress | Live progress line | Better UX for long operations |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                    main.rs                       │
│         (detect client vs server mode)           │
└─────────────────────┬───────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────┐
│               client/mod.rs                      │
│      CLI parsing (clap), command dispatch        │
└─────────────────────┬───────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────┐
│            client/commands/*.rs                  │
│  host.rs, snapshot.rs - command implementations  │
└─────────────────────┬───────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────┐
│             client/grpc.rs                       │
│    gRPC client wrapper with TLS setup            │
└─────────────────────┬───────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────┐
│           router_hosts_common                    │
│     Generated protobuf types and client stubs    │
└─────────────────────────────────────────────────┘
```

**Key components:**
- **CLI layer** - Parses args, loads config, dispatches to commands
- **Command layer** - Each command group (host, snapshot) in own module
- **gRPC layer** - Thin wrapper handling TLS setup and connection
- **Output layer** - Formats results as table/json/csv

## CLI Structure

Using clap with derive macros:

```rust
#[derive(Parser)]
#[command(name = "router-hosts")]
struct Cli {
    #[arg(short, long)] config: Option<PathBuf>,
    #[arg(short, long)] server: Option<String>,
    #[arg(long)] cert: Option<PathBuf>,
    #[arg(long)] key: Option<PathBuf>,
    #[arg(long)] ca: Option<PathBuf>,
    #[arg(short, long)] verbose: bool,
    #[arg(short, long)] quiet: bool,
    #[arg(long, default_value = "table")] format: OutputFormat,

    #[command(subcommand)] command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Host(HostArgs),
    Snapshot(SnapshotArgs),
    Config,  // Show effective config
}

#[derive(Args)]
struct HostArgs {
    #[command(subcommand)] command: HostCommand,
}

#[derive(Subcommand)]
enum HostCommand {
    Add { ip: String, hostname: String, comment: Option<String>, tags: Vec<String> },
    Get { id: String },
    Update { id: String, ip: Option<String>, hostname: Option<String>, ... },
    Delete { id: String },
    List { filter: Option<String>, limit: Option<u32>, offset: Option<u32> },
    Search { query: String },
    Import { file: PathBuf, format: Option<ImportFormat>, conflict_mode: Option<ConflictMode> },
    Export { format: Option<ExportFormat> },
}
```

**Enums:**
- `OutputFormat`: Table, Json, Csv
- `ConflictMode`: Skip (default), Replace, Strict
- `ImportFormat` / `ExportFormat`: Hosts, Json, Csv

## gRPC Client Wrapper

Thin wrapper in `client/grpc.rs`:

```rust
pub struct Client {
    inner: HostsServiceClient<Channel>,
}

impl Client {
    pub async fn connect(config: &ClientConfig) -> Result<Self> {
        // Load client cert + key for mTLS
        let identity = Identity::from_pem(
            tokio::fs::read(&config.cert_path).await?,
            tokio::fs::read(&config.key_path).await?,
        );

        // Load CA cert for server verification
        let ca_cert = Certificate::from_pem(
            tokio::fs::read(&config.ca_cert_path).await?
        );

        let tls = ClientTlsConfig::new()
            .identity(identity)
            .ca_certificate(ca_cert);

        let channel = Channel::from_shared(format\!("https://{}", config.server_address))?
            .tls_config(tls)?
            .connect()
            .await?;

        Ok(Self { inner: HostsServiceClient::new(channel) })
    }

    // Thin wrappers for each RPC
    pub async fn add_host(&mut self, req: AddHostRequest) -> Result<HostEntry> { ... }
    pub async fn list_hosts(&mut self, req: ListHostsRequest) -> Result<Vec<HostEntry>> { ... }
    // etc.
}
```

**Key points:**
- mTLS required (no insecure option)
- Connection created once per CLI invocation
- Methods return domain types, not raw responses
- Streaming RPCs handled internally

## Configuration

Merges from three sources (CLI > env > file):

```rust
#[derive(Debug, Deserialize, Default)]
pub struct ClientConfig {
    pub server_address: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
    pub output_format: OutputFormat,
}

impl ClientConfig {
    pub fn load(cli: &Cli) -> Result<Self> {
        // 1. Start with config file (if exists)
        let file_config = Self::load_from_file(cli.config.as_ref())?;

        // 2. Override with environment variables
        let env_config = Self::from_env()?;

        // 3. Override with CLI args
        Self::merge(file_config, env_config, cli)
    }

    fn default_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("router-hosts/client.toml")
    }
}
```

**Config file format:**
```toml
[server]
address = "router.local:50051"

[tls]
cert_path = "~/.config/router-hosts/client.crt"
key_path = "~/.config/router-hosts/client.key"
ca_cert_path = "~/.config/router-hosts/ca.crt"

[output]
format = "table"
```

**Environment variables:**
- `ROUTER_HOSTS_SERVER`
- `ROUTER_HOSTS_CERT`
- `ROUTER_HOSTS_KEY`
- `ROUTER_HOSTS_CA`

## Output Formatting

Simple output module in `client/output.rs`:

```rust
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

pub trait Outputable {
    fn to_table_row(&self) -> Vec<String>;
    fn table_headers() -> Vec<&'static str>;
}

impl Outputable for HostEntry {
    fn table_headers() -> Vec<&'static str> {
        vec\!["ID", "IP", "HOSTNAME", "COMMENT", "TAGS"]
    }

    fn to_table_row(&self) -> Vec<String> {
        vec\![
            self.id[..12].to_string(),  // Truncate ULID for display
            self.ip_address.clone(),
            self.hostname.clone(),
            self.comment.clone().unwrap_or_default(),
            self.tags.join(","),
        ]
    }
}

pub fn print_items<T: Outputable + Serialize>(items: &[T], format: OutputFormat) {
    match format {
        OutputFormat::Table => print_table(items),
        OutputFormat::Json => println\!("{}", serde_json::to_string_pretty(items).unwrap()),
        OutputFormat::Csv => print_csv(items),
    }
}
```

**Example table output:**
```
ID            IP              HOSTNAME         COMMENT       TAGS
01JF3K2M...   192.168.1.10    server.local     Dev server    homelab,dev
01JF3K2N...   192.168.1.20    nas.home.local   NAS storage   homelab
```

## Error Handling

Map gRPC errors to user-friendly messages:

```rust
pub fn handle_grpc_error(status: tonic::Status) -> anyhow::Error {
    match status.code() {
        Code::InvalidArgument => anyhow\!("Invalid input: {}", status.message()),
        Code::NotFound => anyhow\!("Not found: {}", status.message()),
        Code::AlreadyExists => anyhow\!("Already exists: {}", status.message()),
        Code::Aborted => anyhow\!("Version conflict: entry was modified. Re-fetch and try again."),
        Code::PermissionDenied => anyhow\!("Permission denied: check TLS certificates"),
        Code::Unavailable => anyhow\!("Server unavailable: check address and connectivity"),
        _ => anyhow\!("Server error: {}", status.message()),
    }
}

// Exit codes
pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_ERROR: i32 = 1;      // General error
pub const EXIT_USAGE: i32 = 2;      // Invalid arguments
pub const EXIT_CONFLICT: i32 = 3;   // Version conflict (for scripting)
```

**Behavior:**
- `--quiet`: Only show errors
- `--verbose`: Show request/response details
- Default: Results and user-friendly errors
- Version conflicts exit with code 3

## Testing

**Unit Tests:**
- Config parsing and merging
- Output formatting
- Error message formatting

**Integration Tests:**
- Full CLI invocations against test server
- Reuse existing test infrastructure

```rust
#[tokio::test]
async fn test_host_add_via_cli() {
    let server = start_test_server().await;

    let output = Command::new(env\!("CARGO_BIN_EXE_router-hosts"))
        .args(["--server", &server.address, "host", "add",
               "--ip", "192.168.1.10", "--hostname", "test.local"])
        .output()
        .expect("failed to run");

    assert\!(output.status.success());
}
```

## File Structure

```
crates/router-hosts/src/client/
├── mod.rs           # CLI parsing, main dispatch
├── config.rs        # Config loading and merging
├── grpc.rs          # gRPC client wrapper
├── output.rs        # Output formatting
├── error.rs         # Error handling and exit codes
└── commands/
    ├── mod.rs
    ├── host.rs      # host subcommands
    └── snapshot.rs  # snapshot subcommands
```
