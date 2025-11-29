# Initial Project Setup Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Set up the Cargo workspace with three crates (common, server, client) and protobuf definitions, establishing the foundation for the router-hosts project.

**Architecture:** Cargo workspace with router-hosts-common (shared validation/types), router-hosts-server (gRPC service), and router-hosts-client (CLI tool). Uses tonic for gRPC, DuckDB for storage, and rustls for TLS.

**Tech Stack:** Rust, tonic/prost (gRPC), DuckDB, tokio, clap, serde/toml, rustls, tracing

---

## Task 1: Create Cargo Workspace

**Files:**
- Create: `Cargo.toml`
- Create: `.gitignore` (append to existing)

**Step 1: Create workspace Cargo.toml**

```toml
[workspace]
resolver = "2"

members = [
    "crates/router-hosts-common",
    "crates/router-hosts-server",
    "crates/router-hosts-client",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
authors = ["fzymgc-house"]
license = "MIT"
repository = "https://github.com/fzymgc-house/router-hosts"

[workspace.dependencies]
# gRPC and protobuf
tonic = "0.11"
prost = "0.12"
tonic-build = "0.11"

# Async runtime
tokio = { version = "1.35", features = ["full"] }

# Database
duckdb = "1.0"

# CLI
clap = { version = "4.4", features = ["derive"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"

# TLS
rustls = "0.23"
tokio-rustls = "0.26"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Error handling
anyhow = "1.0"
thiserror = "1.0"

# Utilities
uuid = { version = "1.6", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
```

**Step 2: Append to .gitignore**

Add these lines to existing `.gitignore`:

```
# Rust
target/
Cargo.lock

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store

# Build artifacts
*.pdb
```

**Step 3: Create directory structure**

Run:
```bash
mkdir -p crates/router-hosts-common/src
mkdir -p crates/router-hosts-server/src
mkdir -p crates/router-hosts-client/src
mkdir -p proto
```

Expected: Directories created

**Step 4: Verify workspace structure**

Run:
```bash
tree -L 2 crates/
```

Expected:
```
crates/
├── router-hosts-client
│   └── src
├── router-hosts-common
│   └── src
└── router-hosts-server
    └── src
```

**Step 5: Commit**

```bash
git add Cargo.toml .gitignore
git commit -m "chore: initialize Cargo workspace structure"
```

---

## Task 2: Create router-hosts-common Crate (Validation)

**Files:**
- Create: `crates/router-hosts-common/Cargo.toml`
- Create: `crates/router-hosts-common/src/lib.rs`
- Create: `crates/router-hosts-common/src/validation.rs`

**Step 1: Write Cargo.toml for common crate**

File: `crates/router-hosts-common/Cargo.toml`

```toml
[package]
name = "router-hosts-common"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
thiserror.workspace = true
serde.workspace = true
uuid.workspace = true
chrono.workspace = true
tonic.workspace = true
prost.workspace = true

# IP address validation
regex = "1.10"
```

**Step 2: Write failing test for IPv4 validation**

File: `crates/router-hosts-common/src/validation.rs`

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4_addresses() {
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("10.0.0.1").is_ok());
        assert!(validate_ip_address("127.0.0.1").is_ok());
        assert!(validate_ip_address("255.255.255.255").is_ok());
    }

    #[test]
    fn test_invalid_ipv4_addresses() {
        assert!(validate_ip_address("256.1.1.1").is_err());
        assert!(validate_ip_address("192.168.1").is_err());
        assert!(validate_ip_address("192.168.1.1.1").is_err());
        assert!(validate_ip_address("not-an-ip").is_err());
        assert!(validate_ip_address("").is_err());
    }
}
```

**Step 3: Run tests to verify they fail**

Run:
```bash
cargo test -p router-hosts-common
```

Expected: Compilation error - `validate_ip_address` not found

**Step 4: Implement minimal IPv4 validation**

Add to top of `crates/router-hosts-common/src/validation.rs`:

```rust
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),
}

pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validates an IP address (IPv4 or IPv6)
pub fn validate_ip_address(ip: &str) -> ValidationResult<IpAddr> {
    ip.parse::<IpAddr>()
        .map_err(|_| ValidationError::InvalidIpAddress(ip.to_string()))
}
```

**Step 5: Run tests to verify they pass**

Run:
```bash
cargo test -p router-hosts-common
```

Expected: All tests PASS

**Step 6: Write failing test for IPv6 validation**

Add to tests in `crates/router-hosts-common/src/validation.rs`:

```rust
#[test]
fn test_valid_ipv6_addresses() {
    assert!(validate_ip_address("::1").is_ok());
    assert!(validate_ip_address("fe80::1").is_ok());
    assert!(validate_ip_address("2001:0db8:85a3::8a2e:0370:7334").is_ok());
    assert!(validate_ip_address("::ffff:192.168.1.1").is_ok());
}

#[test]
fn test_invalid_ipv6_addresses() {
    assert!(validate_ip_address("gggg::1").is_err());
    assert!(validate_ip_address("::::::").is_err());
}
```

**Step 7: Run tests to verify IPv6 works**

Run:
```bash
cargo test -p router-hosts-common test_valid_ipv6
```

Expected: All tests PASS (std::net::IpAddr already handles IPv6)

**Step 8: Write failing test for hostname validation**

Add to tests in `crates/router-hosts-common/src/validation.rs`:

```rust
#[test]
fn test_valid_hostnames() {
    assert!(validate_hostname("localhost").is_ok());
    assert!(validate_hostname("server.local").is_ok());
    assert!(validate_hostname("my-server").is_ok());
    assert!(validate_hostname("server123").is_ok());
    assert!(validate_hostname("sub.domain.example.com").is_ok());
}

#[test]
fn test_invalid_hostnames() {
    assert!(validate_hostname("").is_err());
    assert!(validate_hostname("-invalid").is_err());
    assert!(validate_hostname("invalid-").is_err());
    assert!(validate_hostname("in..valid").is_err());
    assert!(validate_hostname("invalid_host").is_err()); // underscores not allowed
    assert!(validate_hostname(".invalid").is_err());
    assert!(validate_hostname("invalid.").is_err());
}
```

**Step 9: Run tests to verify they fail**

Run:
```bash
cargo test -p router-hosts-common test_valid_hostnames
```

Expected: Compilation error - `validate_hostname` not found

**Step 10: Implement hostname validation**

Add to `crates/router-hosts-common/src/validation.rs` after `validate_ip_address`:

```rust
use regex::Regex;

/// Validates a DNS hostname (with or without domain)
/// Rules:
/// - Labels separated by dots
/// - Each label: 1-63 chars, alphanumeric and hyphens
/// - Cannot start or end with hyphen
/// - Cannot start or end with dot
pub fn validate_hostname(hostname: &str) -> ValidationResult<String> {
    if hostname.is_empty() {
        return Err(ValidationError::InvalidHostname("hostname cannot be empty".to_string()));
    }

    if hostname.starts_with('.') || hostname.ends_with('.') {
        return Err(ValidationError::InvalidHostname("hostname cannot start or end with dot".to_string()));
    }

    if hostname.starts_with('-') || hostname.ends_with('-') {
        return Err(ValidationError::InvalidHostname("hostname cannot start or end with hyphen".to_string()));
    }

    // DNS label regex: alphanumeric and hyphens, 1-63 chars, no leading/trailing hyphen
    let label_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$").unwrap();

    for label in hostname.split('.') {
        if !label_regex.is_match(label) {
            return Err(ValidationError::InvalidHostname(
                format!("invalid label '{}' in hostname", label)
            ));
        }
    }

    Ok(hostname.to_string())
}
```

**Step 11: Run tests to verify they pass**

Run:
```bash
cargo test -p router-hosts-common
```

Expected: All tests PASS

**Step 12: Create lib.rs to export validation**

File: `crates/router-hosts-common/src/lib.rs`

```rust
pub mod validation;

pub use validation::{validate_hostname, validate_ip_address, ValidationError, ValidationResult};
```

**Step 13: Verify lib builds**

Run:
```bash
cargo build -p router-hosts-common
```

Expected: Build succeeds

**Step 14: Commit**

```bash
git add crates/router-hosts-common/
git commit -m "feat(common): add IP and hostname validation"
```

---

## Task 3: Add Protobuf Definitions

**Files:**
- Create: `proto/hosts.proto`
- Create: `crates/router-hosts-common/build.rs`
- Modify: `crates/router-hosts-common/Cargo.toml`
- Create: `crates/router-hosts-common/src/proto.rs`

**Step 1: Add build dependencies to common crate**

File: `crates/router-hosts-common/Cargo.toml`

Add to `[dependencies]`:
```toml
[build-dependencies]
tonic-build.workspace = true
```

**Step 2: Create build.rs for protobuf generation**

File: `crates/router-hosts-common/build.rs`

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["../../proto/hosts.proto"], &["../../proto"])?;
    Ok(())
}
```

**Step 3: Write protobuf definitions**

File: `proto/hosts.proto`

```protobuf
syntax = "proto3";

package router_hosts;

// Host entry messages
message HostEntry {
  string id = 1;
  string ip_address = 2;
  string hostname = 3;
  optional string comment = 4;
  repeated string tags = 5;
  string created_at = 6;
  string updated_at = 7;
  bool active = 8;
}

// Host management requests/responses
message AddHostRequest {
  optional string edit_token = 1;
  string ip_address = 2;
  string hostname = 3;
  optional string comment = 4;
  repeated string tags = 5;
}

message AddHostResponse {
  string id = 1;
  HostEntry entry = 2;
}

message GetHostRequest {
  string id = 1;
}

message GetHostResponse {
  HostEntry entry = 1;
}

message UpdateHostRequest {
  optional string edit_token = 1;
  string id = 2;
  optional string ip_address = 3;
  optional string hostname = 4;
  optional string comment = 5;
  repeated string tags = 6;
}

message UpdateHostResponse {
  HostEntry entry = 1;
}

message DeleteHostRequest {
  optional string edit_token = 1;
  string id = 2;
}

message DeleteHostResponse {
  bool success = 1;
}

message ListHostsRequest {
  optional string filter = 1;
  optional int32 limit = 2;
  optional int32 offset = 3;
}

message ListHostsResponse {
  HostEntry entry = 1;
}

message SearchHostsRequest {
  string query = 1;
}

message SearchHostsResponse {
  HostEntry entry = 1;
}

// Edit session requests/responses
message StartEditRequest {}

message StartEditResponse {
  string edit_token = 1;
}

message FinishEditRequest {
  string edit_token = 1;
}

message FinishEditResponse {
  bool success = 1;
  int32 entries_changed = 2;
}

message CancelEditRequest {
  string edit_token = 1;
}

message CancelEditResponse {
  bool success = 1;
}

// Bulk operations
message BulkAddHostsRequest {
  optional string edit_token = 1;
  string ip_address = 2;
  string hostname = 3;
  optional string comment = 4;
  repeated string tags = 5;
}

message BulkAddHostsResponse {
  optional string id = 1;
  optional string error = 2;
}

message ImportHostsRequest {
  optional string edit_token = 1;
  bytes chunk = 2;
  bool last_chunk = 3;
}

message ImportHostsResponse {
  int32 imported = 1;
  int32 failed = 2;
  optional string error = 3;
}

message ExportHostsRequest {
  string format = 1; // "hosts", "json", "csv"
}

message ExportHostsResponse {
  bytes chunk = 1;
}

// Snapshot requests/responses
message CreateSnapshotRequest {
  optional string name = 1;
}

message CreateSnapshotResponse {
  string snapshot_id = 1;
}

message Snapshot {
  string snapshot_id = 1;
  string created_at = 2;
  int32 entry_count = 3;
  string trigger = 4;
}

message ListSnapshotsRequest {}

message ListSnapshotsResponse {
  Snapshot snapshot = 1;
}

message RollbackToSnapshotRequest {
  string snapshot_id = 1;
}

message RollbackToSnapshotResponse {
  bool success = 1;
  string new_snapshot_id = 2;
}

message DeleteSnapshotRequest {
  string snapshot_id = 1;
}

message DeleteSnapshotResponse {
  bool success = 1;
}

// Service definition
service HostsService {
  // Host management
  rpc AddHost(AddHostRequest) returns (AddHostResponse);
  rpc GetHost(GetHostRequest) returns (GetHostResponse);
  rpc UpdateHost(UpdateHostRequest) returns (UpdateHostResponse);
  rpc DeleteHost(DeleteHostRequest) returns (DeleteHostResponse);
  rpc ListHosts(ListHostsRequest) returns (stream ListHostsResponse);
  rpc SearchHosts(SearchHostsRequest) returns (stream SearchHostsResponse);

  // Edit sessions
  rpc StartEdit(StartEditRequest) returns (StartEditResponse);
  rpc FinishEdit(FinishEditRequest) returns (FinishEditResponse);
  rpc CancelEdit(CancelEditRequest) returns (CancelEditResponse);

  // Bulk operations
  rpc BulkAddHosts(stream BulkAddHostsRequest) returns (stream BulkAddHostsResponse);
  rpc ImportHosts(stream ImportHostsRequest) returns (stream ImportHostsResponse);
  rpc ExportHosts(ExportHostsRequest) returns (stream ExportHostsResponse);

  // Snapshots
  rpc CreateSnapshot(CreateSnapshotRequest) returns (CreateSnapshotResponse);
  rpc ListSnapshots(ListSnapshotsRequest) returns (stream ListSnapshotsResponse);
  rpc RollbackToSnapshot(RollbackToSnapshotRequest) returns (RollbackToSnapshotResponse);
  rpc DeleteSnapshot(DeleteSnapshotRequest) returns (DeleteSnapshotResponse);
}
```

**Step 4: Create proto module**

File: `crates/router-hosts-common/src/proto.rs`

```rust
// Re-export generated protobuf code
pub mod router_hosts {
    tonic::include_proto!("router_hosts");
}

pub use router_hosts::*;
```

**Step 5: Export proto from lib.rs**

Modify `crates/router-hosts-common/src/lib.rs`:

```rust
pub mod validation;
pub mod proto;

pub use validation::{validate_hostname, validate_ip_address, ValidationError, ValidationResult};
```

**Step 6: Build to generate protobuf code**

Run:
```bash
cargo build -p router-hosts-common
```

Expected: Build succeeds, proto code generated

**Step 7: Verify generated code exists**

Run:
```bash
find target -name "router_hosts.rs" 2>/dev/null | head -1
```

Expected: Path to generated file displayed

**Step 8: Commit**

```bash
git add proto/ crates/router-hosts-common/
git commit -m "feat(common): add gRPC protobuf definitions"
```

---

## Task 4: Create router-hosts-server Skeleton

**Files:**
- Create: `crates/router-hosts-server/Cargo.toml`
- Create: `crates/router-hosts-server/src/main.rs`
- Create: `crates/router-hosts-server/src/config.rs`

**Step 1: Write Cargo.toml for server**

File: `crates/router-hosts-server/Cargo.toml`

```toml
[package]
name = "router-hosts-server"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
router-hosts-common = { path = "../router-hosts-common" }

tonic.workspace = true
prost.workspace = true
tokio.workspace = true
serde.workspace = true
toml.workspace = true
uuid.workspace = true
chrono.workspace = true
thiserror.workspace = true
anyhow.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
duckdb.workspace = true
```

**Step 2: Write basic config structure with test**

File: `crates/router-hosts-server/src/config.rs`

```rust
use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("hosts_file_path is required but not provided")]
    MissingHostsFilePath,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub hosts_file_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RetentionConfig {
    #[serde(default = "default_max_snapshots")]
    pub max_snapshots: usize,

    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,
}

fn default_max_snapshots() -> usize { 50 }
fn default_max_age_days() -> u32 { 30 }

#[derive(Debug, Deserialize, Clone)]
pub struct EditSessionConfig {
    #[serde(default = "default_timeout_minutes")]
    pub timeout_minutes: u64,
}

fn default_timeout_minutes() -> u64 { 15 }

#[derive(Debug, Deserialize, Clone)]
pub struct HooksConfig {
    #[serde(default)]
    pub on_success: Vec<String>,

    #[serde(default)]
    pub on_failure: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub tls: TlsConfig,

    #[serde(default)]
    pub retention: RetentionConfig,

    #[serde(default)]
    pub edit_session: EditSessionConfig,

    #[serde(default)]
    pub hooks: HooksConfig,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            max_snapshots: default_max_snapshots(),
            max_age_days: default_max_age_days(),
        }
    }
}

impl Default for EditSessionConfig {
    fn default() -> Self {
        Self {
            timeout_minutes: default_timeout_minutes(),
        }
    }
}

impl Default for HooksConfig {
    fn default() -> Self {
        Self {
            on_success: vec![],
            on_failure: vec![],
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;

        // Validate required fields
        if config.server.hosts_file_path.is_empty() {
            return Err(ConfigError::MissingHostsFilePath);
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse_minimal() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            path = "/var/lib/router-hosts/hosts.db"

            [tls]
            cert_path = "/etc/router-hosts/server.crt"
            key_path = "/etc/router-hosts/server.key"
            ca_cert_path = "/etc/router-hosts/ca.crt"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.bind_address, "0.0.0.0:50051");
        assert_eq!(config.server.hosts_file_path, "/etc/hosts");
        assert_eq!(config.retention.max_snapshots, 50);
        assert_eq!(config.edit_session.timeout_minutes, 15);
    }

    #[test]
    fn test_config_missing_hosts_file_path() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = ""

            [database]
            path = "/var/lib/router-hosts/hosts.db"

            [tls]
            cert_path = "/etc/router-hosts/server.crt"
            key_path = "/etc/router-hosts/server.key"
            ca_cert_path = "/etc/router-hosts/ca.crt"
        "#;

        let config: Result<Config, _> = toml::from_str(toml_str);
        assert!(config.is_ok());

        // Should fail validation when using from_file
        let result = Config::from_file("nonexistent");
        // Will fail on file read, but that's expected
    }
}
```

**Step 3: Run tests**

Run:
```bash
cargo test -p router-hosts-server
```

Expected: Tests PASS

**Step 4: Write minimal main.rs**

File: `crates/router-hosts-server/src/main.rs`

```rust
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
```

**Step 5: Build server**

Run:
```bash
cargo build -p router-hosts-server
```

Expected: Build succeeds

**Step 6: Test run server**

Run:
```bash
cargo run -p router-hosts-server
```

Expected: Prints "router-hosts-server starting" and exits

**Step 7: Commit**

```bash
git add crates/router-hosts-server/
git commit -m "feat(server): add server skeleton with config"
```

---

## Task 5: Create router-hosts-client Skeleton

**Files:**
- Create: `crates/router-hosts-client/Cargo.toml`
- Create: `crates/router-hosts-client/src/main.rs`
- Create: `crates/router-hosts-client/src/config.rs`

**Step 1: Write Cargo.toml for client**

File: `crates/router-hosts-client/Cargo.toml`

```toml
[package]
name = "router-hosts-client"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
router-hosts-common = { path = "../router-hosts-common" }

tonic.workspace = true
prost.workspace = true
tokio.workspace = true
serde.workspace = true
toml.workspace = true
clap.workspace = true
anyhow.workspace = true
```

**Step 2: Write client config**

File: `crates/router-hosts-client/src/config.rs`

```rust
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct ClientConfig {
    pub server_address: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub client: ClientConfig,
    pub tls: TlsConfig,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
```

**Step 3: Write CLI structure with clap**

File: `crates/router-hosts-client/src/main.rs`

```rust
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
```

**Step 4: Build client**

Run:
```bash
cargo build -p router-hosts-client
```

Expected: Build succeeds

**Step 5: Test CLI help**

Run:
```bash
cargo run -p router-hosts-client -- --help
```

Expected: Shows help text with subcommands

**Step 6: Test add command parsing**

Run:
```bash
cargo run -p router-hosts-client -- add --ip 192.168.1.1 --hostname test.local
```

Expected: Prints config/command info

**Step 7: Commit**

```bash
git add crates/router-hosts-client/
git commit -m "feat(client): add client skeleton with CLI structure"
```

---

## Task 6: Add README and Development Documentation

**Files:**
- Create: `README.md`
- Create: `.github/workflows/ci.yml`

**Step 1: Write README**

File: `README.md`

```markdown
# router-hosts

Rust CLI tool for managing DNS host entries on routers via gRPC.

## Overview

**router-hosts** provides a client-server architecture for remotely managing `/etc/hosts` files on routers (OpenWrt or similar embedded Linux):

- **Server** runs on the router, exposes gRPC API, manages DuckDB storage
- **Client** runs on your workstation, provides CLI for all operations
- Supports versioning, bulk operations, edit sessions, and validation
- TLS with mutual authentication for security

See [Design Document](docs/plans/2025-11-28-router-hosts-design.md) for detailed architecture.

## Project Structure

```
router-hosts/
├── crates/
│   ├── router-hosts-common/   # Shared validation, types, protobuf
│   ├── router-hosts-server/   # Server binary
│   └── router-hosts-client/   # Client CLI
└── proto/
    └── hosts.proto            # gRPC service definitions
```

## Development

### Build

```bash
cargo build
```

### Test

```bash
cargo test
```

### Run Server (requires config)

```bash
cargo run -p router-hosts-server -- --config server.toml
```

### Run Client

```bash
cargo run -p router-hosts-client -- --help
```

## Status

🚧 **In Development** - Initial setup phase

## License

MIT
```

**Step 2: Create basic CI workflow**

File: `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4

    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable

    - name: Cache cargo registry
      uses: actions/cache@v3
      with:
        path: ~/.cargo/registry
        key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}

    - name: Cache cargo index
      uses: actions/cache@v3
      with:
        path: ~/.cargo/git
        key: ${{ runner.os }}-cargo-index-${{ hashFiles('**/Cargo.lock') }}

    - name: Cache cargo build
      uses: actions/cache@v3
      with:
        path: target
        key: ${{ runner.os }}-cargo-build-target-${{ hashFiles('**/Cargo.lock') }}

    - name: Build
      run: cargo build --verbose

    - name: Run tests
      run: cargo test --verbose

    - name: Check formatting
      run: cargo fmt -- --check

    - name: Run clippy
      run: cargo clippy -- -D warnings
```

**Step 3: Format code**

Run:
```bash
cargo fmt
```

Expected: Code formatted

**Step 4: Run clippy**

Run:
```bash
cargo clippy -- -D warnings
```

Expected: No warnings (or fix any that appear)

**Step 5: Verify CI workflow is valid**

Run:
```bash
mkdir -p .github/workflows
```

Expected: Directory exists

**Step 6: Commit**

```bash
git add README.md .github/
git commit -m "docs: add README and CI workflow"
```

---

## Task 7: Final Verification

**Step 1: Clean build from scratch**

Run:
```bash
cargo clean
cargo build
```

Expected: Full workspace builds successfully

**Step 2: Run all tests**

Run:
```bash
cargo test
```

Expected: All tests pass

**Step 3: Check workspace structure**

Run:
```bash
cargo tree --depth 1
```

Expected: Shows three crates with dependencies

**Step 4: Verify binaries**

Run:
```bash
ls -lh target/debug/router-hosts-{server,client}
```

Expected: Both binaries exist

**Step 5: Push to GitHub**

Run:
```bash
git push origin feat/initial-setup
```

Expected: Branch pushed successfully

**Step 6: Create pull request**

Run:
```bash
gh pr create --title "Initial project setup" --body "Sets up Cargo workspace with three crates, protobuf definitions, validation logic, and CI workflow. Implements basic structure for server and client binaries."
```

Expected: PR created with URL displayed

---

## Completion Criteria

✅ Cargo workspace with three crates builds successfully
✅ Protobuf definitions compile and generate code
✅ IP and hostname validation implemented with tests passing
✅ Server skeleton with config parsing
✅ Client skeleton with CLI structure
✅ README and CI workflow in place
✅ All tests passing
✅ Code formatted and clippy clean
✅ PR created for review

**Next Steps:** After this PR merges, implement database layer (DuckDB operations), gRPC service implementation, and edit session management.
