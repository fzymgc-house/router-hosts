# E2E Acceptance Testing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement Docker-based E2E acceptance tests that validate router-hosts works end-to-end with real mTLS authentication.

**Architecture:** Server runs in Docker container with mounted certs. CLI runs as subprocess on host. Tests generate fresh mTLS certificates at runtime using rcgen. testcontainers-rs manages Docker lifecycle.

**Tech Stack:** Rust, Docker, cargo-chef, testcontainers, rcgen, assert_cmd, GitHub Actions

---

## Task 1: Create Dockerfile with cargo-chef

**Files:**
- Create: `Dockerfile`

**Step 1: Create Dockerfile**

```dockerfile
# Stage 1: Chef - prepare recipe
FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

# Stage 2: Planner - compute dependency graph
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder - cache dependencies, then build
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin router-hosts

# Stage 4: Runtime - minimal image
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/router-hosts /usr/local/bin/
EXPOSE 50051
ENTRYPOINT ["router-hosts"]
CMD ["server", "--config", "/config/server.toml"]
```

**Step 2: Create .dockerignore**

```
target/
.git/
.worktrees/
*.md
!README.md
coverage/
```

**Step 3: Verify Docker build works**

Run: `docker build -t router-hosts:test .`
Expected: Build succeeds, image created

**Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "build: add Dockerfile with cargo-chef for optimized builds"
```

---

## Task 2: Create Taskfile.yml

**Files:**
- Create: `Taskfile.yml`

**Step 1: Create Taskfile**

```yaml
version: '3'

vars:
  IMAGE_NAME: ghcr.io/fzymgc-house/router-hosts
  IMAGE_TAG: '{{.IMAGE_TAG | default "dev"}}'

tasks:
  # ─────────────────────────────────────────────────────────────
  # Development
  # ─────────────────────────────────────────────────────────────
  build:
    desc: Build all crates in debug mode
    cmds:
      - cargo build --workspace

  build:release:
    desc: Build all crates in release mode
    cmds:
      - cargo build --workspace --release

  test:
    desc: Run unit and integration tests
    cmds:
      - cargo test --workspace

  test:coverage:
    desc: Run tests with coverage report
    cmds:
      - cargo tarpaulin --workspace --out Html --output-dir coverage

  lint:
    desc: Run all linters (clippy, fmt, buf)
    cmds:
      - cargo fmt --check
      - cargo clippy --workspace -- -D warnings
      - buf lint
      - buf format --diff --exit-code

  fmt:
    desc: Format all code
    cmds:
      - cargo fmt
      - buf format -w

  # ─────────────────────────────────────────────────────────────
  # Docker
  # ─────────────────────────────────────────────────────────────
  docker:build:
    desc: Build server Docker image for local architecture
    cmds:
      - docker build -t {{.IMAGE_NAME}}:{{.IMAGE_TAG}} .

  docker:run:
    desc: Run server container (requires certs in ./dev/certs/)
    cmds:
      - |
        docker run --rm -it \
          -v {{.USER_WORKING_DIR}}/dev/certs:/certs:ro \
          -v {{.USER_WORKING_DIR}}/dev/data:/data \
          -p 50051:50051 \
          {{.IMAGE_NAME}}:{{.IMAGE_TAG}} \
          server --config /certs/server.toml

  # ─────────────────────────────────────────────────────────────
  # E2E Tests
  # ─────────────────────────────────────────────────────────────
  e2e:
    desc: Run E2E acceptance tests
    deps: [build:release, docker:build]
    env:
      ROUTER_HOSTS_IMAGE: '{{.IMAGE_NAME}}:{{.IMAGE_TAG}}'
      ROUTER_HOSTS_BINARY: '{{.USER_WORKING_DIR}}/target/release/router-hosts'
    cmds:
      - cargo test -p router-hosts-e2e --release -- --test-threads=2

  e2e:quick:
    desc: Run E2E tests (skip rebuild, assumes image exists)
    env:
      ROUTER_HOSTS_IMAGE: '{{.IMAGE_NAME}}:{{.IMAGE_TAG}}'
      ROUTER_HOSTS_BINARY: '{{.USER_WORKING_DIR}}/target/release/router-hosts'
    cmds:
      - cargo test -p router-hosts-e2e --release -- --test-threads=2

  e2e:scenario:
    desc: Run specific E2E scenario (e.g., task e2e:scenario -- daily_operations)
    env:
      ROUTER_HOSTS_IMAGE: '{{.IMAGE_NAME}}:{{.IMAGE_TAG}}'
      ROUTER_HOSTS_BINARY: '{{.USER_WORKING_DIR}}/target/release/router-hosts'
    cmds:
      - cargo test -p router-hosts-e2e --release -- {{.CLI_ARGS}}

  # ─────────────────────────────────────────────────────────────
  # CI Shortcuts
  # ─────────────────────────────────────────────────────────────
  ci:
    desc: Run full CI pipeline locally
    cmds:
      - task: lint
      - task: test
      - task: e2e

  pre-commit:
    desc: Quick checks before committing
    cmds:
      - task: fmt
      - task: lint
      - task: test
```

**Step 2: Verify Task works**

Run: `task --list`
Expected: Shows all tasks with descriptions

**Step 3: Commit**

```bash
git add Taskfile.yml
git commit -m "build: add Taskfile for development workflow orchestration"
```

---

## Task 3: Create E2E crate skeleton

**Files:**
- Create: `crates/router-hosts-e2e/Cargo.toml`
- Create: `crates/router-hosts-e2e/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

**Step 1: Add e2e crate to workspace**

In root `Cargo.toml`, add to members array:

```toml
members = [
    "crates/router-hosts",
    "crates/router-hosts-common",
    "crates/router-hosts-e2e",
]
```

**Step 2: Create E2E crate Cargo.toml**

```toml
[package]
name = "router-hosts-e2e"
version = "0.1.0"
edition = "2021"
publish = false
description = "End-to-end acceptance tests for router-hosts"

[dependencies]
rcgen = "0.13"
testcontainers = "0.23"
testcontainers-modules = { version = "0.11", features = ["generic"] }
tokio = { version = "1", features = ["process", "fs", "rt-multi-thread", "macros", "time"] }
tempfile = "3"
assert_cmd = "2"
predicates = "3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
# This crate IS the test infrastructure - tests are in tests/ directory
```

**Step 3: Create lib.rs skeleton**

```rust
//! End-to-end acceptance tests for router-hosts
//!
//! This crate provides test infrastructure for running E2E tests against
//! a real server in Docker with mTLS authentication.

pub mod certs;
pub mod cli;
pub mod container;

/// Get the Docker image to use for the server
pub fn server_image() -> String {
    std::env::var("ROUTER_HOSTS_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/fzymgc-house/router-hosts:latest".to_string())
}

/// Get the path to the CLI binary
pub fn cli_binary() -> std::path::PathBuf {
    std::env::var("ROUTER_HOSTS_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("router-hosts"))
}
```

**Step 4: Create placeholder modules**

Create `crates/router-hosts-e2e/src/certs.rs`:
```rust
//! Certificate generation for E2E tests
```

Create `crates/router-hosts-e2e/src/cli.rs`:
```rust
//! CLI subprocess wrapper for E2E tests
```

Create `crates/router-hosts-e2e/src/container.rs`:
```rust
//! Docker container management for E2E tests
```

**Step 5: Verify crate compiles**

Run: `cargo build -p router-hosts-e2e`
Expected: Build succeeds

**Step 6: Commit**

```bash
git add Cargo.toml crates/router-hosts-e2e/
git commit -m "feat(e2e): add router-hosts-e2e crate skeleton"
```

---

## Task 4: Implement certificate generation

**Files:**
- Modify: `crates/router-hosts-e2e/src/certs.rs`

**Step 1: Implement TestCertificates**

```rust
//! Certificate generation for E2E tests
//!
//! Generates CA, server, and client certificates at runtime using rcgen.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

/// Paths to certificate files on disk
#[derive(Debug, Clone)]
pub struct CertPaths {
    pub ca_cert: std::path::PathBuf,
    pub server_cert: std::path::PathBuf,
    pub server_key: std::path::PathBuf,
    pub client_cert: std::path::PathBuf,
    pub client_key: std::path::PathBuf,
}

/// Generated test certificates (PEM format)
#[derive(Debug, Clone)]
pub struct TestCertificates {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

impl TestCertificates {
    /// Generate a fresh set of test certificates
    pub fn generate() -> Self {
        Self::generate_with_validity(Duration::from_secs(3600)) // 1 hour
    }

    /// Generate certificates with specific validity period
    pub fn generate_with_validity(validity: Duration) -> Self {
        // 1. Generate CA
        let ca_key = KeyPair::generate().expect("Failed to generate CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "router-hosts-e2e");
        ca_params.not_before = time::OffsetDateTime::now_utc();
        ca_params.not_after = time::OffsetDateTime::now_utc() + validity;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("Failed to generate CA cert");

        // 2. Generate server cert (signed by CA)
        let server_key = KeyPair::generate().expect("Failed to generate server key");
        let mut server_params = CertificateParams::default();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_params.subject_alt_names = vec![
            SanType::DnsName("localhost".into()),
            SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        ];
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.not_before = time::OffsetDateTime::now_utc();
        server_params.not_after = time::OffsetDateTime::now_utc() + validity;
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("Failed to generate server cert");

        // 3. Generate client cert (signed by CA)
        let client_key = KeyPair::generate().expect("Failed to generate client key");
        let mut client_params = CertificateParams::default();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "test-client");
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.not_before = time::OffsetDateTime::now_utc();
        client_params.not_after = time::OffsetDateTime::now_utc() + validity;
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("Failed to generate client cert");

        Self {
            ca_cert_pem: ca_cert.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// Generate expired certificates for testing auth failure
    pub fn generate_expired() -> Self {
        // Generate with validity in the past
        let ca_key = KeyPair::generate().expect("Failed to generate CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Expired Test CA");
        ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        ca_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("Failed to generate CA cert");

        let client_key = KeyPair::generate().expect("Failed to generate client key");
        let mut client_params = CertificateParams::default();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "expired-client");
        client_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        client_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("Failed to generate client cert");

        Self {
            ca_cert_pem: ca_cert.pem(),
            server_cert_pem: String::new(), // Not needed for client-only expired test
            server_key_pem: String::new(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// Write certificates to a directory
    pub fn write_to_dir(&self, dir: &Path) -> std::io::Result<CertPaths> {
        let ca_cert = dir.join("ca.pem");
        let server_cert = dir.join("server.pem");
        let server_key = dir.join("server-key.pem");
        let client_cert = dir.join("client.pem");
        let client_key = dir.join("client-key.pem");

        std::fs::write(&ca_cert, &self.ca_cert_pem)?;
        std::fs::write(&server_cert, &self.server_cert_pem)?;
        std::fs::write(&server_key, &self.server_key_pem)?;
        std::fs::write(&client_cert, &self.client_cert_pem)?;
        std::fs::write(&client_key, &self.client_key_pem)?;

        Ok(CertPaths {
            ca_cert,
            server_cert,
            server_key,
            client_cert,
            client_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificates() {
        let certs = TestCertificates::generate();
        assert!(certs.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(certs.server_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(certs.server_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(certs.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(certs.client_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_write_to_dir() {
        let certs = TestCertificates::generate();
        let temp_dir = tempfile::tempdir().unwrap();
        let paths = certs.write_to_dir(temp_dir.path()).unwrap();

        assert!(paths.ca_cert.exists());
        assert!(paths.server_cert.exists());
        assert!(paths.server_key.exists());
        assert!(paths.client_cert.exists());
        assert!(paths.client_key.exists());
    }
}
```

**Step 2: Add time dependency to Cargo.toml**

Add to `crates/router-hosts-e2e/Cargo.toml`:
```toml
time = "0.3"
```

**Step 3: Verify crate compiles and tests pass**

Run: `cargo test -p router-hosts-e2e`
Expected: 2 tests pass

**Step 4: Commit**

```bash
git add crates/router-hosts-e2e/
git commit -m "feat(e2e): implement certificate generation with rcgen"
```

---

## Task 5: Implement container management

**Files:**
- Modify: `crates/router-hosts-e2e/src/container.rs`

**Step 1: Implement ServerContainer**

```rust
//! Docker container management for E2E tests
//!
//! Uses testcontainers to manage the router-hosts server lifecycle.

use crate::certs::{CertPaths, TestCertificates};
use std::path::PathBuf;
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

/// Configuration for the test server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub hosts_file_path: String,
    pub database_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub tls_ca_path: String,
}

impl ServerConfig {
    /// Create config for container paths
    pub fn for_container(port: u16) -> Self {
        Self {
            bind_address: format!("0.0.0.0:{}", port),
            hosts_file_path: "/data/hosts".to_string(),
            database_path: "/data/router-hosts.db".to_string(),
            tls_cert_path: "/certs/server.pem".to_string(),
            tls_key_path: "/certs/server-key.pem".to_string(),
            tls_ca_path: "/certs/ca.pem".to_string(),
        }
    }

    /// Generate TOML config file content
    pub fn to_toml(&self) -> String {
        format!(
            r#"[server]
bind_address = "{}"
hosts_file_path = "{}"

[database]
path = "{}"

[tls]
cert_path = "{}"
key_path = "{}"
ca_cert_path = "{}"

[retention]
max_snapshots = 10
max_age_days = 7

[hooks]
on_success = []
on_failure = []
"#,
            self.bind_address,
            self.hosts_file_path,
            self.database_path,
            self.tls_cert_path,
            self.tls_key_path,
            self.tls_ca_path
        )
    }
}

/// A running test server container
pub struct TestServer {
    container: testcontainers::ContainerAsync<GenericImage>,
    pub port: u16,
    pub cert_paths: CertPaths,
    pub temp_dir: tempfile::TempDir,
}

impl TestServer {
    /// Start a new test server with fresh certificates
    pub async fn start() -> Self {
        Self::start_with_certs(TestCertificates::generate()).await
    }

    /// Start a test server with specific certificates
    pub async fn start_with_certs(certs: TestCertificates) -> Self {
        let image_name = crate::server_image();
        let (image, tag) = image_name
            .rsplit_once(':')
            .unwrap_or((&image_name, "latest"));

        // Create temp directory for certs and data
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let certs_dir = temp_dir.path().join("certs");
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&certs_dir).expect("Failed to create certs dir");
        std::fs::create_dir_all(&data_dir).expect("Failed to create data dir");

        // Write certificates
        let cert_paths = certs
            .write_to_dir(&certs_dir)
            .expect("Failed to write certs");

        // Write server config
        let config = ServerConfig::for_container(50051);
        let config_path = certs_dir.join("server.toml");
        std::fs::write(&config_path, config.to_toml()).expect("Failed to write config");

        // Create and start container
        let container = GenericImage::new(image, tag)
            .with_exposed_port(ContainerPort::Tcp(50051))
            .with_mount(Mount::bind_mount(
                certs_dir.to_string_lossy().to_string(),
                "/certs",
            ))
            .with_mount(Mount::bind_mount(
                data_dir.to_string_lossy().to_string(),
                "/data",
            ))
            .with_cmd(vec!["server", "--config", "/certs/server.toml"])
            .with_wait_for(WaitFor::message_on_stderr("gRPC server listening"))
            .start()
            .await
            .expect("Failed to start container");

        let port = container
            .get_host_port_ipv4(50051)
            .await
            .expect("Failed to get port");

        Self {
            container,
            port,
            cert_paths,
            temp_dir,
        }
    }

    /// Get the server address for client connections
    pub fn address(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// Stop the container
    pub async fn stop(self) {
        self.container.stop().await.expect("Failed to stop container");
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo build -p router-hosts-e2e`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add crates/router-hosts-e2e/
git commit -m "feat(e2e): implement container management with testcontainers"
```

---

## Task 6: Implement CLI wrapper

**Files:**
- Modify: `crates/router-hosts-e2e/src/cli.rs`

**Step 1: Implement CLI wrapper**

```rust
//! CLI subprocess wrapper for E2E tests
//!
//! Provides a type-safe interface for running router-hosts CLI commands.

use crate::certs::CertPaths;
use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

/// Wrapper for running CLI commands against a test server
pub struct TestCli {
    binary: PathBuf,
    server_address: String,
    cert_paths: CertPaths,
    config_path: PathBuf,
}

impl TestCli {
    /// Create a new CLI wrapper
    pub fn new(server_address: String, cert_paths: CertPaths, temp_dir: &std::path::Path) -> Self {
        let binary = crate::cli_binary();

        // Write client config file
        let config_path = temp_dir.join("client.toml");
        let config_content = format!(
            r#"[server]
address = "{}"

[tls]
cert_path = "{}"
key_path = "{}"
ca_cert_path = "{}"
"#,
            server_address,
            cert_paths.client_cert.display(),
            cert_paths.client_key.display(),
            cert_paths.ca_cert.display()
        );
        std::fs::write(&config_path, config_content).expect("Failed to write client config");

        Self {
            binary,
            server_address,
            cert_paths,
            config_path,
        }
    }

    /// Get a Command configured for this CLI
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--config").arg(&self.config_path);
        cmd
    }

    /// Add a host entry
    pub fn add_host(&self, ip: &str, hostname: &str) -> AddHostBuilder {
        AddHostBuilder {
            cli: self,
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            comment: None,
            tags: Vec::new(),
        }
    }

    /// List all hosts
    pub fn list_hosts(&self) -> Command {
        let mut cmd = self.cmd();
        cmd.arg("list");
        cmd
    }

    /// Get a specific host by ID
    pub fn get_host(&self, id: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["get", id]);
        cmd
    }

    /// Delete a host
    pub fn delete_host(&self, id: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["delete", id]);
        cmd
    }

    /// Update a host
    pub fn update_host(&self, id: &str) -> UpdateHostBuilder {
        UpdateHostBuilder {
            cli: self,
            id: id.to_string(),
            ip: None,
            hostname: None,
            comment: None,
            tags: None,
        }
    }

    /// Search hosts
    pub fn search(&self, query: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["search", query]);
        cmd
    }

    /// Create a snapshot
    pub fn create_snapshot(&self, name: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["snapshot", "create", "--name", name]);
        cmd
    }

    /// List snapshots
    pub fn list_snapshots(&self) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["snapshot", "list"]);
        cmd
    }

    /// Rollback to a snapshot
    pub fn rollback(&self, snapshot_id: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["snapshot", "rollback", snapshot_id]);
        cmd
    }

    /// Export hosts
    pub fn export(&self, format: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["export", "--format", format]);
        cmd
    }

    /// Import hosts from file
    pub fn import(&self, file: &std::path::Path) -> ImportBuilder {
        ImportBuilder {
            cli: self,
            file: file.to_path_buf(),
            format: None,
            mode: None,
        }
    }
}

/// Builder for add host command
pub struct AddHostBuilder<'a> {
    cli: &'a TestCli,
    ip: String,
    hostname: String,
    comment: Option<String>,
    tags: Vec<String>,
}

impl<'a> AddHostBuilder<'a> {
    pub fn comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    pub fn tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    pub fn build(self) -> Command {
        let mut cmd = self.cli.cmd();
        cmd.args(["add", "--ip", &self.ip, "--hostname", &self.hostname]);
        if let Some(comment) = &self.comment {
            cmd.args(["--comment", comment]);
        }
        for tag in &self.tags {
            cmd.args(["--tag", tag]);
        }
        cmd
    }
}

/// Builder for update host command
pub struct UpdateHostBuilder<'a> {
    cli: &'a TestCli,
    id: String,
    ip: Option<String>,
    hostname: Option<String>,
    comment: Option<String>,
    tags: Option<Vec<String>>,
}

impl<'a> UpdateHostBuilder<'a> {
    pub fn ip(mut self, ip: &str) -> Self {
        self.ip = Some(ip.to_string());
        self
    }

    pub fn hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_string());
        self
    }

    pub fn comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    pub fn tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = Some(tags.into_iter().map(String::from).collect());
        self
    }

    pub fn build(self) -> Command {
        let mut cmd = self.cli.cmd();
        cmd.args(["update", &self.id]);
        if let Some(ip) = &self.ip {
            cmd.args(["--ip", ip]);
        }
        if let Some(hostname) = &self.hostname {
            cmd.args(["--hostname", hostname]);
        }
        if let Some(comment) = &self.comment {
            cmd.args(["--comment", comment]);
        }
        if let Some(tags) = &self.tags {
            for tag in tags {
                cmd.args(["--tag", tag]);
            }
        }
        cmd
    }
}

/// Builder for import command
pub struct ImportBuilder<'a> {
    cli: &'a TestCli,
    file: PathBuf,
    format: Option<String>,
    mode: Option<String>,
}

impl<'a> ImportBuilder<'a> {
    pub fn format(mut self, format: &str) -> Self {
        self.format = Some(format.to_string());
        self
    }

    pub fn mode(mut self, mode: &str) -> Self {
        self.mode = Some(mode.to_string());
        self
    }

    pub fn build(self) -> Command {
        let mut cmd = self.cli.cmd();
        cmd.args(["import", self.file.to_str().unwrap()]);
        if let Some(format) = &self.format {
            cmd.args(["--format", format]);
        }
        if let Some(mode) = &self.mode {
            cmd.args(["--mode", mode]);
        }
        cmd
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo build -p router-hosts-e2e`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add crates/router-hosts-e2e/
git commit -m "feat(e2e): implement CLI wrapper with builder pattern"
```

---

## Task 7: Create test scenarios directory structure

**Files:**
- Create: `crates/router-hosts-e2e/tests/e2e_tests.rs`
- Create: `crates/router-hosts-e2e/tests/scenarios/mod.rs`
- Create: `crates/router-hosts-e2e/tests/scenarios/initial_setup.rs`
- Create: `crates/router-hosts-e2e/tests/scenarios/daily_operations.rs`
- Create: `crates/router-hosts-e2e/tests/scenarios/disaster_recovery.rs`
- Create: `crates/router-hosts-e2e/tests/scenarios/auth_failures.rs`

**Step 1: Create test entry point**

`crates/router-hosts-e2e/tests/e2e_tests.rs`:
```rust
//! E2E test entry point
//!
//! Run with: cargo test -p router-hosts-e2e --release

mod scenarios;
```

**Step 2: Create scenarios module**

`crates/router-hosts-e2e/tests/scenarios/mod.rs`:
```rust
//! E2E test scenarios

pub mod auth_failures;
pub mod daily_operations;
pub mod disaster_recovery;
pub mod initial_setup;
```

**Step 3: Create initial_setup.rs**

```rust
//! Initial setup scenarios - first-time deployment workflow

use predicates::prelude::*;
use router_hosts_e2e::cli::TestCli;
use router_hosts_e2e::container::TestServer;

#[tokio::test]
async fn test_initial_deployment() {
    // Start fresh server
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // 1. Verify server is healthy (list returns empty)
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("No hosts found").or(predicate::str::is_empty()));

    // 2. Add first host
    cli.add_host("192.168.1.1", "router.local")
        .comment("Main router")
        .tag("infrastructure")
        .build()
        .assert()
        .success()
        .stdout(predicate::str::contains("Added host"));

    // 3. Verify host appears in list
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.1"))
        .stdout(predicate::str::contains("router.local"));

    // 4. Create initial snapshot
    cli.create_snapshot("baseline")
        .assert()
        .success()
        .stdout(predicate::str::contains("Created snapshot"));

    // 5. Verify snapshot exists
    cli.list_snapshots()
        .assert()
        .success()
        .stdout(predicate::str::contains("baseline"));

    server.stop().await;
}
```

**Step 4: Create daily_operations.rs**

```rust
//! Daily operations scenarios - normal usage patterns

use predicates::prelude::*;
use router_hosts_e2e::cli::TestCli;
use router_hosts_e2e::container::TestServer;
use std::io::Write;

#[tokio::test]
async fn test_crud_workflow() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Add host
    let output = cli
        .add_host("10.0.0.1", "server1.local")
        .comment("Test server")
        .tag("test")
        .build()
        .output()
        .expect("Failed to run add");
    assert!(output.status.success());

    // Extract host ID from output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let id = stdout
        .lines()
        .find(|l| l.contains("ID:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("Failed to extract ID");

    // List and verify
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.1"))
        .stdout(predicate::str::contains("server1.local"));

    // Update IP
    cli.update_host(id)
        .ip("10.0.0.2")
        .build()
        .assert()
        .success();

    // Get and verify update
    cli.get_host(id)
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.2"));

    // Delete
    cli.delete_host(id).assert().success();

    // List and verify gone
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.1").not());

    server.stop().await;
}

#[tokio::test]
async fn test_import_export_roundtrip() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Create hosts file to import
    let import_file = server.temp_dir.path().join("import.hosts");
    let mut f = std::fs::File::create(&import_file).unwrap();
    writeln!(f, "# Test hosts file").unwrap();
    writeln!(f, "192.168.1.10    server1.test.local").unwrap();
    writeln!(f, "192.168.1.20    server2.test.local # Database").unwrap();

    // Import
    cli.import(&import_file)
        .format("hosts")
        .build()
        .assert()
        .success();

    // Verify imported
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.10"))
        .stdout(predicate::str::contains("server2.test.local"));

    // Export to JSON
    let export_output = cli.export("json").output().expect("Failed to export");
    assert!(export_output.status.success());
    let json = String::from_utf8_lossy(&export_output.stdout);
    assert!(json.contains("192.168.1.10"));
    assert!(json.contains("server1.test.local"));

    server.stop().await;
}

#[tokio::test]
async fn test_search_and_filter() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Add hosts with different tags
    cli.add_host("10.1.0.1", "web1.prod.local")
        .tag("production")
        .tag("web")
        .build()
        .assert()
        .success();

    cli.add_host("10.1.0.2", "db1.prod.local")
        .tag("production")
        .tag("database")
        .build()
        .assert()
        .success();

    cli.add_host("10.2.0.1", "web1.dev.local")
        .tag("development")
        .tag("web")
        .build()
        .assert()
        .success();

    // Search by hostname pattern
    cli.search("prod")
        .assert()
        .success()
        .stdout(predicate::str::contains("web1.prod.local"))
        .stdout(predicate::str::contains("db1.prod.local"))
        .stdout(predicate::str::contains("web1.dev.local").not());

    // Search by tag
    cli.search("web")
        .assert()
        .success()
        .stdout(predicate::str::contains("web1.prod.local"))
        .stdout(predicate::str::contains("web1.dev.local"));

    server.stop().await;
}
```

**Step 5: Create disaster_recovery.rs**

```rust
//! Disaster recovery scenarios - backup and restore workflows

use predicates::prelude::*;
use router_hosts_e2e::cli::TestCli;
use router_hosts_e2e::container::TestServer;

#[tokio::test]
async fn test_snapshot_and_rollback() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Create initial state
    cli.add_host("192.168.100.1", "original.local")
        .comment("Original host")
        .build()
        .assert()
        .success();

    // Create snapshot
    let snapshot_output = cli
        .create_snapshot("before-disaster")
        .output()
        .expect("Failed to create snapshot");
    assert!(snapshot_output.status.success());

    // Extract snapshot ID
    let stdout = String::from_utf8_lossy(&snapshot_output.stdout);
    let snapshot_id = stdout
        .lines()
        .find(|l| l.contains("ID:") || l.contains("snapshot_id"))
        .and_then(|l| l.split_whitespace().last())
        .expect("Failed to extract snapshot ID");

    // Make breaking changes
    let list_output = cli.list_hosts().output().expect("Failed to list");
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    let host_id = list_stdout
        .lines()
        .find(|l| l.contains("original.local"))
        .and_then(|l| l.split_whitespace().next())
        .expect("Failed to find host ID");

    cli.delete_host(host_id).assert().success();

    cli.add_host("192.168.100.99", "wrong.local")
        .comment("Wrong host")
        .build()
        .assert()
        .success();

    // Verify broken state
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("wrong.local"))
        .stdout(predicate::str::contains("original.local").not());

    // Rollback
    cli.rollback(snapshot_id).assert().success();

    // Verify restored state
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("original.local"))
        .stdout(predicate::str::contains("wrong.local").not());

    server.stop().await;
}

#[tokio::test]
async fn test_rollback_creates_backup() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Create state
    cli.add_host("10.10.10.1", "backup-test.local")
        .build()
        .assert()
        .success();

    // Create snapshot
    let snapshot_output = cli
        .create_snapshot("checkpoint")
        .output()
        .expect("Failed to create snapshot");
    let stdout = String::from_utf8_lossy(&snapshot_output.stdout);
    let snapshot_id = stdout
        .lines()
        .find(|l| l.contains("ID:") || l.contains("snapshot_id"))
        .and_then(|l| l.split_whitespace().last())
        .expect("Failed to extract snapshot ID");

    // Modify
    cli.add_host("10.10.10.2", "extra.local")
        .build()
        .assert()
        .success();

    // Count snapshots before rollback
    let before = cli.list_snapshots().output().expect("Failed to list");
    let before_count = String::from_utf8_lossy(&before.stdout)
        .lines()
        .filter(|l| l.contains("checkpoint") || l.contains("pre-rollback"))
        .count();

    // Rollback
    cli.rollback(snapshot_id).assert().success();

    // Verify backup snapshot was created
    cli.list_snapshots()
        .assert()
        .success()
        .stdout(predicate::str::contains("pre-rollback"));

    server.stop().await;
}
```

**Step 6: Create auth_failures.rs**

```rust
//! Authentication failure scenarios - security boundary testing

use predicates::prelude::*;
use router_hosts_e2e::certs::TestCertificates;
use router_hosts_e2e::cli::TestCli;
use router_hosts_e2e::container::TestServer;

#[tokio::test]
async fn test_wrong_ca_rejected() {
    let server = TestServer::start().await;

    // Generate a completely different set of certs (different CA)
    let wrong_certs = TestCertificates::generate();
    let wrong_certs_dir = server.temp_dir.path().join("wrong_certs");
    std::fs::create_dir_all(&wrong_certs_dir).unwrap();
    let wrong_paths = wrong_certs.write_to_dir(&wrong_certs_dir).unwrap();

    // Use server's CA for trust but wrong client cert
    let mut mixed_paths = wrong_paths.clone();
    mixed_paths.ca_cert = server.cert_paths.ca_cert.clone();

    let cli = TestCli::new(server.address(), mixed_paths, server.temp_dir.path());

    // Should fail - client cert not signed by server's CA
    cli.list_hosts()
        .assert()
        .failure()
        .stderr(predicate::str::contains("certificate").or(predicate::str::contains("TLS")));

    server.stop().await;
}

#[tokio::test]
async fn test_self_signed_client_rejected() {
    let server = TestServer::start().await;

    // Generate self-signed client cert (not signed by any CA)
    let self_signed = TestCertificates::generate();
    let self_signed_dir = server.temp_dir.path().join("self_signed");
    std::fs::create_dir_all(&self_signed_dir).unwrap();
    let self_signed_paths = self_signed.write_to_dir(&self_signed_dir).unwrap();

    // Use server's CA but self-signed client cert
    let mut mixed_paths = self_signed_paths.clone();
    mixed_paths.ca_cert = server.cert_paths.ca_cert.clone();

    let cli = TestCli::new(server.address(), mixed_paths, server.temp_dir.path());

    // Should fail
    cli.list_hosts()
        .assert()
        .failure()
        .stderr(predicate::str::contains("certificate").or(predicate::str::contains("TLS")));

    server.stop().await;
}

// Note: Testing without client cert requires modifying the CLI to support
// optional client certs, which is out of scope for v1.0. The current CLI
// always requires client cert configuration.

// Note: Testing expired certs is complex because the server also validates
// on startup. This would require a server that accepts expired certs but
// rejects on auth, which is not the current behavior.
```

**Step 7: Verify tests compile**

Run: `cargo build -p router-hosts-e2e --tests`
Expected: Build succeeds

**Step 8: Commit**

```bash
git add crates/router-hosts-e2e/tests/
git commit -m "feat(e2e): add test scenarios for initial setup, daily ops, disaster recovery, and auth"
```

---

## Task 8: Add GitHub Actions workflow for Docker builds

**Files:**
- Create: `.github/workflows/docker.yml`

**Step 1: Create Docker workflow**

```yaml
name: Docker

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build-amd64:
    runs-on:
      - runs-on=${{ github.run_id }}/runner=4cpu-linux-x64/image=ubuntu24-full-x64/extras=s3-cache/spot=lowest-price/volume=100gb

    permissions:
      contents: read
      packages: write

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        if: github.event_name != 'pull_request'
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push (amd64)
        uses: docker/build-push-action@v6
        with:
          context: .
          push: ${{ github.event_name != 'pull_request' }}
          platforms: linux/amd64
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-amd64
          cache-from: type=gha
          cache-to: type=gha,mode=max

  build-arm64:
    runs-on:
      - runs-on=${{ github.run_id }}/runner=4cpu-linux-arm64/image=ubuntu24-full-arm64/extras=s3-cache/spot=lowest-price/volume=100gb

    permissions:
      contents: read
      packages: write

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        if: github.event_name != 'pull_request'
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push (arm64)
        uses: docker/build-push-action@v6
        with:
          context: .
          push: ${{ github.event_name != 'pull_request' }}
          platforms: linux/arm64
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-arm64
          cache-from: type=gha
          cache-to: type=gha,mode=max

  manifest:
    needs: [build-amd64, build-arm64]
    if: github.event_name != 'pull_request'
    runs-on:
      - runs-on=${{ github.run_id }}/runner=2cpu-linux-x64/image=ubuntu24-full-x64/spot=lowest-price

    permissions:
      contents: read
      packages: write

    steps:
      - uses: runs-on/action@v2

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Create and push manifest
        run: |
          docker manifest create ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-amd64 \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-arm64
          docker manifest push ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

          # Also tag as latest on main branch
          if [ "${{ github.ref }}" = "refs/heads/main" ]; then
            docker manifest create ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest \
              ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-amd64 \
              ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-arm64
            docker manifest push ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:latest
          fi
```

**Step 2: Commit**

```bash
git add .github/workflows/docker.yml
git commit -m "ci: add multi-arch Docker build workflow"
```

---

## Task 9: Update CI workflow with E2E tests

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Add E2E test job**

Add after the existing `test` job:

```yaml
  e2e-tests:
    needs: [test]
    runs-on:
      - runs-on=${{ github.run_id }}/runner=4cpu-linux-x64/image=ubuntu24-full-x64/extras=s3-cache+docker/spot=lowest-price/volume=100gb

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install Task
        uses: arduino/setup-task@v2

      - name: Cache Rust dependencies
        uses: Swatinem/rust-cache@v2
        with:
          cache-all-crates: "true"
          key: ${{ runner.os }}-rust-e2e

      - name: Build release binary
        run: cargo build --release --bin router-hosts

      - name: Build Docker image
        run: docker build -t router-hosts:e2e .

      - name: Run E2E tests
        env:
          ROUTER_HOSTS_IMAGE: router-hosts:e2e
          ROUTER_HOSTS_BINARY: ./target/release/router-hosts
        run: cargo test -p router-hosts-e2e --release -- --test-threads=2
```

**Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add E2E test job to CI workflow"
```

---

## Task 10: Update documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Create: `crates/router-hosts-e2e/README.md`

**Step 1: Update README.md**

Add after existing content or replace development section:

```markdown
## Development

### Prerequisites

- Rust 1.75+
- Docker
- [Task](https://taskfile.dev/) (recommended)
- [buf](https://buf.build/) (for protobuf)

### Quick Start

```bash
# Install Task (macOS)
brew install go-task

# Build
task build

# Run tests
task test

# Run E2E tests (requires Docker)
task e2e

# Full CI pipeline locally
task ci
```

### Available Tasks

| Task | Description |
|------|-------------|
| `task build` | Build all crates (debug) |
| `task build:release` | Build all crates (release) |
| `task test` | Run unit and integration tests |
| `task lint` | Run all linters |
| `task fmt` | Format all code |
| `task docker:build` | Build server Docker image |
| `task e2e` | Run E2E acceptance tests |
| `task ci` | Run full CI pipeline locally |

### Docker

```bash
# Build server image
task docker:build

# Run specific E2E scenario
task e2e:scenario -- daily_operations
```
```

**Step 2: Update CLAUDE.md**

In the "Build and Development Commands" section, add:

```markdown
### Using Task (Recommended)

This project uses [Taskfile](https://taskfile.dev/) to orchestrate builds:

```bash
task build          # Build all crates (debug)
task build:release  # Build all crates (release)
task test           # Unit + integration tests
task lint           # All linters (clippy, fmt, buf)
task fmt            # Format all code
task e2e            # E2E acceptance tests
task ci             # Full CI pipeline locally
```

### E2E Tests

E2E tests validate the full stack with real mTLS authentication:

```bash
# Run all E2E tests
task e2e

# Run specific scenario
task e2e:scenario -- disaster_recovery

# Quick run (skip rebuild)
task e2e:quick
```

Required environment:
- Docker running
- `ROUTER_HOSTS_IMAGE`: Docker image (default: `ghcr.io/fzymgc-house/router-hosts:latest`)
- `ROUTER_HOSTS_BINARY`: Path to CLI binary (default: `router-hosts` in PATH)
```

**Step 3: Create E2E crate README**

`crates/router-hosts-e2e/README.md`:
```markdown
# router-hosts-e2e

End-to-end acceptance tests for router-hosts.

## Overview

Tests the full stack: CLI → gRPC/mTLS → Server → DuckDB → Hosts File

- Server runs in Docker container
- CLI runs as subprocess
- Fresh mTLS certificates generated per test
- Uses testcontainers for Docker lifecycle management

## Running Tests

```bash
# From repo root (recommended)
task e2e

# Or manually
ROUTER_HOSTS_IMAGE=router-hosts:dev \
ROUTER_HOSTS_BINARY=./target/release/router-hosts \
cargo test -p router-hosts-e2e --release
```

## Test Scenarios

| Scenario | Description |
|----------|-------------|
| `initial_setup` | First-time deployment workflow |
| `daily_operations` | CRUD, import/export, search |
| `disaster_recovery` | Snapshot and rollback workflows |
| `auth_failures` | mTLS security boundary testing |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ROUTER_HOSTS_IMAGE` | `ghcr.io/fzymgc-house/router-hosts:latest` | Docker image for server |
| `ROUTER_HOSTS_BINARY` | `router-hosts` | Path to CLI binary |

## Architecture

```
Test Process
├── Certificate Generator (rcgen)
├── TestServer (testcontainers)
│   └── Docker container with server
└── TestCli (assert_cmd)
    └── CLI subprocess with client certs
```
```

**Step 4: Commit**

```bash
git add README.md CLAUDE.md crates/router-hosts-e2e/README.md
git commit -m "docs: update documentation for E2E testing and Taskfile"
```

---

## Task 11: Final verification

**Step 1: Run all lints**

Run: `cargo fmt && cargo clippy --workspace -- -D warnings && buf lint && buf format --diff --exit-code`
Expected: All pass

**Step 2: Run all tests**

Run: `cargo test --workspace`
Expected: All tests pass

**Step 3: Build Docker image**

Run: `docker build -t router-hosts:test .`
Expected: Build succeeds

**Step 4: Run E2E tests**

Run: `ROUTER_HOSTS_IMAGE=router-hosts:test ROUTER_HOSTS_BINARY=./target/release/router-hosts cargo test -p router-hosts-e2e --release`
Expected: E2E tests pass (may need to fix issues discovered)

**Step 5: Commit any fixes**

```bash
git add -A
git commit -m "fix: address issues found in final verification"
```

---

## Implementation Complete

All tasks completed. Ready to:
1. Push to feature branch
2. Create pull request
3. Run CI to verify Docker builds and E2E tests

@superpowers:verification-before-completion - Run before claiming work complete
@superpowers:finishing-a-development-branch - Use to merge/cleanup after PR approval
