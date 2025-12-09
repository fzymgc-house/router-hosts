# E2E Acceptance Testing Design

**Date:** 2025-12-08
**Status:** Implemented (PR #72)
**Related:** Pre-v1.0 hardening, security audit preparation

## Implementation Status

**Merged:** 2025-12-08 via PR #72

**What Works:**
- ✅ testcontainers-based server orchestration
- ✅ Runtime certificate generation with rcgen
- ✅ Initial setup scenario (test_initial_deployment)
- ✅ Auth failure scenarios (test_wrong_ca_rejected, test_self_signed_client_rejected)
- ✅ Daily operations: search/filter (test_search_and_filter)
- ✅ Docker CI/E2E integration with Dockerfile.ci

**Ignored Tests (blocked by CLI bugs):**
- ⏸️ test_crud_workflow - Issue #70 (missing 'id' field in JSON output)
- ⏸️ test_import_export_roundtrip - Issue #69 (import command clap type mismatch)
- ⏸️ test_snapshot_and_rollback - Issue #71 (snapshot create returns empty output)
- ⏸️ test_rollback_creates_backup - Issue #71 (snapshot create returns empty output)

**Next Steps:** Fix issues #69, #70, #71 to enable all E2E scenarios.

## Overview

End-to-end acceptance tests to validate router-hosts works in realistic deployment scenarios before releasing to production firewalls/routers.

### Goals

- Verify full stack: CLI → gRPC/mTLS → Server → DuckDB → Hosts File
- Test real mTLS authentication with runtime-generated certificates
- Cover complete user journeys: setup, daily ops, disaster recovery
- Validate security boundaries (auth failures, invalid certs)

### Non-Goals

- Performance benchmarking (separate effort)
- Chaos/fault injection testing (future work)
- Multi-node deployment testing (single server for v1.0)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Test Process (cargo test -p router-hosts-e2e)              │
│  ┌─────────────────┐  ┌──────────────────────────────────┐  │
│  │  Test Scenarios │  │  Certificate Generator (rcgen)   │  │
│  │  (Rust code)    │  │  - CA cert/key                   │  │
│  └────────┬────────┘  │  - Server cert/key               │  │
│           │           │  - Client cert/key               │  │
│           ▼           └──────────────────────────────────┘  │
│  ┌─────────────────┐                                        │
│  │ CLI Binary      │◄─── Executes router-hosts commands    │
│  │ (subprocess)    │     with generated client certs        │
│  └────────┬────────┘                                        │
└───────────┼─────────────────────────────────────────────────┘
            │ gRPC over mTLS
            ▼
┌─────────────────────────────────────────────────────────────┐
│  Docker Container (testcontainers)                          │
│  ┌─────────────────┐  ┌──────────────────────────────────┐  │
│  │ router-hosts    │  │  Mounted volumes:                │  │
│  │ server          │  │  - /certs (CA, server cert/key)  │  │
│  │                 │  │  - /data (DuckDB)                │  │
│  │                 │  │  - /etc/hosts.managed            │  │
│  └─────────────────┘  └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Key Points:**
- Tests generate fresh mTLS certificates at runtime using `rcgen`
- Server runs in Docker with certs mounted as volumes
- CLI runs as subprocess on host, configured with client certs
- Each test gets isolated container + database + hosts file

## Docker Build Infrastructure

### Multi-Architecture Builds

Native builds on amd64 and arm64 runners (no emulation), then combined into multi-arch manifest.

**Workflow:** `.github/workflows/docker.yml`

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

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push (amd64)
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          platforms: linux/amd64
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-amd64
          cache-from: type=gha
          cache-to: type=gha,mode=max

  build-arm64:
    runs-on:
      - runs-on=${{ github.run_id }}/runner=4cpu-linux-arm64/image=ubuntu24-full-arm64/extras=s3-cache/spot=lowest-price/volume=100gb

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push (arm64)
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          platforms: linux/arm64
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-arm64
          cache-from: type=gha
          cache-to: type=gha,mode=max

  manifest:
    needs: [build-amd64, build-arm64]
    runs-on:
      - runs-on=${{ github.run_id }}/runner=2cpu-linux-x64/image=ubuntu24-full-x64/spot=lowest-price

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

### Dockerfile

Uses cargo-chef for optimal layer caching:

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
ENTRYPOINT ["router-hosts", "server"]
```

## E2E Crate Structure

**New crate:** `crates/router-hosts-e2e/`

```
crates/router-hosts-e2e/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs              # Test utilities, shared fixtures
│   ├── certs.rs            # Certificate generation (rcgen)
│   ├── container.rs        # Docker container management
│   └── cli.rs              # CLI subprocess wrapper
└── tests/
    ├── scenarios/
    │   ├── mod.rs
    │   ├── initial_setup.rs      # First-time deployment
    │   ├── daily_operations.rs   # CRUD, import/export
    │   ├── disaster_recovery.rs  # Snapshot/rollback
    │   └── auth_failures.rs      # Invalid certs, expired, wrong CA
    └── e2e_tests.rs        # Main test entry point
```

### Dependencies

```toml
[package]
name = "router-hosts-e2e"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
rcgen = "0.13"              # Runtime certificate generation
testcontainers = "0.23"     # Docker container orchestration
tokio = { version = "1", features = ["process", "fs", "rt-multi-thread", "macros"] }
tempfile = "3"              # Temporary directories for certs/data
assert_cmd = "2"            # CLI subprocess assertions
predicates = "3"            # Output matching
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
```

## Certificate Generation

Runtime generation using `rcgen`:

```rust
// crates/router-hosts-e2e/src/certs.rs

use rcgen::{
    BasicConstraints, Certificate, CertificateParams,
    DnType, IsCa, KeyPair, KeyUsagePurpose
};
use std::path::Path;

pub struct TestCertificates {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

impl TestCertificates {
    pub fn generate() -> Self {
        // 1. Generate CA
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        // 2. Generate server cert (signed by CA)
        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::default();
        server_params.distinguished_name.push(DnType::CommonName, "localhost");
        server_params.subject_alt_names = vec![
            rcgen::SanType::DnsName("localhost".into()),
            rcgen::SanType::IpAddress(std::net::IpAddr::V4([127, 0, 0, 1].into())),
        ];
        let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

        // 3. Generate client cert (signed by CA)
        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::default();
        client_params.distinguished_name.push(DnType::CommonName, "test-client");
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

        Self {
            ca_cert_pem: ca_cert.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// Write certs to a temp directory, return paths
    pub fn write_to_dir(&self, dir: &Path) -> CertPaths {
        // ... implementation
    }
}
```

## Test Scenarios

### initial_setup.rs - First-time deployment

```rust
#[tokio::test]
async fn test_initial_deployment() {
    // 1. Start fresh server container (empty database)
    // 2. Verify server is healthy (grpc health check or list returns empty)
    // 3. Import initial hosts from file
    // 4. Verify hosts file was generated correctly
    // 5. Create initial snapshot ("baseline")
    // 6. Verify snapshot exists
}

#[tokio::test]
async fn test_config_validation() {
    // Server rejects invalid config (missing paths, bad TLS config)
}
```

### daily_operations.rs - Normal usage

```rust
#[tokio::test]
async fn test_crud_workflow() {
    // Add host → List (verify present) → Update IP → Get (verify updated) → Delete → List (verify gone)
}

#[tokio::test]
async fn test_import_export_roundtrip() {
    // Import hosts file → Export to JSON → Clear DB → Import JSON → Verify identical
}

#[tokio::test]
async fn test_search_and_filter() {
    // Add hosts with various tags → Search by tag → Search by hostname pattern
}

#[tokio::test]
async fn test_concurrent_updates() {
    // Two CLI processes update same host → One gets version conflict → Retry succeeds
}
```

### disaster_recovery.rs - Backup and restore

```rust
#[tokio::test]
async fn test_snapshot_and_rollback() {
    // Create hosts → Snapshot → Make breaking changes → Rollback → Verify restored
}

#[tokio::test]
async fn test_backup_snapshot_created() {
    // Rollback creates pre-rollback backup → Can rollback the rollback
}

#[tokio::test]
async fn test_snapshot_retention() {
    // Create many snapshots → Verify old ones pruned per retention policy
}
```

### auth_failures.rs - Security boundaries

```rust
#[tokio::test]
async fn test_no_client_cert_rejected() {
    // Connect without client cert → Connection refused
}

#[tokio::test]
async fn test_wrong_ca_rejected() {
    // Client cert signed by different CA → Connection refused
}

#[tokio::test]
async fn test_expired_cert_rejected() {
    // Generate cert with -1 day validity → Connection refused
}

#[tokio::test]
async fn test_server_cert_validation() {
    // Client rejects server with wrong hostname in cert
}
```

## Taskfile Integration

**`Taskfile.yml`** in repo root:

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
          -v {{.PWD}}/dev/certs:/certs:ro \
          -v {{.PWD}}/dev/data:/data \
          -p 50051:50051 \
          {{.IMAGE_NAME}}:{{.IMAGE_TAG}} \
          --config /certs/server.toml

  # ─────────────────────────────────────────────────────────────
  # E2E Tests
  # ─────────────────────────────────────────────────────────────
  e2e:
    desc: Run E2E acceptance tests
    deps: [build:release, docker:build]
    env:
      ROUTER_HOSTS_IMAGE: '{{.IMAGE_NAME}}:{{.IMAGE_TAG}}'
      ROUTER_HOSTS_BINARY: ./target/release/router-hosts
    cmds:
      - cargo test -p router-hosts-e2e --release

  e2e:quick:
    desc: Run E2E tests (skip rebuild, assumes image exists)
    env:
      ROUTER_HOSTS_IMAGE: '{{.IMAGE_NAME}}:{{.IMAGE_TAG}}'
      ROUTER_HOSTS_BINARY: ./target/release/router-hosts
    cmds:
      - cargo test -p router-hosts-e2e --release

  e2e:scenario:
    desc: Run specific E2E scenario (e.g., task e2e:scenario -- daily_operations)
    env:
      ROUTER_HOSTS_IMAGE: '{{.IMAGE_NAME}}:{{.IMAGE_TAG}}'
      ROUTER_HOSTS_BINARY: ./target/release/router-hosts
    cmds:
      - cargo test -p router-hosts-e2e --release {{.CLI_ARGS}}

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

## CI Integration

**Update `.github/workflows/ci.yml`** to add E2E job:

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

      - name: Run E2E tests
        run: task e2e
```

## Documentation Updates

### README.md

Add development commands section with Task usage.

### CLAUDE.md

Update Build and Development Commands to document:
- Task installation and usage
- E2E test execution
- Docker build commands

### crates/router-hosts-e2e/README.md

Document:
- Test architecture overview
- How to run tests locally
- Test scenario descriptions
- Environment variables

## Implementation Notes

### Test Parallelism
- Each test gets isolated container + temp directory
- `--test-threads=4` runs 4 scenarios concurrently
- testcontainers handles port allocation automatically

### Environment Variables
- `ROUTER_HOSTS_IMAGE`: Docker image to use for server
- `ROUTER_HOSTS_BINARY`: Path to CLI binary

### Local Development
```bash
# One-time setup
brew install go-task

# Build and test
task e2e           # Full build + test
task e2e:quick     # Skip rebuild
task e2e:scenario -- auth_failures  # Single scenario
```
