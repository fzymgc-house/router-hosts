# SQLite Default Storage Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make SQLite the default storage backend, move DuckDB to a separate binary.

**Architecture:** Refactor `router-hosts` to expose a library, create `router-hosts-duckdb` as a thin wrapper that adds DuckDB support. Change feature flags so SQLite is default.

**Tech Stack:** Rust, Cargo features, sqlx (SQLite/Postgres), duckdb, dirs crate for XDG paths

---

## Task 1: Refactor router-hosts to Export Library

**Files:**
- Modify: `crates/router-hosts/src/lib.rs`
- Modify: `crates/router-hosts/src/main.rs`

**Step 1: Update lib.rs to export run function**

Replace `crates/router-hosts/src/lib.rs`:

```rust
//! Router-hosts library crate
//!
//! This library exposes the main entry point and modules for the router-hosts binary.
//! It can be used as a dependency by variant binaries (e.g., router-hosts-duckdb).

pub mod client;
pub mod server;

use anyhow::Result;
use std::env;
use std::process::ExitCode;

/// Initialize the rustls crypto provider.
///
/// Must be called before any TLS operations. Safe to call multiple times.
pub fn init_crypto_provider() {
    // The only possible error is "provider already installed" which is benign
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Main entry point for router-hosts.
///
/// Parses command line arguments and runs in either server or client mode.
pub async fn run() -> Result<ExitCode> {
    init_crypto_provider();

    let args: Vec<String> = env::args().collect();

    if args.len() > 1 && args[1] == "server" {
        server::run().await?;
        Ok(ExitCode::SUCCESS)
    } else {
        client::run().await
    }
}
```

**Step 2: Simplify main.rs to call library**

Replace `crates/router-hosts/src/main.rs`:

```rust
use anyhow::Result;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    router_hosts::run().await
}
```

**Step 3: Build and test**

Run: `task build && task test`
Expected: All 803 tests pass

**Step 4: Commit**

```bash
git add crates/router-hosts/src/lib.rs crates/router-hosts/src/main.rs
git commit -m "refactor(router-hosts): export library entry point

Move main logic into lib.rs::run() so variant binaries can reuse it.
This enables router-hosts-duckdb to import router-hosts as a library."
```

---

## Task 2: Change Default Feature in router-hosts-storage

**Files:**
- Modify: `crates/router-hosts-storage/Cargo.toml`
- Modify: `crates/router-hosts-storage/src/config.rs`

**Step 1: Update Cargo.toml features**

In `crates/router-hosts-storage/Cargo.toml`, change the features section:

```toml
[features]
default = ["sqlite"]
duckdb = ["dep:duckdb"]
sqlite = ["dep:sqlx", "sqlx/sqlite"]
postgres = ["dep:sqlx", "sqlx/postgres"]
```

**Step 2: Update default in config.rs**

In `crates/router-hosts-storage/src/config.rs`, change `StorageConfig::default()`:

```rust
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: BackendType::Sqlite,
            connection_string: ":memory:".to_string(),
            pool_size: None,
        }
    }
}
```

Also add helper for SQLite:

```rust
/// Create in-memory SQLite configuration for testing
#[must_use]
pub fn sqlite_memory() -> Self {
    Self {
        backend: BackendType::Sqlite,
        connection_string: ":memory:".to_string(),
        pool_size: None,
    }
}

/// Create file-based SQLite configuration
#[must_use]
pub fn sqlite_file(path: &str) -> Self {
    Self {
        backend: BackendType::Sqlite,
        connection_string: path.to_string(),
        pool_size: None,
    }
}
```

**Step 3: Update test for new default**

In `crates/router-hosts-storage/src/config.rs`, update the default test:

```rust
#[test]
fn test_default() {
    let config = StorageConfig::default();
    assert_eq!(config.backend, BackendType::Sqlite);
    assert_eq!(config.connection_string, ":memory:");
    assert_eq!(config.pool_size, None);
}
```

**Step 4: Build storage crate with new default**

Run: `cargo build -p router-hosts-storage`
Expected: Builds with SQLite, not DuckDB

**Step 5: Commit**

```bash
git add crates/router-hosts-storage/Cargo.toml crates/router-hosts-storage/src/config.rs
git commit -m "refactor(storage): change default backend from DuckDB to SQLite

SQLite is lighter weight and compiles faster. DuckDB remains available
via the 'duckdb' feature flag for users who need it."
```

---

## Task 3: Update router-hosts to Exclude DuckDB

**Files:**
- Modify: `crates/router-hosts/Cargo.toml`

**Step 1: Update storage dependency**

In `crates/router-hosts/Cargo.toml`, change:

```toml
router-hosts-storage = { path = "../router-hosts-storage", default-features = false, features = ["sqlite", "postgres"] }
```

**Step 2: Remove direct duckdb dependency**

Remove this line from `crates/router-hosts/Cargo.toml`:

```toml
duckdb.workspace = true
```

**Step 3: Build and verify DuckDB is excluded**

Run: `cargo build -p router-hosts 2>&1 | grep -i duckdb`
Expected: No DuckDB compilation

**Step 4: Run tests**

Run: `task test`
Expected: Tests pass (DuckDB tests skipped due to feature)

**Step 5: Commit**

```bash
git add crates/router-hosts/Cargo.toml
git commit -m "refactor(router-hosts): exclude DuckDB, use SQLite/Postgres only

Reduces binary size and compilation time. DuckDB available via
router-hosts-duckdb binary for users who need it."
```

---

## Task 4: Add XDG Default Storage Path

**Files:**
- Modify: `crates/router-hosts/src/server/config.rs`

**Step 1: Add default_storage_url function**

Add to `crates/router-hosts/src/server/config.rs`:

```rust
/// Get the default storage URL using XDG-compliant paths.
///
/// Returns `sqlite:///<data_dir>/router-hosts/hosts.db` where data_dir is:
/// - Linux: ~/.local/share
/// - macOS: ~/Library/Application Support
/// - Windows: C:\Users\<user>\AppData\Roaming
fn default_storage_url() -> String {
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib"))
        .join("router-hosts");

    format!("sqlite:///{}/hosts.db", data_dir.display())
}
```

**Step 2: Update DatabaseConfig::storage_url to use default**

Replace the `storage_url` method:

```rust
/// Get the storage URL, using XDG default if not configured
pub fn storage_url(&self) -> Result<String, ConfigError> {
    // Prefer explicit url if specified
    if let Some(url) = &self.url {
        return Ok(url.clone());
    }

    // Fall back to converting legacy path to duckdb:// URL
    if let Some(path) = &self.path {
        warn!("database.path is deprecated, use database.url instead");
        let path_str = path.to_string_lossy();
        if path_str.starts_with('/') {
            return Ok(format!("duckdb://{}", path_str));
        } else {
            return Ok(format!("duckdb://./{}", path_str));
        }
    }

    // Use XDG-compliant default
    Ok(default_storage_url())
}
```

**Step 3: Add test for default path**

Add test in `crates/router-hosts/src/server/config.rs`:

```rust
#[test]
fn test_database_config_default_url() {
    let config = DatabaseConfig {
        path: None,
        url: None,
    };
    let url = config.storage_url().unwrap();
    assert!(url.starts_with("sqlite:///"));
    assert!(url.ends_with("/router-hosts/hosts.db"));
}
```

**Step 4: Run tests**

Run: `cargo test -p router-hosts database_config`
Expected: Tests pass

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/config.rs
git commit -m "feat(config): add XDG-compliant default storage path

When database.url is not configured, defaults to SQLite at:
- Linux: ~/.local/share/router-hosts/hosts.db
- macOS: ~/Library/Application Support/router-hosts/hosts.db
- Windows: C:\\Users\\<user>\\AppData\\Roaming\\router-hosts\\hosts.db"
```

---

## Task 5: Improve Error Messages for Unsupported Backends

**Files:**
- Modify: `crates/router-hosts-storage/src/error.rs`
- Modify: `crates/router-hosts-storage/src/lib.rs`

**Step 1: Add BackendNotAvailable error variant**

In `crates/router-hosts-storage/src/error.rs`, add:

```rust
/// Backend not compiled into this build
#[error("{backend} backend not available in this build.\n\nTo use {backend}:\n{suggestion}")]
BackendNotAvailable {
    backend: &'static str,
    suggestion: &'static str,
},
```

**Step 2: Update create_storage with helpful errors**

In `crates/router-hosts-storage/src/lib.rs`, update the error cases:

```rust
#[cfg(not(feature = "duckdb"))]
BackendType::DuckDb => {
    return Err(StorageError::BackendNotAvailable {
        backend: "DuckDB",
        suggestion: "  Install router-hosts-duckdb: brew install fzymgc-house/tap/router-hosts-duckdb\n  Or switch to: sqlite:// or postgres://",
    })
}

#[cfg(not(feature = "sqlite"))]
BackendType::Sqlite => {
    return Err(StorageError::BackendNotAvailable {
        backend: "SQLite",
        suggestion: "  Rebuild with --features sqlite\n  Or switch to: postgres://",
    })
}

#[cfg(not(feature = "postgres"))]
BackendType::Postgres => {
    return Err(StorageError::BackendNotAvailable {
        backend: "PostgreSQL",
        suggestion: "  Rebuild with --features postgres\n  Or switch to: sqlite://",
    })
}
```

**Step 3: Add test for error message**

Add test in `crates/router-hosts-storage/src/lib.rs`:

```rust
#[test]
fn test_backend_not_available_error_message() {
    let err = StorageError::BackendNotAvailable {
        backend: "TestDB",
        suggestion: "  Install test-db",
    };
    let msg = err.to_string();
    assert!(msg.contains("TestDB backend not available"));
    assert!(msg.contains("Install test-db"));
}
```

**Step 4: Run tests**

Run: `cargo test -p router-hosts-storage backend_not_available`
Expected: Test passes

**Step 5: Commit**

```bash
git add crates/router-hosts-storage/src/error.rs crates/router-hosts-storage/src/lib.rs
git commit -m "feat(storage): add actionable error messages for unavailable backends

When a user configures a backend that isn't compiled in, provide
clear guidance on how to install the right binary or switch backends."
```

---

## Task 6: Create router-hosts-duckdb Crate

**Files:**
- Create: `crates/router-hosts-duckdb/Cargo.toml`
- Create: `crates/router-hosts-duckdb/src/main.rs`
- Modify: `Cargo.toml` (workspace)

**Step 1: Create directory**

```bash
mkdir -p crates/router-hosts-duckdb/src
```

**Step 2: Create Cargo.toml**

Create `crates/router-hosts-duckdb/Cargo.toml`:

```toml
[package]
name = "router-hosts-duckdb"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
repository.workspace = true
homepage.workspace = true
description = "Router-hosts with DuckDB backend support"

[[bin]]
name = "router-hosts-duckdb"
path = "src/main.rs"

[dependencies]
router-hosts = { path = "../router-hosts" }
router-hosts-storage = { path = "../router-hosts-storage", features = ["duckdb", "sqlite", "postgres"] }
anyhow.workspace = true
tokio.workspace = true
```

**Step 3: Create main.rs**

Create `crates/router-hosts-duckdb/src/main.rs`:

```rust
//! Router-hosts with DuckDB backend support.
//!
//! This binary includes all storage backends (DuckDB, SQLite, PostgreSQL).
//! Use this when you need DuckDB's analytics capabilities.

use anyhow::Result;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> Result<ExitCode> {
    router_hosts::run().await
}
```

**Step 4: Add to workspace**

In root `Cargo.toml`, add to members:

```toml
members = [
    "crates/router-hosts-common",
    "crates/router-hosts",
    "crates/router-hosts-duckdb",
    "crates/router-hosts-e2e",
    "crates/router-hosts-storage",
]
```

**Step 5: Build and test**

Run: `cargo build -p router-hosts-duckdb`
Expected: Builds successfully with DuckDB

**Step 6: Verify DuckDB is included**

Run: `cargo build -p router-hosts-duckdb 2>&1 | grep -i "Compiling duckdb"`
Expected: Shows DuckDB compilation

**Step 7: Commit**

```bash
git add crates/router-hosts-duckdb Cargo.toml
git commit -m "feat: add router-hosts-duckdb binary

Separate binary that includes DuckDB support for users who need it.
The main router-hosts binary uses SQLite/Postgres only for smaller size."
```

---

## Task 7: Add Dockerfile.duckdb

**Files:**
- Create: `Dockerfile.duckdb`
- Modify: `Dockerfile` (update comment)

**Step 1: Update main Dockerfile comment**

Add comment at top of `Dockerfile`:

```dockerfile
# Dockerfile - Main image with SQLite and PostgreSQL backends
# For DuckDB support, see Dockerfile.duckdb
```

**Step 2: Create Dockerfile.duckdb**

Create `Dockerfile.duckdb`:

```dockerfile
# Dockerfile.duckdb - Image with all backends including DuckDB
# For smaller image without DuckDB, see Dockerfile

# Stage 1: Chef - prepare recipe
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
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
RUN cargo build --release --bin router-hosts-duckdb

# Stage 4: Runtime - minimal image
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/router-hosts-duckdb /usr/local/bin/router-hosts
EXPOSE 50051
ENTRYPOINT ["router-hosts"]
CMD ["server", "--config", "/config/server.toml"]
```

**Step 3: Test build**

Run: `docker build -f Dockerfile.duckdb -t router-hosts-duckdb:test .`
Expected: Builds successfully

**Step 4: Commit**

```bash
git add Dockerfile Dockerfile.duckdb
git commit -m "build(docker): add Dockerfile.duckdb for DuckDB variant

Main Dockerfile builds SQLite/Postgres only (smaller).
Dockerfile.duckdb builds with all backends including DuckDB."
```

---

## Task 8: Update CI Workflows

**Files:**
- Modify: `.github/workflows/docker.yml`
- Modify: `.github/workflows/ci.yml`

**Step 1: Update docker.yml for matrix build**

In `.github/workflows/docker.yml`, update the build job to use a matrix:

```yaml
jobs:
  build:
    strategy:
      matrix:
        include:
          - image: router-hosts
            dockerfile: Dockerfile
            binary: router-hosts
          - image: router-hosts-duckdb
            dockerfile: Dockerfile.duckdb
            binary: router-hosts-duckdb
    # ... rest of job uses ${{ matrix.image }}, ${{ matrix.dockerfile }}
```

**Step 2: Update ci.yml to test both binaries**

Ensure the test job builds both binaries:

```yaml
- name: Build
  run: cargo build --workspace
```

**Step 3: Test CI locally**

Run: `task ci`
Expected: All checks pass

**Step 4: Commit**

```bash
git add .github/workflows/docker.yml .github/workflows/ci.yml
git commit -m "ci: build both router-hosts and router-hosts-duckdb

Docker workflow builds two images in parallel.
CI tests both binaries."
```

---

## Task 9: Update Documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/architecture.md` (if exists)

**Step 1: Update CLAUDE.md crate structure**

Update the crate table in `CLAUDE.md`:

```markdown
| Crate | Purpose |
|-------|---------|
| `router-hosts-common` | Protobuf definitions, validation, shared types |
| `router-hosts-storage` | Storage trait with SQLite (default), PostgreSQL, DuckDB backends |
| `router-hosts` | Main binary (SQLite + PostgreSQL only) |
| `router-hosts-duckdb` | DuckDB variant binary (all backends) |
| `router-hosts-e2e` | Docker-based E2E tests with real mTLS |
```

**Step 2: Add storage backend docs**

Add section to CLAUDE.md:

```markdown
### Storage Backends

The default `router-hosts` binary includes SQLite and PostgreSQL backends.
For DuckDB support, install `router-hosts-duckdb`:

```bash
# Main binary (SQLite/PostgreSQL)
brew install fzymgc-house/tap/router-hosts

# DuckDB variant (all backends)
brew install fzymgc-house/tap/router-hosts-duckdb
```

**Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update for SQLite default and DuckDB variant

Document the new binary structure with SQLite as default."
```

---

## Task 10: Final Verification

**Step 1: Run full test suite**

Run: `task test`
Expected: All tests pass

**Step 2: Check binary sizes**

```bash
cargo build --release -p router-hosts
cargo build --release -p router-hosts-duckdb
ls -lh target/release/router-hosts target/release/router-hosts-duckdb
```

Expected: router-hosts significantly smaller than router-hosts-duckdb

**Step 3: Test both binaries work**

```bash
./target/release/router-hosts --help
./target/release/router-hosts-duckdb --help
```

Expected: Both show help

**Step 4: Verify DuckDB error message**

```bash
./target/release/router-hosts server --config /dev/null 2>&1 | head -20
# Create minimal config with duckdb:// URL and verify error message
```

**Step 5: Run coverage**

Run: `task test:coverage:ci`
Expected: Coverage >= 80%

**Step 6: Final commit and push**

```bash
git push origin refactor/sqlite-default
```

---

## Summary

| Task | Description |
|------|-------------|
| 1 | Refactor router-hosts to export library |
| 2 | Change default feature to SQLite |
| 3 | Update router-hosts to exclude DuckDB |
| 4 | Add XDG default storage path |
| 5 | Improve error messages |
| 6 | Create router-hosts-duckdb crate |
| 7 | Add Dockerfile.duckdb |
| 8 | Update CI workflows |
| 9 | Update documentation |
| 10 | Final verification |
