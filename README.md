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
│   └── router-hosts/          # Unified binary (client + server modes)
└── proto/
    └── router_hosts/
        └── v1/
            └── hosts.proto    # gRPC service definitions
```

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

### Manual Commands

#### Build

```bash
cargo build
```

#### Test

```bash
cargo test
```

#### Run in Client Mode (default)

```bash
cargo run -- --help
cargo run -- add --ip 192.168.1.10 --hostname server.local
```

#### Run in Server Mode

```bash
cargo run -- server --config server.toml
```

### Docker

```bash
# Build server image
task docker:build

# Run specific E2E scenario
task e2e:scenario -- daily_operations
```

## Installation

### Shell Installer (macOS/Linux)

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-installer.sh | sh
```

### Homebrew (macOS/Linux)

```bash
brew install fzymgc-house/tap/router-hosts
```

> **Note:** Shell installer and Homebrew install binaries to `~/.cargo/bin/`. Ensure this directory is in your `PATH`:
> ```bash
> export PATH="$HOME/.cargo/bin:$PATH"
> ```
> Add this line to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) to make it permanent.

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/fzymgc-house/router-hosts/releases/latest):
- macOS (Intel & Apple Silicon)
- Linux (x64 & ARM64)
- Windows (x64)

### Verifying Binaries

All release binaries include GitHub attestations for supply chain security:

```bash
# Verify downloaded binary
gh attestation verify router-hosts --repo fzymgc-house/router-hosts

# Audit embedded dependency information
cargo auditable audit router-hosts
```

### Build from Source

```bash
git clone https://github.com/fzymgc-house/router-hosts.git
cd router-hosts
cargo build --release
```

### Distribution Methods

**router-hosts** uses two complementary distribution workflows:

**CLI Binaries (cargo-dist)**:
- Published to [GitHub Releases](https://github.com/fzymgc-house/router-hosts/releases) on version tags (e.g., `v0.5.0`)
- Multi-platform binaries: macOS (Intel/ARM), Linux (x64/ARM64), Windows (x64)
- Includes shell installer and Homebrew formula
- Use for: Installing CLI on workstations for remote management

**Server Containers (Docker)**:
- Published to [GitHub Container Registry](https://github.com/fzymgc-house/router-hosts/pkgs/container/router-hosts) on every main branch commit
- Multi-arch images: `linux/amd64`, `linux/arm64`
- Tagged with commit SHA and `latest`
- Use for: Deploying server on routers, servers, or containers

```bash
# Pull latest server image
docker pull ghcr.io/fzymgc-house/router-hosts:latest

# Run server container
docker run -v /path/to/config:/config ghcr.io/fzymgc-house/router-hosts:latest server --config /config/server.toml
```

## Status

✅ **v0.5.0 Core Complete** - All features implemented, 8/8 E2E tests passing

**Ready for testing:**
- ✅ Client CLI with all commands (host, snapshot, config)
- ✅ Server with event sourcing (DuckDB/CQRS)
- ✅ Import/Export (hosts, JSON, CSV formats)
- ✅ Snapshots with rollback and retention
- ✅ mTLS authentication
- ✅ Full E2E test coverage

See [v0.5.0 Task List](docs/plans/2025-12-01-v1-tasks.md) for implementation details.

> **Note:** v0.5.0 not yet tagged for release. See GitHub Issues for remaining polish items.

## License

MIT
