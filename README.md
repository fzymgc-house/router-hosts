# router-hosts

[![CI](https://github.com/fzymgc-house/router-hosts/actions/workflows/ci-go.yml/badge.svg)](https://github.com/fzymgc-house/router-hosts/actions/workflows/ci-go.yml)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25-green)](docs/test-coverage-audit.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Go CLI tool for managing DNS host entries on routers via gRPC.

## Overview

**router-hosts** provides a client-server architecture for remotely managing `/etc/hosts` files on routers (OpenWrt or similar embedded Linux):

- **Server** runs on the router, exposes gRPC API, manages host entries with event-sourced storage
- **Client** runs on your workstation, provides CLI for all operations
- **Kubernetes Operator** automates DNS registration for Traefik IngressRoutes and custom HostMappings
- Supports versioning, bulk operations, snapshots with rollback, and validation
- TLS with mutual authentication for security
- OpenTelemetry metrics and tracing for observability

See [Architecture](docs/contributing/architecture.md) for detailed design.

## Project Structure

```text
router-hosts/
├── cmd/
│   ├── router-hosts/     # Server + client binary
│   └── operator/         # Kubernetes operator binary
├── internal/
│   ├── acme/             # ACME certificate management
│   ├── client/           # CLI client (commands, output, TUI)
│   ├── config/           # Configuration loading
│   ├── domain/           # Domain types, events, errors
│   ├── operator/         # K8s operator controllers
│   ├── server/           # gRPC server, hosts file, hooks
│   ├── storage/          # Storage interfaces
│   │   └── sqlite/       # SQLite implementation
│   └── validation/       # IP/hostname validation
├── e2e/                  # E2E tests with real mTLS
└── proto/                # Protobuf definitions
```

## Development

### Prerequisites

- Go 1.24+
- Docker
- [Task](https://taskfile.dev/) (recommended)
- [buf](https://buf.build/) (for protobuf)
- [golangci-lint](https://golangci-lint.run/) (for linting)
- [gofumpt](https://github.com/mvdan/gofumpt) (for formatting)

### Quick Start

```bash
# Install Task (macOS)
brew install go-task

# Build
task build

# Run tests
task test

# Run E2E tests (requires Docker)
task test:e2e

# Full CI pipeline locally
task ci
```

### Available Tasks

| Task | Description |
|------|-------------|
| `task build` | Build all binaries (debug) |
| `task build:release` | Build all binaries with optimizations |
| `task test` | Run all unit and integration tests |
| `task test:e2e` | Run E2E tests with real mTLS |
| `task test:coverage` | Run tests with HTML coverage report |
| `task test:coverage:ci` | Coverage with 80% threshold |
| `task lint` | Run all linters (Go + protobuf) |
| `task fmt` | Format all code (Go + protobuf) |
| `task proto:generate` | Generate Go code from protobuf |
| `task docker:build` | Build Docker image |
| `task clean` | Remove build artifacts |
| `task ci` | Full CI pipeline locally |

### Manual Commands

#### Build

```bash
go build ./cmd/router-hosts && go build ./cmd/operator
```

#### Test

```bash
go test ./... -race
```

#### Run Client

```bash
./bin/router-hosts --help
```

#### Run Server

```bash
./bin/router-hosts serve --config server.toml
```

### Docker

```bash
# Build server image
task docker:build
```

## Installation

### Build from Source

```bash
git clone https://github.com/fzymgc-house/router-hosts.git
cd router-hosts
task build:release
# Binaries in bin/
```

### Docker

```bash
# Pull latest server image
docker pull ghcr.io/fzymgc-house/router-hosts:latest

# Run server container
docker run -v /path/to/config:/config ghcr.io/fzymgc-house/router-hosts:latest serve --config /config/server.toml
```

## Status

**Go Rewrite** - Rewritten from Rust to Go for simplified development and deployment

**Features:**

- Client CLI with all commands (host, snapshot, config)
- Server with event sourcing and SQLite storage
- Import/Export (hosts, JSON, CSV formats)
- Snapshots with rollback and retention
- mTLS authentication with SIGHUP certificate reload
- ACME certificate automation (HTTP-01 and DNS-01)
- Kubernetes operator for Traefik integration
- Leader election for operator HA
- Health RPCs for monitoring and probes
- OpenTelemetry metrics and tracing
- E2E test coverage with real mTLS

## License

MIT
