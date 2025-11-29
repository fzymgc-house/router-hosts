# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**router-hosts** is a Rust CLI tool for managing DNS host entries on routers. It uses a client-server architecture where:
- **Server** runs on the router (OpenWrt/embedded Linux), manages /etc/hosts file via DuckDB storage
- **Client** runs on workstation, connects via gRPC over TLS with mutual authentication

See `docs/plans/2025-11-28-router-hosts-design.md` for complete design specification.

## Build and Development Commands

### Build
```bash
# Build all crates
cargo build

# Build specific crate
cargo build -p router-hosts-server
cargo build -p router-hosts-client

# Release build
cargo build --release
```

### Testing
```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p router-hosts-common
cargo test -p router-hosts-server
cargo test -p router-hosts-client

# Run specific test
cargo test test_name

# Run with logging
RUST_LOG=debug cargo test test_name -- --nocapture
```

### Linting and Formatting
```bash
# Format code
cargo fmt

# Check formatting without modifying
cargo fmt -- --check

# Run clippy
cargo clippy -- -D warnings

# Fix clippy suggestions automatically
cargo clippy --fix
```

### Protocol Buffers
```bash
# Regenerate protobuf code (after modifying proto/hosts.proto)
# This happens automatically during build via tonic-build
# Note: Uses bundled protoc from protobuf-src crate (no system installation required)
cargo build -p router-hosts-common
```

### Running Locally
```bash
# Run server (requires config file)
cargo run -p router-hosts-server -- --config server.toml

# Run client
cargo run -p router-hosts-client -- --help
cargo run -p router-hosts-client -- --config client.toml add --ip 192.168.1.10 --hostname server.local
```

## Architecture Overview

### Workspace Structure

Three crates in a Cargo workspace:

1. **router-hosts-common** - Shared library
   - Protocol buffer definitions and generated code
   - Validation logic (IP addresses, hostnames)
   - Shared types and utilities

2. **router-hosts-server** - Server binary
   - gRPC service implementation
   - DuckDB database operations
   - /etc/hosts file generation with atomic writes
   - Edit session management (single session, 15min timeout)
   - Post-edit hook execution

3. **router-hosts-client** - Client binary
   - CLI interface using clap
   - gRPC client wrapper
   - Command handlers for all operations

### Key Design Decisions

**Edit Sessions:**
- Only ONE active edit session allowed server-wide
- `StartEdit()` returns token, `FinishEdit(token)` commits changes
- 15-minute timeout resets on each operation with the token
- Without edit token, operations apply immediately

**Streaming APIs:**
- All multi-item operations use gRPC streaming (not arrays/lists)
- `ListHosts`, `SearchHosts`, `ExportHosts` - server streaming
- `BulkAddHosts`, `ImportHosts` - bidirectional streaming
- Better memory efficiency and flow control

**Request/Response Messages:**
- All gRPC methods use dedicated request/response types
- Never bare parameters - enables API evolution without breaking changes

**Atomic /etc/hosts Updates:**
- Generate to `.tmp` file → fsync → atomic rename
- Original file unchanged on failure
- Post-edit hooks run after success/failure

**Versioning:**
- DuckDB stores snapshots of /etc/hosts at points in time
- Configurable retention (max count and max age)
- Rollback creates snapshot before restoring old version

### Security

- TLS with mutual authentication (client certs) is mandatory
- No fallback to insecure connections
- Server validates client certificates against configured CA

### Configuration

**Server requires:**
- `hosts_file_path` setting (no default) - prevents accidental overwrites
- TLS certificate paths
- DuckDB path
- Optional: retention policy, hooks, timeout settings

**Client:**
- Config file optional (CLI args override)
- Server address and TLS cert paths

## Important Implementation Notes

### DuckDB Usage

- Embedded database, single file, no daemon
- Ideal for embedded/router environments
- Use in-memory for tests (`duckdb::Connection::open_in_memory()`)

### Validation

All validation logic lives in `router-hosts-common/src/validation.rs`:
- IPv4/IPv6 address validation
- Hostname validation (DNS compliance)
- Duplicate detection happens at database level

### Error Handling

Map domain errors to appropriate gRPC status codes:
- `INVALID_ARGUMENT` - validation failures
- `ALREADY_EXISTS` - duplicates
- `NOT_FOUND` - missing entries/tokens
- `FAILED_PRECONDITION` - session conflicts, expired tokens
- `PERMISSION_DENIED` - TLS auth failures

Include detailed error context in response messages.

### Testing

- **Unit tests:** Mock filesystem for /etc/hosts operations
- **Integration tests:** Use in-memory DuckDB, self-signed certs
- **No real file system writes** in tests (use tempfiles or mocks)

### Dependencies

Core dependencies (see Cargo.toml for versions):
- `tonic` + `prost` - gRPC/protobuf
- `tonic-build` + `protobuf-src` - protobuf code generation with bundled protoc
- `duckdb` - embedded database
- `tokio` - async runtime
- `clap` - CLI parsing
- `serde` + `toml` - config
- `rustls` - TLS
- `tracing` - logging

**Note on Protocol Buffers:** The project uses `protobuf-src` to provide a bundled
Protocol Buffers compiler (`protoc`), eliminating the need for system installation.
This makes the build self-contained and portable across development environments.

## /etc/hosts Format

Generated file includes:
- Header comment with metadata (timestamp, entry count)
- Sorted entries (by IP, then hostname)
- Inline comments from entry metadata
- Tags shown as `[tag1, tag2]` in comments

Example:
```
# Generated by router-hosts
# Last updated: 2025-11-28 20:45:32 UTC
# Entry count: 42

192.168.1.10    server.local
192.168.1.20    nas.home.local    # NAS storage [homelab]
```

## Post-Edit Hooks

Server executes shell commands after /etc/hosts updates:
- `on_success` hooks - after successful regeneration (e.g., reload dnsmasq)
- `on_failure` hooks - after failed regeneration (e.g., alerting)
- Hooks run with 30s timeout, failures logged but don't fail operation
- Environment variables provide context (event type, entry count, snapshot ID)
