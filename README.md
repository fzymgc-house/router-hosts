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
