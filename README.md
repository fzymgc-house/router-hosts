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

### Build

```bash
cargo build
```

### Test

```bash
cargo test
```

### Run in Client Mode (default)

```bash
cargo run -- --help
cargo run -- add --ip 192.168.1.10 --hostname server.local
```

### Run in Server Mode

```bash
cargo run -- server --config server.toml
```

## Status

🚧 **In Development** - Initial setup phase

## License

MIT
