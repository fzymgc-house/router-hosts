# router-hosts

A Rust CLI for managing DNS host entries via client-server architecture with gRPC over mTLS.

## Features

- **Client-Server Architecture** — Centralized host management with secure gRPC communication
- **mTLS Security** — Mutual TLS authentication for all client-server communication
- **Multiple Storage Backends** — SQLite (default), PostgreSQL, and DuckDB support
- **ACME Integration** — Automatic certificate management with Let's Encrypt
- **Kubernetes Operator** — Native Kubernetes integration for declarative host management
- **Event Sourcing** — Full audit trail with snapshot-based state recovery

## Quick Start

```bash
# Install
brew install fzymgc-house/tap/router-hosts

# Start server
router-hosts server --config server.toml

# Add a host
router-hosts host add --ip 192.168.1.100 --hostname myserver.local --tag homelab
```

[Get Started](getting-started/index.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/fzymgc-house/router-hosts){ .md-button }
