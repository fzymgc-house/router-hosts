# router-hosts

A Go CLI for managing DNS host entries via client-server architecture with gRPC over mTLS.

## Features

- **Client-Server Architecture** — Centralized host management with secure gRPC communication
- **mTLS Security** — Mutual TLS authentication for all client-server communication
- **SQLite Storage** — Lightweight embedded storage with event sourcing
- **ACME Integration** — Automatic certificate management with Let's Encrypt
- **Kubernetes Operator** — Native Kubernetes integration for declarative host management
- **Event Sourcing** — Full audit trail with snapshot-based state recovery

## Quick Start

```bash
# Build from source
git clone https://github.com/fzymgc-house/router-hosts.git
cd router-hosts && task build:release

# Start server
./bin/router-hosts serve --config server.toml

# Add a host
./bin/router-hosts host add --ip 192.168.1.100 --hostname myserver.local --tag homelab
```

[Get Started](getting-started/index.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/fzymgc-house/router-hosts){ .md-button }
