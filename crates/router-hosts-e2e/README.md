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
