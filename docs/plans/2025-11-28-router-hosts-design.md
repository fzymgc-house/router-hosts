# router-hosts Design Document

**Date:** 2025-11-28
**Status:** DEPRECATED - Superseded by 2025-12-01-router-hosts-v1-design.md

> **Note:** This document is kept for historical reference only. The current design
> removes edit sessions and uses event sourcing. See the v0.5.0 design document.

## Overview

router-hosts is a Rust CLI tool for managing DNS host entries on routers. It provides a gRPC-based client-server architecture for remotely managing /etc/hosts files with versioning, bulk operations, and validation.

## System Architecture

### Operational Modes

**Server Mode:**
- Runs on the router (OpenWrt or similar embedded Linux)
- Exposes gRPC API for remote management
- Stores host entries in DuckDB (embedded, single-file database)
- Manages the /etc/hosts file that dnsmasq reads
- Handles versioning, validation, and backup operations
- Uses TLS with mutual authentication

**Client Mode:**
- Runs on workstation/laptop
- Connects to server via gRPC over TLS
- Provides CLI commands for all operations
- Authenticates using client certificates

### Data Flow

1. Client sends gRPC request (e.g., add host entry)
2. Server validates and stores in DuckDB
3. Changes accumulate in edit session (if active) or apply immediately
4. On completion, server regenerates /etc/hosts from DuckDB
5. Post-edit hooks execute (e.g., reload dnsmasq)
6. Server creates version snapshots based on retention policy
7. Dnsmasq automatically picks up /etc/hosts changes

## Data Model

### Host Entry

Stored in DuckDB with the following schema:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID | Yes | Primary key, system-generated |
| `ip_address` | String | Yes | IPv4 or IPv6 address |
| `hostname` | String | Yes | DNS hostname (with or without domain) |
| `comment` | String | No | Description/notes |
| `tags` | String[] | No | Categories (e.g., "iot", "homelab") |
| `created_at` | Timestamp | Yes | System-generated |
| `updated_at` | Timestamp | Yes | System-generated |
| `active` | Boolean | Yes | Soft delete flag |

**Validation Rules:**
- IP must be valid IPv4 (e.g., `192.168.1.10`) or IPv6 (e.g., `fe80::1`)
- Hostname must be valid DNS name (alphanumeric, hyphens, dots)
- Duplicate IP+hostname combinations rejected
- Tags and comments are freeform

### Version Snapshot

For backup and rollback functionality:

| Field | Type | Description |
|-------|------|-------------|
| `snapshot_id` | UUID | Primary key |
| `created_at` | Timestamp | When snapshot was created |
| `hosts_content` | Text | Full /etc/hosts file content |
| `entry_count` | Integer | Number of active entries |
| `trigger` | Enum | manual, auto_before_change, scheduled |

**Retention Policy:**
- `max_snapshots`: Keep last N versions (configurable)
- `max_age_days`: Delete snapshots older than N days (configurable)
- Both limits enforced - whichever triggers first

## gRPC API

All operations use request/response message types for API evolution.

### Host Entry Management

- `AddHost(AddHostRequest) → AddHostResponse`
- `UpdateHost(UpdateHostRequest) → UpdateHostResponse`
- `DeleteHost(DeleteHostRequest) → DeleteHostResponse`
- `GetHost(GetHostRequest) → GetHostResponse`
- `ListHosts(ListHostsRequest) → stream ListHostsResponse`
- `SearchHosts(SearchHostsRequest) → stream SearchHostsResponse`

### Bulk Operations

- `BulkAddHosts(stream BulkAddHostsRequest) → stream BulkAddHostsResponse`
- `ImportHosts(stream ImportHostsRequest) → stream ImportHostsResponse`
- `ExportHosts(ExportHostsRequest) → stream ExportHostsResponse`

### Edit Session Management

- `StartEdit(StartEditRequest) → StartEditResponse`
- `FinishEdit(FinishEditRequest) → FinishEditResponse`
- `CancelEdit(CancelEditRequest) → CancelEditResponse`

**Edit Session Constraints:**
- Only one active edit token allowed server-wide
- 15-minute timeout since last operation (configurable)
- On timeout: draft changes automatically discarded

**Edit Session Workflow:**
1. `StartEdit()` returns `edit_token` (fails if session exists)
2. Modification operations include optional `edit_token`
   - With token: changes staged, /etc/hosts unchanged
   - Without token: immediate apply, /etc/hosts regenerated
3. `FinishEdit(edit_token)` commits all staged changes
4. `CancelEdit(edit_token)` discards staged changes

Any operation using the token resets the timeout clock.

### Versioning

- `CreateSnapshot(CreateSnapshotRequest) → CreateSnapshotResponse`
- `ListSnapshots(ListSnapshotsRequest) → stream ListSnapshotsResponse`
- `RollbackToSnapshot(RollbackToSnapshotRequest) → RollbackToSnapshotResponse`
- `DeleteSnapshot(DeleteSnapshotRequest) → DeleteSnapshotResponse`

## Configuration

### Server Configuration

File: `server.toml` (required)

```toml
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = "/etc/hosts"  # REQUIRED - no default

[database]
path = "/var/lib/router-hosts/hosts.db"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"

[retention]
max_snapshots = 50
max_age_days = 30

[edit_session]
timeout_minutes = 15

[hooks]
on_success = [
    "/etc/init.d/dnsmasq reload"
]
on_failure = [
    "/usr/local/bin/alert-hosts-failed.sh"
]
```

### Client Configuration

File: `~/.config/router-hosts/client.toml` (optional)

```toml
[client]
server_address = "router.local:50051"

[tls]
cert_path = "~/.config/router-hosts/client.crt"
key_path = "~/.config/router-hosts/client.key"
ca_cert_path = "~/.config/router-hosts/ca.crt"
```

CLI arguments override config file values.

## /etc/hosts File Generation

### Generation Logic

1. Query all active entries from DuckDB (`active = true`)
2. Sort by IP address, then hostname (deterministic output)
3. Generate file with header and entries
4. Write atomically: temp file → fsync → atomic rename

### Output Format

```
# Generated by router-hosts
# Last updated: 2025-11-28 20:45:32 UTC
# Entry count: 42

127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback

192.168.1.10    server.local
192.168.1.20    nas.home.local    # NAS storage
192.168.1.30    printer           # Office printer [iot]
```

**Metadata Handling:**
- Comments appear as inline `# comment`
- Tags shown in comment section as `[tag1, tag2]`

### Atomic Write Process

1. Generate content in memory
2. Write to `{hosts_file_path}.tmp`
3. `fsync()` the temp file
4. Atomic `rename()` to actual path
5. On failure: temp file removed, original unchanged

### Post-Edit Hooks

Execute after /etc/hosts regeneration:

**Success hooks run after:**
- `FinishEdit()` successful commit
- Single operation completion
- `RollbackToSnapshot()` completion

**Failure hooks run when:**
- File write fails
- Validation fails
- Any regeneration error

**Hook Execution:**
- Runs in configured order
- Continues even if one fails
- Captures stdout/stderr for logging
- 30-second timeout per hook (configurable)
- Failures logged but don't fail overall operation

**Hook Environment Variables:**
- `ROUTER_HOSTS_EVENT=success|failure`
- `ROUTER_HOSTS_ENTRY_COUNT=N`
- `ROUTER_HOSTS_SNAPSHOT_ID=uuid`

## Error Handling

### gRPC Status Codes

- `INVALID_ARGUMENT` - Validation failures
- `ALREADY_EXISTS` - Duplicate IP+hostname
- `NOT_FOUND` - Entry, snapshot, or token not found
- `FAILED_PRECONDITION` - Session already active, token expired
- `PERMISSION_DENIED` - TLS auth failure
- `RESOURCE_EXHAUSTED` - Database/retention limits
- `INTERNAL` - Database errors, file I/O failures

### Error Details

Responses include:
- Human-readable message
- Error code for programmatic handling
- Context (e.g., which field failed, duplicate entry ID)

### Logging

**Server-side:**
- Structured JSON logging
- Levels: ERROR, WARN, INFO, DEBUG
- Size-based rotation for embedded environments

**Client-side:**
- User-friendly error messages
- Detailed output with `--verbose` flag
- Exit codes: 0 (success), 1 (user error), 2 (server error), 3 (connection error)

## Testing Strategy

### Unit Tests

- Validation logic (IP, hostname, DNS format)
- DuckDB operations (CRUD, queries, snapshots)
- /etc/hosts file generation
- Edit session management
- Configuration parsing

### Integration Tests

- gRPC client-server communication
- TLS mutual authentication
- Streaming API behavior
- Hook execution
- Atomic file writes and rollback

### Test Environment

- Mock filesystem for /etc/hosts
- In-memory DuckDB for speed
- Self-signed certs for TLS testing
- Docker container for OpenWrt-like testing

### Performance Tests

- Bulk import (10k+ entries)
- Streaming under load
- DuckDB query performance
- Memory usage on embedded hardware

## Project Structure

```
router-hosts/
├── Cargo.toml                    # Workspace root
├── proto/
│   └── hosts.proto              # gRPC service definitions
├── crates/
│   ├── router-hosts-server/     # Server binary
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── config.rs        # Server config
│   │   │   ├── db.rs            # DuckDB ops
│   │   │   ├── service.rs       # gRPC service
│   │   │   ├── hosts_gen.rs     # /etc/hosts generation
│   │   │   ├── hooks.rs         # Post-edit hooks
│   │   │   └── session.rs       # Edit session mgmt
│   │   └── Cargo.toml
│   ├── router-hosts-client/     # Client binary
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── config.rs        # Client config
│   │   │   ├── commands/        # CLI commands
│   │   │   └── grpc.rs          # gRPC client
│   │   └── Cargo.toml
│   └── router-hosts-common/     # Shared library
│       ├── src/
│       │   ├── lib.rs
│       │   ├── validation.rs    # IP/hostname validation
│       │   ├── types.rs         # Shared types
│       │   └── proto.rs         # Generated protobuf
│       └── Cargo.toml
```

### Key Dependencies

- `tonic` - gRPC framework
- `prost` - Protocol buffers
- `duckdb` - Embedded database
- `tokio` - Async runtime
- `clap` - CLI parsing
- `serde` / `toml` - Configuration
- `rustls` - TLS implementation
- `tracing` - Structured logging

## Implementation Notes

### Security

- TLS with mutual authentication required
- Client certificates validated against CA
- No fallback to insecure connections

### Embedded Constraints

- Single DuckDB file - no daemon required
- Configurable log rotation
- Snapshot retention prevents unbounded growth
- Memory-efficient streaming for large datasets

### Deployment

Server typically runs as system service on router:
- OpenWrt: `/etc/init.d/router-hosts`
- systemd: `router-hosts.service`

Client installed on workstation via cargo or binary release.
