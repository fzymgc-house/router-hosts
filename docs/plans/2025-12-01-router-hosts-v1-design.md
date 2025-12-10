# router-hosts v0.5.0 Design Document

**Date:** 2025-12-01
**Status:** Active
**Supersedes:** 2025-11-28-router-hosts-design.md, 2025-11-30-server-completion-design.md, 2025-11-30-server-implementation.md

## Overview

**router-hosts** is a Rust tool for managing DNS host entries on routers and servers. It uses a client-server architecture:

**Server** runs on the target machine (router, server, container), managing a configurable hosts file via an event-sourced database. The hosts file path must be explicitly configured - there is no default, preventing accidental overwrites of system files. The server exposes a gRPC API with mutual TLS authentication.

**Client** runs on a workstation, connecting to the server via gRPC. It provides a CLI organized into subcommand groups (`host`, `snapshot`, etc.).

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Storage | Event Sourcing + CQRS | Complete audit trail, time-travel queries, no soft-delete complexity |
| Transport | gRPC with mTLS | Mandatory mutual auth, streaming support, efficient binary protocol |
| Concurrency | Optimistic locking | Event versions prevent lost updates without explicit sessions |
| File updates | Immediate | Every write regenerates the hosts file; operations are infrequent |
| Hosts file path | Required config, no default | Safety - prevents accidental system file overwrites |
| Edit sessions | **Removed** | Added complexity without sufficient benefit; optimistic concurrency is simpler |

### Data Flow

```
Client CLI → gRPC/mTLS → Server
                           ↓
                    Command Handler
                           ↓
                    Event Store (DuckDB)
                           ↓
                    Hosts file regeneration
                           ↓
                    Post-edit hooks (e.g., reload dnsmasq)
```

## Data Model

### Host Entry

The logical view of a host entry (reconstructed from events):

| Field | Type | Description |
|-------|------|-------------|
| `id` | ULID | Unique identifier, system-generated |
| `ip_address` | String | IPv4 or IPv6 address |
| `hostname` | String | DNS hostname (with or without domain) |
| `comment` | String? | Optional description/notes |
| `tags` | String[] | Categories for filtering (e.g., "homelab", "iot") |
| `created_at` | Timestamp | When entry was created |
| `updated_at` | Timestamp | When entry was last modified |
| `version` | Integer | Event version for optimistic concurrency |

**Validation rules:**
- IP must be valid IPv4 or IPv6
- Hostname must be valid DNS name (RFC 1123)
- Duplicate IP+hostname combinations are rejected

**Optimistic concurrency:**
- Each entry has a `version` field incremented on every change
- Updates require the current version; mismatches return `ABORTED`
- `GetHost` returns the current version for use in subsequent updates

**Conflict resolution (CLI):**
- On version mismatch, CLI shows diff between local changes and server state
- Interactive prompt: "Entry was modified. Apply your changes to new version? [y/n]"
- Use `--non-interactive` flag to fail immediately on conflict (for scripts)
- Programmatic clients should implement retry with exponential backoff (max 3 attempts)

### Domain Events

The event store records immutable facts:

| Event | Fields | Description |
|-------|--------|-------------|
| `HostCreated` | ip, hostname, comment?, tags[] | New entry |
| `IpAddressChanged` | old_ip, new_ip | IP modification |
| `HostnameChanged` | old_hostname, new_hostname | Hostname modification |
| `CommentUpdated` | old_comment?, new_comment? | Comment change |
| `TagsModified` | old_tags[], new_tags[] | Tags change |
| `HostDeleted` | ip, hostname, reason? | Tombstone event |

### Snapshots

Point-in-time captures of the hosts file content:

| Field | Type | Description |
|-------|------|-------------|
| `snapshot_id` | ULID | Unique identifier |
| `created_at` | Timestamp | When snapshot was created |
| `entry_count` | Integer | Number of entries captured |
| `trigger` | String | "manual", "pre-rollback" |

## gRPC API

All operations use dedicated request/response message types for API evolution. No edit sessions - all writes apply immediately.

### Host Management

| RPC | Type | Description |
|-----|------|-------------|
| `AddHost` | Unary | Create new host entry |
| `GetHost` | Unary | Retrieve entry by ID |
| `UpdateHost` | Unary | Modify existing entry (partial updates supported) |
| `DeleteHost` | Unary | Remove entry (tombstone event) |
| `ListHosts` | Server streaming | List all entries with optional filter/pagination |
| `SearchHosts` | Server streaming | Search by query string (matches IP, hostname, comment, tags) |

### Import/Export

| RPC | Type | Description |
|-----|------|-------------|
| `ImportHosts` | Bidirectional streaming | Import from file format (chunked upload, progress responses) |
| `ExportHosts` | Server streaming | Export entries in specified format (hosts/json/csv) |

**Note:** Bulk operations use `ImportHosts` streaming rather than a separate `BulkAddHosts` RPC. For adding multiple entries programmatically, use multiple `AddHost` calls or import from a file.

**Import conflict handling:**
- Default: Skip existing IP+hostname combinations (idempotent imports)
- `--replace` flag: Update existing entries with imported data
- `--strict` flag: Fail on any duplicate

**Progress responses include:**
- Entries processed / total
- Entries created
- Entries skipped (duplicates)
- Entries failed (validation errors)

### Snapshots

| RPC | Type | Description |
|-----|------|-------------|
| `CreateSnapshot` | Unary | Capture current state |
| `ListSnapshots` | Server streaming | List available snapshots |
| `RollbackToSnapshot` | Unary | Restore to previous state (creates backup snapshot first) |
| `DeleteSnapshot` | Unary | Remove a snapshot |

### Error Mapping

| Condition | gRPC Status |
|-----------|-------------|
| Validation failure | `INVALID_ARGUMENT` |
| Duplicate IP+hostname | `ALREADY_EXISTS` |
| Entry/snapshot not found | `NOT_FOUND` |
| Concurrent write conflict | `ABORTED` |
| TLS auth failure | `PERMISSION_DENIED` |
| Database/IO error | `INTERNAL` |

## Client CLI

### Command Structure

Organized into subcommand groups:

```
router-hosts [OPTIONS] <COMMAND>

Commands:
  host      Manage host entries
  snapshot  Manage snapshots
  config    Show effective configuration

Global Options:
  -s, --server <ADDRESS>    Server address (host:port)
  -c, --config <PATH>       Config file path
      --cert <PATH>         Client certificate
      --key <PATH>          Client key
      --ca <PATH>           CA certificate
  -v, --verbose             Verbose output
  -q, --quiet               Suppress non-error output
      --format <FORMAT>     Output format: table, json, csv [default: table]
```

### Host Commands

```
router-hosts host <COMMAND>

Commands:
  add       Add a new host entry
  get       Get a host entry by ID
  update    Update an existing host entry
  delete    Delete a host entry
  list      List all host entries
  search    Search host entries
  import    Import hosts from file
  export    Export hosts to file
```

### Snapshot Commands

```
router-hosts snapshot <COMMAND>

Commands:
  create    Create a new snapshot
  list      List all snapshots
  rollback  Rollback to a snapshot
  delete    Delete a snapshot
```

### Example Usage

```bash
# Add a host entry
router-hosts host add --ip 192.168.1.10 --hostname server.local \
  --comment "Dev server" --tags homelab,dev

# List all hosts
router-hosts host list

# Search for hosts
router-hosts host search nas

# Update a host (by ID from list output)
# All fields optional: --ip, --hostname, --comment, --tags
router-hosts host update 01JF... --ip 192.168.1.11 --comment "Updated server"

# Export to JSON for backup
router-hosts host export --format json > hosts-backup.json

# Create snapshot before major changes
router-hosts snapshot create

# Rollback if something goes wrong
router-hosts snapshot rollback 01JF...
```

### Configuration Precedence

CLI arguments > Environment variables > Config file

| Setting | CLI Flag | Environment Variable |
|---------|----------|---------------------|
| Server address | `--server` | `ROUTER_HOSTS_SERVER` |
| Client cert | `--cert` | `ROUTER_HOSTS_CERT` |
| Client key | `--key` | `ROUTER_HOSTS_KEY` |
| CA cert | `--ca` | `ROUTER_HOSTS_CA` |

Config file: `~/.config/router-hosts/client.toml` (or `--config` override)

### Client Configuration File

```toml
# ~/.config/router-hosts/client.toml

[server]
address = "router.local:50051"

[tls]
cert_path = "~/.config/router-hosts/client.crt"
key_path = "~/.config/router-hosts/client.key"
ca_cert_path = "~/.config/router-hosts/ca.crt"

[output]
format = "table"  # table, json, csv
```

## Server Configuration

Config file is required. No defaults for sensitive paths.

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
max_snapshots = 50        # Keep at most N snapshots
max_age_days = 30         # Delete snapshots older than N days

[hooks]
on_success = [
    "/etc/init.d/dnsmasq reload"
]
on_failure = [
    "/usr/local/bin/notify-failure.sh"
]
```

### Required Fields

| Field | Description |
|-------|-------------|
| `server.hosts_file_path` | Target hosts file - must be explicit |
| `database.path` | DuckDB file location |
| `tls.cert_path` | Server certificate |
| `tls.key_path` | Server private key |
| `tls.ca_cert_path` | CA for client verification |

### Hook Execution

- Hooks run sequentially in configured order
- 30-second timeout per hook
- Failures logged but don't fail the operation
- Environment variables provided:
  - `ROUTER_HOSTS_EVENT` - "success" or "failure"
  - `ROUTER_HOSTS_ENTRY_COUNT` - number of entries
  - `ROUTER_HOSTS_ERROR` - error message (on failure)

### Retention Enforcement

Enforced on snapshot creation - both limits apply (whichever triggers first).

### Event Store Compaction

The event store grows unbounded as events accumulate. For v0.5.0, compaction is manual:

```bash
# Export current state, compact events
router-hosts host export --format json > backup.json
# Future: router-hosts admin compact --before-date 2025-01-01
```

**When to compact:**
- Monitor DuckDB file size (consider compaction at 100MB+)
- Track event count via `router-hosts admin stats` (future command)
- Server logs warning when event count exceeds 100K

**Future enhancement:** Automatic compaction that:
- Creates a snapshot of current state
- Replaces event history with synthetic `HostCreated` events
- Preserves audit trail in archived event files
- Runs based on event count or age thresholds

## Deployment

### Systemd Service

`/etc/systemd/system/router-hosts.service`:

```ini
[Unit]
Description=Router Hosts Management Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/router-hosts server --config /etc/router-hosts/server.toml
Restart=on-failure
RestartSec=5
User=router-hosts
Group=router-hosts

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/router-hosts /etc/hosts

[Install]
WantedBy=multi-user.target
```

### Container Image

```dockerfile
FROM cgr.dev/chainguard/rust:latest AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

FROM cgr.dev/chainguard/glibc-dynamic:latest
COPY --from=builder /build/target/release/router-hosts /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/router-hosts", "server"]
CMD ["--config", "/etc/router-hosts/server.toml"]
```

Run with volume mounts for config, certs, database, and hosts file:

```bash
docker run -d \
  -v /path/to/config:/etc/router-hosts:ro \
  -v /path/to/data:/var/lib/router-hosts \
  -v /etc/hosts:/etc/hosts \
  -p 50051:50051 \
  router-hosts:latest

# Or with host networking (simpler for local deployments)
docker run -d \
  --network host \
  -v /path/to/config:/etc/router-hosts:ro \
  -v /path/to/data:/var/lib/router-hosts \
  -v /etc/hosts:/etc/hosts \
  router-hosts:latest
```

#### Container Security

The container runs as non-root user `nonroot` (UID 65532) from the Chainguard base image.

**Volume permissions:** Ensure mounted directories are accessible:
```bash
# Data directory owned by container user
chown 65532:65532 /path/to/data

# Hosts file writable by container user
chown 65532:65532 /etc/hosts
# Or use a dedicated hosts file, not the system one
```

**Note:** Writing to `/etc/hosts` on the host requires either root privileges or appropriate file ownership. For containerized deployments, consider using a dedicated hosts file path that dnsmasq reads separately.

### Certificate Management

Two modes: **manual** (provide your own certs) or **ACME** (automatic via Let's Encrypt or other CA).

#### Manual Mode

```toml
[tls]
mode = "manual"
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"
```

#### ACME Mode

```toml
[tls]
mode = "acme"
ca_cert_path = "/etc/router-hosts/ca.crt"  # Still needed for client mTLS

[tls.acme]
email = "admin@example.com"
domain = "router-hosts.example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"  # or staging
challenge = "dns"  # "http", "tls-alpn", or "dns"
storage_path = "/var/lib/router-hosts/acme"  # cert cache

# For HTTP-01 challenge
# http_listen = "0.0.0.0:80"

# For DNS-01 challenge
dns_provider = "cloudflare"
dns_credentials_file = "/etc/router-hosts/dns-credentials.toml"
```

#### Challenge Types

| Challenge | Port | Use Case |
|-----------|------|----------|
| `http` | 80 | Server directly reachable on port 80 |
| `tls-alpn` | 443 | Server handles TLS on port 443 |
| `dns` | None | Behind NAT, firewalled, or wildcard certs |

DNS-01 provider support: Cloudflare, Route53, Google Cloud DNS, RFC2136 (dynamic DNS).

#### ACME Initial Certificate Acquisition

On first server start with ACME mode:
1. Server attempts ACME challenge before starting gRPC service
2. If successful: Server starts with acquired certificate
3. If failed: Server exits with error (requires manual intervention)

**Bootstrap strategy:** For initial setup where DNS/firewall isn't ready:
1. Start with `mode = "manual"` using self-signed or internal CA certs
2. Configure DNS/firewall for ACME challenge
3. Switch to `mode = "acme"` and restart server

#### ACME Certificate Renewal

Certificates are automatically renewed before expiration:
- Renewal attempted 30 days before expiry
- Server continues serving with existing cert during renewal
- No restart required - new cert loaded automatically
- Renewal failures logged; server continues with current cert
- Alerts can be configured via failure hooks

## Hosts File Generation

### Output Format

```
# Generated by router-hosts
# Last updated: 2025-12-01 15:30:00 UTC
# Entry count: 42

192.168.1.10    server.local
192.168.1.20    nas.local           # NAS storage [backup, homelab]
192.168.1.30    printer.local       # Office printer [iot]
2001:db8::1    ipv6-host.local
```

**Formatting rules:**
- Header with generation timestamp and entry count
- Entries sorted by IP address, then hostname (deterministic output)
- Comments appear inline after `#`
- Tags shown in brackets at end of comment: `[tag1, tag2]`
- Tab-separated columns for readability

**Edge cases:**
- Comments truncated at 200 characters (prevents line-length issues)
- Empty tags array: no bracket notation in output
- Newlines in comments: rejected during validation (single-line only)
- Hash characters in comments: escaped or rejected during validation

### Atomic Write Process

1. Generate content in memory from current database state
2. Write to `{hosts_file_path}.tmp`
3. `fsync()` the temp file to ensure durability
4. Atomic `rename()` to target path
5. On failure: temp file removed, original unchanged
6. Run success/failure hooks

This ensures the hosts file is never in a partial or corrupted state, even during power loss.

### Regeneration Triggers

The hosts file is regenerated after every successful write operation:
- `AddHost`
- `UpdateHost`
- `DeleteHost`
- `ImportHosts`
- `RollbackToSnapshot`

## Implementation Status

### Completed

| Component | Status | Notes |
|-----------|--------|-------|
| Event Store | Done | DuckDB with CQRS, optimistic concurrency |
| Projections | Done | Current state view, time-travel queries |
| Host CRUD | Done | Add/Get/Update/Delete with validation |
| List/Search | Done | Server streaming with filtering |
| Snapshots | Done | Create/List/Rollback/Delete |
| Hosts File Gen | Done | Atomic writes, sorted output |
| Hooks | Done | Success/failure with timeout |
| gRPC Service | Done | Host and snapshot RPCs wired |
| mTLS (manual certs) | Done | Mutual authentication required |
| Server Startup | Done | Graceful shutdown on SIGTERM/SIGINT |
| Basic Server Config | Done | TOML parsing for current features |

### Remaining for v0.5.0

| Component | Priority | Effort |
|-----------|----------|--------|
| Client CLI | High | Medium |
| Import/Export RPCs | High | Medium |
| ACME Support | Medium | Medium |
| Server Config (ACME) | Medium | Low |
| Snapshot Retention | Medium | Low |
| Container Image | Medium | Low |
| Systemd Unit | Low | Low |
| Proto cleanup (remove BulkAddHosts) | Low | Low |

### Out of Scope for v0.5.0

- Web UI
- Multi-server replication
- Role-based access control (beyond mTLS client identity)
- Scheduled snapshots (use cron + client CLI)

## Project Structure

### Workspace Layout

```
router-hosts/
├── Cargo.toml                    # Workspace root
├── proto/
│   └── router_hosts/v1/
│       └── hosts.proto           # gRPC service definitions
├── crates/
│   ├── router-hosts/             # Unified binary (client + server)
│   │   ├── src/
│   │   │   ├── main.rs           # Entry point, mode dispatch
│   │   │   ├── lib.rs            # Public API for tests
│   │   │   ├── client/           # Client CLI
│   │   │   │   ├── mod.rs
│   │   │   │   ├── config.rs
│   │   │   │   └── commands/     # Subcommand handlers
│   │   │   └── server/
│   │   │       ├── mod.rs        # Server startup, TLS
│   │   │       ├── config.rs     # Server config
│   │   │       ├── commands.rs   # Command handler layer
│   │   │       ├── hosts_file.rs # Hosts file generation
│   │   │       ├── hooks.rs      # Post-edit hooks
│   │   │       ├── db/           # Database layer
│   │   │       │   ├── mod.rs
│   │   │       │   ├── schema.rs
│   │   │       │   ├── events.rs
│   │   │       │   ├── event_store.rs
│   │   │       │   └── projections.rs
│   │   │       └── service/      # gRPC handlers
│   │   │           ├── mod.rs
│   │   │           ├── hosts.rs
│   │   │           ├── import_export.rs
│   │   │           └── snapshots.rs
│   │   └── tests/
│   │       └── integration_test.rs
│   └── router-hosts-common/      # Shared library
│       ├── src/
│       │   ├── lib.rs
│       │   ├── proto.rs          # Generated protobuf code
│       │   └── validation.rs     # IP/hostname validation
│       └── build.rs              # Protobuf code generation
└── docs/
    ├── plans/
    └── architecture/
```

### Binary Modes

Single binary with mode selection:
- `router-hosts server [OPTIONS]` - Run as server
- `router-hosts <command>` - Run as client (default)

## Security Considerations

### Authentication

- **mTLS required** - No fallback to insecure connections
- Client certificates validated against configured CA
- Each client identified by certificate CN/SAN

### Authorization

- v0.5.0: All authenticated clients have full access
- Future: Role-based access control via certificate attributes

### Data Protection

- TLS 1.3 for transport encryption
- DuckDB file should be on encrypted filesystem for data-at-rest
- Hosts file permissions managed by OS (typically root-owned)

### Operational Security

- `hosts_file_path` has no default - prevents accidental system file overwrites
- ACME credentials stored in separate file with restricted permissions
- Hook commands logged but secrets should be in environment/files, not config
