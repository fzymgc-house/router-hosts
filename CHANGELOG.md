# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2025-12-30

### Breaking Changes

#### Hook configuration now requires structured definitions

Hooks now require both a `name` and `command` field. The hook name provides a stable identifier for logging, metrics, and health endpoints without exposing command details.

**Old format (no longer supported):**
```toml
[[hooks.on_success]]
command = "systemctl reload dnsmasq"
```

**New format:**
```toml
[[hooks.on_success]]
name = "reload-dns"
command = "systemctl reload dnsmasq"
```

**Name requirements:**
- Kebab-case only (lowercase letters, numbers, hyphens)
- Maximum 50 characters
- Must be unique within each hook type

### Added

#### Kubernetes Operator (#152)

New `router-hosts-operator` crate provides automated DNS registration for Kubernetes workloads:

- **Resource watching**: IngressRoute, IngressRouteTCP (Traefik), and custom HostMapping CRD
- **Automatic sync**: Creates/updates/deletes host entries based on resource state
- **IP resolution**: Discovers IPs from ingress controller Services or static configuration
- **Graceful deletion**: Configurable grace period before removing entries
- **Helm chart**: Full deployment with RBAC, health probes, and configuration

See [Operator Documentation](docs/operator.md) for details.

#### Health Endpoints (#158, #164)

- **Server**: gRPC health RPCs (`Liveness`, `Readiness`, `Health`) for monitoring and probes
- **Operator**: HTTP `/healthz` (liveness) and `/readyz` (readiness) endpoints
- Readiness probes verify database/server connectivity

#### Prometheus Metrics (#170)

Server-side observability with Prometheus metrics:

- `router_hosts_requests_total` - gRPC request counter by method/status
- `router_hosts_request_duration_seconds` - Request latency histogram
- `router_hosts_storage_operations_total` - Storage operation counter
- `router_hosts_storage_duration_seconds` - Storage operation latency
- `router_hosts_hook_executions_total` - Hook execution counter
- `router_hosts_hook_duration_seconds` - Hook execution latency
- `router_hosts_hosts_entries` - Current host entry gauge

Configure via `[metrics]` section in server config.

#### Leader Election for Operator HA (#171)

Run multiple operator replicas for high availability:

- Kubernetes Lease-based leader election
- Only one active replica reconciles at a time
- Automatic failover on leader failure
- Zero-downtime rolling updates
- Auto-enabled when `replicaCount >= 2`

### Changed

- **Docker images**: Version tags added on release (e.g., `v0.7.0`) in addition to SHA tags (#151)
- **cargo-dist**: Updated to v0.30.3 for release workflow (#173)

### Fixed

- Operator test assertions improved for clarity (#174)

## [0.6.0] - 2025-12-24

### Breaking Changes

#### API: UpdateHostRequest tags field changed to wrapper message

The `UpdateHostRequest.tags` field changed from `repeated string tags` to `TagsUpdate tags` wrapper message. This enables proper optional semantics for update operations.

**Migration:**
- Wrap tag updates: `TagsUpdate { values: ["tag1", "tag2"] }`
- Clear tags: `TagsUpdate { values: [] }`
- Preserve tags: Omit the `tags` field entirely

#### CSV Import/Export format change

The CSV format has changed to include an `aliases` column:

**Old format:**
```csv
ip_address,hostname,comment,tags
```

**New format:**
```csv
ip_address,hostname,aliases,comment,tags
```

**Format details:**
- **Aliases**: Multiple aliases separated by semicolons (`;`) e.g., `srv;web;api`
- **Tags**: Multiple tags separated by semicolons (`;`) e.g., `prod;web`
- Semicolons avoid conflicts with CSV comma delimiters and don't require quoting

**Example:**
```csv
ip_address,hostname,aliases,comment,tags
192.168.1.10,server.local,srv;web,Main server,prod;web
192.168.1.20,db.local,,Database,prod;db
```

**Migration:**
- Legacy CSV files (4-column format) are now **rejected** with a clear error message
- Update CSV files to include the `aliases` column (can be empty)
- Re-export existing data with `router-hosts host export --export-format csv`

**Validation changes:**
- Aliases cannot be IP addresses (e.g., `192.168.1.1` as alias is rejected)
- Maximum 50 aliases per host entry (prevents resource exhaustion)

#### Default storage backend changed from DuckDB to SQLite

The default storage backend is now SQLite instead of DuckDB. This significantly reduces binary size and compilation time.

**Migration:**
- Existing DuckDB databases are **not** automatically migrated
- To continue using DuckDB, install the `router-hosts-duckdb` binary variant
- New installations use SQLite by default with XDG-compliant paths:
  - Linux: `~/.local/share/router-hosts/hosts.db`
  - macOS: `~/Library/Application Support/router-hosts/hosts.db`
  - Windows: `C:\Users\<user>\AppData\Roaming\router-hosts\hosts.db`

**New binaries:**
- `router-hosts` - Standard binary with SQLite + PostgreSQL backends
- `router-hosts-duckdb` - Variant binary with all three backends (DuckDB, SQLite, PostgreSQL)

### Added

- **Hostname aliases support**: Full hosts(5) alias support per Unix standard
  - Parse and output multiple hostnames per IP address (canonical + aliases)
  - CLI flags: `--alias` (repeatable), `--clear-aliases`, `--clear-tags`
  - Search matches both canonical hostname and aliases
  - Import/Export support in hosts, JSON, and CSV formats
  - Aliases sorted alphabetically in output for deterministic results
- **Import --force flag**: Override strict mode alias conflict checks
- Automated multi-platform binary releases via cargo-dist (#93)
- Shell installer script for quick installation
- Homebrew formula generation for macOS/Linux
- GitHub attestations for supply chain security
- cargo-auditable integration for dependency auditing
- Release verification script (`scripts/verify-release.sh`)

### Changed

- Release workflow now uses cargo-dist instead of manual builds

## [0.5.0] - 2025-12-10

### Breaking Changes

#### CLI: Import/Export format argument renamed (#76, fixes #69)

The `--format` argument for `host import` and `host export` commands has been renamed to avoid conflict with the global output format option.

**Migration:**
- `host import --format <fmt>` → `host import --input-format <fmt>`
- `host export --format <fmt>` → `host export --export-format <fmt>`

**Note:** These commands were previously broken (panicked on all invocations due to clap type conflicts), so this fix enables functionality rather than breaking existing usage.

### Added

#### Core Features
- **Event-sourced storage**: DuckDB-based CQRS event store for all state changes
- **Host management**: Full CRUD operations (Add/Get/Update/Delete/List/Search) via gRPC
- **Snapshot system**: Create/List/Rollback/Delete snapshots with retention policy
- **Import/Export**: Bidirectional streaming with multiple formats (hosts, JSON, CSV)
- **Client CLI**: Complete command-line interface with all operations
- **mTLS authentication**: Mutual TLS with client certificate verification
- **Hosts file generation**: Atomic writes with post-edit hooks

#### Advanced Functionality
- **ULID versioning**: Time-ordered, globally unique event identifiers
- **Optimistic concurrency**: Version checking to prevent lost updates
- **Interactive conflict resolution**: CLI diff display with retry workflow
- **Snapshot retention**: Configurable max_snapshots and max_age enforcement
- **Rollback with backup**: Automatic pre-rollback snapshot creation
- **Conflict modes**: Skip/replace/strict modes for import operations

#### Testing & Quality
- **E2E test suite**: 8 comprehensive acceptance tests with Docker/testcontainers
- **Integration tests**: Full gRPC workflow coverage with mTLS
- **Unit tests**: Extensive coverage of core logic and edge cases

### Changed

- **Client mode detection**: Server runs when first argument is "server", otherwise client mode
- **Streaming APIs**: All multi-item operations use gRPC streaming (not arrays)
- **Request/response types**: Dedicated message types for all RPC methods
- **Atomic updates**: Generate to temp file → fsync → atomic rename

### Fixed

- CLI format argument type conflicts (#69)
- JSON output missing 'id' field for host operations (#70)
- Snapshot create --format json returning empty output (#71)
- SQL view not properly merging partial metadata updates (#35)
- Integration tests hanging due to gRPC connection issues (#12)

### Security

- **Mandatory TLS**: No fallback to insecure connections
- **Client certificate validation**: Server validates against configured CA
- **Secure temp file handling**: Atomic operations prevent partial writes

## Implementation Details

### Architecture Decisions

- **Event sourcing**: Complete audit trail and time-travel queries
- **CQRS pattern**: Separation of command and query responsibilities
- **Streaming first**: Better memory efficiency and flow control
- **No bare parameters**: All RPC methods use dedicated request/response types

### Database

- DuckDB embedded database (single file, no daemon)
- In-memory for tests, persistent for production
- Complete event log with current state views

### Compatibility Notes

This is the initial release. Future versions will maintain backward compatibility for:
- gRPC API contracts
- Event store schema
- Configuration file format
- CLI command structure

### Known Limitations

- No automatic certificate management (ACME support planned)
- No event store compaction (monitoring planned)
- Single-node only (no distributed mode)

### Migration Notes

N/A - Initial release

---

[Unreleased]: https://github.com/fzymgc-house/router-hosts/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/fzymgc-house/router-hosts/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/fzymgc-house/router-hosts/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/fzymgc-house/router-hosts/releases/tag/v0.5.0
