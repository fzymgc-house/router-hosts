# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.9](https://github.com/fzymgc-house/router-hosts/compare/v0.8.8...v0.8.9) (2026-01-01)


### Features

* **server:** add access logging for gRPC operations ([#217](https://github.com/fzymgc-house/router-hosts/issues/217)) ([d6c8dc7](https://github.com/fzymgc-house/router-hosts/commit/d6c8dc734bccaf28ce04a01e0ab0ddd37bf1a4c8))


### Documentation

* archive completed mkdocs site plans ([#221](https://github.com/fzymgc-house/router-hosts/issues/221)) ([c977954](https://github.com/fzymgc-house/router-hosts/commit/c977954f822d98e9351d56d04ff0b59e0c32667a))

## [0.8.8](https://github.com/fzymgc-house/router-hosts/compare/v0.8.7...v0.8.8) (2026-01-01)


### Bug Fixes

* **ci:** add --branch=main for Cloudflare Pages production deploy ([#213](https://github.com/fzymgc-house/router-hosts/issues/213)) ([4e5df03](https://github.com/fzymgc-house/router-hosts/commit/4e5df032a2e24c151a828e2c548b8ba3fc9481e8))

## [0.8.7](https://github.com/fzymgc-house/router-hosts/compare/v0.8.6...v0.8.7) (2026-01-01)


### Bug Fixes

* **ci:** extract tarball with --strip-components to fix docs deployment ([#209](https://github.com/fzymgc-house/router-hosts/issues/209)) ([6cf4ac7](https://github.com/fzymgc-house/router-hosts/commit/6cf4ac7a96179a73dab648af2bf78d8a21d3be91))
* **operator:** bind health server to 0.0.0.0 for Kubernetes probes ([#212](https://github.com/fzymgc-house/router-hosts/issues/212)) ([a3e1c5f](https://github.com/fzymgc-house/router-hosts/commit/a3e1c5f0e128aaaf705d5dc5a95360eac21dc250))

## [0.8.6](https://github.com/fzymgc-house/router-hosts/compare/v0.8.5...v0.8.6) (2026-01-01)


### Bug Fixes

* **ci:** use create-release=false for release-please compatibility ([#207](https://github.com/fzymgc-house/router-hosts/issues/207)) ([fb46c4d](https://github.com/fzymgc-house/router-hosts/commit/fb46c4dab9616eefbe631a0fff3fe86553a4f118))

## [0.8.5](https://github.com/fzymgc-house/router-hosts/compare/v0.8.4...v0.8.5) (2026-01-01)


### Bug Fixes

* bump version ([#205](https://github.com/fzymgc-house/router-hosts/issues/205)) ([c4ebd86](https://github.com/fzymgc-house/router-hosts/commit/c4ebd8678412ea06843421f59f4111a3102bf992))
* **ci:** regenerate v-release.yml for cargo-dist compatibility ([#204](https://github.com/fzymgc-house/router-hosts/issues/204)) ([7e3cac7](https://github.com/fzymgc-house/router-hosts/commit/7e3cac793947f620b7877598a04011066230e306))

## [0.8.4](https://github.com/fzymgc-house/router-hosts/compare/v0.8.3...v0.8.4) (2026-01-01)


### Bug Fixes

* **ci:** trigger docs deploy after v-release completes ([#202](https://github.com/fzymgc-house/router-hosts/issues/202)) ([5ef7fdb](https://github.com/fzymgc-house/router-hosts/commit/5ef7fdb545bd573f63e4b2d1c8ad4732fefc9b29))

## [0.8.3](https://github.com/fzymgc-house/router-hosts/compare/v0.8.2...v0.8.3) (2025-12-31)


### Bug Fixes

* **ci:** use valid github-release value in dist config ([#200](https://github.com/fzymgc-house/router-hosts/issues/200)) ([7cc425f](https://github.com/fzymgc-house/router-hosts/commit/7cc425f69762a916f24a350d00ee2217a51cee45))

## [0.8.2](https://github.com/fzymgc-house/router-hosts/compare/v0.8.1...v0.8.2) (2025-12-31)


### Bug Fixes

* **ci:** enable GitHub Release creation for tag pushing ([#198](https://github.com/fzymgc-house/router-hosts/issues/198)) ([66d1700](https://github.com/fzymgc-house/router-hosts/commit/66d1700ecd49d039ea05fb908521051909f3dceb))

## [0.8.1](https://github.com/fzymgc-house/router-hosts/compare/v0.8.0...v0.8.1) (2025-12-31)


### Features

* **ci:** add release-plz automation for versioning and releases ([#194](https://github.com/fzymgc-house/router-hosts/issues/194)) ([fa098c1](https://github.com/fzymgc-house/router-hosts/commit/fa098c17fe7be2df2182ee7ba69858cd26eff79b))


### Bug Fixes

* **ci:** use simple release-type for Cargo workspace ([#196](https://github.com/fzymgc-house/router-hosts/issues/196)) ([bde89a0](https://github.com/fzymgc-house/router-hosts/commit/bde89a050173ed1d36c497f7aed7155836e8635a))
* **operator:** install rustls crypto provider on startup ([#193](https://github.com/fzymgc-house/router-hosts/issues/193)) ([d256a5e](https://github.com/fzymgc-house/router-hosts/commit/d256a5e1d67a4a1517755a4acd5ac27203916b15))


### Documentation

* create MkDocs Material documentation site ([#191](https://github.com/fzymgc-house/router-hosts/issues/191)) ([e7231f2](https://github.com/fzymgc-house/router-hosts/commit/e7231f2e810fb8431ff441e29f4c4bd4aaa383f8))


### Build System

* **ci:** migrate from release-plz to release-please ([#195](https://github.com/fzymgc-house/router-hosts/issues/195)) ([2623ca1](https://github.com/fzymgc-house/router-hosts/commit/2623ca1a8154050461efb210147336cb2b499e34))


### CI/CD

* **ghcr:** disable dry-run mode for image cleanup ([#189](https://github.com/fzymgc-house/router-hosts/issues/189)) ([7c6f9e1](https://github.com/fzymgc-house/router-hosts/commit/7c6f9e1e6edf5678e7be650acde9408867888149))

## [Unreleased]

## [0.8.0] - 2025-12-30

### Added

- **XDG config auto-discovery**: Client now automatically searches for config files in XDG-compliant locations (`~/.config/router-hosts/`, `/etc/router-hosts/`) when no explicit config is provided

### Changed

- **CI/CD improvements**: Optimized build parallelization and added Helm chart OCI registry publishing workflow

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
