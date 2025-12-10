# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2025-12-10

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

**Full Changelog**: https://github.com/fzymgc-house/router-hosts/commits/v0.5.0
