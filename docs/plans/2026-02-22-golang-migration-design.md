# router-hosts Go Migration Design

**Date:** 2026-02-22
**Status:** Draft
**Supersedes:** Rust implementation (v0.8.14)

## Overview

Full migration of router-hosts from Rust to Go. The Go version preserves core
functionality (event sourcing, gRPC/mTLS, host CRUD, snapshots, hosts file
generation, K8s operator, ACME DNS-01) while simplifying the storage layer to
SQLite-only and adopting Go-idiomatic patterns.

### Motivation

- **Ecosystem alignment:** Go's K8s ecosystem (kubebuilder, controller-runtime)
  is a natural fit for the operator. gRPC and mTLS are first-class in Go.
- **Simplification:** Drop multi-backend storage (PostgreSQL, DuckDB). Pure Go
  SQLite via modernc.org eliminates CGo.
- **Maintainability:** Lower barrier for contributors, simpler toolchain.
- **Build & deploy:** Fast compilation, trivial cross-compilation, small static
  binaries.

### Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Storage | SQLite only (modernc.org, no CGo) | Simplicity, embedded, portable |
| Data model | Event sourcing + CQRS (preserved) | Audit trail, time-travel, proven model |
| Proto API | Revise slightly (same RPCs, clean messages) | Wire compat not required |
| CLI framework | Cobra + Bubble Tea + Lip Gloss | Interactive TUI, styled output |
| Error handling | samber/oops with codes | Structured errors, gRPC status mapping |
| ACME | lego with Cloudflare DNS-01 | Built-in provider support |
| K8s operator | kubebuilder + controller-runtime | Standard Go operator pattern |
| Logging | log/slog (stdlib) | Structured, zero-dependency |
| Metrics | OpenTelemetry (same metric names) | Dashboard compatibility |

## Project Layout

```text
router-hosts/
├── proto/router_hosts/v1/
│   └── hosts.proto              # Revised proto definitions
├── buf.gen.yaml                 # buf generate config
├── buf.yaml                     # buf module config
├── cmd/
│   ├── router-hosts/main.go     # Server + Client binary
│   └── operator/main.go         # K8s operator binary
├── api/v1/                      # Generated Go protobuf + gRPC stubs
├── internal/
│   ├── domain/
│   │   ├── events.go            # Domain events (7 event types)
│   │   ├── host.go              # Host aggregate + projection logic
│   │   └── snapshot.go          # Snapshot types
│   ├── storage/
│   │   ├── storage.go           # Storage interface (EventStore + SnapshotStore + HostProjection)
│   │   ├── sqlite/
│   │   │   ├── sqlite.go        # SQLite implementation
│   │   │   ├── migrations/      # SQL migration files (embedded)
│   │   │   └── queries/         # SQL query files
│   │   └── storage_test.go      # Shared compliance test suite
│   ├── server/
│   │   ├── server.go            # gRPC server + mTLS setup + signal handling
│   │   ├── service.go           # HostsService gRPC implementation
│   │   ├── commands.go          # Domain command handler
│   │   ├── hostsfile.go         # Atomic hosts file writer
│   │   ├── hooks.go             # Post-edit hook runner
│   │   ├── writequeue.go        # Channel-based write serialization
│   │   └── metrics.go           # OpenTelemetry metrics + interceptors
│   ├── client/
│   │   ├── client.go            # gRPC client wrapper with mTLS
│   │   ├── commands/            # Cobra command handlers
│   │   ├── tui/                 # Bubble Tea models (progress, conflict, tables)
│   │   └── output/              # Lip Gloss formatters + JSON/CSV raw output
│   ├── validation/
│   │   └── validation.go        # IP + hostname + alias validation
│   ├── config/
│   │   ├── server.go            # Server TOML config
│   │   └── client.go            # Client TOML config + precedence
│   └── acme/
│       └── acme.go              # lego wrapper for DNS-01/Cloudflare + renewal
├── operator/
│   ├── api/v1alpha1/            # CRD types (kubebuilder generated)
│   ├── controllers/             # Reconcilers (IngressRoute, HostMapping)
│   └── config/                  # RBAC, manager, webhook config
├── e2e/                         # Docker-based E2E tests with real mTLS
├── Taskfile.yml                 # Task runner commands
├── Dockerfile                   # Multi-stage build (distroless base)
├── .goreleaser.yml              # Release automation
├── .golangci.yml                # Linter config
├── go.mod
└── go.sum
```

## Dependencies

| Purpose | Library | Notes |
|---------|---------|-------|
| gRPC server/client | `google.golang.org/grpc` | Standard Go gRPC |
| Protobuf | `google.golang.org/protobuf` | Standard Go protobuf runtime |
| Proto generation | `buf` CLI | Already used in Rust project |
| CLI routing | `github.com/spf13/cobra` | Command/subcommand structure |
| TUI framework | `github.com/charmbracelet/bubbletea` | Interactive terminal UI |
| TUI components | `github.com/charmbracelet/bubbles` | Table, spinner, progress, text input |
| TUI styling | `github.com/charmbracelet/lipgloss` | Colors, borders, padding |
| Config (TOML) | `github.com/pelletier/go-toml/v2` | Maintains config file compat |
| SQLite | `modernc.org/sqlite` | Pure Go, no CGo |
| SQLite driver | `zombiezen.com/go/sqlite` | Higher-level API over modernc |
| Error handling | `github.com/samber/oops` | Structured errors with codes |
| ACME | `github.com/go-acme/lego/v4` | DNS-01 + Cloudflare built-in |
| TLS | `crypto/tls` (stdlib) | mTLS, cert reload |
| OpenTelemetry | `go.opentelemetry.io/otel` | Metrics + traces via OTLP |
| Logging | `log/slog` (stdlib) | Structured logging |
| K8s operator | `sigs.k8s.io/controller-runtime` | kubebuilder ecosystem |
| ULID | `github.com/oklog/ulid/v2` | Same ID format as Rust version |
| Testing | `github.com/stretchr/testify` | Assertions + test suites |
| Property testing | `pgregory.net/rapid` | Go property-based testing |

## Domain Model

### Events

Seven domain event types (same as Rust):

| Event | Payload | Description |
|-------|---------|-------------|
| `HostCreated` | ip, hostname, aliases, comment, tags | New entry |
| `IpAddressChanged` | old_ip, new_ip | IP modification |
| `HostnameChanged` | old_hostname, new_hostname | Hostname modification |
| `CommentUpdated` | old_comment, new_comment | Comment change |
| `TagsModified` | old_tags, new_tags | Tags change |
| `AliasesModified` | old_aliases, new_aliases | Aliases change |
| `HostDeleted` | ip, hostname, reason | Tombstone event |

Events are serialized as JSON in the SQLite `events` table with ULID-based
event IDs and aggregate IDs.

### Host Aggregate

```go
type HostEntry struct {
    ID        ulid.ULID
    IP        string
    Hostname  string
    Aliases   []string
    Comment   string
    Tags      []string
    Version   int64
    CreatedAt time.Time
    UpdatedAt time.Time
    Deleted   bool
}
```

Reconstructed from events by replaying the event log for an aggregate ID.

### Optimistic Concurrency

Same model as Rust:

- Each aggregate has a monotonic version counter
- `AppendEvent` requires `expectedVersion` parameter
- Version mismatch returns `oops.Code("version_conflict")` error
- gRPC layer maps to `codes.Aborted`
- CLI presents interactive conflict resolution via Bubble Tea

## Storage Interface

```go
type EventStore interface {
    AppendEvent(ctx context.Context, aggregateID ulid.ULID, event Event, expectedVersion int64) error
    AppendEvents(ctx context.Context, events []Event) error
    LoadEvents(ctx context.Context, aggregateID ulid.ULID) ([]Event, error)
    GetCurrentVersion(ctx context.Context, aggregateID ulid.ULID) (int64, error)
    CountEvents(ctx context.Context) (int64, error)
}

type SnapshotStore interface {
    SaveSnapshot(ctx context.Context, snapshot Snapshot) error
    GetSnapshot(ctx context.Context, id ulid.ULID) (*Snapshot, error)
    ListSnapshots(ctx context.Context) ([]Snapshot, error)
    DeleteSnapshot(ctx context.Context, id ulid.ULID) error
    ApplyRetentionPolicy(ctx context.Context, maxCount int, maxAgeDays int) error
}

type HostProjection interface {
    ListAll(ctx context.Context) ([]HostEntry, error)
    GetByID(ctx context.Context, id ulid.ULID) (*HostEntry, error)
    FindByIPAndHostname(ctx context.Context, ip, hostname string) (*HostEntry, error)
    Search(ctx context.Context, filter SearchFilter) ([]HostEntry, error)
    GetAtTime(ctx context.Context, at time.Time) ([]HostEntry, error)
}

type Storage interface {
    EventStore
    SnapshotStore
    HostProjection
    Initialize(ctx context.Context) error
    HealthCheck(ctx context.Context) error
    Close() error
    BackendName() string
}
```

Single implementation: `sqlite.Storage` in `internal/storage/sqlite/`.

Shared test suite in `internal/storage/storage_test.go` validates any
`Storage` implementation (42+ test cases matching Rust compliance suite).

## Error Handling

Using `samber/oops` with string codes mapped to gRPC status:

| oops Code | gRPC Status | When |
|-----------|-------------|------|
| `version_conflict` | `Aborted` | Optimistic concurrency violation |
| `not_found` | `NotFound` | Missing host/snapshot |
| `duplicate_entry` | `AlreadyExists` | Duplicate IP+hostname |
| `validation_failed` | `InvalidArgument` | Invalid input |
| (default) | `Internal` | Unexpected errors |

Error builder helpers in `internal/domain/` provide consistent error
construction with context metadata (entity type, IDs, etc.).

## Server Architecture

### gRPC + mTLS

- `crypto/tls` with `tls.RequireAndVerifyClientCert`
- TLS cert reload on SIGHUP via `tls.Config.GetCertificate` callback
- Graceful shutdown on SIGTERM/SIGINT with 30-second drain timeout
- `grpc.UnaryInterceptor` / `grpc.StreamInterceptor` for OTel metrics

### Write Queue

Channel-based serialization replacing Rust's `tokio::sync::mpsc`:

- Single goroutine processes write commands from a buffered channel
- Callers send command structs with embedded response channels
- Maintains event ordering and prevents race conditions

### Hosts File Generation

Atomic write pattern (same as Rust):

1. Generate content from current projection
2. Write to `{path}.tmp`
3. `fsync` temp file
4. `os.Rename` to target path
5. Run success/failure hooks

Output format: header comment, sorted by IP then hostname, aliases on same
line, comments inline, tags in brackets.

### Post-edit Hooks

- `os/exec.CommandContext` with configurable timeout (default 30s)
- Environment variables: `ROUTER_HOSTS_EVENT`, `ROUTER_HOSTS_ENTRY_COUNT`,
  `ROUTER_HOSTS_ERROR`
- Sequential execution, failures logged but don't fail the operation

### ACME Certificate Management

Using `lego` library:

- DNS-01 challenge with Cloudflare provider
- Background goroutine for automatic renewal (30 days before expiry)
- Hot-swap via `tls.Config.GetCertificate` (no restart needed)
- Config in server TOML under `[tls.acme]` section

### OpenTelemetry

Same metric names as Rust version for Grafana dashboard compatibility:

- `router_hosts_requests_total` (counter)
- `router_hosts_request_duration_seconds` (histogram)
- `router_hosts_storage_operations_total` (counter)
- `router_hosts_storage_duration_seconds` (histogram)
- `router_hosts_hosts_entries` (gauge)
- `router_hosts_hook_executions_total` (counter)
- `router_hosts_hook_duration_seconds` (histogram)

OTLP/gRPC exporter to collector.

## Client CLI

### Architecture

- **Cobra** for command routing and flag parsing
- **Bubble Tea** for interactive TUI experiences:
  - Version conflict resolution (diff display + prompt)
  - Import progress bar with streaming updates
  - Interactive search/filter
- **Bubbles** for reusable components:
  - Table rendering for `host list`, `snapshot list`
  - Spinner for long-running operations
  - Text input for interactive prompts
- **Lip Gloss** for styled output:
  - Colored status indicators
  - Formatted error messages
  - Styled headers and borders

### Non-interactive Mode

When `--quiet`, `--format json`, or `--format csv` is specified, or when
stdout is not a TTY:

- Bypass Bubble Tea entirely
- Emit raw structured output (JSON/CSV)
- Pipe-friendly for scripting

### Command Structure

```text
router-hosts [global flags] <command> <subcommand>

Global flags:
  -s, --server <ADDRESS>    Server address (host:port)
  -c, --config <PATH>       Config file path
      --cert <PATH>         Client certificate
      --key <PATH>          Client key
      --ca <PATH>           CA certificate
  -v, --verbose             Verbose output
  -q, --quiet               Suppress non-error output
      --format <FORMAT>     Output format: table, json, csv [default: table]

Commands:
  server                    Start the server
  host add                  Add a new host entry
  host get                  Get by ID
  host update               Update a host entry
  host delete               Delete a host entry
  host list                 List all hosts
  host search               Search hosts
  host import               Import from file
  host export               Export to file
  snapshot create           Create snapshot
  snapshot list             List snapshots
  snapshot rollback         Rollback to snapshot
  snapshot delete           Delete snapshot
  config show               Show effective config
```

### Configuration Precedence

CLI arguments > Environment variables > Config file

Same env vars as Rust: `ROUTER_HOSTS_SERVER`, `ROUTER_HOSTS_CERT`,
`ROUTER_HOSTS_KEY`, `ROUTER_HOSTS_CA`.

Config file: `~/.config/router-hosts/client.toml`

## Kubernetes Operator

### Architecture

kubebuilder-generated operator with controller-runtime:

- **Watched resources:**
  - Traefik `IngressRoute` CRD
  - Traefik `IngressRouteTCP` CRD
  - Custom `HostMapping` CRD (for manual entries)
- **Reconciler:** Syncs host entries with router-hosts server via gRPC client
- **Leader election** for HA multi-replica deployments
- **Health endpoints:** `/healthz` (liveness), `/readyz` (readiness)

### CRD: HostMapping

```yaml
apiVersion: router-hosts.fzymgc.house/v1alpha1
kind: HostMapping
metadata:
  name: my-service
spec:
  ip: 192.168.1.10
  hostname: my-service.local
  aliases:
    - svc
    - my-svc
  tags:
    - kubernetes
    - production
```

## Proto API Revisions

Keep the same 14 RPCs. Revisions from Rust version:

- Clean up field names where Go protoc-gen-go naming improves readability
- Remove any discovered unused fields
- Ensure `aliases` field present consistently across relevant messages
- Update package path if needed for Go import conventions
- Accept this as a breaking wire-protocol change (new major version)

## Validation

Same rules as Rust, ported to Go:

- **IP:** `net.ParseIP()` for IPv4/IPv6
- **Hostname:** RFC 1035 compliant (1-253 chars, labels 1-63 chars,
  alphanumeric + hyphens, no leading/trailing hyphen)
- **Aliases:** Same as hostname rules, no duplicate of canonical hostname,
  case-insensitive dedup, max 50 per entry

## Testing Strategy

| Layer | Approach | Coverage target |
|-------|----------|-----------------|
| Validation | Table-driven + `rapid` property tests | High |
| Storage | Shared compliance suite, in-memory SQLite | High |
| Domain | Event replay, aggregate reconstruction | High |
| Server/service | `bufconn` in-process gRPC tests | Medium-high |
| Client commands | Mock gRPC client, output assertions | Medium |
| TUI | Bubble Tea test mode (programmatic input) | Medium |
| E2E | Docker + real mTLS (same as Rust) | Integration |
| Operator | envtest (kubebuilder framework) | Medium |

**Overall target:** ≥80% coverage (same as Rust).

## CI/CD

| Workflow | Tool | Notes |
|----------|------|-------|
| Build & test | GitHub Actions, `go test ./...` | Matrix: linux, darwin |
| Lint | `golangci-lint` | Configured via `.golangci.yml` |
| Proto | `buf generate` + `buf lint` + `buf breaking` | Same as current |
| Release | GoReleaser | Replaces cargo-dist |
| Container | Multi-stage Dockerfile, distroless base | `gcr.io/distroless/static` |
| Helm | Same chart, updated image references | |
| Version mgmt | release-please | Same as current |
| Coverage | `go test -coverprofile` + codecov | 80% threshold |

## What's Dropped

| Feature | Reason |
|---------|--------|
| PostgreSQL backend | Simplification — SQLite covers all use cases |
| DuckDB backend | Simplification — was already a separate binary |
| `router-hosts-duckdb` binary | No DuckDB backend |
| Rust-specific patterns | Replaced with Go idioms |

## Migration Strategy

This is a full rewrite, not an incremental port. The Go version will:

1. Live in the same repository (new branch or clean main after archival)
2. Reuse the `proto/` directory (with revisions)
3. Reuse deployment configs (Helm charts, Dockerfiles — adapted)
4. Target the same infrastructure (K8s, same cert management)
5. Maintain the same metric names for Grafana compatibility

The Rust codebase will be archived (tagged release, archived branch) before
the Go implementation begins on `main`.
