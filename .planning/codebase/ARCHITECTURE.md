<!-- refreshed: 2026-07-08 -->
# Architecture

**Analysis Date:** 2026-07-08

## System Overview

```text
┌─────────────────────────────────────────────────────────────┐
│                      Client Layer                            │
├──────────────────┬──────────────────┬───────────────────────┤
│   Cobra CLI      │   Bubble Tea TUI │   K8s Operator        │
│ `internal/       │ `internal/       │ `internal/operator`   │
│  client/commands`│  client/tui`     │ (controller-runtime)  │
└────────┬─────────┴────────┬─────────┴──────────┬────────────┘
         │                  │                     │
         └──────────────────┴─────────────────────┘
                            │  gRPC over mTLS
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    gRPC Server Layer                         │
│  `internal/server` — HostsServiceImpl, CommandHandler,       │
│  WriteQueue (serialized writes), file generators, hooks      │
└─────────────────────────────────────────────────────────────┘
         │                                    │
         ▼ (write side)                       ▼ (read side)
┌────────────────────────────┐   ┌────────────────────────────┐
│  EventStore (append)       │   │  HostProjection (replay)   │
│  SnapshotStore             │   │  point-in-time queries     │
└────────────┬───────────────┘   └────────────┬───────────────┘
             │                                 │
             ▼                                 ▼
┌─────────────────────────────────────────────────────────────┐
│  SQLite (pure-Go, zombiezen.com/go/sqlite)                   │
│  `internal/storage/sqlite` — event log + snapshots           │
└─────────────────────────────────────────────────────────────┘
             │
             ▼ (side effects on write)
┌─────────────────────────────────────────────────────────────┐
│  Output generators: hosts(5) file, dnsmasq.conf, unbound.conf│
│  + lifecycle hooks (on_success / on_failure)                 │
└─────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| CLI entrypoint | Main binary, delegates to Cobra | `cmd/router-hosts/main.go` |
| Operator entrypoint | K8s operator manager bootstrap | `cmd/operator/main.go` |
| Domain events | Event types, discriminators, envelopes | `internal/domain/events.go` |
| Host aggregate / read model | HostEntry projection, search filters | `internal/domain/host.go` |
| Snapshot model | Point-in-time snapshot types | `internal/domain/snapshot.go` |
| Storage interfaces | EventStore, SnapshotStore, HostProjection (CQRS contracts) | `internal/storage/storage.go` |
| SQLite event store | Append/load events, optimistic concurrency, compaction | `internal/storage/sqlite/eventstore.go` |
| SQLite projection | Replay events into read model, time-travel queries | `internal/storage/sqlite/projection.go` |
| gRPC service | Implements HostsService RPCs | `internal/server/service.go` |
| Command handler | Domain write logic via event sourcing | `internal/server/commands.go` |
| Write queue | Serializes concurrent writes through one goroutine | `internal/server/writequeue.go` |
| Server lifecycle | gRPC server, mTLS, cert hot-reload, graceful shutdown | `internal/server/server.go` |
| File generators | hosts / dnsmasq / unbound config emission | `internal/server/hostsfile.go`, `dnsmasqconf.go`, `unboundconf.go` |
| Hooks | on_success / on_failure command execution | `internal/server/hooks.go` |
| ACME | DNS-01 cert issuance/renewal via lego | `internal/acme/acme.go` |
| Operator controllers | Reconcile HostMapping / IngressRoute CRs | `internal/operator/*_controller.go` |

## Pattern Overview

**Overall:** CQRS + Event Sourcing over gRPC/mTLS, with a Kubernetes operator client.

**Key Characteristics:**

- Write side appends immutable domain events to a SQLite event log with per-aggregate optimistic concurrency (`expectedVersion`).
- Read side rebuilds `HostEntry` read models by replaying events (projection), supporting time-travel queries.
- All writes are serialized through a single-goroutine `WriteQueue` for application-level ordering; on success, output files (hosts/dnsmasq/unbound) are regenerated and lifecycle hooks fire.
- Aggregates are `ulid.ULID`-keyed; deleted entries become retained tombstones for idempotent replay.

## Layers

**Client:**

- Purpose: User + machine interfaces (CLI, TUI, K8s operator)
- Location: `internal/client`, `internal/operator`
- Depends on: generated gRPC stubs `api/v1/router_hosts/v1`
- Used by: end users, kubernetes

**Server:**

- Purpose: gRPC service, command handling, write serialization, output generation
- Location: `internal/server`
- Depends on: `internal/storage`, `internal/domain`, `internal/config`
- Used by: client layer over mTLS

**Domain:**

- Purpose: Event types, aggregate/read-model, validation, errors
- Location: `internal/domain`, `internal/validation`
- Depends on: nothing internal (leaf)
- Used by: server + storage

**Storage:**

- Purpose: Event/snapshot persistence and projection
- Location: `internal/storage`, `internal/storage/sqlite`
- Depends on: `internal/domain`, `zombiezen.com/go/sqlite`
- Used by: server

## Data Flow

### Write Path (e.g. AddHost)

1. Client sends RPC over mTLS (`internal/client/client.go`)
2. `HostsServiceImpl` receives RPC (`internal/server/service.go`)
3. `CommandHandler.submitWrite` routes through `WriteQueue` (`internal/server/commands.go`, `writequeue.go`)
4. Handler builds domain event, `EventStore.AppendEvents` with `expectedVersion` (`internal/storage/sqlite/eventstore.go`)
5. Output files regenerated from projection (`internal/server/hostsfile.go`)
6. Hooks fire on success/failure (`internal/server/hooks.go`)

### Read Path (e.g. ListHosts)

1. Client RPC → `HostsServiceImpl` (`internal/server/service.go`)
2. `Storage.ListAll` gathers aggregate IDs and replays events (`internal/storage/sqlite/projection.go`)
3. Tombstoned (`Deleted=true`) entries excluded from results

**State Management:**

- Authoritative state is the append-only event log; read models are derived and never mutated in place.

## Key Abstractions

**EventEnvelope:**

- Purpose: Event plus metadata (ID, timestamp, version) for storage/audit
- Examples: `internal/domain/events.go`
- Pattern: Tagged union via `EventType` discriminator (matches Rust serde tags for compatibility)

**Storage interfaces (EventStore / SnapshotStore / HostProjection):**

- Purpose: Decouple server from SQLite; enable testable CQRS boundaries
- Examples: `internal/storage/storage.go`, `internal/storage/storagetest/suite.go`
- Pattern: Interface + single SQLite implementation

**WriteQueue:**

- Purpose: Serialize concurrent writes
- Examples: `internal/server/writequeue.go`
- Pattern: Command channel processed by one goroutine

## Entry Points

**router-hosts CLI/server:**

- Location: `cmd/router-hosts/main.go` → `internal/client/commands.Execute()`
- Triggers: user invocation; `serve` subcommand starts the gRPC server (`internal/client/commands/serve.go`)
- Responsibilities: dispatch CLI subcommands or run the server

**operator:**

- Location: `cmd/operator/main.go`
- Triggers: Kubernetes deployment
- Responsibilities: run controller-runtime manager, reconcile HostMapping/IngressRoute, push to gRPC server

## Architectural Constraints

- **Threading:** Writes are serialized by `WriteQueue` (single goroutine); reads may run concurrently. Entropy generation guarded by mutex in `CommandHandler`.
- **Global state:** `commands.Flags` is a package-level singleton for Cobra global flags (`internal/client/commands/root.go`); `Version`/`Commit` set via ldflags.
- **Concurrency control:** Per-aggregate optimistic concurrency via `expectedVersion`; storage is SQLite (single-writer semantics).
- **No CGo:** SQLite via pure-Go `zombiezen.com/go/sqlite` (modernc backend).

## Anti-Patterns

### Mutating read models directly

**What happens:** Treating `HostEntry` as the source of truth and editing it.
**Why it's wrong:** Read models are projections; the event log is authoritative. Direct mutation breaks replay/time-travel.
**Do this instead:** Append a domain event via `CommandHandler`; let the projection rebuild (`internal/storage/sqlite/projection.go`).

### Bypassing the write queue

**What happens:** Calling `EventStore.AppendEvents` directly from a read path or outside the handler.
**Why it's wrong:** Loses write serialization and file-regeneration/hook side effects.
**Do this instead:** Route writes through `CommandHandler.submitWrite` (`internal/server/commands.go`).

## Error Handling

**Strategy:** Structured errors via `samber/oops` with domain error codes; wrap with context.

**Patterns:**

- `oops.Wrapf(err, "doing X")` at boundaries
- Domain codes (`domain.CodeValidation`, etc.) mapped to gRPC status codes in the service layer
- No `log.Fatal`/`os.Exit` in library code (only in `main`)

## Cross-Cutting Concerns

**Logging:** `log/slog` structured logging; bridged to `logr` for controller-runtime in the operator.
**Validation:** Centralized in `internal/validation` (IP, hostname, alias) plus domain-level `SearchFilter.Validate`.
**Metrics:** OpenTelemetry via `internal/server/metrics.go` (OTLP gRPC exporter).
**Authentication:** mTLS with client-cert verification and server cert hot-reload (`internal/server/server.go`).

---

*Architecture analysis: 2026-07-08*
