# Codebase Structure

**Analysis Date:** 2026-07-08

## Directory Layout

```text
router-hosts/
├── cmd/
│   ├── router-hosts/       # CLI + server main binary
│   └── operator/           # Kubernetes operator main binary
├── internal/
│   ├── domain/             # Event types, host aggregate, snapshots, errors
│   ├── validation/         # IP/hostname/alias validators
│   ├── storage/            # Storage interfaces (CQRS contracts)
│   │   ├── sqlite/         # Pure-Go SQLite implementation + migrations
│   │   └── storagetest/    # Shared storage conformance test suite
│   ├── config/             # Server + client TOML config loaders
│   ├── server/             # gRPC server, commands, write queue, generators, hooks, metrics
│   ├── client/             # gRPC client wrapper (mTLS)
│   │   ├── commands/       # Cobra CLI subcommands
│   │   ├── tui/            # Bubble Tea interactive TUI
│   │   └── output/         # Output formatters (table/json/csv)
│   ├── acme/               # ACME DNS-01 cert management (lego)
│   └── operator/           # K8s controllers (HostMapping, IngressRoute)
├── api/
│   ├── v1/router_hosts/v1/ # Generated gRPC protobuf stubs
│   └── operator/v1alpha1/  # Operator CRD Go types + deepcopy
├── proto/router_hosts/v1/  # Protobuf source definitions
├── charts/                 # Helm chart for the operator
├── e2e/                    # E2E tests (build tags: e2e, docker_e2e)
├── docs/                   # Architecture, guides, ADRs, plans
├── examples/               # Example configs
├── scripts/                # Helper scripts
├── certs/                  # Local dev certificates
├── Taskfile.yml            # Task runner (build/test/lint/proto)
├── buf.yaml / buf.gen.yaml # Protobuf lint + codegen config
├── go.mod                  # Go module (go 1.26)
└── .goreleaser.yml         # Release build config
```

## Directory Purposes

**`internal/domain`:**

- Purpose: Pure domain layer (no internal deps)
- Contains: Event definitions, `HostEntry` read model, snapshots, error codes
- Key files: `events.go`, `host.go`, `snapshot.go`, `errors.go`

**`internal/storage`:**

- Purpose: CQRS storage contracts + SQLite backend
- Contains: `EventStore`, `SnapshotStore`, `HostProjection` interfaces; SQLite impl; migrations
- Key files: `storage.go`, `sqlite/eventstore.go`, `sqlite/projection.go`, `sqlite/snapshots.go`, `sqlite/migrations/*.sql`

**`internal/server`:**

- Purpose: gRPC service and write orchestration
- Contains: service impl, command handler, write queue, file/config generators, hooks, metrics
- Key files: `service.go`, `commands.go`, `server.go`, `writequeue.go`

**`internal/client`:**

- Purpose: All client-facing interfaces
- Contains: gRPC client, Cobra commands, TUI, output formatters
- Key files: `client.go`, `commands/root.go`

## Key File Locations

**Entry Points:**

- `cmd/router-hosts/main.go`: CLI/server binary
- `cmd/operator/main.go`: operator binary
- `internal/client/commands/serve.go`: starts the gRPC server

**Configuration:**

- `internal/config/server.go`: server TOML config (strict decoding)
- `internal/config/client.go`: client TOML config

**Core Logic:**

- `internal/server/commands.go`: write command handling
- `internal/storage/sqlite/eventstore.go`: event append + concurrency
- `internal/storage/sqlite/projection.go`: event replay / queries

**Testing:**

- `internal/**/*_test.go`: co-located unit tests
- `internal/storage/storagetest/suite.go`: reusable storage suite
- `e2e/`: end-to-end mTLS + Docker tests

## Naming Conventions

**Files:**

- lowercase, no separators: `hostsfile.go`, `writequeue.go`
- Tests co-located as `<name>_test.go`
- Generated protobuf: `*.pb.go`, `*_grpc.pb.go`; generated deepcopy: `zz_generated.deepcopy.go`
- SQL migrations: `NNN_description.sql` (e.g. `001_initial.sql`)

**Directories:**

- Package-per-directory under `internal/`
- CRD API versions as directory names: `v1alpha1`, `v1`

## Where to Add New Code

**New domain event:**

- Add type/discriminator in `internal/domain/events.go`
- Handle replay in `internal/storage/sqlite/projection.go`
- Emit from a handler in `internal/server/commands.go`

**New gRPC RPC:**

- Define in `proto/router_hosts/v1/`, run `task proto:generate`
- Implement in `internal/server/service.go`
- Wire CLI in `internal/client/commands/`

**New CLI subcommand:**

- Add file under `internal/client/commands/`, register on root command

**New output format:**

- Add formatter in `internal/client/output/`

**New operator behavior:**

- Controllers in `internal/operator/`, CRD types in `api/operator/v1alpha1/`, chart CRDs in `charts/router-hosts-operator/crds/`

**Tests:**

- Co-locate `<name>_test.go` next to source; use `t.TempDir()`, never real FS

## Special Directories

**`api/`:**

- Purpose: Generated gRPC stubs and operator CRD types
- Generated: Yes (via buf / controller-gen)
- Committed: Yes

**`.worktrees/` and `.claude/worktrees/`:**

- Purpose: Git worktrees for isolated feature work
- Committed: No

**`bin/`, `coverage.out`:**

- Purpose: Build artifacts / coverage output
- Committed: No

---

*Structure analysis: 2026-07-08*
