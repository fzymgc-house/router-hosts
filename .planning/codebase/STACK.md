# Technology Stack

**Analysis Date:** 2026-07-08

## Languages

**Primary:**

- Go 1.26.4 - Entire codebase (CLI, gRPC server, K8s operator, TUI). Declared in `go.mod`.

**Secondary:**

- Protocol Buffers (proto3) - gRPC API definitions in `proto/router_hosts/v1/*.proto`
- TOML - Configuration files (`examples/server.toml.example`, `examples/client.toml.example`)
- Starlark/YAML - Task runner (`Taskfile.yml`), CI (`.github/workflows/`)

## Runtime

**Environment:**

- Go 1.26+ (builds with `golang:1.26-alpine` in `Dockerfile`)
- CGo disabled (`CGO_ENABLED=0`) - fully static binaries, pure-Go SQLite backend

**Package Manager:**

- Go modules
- Lockfile: `go.sum` present

## Frameworks

**Core:**

- `google.golang.org/grpc` v1.81.1 - gRPC server/client transport over mTLS
- `google.golang.org/protobuf` v1.36.12 - Protobuf runtime; generated stubs in `api/v1/`
- `github.com/spf13/cobra` v1.10.2 - CLI command framework (`internal/client/commands`)
- `sigs.k8s.io/controller-runtime` v0.24.1 - Kubernetes operator framework (`internal/operator`)

**TUI:**

- `github.com/charmbracelet/bubbletea` v1.3.10 - Interactive TUI event loop (`internal/client/tui`)
- `github.com/charmbracelet/bubbles` v1.0.0 - TUI components
- `github.com/charmbracelet/lipgloss` v1.1.0 - TUI styling

**Testing:**

- `github.com/stretchr/testify` v1.11.1 - Assertions and test suites
- `pgregory.net/rapid` v1.3.0 - Property-based testing

**Build/Dev:**

- Task (`Taskfile.yml`) - Task runner; wraps all build/test/lint commands
- `buf` - Protobuf lint, format, and code generation
- GoReleaser (`.goreleaser.yml`) - Release binary/artifact builds
- golangci-lint v2 (`.golangci.yml`) - Go linting
- cocogitto (`cog.toml`) - Conventional commit validation
- lefthook - Git hooks

## Key Dependencies

**Critical:**

- `zombiezen.com/go/sqlite` v1.4.2 - SQLite access (pure Go, `modernc.org/sqlite` backend). Event-sourced storage in `internal/storage/sqlite`.
- `github.com/samber/oops` v1.22.0 - Structured errors with error codes (mandated project-wide)
- `github.com/go-acme/lego/v4` v4.35.2 - ACME (Let's Encrypt) certificate management via DNS-01 (`internal/acme`)
- `github.com/oklog/ulid/v2` v2.1.1 - ULID event/aggregate identifiers
- `github.com/BurntSushi/toml` v1.6.0 - TOML config parsing (`internal/config`)

**Infrastructure:**

- `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go` v0.36.1 - Kubernetes operator client/types
- `go.opentelemetry.io/otel` v1.44.0 (+ SDK, metric, OTLP gRPC exporter) - Metrics/observability
- `github.com/prometheus/client_golang` v1.23.2 (indirect) - Prometheus metrics
- `github.com/miekg/dns` v1.1.72 (indirect, via lego) - DNS operations
- `golang.org/x/term` v0.43.0 - Terminal handling for TUI/prompts

## Configuration

**Environment:**

- Server/client configured via TOML files (`server.toml`, `client.toml`)
- Config supports env var expansion via `config.ExpandEnvVars` (e.g. Cloudflare API token)
- No `.env` files present in repo

**Build:**

- `Taskfile.yml` - Primary build/test/lint entry points
- `Dockerfile` - Multi-stage build (golang:1.26-alpine builder → distroless/static:nonroot runtime)
- `.goreleaser.yml` - Release artifact configuration
- `tsconfig`/`.golangci.yml` - Lint config

## Platform Requirements

**Development:**

- Go 1.25+/1.26, buf CLI, golangci-lint, gofumpt, Task, cocogitto, lefthook, rumdl, yamlfmt
- No CGo toolchain required (pure Go SQLite)

**Production:**

- Distroless static container (`gcr.io/distroless/static:nonroot`)
- Exposes gRPC port 50051
- Two binaries: `router-hosts` (CLI + server), `operator` (K8s controller)

---

*Stack analysis: 2026-07-08*
