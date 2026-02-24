# CLAUDE.md

Instructions for Claude Code when working in this repository.

## Terminology

The key words "MUST", "MUST NOT", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## Required Skills

You MUST use these skills at the specified trigger points:

| Trigger | Skill | Rationale |
|---------|-------|-----------|
| Before any feature/creative work | `superpowers:brainstorming` | Explore requirements before implementation |
| When encountering bugs or failures | `superpowers:systematic-debugging` | Structured root cause analysis |
| Before claiming work is complete | `superpowers:verification-before-completion` | Verify with evidence, not assumptions |
| When asked to review code/PR | `pr-review-toolkit:review-pr` | Comprehensive multi-agent review |
| After creating or updating a PR | `pr-review-toolkit:review-pr` | Catch issues before human review |

You SHOULD use these skills when applicable:

| Trigger | Skill | Rationale |
|---------|-------|-----------|
| Starting isolated feature work | `superpowers:using-git-worktrees` | Avoid polluting main workspace |
| Planning multi-step implementation | `superpowers:writing-plans` | Create structured implementation plans |
| Creating commits | `commit-commands:commit` | Consistent conventional commits |

## Development Workflow

### Trunk-Based Development

- You MUST create feature branches from `main` for all changes
- You MUST use branch naming: `feat/`, `fix/`, `refactor/`, `docs/`
- You SHOULD keep PRs under 400 lines changed
- You MUST NOT push directly to `main`

### Commit Messages

You MUST follow Conventional Commits format:

```text
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:** `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`

**Scopes:** `proto`, `server`, `client`, `storage`, `validation`, `config`, `ci`, `deps`, `docs`, `operator`, `acme`, `e2e`

Scopes are recommended for clarity but not enforced. See `cog.toml` for scope descriptions.

**Rules:**

- Subject line MUST be ≤50 characters, imperative mood, no period
- Body SHOULD wrap at 72 characters
- Footer MUST reference issues: `Fixes #123`, `Closes #456`

### Pull Requests

- PRs MUST pass all CI checks before merge
- You MUST NOT use `gh pr edit --add-reviewer` for human reviewers
- You MUST use `pr-review-toolkit:review-pr` for code review

### CI Workflows

- `.github/workflows/ci-go.yml` runs lint, test, build, and buf checks on PRs
- You MAY modify workflow files (release-please.yml, ci-go.yml, etc.)

## Build and Test Commands

You MUST use `task` commands instead of direct `go` invocations where a task exists.

You SHOULD run `task --list` to see all available commands and their purposes.

| Command | Purpose |
|---------|---------|
| `task build` | Build all binaries |
| `task build:release` | Build optimized binaries to `bin/` |
| `task test` | Run all tests with race detector |
| `task test:coverage` | Generate HTML coverage report |
| `task test:coverage:ci` | Coverage with 80% threshold |
| `task lint` | Run golangci-lint + buf lint |
| `task fmt` | Format with gofumpt + buf format |
| `task proto:generate` | Regenerate protobuf Go stubs |
| `task test:e2e` | E2E tests with real mTLS (in-process) |
| `task test:e2e:docker` | Docker E2E tests (builds image, requires Docker) |
| `task docker:build` | Build Docker image for local architecture |
| `task clean` | Remove build artifacts |
| `task ci` | Full CI pipeline locally |

You MUST NOT run `go test` directly when `task test` is available.

You MUST maintain ≥80% test coverage. PRs that decrease coverage below 80% MUST be rejected.

E2E tests require build tags: `e2e` for in-process, `docker_e2e` for Docker container tests.

## Code Quality

### Error Handling

- You MUST return `error` from fallible functions
- You MUST use `samber/oops` for structured errors with error codes
- You MUST NOT use `log.Fatal` or `os.Exit` in library code
- You MUST wrap errors with context: `oops.Wrapf(err, "doing X")`

### Testing

- You MUST add tests for all new code
- You MUST add a regression test for every bug fix
- You SHOULD use `pgregory.net/rapid` for property-based testing
- You MUST NOT write to real filesystem in tests (use `t.TempDir()`)

### Linting

- You MUST run `golangci-lint run ./...` before committing
- golangci-lint v2 config is in `.golangci.yml`
- You MUST NOT add `//nolint` directives without explicit justification AND user approval
- You SHOULD fix lint warnings properly, not suppress them

## Development Setup

### Prerequisites

- **Go** (1.25+): `brew install go` or from golang.org
- **buf CLI** (protobuf): `brew install bufbuild/buf/buf`
- **cocogitto** (commit validation): `brew install cocogitto`
- **lefthook**: `brew install lefthook && lefthook install`
- **golangci-lint**: `brew install golangci-lint`
- **gofumpt**: `go install mvdan.cc/gofumpt@latest`
- **rumdl**: `brew install rumdl`
- **yamlfmt**: `brew install yamlfmt`
- **Task** (task runner): `brew install go-task`

### Issue Tracking

All tasks are tracked in GitHub Issues. You MUST:

- Reference issues in commits: `Fixes #123`, `Closes #456`
- Create new issues for discovered work or follow-up tasks

## Project Context

**router-hosts** is a Go CLI for managing DNS host entries via client-server architecture with gRPC over mTLS.

### Package Structure

| Package | Purpose |
|---------|---------|
| `cmd/router-hosts` | Main binary (CLI + server) |
| `cmd/operator` | Kubernetes operator binary |
| `internal/domain` | Event types, host aggregate, errors, snapshots |
| `internal/validation` | IP, hostname, alias validators |
| `internal/storage` | Storage interfaces (EventStore, SnapshotStore, HostProjection) |
| `internal/storage/sqlite` | SQLite implementation (pure Go, no CGo) |
| `internal/config` | Server + client TOML configuration |
| `internal/server` | gRPC server, commands, service, hosts file, hooks, metrics |
| `internal/client` | gRPC client wrapper with mTLS |
| `internal/client/commands` | Cobra CLI commands (host, snapshot, import/export, serve) |
| `internal/client/tui` | Bubble Tea interactive TUI |
| `internal/client/output` | Output formatters (table, JSON, CSV) |
| `internal/acme` | ACME DNS-01/Cloudflare certificate management via lego |
| `internal/operator` | K8s operator controllers (HostMapping, IngressRoute) |
| `api/v1` | Generated protobuf Go stubs |
| `e2e` | E2E tests with real mTLS (build tag: `e2e`) |

**Storage:** SQLite only, via `zombiezen.com/go/sqlite` (pure Go, modernc backend). No CGo required.

**Key libraries:** samber/oops (errors), Cobra (CLI), Bubble Tea + Lip Gloss (TUI), lego (ACME), controller-runtime (K8s operator), OpenTelemetry (metrics).

## Documentation

For detailed information, see:

| Topic | Location |
|-------|----------|
| Architecture & design | `docs/contributing/architecture.md` |
| Release process (GoReleaser) | `docs/contributing/releasing.md` |
| Testing strategy | `docs/contributing/testing.md` |
| ACME certificate management | `docs/guides/acme.md` |
| Operations (SIGHUP, hooks) | `docs/guides/operations.md` |
| Go migration design | `docs/plans/2026-02-22-golang-migration-design.md` |
