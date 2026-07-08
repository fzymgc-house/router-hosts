# Coding Conventions

**Analysis Date:** 2026-07-08

## Naming Patterns

**Files:**

- Snake-free lowercase, single-word or compound: `host.go`, `errors.go`, `writequeue.go`, `hostsfile.go`, `unboundconf.go`
- Test files co-located with `_test.go` suffix: `host_test.go`
- Build-tagged E2E tests: `e2e_test.go`, `docker_e2e_test.go`

**Functions:**

- Exported: PascalCase (`GRPCCode`, `ErrNotFound`, `IsEmpty`)
- Unexported: camelCase
- Constructor-style factories for errors: `ErrNotFound`, `ErrDuplicate`, `ErrValidation` in `internal/domain/errors.go`
- `revive` `exported` rule enforced with `checkPrivateReceivers` — exported identifiers MUST carry doc comments

**Variables:**

- camelCase locals; PascalCase for exported package vars/consts
- Grouped const blocks with aligned trailing comments: see `CodeVersionConflict`, `CodeNotFound`, etc. in `internal/domain/errors.go`

**Types:**

- PascalCase struct names with descriptive intent: `HostEntry`, `SearchFilter`
- Domain read-models documented with CQRS terminology in comments

## Code Style

**Formatting:**

- `gofumpt` (stricter gofmt) enforced via `formatters` block in `.golangci.yml`
- Run with `task fmt` (gofumpt + buf format)
- Go version: `go 1.26.4` (`go.mod`)

**Linting:**

- `golangci-lint` v2 config in `.golangci.yml`, timeout 5m
- Enabled beyond standard: `revive`, `gocritic`, `misspell`, `nilerr`, `errorlint`, `exhaustive`, `prealloc`
- `exhaustive` uses `default-signifies-exhaustive: true` — a `default:` case satisfies switch exhaustiveness
- Run with `task lint` (golangci-lint + buf lint)
- `//nolint` directives require explicit justification AND user approval (per `CLAUDE.md`)

## Import Organization

**Order:**

1. Standard library (`fmt`, `time`, `testing`)
2. Third-party (`github.com/samber/oops`, `google.golang.org/grpc/codes`, `github.com/oklog/ulid/v2`)
3. Internal (`github.com/fzymgc-house/router-hosts/internal/...`)

**Path Aliases:**

- None; full module paths under `github.com/fzymgc-house/router-hosts`

## Error Handling

**Patterns:**

- MUST return `error` from fallible functions
- MUST use `samber/oops` for structured errors with error codes (`internal/domain/errors.go`)
- Error factory functions build oops errors with a code, structured context, and message:

  ```go
  return oops.
      Code(CodeNotFound).
      With("entity", entity).
      With("id", id).
      Errorf("%s %q not found", entity, id)
  ```

- Domain error codes are string constants mapped to gRPC status codes via `GRPCCode` (`internal/domain/errors.go`)
- Wrap with context: `oops.Wrapf(err, "doing X")`
- MUST NOT use `log.Fatal` / `os.Exit` in library code
- `errorlint` + `nilerr` linters enforce correct error comparison/return

**Error code → gRPC mapping:**

- `version_conflict` → Aborted, `not_found` → NotFound, `duplicate_entry` → AlreadyExists, `validation_failed` → InvalidArgument, `internal`/`storage_error` → Internal

## Logging

**Framework:** OpenTelemetry for metrics; structured logging via server layer (`internal/server/metrics`)

**Patterns:**

- Errors carry structured context via oops `.With(...)` rather than log statements in library code

## Comments

**When to Comment:**

- Exported identifiers MUST have doc comments (revive `exported` rule)
- Comments explain intent and invariants, not restate code — e.g. the `Deleted` tombstone semantics on `HostEntry` (`internal/domain/host.go`)
- MUST NOT add obvious comments restating code (per user conventions)

**GoDoc:**

- Standard GoDoc style: comment begins with the identifier name

## Function Design

**Size:** Small, single-responsibility; validation split into focused methods (`IsEmpty`, `Validate`)

**Parameters:** Value receivers for read-only methods (`func (f SearchFilter) Validate()`)

**Return Values:** Return `error` last; nil pointer fields used for optional filter criteria (`*string`)

## Module Design

**Exports:** Package-per-concern under `internal/` (domain, validation, storage, server, client, acme, operator)

**Barrel Files:** Not used; Go package structure per `CLAUDE.md` package table

---

*Convention analysis: 2026-07-08*
