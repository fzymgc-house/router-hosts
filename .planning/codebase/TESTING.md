# Testing Patterns

**Analysis Date:** 2026-07-08

## Test Framework

**Runner:**

- Go standard `testing` package
- Config: none (standard `go test`), orchestrated via `Taskfile.yml`

**Assertion Library:**

- `github.com/stretchr/testify` v1.11.1 — `assert` and `require`
- `require.NoError`/`require.NotNil` for fatal preconditions; `assert.*` for non-fatal checks

**Property-Based Testing:**

- `pgregory.net/rapid` v1.3.0 — used for generative testing (e.g. IP octet ranges in `internal/validation/validation_test.go`)

**Run Commands:**

```bash
task test              # Run all tests with race detector
task test:coverage     # HTML coverage report
task test:coverage:ci  # Coverage enforcing 80% threshold
task test:e2e          # In-process E2E with real mTLS (build tag: e2e)
task test:e2e:docker   # Docker container E2E (build tag: docker_e2e)
```

- MUST NOT run `go test` directly when `task test` exists (per `CLAUDE.md`)

## Test File Organization

**Location:**

- Co-located with source: `internal/domain/host_test.go` next to `host.go`
- E2E tests isolated in `e2e/` package

**Naming:**

- `<source>_test.go` for unit tests
- `Test<Type>_<Method>` for test functions (e.g. `TestSearchFilter_Validate`)
- 112 `_test.go` files across the tree

**Structure:**

```text
internal/<pkg>/<source>.go
internal/<pkg>/<source>_test.go
internal/storage/sqlite/compliance_test.go   # shared storage-interface compliance suite
e2e/e2e_test.go, helpers_test.go, docker_e2e_test.go
```

## Test Structure

**Suite Organization — table-driven with subtests:**

```go
func TestSearchFilter_Validate(t *testing.T) {
    tests := []struct {
        name    string
        filter  SearchFilter
        wantErr bool
        errMsg  string
    }{
        {name: "valid filter all fields set", filter: SearchFilter{...}, wantErr: false},
        {name: "empty IPPattern returns error", filter: SearchFilter{IPPattern: ptr("")}, wantErr: true, errMsg: "ip_pattern must not be an empty string"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // exercise + assert
        })
    }
}
```

**Patterns:**

- Table-driven tests with `for _, tt := range tests { t.Run(tt.name, ...) }` are the dominant style
- Helper `ptr(...)` used to build `*string` optional fields
- `t.Parallel()` used where safe (e.g. `internal/server/service_test.go`, `metrics_test.go`)
- Property checks: `rapid.Check(t, func(t *rapid.T){ rapid.IntRange(0,255).Draw(t, "a") ... })`

## Mocking

**Framework:** No mock-generation framework (no mockgen/counterfeiter/gomock). Hand-written fakes and real in-memory implementations preferred.

**Patterns:**

- Storage tests exercise the real pure-Go SQLite backend against a temp DB rather than mocking
- Operator tests use controller-runtime fakes for K8s clients (`internal/operator/*_controller_test.go`)

**What to Mock:**

- External K8s API surface (operator controllers)

**What NOT to Mock:**

- Storage layer — tested against real SQLite via `t.TempDir()`
- Domain/validation logic — tested directly

## Fixtures and Factories

**Test Data:**

- Inline struct literals in table rows
- Shared compliance suite `internal/storage/sqlite/compliance_test.go` runs a common contract against storage implementations
- E2E helpers in `e2e/helpers_test.go`

**Location:**

- Package-local `testhelper_test.go` files (e.g. `internal/client/commands/testhelper_test.go`)

## Coverage

**Requirements:** ≥80% enforced. `task test:coverage:ci` runs `go test ./internal/... -race -coverprofile=coverage.out -covermode=atomic` and fails below threshold. Test-helper packages (e.g. `/storagetest/`) are excluded from the calculation.

**View Coverage:**

```bash
task test:coverage   # generates coverage.html via go tool cover
```

## Test Types

**Unit Tests:**

- Co-located `_test.go`, race-enabled, table-driven; cover domain, validation, config, server, client, storage

**Integration Tests:**

- SQLite storage compliance suite against real DB (`internal/storage/sqlite/`)
- Migration tests: `legacy_migration_test.go`, `snapshot_schema_migration_test.go`

**E2E Tests:**

- In-process with real mTLS behind `e2e` build tag (`e2e/e2e_test.go`)
- Full Docker container run behind `docker_e2e` build tag (`e2e/docker_e2e_test.go`)

## Common Patterns

**Filesystem isolation:**

```go
dir := t.TempDir()   // MUST NOT write to real filesystem in tests
```

**Error Testing:**

```go
if tt.wantErr {
    require.Error(t, err)
    assert.Contains(t, err.Error(), tt.errMsg)
} else {
    require.NoError(t, err)
}
```

**Property Testing:**

```go
rapid.Check(t, func(t *rapid.T) {
    a := rapid.IntRange(0, 255).Draw(t, "a")
    // build value, assert invariant
})
```

---

*Testing analysis: 2026-07-08*
