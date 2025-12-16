# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Workflow

### Trunk-Based Development

This project follows **trunk-based development** practices:

**Core Principles:**
- `main` branch is always deployable and protected
- All development happens in short-lived feature branches
- Feature branches live for **hours to days, not weeks**
- Merge to `main` frequently (at least daily for active features)
- No long-lived development branches
- Use feature flags for incomplete features if needed

**Branch Naming:**
- `feat/short-description` - new features
- `fix/short-description` - bug fixes
- `refactor/short-description` - refactoring
- `docs/short-description` - documentation

**Workflow:**
1. Create feature branch from latest `main`
2. Make small, focused commits with conventional commit messages
3. Open PR early (can be draft) for visibility
4. Keep PRs small (< 400 lines changed when possible)
5. Merge to `main` as soon as tests pass and code review approves
6. Delete feature branch immediately after merge

**PR Guidelines:**
- PRs should be reviewable in < 30 minutes
- Each PR should have a single, clear purpose
- Break large features into multiple sequential PRs
- CI must pass before merge (all tests, lints, formatting)
- Squash merge is preferred to keep `main` history clean

**Release Strategy:**
- Tag releases from `main`: `v0.1.0`, `v0.2.0`, etc.
- Use semantic versioning
- Releases are created from tested, stable `main` commits

### Commit Message Convention

Follow **Conventional Commits** specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvement
- `test`: Adding or updating tests
- `docs`: Documentation changes
- `build`: Build system or dependency changes
- `ci`: CI/CD configuration changes
- `chore`: Other changes that don't modify src or test files

**Scopes (optional but recommended):**
- `proto`: Protobuf definitions
- `server`: Server-specific code
- `client`: Client-specific code
- `db`: Database layer
- `validation`: Validation logic
- `config`: Configuration handling

**Examples:**
```
feat(server): implement gRPC ListHosts endpoint

Add server streaming implementation for listing all host entries
with support for pagination via limit/offset parameters.

Closes #42
```

```
fix(validation): reject hostnames with consecutive dots

The hostname validator was incorrectly accepting "example..com"
due to not checking for empty labels after splitting.

Fixes #58
```

```
test(db): add integration tests for snapshot rollback

Verify rollback creates backup snapshot and restores state correctly.
```

**Rules:**
- Subject line: ≤50 characters, imperative mood, no period
- Body: Wrap at 72 characters, explain what and why (not how)
- Reference issues in footer: `Fixes #123`, `Closes #456`, `Refs #789`
- Breaking changes: Use `BREAKING CHANGE:` in footer or `!` after type

### Test Coverage Requirements

**MANDATORY: Maintain ≥80% test coverage at all times**

**Coverage Rules:**
- All new code must include tests
- PRs that decrease coverage below 80% will be rejected
- Use `cargo tarpaulin` or `cargo llvm-cov` to measure coverage
- Coverage is measured per-crate and workspace-wide

**Testing Strategy:**
- **Unit tests:** Every public function, method, and module
- **Integration tests:** End-to-end gRPC workflows, database operations
- **Property-based tests:** Use `proptest` for validation logic
- **Regression tests:** Add test for every bug fix

**Test Quality Standards:**
- Tests must be deterministic (no flakiness)
- Use descriptive test names: `test_validate_hostname_rejects_consecutive_dots`
- Arrange-Act-Assert pattern
- One logical assertion per test (multiple `assert!` calls OK if testing same thing)
- Mock external dependencies (filesystem, network, time)

**Coverage Checking:**
```bash
# Install coverage tool
cargo install cargo-tarpaulin

# Run coverage check
cargo tarpaulin --workspace --out Html --output-dir coverage

# View coverage report
open coverage/index.html

# Fail if coverage < 80%
cargo tarpaulin --workspace --fail-under 80
```

**Exemptions (excluded from coverage calculation):**
- Generated protobuf code (in `target/`)
- `main.rs` entry points (minimal logic only)
- `client/grpc.rs` - gRPC client wrapper (requires live server, tested by E2E)
- `server/mod.rs` - gRPC server impl (requires network binding, tested by E2E)
- Trivial getters/setters (if any exist)
- Mark untestable code with `#[cfg(not(tarpaulin_include))]`

## Project Overview

**router-hosts** is a Rust CLI tool for managing DNS host entries on routers and servers. It uses a client-server architecture where:
- **Server** runs on the target machine (router, server, container), manages a configurable hosts file via event-sourced DuckDB storage
- **Client** runs on workstation, connects via gRPC over TLS with mutual authentication

See `docs/plans/2025-12-01-router-hosts-v1-design.md` for complete design specification.

### Issue Tracking

**All tasks are tracked in GitHub Issues.** Use `gh issue list` to see open issues.

When completing work:
- Reference issues in commit messages: `Fixes #123`, `Closes #456`
- Close issues via PR merge or manual close after verification
- Create new issues for discovered work or follow-up tasks

Key issue categories:
- **High priority:** Core features blocking v0.5.0 release
- **Medium priority:** Important but not blocking
- **Low priority:** Nice-to-have improvements

## Development Prerequisites

Before contributing, ensure you have the following tools installed:

- **Rust toolchain** (stable): `rustup install stable`
- **buf CLI** (for protobuf linting/formatting):
  - macOS: `brew install bufbuild/buf/buf`
  - Other: [buf.build/docs/installation](https://buf.build/docs/installation)
- **pre-commit** (CI enforces these checks): `pip install pre-commit`
  - Enable hooks: `pre-commit install && pre-commit install --hook-type pre-push`
  - Running locally catches issues before push

**Note on linting:** Workspace lints in `Cargo.toml` use `warn` level during development, but CI treats warnings as errors via `cargo clippy -- -D warnings`. This allows iterative development while enforcing quality before merge.

**Note on testing:** Tests are run by the `ci.yml` workflow, not pre-commit hooks. Pre-commit handles formatting and linting only (cargo fmt, clippy, buf). This avoids running the test suite twice in CI while keeping local commits fast.

### Dependency Management

This project uses [Renovate](https://docs.renovatebot.com/) for automated dependency updates:

- **Schedule:** Weekly (Monday mornings, America/New_York timezone)
- **Auto-merge:** Patch updates and GitHub Actions are auto-merged after CI passes
- **Manual review:** Minor/major updates require manual review (especially DuckDB)
- **Stability:** Non-patch Cargo updates wait 3 days before being proposed

To temporarily disable Renovate, set `"enabled": false` in `renovate.json` or close unwanted Renovate PRs with a "wontfix" label.

## Build and Development Commands

### Using Task (Recommended)

This project uses [Taskfile](https://taskfile.dev/) to orchestrate builds:

```bash
task build          # Build all crates (debug)
task build:release  # Build all crates (release)
task test           # Unit + integration tests
task lint           # All linters (clippy, fmt, buf)
task fmt            # Format all code
task e2e            # E2E acceptance tests
task ci             # Full CI pipeline locally
```

### Build
```bash
# Build all crates
cargo build

# Build specific crate
cargo build -p router-hosts
cargo build -p router-hosts-common

# Release build
cargo build --release
```

### Testing
```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p router-hosts-common
cargo test -p router-hosts

# Run specific test
cargo test test_name

# Run with logging
RUST_LOG=debug cargo test test_name -- --nocapture

# Run tests with coverage (requires cargo-tarpaulin)
cargo tarpaulin --workspace --out Html --output-dir coverage

# Fail if coverage drops below 80%
cargo tarpaulin --workspace --fail-under 80

# Run tests in release mode (for performance testing)
cargo test --release
```

### E2E Tests

E2E tests validate the full stack with real mTLS authentication:

```bash
# Run all E2E tests
task e2e

# Run specific scenario
task e2e:scenario -- disaster_recovery

# Quick run (skip rebuild)
task e2e:quick
```

Required environment:
- Docker running
- `ROUTER_HOSTS_IMAGE`: Docker image (default: `ghcr.io/fzymgc-house/router-hosts:latest`)
- `ROUTER_HOSTS_BINARY`: Path to CLI binary (default: `router-hosts` in PATH)

### Linting and Formatting
```bash
# Format Rust code
cargo fmt

# Check Rust formatting without modifying
cargo fmt -- --check

# Format protobuf files
buf format -w

# Check protobuf formatting without modifying
buf format --diff --exit-code

# Run clippy
cargo clippy -- -D warnings

# Fix clippy suggestions automatically
cargo clippy --fix
```

### Protocol Buffers
```bash
# Regenerate protobuf code (after modifying proto/hosts.proto)
# This happens automatically during build via tonic-build
# Note: Uses bundled protoc from protobuf-src crate (no system installation required)
cargo build -p router-hosts-common

# Lint protobuf files
buf lint

# Format protobuf files
buf format -w
```

### Running Locally
```bash
# Run in client mode (default)
cargo run -- --help
cargo run -- --config client.toml add --ip 192.168.1.10 --hostname server.local

# Run in server mode
cargo run -- server --config server.toml

# Or use the binary directly
./target/debug/router-hosts --help        # Client mode
./target/debug/router-hosts server --help  # Server mode
```

### Pre-Commit Verification

**Before pushing code, run this checklist:**

```bash
# 1. Format code
cargo fmt

# 2. Run all tests
cargo test --workspace

# 3. Run clippy with strict settings
cargo clippy --workspace -- -D warnings

# 4. Check test coverage
cargo tarpaulin --workspace --fail-under 80

# 5. Lint and format protobuf
buf lint && buf format --diff --exit-code

# 6. Run security audit
cargo audit
```

**Or use this one-liner:**
```bash
cargo fmt && \
cargo test --workspace && \
cargo clippy --workspace -- -D warnings && \
buf lint && \
buf format --diff --exit-code
```

### CI/CD Integration

**GitHub Actions runs on every PR:**
- Build check (debug and release)
- All tests (with coverage reporting)
- Clippy with `-D warnings`
- rustfmt check
- buf lint and format check
- Automated code review via Claude

**Coverage is reported but not yet enforced in CI** (TODO: add after initial implementation)

**Branch Protection Rules:**
- All CI checks must pass before merge
- At least one approving review required
- No force pushes to `main`
- Branches must be up to date before merge

## Release Process

### Testing Releases Locally

Before creating a release tag, test the release build process locally:

```bash
# Test release build locally (without publishing)
dist build --artifacts=local --output-format=json

# Dry-run for a specific tag (shows what would be created)
dist plan --tag=v0.5.0

# Check what artifacts would be generated
dist plan --tag=v0.5.0 --output-format=json | jq '.artifacts'

# Test that binaries are stripped (for smaller size)
cargo build --profile=dist -p router-hosts
ls -lh target/dist/router-hosts
file target/dist/router-hosts  # Should show "stripped"

# Verify the binary runs correctly
./target/dist/router-hosts --version
./target/dist/router-hosts --help
```

### Required GitHub Secrets

The following secrets must be configured in the repository for releases to work:

- **`HOMEBREW_TAP_TOKEN`**: Personal access token with `contents: write` permission for `fzymgc-house/homebrew-tap`
  - Create at: https://github.com/settings/tokens/new
  - Required scopes: `public_repo` (or `repo` if tap is private)
  - Add at: https://github.com/fzymgc-house/router-hosts/settings/secrets/actions

### Creating a Release

1. **Update version in `Cargo.toml`** (workspace root):
   ```toml
   [workspace.package]
   version = "0.6.0"  # Update this
   ```

2. **Update CHANGELOG.md** with release notes

3. **Commit version bump**:
   ```bash
   git commit -am "chore: bump version to v0.6.0"
   git push origin main
   ```

4. **Create and push tag** (triggers release workflow):
   ```bash
   git tag v0.6.0
   git push origin v0.6.0
   ```

5. **Monitor release workflow**:
   - GitHub Actions will build binaries for all platforms
   - Generate shell installer and Homebrew formula
   - Create GitHub Release with all artifacts
   - Generate GitHub attestations for supply chain security
   - Push Homebrew formula to `fzymgc-house/homebrew-tap`

### Post-Release Verification

After the release workflow completes, use the automated verification script:

```bash
# Automated verification (downloads, verifies attestations, checks audit data)
./scripts/verify-release.sh v0.6.0
```

Or manually verify each step:

```bash
# 1. Verify GitHub Release was created
gh release view v0.6.0

# 2. Test shell installer (in clean environment/container)
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/fzymgc-house/router-hosts/releases/download/v0.6.0/router-hosts-installer.sh | sh

# 3. Verify binary attestations
gh attestation verify router-hosts --repo fzymgc-house/router-hosts

# 4. Test Homebrew tap installation (preferred method)
brew install fzymgc-house/tap/router-hosts

# Alternative: Direct formula install from release
curl -LO https://github.com/fzymgc-house/router-hosts/releases/download/v0.6.0/router-hosts.rb
brew install --formula ./router-hosts.rb

# 5. Test binary with audit data
cargo auditable audit router-hosts
```

### Release Tag Format

Use semantic versioning with `v` prefix:
- ✅ `v0.5.0` - Standard release
- ✅ `v0.5.1-rc.1` - Pre-release (marked as prerelease in GitHub)
- ❌ `0.5.0` - Won't trigger workflow (v prefix required)
- ❌ `release-0.5.0` - Won't trigger workflow

**Note:** The release workflow is named `v-release.yml` (not `release.yml`) because
cargo-dist uses this naming convention when `tag-namespace = "v"` is configured.

**Warning:** Do not rename `v-release.yml` manually. Running `dist generate-ci` will
recreate it with the original name, and any custom changes will be lost. Always use
`dist generate-ci` to regenerate the workflow file after modifying `dist-workspace.toml`.

## Architecture Overview

### Workspace Structure

Four crates in a Cargo workspace:

1. **router-hosts-common** - Shared library
   - Protocol buffer definitions and generated code
   - Validation logic (IP addresses, hostnames)
   - Shared types and utilities

2. **router-hosts-storage** - Storage abstraction layer
   - `Storage` trait defining EventStore, SnapshotStore, and HostProjection
   - DuckDB backend (default, embedded, feature-rich)
   - SQLite backend (lightweight, embedded, single-file)
   - PostgreSQL backend (multi-instance, cloud deployments, connection pooling)
   - Shared test suite for backend compliance (42 tests)

3. **router-hosts** - Unified binary (client and server modes)
   - **Client mode (default):** CLI interface using clap, gRPC client wrapper, command handlers
   - **Server mode:** gRPC service implementation, storage integration, hosts file generation with atomic writes, post-edit hook execution
   - Mode selection: runs in server mode when first argument is "server", otherwise client mode

4. **router-hosts-e2e** - End-to-end acceptance tests
   - Docker-based integration tests with real mTLS
   - 8 scenario tests covering CRUD, auth, disaster recovery

### Key Design Decisions

**Event Sourcing:**
- All changes stored as immutable events in the storage backend
- Current state reconstructed from event log (CQRS pattern)
- Complete audit trail and time-travel query capability
- Optimistic concurrency via event versions

**Streaming APIs:**
- All multi-item operations use gRPC streaming (not arrays/lists)
- `ListHosts`, `SearchHosts`, `ExportHosts` - server streaming
- `ImportHosts` - bidirectional streaming
- Better memory efficiency and flow control

**Request/Response Messages:**
- All gRPC methods use dedicated request/response types
- Never bare parameters - enables API evolution without breaking changes

**Atomic /etc/hosts Updates:**
- Generate to `.tmp` file → fsync → atomic rename
- Original file unchanged on failure
- Post-edit hooks run after success/failure

**Versioning:**
- Storage backend stores snapshots of /etc/hosts at points in time
- Configurable retention (max count and max age)
- Rollback creates snapshot before restoring old version

### Security

- TLS with mutual authentication (client certs) is mandatory
- No fallback to insecure connections
- Server validates client certificates against configured CA

### Configuration

**Server requires:**
- `hosts_file_path` setting (no default) - prevents accidental overwrites
- TLS certificate paths
- Storage backend configuration (DuckDB path, SQLite path, or PostgreSQL URL)
- Optional: retention policy, hooks, timeout settings

**Client:**
- Config file optional (CLI args override)
- Server address and TLS cert paths

## Important Implementation Notes

### Storage Layer

- **Storage trait** in `router-hosts-storage` abstracts database operations
- **Available backends:**
  - **DuckDB** (default): Embedded, single file, feature-rich analytics
  - **SQLite**: Lightweight embedded, single file, wide compatibility
  - **PostgreSQL**: Multi-instance deployments, connection pooling, cloud-ready
- Use in-memory mode for tests: `DuckDbStorage::new(":memory:")`
- Shared test suite validates any `Storage` implementation (42 tests)

### Validation

All validation logic lives in `router-hosts-common/src/validation.rs`:
- IPv4/IPv6 address validation
- Hostname validation (DNS compliance)
- Duplicate detection happens at database level

### Error Handling

Map domain errors to appropriate gRPC status codes:
- `INVALID_ARGUMENT` - validation failures
- `ALREADY_EXISTS` - duplicates
- `NOT_FOUND` - missing entries/snapshots
- `ABORTED` - concurrent write conflicts (version mismatch)
- `PERMISSION_DENIED` - TLS auth failures

Include detailed error context in response messages.

### Testing

- **Unit tests:** Mock filesystem for /etc/hosts operations
- **Integration tests:** Use in-memory DuckDB, self-signed certs
- **Storage tests:** Shared test suite in `router-hosts-storage/tests/common/` (42 tests)
  - Any new storage backend must pass all tests via `run_all_tests(&storage).await`
- **E2E tests:** Docker containers with real mTLS (8 scenarios)
- **No real file system writes** in tests (use tempfiles or mocks)

## Rust Best Practices

### Code Quality Standards

**Error Handling:**
- Use `Result<T, E>` for fallible operations (never `panic!` in library code)
- Use `thiserror` for custom error types with good error messages
- Use `anyhow` for application-level error handling
- Propagate errors with `?` operator, not `.unwrap()` or `.expect()`
- Only use `.expect()` in tests or when invariant is guaranteed by type system

**Type Safety:**
- Use newtypes for domain concepts: `struct HostId(String)` not bare `String`
- Use builder pattern for complex constructors
- Leverage Rust's type system to make invalid states unrepresentable
- Use `#[non_exhaustive]` for public enums that might grow

**Async Patterns:**
- Prefer `tokio::spawn` for CPU-bound work in separate tasks
- Use `tokio::select!` carefully (ensure all branches are cancel-safe)
- Avoid holding locks across `.await` points
- Use `#[tokio::test]` for async tests

**Performance:**
- Use `&str` for read-only string data, `String` for owned
- Prefer `&[T]` over `&Vec<T>` in function parameters
- Use `Cow<'_, str>` when you might need to own or borrow
- Avoid unnecessary clones - use references when possible
- Use `Arc<T>` for shared ownership across threads

**Memory Safety:**
- Minimize `unsafe` code (justify each use with SAFETY comment)
- Use `#[must_use]` for types/functions where ignoring return is likely a bug
- Prefer stack allocation over heap when possible

**Code Organization:**
- Keep functions small (< 50 lines)
- Maximum cyclomatic complexity of 10 per function
- Use modules to organize related functionality
- Public APIs should be minimal and well-documented

**Documentation:**
- All public items must have doc comments (`///`)
- Include examples in doc comments for non-trivial APIs
- Use `//!` module-level docs to explain module purpose
- Document panics, errors, and safety requirements

**Clippy:**
```bash
# Enable all clippy lints by default
cargo clippy -- -D warnings

# Deny common mistakes
-D clippy::unwrap_used
-D clippy::expect_used
-D clippy::panic
-D clippy::todo
-D clippy::unimplemented
```

### Modern Rust Features (Edition 2021+)

**Use these patterns:**
- `if let` chains: `if let Some(x) = opt && x > 5 { }`
- `let else`: `let Some(x) = opt else { return }`
- `impl Trait` in function signatures for clarity
- `async fn` in traits (requires `async-trait` or nightly)
- Const generics where applicable

**Avoid:**
- `.clone()` on `Arc<T>` without understanding ref counting
- `Rc<RefCell<T>>` in async code (not `Send`)
- String allocations in hot paths
- Excessive trait bounds (use `where` clauses for readability)

### Dependency Management

**Philosophy:**
- Minimize dependencies (each dependency is a liability)
- Prefer well-maintained crates with recent updates
- Check `cargo-audit` regularly for security issues
- Pin versions in `Cargo.lock` (committed for binaries)

**Workspace Dependencies:**
- All dependency versions defined in workspace `Cargo.toml`
- Individual crates use `workspace = true` references
- Keep dependencies up-to-date (check monthly)

**Security:**
```bash
# Install audit tool
cargo install cargo-audit

# Check for vulnerabilities
cargo audit

# Check for outdated dependencies
cargo outdated --workspace
```

### Dependencies

Core dependencies (see Cargo.toml for versions):
- `tonic` + `prost` - gRPC/protobuf
- `tonic-build` + `protobuf-src` - protobuf code generation with bundled protoc
- `duckdb` - embedded database
- `tokio` - async runtime
- `clap` - CLI parsing
- `serde` + `toml` - config
- `rustls` - TLS
- `tracing` - logging
- `proptest` - property-based testing

**Note on Protocol Buffers:** The project uses `protobuf-src` to provide a bundled
Protocol Buffers compiler (`protoc`), eliminating the need for system installation.
This makes the build self-contained and portable across development environments.

## /etc/hosts Format

Generated file includes:
- Header comment with metadata (timestamp, entry count)
- Sorted entries (by IP, then hostname)
- Inline comments from entry metadata
- Tags shown as `[tag1, tag2]` in comments

Example:
```
# Generated by router-hosts
# Last updated: 2025-11-28 20:45:32 UTC
# Entry count: 42

192.168.1.10    server.local
192.168.1.20    nas.home.local    # NAS storage [homelab]
```

## Post-Edit Hooks

Server executes shell commands after /etc/hosts updates:
- `on_success` hooks - after successful regeneration (e.g., reload dnsmasq)
- `on_failure` hooks - after failed regeneration (e.g., alerting)
- Hooks run with 30s timeout, failures logged but don't fail operation
- Environment variables provide context (event type, entry count, snapshot ID)

## Certificate Reload via SIGHUP

The server supports dynamic TLS certificate reload via SIGHUP signal (Unix only).

### How It Works

1. Server receives SIGHUP signal
2. Validates new certificates on disk (PEM format, key present, CA present)
3. If valid: graceful shutdown (30s drain), restart with new certs
4. If invalid: logs error, keeps running with current certs

### Graceful Shutdown Details

During the 30-second graceful shutdown period:

- **New connections**: Rejected (server stops accepting)
- **In-flight gRPC requests**: Allowed to complete
- **WriteQueue operations**: Continue processing until completion or timeout
- **Storage layer**: Shared across reloads (database connections persist)

If the timeout expires before all operations complete, remaining connections are forcibly closed. The server logs a warning indicating some requests may have been interrupted.

**What persists across reloads:**
- Storage backend (DuckDB/SQLite/PostgreSQL connection)
- CommandHandler (business logic)
- HookExecutor (post-edit hooks configuration)
- HostsFileGenerator (output path configuration)

**What is recreated:**
- TLS certificates (the whole point of SIGHUP)
- gRPC server instance
- WriteQueue (fresh channel and worker task)

### Usage

```bash
# Find server PID and send SIGHUP
pkill -HUP router-hosts

# Or with explicit PID
kill -HUP $(pgrep router-hosts)
```

### With Vault Agent

Configure Vault Agent to send SIGHUP after certificate renewal:

```hcl
template {
  source      = "cert.tpl"
  destination = "/etc/router-hosts/server.crt"
  command     = "pkill -HUP router-hosts"
}
```

### Platform Support

| Platform | SIGHUP Support |
|----------|----------------|
| Linux    | Yes            |
| macOS    | Yes            |
| Windows  | No (logs warning) |

### What Gets Validated

- Files exist and are readable
- Valid PEM format
- Private key can be parsed
- CA certificate can be parsed

### What Doesn't Get Validated

- Certificate expiry (server starts with expired certs)
- CA chain validity (checked at connection time)
- Key/cert match (checked by tonic on load)

#### macOS E2E Testing

**Issue:** `task e2e` fails on macOS with "Exec format error" because it uses host binary (macOS) in Linux container.

**Solution:**

```bash
# 1. Build Docker image with Linux binary (multi-stage Docker build)
task docker:build

# 2. Run E2E tests
ROUTER_HOSTS_IMAGE=ghcr.io/fzymgc-house/router-hosts:dev \
ROUTER_HOSTS_BINARY=$(pwd)/target/release/router-hosts \
cargo test -p router-hosts-e2e --release

# Or run specific test
ROUTER_HOSTS_IMAGE=ghcr.io/fzymgc-house/router-hosts:dev \
ROUTER_HOSTS_BINARY=$(pwd)/target/release/router-hosts \
cargo test -p router-hosts-e2e --release test_import_export_roundtrip
```

**Why:**
- `docker:build` compiles Linux binary inside Docker (works cross-platform)
- `docker:build-ci` copies host binary (fast on Linux CI, broken on macOS)
- Tests need `ROUTER_HOSTS_IMAGE=...dev` to use locally built image

**Important:** Never push commits directly to Renovate-originated branches. Renovate manages these branches automatically and will force-push updates. Always create a separate branch for any manual fixes.
