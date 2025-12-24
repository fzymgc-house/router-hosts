# SQLite Default Storage Design

**Status:** IMPLEMENTED (2025-12-24)

## Problem

DuckDB adds significant weight to the binary (~30MB bundled) and slows compilation. For a simple hosts file manager with event sourcing, SQLite provides equivalent functionality with lower overhead.

## Solution

Make SQLite the default storage backend. Move DuckDB to a separate binary for users who need it.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Binary structure | Separate binary in same repo | Shared code, independent artifacts |
| Binary names | `router-hosts` + `router-hosts-duckdb` | Main binary stays lightweight |
| Default storage path | XDG-compliant | `~/.local/share/router-hosts/hosts.db` on Linux |
| Docker images | Two separate images | Keeps main image small |
| Migration tools | None | No existing users |

## Implementation

### Crate Structure

```
crates/
├── router-hosts-common/      # Unchanged
├── router-hosts-storage/     # All 3 backends (default: sqlite)
├── router-hosts/             # Main binary: SQLite + Postgres
├── router-hosts-duckdb/      # DuckDB variant binary
└── router-hosts-e2e/         # Tests both binaries
```

### Feature Flag Changes

**`router-hosts-storage/Cargo.toml`:**

```toml
[features]
default = ["sqlite"]           # Was: ["duckdb"]
sqlite = ["dep:sqlx", "sqlx/sqlite"]
postgres = ["dep:sqlx", "sqlx/postgres"]
duckdb = ["dep:duckdb"]
```

**`router-hosts/Cargo.toml`:**

```toml
[dependencies]
router-hosts-storage = { path = "../router-hosts-storage", default-features = false, features = ["sqlite", "postgres"] }
```

**`router-hosts-duckdb/Cargo.toml`:**

```toml
[dependencies]
router-hosts = { path = "../router-hosts" }
router-hosts-storage = { path = "../router-hosts-storage", features = ["duckdb"] }
```

### XDG Default Storage Path

When no `database.url` is configured, use XDG-compliant default:

| Platform | Default Path |
|----------|--------------|
| Linux | `~/.local/share/router-hosts/hosts.db` |
| macOS | `~/Library/Application Support/router-hosts/hosts.db` |
| Windows | `C:\Users\<user>\AppData\Roaming\router-hosts\hosts.db` |

### Error Messages

Unsupported backends return actionable errors:

```
Error: DuckDB backend not available in this build.

To use DuckDB, install the router-hosts-duckdb binary:
  brew install fzymgc-house/tap/router-hosts-duckdb

Or switch to a supported backend:
  sqlite:///path/to/hosts.db
  postgres://user:pass@host/db
```

### Code Sharing

Refactor `router-hosts` to expose a library. The DuckDB crate imports it:

```rust
// router-hosts-duckdb/src/main.rs
fn main() -> anyhow::Result<()> {
    router_hosts::run()
}
```

### Docker Images

| Image | Size (est.) | Contents |
|-------|-------------|----------|
| `ghcr.io/fzymgc-house/router-hosts` | ~15MB | SQLite + Postgres |
| `ghcr.io/fzymgc-house/router-hosts-duckdb` | ~50MB | All backends |

### CI/CD Changes

- `docker.yml`: Matrix build for both images
- `v-release.yml`: Two binaries, two Homebrew formulae

## Implementation Order

1. Refactor `router-hosts` to expose library (`lib.rs`)
2. Create `router-hosts-duckdb` crate
3. Change default feature in `router-hosts-storage`
4. Add XDG default storage path
5. Improve error messages for unsupported backends
6. Add `Dockerfile.duckdb`
7. Update CI workflows

## Out of Scope

- Data migration tools (no users yet)
- CLI interface changes (stays identical)
- Removing backends from storage crate
