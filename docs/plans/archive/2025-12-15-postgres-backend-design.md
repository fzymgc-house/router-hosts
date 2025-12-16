# PostgreSQL Backend Design

**Date:** 2025-12-15
**Status:** ✅ Implemented (PR #116)
**Issue:** #113

## Overview

Add PostgreSQL as an alternative storage backend for multi-instance and cloud deployments.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Async library | sqlx 0.8 | Compile-time query checking, built-in pooling, truly async |
| Schema setup | Auto-initialize | Consistent with DuckDB/SQLite, simple for users |
| Pool defaults | min=1, max=10, acquire=30s, idle=10min | Conservative, overridable via URL params |
| SSL/TLS | Connection string | Standard PostgreSQL `sslmode` parameter |
| Testing | testcontainers-rs | Convenient local testing, auto-cleanup |

## Dependencies

```toml
# Cargo.toml additions
[features]
postgres = ["dep:sqlx"]

[dependencies]
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "tls-rustls"], optional = true }

[dev-dependencies]
testcontainers = "0.23"
testcontainers-modules = { version = "0.11", features = ["postgres"] }
```

## Module Structure

```
src/backends/postgres/
├── mod.rs           # PostgresStorage struct, Storage trait impl
├── schema.rs        # CREATE TABLE IF NOT EXISTS statements
├── event_store.rs   # EventStore trait implementation
├── snapshot_store.rs # SnapshotStore trait implementation
└── projection.rs    # HostProjection trait implementation
```

## Core Implementation

### PostgresStorage Struct

```rust
pub struct PostgresStorage {
    pool: sqlx::PgPool,
}

impl PostgresStorage {
    pub async fn new(url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .connect(url)
            .await?;
        Ok(Self { pool })
    }
}
```

Key difference from DuckDB/SQLite: No `spawn_blocking` wrappers - sqlx is truly async.

### Schema

```sql
-- Event store table
CREATE TABLE IF NOT EXISTS host_events (
    event_id TEXT PRIMARY KEY,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_version TEXT NOT NULL,
    ip_address TEXT,
    hostname TEXT,
    comment TEXT,
    tags TEXT,
    event_timestamp TIMESTAMPTZ NOT NULL,
    metadata TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT,
    expected_version TEXT,
    UNIQUE(aggregate_id, event_version)
);

CREATE INDEX IF NOT EXISTS idx_events_aggregate
    ON host_events(aggregate_id, event_version);
CREATE INDEX IF NOT EXISTS idx_events_time
    ON host_events(created_at);

-- Snapshots table
CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hosts_content TEXT NOT NULL,
    entry_count INTEGER NOT NULL,
    trigger TEXT NOT NULL,
    name TEXT,
    event_log_position BIGINT
);

CREATE INDEX IF NOT EXISTS idx_snapshots_created
    ON snapshots(created_at DESC);
```

### Current Hosts View

PostgreSQL supports `IGNORE NULLS` in window functions (like DuckDB, unlike SQLite):

```sql
CREATE VIEW IF NOT EXISTS host_entries_current AS
WITH windowed AS (
    SELECT
        aggregate_id,
        event_version,
        event_type,
        LAST_VALUE(ip_address) IGNORE NULLS OVER w as ip_address,
        LAST_VALUE(hostname) IGNORE NULLS OVER w as hostname,
        LAST_VALUE(comment) IGNORE NULLS OVER w as comment,
        LAST_VALUE(tags) IGNORE NULLS OVER w as tags,
        FIRST_VALUE(event_timestamp) OVER w as created_at,
        LAST_VALUE(created_at) OVER w as updated_at,
        LAST_VALUE(event_type) OVER w as latest_event_type,
        ROW_NUMBER() OVER (PARTITION BY aggregate_id ORDER BY event_version DESC) as rn
    FROM host_events
    WINDOW w AS (PARTITION BY aggregate_id ORDER BY event_version
                 ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)
)
SELECT aggregate_id as id, ip_address, hostname, comment, tags,
       created_at, updated_at, event_version
FROM windowed
WHERE rn = 1 AND latest_event_type != 'HostDeleted';
```

### Ordering Strategy

Unlike SQLite (which needed `rowid` due to ULID same-millisecond collisions), PostgreSQL uses `event_version` (ULID) directly:

- PostgreSQL connections come from different processes with different ULID generators
- Same-millisecond collisions are naturally avoided by different random suffixes
- Standard `ORDER BY event_version` works correctly

## Testing

### Test Structure

```
tests/
├── common/mod.rs           # Shared test harness (existing)
├── duckdb_backend.rs       # DuckDB tests (existing)
├── sqlite_backend.rs       # SQLite tests (existing)
└── postgres_backend.rs     # PostgreSQL tests (new)
```

### Test Runner with Testcontainers

```rust
use testcontainers::{runners::AsyncRunner, ContainerAsync};
use testcontainers_modules::postgres::Postgres;

async fn setup_postgres() -> (ContainerAsync<Postgres>, PostgresStorage) {
    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@localhost:{}/postgres", port);

    let storage = PostgresStorage::new(&url).await.unwrap();
    storage.initialize().await.unwrap();
    (container, storage)
}

#[tokio::test]
async fn postgres_passes_event_store_tests() {
    let (_container, storage) = setup_postgres().await;
    common::run_event_store_tests(&storage).await;
}
```

### CI Configuration

```yaml
postgres-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Run PostgreSQL tests
      run: cargo test -p router-hosts-storage --features postgres --test postgres_backend
```

## Connection String Format

Standard PostgreSQL URL format with optional pool overrides:

```
postgres://user:password@host:5432/dbname
postgres://host/db?sslmode=require
postgres://host/db?max_connections=20&min_connections=5
```

## Acceptance Criteria

- [ ] PostgreSQL backend implements all Storage trait methods
- [ ] Passes all tests in shared test suite
- [ ] Connection pooling with configurable defaults
- [ ] Transactions for atomic operations
- [ ] Feature flag `postgres` for conditional compilation
- [ ] Documentation updated
