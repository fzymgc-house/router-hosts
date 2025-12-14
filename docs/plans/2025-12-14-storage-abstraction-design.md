# Storage Abstraction Design

**Date:** 2025-12-14
**Status:** Draft
**Authors:** Sean (human), Claude (AI)

## Overview

Abstract the database implementation behind interfaces to support multiple backends: DuckDB (default), SQLite (lightweight), and PostgreSQL (clustered deployments).

### Goals

1. **Deployment flexibility** - Run on systems where DuckDB isn't ideal (existing PostgreSQL infrastructure, constrained embedded devices)
2. **Future-proofing** - Enable migration away from DuckDB if needed
3. **Multi-node support** - PostgreSQL for active-passive clustered deployments

### Non-Goals

- Active-active clustering (out of scope)
- NoSQL backends (event sourcing needs ACID)
- Compile-time backend selection (runtime configuration preferred)

## Architecture

### Crate Structure

```
router-hosts/
├── router-hosts-common/     # Proto definitions, validation (unchanged)
├── router-hosts-storage/    # NEW: Storage traits + implementations
│   ├── src/
│   │   ├── lib.rs
│   │   ├── error.rs         # StorageError enum
│   │   ├── traits/
│   │   │   ├── mod.rs
│   │   │   ├── event_store.rs
│   │   │   ├── snapshot_store.rs
│   │   │   └── projection.rs
│   │   ├── backends/
│   │   │   ├── mod.rs
│   │   │   ├── duckdb/
│   │   │   ├── postgres/
│   │   │   └── sqlite/
│   │   └── config.rs        # Connection string parsing
│   └── Cargo.toml
└── router-hosts/            # CLI + server (depends on storage)
```

### Dependency Flow

```
router-hosts-common (proto, validation)
         ↓
router-hosts-storage (traits, backends)
         ↓
router-hosts (CLI, server, gRPC)
```

### Backend Selection

Connection string in config determines backend at runtime:

- `duckdb:///var/lib/router-hosts/data.db`
- `sqlite:///var/lib/router-hosts/data.sqlite`
- `postgres://user:pass@host/dbname`

## Core Traits

### EventStore

```rust
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Append a single event with optimistic concurrency check
    async fn append_event(
        &self,
        aggregate_id: &str,
        event: &HostEvent,
        expected_version: Option<&str>,
    ) -> Result<(), StorageError>;

    /// Append multiple events atomically (all-or-nothing)
    async fn append_events(
        &self,
        aggregate_id: &str,
        events: &[HostEvent],
        expected_version: Option<&str>,
    ) -> Result<(), StorageError>;

    /// Load all events for an aggregate in version order
    async fn load_events(&self, aggregate_id: &str) -> Result<Vec<HostEvent>, StorageError>;

    /// Get the current (latest) event version for an aggregate
    async fn get_current_version(&self, aggregate_id: &str) -> Result<Option<String>, StorageError>;

    /// Count events for an aggregate
    async fn count_events(&self, aggregate_id: &str) -> Result<u64, StorageError>;
}
```

### SnapshotStore

```rust
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    /// Save a snapshot of /etc/hosts state
    async fn save_snapshot(&self, snapshot: &Snapshot) -> Result<(), StorageError>;

    /// Retrieve a specific snapshot by ID
    async fn get_snapshot(&self, snapshot_id: &str) -> Result<Option<Snapshot>, StorageError>;

    /// List all snapshots (metadata only)
    async fn list_snapshots(&self) -> Result<Vec<SnapshotMetadata>, StorageError>;

    /// Delete a specific snapshot
    async fn delete_snapshot(&self, snapshot_id: &str) -> Result<bool, StorageError>;

    /// Apply retention policy (delete old snapshots)
    async fn apply_retention_policy(
        &self,
        max_count: usize,
        max_age: Duration,
    ) -> Result<u64, StorageError>;
}
```

### HostProjection

```rust
#[async_trait]
pub trait HostProjection: Send + Sync {
    /// List all active (non-deleted) host entries
    async fn list_all(&self) -> Result<Vec<HostEntry>, StorageError>;

    /// Get a single host by aggregate ID
    async fn get_by_id(&self, aggregate_id: &str) -> Result<Option<HostEntry>, StorageError>;

    /// Find by IP and hostname (for duplicate detection)
    async fn find_by_ip_and_hostname(
        &self,
        ip: &str,
        hostname: &str,
    ) -> Result<Option<HostEntry>, StorageError>;

    /// Search with filters (IP prefix, hostname pattern, tags)
    async fn search(&self, filter: &HostFilter) -> Result<Vec<HostEntry>, StorageError>;

    /// Time-travel query: state at a specific point in time
    async fn get_at_time(&self, timestamp: DateTime<Utc>) -> Result<Vec<HostEntry>, StorageError>;
}
```

### Unified Storage Trait

```rust
/// Main entry point - combines all storage capabilities
pub trait Storage: EventStore + SnapshotStore + HostProjection {
    /// Initialize schema (create tables, views, indexes if missing)
    async fn initialize(&self) -> Result<(), StorageError>;

    /// Health check (verify connection is alive)
    async fn health_check(&self) -> Result<(), StorageError>;

    /// Close connections gracefully
    async fn close(&self) -> Result<(), StorageError>;
}
```

## Error Handling

```rust
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("concurrent write conflict on aggregate {aggregate_id}")]
    ConcurrentWriteConflict { aggregate_id: String },

    #[error("duplicate entry: {ip} {hostname} already exists")]
    DuplicateEntry { ip: String, hostname: String },

    #[error("not found: {entity_type} with id {id}")]
    NotFound { entity_type: &'static str, id: String },

    #[error("connection failed: {message}")]
    Connection {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    #[error("query failed: {message}")]
    Query {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    #[error("schema migration failed: {message}")]
    Migration {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    #[error("invalid connection string: {0}")]
    InvalidConnectionString(String),
}

type BoxedError = Box<dyn std::error::Error + Send + Sync>;
```

## Configuration

### Connection String Parsing

```rust
pub enum BackendType {
    DuckDb,
    Sqlite,
    Postgres,
}

pub struct StorageConfig {
    pub backend: BackendType,
    pub connection_string: String,
    pub pool_size: Option<usize>,        // PostgreSQL only
    pub busy_timeout: Option<Duration>,  // SQLite only
}

impl StorageConfig {
    pub fn from_url(url: &str) -> Result<Self, StorageError> {
        let parsed = Url::parse(url)
            .map_err(|e| StorageError::InvalidConnectionString(e.to_string()))?;

        let backend = match parsed.scheme() {
            "duckdb" => BackendType::DuckDb,
            "sqlite" => BackendType::Sqlite,
            "postgres" | "postgresql" => BackendType::Postgres,
            scheme => return Err(StorageError::InvalidConnectionString(
                format!("unknown scheme: {scheme}")
            )),
        };

        Ok(Self { backend, connection_string: url.to_string(), ..Default::default() })
    }
}
```

### Factory Function

```rust
pub async fn create_storage(config: &StorageConfig) -> Result<Arc<dyn Storage>, StorageError> {
    let storage: Arc<dyn Storage> = match config.backend {
        BackendType::DuckDb => Arc::new(DuckDbStorage::new(&config.connection_string).await?),
        BackendType::Sqlite => Arc::new(SqliteStorage::new(&config.connection_string).await?),
        BackendType::Postgres => Arc::new(PostgresStorage::new(&config.connection_string).await?),
    };

    storage.initialize().await?;
    Ok(storage)
}
```

### Config File Integration

```toml
[server]
# Connection string determines backend
database_url = "duckdb:///var/lib/router-hosts/data.db"
# or: database_url = "postgres://user:pass@localhost/router_hosts"
# or: database_url = "sqlite:///var/lib/router-hosts/data.sqlite"
```

## Backend Implementations

### DuckDB Backend

```rust
pub struct DuckDbStorage {
    conn: Arc<Mutex<duckdb::Connection>>,  // Single connection, mutex for safety
}

impl DuckDbStorage {
    pub async fn new(url: &str) -> Result<Self, StorageError> {
        let path = parse_duckdb_path(url)?;
        let conn = tokio::task::spawn_blocking(move || {
            duckdb::Connection::open(&path)
        }).await??;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }
}
```

**Schema features:**
- Uses `LAST_VALUE(... IGNORE NULLS)` window functions in views
- Materialized views for efficient current-state queries
- Single connection with mutex (embedded database)

### PostgreSQL Backend

```rust
pub struct PostgresStorage {
    pool: deadpool_postgres::Pool,  // Connection pool
}

impl PostgresStorage {
    pub async fn new(url: &str) -> Result<Self, StorageError> {
        let config = url.parse::<deadpool_postgres::Config>()?;
        let pool = config.create_pool(None, tokio_postgres::NoTls)?;
        Ok(Self { pool })
    }
}
```

**Schema features:**
- Uses equivalent window functions (PostgreSQL has full support)
- Connection pooling via `deadpool-postgres`
- Supports active-passive clustering via streaming replication

### SQLite Backend

```rust
pub struct SqliteStorage {
    conn: Arc<Mutex<rusqlite::Connection>>,  // Single connection
}

impl SqliteStorage {
    pub async fn new(url: &str) -> Result<Self, StorageError> {
        let path = parse_sqlite_path(url)?;
        let conn = tokio::task::spawn_blocking(move || {
            rusqlite::Connection::open(&path)
        }).await??;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }
}
```

**Schema features:**
- Simpler views (SQLite lacks `IGNORE NULLS` in window functions)
- Complex projections rebuild state in Rust via event replay
- Single connection with mutex (embedded database)

### Projection Strategy (Hybrid)

| Method | DuckDB/PostgreSQL | SQLite |
|--------|-------------------|--------|
| `list_all()` | Query materialized view | Query simpler view |
| `get_by_id()` | Replay events in Rust | Replay events in Rust |
| `search()` | SQL WHERE clauses | SQL WHERE clauses |
| `get_at_time()` | Replay events up to timestamp | Replay events up to timestamp |

## Schema Management

Auto-schema on startup with versioned migrations:

```rust
async fn initialize(&self) -> Result<(), StorageError> {
    let version = self.get_schema_version().await?;
    for migration in MIGRATIONS.iter().filter(|m| m.version > version) {
        self.run_migration(migration).await?;
        self.set_schema_version(migration.version).await?;
    }
    Ok(())
}
```

Each backend maintains its own migration SQL files embedded in the binary.

## Testing Strategy

### Shared Test Suite

All backends must pass identical behavioral tests:

```rust
pub async fn run_event_store_tests<S: Storage>(storage: &S) {
    test_append_single_event(storage).await;
    test_append_multiple_events_atomic(storage).await;
    test_optimistic_concurrency_conflict(storage).await;
    test_load_events_in_order(storage).await;
}

pub async fn run_projection_tests<S: Storage>(storage: &S) {
    test_list_all_excludes_deleted(storage).await;
    test_find_by_ip_and_hostname(storage).await;
    test_time_travel_query(storage).await;
}
```

### CI Strategy

- **DuckDB + SQLite:** Run on every PR (in-memory, fast)
- **PostgreSQL:** Run in CI with service container, `#[ignore]` for local dev

## Migration Path

### Phase 1: Extract Traits (Non-breaking)

1. Create `router-hosts-storage` crate
2. Define traits (`EventStore`, `SnapshotStore`, `HostProjection`, `Storage`)
3. Define `StorageError` enum
4. Move existing DuckDB code into `backends/duckdb/`, implement traits
5. Main crate depends on storage, uses `Arc<dyn Storage>`
6. All tests pass, behavior unchanged

### Phase 2: Add SQLite Backend

1. Implement `SqliteStorage` with simpler views
2. Add shared test suite, verify SQLite passes
3. Test runtime switching via connection string
4. Optional: release as minor version

### Phase 3: Add PostgreSQL Backend

1. Implement `PostgresStorage` with connection pooling
2. Add integration tests (CI with PostgreSQL container)
3. Document active-passive clustering setup
4. Release as minor version with new capability

### Server Startup Change

From:
```rust
let db = Database::new(&config.database_path)?;
```

To:
```rust
let storage = create_storage(&config.storage).await?;
```

## Dependencies

### New Dependencies for `router-hosts-storage`

```toml
[dependencies]
async-trait = "0.1"
thiserror = "1.0"
tokio = { version = "1", features = ["rt", "sync"] }
url = "2"
chrono = { version = "0.4", features = ["serde"] }

# DuckDB (always included)
duckdb = { version = "1.0", features = ["bundled"] }

# SQLite (always included - lightweight)
rusqlite = { version = "0.32", features = ["bundled"] }

# PostgreSQL (always included for runtime flexibility)
deadpool-postgres = "0.14"
tokio-postgres = "0.7"
```

## Open Questions

1. **In-memory mode for SQLite/DuckDB:** Should `sqlite://:memory:` and `duckdb://:memory:` be supported for testing?
   - **Recommendation:** Yes, enables fast isolated tests

2. **Connection string secrets:** Should we support environment variable expansion in connection strings (e.g., `postgres://${DB_USER}:${DB_PASS}@host/db`)?
   - **Recommendation:** Defer to config layer, not storage layer

3. **Read replicas:** Should PostgreSQL support separate read/write connection strings for read replicas?
   - **Recommendation:** Out of scope for v1, can add later

## References

- [Current DuckDB implementation](../router-hosts/src/server/db/)
- [Event sourcing design](./2025-12-01-router-hosts-v1-design.md)
- [CQRS pattern](https://martinfowler.com/bliki/CQRS.html)
