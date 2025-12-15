# Storage Abstraction Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extract database layer into `router-hosts-storage` crate with backend-agnostic traits.

**Architecture:** Mid-level repository pattern with async traits. DuckDB backend first, SQLite/PostgreSQL later.

**Tech Stack:** Rust, async-trait, thiserror, tokio, duckdb

---

## Status

| Phase | Task | Status | PR/Issue |
|-------|------|--------|----------|
| 1 | 1.1: Create router-hosts-storage crate | ✅ Complete | PR #99 |
| 1 | 1.2: Create error types | ✅ Complete | PR #99 |
| 1 | 1.3: Create domain types | ✅ Complete | PR #99 |
| 2 | 2.1: Create storage traits | ✅ Complete | PR #99 |
| 2 | 2.2: Create configuration types | ✅ Complete | PR #99 |
| 3 | 3.1: Create DuckDB backend module structure | ✅ Complete | PR #99 |
| 3 | 3.2: Implement DuckDB schema initialization | ✅ Complete | PR #99 |
| 3 | 3.3: Implement DuckDB EventStore trait | ✅ Complete | PR #99 |
| 3 | 3.4: Implement DuckDB SnapshotStore and HostProjection | ✅ Complete | PR #99 |
| 4 | 4.1: Add router-hosts-storage dependency | ✅ Complete | PR #99 |
| 4 | 4.2: Update server to use storage abstraction | ✅ Complete | PR #104 |
| 5 | 5.1: Remove old db module | ✅ Complete | PR #104 |
| 5 | 5.2: Add shared test suite | 🔲 Pending | Issue #102 |

**Last Updated:** 2025-12-15

---

## Phase 1: Create Crate Structure

### Task 1.1: Create router-hosts-storage crate ✅

**Files:**
- Create: `crates/router-hosts-storage/Cargo.toml`
- Create: `crates/router-hosts-storage/src/lib.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "router-hosts-storage"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
description = "Storage abstraction layer for router-hosts"

[dependencies]
# Async
async-trait = "0.1"
tokio = { version = "1", features = ["rt", "sync"] }

# Error handling
thiserror = "1.0"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Time
chrono = { version = "0.4", features = ["serde"] }

# IDs
ulid = "1.1"

# URL parsing
url = "2"

# DuckDB backend (always included)
duckdb = { version = "1.1", features = ["bundled"] }

# Logging
tracing = "0.1"

[dev-dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

**Step 2: Create lib.rs skeleton**

```rust
//! Storage abstraction layer for router-hosts
//!
//! Provides backend-agnostic traits for event sourcing storage.
//! Supports DuckDB (default), with SQLite and PostgreSQL planned.

mod error;
mod types;
mod traits;
mod config;

pub mod backends;

// Re-exports
pub use error::StorageError;
pub use types::{HostEvent, HostEntry, Snapshot, SnapshotMetadata, EventEnvelope};
pub use traits::{EventStore, SnapshotStore, HostProjection, Storage};
pub use config::{StorageConfig, BackendType};

/// Create storage from configuration
pub async fn create_storage(config: &StorageConfig) -> Result<std::sync::Arc<dyn Storage>, StorageError> {
    use backends::duckdb::DuckDbStorage;

    let storage: std::sync::Arc<dyn Storage> = match config.backend {
        BackendType::DuckDb => std::sync::Arc::new(DuckDbStorage::new(&config.connection_string).await?),
        BackendType::Sqlite => return Err(StorageError::InvalidConnectionString("SQLite not yet implemented".into())),
        BackendType::Postgres => return Err(StorageError::InvalidConnectionString("PostgreSQL not yet implemented".into())),
    };

    storage.initialize().await?;
    Ok(storage)
}
```

**Step 3: Add to workspace Cargo.toml**

Edit `Cargo.toml` (workspace root) to add member:

```toml
members = [
    "crates/router-hosts",
    "crates/router-hosts-common",
    "crates/router-hosts-e2e",
    "crates/router-hosts-storage",  # Add this line
]
```

**Step 4: Run cargo check**

Run: `cargo check -p router-hosts-storage`
Expected: Errors about missing modules (that's fine, we'll create them next)

**Step 5: Commit**

```bash
git add crates/router-hosts-storage/Cargo.toml crates/router-hosts-storage/src/lib.rs Cargo.toml
git commit -m "feat(storage): scaffold router-hosts-storage crate

Add new crate for storage abstraction layer.
Includes Cargo.toml with dependencies and lib.rs skeleton.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 1.2: Create error types ✅

**Files:**
- Create: `crates/router-hosts-storage/src/error.rs`

**Step 1: Write error.rs**

```rust
//! Storage error types

use std::error::Error as StdError;
use thiserror::Error;

/// Boxed error for wrapping backend-specific errors
pub type BoxedError = Box<dyn StdError + Send + Sync>;

/// Storage layer errors
#[derive(Debug, Error)]
pub enum StorageError {
    /// Optimistic concurrency conflict
    #[error("concurrent write conflict on aggregate {aggregate_id}")]
    ConcurrentWriteConflict { aggregate_id: String },

    /// Duplicate IP+hostname entry
    #[error("duplicate entry: {ip} {hostname} already exists")]
    DuplicateEntry { ip: String, hostname: String },

    /// Entity not found
    #[error("not found: {entity_type} with id {id}")]
    NotFound {
        entity_type: &'static str,
        id: String,
    },

    /// Connection failure
    #[error("connection failed: {message}")]
    Connection {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    /// Query execution failure
    #[error("query failed: {message}")]
    Query {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    /// Schema migration failure
    #[error("schema migration failed: {message}")]
    Migration {
        message: String,
        #[source]
        source: Option<BoxedError>,
    },

    /// Invalid connection string
    #[error("invalid connection string: {0}")]
    InvalidConnectionString(String),

    /// Invalid data (corruption or format error)
    #[error("invalid data: {0}")]
    InvalidData(String),
}

impl StorageError {
    /// Create a connection error with source
    pub fn connection(message: impl Into<String>, source: impl StdError + Send + Sync + 'static) -> Self {
        Self::Connection {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a query error with source
    pub fn query(message: impl Into<String>, source: impl StdError + Send + Sync + 'static) -> Self {
        Self::Query {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a migration error with source
    pub fn migration(message: impl Into<String>, source: impl StdError + Send + Sync + 'static) -> Self {
        Self::Migration {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p router-hosts-storage`
Expected: Still errors for missing modules

**Step 3: Commit**

```bash
git add crates/router-hosts-storage/src/error.rs
git commit -m "feat(storage): add StorageError types

Define unified error enum with variants for concurrency conflicts,
duplicates, not found, connection, query, migration, and data errors.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 1.3: Create domain types ✅

**Files:**
- Create: `crates/router-hosts-storage/src/types.rs`

**Step 1: Write types.rs**

Copy and adapt from existing `events.rs` and `projections.rs`:

```rust
//! Domain types for storage layer

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Domain events for host entries (event sourcing pattern)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum HostEvent {
    /// A new host entry was created
    HostCreated {
        ip_address: String,
        hostname: String,
        comment: Option<String>,
        tags: Vec<String>,
        created_at: DateTime<Utc>,
    },

    /// Host IP address was changed
    IpAddressChanged {
        old_ip: String,
        new_ip: String,
        changed_at: DateTime<Utc>,
    },

    /// Host hostname was changed
    HostnameChanged {
        old_hostname: String,
        new_hostname: String,
        changed_at: DateTime<Utc>,
    },

    /// Host comment was updated
    CommentUpdated {
        old_comment: Option<String>,
        new_comment: Option<String>,
        updated_at: DateTime<Utc>,
    },

    /// Host tags were modified
    TagsModified {
        old_tags: Vec<String>,
        new_tags: Vec<String>,
        modified_at: DateTime<Utc>,
    },

    /// Host entry was deleted (tombstone)
    HostDeleted {
        ip_address: String,
        hostname: String,
        deleted_at: DateTime<Utc>,
        reason: Option<String>,
    },
}

impl HostEvent {
    /// Get the event type name
    pub fn event_type(&self) -> &'static str {
        match self {
            HostEvent::HostCreated { .. } => "HostCreated",
            HostEvent::IpAddressChanged { .. } => "IpAddressChanged",
            HostEvent::HostnameChanged { .. } => "HostnameChanged",
            HostEvent::CommentUpdated { .. } => "CommentUpdated",
            HostEvent::TagsModified { .. } => "TagsModified",
            HostEvent::HostDeleted { .. } => "HostDeleted",
        }
    }

    /// Get the timestamp when this event occurred
    pub fn occurred_at(&self) -> DateTime<Utc> {
        match self {
            HostEvent::HostCreated { created_at, .. } => *created_at,
            HostEvent::IpAddressChanged { changed_at, .. } => *changed_at,
            HostEvent::HostnameChanged { changed_at, .. } => *changed_at,
            HostEvent::CommentUpdated { updated_at, .. } => *updated_at,
            HostEvent::TagsModified { modified_at, .. } => *modified_at,
            HostEvent::HostDeleted { deleted_at, .. } => *deleted_at,
        }
    }
}

/// Envelope wrapping an event with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// K-sortable event identifier (ULID)
    pub event_id: Ulid,
    /// Aggregate root identifier
    pub aggregate_id: Ulid,
    /// The domain event
    pub event: HostEvent,
    /// ULID version for optimistic concurrency
    pub event_version: String,
    /// When this envelope was created
    pub created_at: DateTime<Utc>,
    /// Who created this event
    pub created_by: Option<String>,
}

/// Read model for current host entries (CQRS Query side)
#[derive(Debug, Clone, PartialEq)]
pub struct HostEntry {
    pub id: Ulid,
    pub ip_address: String,
    pub hostname: String,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// ULID version identifier for optimistic locking
    pub version: String,
}

/// Snapshot of hosts file at a point in time
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub snapshot_id: String,
    pub created_at: DateTime<Utc>,
    pub hosts_content: String,
    pub entry_count: i32,
    pub trigger: String,
    pub name: Option<String>,
    pub event_log_position: Option<i64>,
}

/// Snapshot metadata (without content, for listing)
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotMetadata {
    pub snapshot_id: String,
    pub created_at: DateTime<Utc>,
    pub entry_count: i32,
    pub trigger: String,
    pub name: Option<String>,
}

impl From<Snapshot> for SnapshotMetadata {
    fn from(s: Snapshot) -> Self {
        Self {
            snapshot_id: s.snapshot_id,
            created_at: s.created_at,
            entry_count: s.entry_count,
            trigger: s.trigger,
            name: s.name,
        }
    }
}

/// Filter for searching hosts
#[derive(Debug, Clone, Default)]
pub struct HostFilter {
    /// Filter by IP address pattern
    pub ip_pattern: Option<String>,
    /// Filter by hostname pattern
    pub hostname_pattern: Option<String>,
    /// Filter by tags (any match)
    pub tags: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_names() {
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.1".into(),
            hostname: "test.local".into(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };
        assert_eq!(event.event_type(), "HostCreated");
    }

    #[test]
    fn test_event_serialization() {
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.10".into(),
            hostname: "server.local".into(),
            comment: Some("Test".into()),
            tags: vec!["prod".into()],
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deser: HostEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deser);
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p router-hosts-storage`
Expected: Still errors for missing modules (traits, config, backends)

**Step 3: Commit**

```bash
git add crates/router-hosts-storage/src/types.rs
git commit -m "feat(storage): add domain types

Add HostEvent, EventEnvelope, HostEntry, Snapshot, SnapshotMetadata,
and HostFilter types for the storage abstraction layer.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Phase 2: Define Core Traits

### Task 2.1: Create storage traits ✅

**Files:**
- Create: `crates/router-hosts-storage/src/traits.rs`

**Step 1: Write traits.rs**

```rust
//! Storage trait definitions

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::time::Duration;

use crate::error::StorageError;
use crate::types::{EventEnvelope, HostEntry, HostEvent, HostFilter, Snapshot, SnapshotMetadata};

/// Event store for persisting domain events (CQRS write side)
#[async_trait]
pub trait EventStore: Send + Sync {
    /// Append a single event with optimistic concurrency check
    ///
    /// # Arguments
    /// * `aggregate_id` - ID of the aggregate (host entry)
    /// * `event` - Domain event to store
    /// * `expected_version` - Expected current version (None for new aggregate)
    /// * `created_by` - Optional user/system identifier
    async fn append_event(
        &self,
        aggregate_id: &str,
        event: HostEvent,
        expected_version: Option<&str>,
        created_by: Option<String>,
    ) -> Result<EventEnvelope, StorageError>;

    /// Append multiple events atomically
    async fn append_events(
        &self,
        aggregate_id: &str,
        events: Vec<HostEvent>,
        expected_version: Option<&str>,
        created_by: Option<String>,
    ) -> Result<Vec<EventEnvelope>, StorageError>;

    /// Load all events for an aggregate in version order
    async fn load_events(&self, aggregate_id: &str) -> Result<Vec<EventEnvelope>, StorageError>;

    /// Get the current (latest) event version for an aggregate
    async fn get_current_version(&self, aggregate_id: &str) -> Result<Option<String>, StorageError>;

    /// Count events for an aggregate
    async fn count_events(&self, aggregate_id: &str) -> Result<u64, StorageError>;
}

/// Snapshot store for /etc/hosts versioning
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    /// Save a snapshot
    async fn save_snapshot(&self, snapshot: &Snapshot) -> Result<(), StorageError>;

    /// Get a specific snapshot by ID
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

/// Host projection queries (CQRS read side)
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

    /// Search with filters
    async fn search(&self, filter: &HostFilter) -> Result<Vec<HostEntry>, StorageError>;

    /// Time-travel query: state at a specific point in time
    async fn get_at_time(
        &self,
        aggregate_id: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<Option<HostEntry>, StorageError>;
}

/// Combined storage interface
#[async_trait]
pub trait Storage: EventStore + SnapshotStore + HostProjection {
    /// Initialize schema (create tables, views, indexes)
    async fn initialize(&self) -> Result<(), StorageError>;

    /// Health check
    async fn health_check(&self) -> Result<(), StorageError>;

    /// Close connections gracefully
    async fn close(&self) -> Result<(), StorageError>;
}
```

**Step 2: Run cargo check**

Run: `cargo check -p router-hosts-storage`
Expected: Errors for missing config and backends modules

**Step 3: Commit**

```bash
git add crates/router-hosts-storage/src/traits.rs
git commit -m "feat(storage): define storage traits

Add EventStore, SnapshotStore, HostProjection, and Storage traits
with async methods for backend-agnostic storage operations.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 2.2: Create configuration types ✅

**Files:**
- Create: `crates/router-hosts-storage/src/config.rs`

**Step 1: Write config.rs**

```rust
//! Storage configuration

use url::Url;
use crate::error::StorageError;

/// Supported database backends
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    DuckDb,
    Sqlite,
    Postgres,
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Backend type
    pub backend: BackendType,
    /// Full connection string
    pub connection_string: String,
    /// Pool size (PostgreSQL only)
    pub pool_size: Option<usize>,
}

impl StorageConfig {
    /// Parse configuration from a connection URL
    ///
    /// Supported schemes:
    /// - `duckdb:///path/to/db` or `duckdb://:memory:`
    /// - `sqlite:///path/to/db` or `sqlite://:memory:`
    /// - `postgres://user:pass@host/dbname`
    pub fn from_url(url: &str) -> Result<Self, StorageError> {
        // Handle special :memory: case
        if url == "duckdb://:memory:" || url.starts_with("duckdb://:memory:") {
            return Ok(Self {
                backend: BackendType::DuckDb,
                connection_string: url.to_string(),
                pool_size: None,
            });
        }
        if url == "sqlite://:memory:" || url.starts_with("sqlite://:memory:") {
            return Ok(Self {
                backend: BackendType::Sqlite,
                connection_string: url.to_string(),
                pool_size: None,
            });
        }

        let parsed = Url::parse(url).map_err(|e| {
            StorageError::InvalidConnectionString(format!("invalid URL: {}", e))
        })?;

        let backend = match parsed.scheme() {
            "duckdb" => BackendType::DuckDb,
            "sqlite" => BackendType::Sqlite,
            "postgres" | "postgresql" => BackendType::Postgres,
            scheme => {
                return Err(StorageError::InvalidConnectionString(format!(
                    "unknown scheme: {}",
                    scheme
                )))
            }
        };

        let pool_size = if backend == BackendType::Postgres {
            // Parse pool_size from query params if present
            parsed
                .query_pairs()
                .find(|(k, _)| k == "pool_size")
                .and_then(|(_, v)| v.parse().ok())
        } else {
            None
        };

        Ok(Self {
            backend,
            connection_string: url.to_string(),
            pool_size,
        })
    }

    /// Create in-memory DuckDB config (for testing)
    pub fn duckdb_memory() -> Self {
        Self {
            backend: BackendType::DuckDb,
            connection_string: "duckdb://:memory:".to_string(),
            pool_size: None,
        }
    }

    /// Create file-based DuckDB config
    pub fn duckdb_file(path: &str) -> Self {
        Self {
            backend: BackendType::DuckDb,
            connection_string: format!("duckdb:///{}", path),
            pool_size: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::duckdb_memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duckdb_memory() {
        let config = StorageConfig::from_url("duckdb://:memory:").unwrap();
        assert_eq!(config.backend, BackendType::DuckDb);
    }

    #[test]
    fn test_parse_duckdb_file() {
        let config = StorageConfig::from_url("duckdb:///var/lib/data.db").unwrap();
        assert_eq!(config.backend, BackendType::DuckDb);
    }

    #[test]
    fn test_parse_postgres() {
        let config = StorageConfig::from_url("postgres://user:pass@localhost/db").unwrap();
        assert_eq!(config.backend, BackendType::Postgres);
    }

    #[test]
    fn test_parse_postgres_with_pool() {
        let config = StorageConfig::from_url("postgres://localhost/db?pool_size=10").unwrap();
        assert_eq!(config.backend, BackendType::Postgres);
        assert_eq!(config.pool_size, Some(10));
    }

    #[test]
    fn test_parse_invalid_scheme() {
        let result = StorageConfig::from_url("mysql://localhost/db");
        assert!(result.is_err());
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p router-hosts-storage`
Expected: Error for missing backends module

**Step 3: Commit**

```bash
git add crates/router-hosts-storage/src/config.rs
git commit -m "feat(storage): add configuration types

Add BackendType enum and StorageConfig with URL parsing
for duckdb, sqlite, and postgres connection strings.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Phase 3: DuckDB Backend

### Task 3.1: Create DuckDB backend module structure ✅

**Files:**
- Create: `crates/router-hosts-storage/src/backends/mod.rs`
- Create: `crates/router-hosts-storage/src/backends/duckdb/mod.rs`

**Step 1: Create backends/mod.rs**

```rust
//! Storage backend implementations

pub mod duckdb;
```

**Step 2: Create backends/duckdb/mod.rs skeleton**

```rust
//! DuckDB storage backend

mod schema;
mod event_store;
mod snapshot_store;
mod projection;

use async_trait::async_trait;
use parking_lot::Mutex;
use std::sync::Arc;

use crate::error::StorageError;
use crate::traits::Storage;

/// DuckDB storage implementation
pub struct DuckDbStorage {
    conn: Arc<Mutex<duckdb::Connection>>,
}

impl DuckDbStorage {
    /// Create new DuckDB storage from connection string
    pub async fn new(url: &str) -> Result<Self, StorageError> {
        let path = Self::parse_path(url)?;

        let conn = tokio::task::spawn_blocking(move || {
            if path == ":memory:" {
                duckdb::Connection::open_in_memory()
            } else {
                duckdb::Connection::open(&path)
            }
        })
        .await
        .map_err(|e| StorageError::Connection {
            message: format!("spawn_blocking failed: {}", e),
            source: None,
        })?
        .map_err(|e| StorageError::connection("failed to open database", e))?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Parse path from duckdb:// URL
    fn parse_path(url: &str) -> Result<String, StorageError> {
        if url == "duckdb://:memory:" {
            return Ok(":memory:".to_string());
        }

        let stripped = url
            .strip_prefix("duckdb://")
            .ok_or_else(|| StorageError::InvalidConnectionString("missing duckdb:// prefix".into()))?;

        // Handle file paths (duckdb:///path/to/file -> /path/to/file)
        if let Some(path) = stripped.strip_prefix('/') {
            Ok(format!("/{}", path))
        } else {
            Ok(stripped.to_string())
        }
    }

    /// Get connection for internal use
    pub(crate) fn conn(&self) -> parking_lot::MutexGuard<'_, duckdb::Connection> {
        self.conn.lock()
    }
}

#[async_trait]
impl Storage for DuckDbStorage {
    async fn initialize(&self) -> Result<(), StorageError> {
        schema::initialize_schema(self).await
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            guard.execute("SELECT 1", [])
        })
        .await
        .map_err(|e| StorageError::Query {
            message: format!("health check failed: {}", e),
            source: None,
        })?
        .map_err(|e| StorageError::query("health check failed", e))?;
        Ok(())
    }

    async fn close(&self) -> Result<(), StorageError> {
        // DuckDB connection closes on drop, nothing explicit needed
        Ok(())
    }
}
```

**Step 3: Run cargo check**

Run: `cargo check -p router-hosts-storage`
Expected: Errors for missing schema, event_store, etc.

**Step 4: Commit**

```bash
git add crates/router-hosts-storage/src/backends/
git commit -m "feat(storage): add DuckDB backend skeleton

Create DuckDbStorage struct with connection handling
and Storage trait implementation skeleton.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 3.2: Implement DuckDB schema initialization ✅

**Files:**
- Create: `crates/router-hosts-storage/src/backends/duckdb/schema.rs`

**Step 1: Write schema.rs**

Adapt from existing `crates/router-hosts/src/server/db/schema.rs`:

```rust
//! DuckDB schema initialization

use crate::error::StorageError;
use super::DuckDbStorage;

/// Initialize the event-sourced schema
pub async fn initialize_schema(storage: &DuckDbStorage) -> Result<(), StorageError> {
    let conn = storage.conn.clone();

    tokio::task::spawn_blocking(move || {
        let guard = conn.lock();

        // Event store table
        guard.execute(
            r#"
            CREATE TABLE IF NOT EXISTS host_events (
                event_id VARCHAR PRIMARY KEY,
                aggregate_id VARCHAR NOT NULL,
                event_type VARCHAR NOT NULL,
                event_version VARCHAR NOT NULL,
                ip_address VARCHAR,
                hostname VARCHAR,
                comment VARCHAR,
                tags VARCHAR,
                event_timestamp TIMESTAMP NOT NULL,
                metadata VARCHAR NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR,
                expected_version VARCHAR,
                UNIQUE(aggregate_id, event_version)
            )
            "#,
            [],
        )?;

        // Index for fast event replay
        guard.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_aggregate ON host_events(aggregate_id, event_version)",
            [],
        )?;

        // Index for temporal queries
        guard.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_time ON host_events(created_at)",
            [],
        )?;

        // Current hosts view with LAST_VALUE IGNORE NULLS
        guard.execute(
            r#"
            CREATE VIEW IF NOT EXISTS host_entries_current AS
            WITH windowed AS (
                SELECT
                    aggregate_id,
                    event_version,
                    event_type,
                    LAST_VALUE(ip_address IGNORE NULLS) OVER (
                        PARTITION BY aggregate_id ORDER BY event_version
                        ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                    ) as ip_address,
                    LAST_VALUE(hostname IGNORE NULLS) OVER (
                        PARTITION BY aggregate_id ORDER BY event_version
                        ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                    ) as hostname,
                    LAST_VALUE(comment IGNORE NULLS) OVER (
                        PARTITION BY aggregate_id ORDER BY event_version
                        ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                    ) as comment,
                    LAST_VALUE(tags IGNORE NULLS) OVER (
                        PARTITION BY aggregate_id ORDER BY event_version
                        ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                    ) as tags,
                    FIRST_VALUE(event_timestamp) OVER (
                        PARTITION BY aggregate_id ORDER BY event_version
                        ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                    ) as created_at,
                    LAST_VALUE(created_at) OVER (
                        PARTITION BY aggregate_id ORDER BY event_version
                        ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                    ) as updated_at,
                    LAST_VALUE(event_type) OVER (
                        PARTITION BY aggregate_id ORDER BY event_version
                        ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                    ) as latest_event_type,
                    ROW_NUMBER() OVER (PARTITION BY aggregate_id ORDER BY event_version DESC) as rn
                FROM host_events
            )
            SELECT
                aggregate_id as id,
                CAST(ip_address AS VARCHAR) as ip_address,
                hostname,
                comment,
                tags,
                CAST(EXTRACT(EPOCH FROM created_at) * 1000000 AS BIGINT) as created_at,
                CAST(EXTRACT(EPOCH FROM updated_at) * 1000000 AS BIGINT) as updated_at,
                event_version
            FROM windowed
            WHERE rn = 1
              AND latest_event_type != 'HostDeleted'
            "#,
            [],
        )?;

        // History view
        guard.execute(
            r#"
            CREATE VIEW IF NOT EXISTS host_entries_history AS
            SELECT
                event_id,
                aggregate_id,
                event_type,
                event_version,
                ip_address,
                hostname,
                metadata,
                event_timestamp,
                created_at
            FROM host_events
            ORDER BY aggregate_id, event_version
            "#,
            [],
        )?;

        // Snapshots table
        guard.execute(
            r#"
            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id VARCHAR PRIMARY KEY,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                hosts_content TEXT NOT NULL,
                entry_count INTEGER NOT NULL,
                trigger VARCHAR NOT NULL,
                name VARCHAR,
                event_log_position INTEGER
            )
            "#,
            [],
        )?;

        Ok::<_, duckdb::Error>(())
    })
    .await
    .map_err(|e| StorageError::Migration {
        message: format!("spawn_blocking failed: {}", e),
        source: None,
    })?
    .map_err(|e| StorageError::migration("schema initialization failed", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_schema_initialization() {
        let storage = DuckDbStorage::new("duckdb://:memory:").await.unwrap();
        storage.initialize().await.unwrap();

        // Verify tables exist
        let conn = storage.conn();
        let count: i32 = conn
            .query_row("SELECT COUNT(*) FROM host_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p router-hosts-storage`
Expected: Errors for missing event_store, snapshot_store, projection

**Step 3: Commit**

```bash
git add crates/router-hosts-storage/src/backends/duckdb/schema.rs
git commit -m "feat(storage): implement DuckDB schema initialization

Add schema.rs with event store table, views for current hosts
(using LAST_VALUE IGNORE NULLS), and snapshots table.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 3.3: Implement DuckDB EventStore trait ✅

**Files:**
- Create: `crates/router-hosts-storage/src/backends/duckdb/event_store.rs`

**Step 1: Write event_store.rs**

Adapt from existing code (this is a large file, key methods shown):

```rust
//! DuckDB EventStore implementation

use async_trait::async_trait;
use chrono::Utc;
use duckdb::OptionalExt;
use tracing::error;
use ulid::Ulid;

use crate::error::StorageError;
use crate::traits::EventStore;
use crate::types::{EventEnvelope, HostEvent};
use super::DuckDbStorage;

/// Internal event data for JSON serialization
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct EventData {
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted_reason: Option<String>,
}

#[async_trait]
impl EventStore for DuckDbStorage {
    async fn append_event(
        &self,
        aggregate_id: &str,
        event: HostEvent,
        expected_version: Option<&str>,
        created_by: Option<String>,
    ) -> Result<EventEnvelope, StorageError> {
        let conn = self.conn.clone();
        let aggregate_id = aggregate_id.to_string();
        let expected_version = expected_version.map(|s| s.to_string());

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            append_event_sync(&guard, &aggregate_id, event, expected_version.as_deref(), created_by)
        })
        .await
        .map_err(|e| StorageError::Query {
            message: format!("spawn_blocking failed: {}", e),
            source: None,
        })?
    }

    async fn append_events(
        &self,
        aggregate_id: &str,
        events: Vec<HostEvent>,
        expected_version: Option<&str>,
        created_by: Option<String>,
    ) -> Result<Vec<EventEnvelope>, StorageError> {
        if events.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.conn.clone();
        let aggregate_id = aggregate_id.to_string();
        let expected_version = expected_version.map(|s| s.to_string());

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            append_events_sync(&guard, &aggregate_id, events, expected_version.as_deref(), created_by)
        })
        .await
        .map_err(|e| StorageError::Query {
            message: format!("spawn_blocking failed: {}", e),
            source: None,
        })?
    }

    async fn load_events(&self, aggregate_id: &str) -> Result<Vec<EventEnvelope>, StorageError> {
        let conn = self.conn.clone();
        let aggregate_id = aggregate_id.to_string();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            load_events_sync(&guard, &aggregate_id)
        })
        .await
        .map_err(|e| StorageError::Query {
            message: format!("spawn_blocking failed: {}", e),
            source: None,
        })?
    }

    async fn get_current_version(&self, aggregate_id: &str) -> Result<Option<String>, StorageError> {
        let conn = self.conn.clone();
        let aggregate_id = aggregate_id.to_string();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            get_current_version_sync(&guard, &aggregate_id)
        })
        .await
        .map_err(|e| StorageError::Query {
            message: format!("spawn_blocking failed: {}", e),
            source: None,
        })?
    }

    async fn count_events(&self, aggregate_id: &str) -> Result<u64, StorageError> {
        let conn = self.conn.clone();
        let aggregate_id = aggregate_id.to_string();

        tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            let count: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM host_events WHERE aggregate_id = ?",
                    [&aggregate_id],
                    |row| row.get(0),
                )
                .map_err(|e| StorageError::query("count_events failed", e))?;
            Ok(count as u64)
        })
        .await
        .map_err(|e| StorageError::Query {
            message: format!("spawn_blocking failed: {}", e),
            source: None,
        })?
    }
}

// Synchronous helper functions (called within spawn_blocking)
// These are adapted from the existing event_store.rs implementation

fn get_current_version_sync(
    conn: &duckdb::Connection,
    aggregate_id: &str,
) -> Result<Option<String>, StorageError> {
    let version = conn
        .query_row(
            "SELECT event_version FROM host_events WHERE aggregate_id = ? ORDER BY event_version DESC LIMIT 1",
            [aggregate_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(|e| StorageError::query("get_current_version failed", e))?;
    Ok(version.flatten())
}

fn rollback_and_return(conn: &duckdb::Connection, error: StorageError) -> StorageError {
    if let Err(e) = conn.execute("ROLLBACK", []) {
        error!("Rollback failed after error '{}': {}", error, e);
        StorageError::Query {
            message: format!("Original: {}; Rollback failed: {}", error, e),
            source: None,
        }
    } else {
        error
    }
}

fn append_event_sync(
    conn: &duckdb::Connection,
    aggregate_id: &str,
    event: HostEvent,
    expected_version: Option<&str>,
    created_by: Option<String>,
) -> Result<EventEnvelope, StorageError> {
    // Begin transaction
    conn.execute("BEGIN TRANSACTION", [])
        .map_err(|e| StorageError::query("begin transaction failed", e))?;

    // Check for duplicate on HostCreated
    if let HostEvent::HostCreated { ip_address, hostname, .. } = &event {
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM host_entries_current WHERE ip_address = ? AND hostname = ?)",
                [ip_address.as_str(), hostname.as_str()],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if exists {
            return Err(rollback_and_return(
                conn,
                StorageError::DuplicateEntry {
                    ip: ip_address.clone(),
                    hostname: hostname.clone(),
                },
            ));
        }
    }

    // Version check
    let current = get_current_version_sync(conn, aggregate_id)
        .map_err(|e| rollback_and_return(conn, e))?;

    if expected_version != current.as_deref() {
        return Err(rollback_and_return(
            conn,
            StorageError::ConcurrentWriteConflict {
                aggregate_id: aggregate_id.to_string(),
            },
        ));
    }

    // Generate IDs
    use std::time::SystemTime;
    let mut gen = ulid::Generator::new();
    let ts = SystemTime::now();
    let new_version = gen.generate_from_datetime(ts)
        .map_err(|e| StorageError::InvalidData(format!("ULID generation failed: {}", e)))?
        .to_string();
    let event_id = gen.generate_from_datetime(ts)
        .map_err(|e| StorageError::InvalidData(format!("ULID generation failed: {}", e)))?;
    let now = Utc::now();

    // Build event data
    let (ip_opt, hostname_opt, comment_opt, tags_opt, event_ts, event_data) = extract_event_columns(&event);
    let event_data_json = serde_json::to_string(&event_data)
        .map_err(|e| StorageError::InvalidData(format!("JSON serialization failed: {}", e)))?;

    // Insert
    conn.execute(
        r#"
        INSERT INTO host_events (
            event_id, aggregate_id, event_type, event_version,
            ip_address, hostname, comment, tags,
            event_timestamp, metadata,
            created_at, created_by, expected_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, to_timestamp(?::BIGINT / 1000000.0), ?, to_timestamp(?::BIGINT / 1000000.0), ?, ?)
        "#,
        [
            &event_id.to_string() as &dyn duckdb::ToSql,
            &aggregate_id,
            &event.event_type(),
            &new_version,
            &ip_opt as &dyn duckdb::ToSql,
            &hostname_opt as &dyn duckdb::ToSql,
            &comment_opt as &dyn duckdb::ToSql,
            &tags_opt as &dyn duckdb::ToSql,
            &event_ts.timestamp_micros(),
            &event_data_json,
            &now.timestamp_micros(),
            &created_by.as_deref().unwrap_or("system"),
            &expected_version,
        ],
    )
    .map_err(|e| {
        let msg = e.to_string();
        let err = if msg.contains("UNIQUE") {
            StorageError::ConcurrentWriteConflict { aggregate_id: aggregate_id.to_string() }
        } else {
            StorageError::query("insert event failed", e)
        };
        rollback_and_return(conn, err)
    })?;

    // Commit
    conn.execute("COMMIT", [])
        .map_err(|e| StorageError::query("commit failed", e))?;

    let agg_ulid = Ulid::from_string(aggregate_id)
        .map_err(|e| StorageError::InvalidData(format!("invalid aggregate_id: {}", e)))?;

    Ok(EventEnvelope {
        event_id,
        aggregate_id: agg_ulid,
        event,
        event_version: new_version,
        created_at: now,
        created_by,
    })
}

fn append_events_sync(
    conn: &duckdb::Connection,
    aggregate_id: &str,
    events: Vec<HostEvent>,
    expected_version: Option<&str>,
    created_by: Option<String>,
) -> Result<Vec<EventEnvelope>, StorageError> {
    // Similar to append_event_sync but for multiple events
    // Implementation follows same pattern with loop
    // (Abbreviated for plan - full implementation copies existing logic)

    conn.execute("BEGIN TRANSACTION", [])
        .map_err(|e| StorageError::query("begin transaction failed", e))?;

    let current = get_current_version_sync(conn, aggregate_id)
        .map_err(|e| rollback_and_return(conn, e))?;

    if expected_version != current.as_deref() {
        return Err(rollback_and_return(
            conn,
            StorageError::ConcurrentWriteConflict { aggregate_id: aggregate_id.to_string() },
        ));
    }

    let mut envelopes = Vec::with_capacity(events.len());
    let now = Utc::now();

    use std::time::SystemTime;
    let mut gen = ulid::Generator::new();
    let batch_ts = SystemTime::now();

    let agg_ulid = Ulid::from_string(aggregate_id)
        .map_err(|e| StorageError::InvalidData(format!("invalid aggregate_id: {}", e)))?;

    for event in events {
        let version = gen.generate_from_datetime(batch_ts)
            .map_err(|e| StorageError::InvalidData(format!("ULID failed: {}", e)))?
            .to_string();
        let event_id = gen.generate_from_datetime(batch_ts)
            .map_err(|e| StorageError::InvalidData(format!("ULID failed: {}", e)))?;

        let (ip_opt, hostname_opt, comment_opt, tags_opt, event_ts, event_data) = extract_event_columns(&event);
        let event_data_json = serde_json::to_string(&event_data)
            .map_err(|e| rollback_and_return(conn, StorageError::InvalidData(format!("JSON failed: {}", e))))?;

        conn.execute(
            r#"
            INSERT INTO host_events (
                event_id, aggregate_id, event_type, event_version,
                ip_address, hostname, comment, tags,
                event_timestamp, metadata,
                created_at, created_by, expected_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, to_timestamp(?::BIGINT / 1000000.0), ?, to_timestamp(?::BIGINT / 1000000.0), ?, ?)
            "#,
            [
                &event_id.to_string() as &dyn duckdb::ToSql,
                &aggregate_id,
                &event.event_type(),
                &version,
                &ip_opt as &dyn duckdb::ToSql,
                &hostname_opt as &dyn duckdb::ToSql,
                &comment_opt as &dyn duckdb::ToSql,
                &tags_opt as &dyn duckdb::ToSql,
                &event_ts.timestamp_micros(),
                &event_data_json,
                &now.timestamp_micros(),
                &created_by.as_deref().unwrap_or("system"),
                &expected_version,
            ],
        )
        .map_err(|e| {
            let msg = e.to_string();
            let err = if msg.contains("UNIQUE") {
                StorageError::ConcurrentWriteConflict { aggregate_id: aggregate_id.to_string() }
            } else {
                StorageError::query("insert event failed", e)
            };
            rollback_and_return(conn, err)
        })?;

        envelopes.push(EventEnvelope {
            event_id,
            aggregate_id: agg_ulid,
            event,
            event_version: version,
            created_at: now,
            created_by: created_by.clone(),
        });
    }

    conn.execute("COMMIT", [])
        .map_err(|e| StorageError::query("commit failed", e))?;

    Ok(envelopes)
}

fn load_events_sync(
    conn: &duckdb::Connection,
    aggregate_id: &str,
) -> Result<Vec<EventEnvelope>, StorageError> {
    // Implementation from existing load_events
    // (Abbreviated for plan - full implementation copies existing logic)
    let mut stmt = conn
        .prepare(
            r#"
            SELECT
                event_id, aggregate_id, event_type, event_version,
                CAST(ip_address AS VARCHAR), hostname,
                CAST(metadata AS VARCHAR), event_timestamp,
                created_at, created_by
            FROM host_events
            WHERE aggregate_id = ?
            ORDER BY event_version ASC
            "#,
        )
        .map_err(|e| StorageError::query("prepare failed", e))?;

    let rows = stmt
        .query_map([aggregate_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(|e| StorageError::query("query failed", e))?;

    let mut envelopes = Vec::new();

    for row in rows {
        let (event_id_str, agg_str, event_type, version, ip, hostname, metadata_json, event_ts_micros, created_at_micros, created_by) =
            row.map_err(|e| StorageError::query("row read failed", e))?;

        let event_id = Ulid::from_string(&event_id_str)
            .map_err(|e| StorageError::InvalidData(format!("invalid event_id: {}", e)))?;
        let agg_ulid = Ulid::from_string(&agg_str)
            .map_err(|e| StorageError::InvalidData(format!("invalid aggregate_id: {}", e)))?;

        let event_data: EventData = serde_json::from_str(&metadata_json)
            .map_err(|e| StorageError::InvalidData(format!("JSON parse failed: {}", e)))?;

        let event_ts = chrono::DateTime::from_timestamp_micros(event_ts_micros)
            .ok_or_else(|| StorageError::InvalidData("invalid event_timestamp".into()))?;

        let event = reconstruct_event(&event_type, ip, hostname, event_ts, &event_data)?;

        let created_at = chrono::DateTime::from_timestamp_micros(created_at_micros)
            .ok_or_else(|| StorageError::InvalidData("invalid created_at".into()))?;

        envelopes.push(EventEnvelope {
            event_id,
            aggregate_id: agg_ulid,
            event,
            event_version: version,
            created_at,
            created_by: if created_by == "system" { None } else { Some(created_by) },
        });
    }

    Ok(envelopes)
}

fn extract_event_columns(event: &HostEvent) -> (Option<String>, Option<String>, Option<String>, Option<String>, chrono::DateTime<Utc>, EventData) {
    match event {
        HostEvent::HostCreated { ip_address, hostname, comment, tags, created_at } => (
            Some(ip_address.clone()),
            Some(hostname.clone()),
            Some(comment.clone().unwrap_or_default()),
            Some(serde_json::to_string(tags).unwrap_or_else(|_| "[]".into())),
            *created_at,
            EventData { comment: comment.clone(), tags: Some(tags.clone()), ..Default::default() },
        ),
        HostEvent::IpAddressChanged { old_ip, new_ip, changed_at } => (
            Some(new_ip.clone()),
            None,
            None,
            None,
            *changed_at,
            EventData { previous_ip: Some(old_ip.clone()), ..Default::default() },
        ),
        HostEvent::HostnameChanged { old_hostname, new_hostname, changed_at } => (
            None,
            Some(new_hostname.clone()),
            None,
            None,
            *changed_at,
            EventData { previous_hostname: Some(old_hostname.clone()), ..Default::default() },
        ),
        HostEvent::CommentUpdated { old_comment, new_comment, updated_at } => (
            None,
            None,
            Some(new_comment.clone().unwrap_or_default()),
            None,
            *updated_at,
            EventData { comment: new_comment.clone(), previous_comment: old_comment.clone(), ..Default::default() },
        ),
        HostEvent::TagsModified { old_tags, new_tags, modified_at } => (
            None,
            None,
            None,
            Some(serde_json::to_string(new_tags).unwrap_or_else(|_| "[]".into())),
            *modified_at,
            EventData { tags: Some(new_tags.clone()), previous_tags: Some(old_tags.clone()), ..Default::default() },
        ),
        HostEvent::HostDeleted { ip_address, hostname, deleted_at, reason } => (
            Some(ip_address.clone()),
            Some(hostname.clone()),
            None,
            None,
            *deleted_at,
            EventData { deleted_reason: reason.clone(), ..Default::default() },
        ),
    }
}

fn reconstruct_event(
    event_type: &str,
    ip: Option<String>,
    hostname: Option<String>,
    event_ts: chrono::DateTime<Utc>,
    data: &EventData,
) -> Result<HostEvent, StorageError> {
    match event_type {
        "HostCreated" => Ok(HostEvent::HostCreated {
            ip_address: ip.ok_or_else(|| StorageError::InvalidData("missing ip".into()))?,
            hostname: hostname.ok_or_else(|| StorageError::InvalidData("missing hostname".into()))?,
            comment: data.comment.clone(),
            tags: data.tags.clone().unwrap_or_default(),
            created_at: event_ts,
        }),
        "IpAddressChanged" => Ok(HostEvent::IpAddressChanged {
            old_ip: data.previous_ip.clone().ok_or_else(|| StorageError::InvalidData("missing previous_ip".into()))?,
            new_ip: ip.ok_or_else(|| StorageError::InvalidData("missing ip".into()))?,
            changed_at: event_ts,
        }),
        "HostnameChanged" => Ok(HostEvent::HostnameChanged {
            old_hostname: data.previous_hostname.clone().ok_or_else(|| StorageError::InvalidData("missing previous_hostname".into()))?,
            new_hostname: hostname.ok_or_else(|| StorageError::InvalidData("missing hostname".into()))?,
            changed_at: event_ts,
        }),
        "CommentUpdated" => Ok(HostEvent::CommentUpdated {
            old_comment: data.previous_comment.clone(),
            new_comment: data.comment.clone(),
            updated_at: event_ts,
        }),
        "TagsModified" => Ok(HostEvent::TagsModified {
            old_tags: data.previous_tags.clone().unwrap_or_default(),
            new_tags: data.tags.clone().unwrap_or_default(),
            modified_at: event_ts,
        }),
        "HostDeleted" => Ok(HostEvent::HostDeleted {
            ip_address: ip.ok_or_else(|| StorageError::InvalidData("missing ip".into()))?,
            hostname: hostname.ok_or_else(|| StorageError::InvalidData("missing hostname".into()))?,
            deleted_at: event_ts,
            reason: data.deleted_reason.clone(),
        }),
        _ => Err(StorageError::InvalidData(format!("unknown event type: {}", event_type))),
    }
}
```

**Step 2: Run cargo check**

Run: `cargo check -p router-hosts-storage`

**Step 3: Commit**

```bash
git add crates/router-hosts-storage/src/backends/duckdb/event_store.rs
git commit -m "feat(storage): implement DuckDB EventStore trait

Add async EventStore implementation for DuckDB with spawn_blocking
wrappers around synchronous DuckDB operations.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 3.4: Implement DuckDB SnapshotStore and HostProjection traits ✅

**Files:**
- Create: `crates/router-hosts-storage/src/backends/duckdb/snapshot_store.rs`
- Create: `crates/router-hosts-storage/src/backends/duckdb/projection.rs`

These follow the same pattern as event_store.rs - wrap synchronous DuckDB calls in spawn_blocking.

**Step 1: Write snapshot_store.rs**

(Similar pattern - abbreviated for plan)

**Step 2: Write projection.rs**

(Similar pattern - abbreviated for plan)

**Step 3: Run tests**

```bash
cargo test -p router-hosts-storage
```

**Step 4: Commit**

```bash
git add crates/router-hosts-storage/src/backends/duckdb/
git commit -m "feat(storage): implement DuckDB SnapshotStore and HostProjection

Complete DuckDB backend with all Storage trait implementations.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Phase 4: Update Main Crate

### Task 4.1: Add router-hosts-storage dependency ✅

**Files:**
- Modify: `crates/router-hosts/Cargo.toml`

**Step 1: Add dependency**

```toml
[dependencies]
router-hosts-storage = { path = "../router-hosts-storage" }
```

**Step 2: Commit**

```bash
git add crates/router-hosts/Cargo.toml
git commit -m "build: add router-hosts-storage dependency

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 4.2: Update server to use storage abstraction

**Files:**
- Modify: `crates/router-hosts/src/server/mod.rs`
- Modify: `crates/router-hosts/src/server/commands.rs`
- Modify: `crates/router-hosts/src/server/service/mod.rs`

This involves:
1. Replace `Database` with `Arc<dyn Storage>`
2. Update imports to use `router_hosts_storage::{...}`
3. Convert synchronous calls to async `.await`
4. Update configuration to use `StorageConfig`

**Step 1: Update server initialization**

Change from:
```rust
let db = Database::new(&config.database_path)?;
```

To:
```rust
let storage_config = StorageConfig::from_url(&config.database_url)?;
let storage = create_storage(&storage_config).await?;
```

**Step 2: Update command handlers to use async storage**

**Step 3: Run tests**

```bash
cargo test -p router-hosts -p router-hosts-common
```

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/
git commit -m "refactor(server): use storage abstraction

Replace direct DuckDB usage with router-hosts-storage traits.
Server now uses Arc<dyn Storage> for backend-agnostic storage.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Phase 5: Cleanup and Testing

### Task 5.1: Remove old db module (or deprecate)

**Files:**
- Remove or mark deprecated: `crates/router-hosts/src/server/db/`

**Step 1: Remove old db module**

The old `db/` module can be removed since all functionality is now in `router-hosts-storage`.

**Step 2: Run full test suite**

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

**Step 3: Commit**

```bash
git rm -r crates/router-hosts/src/server/db/
git commit -m "refactor(server): remove old db module

All database functionality now in router-hosts-storage crate.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

### Task 5.2: Add shared test suite

**Files:**
- Create: `crates/router-hosts-storage/tests/common/mod.rs`
- Create: `crates/router-hosts-storage/tests/duckdb_tests.rs`

**Step 1: Create shared test harness**

```rust
// tests/common/mod.rs
use router_hosts_storage::*;

pub async fn run_event_store_tests<S: Storage>(storage: &S) {
    test_append_single_event(storage).await;
    test_optimistic_concurrency(storage).await;
    test_load_events_in_order(storage).await;
    // ... more tests
}

async fn test_append_single_event<S: Storage>(storage: &S) {
    // Test implementation
}
```

**Step 2: Create DuckDB-specific test file**

```rust
// tests/duckdb_tests.rs
mod common;

use router_hosts_storage::backends::duckdb::DuckDbStorage;

#[tokio::test]
async fn duckdb_passes_event_store_tests() {
    let storage = DuckDbStorage::new("duckdb://:memory:").await.unwrap();
    storage.initialize().await.unwrap();
    common::run_event_store_tests(&storage).await;
}
```

**Step 3: Run tests**

```bash
cargo test -p router-hosts-storage
```

**Step 4: Commit**

```bash
git add crates/router-hosts-storage/tests/
git commit -m "test(storage): add shared test suite

Add backend-agnostic test harness that all backends must pass.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

---

## Summary

This plan implements Phase 1 of the storage abstraction design:

1. **New crate** `router-hosts-storage` with traits and DuckDB backend
2. **Main crate** updated to use storage abstraction
3. **Old db module** removed
4. **Shared test suite** for backend validation

Future phases (SQLite, PostgreSQL) follow the same pattern:
- Implement `backends/sqlite/` with trait implementations
- Implement `backends/postgres/` with connection pooling
- Add backend-specific test files using shared test harness
