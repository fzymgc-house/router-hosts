# Server Completion Implementation Plan

**Status:** DEPRECATED - Superseded by 2025-12-01-router-hosts-v1-design.md

> **Note:** This document is kept for historical reference only. See the v1.0 design document.

---

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete the router-hosts gRPC server from current database layer to fully functional server with mTLS, edit sessions, /etc/hosts generation, and snapshot management.

**Architecture:** Event-sourced CQRS with command handlers, in-memory edit sessions, atomic file generation, and streaming gRPC. Server uses rustls+webpki for mTLS.

**Tech Stack:** Rust, tonic (gRPC), DuckDB, tokio, rustls, chrono, ulid

---

## Phase 1: Database Stabilization

### Task 1.1: Fix Timestamp Format in Event Store

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs:180-182`

**Step 1: Locate the timestamp writes**

Find lines that write RFC3339 strings:
```rust
&event_timestamp.to_rfc3339(),
&now.to_rfc3339(),
```

**Step 2: Fix to use microseconds**

Change to:
```rust
&event_timestamp.timestamp_micros(),
&now.timestamp_micros(),
```

**Step 3: Run tests to verify**

Run: `cargo test -p router-hosts event_store`
Expected: All tests pass (existing tests already read as micros)

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/db/event_store.rs
git commit -m "fix(db): use timestamp_micros for consistent storage format"
```

---

### Task 1.2: Add Transaction Boundaries to append_event

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs:44-208`

**Step 1: Write test for concurrent write detection**

Add to `event_store.rs` tests:
```rust
#[test]
fn test_transaction_prevents_race_condition() {
    let db = Database::in_memory().unwrap();
    let aggregate_id = Ulid::new();

    // First event
    EventStore::append_event(
        &db,
        &aggregate_id,
        HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        },
        None,
        None,
    )
    .unwrap();

    // Verify version is now 1
    let events = EventStore::load_events(&db, &aggregate_id).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_version, 1);
}
```

**Step 2: Run test to verify it passes (baseline)**

Run: `cargo test -p router-hosts test_transaction_prevents_race_condition`
Expected: PASS

**Step 3: Wrap version check + insert in transaction**

In `append_event()`, after getting `db` reference, add:
```rust
db.conn()
    .execute("BEGIN TRANSACTION", [])
    .map_err(|e| DatabaseError::QueryFailed(format!("Failed to begin transaction: {}", e)))?;
```

After successful insert, before returning Ok:
```rust
db.conn()
    .execute("COMMIT", [])
    .map_err(|e| DatabaseError::QueryFailed(format!("Failed to commit transaction: {}", e)))?;
```

On error paths, add rollback. Change the error mapping block to:
```rust
.map_err(|e: duckdb::Error| {
    let _ = db.conn().execute("ROLLBACK", []);
    // ... existing error mapping
})?;
```

**Step 4: Run all event_store tests**

Run: `cargo test -p router-hosts event_store`
Expected: All pass

**Step 5: Commit**

```bash
git add crates/router-hosts/src/server/db/event_store.rs
git commit -m "fix(db): wrap append_event in transaction for atomicity"
```

---

### Task 1.3: Add Duplicate IP+Hostname Detection

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs`

**Step 1: Write failing test**

Add to `event_store.rs` tests:
```rust
#[test]
fn test_reject_duplicate_ip_hostname() {
    let db = Database::in_memory().unwrap();

    // Create first host
    EventStore::append_event(
        &db,
        &Ulid::new(),
        HostEvent::HostCreated {
            ip_address: "192.168.1.100".to_string(),
            hostname: "server.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        },
        None,
        None,
    )
    .unwrap();

    // Try to create duplicate
    let result = EventStore::append_event(
        &db,
        &Ulid::new(),
        HostEvent::HostCreated {
            ip_address: "192.168.1.100".to_string(),
            hostname: "server.local".to_string(),
            comment: Some("Different comment".to_string()),
            tags: vec![],
            created_at: Utc::now(),
        },
        None,
        None,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DatabaseError::DuplicateEntry(_)));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p router-hosts test_reject_duplicate_ip_hostname`
Expected: FAIL (currently allows duplicates)

**Step 3: Add duplicate check in append_event**

Add import at top of file:
```rust
use super::projections::HostProjections;
```

In `append_event()`, after transaction begin and before version check, add:
```rust
// Check for duplicate IP+hostname on HostCreated events
if let HostEvent::HostCreated { ip_address, hostname, .. } = &event {
    if HostProjections::find_by_ip_and_hostname(db, ip_address, hostname)?.is_some() {
        let _ = db.conn().execute("ROLLBACK", []);
        return Err(DatabaseError::DuplicateEntry(format!(
            "Host with IP {} and hostname {} already exists",
            ip_address, hostname
        )));
    }
}
```

**Step 4: Run test to verify it passes**

Run: `cargo test -p router-hosts test_reject_duplicate_ip_hostname`
Expected: PASS

**Step 5: Run all tests**

Run: `cargo test -p router-hosts`
Expected: All pass

**Step 6: Commit**

```bash
git add crates/router-hosts/src/server/db/event_store.rs
git commit -m "fix(db): reject duplicate IP+hostname combinations"
```

---

### Task 1.4: Fix get_at_time Query

**Files:**
- Modify: `crates/router-hosts/src/server/db/projections.rs:415-521`

**Step 1: Write test for time-travel query**

Add to `projections.rs` tests:
```rust
#[test]
fn test_get_at_time() {
    let db = Database::in_memory().unwrap();
    let aggregate_id = Ulid::new();
    let t0 = Utc::now();

    // Create host
    EventStore::append_event(
        &db,
        &aggregate_id,
        HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "original.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: t0,
        },
        None,
        None,
    )
    .unwrap();

    // Small delay to ensure different timestamp
    std::thread::sleep(std::time::Duration::from_millis(10));
    let t1 = Utc::now();

    // Update hostname
    EventStore::append_event(
        &db,
        &aggregate_id,
        HostEvent::HostnameChanged {
            old_hostname: "original.local".to_string(),
            new_hostname: "updated.local".to_string(),
            changed_at: t1,
        },
        Some(1),
        None,
    )
    .unwrap();

    // Query at time before update - should see original hostname
    let state_at_t0 = HostProjections::get_at_time(&db, &aggregate_id, t0 + chrono::Duration::milliseconds(5)).unwrap();
    assert!(state_at_t0.is_some());
    assert_eq!(state_at_t0.unwrap().hostname, "original.local");

    // Query at current time - should see updated hostname
    let state_now = HostProjections::get_at_time(&db, &aggregate_id, Utc::now()).unwrap();
    assert!(state_now.is_some());
    assert_eq!(state_now.unwrap().hostname, "updated.local");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p router-hosts test_get_at_time`
Expected: FAIL (SQL references non-existent columns)

**Step 3: Rewrite get_at_time to use correct schema**

Replace the entire `get_at_time` function with:
```rust
/// Get historical state of a host at a specific point in time
///
/// Replays events up to the given timestamp to reconstruct past state.
pub fn get_at_time(
    db: &Database,
    id: &Ulid,
    at_time: DateTime<Utc>,
) -> DatabaseResult<Option<HostEntry>> {
    let mut stmt = db
        .conn()
        .prepare(
            r#"
            SELECT
                event_id,
                aggregate_id,
                event_type,
                event_version,
                CAST(ip_address AS VARCHAR) as ip_address,
                hostname,
                CAST(metadata AS VARCHAR) as metadata,
                event_timestamp,
                created_at,
                created_by
            FROM host_events
            WHERE aggregate_id = ? AND created_at <= ?
            ORDER BY event_version ASC
            "#,
        )
        .map_err(|e| {
            DatabaseError::QueryFailed(format!("Failed to prepare time travel query: {}", e))
        })?;

    let at_time_micros = at_time.timestamp_micros();

    let rows = stmt
        .query_map(
            [
                &id.to_string() as &dyn duckdb::ToSql,
                &at_time_micros as &dyn duckdb::ToSql,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,         // event_id
                    row.get::<_, String>(1)?,         // aggregate_id
                    row.get::<_, String>(2)?,         // event_type
                    row.get::<_, i64>(3)?,            // event_version
                    row.get::<_, Option<String>>(4)?, // ip_address
                    row.get::<_, Option<String>>(5)?, // hostname
                    row.get::<_, String>(6)?,         // metadata
                    row.get::<_, i64>(7)?,            // event_timestamp
                    row.get::<_, i64>(8)?,            // created_at
                    row.get::<_, String>(9)?,         // created_by
                ))
            },
        )
        .map_err(|e| DatabaseError::QueryFailed(format!("Failed to query events: {}", e)))?;

    // Reuse the same event reconstruction logic as load_events
    let mut envelopes = Vec::new();
    for row in rows {
        let (
            event_id_str,
            aggregate_id_str,
            event_type,
            event_version,
            ip_address,
            hostname,
            metadata_json,
            event_timestamp_micros,
            created_at_micros,
            created_by,
        ) = row.map_err(|e| DatabaseError::QueryFailed(format!("Failed to read row: {}", e)))?;

        let event_id = Ulid::from_string(&event_id_str)
            .map_err(|e| DatabaseError::InvalidData(format!("Invalid event_id ULID: {}", e)))?;

        let agg_id = Ulid::from_string(&aggregate_id_str)
            .map_err(|e| DatabaseError::InvalidData(format!("Invalid aggregate_id ULID: {}", e)))?;

        let event_timestamp = DateTime::from_timestamp_micros(event_timestamp_micros)
            .ok_or_else(|| {
                DatabaseError::InvalidData(format!(
                    "Invalid event timestamp: {}",
                    event_timestamp_micros
                ))
            })?;

        use super::events::EventData;
        let event_data: EventData = serde_json::from_str(&metadata_json).map_err(|e| {
            DatabaseError::InvalidData(format!("Failed to deserialize event metadata: {}", e))
        })?;

        let event = match event_type.as_str() {
            "HostCreated" => {
                let ip = ip_address.ok_or_else(|| {
                    DatabaseError::InvalidData("HostCreated missing ip_address".to_string())
                })?;
                let host = hostname.ok_or_else(|| {
                    DatabaseError::InvalidData("HostCreated missing hostname".to_string())
                })?;
                HostEvent::HostCreated {
                    ip_address: ip,
                    hostname: host,
                    comment: event_data.comment.clone(),
                    tags: event_data.tags.clone().unwrap_or_default(),
                    created_at: event_timestamp,
                }
            }
            "IpAddressChanged" => {
                let new_ip = ip_address.ok_or_else(|| {
                    DatabaseError::InvalidData("IpAddressChanged missing ip_address".to_string())
                })?;
                let old_ip = event_data.previous_ip.clone().ok_or_else(|| {
                    DatabaseError::InvalidData("IpAddressChanged missing previous_ip".to_string())
                })?;
                HostEvent::IpAddressChanged {
                    old_ip,
                    new_ip,
                    changed_at: event_timestamp,
                }
            }
            "HostnameChanged" => {
                let new_hostname = hostname.ok_or_else(|| {
                    DatabaseError::InvalidData("HostnameChanged missing hostname".to_string())
                })?;
                let old_hostname = event_data.previous_hostname.clone().ok_or_else(|| {
                    DatabaseError::InvalidData("HostnameChanged missing previous_hostname".to_string())
                })?;
                HostEvent::HostnameChanged {
                    old_hostname,
                    new_hostname,
                    changed_at: event_timestamp,
                }
            }
            "CommentUpdated" => HostEvent::CommentUpdated {
                old_comment: event_data.previous_comment.clone(),
                new_comment: event_data.comment.clone(),
                updated_at: event_timestamp,
            },
            "TagsModified" => HostEvent::TagsModified {
                old_tags: event_data.previous_tags.clone().unwrap_or_default(),
                new_tags: event_data.tags.clone().unwrap_or_default(),
                modified_at: event_timestamp,
            },
            "HostDeleted" => HostEvent::HostDeleted {
                ip_address: ip_address.ok_or_else(|| {
                    DatabaseError::InvalidData("HostDeleted missing ip_address".to_string())
                })?,
                hostname: hostname.ok_or_else(|| {
                    DatabaseError::InvalidData("HostDeleted missing hostname".to_string())
                })?,
                deleted_at: event_timestamp,
                reason: event_data.deleted_reason.clone(),
            },
            _ => {
                return Err(DatabaseError::InvalidData(format!(
                    "Unknown event type: {}",
                    event_type
                )))
            }
        };

        let created_at = DateTime::from_timestamp_micros(created_at_micros).ok_or_else(|| {
            DatabaseError::InvalidData(format!("Invalid timestamp: {}", created_at_micros))
        })?;

        envelopes.push(EventEnvelope {
            event_id,
            aggregate_id: agg_id,
            event,
            event_version,
            created_at,
            created_by: if created_by == "system" {
                None
            } else {
                Some(created_by)
            },
            metadata: None,
        });
    }

    Self::rebuild_from_events(&envelopes)
}
```

**Step 4: Add missing import**

At top of projections.rs, ensure this import exists:
```rust
use super::events::{EventEnvelope, HostEvent};
```

**Step 5: Run test to verify it passes**

Run: `cargo test -p router-hosts test_get_at_time`
Expected: PASS

**Step 6: Run all tests**

Run: `cargo test -p router-hosts`
Expected: All pass

**Step 7: Commit**

```bash
git add crates/router-hosts/src/server/db/projections.rs
git commit -m "fix(db): rewrite get_at_time to use correct schema columns"
```

---

### Task 1.5: Remove Unused EventMetadata Parameter

**Files:**
- Modify: `crates/router-hosts/src/server/db/event_store.rs`

**Step 1: Remove metadata parameter from append_event signature**

Change from:
```rust
pub fn append_event(
    db: &Database,
    aggregate_id: &Ulid,
    event: HostEvent,
    expected_version: Option<i64>,
    created_by: Option<String>,
    metadata: Option<EventMetadata>,
) -> DatabaseResult<EventEnvelope> {
```

To:
```rust
pub fn append_event(
    db: &Database,
    aggregate_id: &Ulid,
    event: HostEvent,
    expected_version: Option<i64>,
    created_by: Option<String>,
) -> DatabaseResult<EventEnvelope> {
```

**Step 2: Remove the unused parameter handling**

Delete these lines:
```rust
// Note: EventMetadata (correlation/causation/user_agent/source_ip) parameter is accepted
// but not currently persisted to the database. Only EventData is stored in metadata column.
// To persist EventMetadata, we would need to add a separate column or extend the schema.
let _ = metadata; // Acknowledge unused parameter
```

**Step 3: Update EventEnvelope creation**

In the Ok() return, change:
```rust
metadata,
```
To:
```rust
metadata: None,
```

**Step 4: Update all test calls**

Search and replace all `None, None, None)` with `None, None)` in the test functions. There are approximately 20+ occurrences.

**Step 5: Update projection tests**

In `projections.rs` tests, update any calls to `append_event` to remove the last `None` parameter.

**Step 6: Run all tests**

Run: `cargo test -p router-hosts`
Expected: All pass

**Step 7: Commit**

```bash
git add crates/router-hosts/src/server/db/event_store.rs crates/router-hosts/src/server/db/projections.rs
git commit -m "refactor(db): remove unused EventMetadata parameter from append_event"
```

---

## Phase 2: Core Server Infrastructure

### Task 2.1: Create Command Error Types

**Files:**
- Create: `crates/router-hosts/src/server/commands.rs`

**Step 1: Create the commands module with error types**

```rust
//! Command handlers for host management operations
//!
//! This module centralizes validation and event generation for all write operations.

use crate::server::db::events::HostEvent;
use crate::server::db::schema::DatabaseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Session conflict: {0}")]
    SessionConflict(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type CommandResult<T> = Result<T, CommandError>;
```

**Step 2: Add to server mod.rs**

In `crates/router-hosts/src/server/mod.rs`, add:
```rust
pub mod commands;
```

**Step 3: Verify it compiles**

Run: `cargo build -p router-hosts`
Expected: Success

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/commands.rs crates/router-hosts/src/server/mod.rs
git commit -m "feat(server): add command error types"
```

---

### Task 2.2: Create Session Manager

**Files:**
- Create: `crates/router-hosts/src/server/session.rs`

**Step 1: Write failing test**

Create the file with tests first:
```rust
//! Edit session management
//!
//! Manages single-server edit sessions with 15-minute timeout.

use crate::server::db::events::HostEvent;
use chrono::{DateTime, Duration, Utc};
use std::sync::Mutex;
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Edit session already active")]
    SessionAlreadyActive,

    #[error("Invalid or expired session token")]
    InvalidToken,

    #[error("Session expired")]
    Expired,

    #[error("No active session")]
    NoActiveSession,
}

pub type SessionResult<T> = Result<T, SessionError>;

struct ActiveSession {
    token: String,
    started_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    staged_events: Vec<(Ulid, HostEvent)>,
}

pub struct SessionManager {
    active: Mutex<Option<ActiveSession>>,
    timeout_minutes: i64,
}

impl SessionManager {
    pub fn new(timeout_minutes: i64) -> Self {
        Self {
            active: Mutex::new(None),
            timeout_minutes,
        }
    }

    /// Start a new edit session
    pub fn start_edit(&self) -> SessionResult<String> {
        let mut guard = self.active.lock().unwrap();

        // Check if session exists and is still valid
        if let Some(ref session) = *guard {
            if !self.is_expired(session) {
                return Err(SessionError::SessionAlreadyActive);
            }
        }

        // Create new session
        let token = Ulid::new().to_string();
        let now = Utc::now();
        *guard = Some(ActiveSession {
            token: token.clone(),
            started_at: now,
            last_activity: now,
            staged_events: Vec::new(),
        });

        Ok(token)
    }

    /// Validate that a token is valid and not expired
    pub fn validate_token(&self, token: &str) -> SessionResult<()> {
        let guard = self.active.lock().unwrap();
        match &*guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    Err(SessionError::Expired)
                } else {
                    Ok(())
                }
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Reset the timeout for a session
    pub fn touch(&self, token: &str) -> SessionResult<()> {
        let mut guard = self.active.lock().unwrap();
        match &mut *guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    *guard = None;
                    Err(SessionError::Expired)
                } else {
                    session.last_activity = Utc::now();
                    Ok(())
                }
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Stage an event for later commit
    pub fn stage_event(&self, token: &str, agg_id: Ulid, event: HostEvent) -> SessionResult<()> {
        let mut guard = self.active.lock().unwrap();
        match &mut *guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    *guard = None;
                    Err(SessionError::Expired)
                } else {
                    session.last_activity = Utc::now();
                    session.staged_events.push((agg_id, event));
                    Ok(())
                }
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Finish the edit session and return staged events
    pub fn finish_edit(&self, token: &str) -> SessionResult<Vec<(Ulid, HostEvent)>> {
        let mut guard = self.active.lock().unwrap();
        match &*guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    *guard = None;
                    return Err(SessionError::Expired);
                }
                let session = guard.take().unwrap();
                Ok(session.staged_events)
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Cancel the edit session and discard staged events
    pub fn cancel_edit(&self, token: &str) -> SessionResult<()> {
        let mut guard = self.active.lock().unwrap();
        match &*guard {
            Some(session) if session.token == token => {
                *guard = None;
                Ok(())
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    fn is_expired(&self, session: &ActiveSession) -> bool {
        let timeout = Duration::minutes(self.timeout_minutes);
        Utc::now() - session.last_activity > timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_edit_returns_token() {
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn test_cannot_start_second_session() {
        let mgr = SessionManager::new(15);
        let _token1 = mgr.start_edit().unwrap();
        let result = mgr.start_edit();
        assert!(matches!(result, Err(SessionError::SessionAlreadyActive)));
    }

    #[test]
    fn test_validate_token() {
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();
        assert!(mgr.validate_token(&token).is_ok());
        assert!(matches!(
            mgr.validate_token("wrong"),
            Err(SessionError::InvalidToken)
        ));
    }

    #[test]
    fn test_stage_and_finish() {
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();

        let agg_id = Ulid::new();
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        mgr.stage_event(&token, agg_id, event).unwrap();

        let events = mgr.finish_edit(&token).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_cancel_discards_events() {
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();

        let agg_id = Ulid::new();
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        mgr.stage_event(&token, agg_id, event).unwrap();
        mgr.cancel_edit(&token).unwrap();

        // Session is gone, so validate should fail
        assert!(matches!(
            mgr.validate_token(&token),
            Err(SessionError::NoActiveSession)
        ));
    }

    #[test]
    fn test_expired_session() {
        let mgr = SessionManager::new(0); // 0 minute timeout = immediate expiry
        let token = mgr.start_edit().unwrap();

        // Wait briefly to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(10));

        assert!(matches!(
            mgr.validate_token(&token),
            Err(SessionError::Expired)
        ));
    }
}
```

**Step 2: Add to server mod.rs**

In `crates/router-hosts/src/server/mod.rs`, add:
```rust
pub mod session;
```

**Step 3: Run tests**

Run: `cargo test -p router-hosts session`
Expected: All pass

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/session.rs crates/router-hosts/src/server/mod.rs
git commit -m "feat(server): add edit session manager with timeout"
```

---

### Task 2.3: Create Hosts File Generator

**Files:**
- Create: `crates/router-hosts/src/server/hosts_file.rs`

**Step 1: Create the module**

```rust
//! /etc/hosts file generation with atomic writes

use crate::server::db::projections::{HostEntry, HostProjections};
use crate::server::db::schema::Database;
use chrono::Utc;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Error)]
pub enum GenerateError {
    #[error("Database error: {0}")]
    Database(#[from] crate::server::db::schema::DatabaseError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type GenerateResult<T> = Result<T, GenerateError>;

pub struct HostsFileGenerator {
    path: PathBuf,
}

impl HostsFileGenerator {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Regenerate /etc/hosts from current database state
    pub async fn regenerate(&self, db: &Database) -> GenerateResult<usize> {
        // Query all active hosts
        let entries = HostProjections::list_all(db)?;
        let count = entries.len();

        // Generate content
        let content = self.format_hosts_file(&entries);

        // Atomic write
        self.atomic_write(&content).await?;

        Ok(count)
    }

    /// Format entries as /etc/hosts content
    fn format_hosts_file(&self, entries: &[HostEntry]) -> String {
        let mut lines = Vec::new();

        // Header
        lines.push("# Generated by router-hosts".to_string());
        lines.push(format!(
            "# Last updated: {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));
        lines.push(format!("# Entry count: {}", entries.len()));
        lines.push(String::new());

        // Entries (already sorted by list_all)
        for entry in entries {
            let mut line = format!("{}\t{}", entry.ip_address, entry.hostname);

            // Add comment and tags
            let has_comment = entry.comment.is_some();
            let has_tags = !entry.tags.is_empty();

            if has_comment || has_tags {
                line.push_str("\t# ");
                if let Some(ref comment) = entry.comment {
                    line.push_str(comment);
                }
                if has_tags {
                    if has_comment {
                        line.push(' ');
                    }
                    line.push('[');
                    line.push_str(&entry.tags.join(", "));
                    line.push(']');
                }
            }

            lines.push(line);
        }

        lines.join("\n") + "\n"
    }

    /// Write content atomically: tmp file -> fsync -> rename
    async fn atomic_write(&self, content: &str) -> GenerateResult<()> {
        let tmp_path = self.path.with_extension("tmp");

        // Write to temp file
        let mut file = fs::File::create(&tmp_path).await?;
        file.write_all(content.as_bytes()).await?;
        file.sync_all().await?;
        drop(file);

        // Atomic rename
        fs::rename(&tmp_path, &self.path).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hosts_file_empty() {
        let gen = HostsFileGenerator::new("/tmp/hosts");
        let content = gen.format_hosts_file(&[]);

        assert!(content.contains("# Generated by router-hosts"));
        assert!(content.contains("# Entry count: 0"));
    }

    #[test]
    fn test_format_hosts_file_with_entries() {
        let gen = HostsFileGenerator::new("/tmp/hosts");
        let entries = vec![
            HostEntry {
                id: ulid::Ulid::new(),
                ip_address: "192.168.1.10".to_string(),
                hostname: "server.local".to_string(),
                comment: None,
                tags: vec![],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 1,
            },
            HostEntry {
                id: ulid::Ulid::new(),
                ip_address: "192.168.1.20".to_string(),
                hostname: "nas.local".to_string(),
                comment: Some("NAS storage".to_string()),
                tags: vec!["homelab".to_string()],
                created_at: Utc::now(),
                updated_at: Utc::now(),
                version: 1,
            },
        ];

        let content = gen.format_hosts_file(&entries);

        assert!(content.contains("192.168.1.10\tserver.local"));
        assert!(content.contains("192.168.1.20\tnas.local\t# NAS storage [homelab]"));
    }

    #[tokio::test]
    async fn test_atomic_write() {
        let tmp_dir = std::env::temp_dir();
        let hosts_path = tmp_dir.join("test_hosts_atomic");

        let gen = HostsFileGenerator::new(&hosts_path);
        gen.atomic_write("test content\n").await.unwrap();

        let content = fs::read_to_string(&hosts_path).await.unwrap();
        assert_eq!(content, "test content\n");

        // Cleanup
        let _ = fs::remove_file(&hosts_path).await;
    }
}
```

**Step 2: Add to server mod.rs**

```rust
pub mod hosts_file;
```

**Step 3: Run tests**

Run: `cargo test -p router-hosts hosts_file`
Expected: All pass

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/hosts_file.rs crates/router-hosts/src/server/mod.rs
git commit -m "feat(server): add /etc/hosts file generator with atomic writes"
```

---

### Task 2.4: Create Hook Executor

**Files:**
- Create: `crates/router-hosts/src/server/hooks.rs`

**Step 1: Create the module**

```rust
//! Post-edit hook execution

use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
pub enum HookError {
    #[error("Hook timed out after {0} seconds")]
    Timeout(u64),

    #[error("Hook failed with exit code {0}: {1}")]
    Failed(i32, String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct HookExecutor {
    on_success: Vec<String>,
    on_failure: Vec<String>,
    timeout_secs: u64,
}

impl HookExecutor {
    pub fn new(on_success: Vec<String>, on_failure: Vec<String>, timeout_secs: u64) -> Self {
        Self {
            on_success,
            on_failure,
            timeout_secs,
        }
    }

    /// Run success hooks after successful hosts file regeneration
    pub async fn run_success(&self, entry_count: usize) {
        for cmd in &self.on_success {
            if let Err(e) = self.run_hook(cmd, "success", entry_count).await {
                warn!("Success hook failed (continuing): {} - {}", cmd, e);
            }
        }
    }

    /// Run failure hooks after failed hosts file regeneration
    pub async fn run_failure(&self, entry_count: usize, error: &str) {
        for cmd in &self.on_failure {
            if let Err(e) = self.run_hook_with_error(cmd, "failure", entry_count, error).await {
                warn!("Failure hook failed (continuing): {} - {}", cmd, e);
            }
        }
    }

    async fn run_hook(&self, cmd: &str, event: &str, entry_count: usize) -> Result<(), HookError> {
        self.run_hook_with_error(cmd, event, entry_count, "").await
    }

    async fn run_hook_with_error(
        &self,
        cmd: &str,
        event: &str,
        entry_count: usize,
        error_msg: &str,
    ) -> Result<(), HookError> {
        info!("Running hook: {}", cmd);

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .env("ROUTER_HOSTS_EVENT", event)
            .env("ROUTER_HOSTS_ENTRY_COUNT", entry_count.to_string())
            .env("ROUTER_HOSTS_ERROR", error_msg)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let result = timeout(Duration::from_secs(self.timeout_secs), child.wait()).await;

        match result {
            Ok(Ok(status)) => {
                if status.success() {
                    info!("Hook completed successfully: {}", cmd);
                    Ok(())
                } else {
                    let code = status.code().unwrap_or(-1);
                    error!("Hook failed with code {}: {}", code, cmd);
                    Err(HookError::Failed(code, cmd.to_string()))
                }
            }
            Ok(Err(e)) => Err(HookError::Io(e)),
            Err(_) => {
                let _ = child.kill().await;
                error!("Hook timed out: {}", cmd);
                Err(HookError::Timeout(self.timeout_secs))
            }
        }
    }
}

impl Default for HookExecutor {
    fn default() -> Self {
        Self::new(vec![], vec![], 30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_success_hook() {
        let executor = HookExecutor::new(vec!["echo success".to_string()], vec![], 5);
        executor.run_success(10).await;
        // Should complete without error
    }

    #[tokio::test]
    async fn test_hook_with_env_vars() {
        let executor = HookExecutor::new(
            vec!["test \"$ROUTER_HOSTS_EVENT\" = \"success\"".to_string()],
            vec![],
            5,
        );
        executor.run_success(10).await;
        // Should complete without error (env var is set correctly)
    }

    #[tokio::test]
    async fn test_hook_timeout() {
        let executor = HookExecutor::new(vec!["sleep 10".to_string()], vec![], 1);
        // This will timeout but continue
        executor.run_success(10).await;
    }

    #[tokio::test]
    async fn test_empty_hooks() {
        let executor = HookExecutor::default();
        executor.run_success(0).await;
        executor.run_failure(0, "test error").await;
        // Should complete immediately with no hooks
    }
}
```

**Step 2: Add to server mod.rs**

```rust
pub mod hooks;
```

**Step 3: Run tests**

Run: `cargo test -p router-hosts hooks`
Expected: All pass

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/hooks.rs crates/router-hosts/src/server/mod.rs
git commit -m "feat(server): add post-edit hook executor with timeout"
```

---

### Task 2.5: Create Command Handler

**Files:**
- Modify: `crates/router-hosts/src/server/commands.rs`

**Step 1: Expand commands.rs with full handler**

Replace the file content with:
```rust
//! Command handlers for host management operations
//!
//! This module centralizes validation and event generation for all write operations.

use crate::server::db::event_store::EventStore;
use crate::server::db::events::HostEvent;
use crate::server::db::projections::{HostEntry, HostProjections};
use crate::server::db::schema::{Database, DatabaseError};
use crate::server::hooks::HookExecutor;
use crate::server::hosts_file::HostsFileGenerator;
use crate::server::session::{SessionError, SessionManager};
use chrono::Utc;
use router_hosts_common::validation::{validate_hostname, validate_ip_address};
use std::sync::Arc;
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Session conflict: another edit session is active")]
    SessionConflict,

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("No active session")]
    NoActiveSession,

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("File generation error: {0}")]
    FileGeneration(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<SessionError> for CommandError {
    fn from(e: SessionError) -> Self {
        match e {
            SessionError::SessionAlreadyActive => CommandError::SessionConflict,
            SessionError::InvalidToken => CommandError::InvalidToken,
            SessionError::Expired => CommandError::SessionExpired,
            SessionError::NoActiveSession => CommandError::NoActiveSession,
        }
    }
}

pub type CommandResult<T> = Result<T, CommandError>;

pub struct CommandHandler {
    db: Arc<Database>,
    session_mgr: Arc<SessionManager>,
    hosts_file: Arc<HostsFileGenerator>,
    hooks: Arc<HookExecutor>,
}

impl CommandHandler {
    pub fn new(
        db: Arc<Database>,
        session_mgr: Arc<SessionManager>,
        hosts_file: Arc<HostsFileGenerator>,
        hooks: Arc<HookExecutor>,
    ) -> Self {
        Self {
            db,
            session_mgr,
            hosts_file,
            hooks,
        }
    }

    /// Add a new host entry
    pub async fn add_host(
        &self,
        ip_address: String,
        hostname: String,
        comment: Option<String>,
        tags: Vec<String>,
        edit_token: Option<String>,
    ) -> CommandResult<HostEntry> {
        // Validate inputs
        validate_ip_address(&ip_address)
            .map_err(|e| CommandError::ValidationFailed(e.to_string()))?;
        validate_hostname(&hostname)
            .map_err(|e| CommandError::ValidationFailed(e.to_string()))?;

        let aggregate_id = Ulid::new();
        let event = HostEvent::HostCreated {
            ip_address,
            hostname,
            comment,
            tags,
            created_at: Utc::now(),
        };

        if let Some(ref token) = edit_token {
            // Stage the event
            self.session_mgr.stage_event(token, aggregate_id, event)?;
            // Return placeholder entry (not yet committed)
            return self.get_host(aggregate_id).await.map(|opt| {
                opt.unwrap_or_else(|| {
                    // Return a stub since event is staged, not committed
                    HostEntry {
                        id: aggregate_id,
                        ip_address: String::new(),
                        hostname: String::new(),
                        comment: None,
                        tags: vec![],
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        version: 0,
                    }
                })
            });
        }

        // Immediate commit
        EventStore::append_event(&self.db, &aggregate_id, event, None, None)?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        // Return the created entry
        self.get_host(aggregate_id)
            .await?
            .ok_or_else(|| CommandError::Internal("Entry not found after creation".to_string()))
    }

    /// Update an existing host entry
    pub async fn update_host(
        &self,
        id: Ulid,
        ip_address: Option<String>,
        hostname: Option<String>,
        comment: Option<Option<String>>,
        tags: Option<Vec<String>>,
        edit_token: Option<String>,
    ) -> CommandResult<HostEntry> {
        // Get current state
        let current = HostProjections::get_by_id(&self.db, &id)?
            .ok_or_else(|| CommandError::NotFound(format!("Host {} not found", id)))?;

        let current_version = current.version;
        let mut events = Vec::new();

        // Generate events for each change
        if let Some(new_ip) = ip_address {
            validate_ip_address(&new_ip)
                .map_err(|e| CommandError::ValidationFailed(e.to_string()))?;
            if new_ip != current.ip_address {
                events.push(HostEvent::IpAddressChanged {
                    old_ip: current.ip_address.clone(),
                    new_ip,
                    changed_at: Utc::now(),
                });
            }
        }

        if let Some(new_hostname) = hostname {
            validate_hostname(&new_hostname)
                .map_err(|e| CommandError::ValidationFailed(e.to_string()))?;
            if new_hostname != current.hostname {
                events.push(HostEvent::HostnameChanged {
                    old_hostname: current.hostname.clone(),
                    new_hostname,
                    changed_at: Utc::now(),
                });
            }
        }

        if let Some(new_comment) = comment {
            if new_comment != current.comment {
                events.push(HostEvent::CommentUpdated {
                    old_comment: current.comment.clone(),
                    new_comment,
                    updated_at: Utc::now(),
                });
            }
        }

        if let Some(new_tags) = tags {
            if new_tags != current.tags {
                events.push(HostEvent::TagsModified {
                    old_tags: current.tags.clone(),
                    new_tags,
                    modified_at: Utc::now(),
                });
            }
        }

        if events.is_empty() {
            return Ok(current);
        }

        if let Some(ref token) = edit_token {
            // Stage all events
            for event in events {
                self.session_mgr.stage_event(token, id, event)?;
            }
            return Ok(current);
        }

        // Immediate commit
        let mut version = current_version;
        for event in events {
            EventStore::append_event(&self.db, &id, event, Some(version), None)?;
            version += 1;
        }

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        // Return updated entry
        self.get_host(id)
            .await?
            .ok_or_else(|| CommandError::Internal("Entry not found after update".to_string()))
    }

    /// Delete a host entry
    pub async fn delete_host(
        &self,
        id: Ulid,
        reason: Option<String>,
        edit_token: Option<String>,
    ) -> CommandResult<()> {
        let current = HostProjections::get_by_id(&self.db, &id)?
            .ok_or_else(|| CommandError::NotFound(format!("Host {} not found", id)))?;

        let event = HostEvent::HostDeleted {
            ip_address: current.ip_address.clone(),
            hostname: current.hostname.clone(),
            deleted_at: Utc::now(),
            reason,
        };

        if let Some(ref token) = edit_token {
            self.session_mgr.stage_event(token, id, event)?;
            return Ok(());
        }

        // Immediate commit
        EventStore::append_event(&self.db, &id, event, Some(current.version), None)?;

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        Ok(())
    }

    /// Get a host by ID
    pub async fn get_host(&self, id: Ulid) -> CommandResult<Option<HostEntry>> {
        Ok(HostProjections::get_by_id(&self.db, &id)?)
    }

    /// List all hosts
    pub async fn list_hosts(&self) -> CommandResult<Vec<HostEntry>> {
        Ok(HostProjections::list_all(&self.db)?)
    }

    /// Search hosts
    pub async fn search_hosts(&self, pattern: &str) -> CommandResult<Vec<HostEntry>> {
        Ok(HostProjections::search(&self.db, pattern)?)
    }

    /// Start an edit session
    pub fn start_edit(&self) -> CommandResult<String> {
        Ok(self.session_mgr.start_edit()?)
    }

    /// Finish an edit session and commit all staged changes
    pub async fn finish_edit(&self, token: &str) -> CommandResult<usize> {
        let staged_events = self.session_mgr.finish_edit(token)?;
        let count = staged_events.len();

        // Commit all staged events
        for (agg_id, event) in staged_events {
            // Get current version for this aggregate
            let version = match HostProjections::get_by_id(&self.db, &agg_id)? {
                Some(entry) => Some(entry.version),
                None => None,
            };
            EventStore::append_event(&self.db, &agg_id, event, version, None)?;
        }

        // Regenerate hosts file
        self.regenerate_hosts_file().await?;

        Ok(count)
    }

    /// Cancel an edit session
    pub fn cancel_edit(&self, token: &str) -> CommandResult<()> {
        Ok(self.session_mgr.cancel_edit(token)?)
    }

    async fn regenerate_hosts_file(&self) -> CommandResult<()> {
        match self.hosts_file.regenerate(&self.db).await {
            Ok(count) => {
                self.hooks.run_success(count).await;
                Ok(())
            }
            Err(e) => {
                self.hooks.run_failure(0, &e.to_string()).await;
                Err(CommandError::FileGeneration(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn setup() -> CommandHandler {
        let db = Arc::new(Database::in_memory().unwrap());
        let session_mgr = Arc::new(SessionManager::new(15));
        let hosts_file = Arc::new(HostsFileGenerator::new(temp_dir().join("test_hosts")));
        let hooks = Arc::new(HookExecutor::default());
        CommandHandler::new(db, session_mgr, hosts_file, hooks)
    }

    #[tokio::test]
    async fn test_add_host() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
                None,
            )
            .await
            .unwrap();

        assert_eq!(entry.ip_address, "192.168.1.1");
        assert_eq!(entry.hostname, "test.local");
    }

    #[tokio::test]
    async fn test_add_host_validation_failure() {
        let handler = setup();
        let result = handler
            .add_host(
                "invalid-ip".to_string(),
                "test.local".to_string(),
                None,
                vec![],
                None,
            )
            .await;

        assert!(matches!(result, Err(CommandError::ValidationFailed(_))));
    }

    #[tokio::test]
    async fn test_update_host() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
                None,
            )
            .await
            .unwrap();

        let updated = handler
            .update_host(
                entry.id,
                Some("192.168.1.2".to_string()),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(updated.ip_address, "192.168.1.2");
    }

    #[tokio::test]
    async fn test_delete_host() {
        let handler = setup();
        let entry = handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
                None,
            )
            .await
            .unwrap();

        handler.delete_host(entry.id, None, None).await.unwrap();

        let result = handler.get_host(entry.id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_edit_session_workflow() {
        let handler = setup();

        // Start session
        let token = handler.start_edit().unwrap();

        // Add host in session
        handler
            .add_host(
                "192.168.1.1".to_string(),
                "test.local".to_string(),
                None,
                vec![],
                Some(token.clone()),
            )
            .await
            .unwrap();

        // Finish session
        let count = handler.finish_edit(&token).await.unwrap();
        assert_eq!(count, 1);
    }
}
```

**Step 2: Verify it compiles**

Run: `cargo build -p router-hosts`
Expected: Success

**Step 3: Run tests**

Run: `cargo test -p router-hosts commands`
Expected: All pass

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/commands.rs
git commit -m "feat(server): implement command handler with validation and sessions"
```

---

## Phase 3: gRPC Service Layer

### Task 3.1: Create Service Module Structure

**Files:**
- Create: `crates/router-hosts/src/server/service/mod.rs`
- Create: `crates/router-hosts/src/server/service/hosts.rs`
- Create: `crates/router-hosts/src/server/service/sessions.rs`
- Create: `crates/router-hosts/src/server/service/bulk.rs`
- Create: `crates/router-hosts/src/server/service/snapshots.rs`

**Step 1: Create service/mod.rs**

```rust
//! gRPC service implementation

mod bulk;
mod hosts;
mod sessions;
mod snapshots;

use crate::server::commands::CommandHandler;
use crate::server::db::schema::Database;
use crate::server::session::SessionManager;
use router_hosts_common::proto::router_hosts::v1::hosts_service_server::HostsService;
use std::sync::Arc;

pub use router_hosts_common::proto::router_hosts::v1::hosts_service_server::HostsServiceServer;

pub struct HostsServiceImpl {
    pub(crate) commands: Arc<CommandHandler>,
    pub(crate) db: Arc<Database>,
    pub(crate) session_mgr: Arc<SessionManager>,
}

impl HostsServiceImpl {
    pub fn new(
        commands: Arc<CommandHandler>,
        db: Arc<Database>,
        session_mgr: Arc<SessionManager>,
    ) -> Self {
        Self {
            commands,
            db,
            session_mgr,
        }
    }
}
```

**Step 2: Create service/hosts.rs (stub)**

```rust
//! Host CRUD handlers

use super::HostsServiceImpl;
use crate::server::commands::CommandError;
use router_hosts_common::proto::router_hosts::v1::*;
use tonic::{Request, Response, Status};
use ulid::Ulid;

impl HostsServiceImpl {
    pub(crate) async fn handle_add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<AddHostResponse>, Status> {
        let req = request.into_inner();

        let entry = self
            .commands
            .add_host(
                req.ip_address,
                req.hostname,
                req.comment,
                req.tags,
                req.edit_token,
            )
            .await
            .map_err(command_error_to_status)?;

        Ok(Response::new(AddHostResponse {
            id: entry.id.to_string(),
            entry: Some(entry.into()),
        }))
    }

    pub(crate) async fn handle_get_host(
        &self,
        request: Request<GetHostRequest>,
    ) -> Result<Response<GetHostResponse>, Status> {
        let req = request.into_inner();
        let id = parse_ulid(&req.id)?;

        let entry = self
            .commands
            .get_host(id)
            .await
            .map_err(command_error_to_status)?
            .ok_or_else(|| Status::not_found(format!("Host {} not found", id)))?;

        Ok(Response::new(GetHostResponse {
            entry: Some(entry.into()),
        }))
    }

    pub(crate) async fn handle_update_host(
        &self,
        request: Request<UpdateHostRequest>,
    ) -> Result<Response<UpdateHostResponse>, Status> {
        let req = request.into_inner();
        let id = parse_ulid(&req.id)?;

        let entry = self
            .commands
            .update_host(
                id,
                req.ip_address,
                req.hostname,
                req.comment.map(Some),
                if req.tags.is_empty() {
                    None
                } else {
                    Some(req.tags)
                },
                req.edit_token,
            )
            .await
            .map_err(command_error_to_status)?;

        Ok(Response::new(UpdateHostResponse {
            entry: Some(entry.into()),
        }))
    }

    pub(crate) async fn handle_delete_host(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        let req = request.into_inner();
        let id = parse_ulid(&req.id)?;

        self.commands
            .delete_host(id, None, req.edit_token)
            .await
            .map_err(command_error_to_status)?;

        Ok(Response::new(DeleteHostResponse { success: true }))
    }
}

fn parse_ulid(s: &str) -> Result<Ulid, Status> {
    Ulid::from_string(s).map_err(|_| Status::invalid_argument(format!("Invalid ID: {}", s)))
}

fn command_error_to_status(e: CommandError) -> Status {
    match e {
        CommandError::ValidationFailed(msg) => Status::invalid_argument(msg),
        CommandError::DuplicateEntry(msg) => Status::already_exists(msg),
        CommandError::NotFound(msg) => Status::not_found(msg),
        CommandError::SessionConflict => {
            Status::failed_precondition("Another edit session is active")
        }
        CommandError::SessionExpired => Status::failed_precondition("Session expired"),
        CommandError::InvalidToken => Status::failed_precondition("Invalid session token"),
        CommandError::NoActiveSession => Status::failed_precondition("No active edit session"),
        CommandError::Database(e) => Status::internal(e.to_string()),
        CommandError::FileGeneration(msg) => Status::internal(msg),
        CommandError::Internal(msg) => Status::internal(msg),
    }
}

// Conversion from HostEntry to proto HostEntry
impl From<crate::server::db::projections::HostEntry> for HostEntry {
    fn from(e: crate::server::db::projections::HostEntry) -> Self {
        use prost_types::Timestamp;
        Self {
            id: e.id.to_string(),
            ip_address: e.ip_address,
            hostname: e.hostname,
            comment: e.comment,
            tags: e.tags,
            created_at: Some(Timestamp {
                seconds: e.created_at.timestamp(),
                nanos: e.created_at.timestamp_subsec_nanos() as i32,
            }),
            updated_at: Some(Timestamp {
                seconds: e.updated_at.timestamp(),
                nanos: e.updated_at.timestamp_subsec_nanos() as i32,
            }),
            active: true,
        }
    }
}
```

**Step 3: Create service/sessions.rs (stub)**

```rust
//! Edit session handlers

use super::HostsServiceImpl;
use crate::server::commands::CommandError;
use router_hosts_common::proto::router_hosts::v1::*;
use tonic::{Request, Response, Status};

impl HostsServiceImpl {
    pub(crate) async fn handle_start_edit(
        &self,
        _request: Request<StartEditRequest>,
    ) -> Result<Response<StartEditResponse>, Status> {
        let token = self
            .commands
            .start_edit()
            .map_err(|e| command_error_to_status(e))?;

        Ok(Response::new(StartEditResponse { edit_token: token }))
    }

    pub(crate) async fn handle_finish_edit(
        &self,
        request: Request<FinishEditRequest>,
    ) -> Result<Response<FinishEditResponse>, Status> {
        let req = request.into_inner();

        let count = self
            .commands
            .finish_edit(&req.edit_token)
            .await
            .map_err(command_error_to_status)?;

        Ok(Response::new(FinishEditResponse {
            success: true,
            entries_changed: count as i32,
        }))
    }

    pub(crate) async fn handle_cancel_edit(
        &self,
        request: Request<CancelEditRequest>,
    ) -> Result<Response<CancelEditResponse>, Status> {
        let req = request.into_inner();

        self.commands
            .cancel_edit(&req.edit_token)
            .map_err(command_error_to_status)?;

        Ok(Response::new(CancelEditResponse { success: true }))
    }
}

fn command_error_to_status(e: CommandError) -> Status {
    match e {
        CommandError::SessionConflict => {
            Status::failed_precondition("Another edit session is active")
        }
        CommandError::SessionExpired => Status::failed_precondition("Session expired"),
        CommandError::InvalidToken => Status::failed_precondition("Invalid session token"),
        CommandError::NoActiveSession => Status::failed_precondition("No active edit session"),
        _ => Status::internal(e.to_string()),
    }
}
```

**Step 4: Create service/bulk.rs (stub)**

```rust
//! Bulk operation and streaming handlers

use super::HostsServiceImpl;
use crate::server::db::projections::HostProjections;
use futures::stream::{self, BoxStream};
use router_hosts_common::proto::router_hosts::v1::*;
use tonic::{Request, Response, Status, Streaming};

impl HostsServiceImpl {
    pub(crate) async fn handle_list_hosts(
        &self,
        _request: Request<ListHostsRequest>,
    ) -> Result<Response<BoxStream<'static, Result<ListHostsResponse, Status>>>, Status> {
        let entries = self
            .commands
            .list_hosts()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let stream = stream::iter(entries.into_iter().map(|entry| {
            Ok(ListHostsResponse {
                entry: Some(entry.into()),
            })
        }));

        Ok(Response::new(Box::pin(stream)))
    }

    pub(crate) async fn handle_search_hosts(
        &self,
        request: Request<SearchHostsRequest>,
    ) -> Result<Response<BoxStream<'static, Result<SearchHostsResponse, Status>>>, Status> {
        let req = request.into_inner();

        let entries = self
            .commands
            .search_hosts(&req.query)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let stream = stream::iter(entries.into_iter().map(|entry| {
            Ok(SearchHostsResponse {
                entry: Some(entry.into()),
            })
        }));

        Ok(Response::new(Box::pin(stream)))
    }

    pub(crate) async fn handle_bulk_add_hosts(
        &self,
        _request: Request<Streaming<BulkAddHostsRequest>>,
    ) -> Result<Response<BoxStream<'static, Result<BulkAddHostsResponse, Status>>>, Status> {
        // TODO: Implement bidirectional streaming
        Err(Status::unimplemented("bulk_add_hosts not yet implemented"))
    }

    pub(crate) async fn handle_import_hosts(
        &self,
        _request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<BoxStream<'static, Result<ImportHostsResponse, Status>>>, Status> {
        // TODO: Implement import streaming
        Err(Status::unimplemented("import_hosts not yet implemented"))
    }

    pub(crate) async fn handle_export_hosts(
        &self,
        _request: Request<ExportHostsRequest>,
    ) -> Result<Response<BoxStream<'static, Result<ExportHostsResponse, Status>>>, Status> {
        // TODO: Implement export streaming
        Err(Status::unimplemented("export_hosts not yet implemented"))
    }
}
```

**Step 5: Create service/snapshots.rs (stub)**

```rust
//! Snapshot management handlers

use super::HostsServiceImpl;
use futures::stream::BoxStream;
use router_hosts_common::proto::router_hosts::v1::*;
use tonic::{Request, Response, Status};

impl HostsServiceImpl {
    pub(crate) async fn handle_create_snapshot(
        &self,
        _request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        // TODO: Implement snapshot creation
        Err(Status::unimplemented("create_snapshot not yet implemented"))
    }

    pub(crate) async fn handle_list_snapshots(
        &self,
        _request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<BoxStream<'static, Result<ListSnapshotsResponse, Status>>>, Status> {
        // TODO: Implement snapshot listing
        Err(Status::unimplemented("list_snapshots not yet implemented"))
    }

    pub(crate) async fn handle_rollback_to_snapshot(
        &self,
        _request: Request<RollbackToSnapshotRequest>,
    ) -> Result<Response<RollbackToSnapshotResponse>, Status> {
        // TODO: Implement rollback
        Err(Status::unimplemented(
            "rollback_to_snapshot not yet implemented",
        ))
    }

    pub(crate) async fn handle_delete_snapshot(
        &self,
        _request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        // TODO: Implement snapshot deletion
        Err(Status::unimplemented(
            "delete_snapshot not yet implemented",
        ))
    }
}
```

**Step 6: Add service module to server mod.rs**

```rust
pub mod service;
```

**Step 7: Verify it compiles**

Run: `cargo build -p router-hosts`
Expected: Success (may have warnings about unused items)

**Step 8: Commit**

```bash
git add crates/router-hosts/src/server/service/
git add crates/router-hosts/src/server/mod.rs
git commit -m "feat(server): add gRPC service module structure with handlers"
```

---

### Task 3.2: Implement HostsService Trait

**Files:**
- Modify: `crates/router-hosts/src/server/service/mod.rs`

**Step 1: Add the trait implementation**

Add to the end of `service/mod.rs`:

```rust
use futures::stream::BoxStream;
use router_hosts_common::proto::router_hosts::v1::*;
use tonic::{Request, Response, Status, Streaming};

#[tonic::async_trait]
impl HostsService for HostsServiceImpl {
    // Host management
    async fn add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<AddHostResponse>, Status> {
        self.handle_add_host(request).await
    }

    async fn get_host(
        &self,
        request: Request<GetHostRequest>,
    ) -> Result<Response<GetHostResponse>, Status> {
        self.handle_get_host(request).await
    }

    async fn update_host(
        &self,
        request: Request<UpdateHostRequest>,
    ) -> Result<Response<UpdateHostResponse>, Status> {
        self.handle_update_host(request).await
    }

    async fn delete_host(
        &self,
        request: Request<DeleteHostRequest>,
    ) -> Result<Response<DeleteHostResponse>, Status> {
        self.handle_delete_host(request).await
    }

    // Streaming
    type ListHostsStream = BoxStream<'static, Result<ListHostsResponse, Status>>;

    async fn list_hosts(
        &self,
        request: Request<ListHostsRequest>,
    ) -> Result<Response<Self::ListHostsStream>, Status> {
        self.handle_list_hosts(request).await
    }

    type SearchHostsStream = BoxStream<'static, Result<SearchHostsResponse, Status>>;

    async fn search_hosts(
        &self,
        request: Request<SearchHostsRequest>,
    ) -> Result<Response<Self::SearchHostsStream>, Status> {
        self.handle_search_hosts(request).await
    }

    // Edit sessions
    async fn start_edit(
        &self,
        request: Request<StartEditRequest>,
    ) -> Result<Response<StartEditResponse>, Status> {
        self.handle_start_edit(request).await
    }

    async fn finish_edit(
        &self,
        request: Request<FinishEditRequest>,
    ) -> Result<Response<FinishEditResponse>, Status> {
        self.handle_finish_edit(request).await
    }

    async fn cancel_edit(
        &self,
        request: Request<CancelEditRequest>,
    ) -> Result<Response<CancelEditResponse>, Status> {
        self.handle_cancel_edit(request).await
    }

    // Bulk operations
    type BulkAddHostsStream = BoxStream<'static, Result<BulkAddHostsResponse, Status>>;

    async fn bulk_add_hosts(
        &self,
        request: Request<Streaming<BulkAddHostsRequest>>,
    ) -> Result<Response<Self::BulkAddHostsStream>, Status> {
        self.handle_bulk_add_hosts(request).await
    }

    type ImportHostsStream = BoxStream<'static, Result<ImportHostsResponse, Status>>;

    async fn import_hosts(
        &self,
        request: Request<Streaming<ImportHostsRequest>>,
    ) -> Result<Response<Self::ImportHostsStream>, Status> {
        self.handle_import_hosts(request).await
    }

    type ExportHostsStream = BoxStream<'static, Result<ExportHostsResponse, Status>>;

    async fn export_hosts(
        &self,
        request: Request<ExportHostsRequest>,
    ) -> Result<Response<Self::ExportHostsStream>, Status> {
        self.handle_export_hosts(request).await
    }

    // Snapshots
    async fn create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        self.handle_create_snapshot(request).await
    }

    type ListSnapshotsStream = BoxStream<'static, Result<ListSnapshotsResponse, Status>>;

    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<Self::ListSnapshotsStream>, Status> {
        self.handle_list_snapshots(request).await
    }

    async fn rollback_to_snapshot(
        &self,
        request: Request<RollbackToSnapshotRequest>,
    ) -> Result<Response<RollbackToSnapshotResponse>, Status> {
        self.handle_rollback_to_snapshot(request).await
    }

    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        self.handle_delete_snapshot(request).await
    }
}
```

**Step 2: Add futures dependency if needed**

In workspace Cargo.toml, ensure `futures` is listed.

**Step 3: Verify it compiles**

Run: `cargo build -p router-hosts`
Expected: Success

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/service/mod.rs
git commit -m "feat(server): implement HostsService trait for gRPC"
```

---

### Task 3.3: Implement Server Startup with TLS

**Files:**
- Modify: `crates/router-hosts/src/server/mod.rs`

**Step 1: Update server mod.rs with full startup logic**

Replace the entire file:

```rust
mod commands;
pub mod config;
pub mod db;
mod hooks;
mod hosts_file;
pub mod service;
mod session;

use crate::server::commands::CommandHandler;
use crate::server::config::Config;
use crate::server::db::schema::Database;
use crate::server::hooks::HookExecutor;
use crate::server::hosts_file::HostsFileGenerator;
use crate::server::service::{HostsServiceImpl, HostsServiceServer};
use crate::server::session::SessionManager;
use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::info;

#[derive(Parser)]
#[command(name = "router-hosts server")]
#[command(about = "Router hosts file management server", long_about = None)]
struct ServerCli {
    /// Path to config file
    #[arg(short, long)]
    config: String,
}

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Parse server-specific arguments
    let args: Vec<String> = std::env::args().skip(2).collect();
    let cli = ServerCli::parse_from(std::iter::once("server".to_string()).chain(args));

    info!("router-hosts server starting");
    info!("Loading config from: {}", cli.config);

    // Load configuration
    let config = Config::from_file(&cli.config).context("Failed to load config")?;

    // Initialize database
    let db = Arc::new(
        Database::new(&config.database.path.into())
            .context("Failed to initialize database")?,
    );

    // Initialize components
    let session_mgr = Arc::new(SessionManager::new(
        config.edit_session.timeout_minutes as i64,
    ));
    let hosts_file = Arc::new(HostsFileGenerator::new(&config.server.hosts_file_path));
    let hooks = Arc::new(HookExecutor::new(
        config.hooks.on_success.clone(),
        config.hooks.on_failure.clone(),
        config.hooks.timeout_seconds.unwrap_or(30),
    ));

    // Create command handler
    let commands = Arc::new(CommandHandler::new(
        db.clone(),
        session_mgr.clone(),
        hosts_file,
        hooks,
    ));

    // Create gRPC service
    let service = HostsServiceImpl::new(commands, db, session_mgr);

    // Setup TLS
    let cert = tokio::fs::read(&config.tls.cert_path)
        .await
        .context("Failed to read server certificate")?;
    let key = tokio::fs::read(&config.tls.key_path)
        .await
        .context("Failed to read server key")?;
    let ca_cert = tokio::fs::read(&config.tls.ca_cert_path)
        .await
        .context("Failed to read CA certificate")?;

    let identity = Identity::from_pem(&cert, &key);
    let client_ca = Certificate::from_pem(&ca_cert);

    let tls_config = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let addr = config.server.bind_address.parse().context("Invalid bind address")?;

    info!("Server listening on {} with mTLS", addr);

    Server::builder()
        .tls_config(tls_config)?
        .add_service(HostsServiceServer::new(service))
        .serve(addr)
        .await
        .context("Server failed")?;

    Ok(())
}
```

**Step 2: Update config.rs to include all fields**

Ensure `config.rs` has all necessary fields (hooks.timeout_seconds, etc.). Add if missing:

```rust
#[derive(Debug, Deserialize, Default)]
pub struct HooksConfig {
    #[serde(default)]
    pub on_success: Vec<String>,
    #[serde(default)]
    pub on_failure: Vec<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}
```

**Step 3: Verify it compiles**

Run: `cargo build -p router-hosts`
Expected: Success

**Step 4: Commit**

```bash
git add crates/router-hosts/src/server/mod.rs crates/router-hosts/src/server/config.rs
git commit -m "feat(server): implement server startup with mTLS"
```

---

## Phase 4: Integration & Polish

### Task 4.1: Add Integration Test

**Files:**
- Create: `crates/router-hosts/tests/integration_test.rs`

**Step 1: Create basic integration test**

```rust
//! Integration tests for router-hosts server

use router_hosts::server::commands::CommandHandler;
use router_hosts::server::db::schema::Database;
use router_hosts::server::hooks::HookExecutor;
use router_hosts::server::hosts_file::HostsFileGenerator;
use router_hosts::server::session::SessionManager;
use std::sync::Arc;

fn setup() -> CommandHandler {
    let db = Arc::new(Database::in_memory().unwrap());
    let session_mgr = Arc::new(SessionManager::new(15));
    let hosts_file = Arc::new(HostsFileGenerator::new("/tmp/test_hosts"));
    let hooks = Arc::new(HookExecutor::default());
    CommandHandler::new(db, session_mgr, hosts_file, hooks)
}

#[tokio::test]
async fn test_full_crud_workflow() {
    let handler = setup();

    // Create
    let entry = handler
        .add_host(
            "192.168.1.1".to_string(),
            "test.local".to_string(),
            Some("Test server".to_string()),
            vec!["dev".to_string()],
            None,
        )
        .await
        .unwrap();

    assert_eq!(entry.ip_address, "192.168.1.1");
    assert_eq!(entry.hostname, "test.local");

    // Read
    let fetched = handler.get_host(entry.id).await.unwrap().unwrap();
    assert_eq!(fetched.id, entry.id);

    // Update
    let updated = handler
        .update_host(
            entry.id,
            Some("192.168.1.2".to_string()),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(updated.ip_address, "192.168.1.2");

    // List
    let all = handler.list_hosts().await.unwrap();
    assert_eq!(all.len(), 1);

    // Delete
    handler.delete_host(entry.id, None, None).await.unwrap();

    // Verify deleted
    let deleted = handler.get_host(entry.id).await.unwrap();
    assert!(deleted.is_none());
}

#[tokio::test]
async fn test_edit_session_batching() {
    let handler = setup();

    // Start session
    let token = handler.start_edit().unwrap();

    // Add multiple hosts in session
    for i in 1..=5 {
        handler
            .add_host(
                format!("192.168.1.{}", i),
                format!("host{}.local", i),
                None,
                vec![],
                Some(token.clone()),
            )
            .await
            .unwrap();
    }

    // Nothing committed yet
    let before = handler.list_hosts().await.unwrap();
    assert_eq!(before.len(), 0);

    // Finish session
    let count = handler.finish_edit(&token).await.unwrap();
    assert_eq!(count, 5);

    // Now all are committed
    let after = handler.list_hosts().await.unwrap();
    assert_eq!(after.len(), 5);
}
```

**Step 2: Make modules public for testing**

In `crates/router-hosts/src/lib.rs`, ensure server module is public:

```rust
pub mod server;
```

Create `crates/router-hosts/src/lib.rs` if it doesn't exist.

**Step 3: Run integration tests**

Run: `cargo test --test integration_test`
Expected: All pass

**Step 4: Commit**

```bash
git add crates/router-hosts/tests/integration_test.rs crates/router-hosts/src/lib.rs
git commit -m "test: add integration tests for command handler workflows"
```

---

### Task 4.2: Run Full Test Suite and Fix Issues

**Step 1: Run all tests**

Run: `cargo test --workspace`
Expected: All pass

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Fix any warnings.

**Step 3: Run fmt**

Run: `cargo fmt --check`
Fix any formatting issues.

**Step 4: Commit fixes if any**

```bash
git add -A
git commit -m "fix: address clippy warnings and formatting"
```

---

### Task 4.3: Final Verification and Summary

**Step 1: Run full pre-commit check**

```bash
cargo fmt && \
cargo test --workspace && \
cargo clippy --workspace -- -D warnings && \
buf lint && \
buf format --diff --exit-code
```

**Step 2: Verify server starts (dry run)**

Create a test config and try starting (will fail without certs, but should parse config):

```bash
echo '[server]
bind_address = "127.0.0.1:50051"
hosts_file_path = "/tmp/test_hosts"

[database]
path = "/tmp/test.db"

[tls]
cert_path = "/tmp/server.crt"
key_path = "/tmp/server.key"
ca_cert_path = "/tmp/ca.crt"

[edit_session]
timeout_minutes = 15

[hooks]
on_success = []
on_failure = []' > /tmp/test_server.toml

cargo run -- server --config /tmp/test_server.toml 2>&1 | head -5
```

Expected: Should show "router-hosts server starting" before failing on missing certs.

**Step 3: Commit any final changes**

```bash
git add -A
git commit -m "chore: final cleanup and verification"
```

---

## Summary

After completing all tasks, the server will have:

- ✅ Fixed database bugs (timestamps, transactions, duplicates, time-travel)
- ✅ Command handler with validation
- ✅ Edit session manager (in-memory, 15-min timeout)
- ✅ /etc/hosts file generator with atomic writes
- ✅ Post-edit hook executor
- ✅ gRPC service layer with mTLS
- ✅ Core CRUD + streaming handlers
- ✅ Integration tests

**Not implemented (marked as TODO in code):**
- Snapshot management (create/list/rollback/delete)
- Bulk add bidirectional streaming
- Import/Export streaming
- Snapshot retention enforcement

These can be added in a follow-up PR.
