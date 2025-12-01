# Server Completion Design

**Date:** 2025-11-30
**Status:** Draft

## Overview

Complete implementation plan for the router-hosts server, from current state (database layer with bugs) to fully functional gRPC server with mTLS, edit sessions, /etc/hosts generation, and snapshot management.

## Implementation Phases

### Phase 1: Database Stabilization (~1 day)

- Fix timestamp format inconsistency (RFC3339 → micros)
- Fix broken `get_at_time()` SQL query
- Add transaction boundaries to `append_event()`
- Add duplicate IP+hostname detection
- Remove unused `EventMetadata` parameter

### Phase 2: Core Server Infrastructure (~2 days)

- Command handlers module (`commands.rs`)
- Edit session manager (in-memory, Mutex-based)
- `/etc/hosts` file generator with atomic writes
- Post-edit hook executor

### Phase 3: gRPC Service Layer (~2-3 days)

- TLS setup (rustls + webpki, mTLS)
- Service modules: hosts, bulk, sessions, snapshots
- Wire handlers to command layer
- Streaming implementations for List/Search/Export

### Phase 4: Integration & Polish (~1 day)

- Snapshot retention (prune on create)
- Server startup/shutdown
- Config loading and validation
- End-to-end tests

## Module Structure

```
crates/router-hosts/src/server/
├── mod.rs                 # Server startup, TLS config, gRPC server
├── config.rs              # Config structs (exists)
├── commands.rs            # Command validation + event generation
├── session.rs             # EditSession manager (in-memory)
├── hosts_file.rs          # /etc/hosts generation + atomic write
├── hooks.rs               # Post-edit hook execution
├── db/
│   ├── mod.rs
│   ├── schema.rs          # DuckDB init (exists, minor fixes)
│   ├── events.rs          # Event types (exists)
│   ├── event_store.rs     # Event persistence (exists, fixes needed)
│   └── projections.rs     # Read models (exists, fixes needed)
└── service/
    ├── mod.rs             # HostsService impl, routes to sub-modules
    ├── hosts.rs           # Add/Get/Update/Delete handlers
    ├── bulk.rs            # BulkAdd, Import, Export (streaming)
    ├── sessions.rs        # StartEdit/FinishEdit/CancelEdit
    └── snapshots.rs       # Create/List/Rollback/Delete snapshots
```

**Module dependencies:**

- `service/*` → `commands` → `db/event_store` + `db/projections`
- `service/*` → `session` (for edit token validation)
- `commands` → `hosts_file` → `hooks` (on successful writes)

## Command Handler Design

The `commands.rs` module centralizes validation and event generation:

```rust
pub struct CommandHandler {
    db: Arc<Database>,
    session_mgr: Arc<SessionManager>,
    hosts_file: Arc<HostsFileGenerator>,
}

impl CommandHandler {
    pub async fn add_host(&self, req: AddHostRequest, edit_token: Option<String>)
        -> Result<HostEntry, CommandError>;

    pub async fn update_host(&self, req: UpdateHostRequest, edit_token: Option<String>)
        -> Result<HostEntry, CommandError>;

    pub async fn delete_host(&self, id: Ulid, edit_token: Option<String>)
        -> Result<(), CommandError>;
}
```

**Validation flow for AddHost:**

1. Validate IP format (via `router-hosts-common`)
2. Validate hostname format (via `router-hosts-common`)
3. Check for duplicate IP+hostname
4. Generate `HostCreated` event
5. Append to event store (with transaction)
6. If no edit token: regenerate `/etc/hosts`, run success hooks
7. If edit token: stage change, defer regeneration to `FinishEdit`

**Edit token behavior:**

- Without token: immediate write + file regeneration
- With valid token: stage in session, reset 15-min timeout
- With invalid/expired token: return `FAILED_PRECONDITION`

## Edit Session Manager

Simple in-memory session tracking:

```rust
pub struct SessionManager {
    active: Mutex<Option<ActiveSession>>,
}

struct ActiveSession {
    token: String,
    started_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    staged_events: Vec<(Ulid, HostEvent)>,
}

impl SessionManager {
    pub fn start_edit(&self) -> Result<String, SessionError>;
    pub fn validate_token(&self, token: &str) -> Result<(), SessionError>;
    pub fn touch(&self, token: &str);  // Reset timeout
    pub fn stage_event(&self, token: &str, agg_id: Ulid, event: HostEvent);
    pub fn finish_edit(&self, token: &str) -> Result<Vec<(Ulid, HostEvent)>, SessionError>;
    pub fn cancel_edit(&self, token: &str) -> Result<(), SessionError>;
}
```

**Timeout handling:**

- `validate_token()` checks if `last_activity + 15min > now`
- Expired session returns `SessionError::Expired`
- No background cleanup needed - stale sessions rejected on next access

**Token generation:** ULID (already a dependency)

## /etc/hosts Generation

```rust
pub struct HostsFileGenerator {
    path: PathBuf,
    hooks: HookExecutor,
}

impl HostsFileGenerator {
    pub async fn regenerate(&self, db: &Database) -> Result<(), GenerateError> {
        // 1. Query all active hosts from projection
        let entries = HostProjections::list_all(db)?;

        // 2. Generate content
        let content = self.format_hosts_file(&entries);

        // 3. Atomic write: write to .tmp, fsync, rename
        let tmp_path = self.path.with_extension("tmp");
        fs::write(&tmp_path, &content).await?;
        File::open(&tmp_path).await?.sync_all().await?;
        fs::rename(&tmp_path, &self.path).await?;

        // 4. Run success hooks
        self.hooks.run_success(entries.len()).await;

        Ok(())
    }
}
```

**Output format:**

```
# Generated by router-hosts
# Last updated: 2025-11-30 12:00:00 UTC
# Entry count: 42

192.168.1.10    server.local
192.168.1.20    nas.local         # NAS storage [backup, homelab]
```

- Sorted by IP, then hostname (deterministic)
- Comments inline, tags in brackets
- Header with metadata

## gRPC Service Layer

```rust
pub struct HostsServiceImpl {
    commands: Arc<CommandHandler>,
    session_mgr: Arc<SessionManager>,
    db: Arc<Database>,
}

#[tonic::async_trait]
impl HostsService for HostsServiceImpl {
    async fn add_host(&self, req: Request<AddHostRequest>)
        -> Result<Response<AddHostResponse>, Status>;
    // ... other methods delegate to sub-modules
}
```

**TLS setup:**

```rust
let tls_config = ServerTlsConfig::new()
    .identity(Identity::from_pem(&cert, &key))
    .client_ca_root(Certificate::from_pem(&ca_cert));  // mTLS

Server::builder()
    .tls_config(tls_config)?
    .add_service(HostsServiceServer::new(service))
    .serve(addr)
    .await?;
```

**Error mapping:**

| CommandError | gRPC Status |
|--------------|-------------|
| ValidationFailed | INVALID_ARGUMENT |
| DuplicateEntry | ALREADY_EXISTS |
| NotFound | NOT_FOUND |
| SessionConflict | FAILED_PRECONDITION |
| SessionExpired | FAILED_PRECONDITION |
| Internal | INTERNAL |

## Streaming Handlers

```rust
async fn list_hosts(
    &self,
    request: Request<ListHostsRequest>,
) -> Result<Response<Self::ListHostsStream>, Status> {
    let entries = HostProjections::list_all(&self.db)?;

    let stream = futures::stream::iter(entries)
        .map(|entry| Ok(ListHostsResponse { host: Some(entry.into()) }));

    Ok(Response::new(Box::pin(stream)))
}

async fn bulk_add_hosts(
    &self,
    request: Request<Streaming<BulkAddHostsRequest>>,
) -> Result<Response<Self::BulkAddHostsStream>, Status> {
    let mut in_stream = request.into_inner();
    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        while let Some(req) = in_stream.next().await {
            let result = self.commands.add_host(req?, None).await;
            tx.send(result.into()).await?;
        }
    });

    Ok(Response::new(ReceiverStream::new(rx)))
}
```

**Backpressure:** Channel-based with bounded buffer (32).

## Database Fixes (Phase 1)

### 1. Timestamp format (`event_store.rs`)

```rust
// Before (wrong)
&event_timestamp.to_rfc3339(),

// After
&event_timestamp.timestamp_micros(),
```

### 2. Fix `get_at_time()` (`projections.rs`)

Replace broken query referencing non-existent columns. Use same approach as `load_events()` - query actual columns (`ip_address`, `hostname`, `metadata`), reconstruct events.

### 3. Transaction boundary (`event_store.rs`)

```rust
db.conn().execute("BEGIN TRANSACTION", [])?;
let current_version = Self::get_current_version(db, aggregate_id)?;
// ... version check, insert ...
db.conn().execute("COMMIT", [])?;
```

### 4. Duplicate detection (`event_store.rs`)

```rust
if let HostEvent::HostCreated { ip_address, hostname, .. } = &event {
    if HostProjections::find_by_ip_and_hostname(db, ip_address, hostname)?.is_some() {
        return Err(DatabaseError::DuplicateEntry(...));
    }
}
```

### 5. Remove unused parameter

Drop `metadata: Option<EventMetadata>` from `append_event()` signature.

## Snapshot Retention

Enforcement on snapshot creation:

```rust
impl SnapshotManager {
    pub fn create(
        db: &Database,
        trigger: SnapshotTrigger,
        name: Option<String>,
    ) -> DatabaseResult<Snapshot> {
        // 1. Generate hosts content from current state
        let entries = HostProjections::list_all(db)?;
        let content = format_hosts_content(&entries);

        // 2. Insert snapshot
        let snapshot_id = Ulid::new();
        db.conn().execute("INSERT INTO snapshots (...) VALUES (...)", [...])?;

        // 3. Prune old snapshots
        Self::enforce_retention(db, max_snapshots, max_age_days)?;

        Ok(snapshot)
    }

    fn enforce_retention(db: &Database, max_count: u32, max_age_days: u32) -> DatabaseResult<()> {
        // Delete by age first
        db.conn().execute(
            "DELETE FROM snapshots WHERE created_at < ?",
            [&(Utc::now() - Duration::days(max_age_days as i64))],
        )?;

        // Then enforce count limit (keep newest)
        db.conn().execute(
            "DELETE FROM snapshots WHERE snapshot_id NOT IN (
                SELECT snapshot_id FROM snapshots ORDER BY created_at DESC LIMIT ?
            )",
            [&max_count],
        )?;

        Ok(())
    }
}
```

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| TLS | rustls + webpki | tonic first-class support, no OpenSSL for OpenWrt |
| Edit sessions | In-memory | Short-lived by design, restart loss acceptable |
| File regeneration | On every write | Infrequent changes, atomic writes cheap, simpler |
| Domain model | Command handlers | Lightweight, domain is simple, avoids DDD overhead |
| Service structure | Split by concern | 15 methods warrants organization |
| Snapshot retention | Prune on create | Fast, no background task, always enforced |
