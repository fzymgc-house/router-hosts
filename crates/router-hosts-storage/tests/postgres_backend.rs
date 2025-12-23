//! PostgreSQL backend test runner
//!
//! This module runs the shared test suite against the PostgreSQL storage backend
//! using testcontainers for ephemeral database instances.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p router-hosts-storage --features postgres --test postgres_backend
//! ```
//!
//! # Prerequisites
//!
//! - Docker must be running (testcontainers uses Docker to spin up PostgreSQL)
//! - The `postgres` feature must be enabled
//!
//! # Notes
//!
//! Unlike SQLite/DuckDB which use in-memory databases, PostgreSQL tests spin up
//! a real PostgreSQL container. This makes tests slower but ensures compatibility
//! with production PostgreSQL behavior.

#![cfg(feature = "postgres")]

mod common;

use router_hosts_storage::backends::postgres::PostgresStorage;
use router_hosts_storage::Storage;
use testcontainers::runners::AsyncRunner;
use testcontainers::ImageExt;
use testcontainers_modules::postgres::Postgres;

/// Create an initialized PostgreSQL storage using testcontainers
///
/// Uses PostgreSQL 17 (latest stable). The schema is compatible with PostgreSQL 12+
/// using DISTINCT ON for "last non-null value" patterns (IGNORE NULLS not supported until PG19).
async fn create_storage() -> (PostgresStorage, testcontainers::ContainerAsync<Postgres>) {
    // Start a PostgreSQL 17 container (latest stable as of Dec 2024)
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("failed to start PostgreSQL container");

    // Get connection parameters
    let host = container.get_host().await.expect("failed to get host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get port");

    // Build connection URL (default user/password/db from testcontainers-modules)
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);

    // Create and initialize storage
    let storage = PostgresStorage::new(&url)
        .await
        .expect("failed to create PostgreSQL storage");
    storage
        .initialize()
        .await
        .expect("failed to initialize PostgreSQL storage");

    // Return both storage and container (container must stay alive for tests)
    (storage, container)
}

// ============================================================================
// Full Test Suite
// ============================================================================

/// Run the complete storage test suite against PostgreSQL
#[tokio::test]
async fn postgres_passes_all_storage_tests() {
    let (storage, _container) = create_storage().await;
    common::run_all_tests(&storage).await;
}

// ============================================================================
// Individual Test Suites (for targeted testing)
// ============================================================================

/// Run only EventStore tests against PostgreSQL
#[tokio::test]
async fn postgres_passes_event_store_tests() {
    let (storage, _container) = create_storage().await;
    common::run_event_store_tests(&storage).await;
}

/// Run only SnapshotStore tests against PostgreSQL
#[tokio::test]
async fn postgres_passes_snapshot_store_tests() {
    let (storage, _container) = create_storage().await;
    common::run_snapshot_store_tests(&storage).await;
}

/// Run only HostProjection tests against PostgreSQL
#[tokio::test]
async fn postgres_passes_host_projection_tests() {
    let (storage, _container) = create_storage().await;
    common::run_host_projection_tests(&storage).await;
}

// ============================================================================
// PostgreSQL-Specific Tests
// ============================================================================

/// Test PostgreSQL health check
#[tokio::test]
async fn postgres_health_check() {
    let (storage, _container) = create_storage().await;

    let result = storage.health_check().await;
    assert!(result.is_ok(), "health check should succeed: {:?}", result);
}

/// Test PostgreSQL close is safe
#[tokio::test]
async fn postgres_close_works() {
    let (storage, _container) = create_storage().await;

    // Close the connection pool
    storage.close().await.expect("close should succeed");

    // Note: Unlike SQLite, closing PostgreSQL pool makes it unusable
    // We don't test double-close because pool.close() consumes connections
}

/// Test PostgreSQL initialization is idempotent
#[tokio::test]
async fn postgres_initialize_is_idempotent() {
    let (storage, _container) = create_storage().await;

    // Storage is already initialized in create_storage()
    // Second init should also succeed (uses IF NOT EXISTS)
    storage
        .initialize()
        .await
        .expect("second initialize should succeed");

    // Storage should work normally
    storage
        .health_check()
        .await
        .expect("health check should succeed after double init");
}

/// Test PostgreSQL connection string parsing
#[tokio::test]
async fn postgres_connection_string_parsing() {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("failed to start PostgreSQL container");

    let host = container.get_host().await.expect("failed to get host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("failed to get port");

    // Test standard connection URL format
    let url = format!("postgres://postgres:postgres@{}:{}/postgres", host, port);
    let storage = PostgresStorage::new(&url).await;
    assert!(
        storage.is_ok(),
        "should accept standard postgres:// URL: {:?}",
        storage
    );
}

/// Test PostgreSQL rejects invalid connection string
#[tokio::test]
async fn postgres_rejects_invalid_connection_string() {
    // Invalid host should fail
    let result = PostgresStorage::new("postgres://localhost:99999/nonexistent").await;
    assert!(
        result.is_err(),
        "should reject invalid connection string: {:?}",
        result
    );
}

// ============================================================================
// Migration Tests
// ============================================================================

/// Test that migrations create all expected tables
#[tokio::test]
async fn postgres_migrations_create_tables() {
    let (storage, _container) = create_storage().await;

    // Verify host_events table exists
    let tables: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT table_name::text FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'
        ORDER BY table_name
        "#,
    )
    .fetch_all(storage.pool())
    .await
    .expect("should be able to query tables");

    let table_names: Vec<&str> = tables.iter().map(|(name,)| name.as_str()).collect();

    assert!(
        table_names.contains(&"host_events"),
        "host_events table should exist, found: {:?}",
        table_names
    );
    assert!(
        table_names.contains(&"snapshots"),
        "snapshots table should exist, found: {:?}",
        table_names
    );
    assert!(
        table_names.contains(&"_sqlx_migrations"),
        "_sqlx_migrations table should exist, found: {:?}",
        table_names
    );
}

/// Test that migrations create all expected views
#[tokio::test]
async fn postgres_migrations_create_views() {
    let (storage, _container) = create_storage().await;

    // Query for views
    let views: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT table_name::text FROM information_schema.views
        WHERE table_schema = 'public'
        ORDER BY table_name
        "#,
    )
    .fetch_all(storage.pool())
    .await
    .expect("should be able to query views");

    let view_names: Vec<&str> = views.iter().map(|(name,)| name.as_str()).collect();

    assert!(
        view_names.contains(&"host_entries_current"),
        "host_entries_current view should exist, found: {:?}",
        view_names
    );
    assert!(
        view_names.contains(&"host_entries_history"),
        "host_entries_history view should exist, found: {:?}",
        view_names
    );
}

/// Test that migrations create all expected indexes
#[tokio::test]
async fn postgres_migrations_create_indexes() {
    let (storage, _container) = create_storage().await;

    // Query pg_indexes for our tables
    let indexes: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT tablename::text, indexname::text
        FROM pg_indexes
        WHERE schemaname = 'public'
          AND indexname NOT LIKE '%_pkey'
        ORDER BY tablename, indexname
        "#,
    )
    .fetch_all(storage.pool())
    .await
    .expect("should be able to query indexes");

    let index_names: Vec<&str> = indexes.iter().map(|(_, name)| name.as_str()).collect();

    // Verify all expected indexes on host_events
    assert!(
        index_names.contains(&"idx_events_aggregate"),
        "idx_events_aggregate index should exist, found: {:?}",
        index_names
    );
    assert!(
        index_names.contains(&"idx_events_time"),
        "idx_events_time index should exist, found: {:?}",
        index_names
    );
    assert!(
        index_names.contains(&"idx_events_ip_hostname"),
        "idx_events_ip_hostname index should exist, found: {:?}",
        index_names
    );

    // Verify snapshots index
    assert!(
        index_names.contains(&"idx_snapshots_created"),
        "idx_snapshots_created index should exist, found: {:?}",
        index_names
    );
}

/// Test that migrations are recorded correctly
#[tokio::test]
async fn postgres_migrations_recorded() {
    let (storage, _container) = create_storage().await;

    // Verify migrations table has at least one entry
    let migrations_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(storage.pool())
        .await
        .expect("_sqlx_migrations table should exist");

    assert!(
        migrations_count.0 >= 1,
        "at least one migration should be recorded"
    );
}
