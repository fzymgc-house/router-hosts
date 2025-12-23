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
// Schema Validation
// ============================================================================
// Note: Detailed migration tests (table/view/index verification) are performed
// via the shared test suite in common/. The 42-test suite exercises all storage
// operations which implicitly validates the schema. Additional schema verification
// using direct pool access would require pub visibility, breaking encapsulation.
//
// The health_check test above verifies that:
// 1. Database connectivity works
// 2. The host_events table exists (schema was applied)
