//! SQLite backend test runner
//!
//! This module runs the shared test suite against the SQLite storage backend.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p router-hosts-storage --features sqlite --test sqlite_backend
//! ```
//!
//! # Notes
//!
//! This file mirrors the DuckDB backend test runner structure. The shared test suite
//! in `common/` validates that both backends behave identically for all storage
//! operations.

#![cfg(feature = "sqlite")]

mod common;

use router_hosts_storage::backends::sqlite::SqliteStorage;
use router_hosts_storage::Storage;

/// Create an initialized in-memory SQLite storage for testing
async fn create_storage() -> SqliteStorage {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("failed to create SQLite storage");
    storage
        .initialize()
        .await
        .expect("failed to initialize SQLite storage");
    storage
}

// ============================================================================
// Full Test Suite
// ============================================================================

/// Run the complete storage test suite against SQLite
#[tokio::test]
async fn sqlite_passes_all_storage_tests() {
    let storage = create_storage().await;
    common::run_all_tests(&storage).await;
}

// ============================================================================
// Individual Test Suites (for targeted testing)
// ============================================================================

/// Run only EventStore tests against SQLite
#[tokio::test]
async fn sqlite_passes_event_store_tests() {
    let storage = create_storage().await;
    common::run_event_store_tests(&storage).await;
}

/// Run only SnapshotStore tests against SQLite
#[tokio::test]
async fn sqlite_passes_snapshot_store_tests() {
    let storage = create_storage().await;
    common::run_snapshot_store_tests(&storage).await;
}

/// Run only HostProjection tests against SQLite
#[tokio::test]
async fn sqlite_passes_host_projection_tests() {
    let storage = create_storage().await;
    common::run_host_projection_tests(&storage).await;
}

// ============================================================================
// SQLite-Specific Tests
// ============================================================================

/// Test SQLite file-based database creation
#[tokio::test]
async fn sqlite_file_database_works() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("test.sqlite");

    let storage = SqliteStorage::new(db_path.to_str().unwrap())
        .await
        .expect("failed to create file-based SQLite");
    storage
        .initialize()
        .await
        .expect("failed to initialize file-based SQLite");

    // Verify health check works
    storage
        .health_check()
        .await
        .expect("health check should succeed");

    // Verify file was created
    assert!(db_path.exists(), "database file should exist");
}

/// Test SQLite health check
#[tokio::test]
async fn sqlite_health_check() {
    let storage = create_storage().await;

    let result = storage.health_check().await;
    assert!(result.is_ok(), "health check should succeed: {:?}", result);
}

/// Test SQLite close is idempotent
#[tokio::test]
async fn sqlite_close_is_idempotent() {
    let storage = create_storage().await;

    // First close
    storage.close().await.expect("first close should succeed");

    // Second close should also succeed
    storage.close().await.expect("second close should succeed");
}

/// Test SQLite initialization is idempotent
#[tokio::test]
async fn sqlite_initialize_is_idempotent() {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("failed to create storage");

    // First init
    storage
        .initialize()
        .await
        .expect("first initialize should succeed");

    // Second init should also succeed (tables already exist)
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
