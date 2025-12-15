//! DuckDB backend test runner
//!
//! This module runs the shared test suite against the DuckDB storage backend.
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p router-hosts-storage --test duckdb_backend
//! ```
//!
//! # Adding Tests for a New Backend
//!
//! 1. Create a new file: `tests/<backend>_backend.rs`
//! 2. Copy this file's structure
//! 3. Replace `DuckDbStorage` with your backend type
//! 4. Implement any backend-specific setup in `create_storage()`

mod common;

use router_hosts_storage::backends::duckdb::DuckDbStorage;
use router_hosts_storage::Storage;

/// Create an initialized in-memory DuckDB storage for testing
async fn create_storage() -> DuckDbStorage {
    let storage = DuckDbStorage::new(":memory:")
        .await
        .expect("failed to create DuckDB storage");
    storage
        .initialize()
        .await
        .expect("failed to initialize DuckDB storage");
    storage
}

// ============================================================================
// Full Test Suite
// ============================================================================

/// Run the complete storage test suite against DuckDB
#[tokio::test]
async fn duckdb_passes_all_storage_tests() {
    let storage = create_storage().await;
    common::run_all_tests(&storage).await;
}

// ============================================================================
// Individual Test Suites (for targeted testing)
// ============================================================================

/// Run only EventStore tests against DuckDB
#[tokio::test]
async fn duckdb_passes_event_store_tests() {
    let storage = create_storage().await;
    common::run_event_store_tests(&storage).await;
}

/// Run only SnapshotStore tests against DuckDB
#[tokio::test]
async fn duckdb_passes_snapshot_store_tests() {
    let storage = create_storage().await;
    common::run_snapshot_store_tests(&storage).await;
}

/// Run only HostProjection tests against DuckDB
#[tokio::test]
async fn duckdb_passes_host_projection_tests() {
    let storage = create_storage().await;
    common::run_host_projection_tests(&storage).await;
}

// ============================================================================
// DuckDB-Specific Tests
// ============================================================================

/// Test DuckDB file-based database creation
#[tokio::test]
async fn duckdb_file_database_works() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let db_path = temp_dir.path().join("test.duckdb");

    let storage = DuckDbStorage::new(db_path.to_str().unwrap())
        .await
        .expect("failed to create file-based DuckDB");
    storage
        .initialize()
        .await
        .expect("failed to initialize file-based DuckDB");

    // Verify health check works
    storage
        .health_check()
        .await
        .expect("health check should succeed");

    // Verify file was created
    assert!(db_path.exists(), "database file should exist");
}

/// Test DuckDB health check
#[tokio::test]
async fn duckdb_health_check() {
    let storage = create_storage().await;

    let result = storage.health_check().await;
    assert!(result.is_ok(), "health check should succeed: {:?}", result);
}

/// Test DuckDB close is idempotent
#[tokio::test]
async fn duckdb_close_is_idempotent() {
    let storage = create_storage().await;

    // First close
    storage.close().await.expect("first close should succeed");

    // Second close should also succeed
    storage.close().await.expect("second close should succeed");
}

/// Test DuckDB initialization is idempotent
#[tokio::test]
async fn duckdb_initialize_is_idempotent() {
    let storage = DuckDbStorage::new(":memory:")
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
