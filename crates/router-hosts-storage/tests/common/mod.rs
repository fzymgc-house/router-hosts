//! Shared test harness for storage backends
//!
//! This module provides generic test functions that verify correct
//! implementation of the storage traits. All storage backends must
//! pass these tests to ensure consistent behavior.
//!
//! # Usage
//!
//! ```ignore
//! use router_hosts_storage::backends::duckdb::DuckDbStorage;
//! use common::{run_all_tests, run_event_store_tests};
//!
//! #[tokio::test]
//! async fn duckdb_passes_all_tests() {
//!     let storage = DuckDbStorage::new(":memory:").await.unwrap();
//!     storage.initialize().await.unwrap();
//!     run_all_tests(&storage).await;
//! }
//! ```
//!
//! # Adding Tests for New Backends
//!
//! 1. Create a new test file (e.g., `tests/sqlite_backend.rs`)
//! 2. Initialize your storage backend
//! 3. Call `run_all_tests(&storage).await` or individual test runners
//!
//! See `tests/duckdb_backend.rs` for a complete example.

pub mod event_store_tests;
pub mod host_projection_tests;
pub mod snapshot_store_tests;

use router_hosts_storage::Storage;

/// Run all storage trait tests
///
/// This is the main entry point for testing a storage backend.
/// It runs all test suites in sequence.
pub async fn run_all_tests<S: Storage>(storage: &S) {
    println!("Running EventStore tests...");
    event_store_tests::run_all(storage).await;

    println!("Running SnapshotStore tests...");
    snapshot_store_tests::run_all(storage).await;

    println!("Running HostProjection tests...");
    host_projection_tests::run_all(storage).await;

    println!("All storage tests passed!");
}

/// Run only EventStore trait tests
pub async fn run_event_store_tests<S: Storage>(storage: &S) {
    event_store_tests::run_all(storage).await;
}

/// Run only SnapshotStore trait tests
pub async fn run_snapshot_store_tests<S: Storage>(storage: &S) {
    snapshot_store_tests::run_all(storage).await;
}

/// Run only HostProjection trait tests
pub async fn run_host_projection_tests<S: Storage>(storage: &S) {
    host_projection_tests::run_all(storage).await;
}
