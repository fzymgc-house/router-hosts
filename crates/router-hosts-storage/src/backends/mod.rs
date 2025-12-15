//! Storage backend implementations
//!
//! This module contains implementations of the Storage trait for different databases.
//! At least one backend must be enabled via feature flags.

#[cfg(feature = "duckdb")]
pub mod duckdb;

#[cfg(feature = "sqlite")]
pub mod sqlite;
