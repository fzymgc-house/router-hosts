//! Event store implementation for DuckDB
//!
//! This module implements the event sourcing write side:
//! - Append events with optimistic concurrency control
//! - Load event streams for aggregates
//! - Version management for conflict detection
//!
//! TODO: Implementation in Task 3.3
//! - Implement append_event with version checking
//! - Implement append_events (atomic batch append)
//! - Implement load_events (ordered by version)
//! - Implement get_current_version
//! - Implement count_events
//! - Add proper error handling and mapping
