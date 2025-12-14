//! Host projection implementation for DuckDB (CQRS read side)
//!
//! This module implements the materialized view of current host entries:
//! - List all hosts
//! - Get host by ID
//! - Find host by IP + hostname (duplicate detection)
//! - Search hosts with filters (IP pattern, hostname pattern, tags)
//! - Time-travel queries (get state at specific timestamp)
//!
//! The projection is built by replaying events from the event store.
//! It provides optimized queries for the read side of CQRS.
//!
//! TODO: Implementation in Task 3.5
//! - Implement list_all (sorted by IP, then hostname)
//! - Implement get_by_id with proper NotFound error
//! - Implement find_by_ip_and_hostname for duplicate checking
//! - Implement search with filter support (wildcards, tags)
//! - Implement get_at_time (replay events up to timestamp)
//! - Add query optimization and indexing strategy
