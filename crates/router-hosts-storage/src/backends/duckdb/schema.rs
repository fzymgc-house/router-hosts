//! Database schema definitions and migrations
//!
//! This module defines the DuckDB table schemas for:
//! - Event log (event sourcing write side)
//! - Host entries projection (CQRS read side)
//! - Snapshots (versioned hosts file storage)
//!
//! TODO: Implementation in Task 3.2
//! - Define CREATE TABLE statements
//! - Create indexes for common queries
//! - Implement schema initialization
//! - Add migration support for schema evolution
