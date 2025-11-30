//! Command handlers for host management operations
//!
//! This module centralizes validation and event generation for all write operations.

use crate::server::db::{DatabaseError, HostEvent};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Session conflict: {0}")]
    SessionConflict(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type CommandResult<T> = Result<T, CommandError>;
