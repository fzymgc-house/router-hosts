//! gRPC service layer for router-hosts server
//!
//! This module contains the HostsService implementation that handles
//! all gRPC requests and delegates to the command handler layer.

mod bulk;
mod hosts;
mod sessions;
mod snapshots;

use crate::server::commands::CommandHandler;
use crate::server::db::Database;
use crate::server::session::SessionManager;
use std::sync::Arc;

/// Main gRPC service implementation
pub struct HostsServiceImpl {
    /// Command handler for business logic
    pub(crate) commands: Arc<CommandHandler>,
    /// Session manager for edit sessions
    pub(crate) session_mgr: Arc<SessionManager>,
    /// Database connection
    pub(crate) db: Arc<Database>,
}

impl HostsServiceImpl {
    /// Create a new service instance
    pub fn new(
        commands: Arc<CommandHandler>,
        session_mgr: Arc<SessionManager>,
        db: Arc<Database>,
    ) -> Self {
        Self {
            commands,
            session_mgr,
            db,
        }
    }
}
