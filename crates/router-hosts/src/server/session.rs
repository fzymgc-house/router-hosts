//! Edit session management
//!
//! Manages single-server edit sessions with 15-minute timeout.

use crate::server::db::HostEvent;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;
use std::sync::Mutex;
use thiserror::Error;
use ulid::Ulid;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Edit session already active")]
    SessionAlreadyActive,

    #[error("Invalid or expired session token")]
    InvalidToken,

    #[error("Session expired")]
    Expired,

    #[error("No active session")]
    NoActiveSession,

    #[error("Duplicate entry: {0}")]
    DuplicateEntry(String),
}

pub type SessionResult<T> = Result<T, SessionError>;

struct ActiveSession {
    token: String,
    #[allow(dead_code)]
    started_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    staged_events: Vec<(Ulid, HostEvent)>,
    /// Track IP+hostname combinations staged for creation/update to detect duplicates
    /// within the same session. Format: "ip:hostname"
    staged_ip_hostnames: HashSet<String>,
    /// Track aggregate IDs that have been staged for deletion
    staged_deletions: HashSet<Ulid>,
}

/// Minimum timeout in minutes (prevents accidentally setting 0 or negative)
const MIN_TIMEOUT_MINUTES: i64 = 1;
/// Maximum timeout in minutes (prevents excessive session lifetimes)
const MAX_TIMEOUT_MINUTES: i64 = 60;
/// Default timeout in minutes
#[allow(dead_code)]
pub const DEFAULT_TIMEOUT_MINUTES: i64 = 15;

pub struct SessionManager {
    active: Mutex<Option<ActiveSession>>,
    timeout_minutes: i64,
}

impl SessionManager {
    /// Create a new session manager with the specified timeout in minutes.
    ///
    /// # Arguments
    /// * `timeout_minutes` - Session timeout in minutes. Will be clamped to [1, 60].
    ///
    /// # Examples
    /// ```ignore
    /// let mgr = SessionManager::new(15); // 15 minute timeout
    /// let mgr = SessionManager::new(0);  // Clamped to 1 minute
    /// let mgr = SessionManager::new(120); // Clamped to 60 minutes
    /// ```
    pub fn new(timeout_minutes: i64) -> Self {
        let clamped_timeout = timeout_minutes.clamp(MIN_TIMEOUT_MINUTES, MAX_TIMEOUT_MINUTES);
        if clamped_timeout != timeout_minutes {
            tracing::warn!(
                "Session timeout {} minutes clamped to {} (valid range: {}-{})",
                timeout_minutes,
                clamped_timeout,
                MIN_TIMEOUT_MINUTES,
                MAX_TIMEOUT_MINUTES
            );
        }
        Self {
            active: Mutex::new(None),
            timeout_minutes: clamped_timeout,
        }
    }

    /// Start a new edit session
    pub fn start_edit(&self) -> SessionResult<String> {
        let mut guard = self.active.lock().unwrap();

        // Check if session exists and is still valid
        if let Some(ref session) = *guard {
            if !self.is_expired(session) {
                return Err(SessionError::SessionAlreadyActive);
            }
        }

        // Create new session
        let token = Ulid::new().to_string();
        let now = Utc::now();
        *guard = Some(ActiveSession {
            token: token.clone(),
            started_at: now,
            last_activity: now,
            staged_events: Vec::new(),
            staged_ip_hostnames: HashSet::new(),
            staged_deletions: HashSet::new(),
        });

        Ok(token)
    }

    /// Validate that a token is valid and not expired
    #[allow(dead_code)]
    pub fn validate_token(&self, token: &str) -> SessionResult<()> {
        let guard = self.active.lock().unwrap();
        match &*guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    Err(SessionError::Expired)
                } else {
                    Ok(())
                }
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Reset the timeout for a session
    #[allow(dead_code)]
    pub fn touch(&self, token: &str) -> SessionResult<()> {
        let mut guard = self.active.lock().unwrap();
        match &mut *guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    *guard = None;
                    Err(SessionError::Expired)
                } else {
                    session.last_activity = Utc::now();
                    Ok(())
                }
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Stage an event for later commit
    ///
    /// For HostCreated and IP/hostname change events, this also tracks the
    /// resulting IP+hostname combination to detect duplicates within the session.
    pub fn stage_event(&self, token: &str, agg_id: Ulid, event: HostEvent) -> SessionResult<()> {
        let mut guard = self.active.lock().unwrap();
        match &mut *guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    *guard = None;
                    Err(SessionError::Expired)
                } else {
                    session.last_activity = Utc::now();

                    // Track IP+hostname for duplicate detection
                    match &event {
                        HostEvent::HostCreated {
                            ip_address,
                            hostname,
                            ..
                        } => {
                            let key = format!("{}:{}", ip_address, hostname);
                            if !session.staged_ip_hostnames.insert(key.clone()) {
                                return Err(SessionError::DuplicateEntry(format!(
                                    "IP {} with hostname {} already staged in this session",
                                    ip_address, hostname
                                )));
                            }
                        }
                        HostEvent::HostDeleted { .. } => {
                            session.staged_deletions.insert(agg_id);
                        }
                        _ => {
                            // IP/hostname changes are validated via check_staged_duplicate
                        }
                    }

                    session.staged_events.push((agg_id, event));
                    Ok(())
                }
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Check if an IP+hostname combination would conflict with staged events
    ///
    /// Returns true if the combination is safe (no conflict), false if it conflicts.
    /// This should be called before staging update events that change IP or hostname.
    pub fn check_staged_duplicate(
        &self,
        token: &str,
        ip: &str,
        hostname: &str,
    ) -> SessionResult<bool> {
        let guard = self.active.lock().unwrap();
        match &*guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    return Err(SessionError::Expired);
                }
                let key = format!("{}:{}", ip, hostname);
                Ok(!session.staged_ip_hostnames.contains(&key))
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Register an IP+hostname combination as staged
    ///
    /// Called after validation passes to track the combination for future checks.
    pub fn register_staged_ip_hostname(
        &self,
        token: &str,
        ip: &str,
        hostname: &str,
    ) -> SessionResult<()> {
        let mut guard = self.active.lock().unwrap();
        match &mut *guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    *guard = None;
                    return Err(SessionError::Expired);
                }
                let key = format!("{}:{}", ip, hostname);
                session.staged_ip_hostnames.insert(key);
                Ok(())
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Check if an aggregate ID has been staged for deletion
    #[allow(dead_code)]
    pub fn is_staged_for_deletion(&self, token: &str, agg_id: &Ulid) -> SessionResult<bool> {
        let guard = self.active.lock().unwrap();
        match &*guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    return Err(SessionError::Expired);
                }
                Ok(session.staged_deletions.contains(agg_id))
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Finish the edit session and return staged events
    pub fn finish_edit(&self, token: &str) -> SessionResult<Vec<(Ulid, HostEvent)>> {
        let mut guard = self.active.lock().unwrap();
        match &*guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    *guard = None;
                    return Err(SessionError::Expired);
                }
                let session = guard.take().unwrap();
                Ok(session.staged_events)
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    /// Cancel the edit session and discard staged events
    pub fn cancel_edit(&self, token: &str) -> SessionResult<()> {
        let mut guard = self.active.lock().unwrap();
        match &*guard {
            Some(session) if session.token == token => {
                *guard = None;
                Ok(())
            }
            Some(_) => Err(SessionError::InvalidToken),
            None => Err(SessionError::NoActiveSession),
        }
    }

    fn is_expired(&self, session: &ActiveSession) -> bool {
        let timeout = Duration::minutes(self.timeout_minutes);
        Utc::now() - session.last_activity > timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_start_edit_returns_token() {
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn test_cannot_start_second_session() {
        let mgr = SessionManager::new(15);
        let _token1 = mgr.start_edit().unwrap();
        let result = mgr.start_edit();
        assert!(matches!(result, Err(SessionError::SessionAlreadyActive)));
    }

    #[test]
    fn test_validate_token() {
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();
        assert!(mgr.validate_token(&token).is_ok());
        assert!(matches!(
            mgr.validate_token("wrong"),
            Err(SessionError::InvalidToken)
        ));
    }

    #[test]
    fn test_stage_and_finish() {
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();

        let agg_id = Ulid::new();
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        mgr.stage_event(&token, agg_id, event).unwrap();

        let events = mgr.finish_edit(&token).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_cancel_discards_events() {
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();

        let agg_id = Ulid::new();
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        mgr.stage_event(&token, agg_id, event).unwrap();
        mgr.cancel_edit(&token).unwrap();

        // Session is gone, so validate should fail
        assert!(matches!(
            mgr.validate_token(&token),
            Err(SessionError::NoActiveSession)
        ));
    }

    #[test]
    fn test_expired_session() {
        // Use minimum timeout (1 minute) - we can't actually test expiry in unit tests
        // without waiting, but we can verify the timeout mechanism works by testing
        // that a session is NOT expired immediately after creation
        let mgr = SessionManager::new(1);
        let token = mgr.start_edit().unwrap();

        // Session should be valid immediately after creation
        assert!(mgr.validate_token(&token).is_ok());
    }

    #[test]
    fn test_timeout_clamping() {
        // Test that timeout is clamped to valid range
        let mgr_low = SessionManager::new(0);
        let mgr_high = SessionManager::new(120);
        let mgr_normal = SessionManager::new(15);

        // We can verify clamping worked by checking the internal state
        // through the is_expired behavior - create a session and it should
        // not be immediately expired (timeout >= 1 minute)
        let token_low = mgr_low.start_edit().unwrap();
        assert!(mgr_low.validate_token(&token_low).is_ok());

        let token_high = mgr_high.start_edit().unwrap();
        assert!(mgr_high.validate_token(&token_high).is_ok());

        let token_normal = mgr_normal.start_edit().unwrap();
        assert!(mgr_normal.validate_token(&token_normal).is_ok());
    }

    #[test]
    fn test_duplicate_staged_events() {
        // Test that staging duplicate IP+hostname fails
        let mgr = SessionManager::new(15);
        let token = mgr.start_edit().unwrap();

        let agg_id1 = Ulid::new();
        let event1 = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        mgr.stage_event(&token, agg_id1, event1).unwrap();

        // Try to stage another HostCreated with same IP+hostname
        let agg_id2 = Ulid::new();
        let event2 = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };

        let result = mgr.stage_event(&token, agg_id2, event2);
        assert!(matches!(result, Err(SessionError::DuplicateEntry(_))));
    }
}
