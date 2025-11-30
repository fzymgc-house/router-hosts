//! Edit session management
//!
//! Manages single-server edit sessions with 15-minute timeout.

use crate::server::db::HostEvent;
use chrono::{DateTime, Duration, Utc};
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
}

pub type SessionResult<T> = Result<T, SessionError>;

struct ActiveSession {
    token: String,
    #[allow(dead_code)]
    started_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    staged_events: Vec<(Ulid, HostEvent)>,
}

pub struct SessionManager {
    active: Mutex<Option<ActiveSession>>,
    timeout_minutes: i64,
}

impl SessionManager {
    pub fn new(timeout_minutes: i64) -> Self {
        Self {
            active: Mutex::new(None),
            timeout_minutes,
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
    pub fn stage_event(&self, token: &str, agg_id: Ulid, event: HostEvent) -> SessionResult<()> {
        let mut guard = self.active.lock().unwrap();
        match &mut *guard {
            Some(session) if session.token == token => {
                if self.is_expired(session) {
                    *guard = None;
                    Err(SessionError::Expired)
                } else {
                    session.last_activity = Utc::now();
                    session.staged_events.push((agg_id, event));
                    Ok(())
                }
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
        let mgr = SessionManager::new(0); // 0 minute timeout = immediate expiry
        let token = mgr.start_edit().unwrap();

        // Wait briefly to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(10));

        assert!(matches!(
            mgr.validate_token(&token),
            Err(SessionError::Expired)
        ));
    }
}
