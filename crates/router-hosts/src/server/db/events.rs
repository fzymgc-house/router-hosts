use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Domain events for host entries following event sourcing pattern
///
/// Each event represents a single atomic change to a host aggregate.
/// Events are immutable and form an append-only log that is the source of truth.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum HostEvent {
    /// A new host entry was created
    HostCreated {
        ip_address: String,
        hostname: String,
        comment: Option<String>,
        tags: Vec<String>,
        created_at: DateTime<Utc>,
    },

    /// Host IP address was changed
    IpAddressChanged {
        old_ip: String,
        new_ip: String,
        changed_at: DateTime<Utc>,
    },

    /// Host hostname was changed
    HostnameChanged {
        old_hostname: String,
        new_hostname: String,
        changed_at: DateTime<Utc>,
    },

    /// Host comment was updated
    CommentUpdated {
        old_comment: Option<String>,
        new_comment: Option<String>,
        updated_at: DateTime<Utc>,
    },

    /// Host tags were modified
    TagsModified {
        old_tags: Vec<String>,
        new_tags: Vec<String>,
        modified_at: DateTime<Utc>,
    },

    /// Host entry was deleted (tombstone event)
    HostDeleted {
        ip_address: String,
        hostname: String,
        deleted_at: DateTime<Utc>,
        reason: Option<String>,
    },
}

impl HostEvent {
    /// Get the event type name for storage
    pub fn event_type(&self) -> &'static str {
        match self {
            HostEvent::HostCreated { .. } => "HostCreated",
            HostEvent::IpAddressChanged { .. } => "IpAddressChanged",
            HostEvent::HostnameChanged { .. } => "HostnameChanged",
            HostEvent::CommentUpdated { .. } => "CommentUpdated",
            HostEvent::TagsModified { .. } => "TagsModified",
            HostEvent::HostDeleted { .. } => "HostDeleted",
        }
    }

    /// Get the timestamp when this event occurred
    pub fn occurred_at(&self) -> DateTime<Utc> {
        match self {
            HostEvent::HostCreated { created_at, .. } => *created_at,
            HostEvent::IpAddressChanged { changed_at, .. } => *changed_at,
            HostEvent::HostnameChanged { changed_at, .. } => *changed_at,
            HostEvent::CommentUpdated { updated_at, .. } => *updated_at,
            HostEvent::TagsModified { modified_at, .. } => *modified_at,
            HostEvent::HostDeleted { deleted_at, .. } => *deleted_at,
        }
    }
}

/// Envelope for storing events with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// K-sortable event identifier (ULID for chronological ordering)
    pub event_id: Ulid,
    /// Aggregate root identifier
    pub aggregate_id: Ulid,
    pub event: HostEvent,
    /// ULID version of this event (for optimistic concurrency control)
    pub event_version: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<String>,
    pub metadata: Option<EventMetadata>,
}

/// Event-specific data stored as JSON metadata
/// Contains tags, comments, and previous values (for change events)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventData {
    // Common fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    // Previous values for change events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_tags: Option<Vec<String>>,

    // For deleted events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_reason: Option<String>,
}

/// Optional correlation metadata attached to events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub correlation_id: Option<Ulid>,
    pub causation_id: Option<Ulid>,
    pub user_agent: Option<String>,
    pub source_ip: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_names() {
        let created = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        };
        assert_eq!(created.event_type(), "HostCreated");

        let deleted = HostEvent::HostDeleted {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            deleted_at: Utc::now(),
            reason: None,
        };
        assert_eq!(deleted.event_type(), "HostDeleted");
    }

    #[test]
    fn test_event_serialization() {
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            comment: Some("Test server".to_string()),
            tags: vec!["production".to_string()],
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: HostEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_event_occurred_at() {
        let now = Utc::now();
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.1".to_string(),
            hostname: "test.local".to_string(),
            comment: None,
            tags: vec![],
            created_at: now,
        };

        assert_eq!(event.occurred_at(), now);
    }
}
