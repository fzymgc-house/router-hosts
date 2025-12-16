//! Domain types for storage layer

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use ulid::Ulid;

/// Strongly-typed snapshot identifier
///
/// This newtype prevents accidentally passing a hostname, IP address,
/// or other string where a snapshot ID is expected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(String);

impl SnapshotId {
    /// Create a new SnapshotId from a string
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the inner string reference
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner string
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for SnapshotId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SnapshotId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for SnapshotId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Domain events for host entries (event sourcing pattern)
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

    /// Host entry was deleted (tombstone)
    HostDeleted {
        ip_address: String,
        hostname: String,
        deleted_at: DateTime<Utc>,
        reason: Option<String>,
    },
}

impl HostEvent {
    /// Get the event type name
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

/// Envelope wrapping an event with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// K-sortable event identifier (ULID)
    pub event_id: Ulid,
    /// Aggregate root identifier
    pub aggregate_id: Ulid,
    /// The domain event
    pub event: HostEvent,
    /// ULID version for optimistic concurrency
    pub event_version: String,
    /// When this envelope was created
    pub created_at: DateTime<Utc>,
    /// Who created this event
    pub created_by: Option<String>,
}

/// Read model for current host entries (CQRS Query side)
#[derive(Debug, Clone, PartialEq)]
pub struct HostEntry {
    pub id: Ulid,
    pub ip_address: String,
    pub hostname: String,
    pub comment: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// ULID version identifier for optimistic locking
    pub version: String,
}

/// Snapshot of hosts file at a point in time
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub snapshot_id: SnapshotId,
    pub created_at: DateTime<Utc>,
    pub hosts_content: String,
    pub entry_count: i32,
    pub trigger: String,
    pub name: Option<String>,
    pub event_log_position: Option<i64>,
}

/// Snapshot metadata (without content, for listing)
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotMetadata {
    pub snapshot_id: SnapshotId,
    pub created_at: DateTime<Utc>,
    pub entry_count: i32,
    pub trigger: String,
    pub name: Option<String>,
}

impl From<Snapshot> for SnapshotMetadata {
    fn from(s: Snapshot) -> Self {
        Self {
            snapshot_id: s.snapshot_id,
            created_at: s.created_at,
            entry_count: s.entry_count,
            trigger: s.trigger,
            name: s.name,
        }
    }
}

/// Filter for searching hosts
#[derive(Debug, Clone, Default)]
pub struct HostFilter {
    /// Filter by IP address pattern
    pub ip_pattern: Option<String>,
    /// Filter by hostname pattern
    pub hostname_pattern: Option<String>,
    /// Filter by tags (any match)
    pub tags: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_names() {
        let now = Utc::now();

        // Test all event type names
        assert_eq!(
            HostEvent::HostCreated {
                ip_address: "192.168.1.1".into(),
                hostname: "test.local".into(),
                comment: None,
                tags: vec![],
                created_at: now,
            }
            .event_type(),
            "HostCreated"
        );

        assert_eq!(
            HostEvent::IpAddressChanged {
                old_ip: "192.168.1.1".into(),
                new_ip: "192.168.1.2".into(),
                changed_at: now,
            }
            .event_type(),
            "IpAddressChanged"
        );

        assert_eq!(
            HostEvent::HostnameChanged {
                old_hostname: "old.local".into(),
                new_hostname: "new.local".into(),
                changed_at: now,
            }
            .event_type(),
            "HostnameChanged"
        );

        assert_eq!(
            HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("new".into()),
                updated_at: now,
            }
            .event_type(),
            "CommentUpdated"
        );

        assert_eq!(
            HostEvent::TagsModified {
                old_tags: vec![],
                new_tags: vec!["prod".into()],
                modified_at: now,
            }
            .event_type(),
            "TagsModified"
        );

        assert_eq!(
            HostEvent::HostDeleted {
                ip_address: "192.168.1.1".into(),
                hostname: "test.local".into(),
                deleted_at: now,
                reason: None,
            }
            .event_type(),
            "HostDeleted"
        );
    }

    #[test]
    fn test_event_occurred_at() {
        let now = Utc::now();

        // Test occurred_at for all event types
        let created = HostEvent::HostCreated {
            ip_address: "192.168.1.1".into(),
            hostname: "test.local".into(),
            comment: None,
            tags: vec![],
            created_at: now,
        };
        assert_eq!(created.occurred_at(), now);

        let ip_changed = HostEvent::IpAddressChanged {
            old_ip: "192.168.1.1".into(),
            new_ip: "192.168.1.2".into(),
            changed_at: now,
        };
        assert_eq!(ip_changed.occurred_at(), now);

        let hostname_changed = HostEvent::HostnameChanged {
            old_hostname: "old.local".into(),
            new_hostname: "new.local".into(),
            changed_at: now,
        };
        assert_eq!(hostname_changed.occurred_at(), now);

        let comment_updated = HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("new".into()),
            updated_at: now,
        };
        assert_eq!(comment_updated.occurred_at(), now);

        let tags_modified = HostEvent::TagsModified {
            old_tags: vec![],
            new_tags: vec!["prod".into()],
            modified_at: now,
        };
        assert_eq!(tags_modified.occurred_at(), now);

        let deleted = HostEvent::HostDeleted {
            ip_address: "192.168.1.1".into(),
            hostname: "test.local".into(),
            deleted_at: now,
            reason: Some("cleanup".into()),
        };
        assert_eq!(deleted.occurred_at(), now);
    }

    #[test]
    fn test_event_serialization() {
        let event = HostEvent::HostCreated {
            ip_address: "192.168.1.10".into(),
            hostname: "server.local".into(),
            comment: Some("Test".into()),
            tags: vec!["prod".into()],
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deser: HostEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deser);
    }

    #[test]
    fn test_snapshot_id_new_and_as_str() {
        let id = SnapshotId::new("snap-123");
        assert_eq!(id.as_str(), "snap-123");
    }

    #[test]
    fn test_snapshot_id_into_inner() {
        let id = SnapshotId::new("snap-456");
        assert_eq!(id.into_inner(), "snap-456");
    }

    #[test]
    fn test_snapshot_id_display() {
        let id = SnapshotId::new("snap-789");
        assert_eq!(format!("{}", id), "snap-789");
    }

    #[test]
    fn test_snapshot_id_from_string() {
        let id: SnapshotId = String::from("snap-abc").into();
        assert_eq!(id.as_str(), "snap-abc");
    }

    #[test]
    fn test_snapshot_id_from_str() {
        let id: SnapshotId = "snap-def".into();
        assert_eq!(id.as_str(), "snap-def");
    }

    #[test]
    fn test_snapshot_id_as_ref() {
        let id = SnapshotId::new("snap-ghi");
        let s: &str = id.as_ref();
        assert_eq!(s, "snap-ghi");
    }

    #[test]
    fn test_snapshot_metadata_from_snapshot() {
        let snapshot = Snapshot {
            snapshot_id: SnapshotId::new("snap-001"),
            created_at: Utc::now(),
            hosts_content: "192.168.1.1\ttest.local".into(),
            entry_count: 1,
            trigger: "manual".into(),
            name: Some("backup".into()),
            event_log_position: Some(42),
        };

        let metadata: SnapshotMetadata = snapshot.clone().into();
        assert_eq!(metadata.snapshot_id, snapshot.snapshot_id);
        assert_eq!(metadata.created_at, snapshot.created_at);
        assert_eq!(metadata.entry_count, snapshot.entry_count);
        assert_eq!(metadata.trigger, snapshot.trigger);
        assert_eq!(metadata.name, snapshot.name);
    }

    #[test]
    fn test_host_filter_default() {
        let filter = HostFilter::default();
        assert!(filter.ip_pattern.is_none());
        assert!(filter.hostname_pattern.is_none());
        assert!(filter.tags.is_none());
    }
}
