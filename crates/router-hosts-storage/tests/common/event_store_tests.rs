//! EventStore trait test suite
//!
//! Tests for the event sourcing write side of the storage abstraction.

use chrono::Utc;
use router_hosts_storage::{EventEnvelope, HostEvent, Storage, StorageError};
use ulid::Ulid;

/// Run all EventStore tests
pub async fn run_all<S: Storage>(storage: &S) {
    test_append_single_event(storage).await;
    test_append_multiple_events_atomically(storage).await;
    test_optimistic_concurrency_conflict(storage).await;
    test_optimistic_concurrency_with_none_version(storage).await;
    test_load_events_in_order(storage).await;
    test_load_events_empty(storage).await;
    test_version_tracking(storage).await;
    test_count_events(storage).await;
    test_count_events_empty(storage).await;
}

/// Test appending a single event
pub async fn test_append_single_event<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    let event = create_host_created_event("192.168.1.10", "server.local");
    let envelope = create_envelope(aggregate_id, event);

    // Append should succeed with no expected version
    storage
        .append_event(aggregate_id, envelope, None)
        .await
        .expect("append_event should succeed");

    // Verify event was stored
    let events = storage
        .load_events(aggregate_id)
        .await
        .expect("load_events should succeed");

    assert_eq!(events.len(), 1, "should have exactly one event");
    assert_eq!(events[0].aggregate_id, aggregate_id);
}

/// Test appending multiple events atomically
pub async fn test_append_multiple_events_atomically<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // Create initial event
    let v1 = Ulid::new().to_string();
    let event1 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: create_host_created_event("192.168.1.20", "multi.local"),
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event1, None)
        .await
        .expect("first event should succeed");

    // Append multiple events atomically
    let v2 = Ulid::new().to_string();
    let v3 = Ulid::new().to_string();

    let events = vec![
        EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::IpAddressChanged {
                old_ip: "192.168.1.20".to_string(),
                new_ip: "192.168.1.21".to_string(),
                changed_at: Utc::now(),
            },
            event_version: v2,
            created_at: Utc::now(),
            created_by: None,
        },
        EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::CommentUpdated {
                old_comment: None,
                new_comment: Some("Updated comment".to_string()),
                updated_at: Utc::now(),
            },
            event_version: v3,
            created_at: Utc::now(),
            created_by: None,
        },
    ];

    storage
        .append_events(aggregate_id, events, Some(v1))
        .await
        .expect("append_events should succeed");

    // Verify all events were stored
    let loaded = storage
        .load_events(aggregate_id)
        .await
        .expect("load_events should succeed");

    assert_eq!(loaded.len(), 3, "should have three events");
}

/// Test optimistic concurrency conflict detection
pub async fn test_optimistic_concurrency_conflict<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // Create initial event
    let v1 = Ulid::new().to_string();
    let event1 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: create_host_created_event("192.168.1.30", "conflict.local"),
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event1, None)
        .await
        .expect("first event should succeed");

    // Try to append with wrong expected version
    let wrong_version = Ulid::new().to_string();
    let event2 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("Should fail".to_string()),
            updated_at: Utc::now(),
        },
        event_version: Ulid::new().to_string(),
        created_at: Utc::now(),
        created_by: None,
    };

    let result = storage
        .append_event(aggregate_id, event2, Some(wrong_version))
        .await;

    assert!(
        matches!(result, Err(StorageError::ConcurrentWriteConflict { .. })),
        "should return ConcurrentWriteConflict error, got: {:?}",
        result
    );
}

/// Test optimistic concurrency with None expected version on existing aggregate
pub async fn test_optimistic_concurrency_with_none_version<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // Create initial event
    let event1 = create_envelope(
        aggregate_id,
        create_host_created_event("192.168.1.40", "none-version.local"),
    );

    storage
        .append_event(aggregate_id, event1, None)
        .await
        .expect("first event should succeed");

    // Try to append with None expected version (should fail - aggregate exists)
    let event2 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("Should fail".to_string()),
            updated_at: Utc::now(),
        },
        event_version: Ulid::new().to_string(),
        created_at: Utc::now(),
        created_by: None,
    };

    let result = storage.append_event(aggregate_id, event2, None).await;

    assert!(
        matches!(result, Err(StorageError::ConcurrentWriteConflict { .. })),
        "should return ConcurrentWriteConflict when using None on existing aggregate, got: {:?}",
        result
    );
}

/// Test events are loaded in version order
pub async fn test_load_events_in_order<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // Create events with sequential versions
    let v1 = Ulid::new().to_string();
    std::thread::sleep(std::time::Duration::from_millis(2)); // Ensure different ULIDs
    let v2 = Ulid::new().to_string();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let v3 = Ulid::new().to_string();

    let event1 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: create_host_created_event("192.168.1.50", "order.local"),
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event1, None)
        .await
        .expect("event1 should succeed");

    let event2 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("First update".to_string()),
            updated_at: Utc::now(),
        },
        event_version: v2.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event2, Some(v1.clone()))
        .await
        .expect("event2 should succeed");

    let event3 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: Some("First update".to_string()),
            new_comment: Some("Second update".to_string()),
            updated_at: Utc::now(),
        },
        event_version: v3.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event3, Some(v2.clone()))
        .await
        .expect("event3 should succeed");

    // Load and verify order
    let events = storage
        .load_events(aggregate_id)
        .await
        .expect("load_events should succeed");

    assert_eq!(events.len(), 3);
    assert_eq!(events[0].event_version, v1);
    assert_eq!(events[1].event_version, v2);
    assert_eq!(events[2].event_version, v3);
}

/// Test loading events for non-existent aggregate returns empty
pub async fn test_load_events_empty<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    let events = storage
        .load_events(aggregate_id)
        .await
        .expect("load_events should succeed");

    assert!(
        events.is_empty(),
        "should return empty vec for non-existent aggregate"
    );
}

/// Test version tracking
pub async fn test_version_tracking<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // No version for new aggregate
    let version = storage
        .get_current_version(aggregate_id)
        .await
        .expect("get_current_version should succeed");
    assert!(
        version.is_none(),
        "should return None for non-existent aggregate"
    );

    // Add event and verify version
    let v1 = Ulid::new().to_string();
    let event = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: create_host_created_event("192.168.1.60", "version.local"),
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event, None)
        .await
        .expect("append should succeed");

    let version = storage
        .get_current_version(aggregate_id)
        .await
        .expect("get_current_version should succeed");
    assert_eq!(version, Some(v1.clone()));

    // Add another event and verify version updates
    let v2 = Ulid::new().to_string();
    let event2 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("Updated".to_string()),
            updated_at: Utc::now(),
        },
        event_version: v2.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event2, Some(v1))
        .await
        .expect("append should succeed");

    let version = storage
        .get_current_version(aggregate_id)
        .await
        .expect("get_current_version should succeed");
    assert_eq!(version, Some(v2));
}

/// Test event counting
pub async fn test_count_events<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    let v1 = Ulid::new().to_string();
    let event1 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: create_host_created_event("192.168.1.70", "count.local"),
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event1, None)
        .await
        .expect("append should succeed");

    let count = storage
        .count_events(aggregate_id)
        .await
        .expect("count_events should succeed");
    assert_eq!(count, 1);

    // Add another event
    let v2 = Ulid::new().to_string();
    let event2 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("Comment".to_string()),
            updated_at: Utc::now(),
        },
        event_version: v2,
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event2, Some(v1))
        .await
        .expect("append should succeed");

    let count = storage
        .count_events(aggregate_id)
        .await
        .expect("count_events should succeed");
    assert_eq!(count, 2);
}

/// Test count returns 0 for non-existent aggregate
pub async fn test_count_events_empty<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    let count = storage
        .count_events(aggregate_id)
        .await
        .expect("count_events should succeed");
    assert_eq!(count, 0);
}

// Helper functions

fn create_host_created_event(ip: &str, hostname: &str) -> HostEvent {
    HostEvent::HostCreated {
        ip_address: ip.to_string(),
        hostname: hostname.to_string(),
        comment: None,
        tags: vec![],
        created_at: Utc::now(),
    }
}

fn create_envelope(aggregate_id: Ulid, event: HostEvent) -> EventEnvelope {
    EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event,
        event_version: Ulid::new().to_string(),
        created_at: Utc::now(),
        created_by: None,
    }
}
