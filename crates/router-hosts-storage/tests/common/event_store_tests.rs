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
    test_concurrent_writes_conflict(storage).await;
    test_large_batch_append(storage).await;
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

/// Test concurrent writes to same aggregate - simulates race condition
///
/// This test validates that optimistic concurrency control works correctly
/// when two "clients" read the same version and both try to write.
/// One should succeed, one should fail with ConcurrentWriteConflict.
pub async fn test_concurrent_writes_conflict<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // Create initial event
    let v1 = Ulid::new().to_string();
    let event1 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: create_host_created_event("192.168.1.100", "concurrent.local"),
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event1, None)
        .await
        .expect("initial event should succeed");

    // Simulate two "clients" that both read v1 as the current version
    // before either writes (classic race condition scenario)
    let stale_version = v1.clone();

    // First writer - should succeed
    let v2 = Ulid::new().to_string();
    let event_a = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("Writer A".to_string()),
            updated_at: Utc::now(),
        },
        event_version: v2,
        created_at: Utc::now(),
        created_by: None,
    };

    let result_a = storage.append_event(aggregate_id, event_a, Some(v1)).await;

    // Second writer tries with the same stale version - should fail
    // (version has changed since they "read" it)
    let v3 = Ulid::new().to_string();
    let event_b = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: None,
            new_comment: Some("Writer B".to_string()),
            updated_at: Utc::now(),
        },
        event_version: v3,
        created_at: Utc::now(),
        created_by: None,
    };

    let result_b = storage
        .append_event(aggregate_id, event_b, Some(stale_version))
        .await;

    // First write should succeed
    assert!(
        result_a.is_ok(),
        "first writer should succeed, got: {:?}",
        result_a
    );

    // Second write should fail with stale version
    assert!(
        matches!(result_b, Err(StorageError::ConcurrentWriteConflict { .. })),
        "second writer should get ConcurrentWriteConflict, got: {:?}",
        result_b
    );

    // Verify only 2 events exist (initial + first writer)
    let events = storage
        .load_events(aggregate_id)
        .await
        .expect("load_events should succeed");
    assert_eq!(events.len(), 2, "should have exactly 2 events");
}

/// Test appending a large batch of events atomically
///
/// Validates that the storage can handle 100+ events in a single atomic operation.
pub async fn test_large_batch_append<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // Create initial event
    let v1 = Ulid::new().to_string();
    let event1 = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: create_host_created_event("192.168.1.200", "large-batch.local"),
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, event1, None)
        .await
        .expect("initial event should succeed");

    // Create 100 events to append atomically
    let batch_size = 100;
    let mut events = Vec::with_capacity(batch_size);

    for i in 0..batch_size {
        let new_version = Ulid::new().to_string();
        events.push(EventEnvelope {
            event_id: Ulid::new(),
            aggregate_id,
            event: HostEvent::CommentUpdated {
                old_comment: if i == 0 {
                    None
                } else {
                    Some(format!("Batch update {}", i - 1))
                },
                new_comment: Some(format!("Batch update {}", i)),
                updated_at: Utc::now(),
            },
            event_version: new_version,
            created_at: Utc::now(),
            created_by: None,
        });
    }

    // Append all events atomically
    storage
        .append_events(aggregate_id, events, Some(v1))
        .await
        .expect("large batch append should succeed");

    // Verify all events were stored
    let loaded = storage
        .load_events(aggregate_id)
        .await
        .expect("load_events should succeed");
    assert_eq!(
        loaded.len(),
        batch_size + 1,
        "should have {} events (1 initial + {} batch)",
        batch_size + 1,
        batch_size
    );

    // Verify version tracking - current version should be one of the batch events
    let current_version = storage
        .get_current_version(aggregate_id)
        .await
        .expect("get_current_version should succeed");
    assert!(current_version.is_some(), "should have a current version");

    // The current version should be the version of the last event in sort order
    // (which is the last event returned by load_events)
    let expected_version = loaded.last().map(|e| e.event_version.clone());
    assert_eq!(
        current_version, expected_version,
        "current version should match last event's version"
    );

    // Verify event count
    let count = storage
        .count_events(aggregate_id)
        .await
        .expect("count_events should succeed");
    assert_eq!(count, (batch_size + 1) as i64);
}

/// Test events are loaded in version order
pub async fn test_load_events_in_order<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // Create events with sequential versions
    let v1 = Ulid::new().to_string();
    tokio::time::sleep(std::time::Duration::from_millis(2)).await; // Ensure different ULIDs
    let v2 = Ulid::new().to_string();
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
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
        aliases: vec![],
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
