//! SnapshotStore trait test suite
//!
//! Tests for the snapshot storage functionality.

use chrono::{Duration, Utc};
use router_hosts_storage::{Snapshot, SnapshotId, Storage, StorageError};
use std::collections::HashSet;
use ulid::Ulid;

/// Run all SnapshotStore tests
pub async fn run_all<S: Storage>(storage: &S) {
    test_save_and_retrieve_snapshot(storage).await;
    test_get_nonexistent_snapshot(storage).await;
    test_list_snapshots(storage).await;
    test_list_snapshots_pagination(storage).await;
    test_list_snapshots_empty(storage).await;
    test_delete_snapshot(storage).await;
    test_delete_nonexistent_snapshot(storage).await;
    test_retention_policy_by_count(storage).await;
    test_retention_policy_by_age(storage).await;
    test_retention_policy_combined(storage).await;
    test_retention_policy_disabled(storage).await;
}

/// Test saving and retrieving a snapshot
pub async fn test_save_and_retrieve_snapshot<S: Storage>(storage: &S) {
    let snapshot_id = SnapshotId::new(Ulid::new().to_string());
    let now = Utc::now();

    let snapshot = Snapshot {
        snapshot_id: snapshot_id.clone(),
        created_at: now,
        hosts_content: "192.168.1.1 server.local\n192.168.1.2 db.local\n".to_string(),
        entry_count: 2,
        trigger: "manual".to_string(),
        name: Some("Test snapshot".to_string()),
        event_log_position: Some(42),
    };

    storage
        .save_snapshot(snapshot.clone())
        .await
        .expect("save_snapshot should succeed");

    let retrieved = storage
        .get_snapshot(&snapshot_id)
        .await
        .expect("get_snapshot should succeed");

    assert_eq!(retrieved.snapshot_id, snapshot_id);
    assert_eq!(retrieved.hosts_content, snapshot.hosts_content);
    assert_eq!(retrieved.entry_count, snapshot.entry_count);
    assert_eq!(retrieved.trigger, snapshot.trigger);
    assert_eq!(retrieved.name, snapshot.name);
    assert_eq!(retrieved.event_log_position, snapshot.event_log_position);
}

/// Test retrieving a non-existent snapshot
pub async fn test_get_nonexistent_snapshot<S: Storage>(storage: &S) {
    let snapshot_id = SnapshotId::new("nonexistent-id");

    let result = storage.get_snapshot(&snapshot_id).await;

    assert!(
        matches!(result, Err(StorageError::NotFound { .. })),
        "should return NotFound error, got: {:?}",
        result
    );
}

/// Test listing snapshots
pub async fn test_list_snapshots<S: Storage>(storage: &S) {
    // Create multiple snapshots
    let mut ids: Vec<SnapshotId> = Vec::with_capacity(3);
    for i in 0..3 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        ids.push(SnapshotId::new(format!("list-test-{}-{}", Ulid::new(), i)));
    }

    for (i, id) in ids.iter().enumerate() {
        let snapshot = Snapshot {
            snapshot_id: id.clone(),
            created_at: Utc::now(),
            hosts_content: format!("# Snapshot {}\n", i),
            entry_count: i as i32,
            trigger: "test".to_string(),
            name: Some(format!("Snapshot {}", i)),
            event_log_position: None,
        };
        storage
            .save_snapshot(snapshot)
            .await
            .expect("save_snapshot should succeed");
    }

    // List without pagination
    let listed = storage
        .list_snapshots(None, None)
        .await
        .expect("list_snapshots should succeed");

    // Should contain at least our 3 snapshots (may have others from previous tests)
    assert!(
        listed.len() >= 3,
        "should have at least 3 snapshots, got {}",
        listed.len()
    );

    // Verify our snapshots are present
    for id in &ids {
        assert!(
            listed.iter().any(|s| s.snapshot_id == *id),
            "snapshot {} should be in list",
            id
        );
    }

    // Verify sorted by created_at descending (newest first)
    for window in listed.windows(2) {
        assert!(
            window[0].created_at >= window[1].created_at,
            "snapshots should be sorted by created_at descending"
        );
    }
}

/// Test listing snapshots with pagination
pub async fn test_list_snapshots_pagination<S: Storage>(storage: &S) {
    // Create 5 snapshots for pagination test
    let mut ids: Vec<SnapshotId> = Vec::with_capacity(5);
    for i in 0..5 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        ids.push(SnapshotId::new(format!("page-test-{}-{}", Ulid::new(), i)));
    }

    for (i, id) in ids.iter().enumerate() {
        let snapshot = Snapshot {
            snapshot_id: id.clone(),
            created_at: Utc::now(),
            hosts_content: format!("# Page test {}\n", i),
            entry_count: i as i32,
            trigger: "pagination".to_string(),
            name: None,
            event_log_position: None,
        };
        storage
            .save_snapshot(snapshot)
            .await
            .expect("save_snapshot should succeed");
    }

    // Test limit
    let page1 = storage
        .list_snapshots(Some(2), None)
        .await
        .expect("list_snapshots should succeed");
    assert_eq!(page1.len(), 2, "should return exactly 2 snapshots");

    // Test offset
    let page2 = storage
        .list_snapshots(Some(2), Some(2))
        .await
        .expect("list_snapshots should succeed");
    assert_eq!(page2.len(), 2, "should return exactly 2 snapshots");

    // Pages should be completely disjoint (no overlapping snapshots)
    let page1_ids: HashSet<_> = page1.iter().map(|s| &s.snapshot_id).collect();
    let page2_ids: HashSet<_> = page2.iter().map(|s| &s.snapshot_id).collect();
    assert!(
        page1_ids.is_disjoint(&page2_ids),
        "pages should not overlap - page1: {:?}, page2: {:?}",
        page1_ids,
        page2_ids
    );
}

/// Test listing snapshots when empty
pub async fn test_list_snapshots_empty<S: Storage>(storage: &S) {
    // Use a high offset to effectively get "empty" results
    let listed = storage
        .list_snapshots(Some(10), Some(10000))
        .await
        .expect("list_snapshots should succeed");

    assert!(
        listed.is_empty(),
        "should return empty list with high offset"
    );
}

/// Test deleting a snapshot
pub async fn test_delete_snapshot<S: Storage>(storage: &S) {
    let snapshot_id = SnapshotId::new(format!("delete-test-{}", Ulid::new()));

    let snapshot = Snapshot {
        snapshot_id: snapshot_id.clone(),
        created_at: Utc::now(),
        hosts_content: "# To be deleted\n".to_string(),
        entry_count: 0,
        trigger: "test".to_string(),
        name: None,
        event_log_position: None,
    };

    storage
        .save_snapshot(snapshot)
        .await
        .expect("save_snapshot should succeed");

    // Verify it exists
    storage
        .get_snapshot(&snapshot_id)
        .await
        .expect("snapshot should exist");

    // Delete it
    storage
        .delete_snapshot(&snapshot_id)
        .await
        .expect("delete_snapshot should succeed");

    // Verify it's gone
    let result = storage.get_snapshot(&snapshot_id).await;
    assert!(
        matches!(result, Err(StorageError::NotFound { .. })),
        "snapshot should be deleted"
    );
}

/// Test deleting a non-existent snapshot
pub async fn test_delete_nonexistent_snapshot<S: Storage>(storage: &S) {
    let snapshot_id = SnapshotId::new("nonexistent-delete");

    let result = storage.delete_snapshot(&snapshot_id).await;

    assert!(
        matches!(result, Err(StorageError::NotFound { .. })),
        "should return NotFound error, got: {:?}",
        result
    );
}

/// Test retention policy by count
pub async fn test_retention_policy_by_count<S: Storage>(storage: &S) {
    // Create 5 snapshots with unique prefix
    let prefix = format!("retention-count-{}", Ulid::new());
    let mut ids = Vec::new();

    for i in 0..5 {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let id = SnapshotId::new(format!("{}-{}", prefix, i));
        let snapshot = Snapshot {
            snapshot_id: id.clone(),
            created_at: Utc::now(),
            hosts_content: format!("# Retention test {}\n", i),
            entry_count: i,
            trigger: "retention-test".to_string(),
            name: None,
            event_log_position: None,
        };
        storage
            .save_snapshot(snapshot)
            .await
            .expect("save_snapshot should succeed");
        ids.push(id);
    }

    // Apply retention policy to keep only 3
    let deleted = storage
        .apply_retention_policy(Some(3), None)
        .await
        .expect("apply_retention_policy should succeed");

    // Should have deleted at least 2 (might delete more from other tests)
    assert!(
        deleted >= 2,
        "should have deleted at least 2 snapshots, deleted: {}",
        deleted
    );

    // List remaining and verify count
    let remaining = storage
        .list_snapshots(None, None)
        .await
        .expect("list_snapshots should succeed");

    assert!(
        remaining.len() <= 3,
        "should have at most 3 snapshots after retention, got {}",
        remaining.len()
    );
}

/// Test retention policy by age
pub async fn test_retention_policy_by_age<S: Storage>(storage: &S) {
    // Create an "old" snapshot (we'll use a backdated timestamp)
    // Note: This test may not work perfectly with all backends depending on how
    // they handle timestamp precision. The implementation should use created_at
    // from the Snapshot struct, not CURRENT_TIMESTAMP.
    let old_id = SnapshotId::new(format!("old-snapshot-{}", Ulid::new()));
    let old_snapshot = Snapshot {
        snapshot_id: old_id.clone(),
        created_at: Utc::now() - Duration::days(100), // 100 days old
        hosts_content: "# Old snapshot\n".to_string(),
        entry_count: 0,
        trigger: "age-test".to_string(),
        name: Some("Old".to_string()),
        event_log_position: None,
    };

    storage
        .save_snapshot(old_snapshot)
        .await
        .expect("save_snapshot should succeed");

    // Create a recent snapshot
    let new_id = SnapshotId::new(format!("new-snapshot-{}", Ulid::new()));
    let new_snapshot = Snapshot {
        snapshot_id: new_id.clone(),
        created_at: Utc::now(),
        hosts_content: "# New snapshot\n".to_string(),
        entry_count: 0,
        trigger: "age-test".to_string(),
        name: Some("New".to_string()),
        event_log_position: None,
    };

    storage
        .save_snapshot(new_snapshot)
        .await
        .expect("save_snapshot should succeed");

    // Apply retention policy to delete snapshots older than 30 days
    let deleted = storage
        .apply_retention_policy(None, Some(30))
        .await
        .expect("apply_retention_policy should succeed");

    assert!(deleted >= 1, "should have deleted at least 1 old snapshot");

    // Old snapshot should be gone
    let old_result = storage.get_snapshot(&old_id).await;
    assert!(
        matches!(old_result, Err(StorageError::NotFound { .. })),
        "old snapshot should be deleted"
    );

    // New snapshot should still exist
    storage
        .get_snapshot(&new_id)
        .await
        .expect("new snapshot should still exist");
}

/// Test retention policy with both count and age
pub async fn test_retention_policy_combined<S: Storage>(storage: &S) {
    // This test verifies that both conditions are applied
    let prefix = format!("combined-{}", Ulid::new());

    // Create some snapshots
    for i in 0..3 {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let id = SnapshotId::new(format!("{}-{}", prefix, i));
        let snapshot = Snapshot {
            snapshot_id: id,
            created_at: Utc::now(),
            hosts_content: format!("# Combined test {}\n", i),
            entry_count: i,
            trigger: "combined-test".to_string(),
            name: None,
            event_log_position: None,
        };
        storage
            .save_snapshot(snapshot)
            .await
            .expect("save_snapshot should succeed");
    }

    // Apply both constraints - this should work without error
    let result = storage.apply_retention_policy(Some(10), Some(365)).await;
    assert!(result.is_ok(), "combined retention policy should succeed");
}

/// Test retention policy when disabled (both None)
pub async fn test_retention_policy_disabled<S: Storage>(storage: &S) {
    // Create a snapshot first
    let id = SnapshotId::new(format!("disabled-retention-{}", Ulid::new()));
    let snapshot = Snapshot {
        snapshot_id: id.clone(),
        created_at: Utc::now(),
        hosts_content: "# Should not be deleted\n".to_string(),
        entry_count: 0,
        trigger: "disabled-test".to_string(),
        name: None,
        event_log_position: None,
    };

    storage
        .save_snapshot(snapshot)
        .await
        .expect("save_snapshot should succeed");

    // Apply retention with both disabled
    let deleted = storage
        .apply_retention_policy(None, None)
        .await
        .expect("apply_retention_policy should succeed");

    assert_eq!(
        deleted, 0,
        "should not delete anything when retention is disabled"
    );

    // Snapshot should still exist
    storage
        .get_snapshot(&id)
        .await
        .expect("snapshot should still exist");
}
