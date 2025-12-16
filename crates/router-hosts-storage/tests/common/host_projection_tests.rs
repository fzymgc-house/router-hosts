//! HostProjection trait test suite
//!
//! Tests for the CQRS read side projection.

use chrono::{Duration, Utc};
use router_hosts_storage::{EventEnvelope, HostEvent, HostFilter, Storage, StorageError};
use ulid::Ulid;

/// Run all HostProjection tests
pub async fn run_all<S: Storage>(storage: &S) {
    test_list_all_entries(storage).await;
    test_list_all_empty(storage).await;
    test_list_all_sorted_by_ip_then_hostname(storage).await;
    test_get_by_id(storage).await;
    test_get_by_id_not_found(storage).await;
    test_find_by_ip_and_hostname(storage).await;
    test_find_by_ip_and_hostname_not_found(storage).await;
    test_search_by_ip_pattern(storage).await;
    test_search_by_hostname_pattern(storage).await;
    test_search_by_tags(storage).await;
    test_search_combined_filters(storage).await;
    test_search_empty_filter(storage).await;
    test_deleted_entries_not_listed(storage).await;
    test_get_at_time(storage).await;
    test_unicode_hostnames(storage).await;
    test_special_characters_in_search(storage).await;
    test_edge_case_strings(storage).await;
}

/// Helper to create a host entry via events
async fn create_host<S: Storage>(
    storage: &S,
    ip: &str,
    hostname: &str,
    comment: Option<&str>,
    tags: Vec<&str>,
) -> Ulid {
    let aggregate_id = Ulid::new();
    let event = HostEvent::HostCreated {
        ip_address: ip.to_string(),
        hostname: hostname.to_string(),
        aliases: vec![],
        comment: comment.map(String::from),
        tags: tags.into_iter().map(String::from).collect(),
        created_at: Utc::now(),
    };

    let envelope = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event,
        event_version: Ulid::new().to_string(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, envelope, None)
        .await
        .expect("create host should succeed");

    aggregate_id
}

/// Test listing all entries
pub async fn test_list_all_entries<S: Storage>(storage: &S) {
    // Create a few entries
    let id1 = create_host(storage, "10.0.0.1", "list-all-1.local", None, vec![]).await;
    let id2 = create_host(
        storage,
        "10.0.0.2",
        "list-all-2.local",
        Some("Second"),
        vec!["test"],
    )
    .await;

    let entries = storage.list_all().await.expect("list_all should succeed");

    // Should contain our entries
    assert!(
        entries.iter().any(|e| e.id == id1),
        "should contain first entry"
    );
    assert!(
        entries.iter().any(|e| e.id == id2),
        "should contain second entry"
    );

    // Verify entry data
    let entry2 = entries.iter().find(|e| e.id == id2).unwrap();
    assert_eq!(entry2.ip_address, "10.0.0.2");
    assert_eq!(entry2.hostname, "list-all-2.local");
    assert_eq!(entry2.comment, Some("Second".to_string()));
    assert_eq!(entry2.tags, vec!["test".to_string()]);
}

/// Test listing when no entries exist
pub async fn test_list_all_empty<S: Storage>(storage: &S) {
    // Use search with a filter that won't match anything
    let filter = HostFilter {
        ip_pattern: Some("255.255.255.255".to_string()),
        hostname_pattern: None,
        tags: None,
    };

    let entries = storage.search(filter).await.expect("search should succeed");

    assert!(
        entries.is_empty(),
        "should return empty with non-matching filter"
    );
}

/// Test getting entry by ID
pub async fn test_get_by_id<S: Storage>(storage: &S) {
    let id = create_host(
        storage,
        "10.1.0.1",
        "get-by-id.local",
        Some("Test comment"),
        vec!["prod", "web"],
    )
    .await;

    let entry = storage
        .get_by_id(id)
        .await
        .expect("get_by_id should succeed");

    assert_eq!(entry.id, id);
    assert_eq!(entry.ip_address, "10.1.0.1");
    assert_eq!(entry.hostname, "get-by-id.local");
    assert_eq!(entry.comment, Some("Test comment".to_string()));
    assert_eq!(entry.tags, vec!["prod".to_string(), "web".to_string()]);
    assert!(!entry.version.is_empty(), "version should be set");
}

/// Test getting non-existent entry by ID
pub async fn test_get_by_id_not_found<S: Storage>(storage: &S) {
    let fake_id = Ulid::new();

    let result = storage.get_by_id(fake_id).await;

    assert!(
        matches!(result, Err(StorageError::NotFound { .. })),
        "should return NotFound error, got: {:?}",
        result
    );
}

/// Test finding entry by IP and hostname
pub async fn test_find_by_ip_and_hostname<S: Storage>(storage: &S) {
    let id = create_host(storage, "10.2.0.1", "find-test.local", None, vec![]).await;

    let result = storage
        .find_by_ip_and_hostname("10.2.0.1", "find-test.local")
        .await
        .expect("find_by_ip_and_hostname should succeed");

    assert!(result.is_some(), "should find the entry");
    let entry = result.unwrap();
    assert_eq!(entry.id, id);
    assert_eq!(entry.ip_address, "10.2.0.1");
    assert_eq!(entry.hostname, "find-test.local");
}

/// Test finding non-existent entry by IP and hostname
pub async fn test_find_by_ip_and_hostname_not_found<S: Storage>(storage: &S) {
    let result = storage
        .find_by_ip_and_hostname("255.255.255.254", "nonexistent.local")
        .await
        .expect("find_by_ip_and_hostname should succeed");

    assert!(
        result.is_none(),
        "should return None for non-existent entry"
    );
}

/// Test searching by IP pattern
pub async fn test_search_by_ip_pattern<S: Storage>(storage: &S) {
    create_host(storage, "172.16.1.1", "ip-search-1.local", None, vec![]).await;
    create_host(storage, "172.16.1.2", "ip-search-2.local", None, vec![]).await;
    create_host(
        storage,
        "192.168.1.1",
        "ip-search-other.local",
        None,
        vec![],
    )
    .await;

    let filter = HostFilter {
        ip_pattern: Some("172.16.1".to_string()),
        hostname_pattern: None,
        tags: None,
    };

    let results = storage.search(filter).await.expect("search should succeed");

    assert!(
        results.len() >= 2,
        "should find at least 2 entries matching 172.16.1"
    );
    assert!(
        results.iter().all(|e| e.ip_address.starts_with("172.16.1")),
        "all results should match IP pattern"
    );
}

/// Test searching by hostname pattern
pub async fn test_search_by_hostname_pattern<S: Storage>(storage: &S) {
    create_host(storage, "10.3.0.1", "web-server.prod.local", None, vec![]).await;
    create_host(storage, "10.3.0.2", "db-server.prod.local", None, vec![]).await;
    create_host(storage, "10.3.0.3", "web-server.dev.local", None, vec![]).await;

    let filter = HostFilter {
        ip_pattern: None,
        hostname_pattern: Some("prod.local".to_string()),
        tags: None,
    };

    let results = storage.search(filter).await.expect("search should succeed");

    assert!(
        results.len() >= 2,
        "should find at least 2 entries matching prod.local"
    );
    assert!(
        results.iter().all(|e| e.hostname.contains("prod.local")),
        "all results should match hostname pattern"
    );
}

/// Test searching by tags
pub async fn test_search_by_tags<S: Storage>(storage: &S) {
    create_host(
        storage,
        "10.4.0.1",
        "tagged-1.local",
        None,
        vec!["production", "web"],
    )
    .await;
    create_host(
        storage,
        "10.4.0.2",
        "tagged-2.local",
        None,
        vec!["production", "db"],
    )
    .await;
    create_host(storage, "10.4.0.3", "tagged-3.local", None, vec!["staging"]).await;

    let filter = HostFilter {
        ip_pattern: None,
        hostname_pattern: None,
        tags: Some(vec!["production".to_string()]),
    };

    let results = storage.search(filter).await.expect("search should succeed");

    assert!(
        results.len() >= 2,
        "should find at least 2 entries with production tag"
    );
    assert!(
        results
            .iter()
            .all(|e| e.tags.contains(&"production".to_string())),
        "all results should have production tag"
    );
}

/// Test searching with combined filters
pub async fn test_search_combined_filters<S: Storage>(storage: &S) {
    create_host(
        storage,
        "10.5.1.1",
        "api.example.com",
        None,
        vec!["api", "prod"],
    )
    .await;
    create_host(
        storage,
        "10.5.1.2",
        "web.example.com",
        None,
        vec!["web", "prod"],
    )
    .await;
    create_host(
        storage,
        "10.6.1.1",
        "api.other.com",
        None,
        vec!["api", "prod"],
    )
    .await;

    let filter = HostFilter {
        ip_pattern: Some("10.5".to_string()),
        hostname_pattern: Some("example.com".to_string()),
        tags: Some(vec!["prod".to_string()]),
    };

    let results = storage.search(filter).await.expect("search should succeed");

    // Should match entries that satisfy ALL conditions
    for entry in &results {
        assert!(
            entry.ip_address.starts_with("10.5"),
            "IP should match pattern"
        );
        assert!(
            entry.hostname.contains("example.com"),
            "hostname should match pattern"
        );
        assert!(
            entry.tags.contains(&"prod".to_string()),
            "should have prod tag"
        );
    }
}

/// Test searching with empty filter returns all
pub async fn test_search_empty_filter<S: Storage>(storage: &S) {
    // Create at least one entry to verify non-empty results
    create_host(storage, "10.6.0.1", "empty-filter-test.local", None, vec![]).await;

    let filter = HostFilter::default();

    let results = storage.search(filter).await.expect("search should succeed");

    assert!(
        !results.is_empty(),
        "empty filter should return all entries"
    );
}

/// Test that deleted entries are not listed
pub async fn test_deleted_entries_not_listed<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();

    // Create entry
    let v1 = Ulid::new().to_string();
    let create_event = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::HostCreated {
            ip_address: "10.7.0.1".to_string(),
            hostname: "to-delete.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
            created_at: Utc::now(),
        },
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, create_event, None)
        .await
        .expect("create should succeed");

    // Verify it exists
    let entry = storage.get_by_id(aggregate_id).await;
    assert!(entry.is_ok(), "entry should exist after creation");

    // Delete entry
    let delete_event = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::HostDeleted {
            ip_address: "10.7.0.1".to_string(),
            hostname: "to-delete.local".to_string(),
            deleted_at: Utc::now(),
            reason: Some("Test deletion".to_string()),
        },
        event_version: Ulid::new().to_string(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, delete_event, Some(v1))
        .await
        .expect("delete should succeed");

    // Verify it's not in list_all
    let all = storage.list_all().await.expect("list_all should succeed");
    assert!(
        !all.iter().any(|e| e.id == aggregate_id),
        "deleted entry should not appear in list_all"
    );

    // Verify get_by_id returns NotFound
    let result = storage.get_by_id(aggregate_id).await;
    assert!(
        matches!(result, Err(StorageError::NotFound { .. })),
        "deleted entry should return NotFound"
    );
}

/// Test time-travel query
pub async fn test_get_at_time<S: Storage>(storage: &S) {
    let aggregate_id = Ulid::new();
    let t0 = Utc::now();

    // Wait a moment to ensure time difference
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Create entry
    let v1 = Ulid::new().to_string();
    let create_event = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::HostCreated {
            ip_address: "10.8.0.1".to_string(),
            hostname: "time-travel.local".to_string(),
            aliases: vec![],
            comment: Some("Initial".to_string()),
            tags: vec![],
            created_at: Utc::now(),
        },
        event_version: v1.clone(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, create_event, None)
        .await
        .expect("create should succeed");

    let t1 = Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Update entry
    let update_event = EventEnvelope {
        event_id: Ulid::new(),
        aggregate_id,
        event: HostEvent::CommentUpdated {
            old_comment: Some("Initial".to_string()),
            new_comment: Some("Updated".to_string()),
            updated_at: Utc::now(),
        },
        event_version: Ulid::new().to_string(),
        created_at: Utc::now(),
        created_by: None,
    };

    storage
        .append_event(aggregate_id, update_event, Some(v1))
        .await
        .expect("update should succeed");

    let t2 = Utc::now();

    // Query at t0 (before creation) - entry shouldn't exist
    let at_t0 = storage
        .get_at_time(t0)
        .await
        .expect("get_at_time should succeed");
    assert!(
        !at_t0.iter().any(|e| e.id == aggregate_id),
        "entry should not exist at t0"
    );

    // Query at t1 (after creation, before update) - should have initial comment
    let at_t1 = storage
        .get_at_time(t1)
        .await
        .expect("get_at_time should succeed");
    let entry_t1 = at_t1.iter().find(|e| e.id == aggregate_id);
    assert!(entry_t1.is_some(), "entry should exist at t1");
    assert_eq!(
        entry_t1.unwrap().comment,
        Some("Initial".to_string()),
        "should have initial comment at t1"
    );

    // Query at t2 (after update) - should have updated comment
    let at_t2 = storage
        .get_at_time(t2)
        .await
        .expect("get_at_time should succeed");
    let entry_t2 = at_t2.iter().find(|e| e.id == aggregate_id);
    assert!(entry_t2.is_some(), "entry should exist at t2");
    assert_eq!(
        entry_t2.unwrap().comment,
        Some("Updated".to_string()),
        "should have updated comment at t2"
    );

    // Query far in the future - should match current state
    let future = Utc::now() + Duration::days(365);
    let at_future = storage
        .get_at_time(future)
        .await
        .expect("get_at_time should succeed");
    let entry_future = at_future.iter().find(|e| e.id == aggregate_id);
    assert!(entry_future.is_some(), "entry should exist in future query");
}

/// Test Unicode characters in hostnames and comments
///
/// Validates that the storage correctly handles non-ASCII characters.
pub async fn test_unicode_hostnames<S: Storage>(storage: &S) {
    // Create entries with Unicode hostnames and comments
    let id1 = create_host(
        storage,
        "10.100.0.1",
        "サーバー.local",       // Japanese: "server"
        Some("日本語コメント"), // Japanese comment
        vec!["unicode", "日本語"],
    )
    .await;

    let id2 = create_host(
        storage,
        "10.100.0.2",
        "сервер.local",              // Russian: "server"
        Some("Русский комментарий"), // Russian comment
        vec!["unicode", "русский"],
    )
    .await;

    let id3 = create_host(
        storage,
        "10.100.0.3",
        "服务器.local",   // Chinese: "server"
        Some("中文注释"), // Chinese comment
        vec!["unicode", "中文"],
    )
    .await;

    // Verify entries can be retrieved
    let entry1 = storage
        .get_by_id(id1)
        .await
        .expect("should retrieve Japanese hostname");
    assert_eq!(entry1.hostname, "サーバー.local");
    assert_eq!(entry1.comment, Some("日本語コメント".to_string()));
    assert!(entry1.tags.contains(&"日本語".to_string()));

    let entry2 = storage
        .get_by_id(id2)
        .await
        .expect("should retrieve Russian hostname");
    assert_eq!(entry2.hostname, "сервер.local");

    let entry3 = storage
        .get_by_id(id3)
        .await
        .expect("should retrieve Chinese hostname");
    assert_eq!(entry3.hostname, "服务器.local");

    // Test search with Unicode pattern
    let filter = HostFilter {
        ip_pattern: None,
        hostname_pattern: Some("サーバー".to_string()),
        tags: None,
    };
    let results = storage.search(filter).await.expect("search should succeed");
    assert!(
        results.iter().any(|e| e.id == id1),
        "should find Japanese hostname by pattern"
    );

    // Test search by Unicode tag
    let filter = HostFilter {
        ip_pattern: None,
        hostname_pattern: None,
        tags: Some(vec!["中文".to_string()]),
    };
    let results = storage.search(filter).await.expect("search should succeed");
    assert!(
        results.iter().any(|e| e.id == id3),
        "should find entry by Chinese tag"
    );
}

/// Test SQL special characters don't cause injection or errors
///
/// Validates that the storage safely handles characters that could
/// cause SQL injection if not properly escaped.
pub async fn test_special_characters_in_search<S: Storage>(storage: &S) {
    // Create entries with SQL-sensitive characters
    let id1 = create_host(
        storage,
        "10.101.0.1",
        "test's-server.local", // Single quote
        Some("Comment with 'quotes'"),
        vec!["sql-test"],
    )
    .await;

    let id2 = create_host(
        storage,
        "10.101.0.2",
        "test\"double\".local", // Double quote
        Some("Comment with \"double quotes\""),
        vec!["sql-test"],
    )
    .await;

    let id3 = create_host(
        storage,
        "10.101.0.3",
        "test;drop.local", // Semicolon (SQL terminator)
        Some("'; DROP TABLE hosts; --"),
        vec!["sql-test", "injection-attempt"],
    )
    .await;

    let id4 = create_host(
        storage,
        "10.101.0.4",
        "test%wildcard%.local", // SQL wildcards
        Some("100% complete"),
        vec!["sql-test"],
    )
    .await;

    let _id5 = create_host(
        storage,
        "10.101.0.5",
        "test_underscore_.local", // SQL single-char wildcard
        Some("Under_score_test"),
        vec!["sql-test"],
    )
    .await;

    // Verify all entries stored correctly
    let entry1 = storage.get_by_id(id1).await.expect("should get entry1");
    assert_eq!(entry1.hostname, "test's-server.local");

    let entry2 = storage.get_by_id(id2).await.expect("should get entry2");
    assert_eq!(entry2.hostname, "test\"double\".local");

    let entry3 = storage.get_by_id(id3).await.expect("should get entry3");
    assert_eq!(entry3.comment, Some("'; DROP TABLE hosts; --".to_string()));

    // Search with special characters in pattern
    let filter = HostFilter {
        ip_pattern: None,
        hostname_pattern: Some("test's".to_string()),
        tags: None,
    };
    let results = storage.search(filter).await.expect("search should succeed");
    assert!(
        results.iter().any(|e| e.id == id1),
        "should find hostname with single quote"
    );

    // Search with SQL wildcard characters (should be treated literally)
    let filter = HostFilter {
        ip_pattern: None,
        hostname_pattern: Some("%wildcard%".to_string()),
        tags: None,
    };
    let results = storage.search(filter).await.expect("search should succeed");
    assert!(
        results.iter().any(|e| e.id == id4),
        "should find hostname with percent signs"
    );

    // Verify SQL injection attempt didn't affect anything
    let all_entries = storage.list_all().await.expect("list_all should succeed");
    assert!(
        all_entries.iter().any(|e| e.id == id3),
        "entry with injection attempt should exist safely"
    );
}

/// Test edge case strings (empty, very long, whitespace)
pub async fn test_edge_case_strings<S: Storage>(storage: &S) {
    // Test with comment containing only whitespace
    let id1 = create_host(
        storage,
        "10.102.0.1",
        "whitespace-comment.local",
        Some("   "), // Whitespace-only comment
        vec!["edge-case"],
    )
    .await;

    // Test with very long hostname (253 chars is max for DNS)
    let long_label = "a".repeat(63); // Max label length is 63
    let long_hostname = format!("{}.{}.{}.local", long_label, long_label, long_label);
    let id2 = create_host(
        storage,
        "10.102.0.2",
        &long_hostname,
        Some("Long hostname test"),
        vec!["edge-case", "long"],
    )
    .await;

    // Test with very long comment
    let long_comment = "x".repeat(10000);
    let id3 = create_host(
        storage,
        "10.102.0.3",
        "long-comment.local",
        Some(&long_comment),
        vec!["edge-case"],
    )
    .await;

    // Test with many tags
    let many_tags: Vec<&str> = (0..50)
        .map(|i| {
            // Leak the string to get a static reference - acceptable in tests
            Box::leak(format!("tag-{}", i).into_boxed_str()) as &str
        })
        .collect();
    let id4 = create_host(storage, "10.102.0.4", "many-tags.local", None, many_tags).await;

    // Verify whitespace comment preserved
    let entry1 = storage.get_by_id(id1).await.expect("should get entry1");
    assert_eq!(entry1.comment, Some("   ".to_string()));

    // Verify long hostname stored correctly
    let entry2 = storage.get_by_id(id2).await.expect("should get entry2");
    assert_eq!(entry2.hostname, long_hostname);

    // Verify long comment stored correctly
    let entry3 = storage.get_by_id(id3).await.expect("should get entry3");
    assert_eq!(entry3.comment.as_ref().map(|c| c.len()), Some(10000));

    // Verify many tags stored correctly
    let entry4 = storage.get_by_id(id4).await.expect("should get entry4");
    assert_eq!(entry4.tags.len(), 50);

    // Search for entry with long hostname
    let filter = HostFilter {
        ip_pattern: None,
        hostname_pattern: Some("aaaaaa".to_string()), // Partial match
        tags: None,
    };
    let results = storage.search(filter).await.expect("search should succeed");
    assert!(
        results.iter().any(|e| e.id == id2),
        "should find entry with long hostname"
    );
}

/// Test that list_all returns entries sorted by IP address, then hostname
///
/// This is a critical invariant for /etc/hosts file generation.
/// Design doc: "Sorted entries (by IP, then hostname)"
pub async fn test_list_all_sorted_by_ip_then_hostname<S: Storage>(storage: &S) {
    // Create entries in random order (not sorted by IP or hostname)
    // Using IPs that will sort differently lexicographically vs numerically
    let entries = [
        ("192.168.10.1", "zebra.local"),
        ("10.0.0.1", "alpha.local"),
        ("192.168.1.1", "gamma.local"),
        ("10.0.0.1", "beta.local"), // Same IP as alpha, different hostname
        ("192.168.1.1", "delta.local"), // Same IP as gamma, different hostname
        ("172.16.0.1", "epsilon.local"),
    ];

    for (ip, hostname) in entries {
        create_host(storage, ip, hostname, None, vec!["sort-test"]).await;
    }

    let all = storage.list_all().await.expect("list_all should succeed");

    // Filter to only our test entries
    let sorted: Vec<_> = all
        .iter()
        .filter(|e| e.tags.contains(&"sort-test".to_string()))
        .collect();

    assert_eq!(sorted.len(), 6, "should have all 6 test entries");

    // Verify sorting: IPs should be sorted lexicographically (string order),
    // then hostnames within same IP
    //
    // Expected order (lexicographic IP sort):
    // 1. 10.0.0.1 alpha.local
    // 2. 10.0.0.1 beta.local
    // 3. 172.16.0.1 epsilon.local
    // 4. 192.168.1.1 delta.local
    // 5. 192.168.1.1 gamma.local
    // 6. 192.168.10.1 zebra.local

    // Verify IP ordering
    for i in 0..sorted.len() - 1 {
        let current = &sorted[i];
        let next = &sorted[i + 1];

        let ip_cmp = current.ip_address.cmp(&next.ip_address);
        let hostname_cmp = current.hostname.cmp(&next.hostname);

        assert!(
            ip_cmp.is_lt() || (ip_cmp.is_eq() && hostname_cmp.is_lt()),
            "Entries not sorted correctly at position {}: {} {} should come before {} {}",
            i,
            current.ip_address,
            current.hostname,
            next.ip_address,
            next.hostname
        );
    }

    // Verify specific expected order
    assert_eq!(sorted[0].ip_address, "10.0.0.1");
    assert_eq!(sorted[0].hostname, "alpha.local");

    assert_eq!(sorted[1].ip_address, "10.0.0.1");
    assert_eq!(sorted[1].hostname, "beta.local");

    assert_eq!(sorted[2].ip_address, "172.16.0.1");
    assert_eq!(sorted[2].hostname, "epsilon.local");

    assert_eq!(sorted[3].ip_address, "192.168.1.1");
    assert_eq!(sorted[3].hostname, "delta.local");

    assert_eq!(sorted[4].ip_address, "192.168.1.1");
    assert_eq!(sorted[4].hostname, "gamma.local");

    assert_eq!(sorted[5].ip_address, "192.168.10.1");
    assert_eq!(sorted[5].hostname, "zebra.local");
}
