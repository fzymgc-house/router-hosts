//! Integration tests for the router-hosts gRPC server
//!
//! # Security Note
//!
//! These integration tests use plain HTTP instead of mTLS for the following reasons:
//!
//! 1. **Certificate Generation**: mTLS testing requires generating CA certificates,
//!    server certificates, and client certificates at test runtime. This adds
//!    significant complexity and external dependencies (openssl or similar).
//!
//! 2. **Test Isolation**: Each test would need unique certificates to avoid
//!    port/certificate conflicts when running tests in parallel.
//!
//! 3. **Scope**: The TLS implementation uses well-tested libraries (rustls, webpki).
//!    The value of integration testing is primarily in the gRPC service logic,
//!    not in re-testing the TLS stack.
//!
//! For production deployment, mTLS is mandatory and configured via the server config.
//!
//! **Note:** Full mTLS testing is covered by E2E tests (router-hosts-e2e crate) which
//! use real certificates generated at test runtime. These unit-level integration tests
//! focus on gRPC service logic without the TLS overhead.

use router_hosts::server::commands::CommandHandler;
use router_hosts::server::hooks::HookExecutor;
use router_hosts::server::hosts_file::HostsFileGenerator;
use router_hosts::server::service::HostsServiceImpl;
use router_hosts::server::write_queue::WriteQueue;
use router_hosts_common::proto::hosts_service_client::HostsServiceClient;
use router_hosts_common::proto::hosts_service_server::HostsServiceServer;
use router_hosts_common::proto::{
    AddHostRequest, AliasesUpdate, CreateSnapshotRequest, DeleteHostRequest, DeleteSnapshotRequest,
    ExportHostsRequest, GetHostRequest, ImportHostsRequest, ListHostsRequest, ListSnapshotsRequest,
    RollbackToSnapshotRequest, SearchHostsRequest, UpdateHostRequest,
};
use router_hosts_storage::backends::sqlite::SqliteStorage;
use router_hosts_storage::Storage;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tonic::transport::{Channel, Server};

/// Start a test server on a random port and return the address and temp directory handle.
/// The caller must keep the returned TempDir alive for the duration of the test.
async fn start_test_server() -> (SocketAddr, Arc<tempfile::TempDir>) {
    // Bind to port 0 to let the OS assign an available port
    // This prevents port conflicts when tests run in parallel
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release the port for the server to use

    // Create in-memory storage
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("failed to create in-memory storage");
    storage
        .initialize()
        .await
        .expect("failed to initialize storage");
    let storage: Arc<dyn Storage> = Arc::new(storage);

    // Create hooks (no-op for tests)
    let hooks = Arc::new(HookExecutor::new(vec![], vec![], 30));

    // Create hosts file generator with temp path.
    // The TempDir is wrapped in Arc and returned to the caller to ensure
    // the directory stays alive for the test duration.
    let temp_dir = Arc::new(tempfile::tempdir().unwrap());
    let hosts_path = temp_dir.path().join("hosts");
    let hosts_path_str = hosts_path.to_string_lossy().to_string();
    let hosts_file = Arc::new(HostsFileGenerator::new(hosts_path));

    // Create test config
    let config = Arc::new(router_hosts::server::config::Config {
        server: router_hosts::server::config::ServerConfig {
            bind_address: format!("127.0.0.1:{}", addr.port()),
            hosts_file_path: hosts_path_str,
        },
        database: router_hosts::server::config::DatabaseConfig {
            path: None,
            url: Some("sqlite://:memory:".to_string()),
        },
        tls: router_hosts::server::config::TlsConfig {
            cert_path: std::path::PathBuf::from("/tmp/cert.pem"),
            key_path: std::path::PathBuf::from("/tmp/key.pem"),
            ca_cert_path: std::path::PathBuf::from("/tmp/ca.pem"),
        },
        retention: router_hosts::server::config::RetentionConfig {
            max_snapshots: 50,
            max_age_days: 30,
        },
        hooks: router_hosts::server::config::HooksConfig::default(),
        acme: router_hosts::server::acme::AcmeConfig::default(),
    });

    // Create command handler
    let commands = Arc::new(CommandHandler::new(
        Arc::clone(&storage),
        Arc::clone(&hosts_file),
        Arc::clone(&hooks),
        config,
    ));

    // Create write queue for serialized mutation operations
    let write_queue = WriteQueue::new(Arc::clone(&commands));

    // Create service
    let service = HostsServiceImpl::new(
        write_queue,
        Arc::clone(&commands),
        Arc::clone(&storage),
        hooks,
        false, // acme_enabled
        None,  // tls_cert_path
    );

    // Spawn server task
    tokio::spawn(async move {
        eprintln!("Starting server on {}", addr);
        let result = Server::builder()
            .add_service(HostsServiceServer::new(service))
            .serve(addr)
            .await;
        if let Err(e) = result {
            eprintln!("Server error: {}", e);
        }
    });

    // Wait for server to be ready by trying to connect
    for i in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        if TcpStream::connect(addr).await.is_ok() {
            eprintln!("Server is ready after {} attempts", i + 1);
            return (addr, temp_dir);
        }
    }

    panic!("Server failed to start within 3 seconds");
}

/// Create a client connected to the test server
async fn create_client(addr: SocketAddr) -> HostsServiceClient<Channel> {
    let endpoint = format!("http://{}", addr);

    eprintln!("Connecting to: {}", endpoint);

    // Create a lazy channel (doesn't connect until first request)
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect_timeout(tokio::time::Duration::from_secs(2))
        .timeout(tokio::time::Duration::from_secs(5))
        .connect_lazy();

    HostsServiceClient::new(channel)
}

#[tokio::test]
async fn test_add_and_get_host() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    let add_response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec![],
            comment: Some("Test server".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap()
        .into_inner();

    let host_id = add_response.id;
    assert!(!host_id.is_empty());

    let entry = add_response.entry.unwrap();
    assert_eq!(entry.ip_address, "192.168.1.10");
    assert_eq!(entry.hostname, "server.local");
    assert_eq!(entry.comment, Some("Test server".to_string()));
    assert_eq!(entry.tags, vec!["test".to_string()]);

    // Get the host
    let get_response = client
        .get_host(GetHostRequest {
            id: host_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    let fetched = get_response.entry.unwrap();
    assert_eq!(fetched.id, host_id);
    assert_eq!(fetched.ip_address, "192.168.1.10");
    assert_eq!(fetched.hostname, "server.local");
}

#[tokio::test]
async fn test_server_starts() {
    // Simply verify we can start a test server
    let (addr, _temp_dir) = start_test_server().await;
    eprintln!("Test server started successfully on {}", addr);
}

#[tokio::test]
async fn test_update_host() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    let add_response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.20".to_string(),
            hostname: "old.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let host_id = add_response.id;

    // Update the host
    let update_response = client
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.1.21".to_string()),
            hostname: Some("new.local".to_string()),
            aliases: None,
            comment: Some("Updated".to_string()),
            tags: Some(router_hosts_common::proto::TagsUpdate {
                values: vec!["updated".to_string()],
            }),
            expected_version: None,
        })
        .await
        .unwrap()
        .into_inner();

    let updated = update_response.entry.unwrap();
    assert_eq!(updated.ip_address, "192.168.1.21");
    assert_eq!(updated.hostname, "new.local");
    assert_eq!(updated.comment, Some("Updated".to_string()));
}

#[tokio::test]
async fn test_delete_host() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    let add_response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.30".to_string(),
            hostname: "delete.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let host_id = add_response.id;

    // Delete the host
    let delete_response = client
        .delete_host(DeleteHostRequest {
            id: host_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(delete_response.success);

    // Try to get the deleted host - should fail
    let get_result = client.get_host(GetHostRequest { id: host_id }).await;

    assert!(get_result.is_err());
}

#[tokio::test]
async fn test_list_hosts() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add multiple hosts
    for i in 1..=3 {
        client
            .add_host(AddHostRequest {
                ip_address: format!("192.168.1.{}", 40 + i),
                hostname: format!("host{}.local", i),
                aliases: vec![],
                comment: None,
                tags: vec![],
            })
            .await
            .unwrap();
    }

    // List all hosts
    let mut stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let mut count = 0;
    while let Some(response) = stream.message().await.unwrap() {
        assert!(response.entry.is_some());
        count += 1;
    }

    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_search_hosts() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add hosts with different names
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.50".to_string(),
            hostname: "webserver.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.51".to_string(),
            hostname: "database.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Search for "web"
    let mut stream = client
        .search_hosts(SearchHostsRequest {
            query: "web".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut results = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        results.push(response.entry.unwrap());
    }

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].hostname, "webserver.local");
}

#[tokio::test]
async fn test_export_hosts_hosts_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add some hosts
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec![],
            comment: Some("Test server".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap();

    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.20".to_string(),
            hostname: "nas.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Export as hosts format
    let mut stream = client
        .export_hosts(ExportHostsRequest {
            format: "hosts".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut chunks = Vec::new();
    while let Some(response) = stream.message().await.unwrap() {
        chunks.push(response.chunk);
    }

    // First chunk should be header
    let header = String::from_utf8(chunks[0].clone()).unwrap();
    assert!(header.contains("Generated by router-hosts"));
    assert!(header.contains("Entry count: 2"));

    // Should have header + 2 entries = 3 chunks
    assert_eq!(chunks.len(), 3);
}

#[tokio::test]
async fn test_export_hosts_json_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec![],
            comment: Some("Test".to_string()),
            tags: vec!["tag1".to_string()],
        })
        .await
        .unwrap();

    // Export as JSON
    let mut stream = client
        .export_hosts(ExportHostsRequest {
            format: "json".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut chunks = Vec::new();
    while let Some(response) = stream.message().await.unwrap() {
        chunks.push(response.chunk);
    }

    // JSON has no header, just 1 entry
    assert_eq!(chunks.len(), 1);

    // Verify it's valid JSON
    let json_str = String::from_utf8(chunks[0].clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["ip_address"], "192.168.1.10");
    assert_eq!(parsed["hostname"], "server.local");
}

#[tokio::test]
async fn test_export_hosts_invalid_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    let result = client
        .export_hosts(ExportHostsRequest {
            format: "invalid".to_string(),
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_export_hosts_csv_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host with a comment containing a comma
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec![],
            comment: Some("Hello, world".to_string()),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
        })
        .await
        .unwrap();

    // Export as CSV
    let mut stream = client
        .export_hosts(ExportHostsRequest {
            format: "csv".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut chunks = Vec::new();
    while let Some(response) = stream.message().await.unwrap() {
        chunks.push(response.chunk);
    }

    // CSV has header + 1 entry = 2 chunks
    assert_eq!(chunks.len(), 2);

    // First chunk should be header
    let header = String::from_utf8(chunks[0].clone()).unwrap();
    assert_eq!(header, "ip_address,hostname,aliases,comment,tags\n");

    // Second chunk should have properly escaped comment
    let entry = String::from_utf8(chunks[1].clone()).unwrap();
    assert!(entry.contains("\"Hello, world\"")); // Comma should be quoted
    assert!(entry.contains("tag1;tag2"));
}

// ============================================================================
// Empty Database Export Tests (Issue #26)
//
// These tests verify ExportHosts behavior when the database has no entries.
// Each format should handle the empty case gracefully.
// ============================================================================

#[tokio::test]
async fn test_export_hosts_empty_database_hosts_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Export without adding any hosts - database is empty
    let mut stream = client
        .export_hosts(ExportHostsRequest {
            format: "hosts".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut chunks = Vec::new();
    while let Some(response) = stream.message().await.unwrap() {
        chunks.push(response.chunk);
    }

    // Should have only header, no entries
    assert_eq!(
        chunks.len(),
        1,
        "Empty database should return only header chunk"
    );
    let header = String::from_utf8(chunks[0].clone()).unwrap();
    assert!(
        header.contains("Generated by router-hosts"),
        "Header should contain generator comment"
    );
    assert!(
        header.contains("Entry count: 0"),
        "Header should show zero entry count"
    );
}

#[tokio::test]
async fn test_export_hosts_empty_database_json_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Export without adding any hosts - database is empty
    let mut stream = client
        .export_hosts(ExportHostsRequest {
            format: "json".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut chunks = Vec::new();
    while let Some(response) = stream.message().await.unwrap() {
        chunks.push(response.chunk);
    }

    // JSON format with empty database should return no chunks
    assert_eq!(
        chunks.len(),
        0,
        "Empty database JSON export should return no chunks"
    );
}

#[tokio::test]
async fn test_export_hosts_empty_database_csv_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Export without adding any hosts - database is empty
    let mut stream = client
        .export_hosts(ExportHostsRequest {
            format: "csv".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut chunks = Vec::new();
    while let Some(response) = stream.message().await.unwrap() {
        chunks.push(response.chunk);
    }

    // CSV format should return only the header row
    assert_eq!(
        chunks.len(),
        1,
        "Empty database CSV export should return only header chunk"
    );
    let header = String::from_utf8(chunks[0].clone()).unwrap();
    assert_eq!(header, "ip_address,hostname,aliases,comment,tags\n");
}

#[tokio::test]
async fn test_import_hosts_via_grpc() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Import some hosts
    let import_data =
        b"192.168.1.10\tserver1.local\n192.168.1.11\tserver2.local\t# Second server\n";

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: Some("skip".to_string()),
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.processed, 2);
    assert_eq!(progress.created, 2);
    assert_eq!(progress.skipped, 0);
    assert_eq!(progress.failed, 0);

    // Verify hosts were created
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let mut stream = list_response.into_inner();
    let mut count = 0;
    while let Some(_) = stream.message().await.unwrap() {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_import_export_roundtrip() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "roundtrip.local".to_string(),
            aliases: vec![],
            comment: Some("Roundtrip test".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap();

    // Export as hosts format
    let export_response = client
        .export_hosts(ExportHostsRequest {
            format: "hosts".to_string(),
        })
        .await
        .unwrap();

    let mut export_data = Vec::new();
    let mut stream = export_response.into_inner();
    while let Some(chunk) = stream.message().await.unwrap() {
        export_data.extend_from_slice(&chunk.chunk);
    }

    // Delete the host
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let mut stream = list_response.into_inner();
    let first_entry = stream.message().await.unwrap().unwrap();
    let host_id = first_entry.entry.as_ref().unwrap().id.clone();

    client
        .delete_host(DeleteHostRequest { id: host_id })
        .await
        .unwrap();

    // Import the exported data
    let requests = vec![ImportHostsRequest {
        chunk: export_data,
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: Some("skip".to_string()),
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.created, 1);

    // Verify host is back
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let mut stream = list_response.into_inner();
    let mut count = 0;
    let mut restored_hostname = None;
    while let Some(response) = stream.message().await.unwrap() {
        if let Some(entry) = response.entry {
            restored_hostname = Some(entry.hostname);
            count += 1;
        }
    }
    assert_eq!(count, 1);
    assert_eq!(restored_hostname, Some("roundtrip.local".to_string()));
}

#[tokio::test]
async fn test_import_hosts_json_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Import hosts using JSON Lines format
    let import_data = br#"{"ip_address": "10.0.0.1", "hostname": "json1.local", "comment": "JSON import 1", "tags": ["test", "json"]}
{"ip_address": "10.0.0.2", "hostname": "json2.local"}"#;

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("json".to_string()),
        conflict_mode: Some("skip".to_string()),
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.processed, 2);
    assert_eq!(progress.created, 2);
    assert_eq!(progress.failed, 0);

    // Verify hosts were created
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let mut stream = list_response.into_inner();
    let mut count = 0;
    while stream.message().await.unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, 2);
}

#[tokio::test]
async fn test_import_hosts_csv_format() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Import hosts using CSV format
    let import_data = b"ip_address,hostname,aliases,comment,tags
10.1.0.1,csv1.local,,CSV import 1,test;csv
10.1.0.2,csv2.local,,,";

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("csv".to_string()),
        conflict_mode: Some("skip".to_string()),
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.processed, 2);
    assert_eq!(progress.created, 2);
    assert_eq!(progress.failed, 0);

    // Verify hosts were created
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let mut stream = list_response.into_inner();
    let mut count = 0;
    while stream.message().await.unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, 2);
}

// ============================================================================
// Import Conflict Mode Integration Tests
//
// These tests verify the different conflict handling modes for the import
// endpoint: skip (default), replace, and strict.
// ============================================================================

/// Test import with `skip` mode - skips duplicate IP+hostname combinations
#[tokio::test]
async fn test_import_conflict_mode_skip() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // First, add a host directly
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.50.1".to_string(),
            hostname: "skip-test.local".to_string(),
            aliases: vec![],
            comment: Some("Original entry".to_string()),
            tags: vec!["original".to_string()],
        })
        .await
        .unwrap();

    // Import with skip mode - same IP+hostname should be skipped
    let import_data =
        b"192.168.50.1\tskip-test.local\t# Imported entry\n192.168.50.2\tnew-skip.local\n";

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: Some("skip".to_string()),
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.processed, 2);
    assert_eq!(progress.created, 1); // Only the new entry
    assert_eq!(progress.skipped, 1); // Duplicate skipped
    assert_eq!(progress.failed, 0);

    // Verify original entry wasn't modified
    let search_response = client
        .search_hosts(SearchHostsRequest {
            query: "skip-test.local".to_string(),
        })
        .await
        .unwrap();

    let mut stream = search_response.into_inner();
    let entry = stream.message().await.unwrap().unwrap().entry.unwrap();
    assert_eq!(entry.comment.as_deref(), Some("Original entry")); // Unchanged
    assert_eq!(entry.tags, vec!["original".to_string()]);
}

/// Test import with `replace` mode - updates existing entries with new values
#[tokio::test]
async fn test_import_conflict_mode_replace() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // First, add a host directly
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.51.1".to_string(),
            hostname: "replace-test.local".to_string(),
            aliases: vec![],
            comment: Some("Original entry".to_string()),
            tags: vec!["original".to_string()],
        })
        .await
        .unwrap();

    // Import with replace mode - same IP+hostname should be updated
    let import_data =
        b"192.168.51.1\treplace-test.local\t# Updated entry\n192.168.51.2\tnew-replace.local\n";

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: Some("replace".to_string()),
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.processed, 2);
    assert_eq!(progress.created, 1); // New entry created
    assert_eq!(progress.updated, 1); // Existing entry updated
    assert_eq!(progress.skipped, 0);
    assert_eq!(progress.failed, 0);

    // Verify the entry was updated
    let search_response = client
        .search_hosts(SearchHostsRequest {
            query: "replace-test.local".to_string(),
        })
        .await
        .unwrap();

    let mut stream = search_response.into_inner();
    let entry = stream.message().await.unwrap().unwrap().entry.unwrap();
    assert_eq!(entry.comment.as_deref(), Some("Updated entry")); // Changed
    assert!(entry.tags.is_empty()); // Tags not in hosts format, so empty
}

/// Test import with `strict` mode - fails on any duplicate with ALREADY_EXISTS error
#[tokio::test]
async fn test_import_conflict_mode_strict() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // First, add a host directly
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.52.1".to_string(),
            hostname: "strict-test.local".to_string(),
            aliases: vec![],
            comment: Some("Original entry".to_string()),
            tags: vec![],
        })
        .await
        .unwrap();

    // Import with strict mode - same IP+hostname should fail with ALREADY_EXISTS
    let import_data = b"192.168.52.2\tnew-strict.local\n192.168.52.1\tstrict-test.local\n";

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: Some("strict".to_string()),
        force: Some(false),
    }];

    let result = client.import_hosts(tokio_stream::iter(requests)).await;

    // Strict mode should return an error for duplicates
    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::AlreadyExists);
    assert!(status.message().contains("already exists"));
}

/// Test import with invalid conflict mode - should default to skip
#[tokio::test]
async fn test_import_invalid_conflict_mode_defaults_to_skip() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // First, add a host directly
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.53.1".to_string(),
            hostname: "default-test.local".to_string(),
            aliases: vec![],
            comment: Some("Original".to_string()),
            tags: vec![],
        })
        .await
        .unwrap();

    // Import with no conflict_mode specified (should default to skip)
    let import_data = b"192.168.53.1\tdefault-test.local\t# Imported\n";

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: None, // Not specified
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    // Should behave like skip mode
    assert_eq!(progress.skipped, 1);
    assert_eq!(progress.created, 0);
    assert_eq!(progress.failed, 0);
}

/// Test import replace mode with JSON format preserves tags
#[tokio::test]
async fn test_import_replace_mode_json_preserves_tags() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // First, add a host directly
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.54.1".to_string(),
            hostname: "json-replace.local".to_string(),
            aliases: vec![],
            comment: Some("Original".to_string()),
            tags: vec!["old-tag".to_string()],
        })
        .await
        .unwrap();

    // Import with replace mode using JSON (which supports tags)
    let import_data =
        br#"{"ip_address": "192.168.54.1", "hostname": "json-replace.local", "comment": "Updated via JSON", "tags": ["new-tag", "imported"]}"#;

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("json".to_string()),
        conflict_mode: Some("replace".to_string()),
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.updated, 1);

    // Verify the entry was updated with new tags
    let search_response = client
        .search_hosts(SearchHostsRequest {
            query: "json-replace.local".to_string(),
        })
        .await
        .unwrap();

    let mut stream = search_response.into_inner();
    let entry = stream.message().await.unwrap().unwrap().entry.unwrap();
    assert_eq!(entry.comment.as_deref(), Some("Updated via JSON"));
    assert!(entry.tags.contains(&"new-tag".to_string()));
    assert!(entry.tags.contains(&"imported".to_string()));
    assert!(!entry.tags.contains(&"old-tag".to_string())); // Old tag replaced
}

// ============================================================================
// Version Conflict Integration Tests (Issue #52)
//
// These tests verify the server-side optimistic concurrency control for
// the UpdateHost RPC. They simulate concurrent modifications by multiple
// clients and verify that version conflicts are detected and handled correctly.
//
// Test Coverage:
// ✅ Scenario 1: Version conflict detection with successful retry
// ✅ Scenario 3: Maximum retry enforcement (multiple rapid conflicts)
// ✅ Scenario 5: Recursive retry on subsequent conflicts
// ⚠️  Scenario 2: Non-interactive mode (client-side CLI behavior, tested manually)
// ⚠️  Scenario 4: User cancellation (client-side CLI prompting, tested manually)
//
// Note on Scenarios 2 & 4:
// These scenarios involve client-side interactive prompt behavior that is
// tested manually and through client unit tests. Testing these end-to-end
// would require subprocess infrastructure to spawn the CLI binary and inject
// stdin input, which is beyond the scope of gRPC integration tests.
//
// The server correctly returns ABORTED status (verified by all tests below),
// and the client handle_version_conflict() function is documented and manually
// tested for both interactive and non-interactive modes.
// ============================================================================

#[tokio::test]
async fn test_version_conflict_detection() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client1 = create_client(addr).await;
    let mut client2 = create_client(addr).await;

    // Create a host with client1
    let add_response = client1
        .add_host(AddHostRequest {
            ip_address: "192.168.100.1".to_string(),
            hostname: "conflict-test.local".to_string(),
            aliases: vec![],
            comment: Some("Initial".to_string()),
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let host_id = add_response.id;
    let entry = add_response.entry.unwrap();
    let v1 = entry.version.clone();

    // Client2 updates the host (version changes from v1 to v2)
    client2
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.100.2".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Updated by client2".to_string()),
            tags: None,
            expected_version: None, // No version check
        })
        .await
        .unwrap();

    // Client1 tries to update using old version v1 - should fail with ABORTED
    let result = client1
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.100.3".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Updated by client1".to_string()),
            tags: None,
            expected_version: Some(v1.clone()), // Stale version
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Aborted);
    assert!(status.message().contains("Version conflict"));

    // Verify host wasn't updated by client1
    let get_response = client1
        .get_host(GetHostRequest { id: host_id })
        .await
        .unwrap()
        .into_inner();

    let current = get_response.entry.unwrap();
    assert_eq!(current.ip_address, "192.168.100.2"); // Client2's update
    assert_eq!(current.comment.as_deref().unwrap(), "Updated by client2");
}

#[tokio::test]
async fn test_version_conflict_with_successful_retry() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client1 = create_client(addr).await;
    let mut client2 = create_client(addr).await;

    // Create a host
    let add_response = client1
        .add_host(AddHostRequest {
            ip_address: "192.168.101.1".to_string(),
            hostname: "retry-test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let host_id = add_response.id;
    let v1 = add_response.entry.unwrap().version.clone();

    // Client2 updates (v1 -> v2)
    let client2_update = client2
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.101.2".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Client2 update".to_string()),
            tags: None,
            expected_version: None,
        })
        .await
        .unwrap()
        .into_inner();

    let _v2 = client2_update.entry.unwrap().version.clone();

    // Client1 tries with v1 - should fail
    let result = client1
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.101.3".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Client1 first attempt".to_string()),
            tags: None,
            expected_version: Some(v1),
        })
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Aborted);

    // Client1 fetches current version and retries with v2 - should succeed
    let current = client1
        .get_host(GetHostRequest {
            id: host_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    let retry_result = client1
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.101.3".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Client1 retry".to_string()),
            tags: None,
            expected_version: Some(current.entry.unwrap().version),
        })
        .await;

    assert!(retry_result.is_ok());
    let updated = retry_result.unwrap().into_inner().entry.unwrap();
    assert_eq!(updated.ip_address, "192.168.101.3");
    assert_eq!(updated.comment.as_deref().unwrap(), "Client1 retry");
}

#[tokio::test]
async fn test_version_conflict_multiple_rapid_conflicts() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client1 = create_client(addr).await;
    let mut client2 = create_client(addr).await;
    let mut client3 = create_client(addr).await;

    // Create a host
    let add_response = client1
        .add_host(AddHostRequest {
            ip_address: "192.168.102.1".to_string(),
            hostname: "rapid-conflict.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let host_id = add_response.id;
    let v1 = add_response.entry.unwrap().version.clone();

    // Client2 updates (v1 -> v2)
    client2
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.102.2".to_string()),
            hostname: None,
            aliases: None,
            comment: None,
            tags: None,
            expected_version: None,
        })
        .await
        .unwrap();

    // Client3 updates (v2 -> v3)
    client3
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.102.3".to_string()),
            hostname: None,
            aliases: None,
            comment: None,
            tags: None,
            expected_version: None,
        })
        .await
        .unwrap();

    // Client1 tries with v1 - should fail (now at v3)
    let result = client1
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.102.99".to_string()),
            hostname: None,
            aliases: None,
            comment: None,
            tags: None,
            expected_version: Some(v1),
        })
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), tonic::Code::Aborted);

    // Verify final state is v3 from client3
    let final_state = client1
        .get_host(GetHostRequest { id: host_id })
        .await
        .unwrap()
        .into_inner()
        .entry
        .unwrap();

    assert_eq!(final_state.ip_address, "192.168.102.3");
}

#[tokio::test]
async fn test_version_conflict_recursive_retry_simulation() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client1 = create_client(addr).await;
    let mut client2 = create_client(addr).await;

    // Create a host
    let add_response = client1
        .add_host(AddHostRequest {
            ip_address: "192.168.103.1".to_string(),
            hostname: "recursive.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let host_id = add_response.id;
    let v1 = add_response.entry.unwrap().version.clone();

    // Client2 modifies twice (v1 -> v2 -> v3)
    let update1 = client2
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.103.2".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Update 1".to_string()),
            tags: None,
            expected_version: None,
        })
        .await
        .unwrap()
        .into_inner();

    let v2 = update1.entry.unwrap().version;

    client2
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.103.3".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Update 2".to_string()),
            tags: None,
            expected_version: Some(v2),
        })
        .await
        .unwrap();

    // Client1 tries with v1 - fails (conflict 1)
    let attempt1 = client1
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.103.99".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Client1 attempt".to_string()),
            tags: None,
            expected_version: Some(v1),
        })
        .await;

    assert!(attempt1.is_err());
    assert_eq!(attempt1.unwrap_err().code(), tonic::Code::Aborted);

    // Simulate first retry: fetch current version
    let current1 = client1
        .get_host(GetHostRequest {
            id: host_id.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .entry
        .unwrap();

    let v3 = current1.version.clone();

    // While client1 is preparing retry, client2 updates again (v3 -> v4)
    client2
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.103.4".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Update 3".to_string()),
            tags: None,
            expected_version: Some(v3.clone()),
        })
        .await
        .unwrap();

    // Client1's first retry with v3 - fails again (conflict 2)
    let attempt2 = client1
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.103.99".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Client1 retry 1".to_string()),
            tags: None,
            expected_version: Some(v3),
        })
        .await;

    assert!(attempt2.is_err());
    assert_eq!(attempt2.unwrap_err().code(), tonic::Code::Aborted);

    // Simulate second retry: fetch current version again
    let current2 = client1
        .get_host(GetHostRequest {
            id: host_id.clone(),
        })
        .await
        .unwrap()
        .into_inner()
        .entry
        .unwrap();

    // Second retry with current version - should succeed
    let final_attempt = client1
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.103.99".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Client1 final retry".to_string()),
            tags: None,
            expected_version: Some(current2.version),
        })
        .await;

    assert!(final_attempt.is_ok());
    let final_entry = final_attempt.unwrap().into_inner().entry.unwrap();
    assert_eq!(final_entry.ip_address, "192.168.103.99");
    assert_eq!(
        final_entry.comment.as_deref().unwrap(),
        "Client1 final retry"
    );
}

#[tokio::test]
async fn test_update_without_version_check_always_succeeds() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client1 = create_client(addr).await;
    let mut client2 = create_client(addr).await;

    // Create a host
    let add_response = client1
        .add_host(AddHostRequest {
            ip_address: "192.168.104.1".to_string(),
            hostname: "no-version-check.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let host_id = add_response.id;

    // Client2 updates
    client2
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.104.2".to_string()),
            hostname: None,
            aliases: None,
            comment: None,
            tags: None,
            expected_version: None,
        })
        .await
        .unwrap();

    // Client1 updates without version check - should succeed even though version changed
    let result = client1
        .update_host(UpdateHostRequest {
            id: host_id.clone(),
            ip_address: Some("192.168.104.3".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("No version check".to_string()),
            tags: None,
            expected_version: None, // No version check = last write wins
        })
        .await;

    assert!(result.is_ok());
    let updated = result.unwrap().into_inner().entry.unwrap();
    assert_eq!(updated.ip_address, "192.168.104.3");
}

// ============================================================================
// Snapshot Integration Tests (Issue #17 - Coverage Audit)
//
// These tests verify snapshot CRUD operations to bring coverage of
// server/service/snapshots.rs from 0% to ≥80%.
//
// Test Coverage:
// ✅ CreateSnapshot - manual trigger with custom name
// ✅ ListSnapshots - pagination and ordering
// ✅ RollbackToSnapshot - state restoration and auto-backup
// ✅ DeleteSnapshot - removal and error handling
// ============================================================================

#[tokio::test]
async fn test_create_snapshot_manual() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add some hosts to create initial state
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.200.1".to_string(),
            hostname: "snapshot-test-1.local".to_string(),
            aliases: vec![],
            comment: Some("Test host 1".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap();

    client
        .add_host(AddHostRequest {
            ip_address: "192.168.200.2".to_string(),
            hostname: "snapshot-test-2.local".to_string(),
            aliases: vec![],
            comment: Some("Test host 2".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap();

    // Create a manual snapshot
    let response = client
        .create_snapshot(CreateSnapshotRequest {
            name: "test-snapshot".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!response.snapshot_id.is_empty());
    assert!(response.created_at > 0);
    assert_eq!(response.entry_count, 2);
}

#[tokio::test]
async fn test_list_snapshots() {
    use tonic::Streaming;

    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.201.1".to_string(),
            hostname: "list-snapshot-test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Create three snapshots
    let snap1 = client
        .create_snapshot(CreateSnapshotRequest {
            name: "snapshot-1".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let snap2 = client
        .create_snapshot(CreateSnapshotRequest {
            name: "snapshot-2".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let snap3 = client
        .create_snapshot(CreateSnapshotRequest {
            name: "snapshot-3".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    // List all snapshots
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let mut snapshot_ids = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        let snapshot = response.snapshot.unwrap();
        snapshot_ids.push(snapshot.snapshot_id.clone());
        assert_eq!(snapshot.entry_count, 1);
        assert_eq!(snapshot.trigger, "manual");
    }

    // Verify all three snapshots are listed
    assert_eq!(snapshot_ids.len(), 3);
    assert!(snapshot_ids.contains(&snap1.snapshot_id));
    assert!(snapshot_ids.contains(&snap2.snapshot_id));
    assert!(snapshot_ids.contains(&snap3.snapshot_id));
}

#[tokio::test]
async fn test_list_snapshots_with_pagination() {
    use tonic::Streaming;

    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.202.1".to_string(),
            hostname: "pagination-test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Create 5 snapshots
    for i in 1..=5 {
        client
            .create_snapshot(CreateSnapshotRequest {
                name: format!("snapshot-{}", i),
                trigger: "manual".to_string(),
            })
            .await
            .unwrap();
    }

    // List with limit=2, offset=0 (first page)
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 2,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let mut first_page = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        first_page.push(response.snapshot.unwrap());
    }

    assert_eq!(first_page.len(), 2);

    // List with limit=2, offset=2 (second page)
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 2,
            offset: 2,
        })
        .await
        .unwrap()
        .into_inner();

    let mut second_page = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        second_page.push(response.snapshot.unwrap());
    }

    assert_eq!(second_page.len(), 2);

    // Verify no overlap between pages
    let first_ids: Vec<_> = first_page.iter().map(|s| &s.snapshot_id).collect();
    let second_ids: Vec<_> = second_page.iter().map(|s| &s.snapshot_id).collect();
    for id in &first_ids {
        assert!(!second_ids.contains(id));
    }
}

#[tokio::test]
async fn test_delete_snapshot() {
    use tonic::Streaming;

    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.204.1".to_string(),
            hostname: "delete-snapshot-test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Create snapshot
    let snapshot_response = client
        .create_snapshot(CreateSnapshotRequest {
            name: "to-be-deleted".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let snapshot_id = snapshot_response.snapshot_id.clone();

    // Verify snapshot exists
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let mut found = false;
    while let Some(response) = stream.message().await.unwrap() {
        if response.snapshot.unwrap().snapshot_id == snapshot_id {
            found = true;
            break;
        }
    }
    assert!(found, "Snapshot should exist before deletion");

    // Delete snapshot
    let delete_response = client
        .delete_snapshot(DeleteSnapshotRequest {
            snapshot_id: snapshot_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(delete_response.success);

    // Verify snapshot no longer exists
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let mut found = false;
    while let Some(response) = stream.message().await.unwrap() {
        if response.snapshot.unwrap().snapshot_id == snapshot_id {
            found = true;
            break;
        }
    }
    assert!(!found, "Snapshot should not exist after deletion");
}

#[tokio::test]
async fn test_delete_nonexistent_snapshot() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Try to delete a snapshot that doesn't exist
    let result = client
        .delete_snapshot(DeleteSnapshotRequest {
            snapshot_id: "nonexistent-snapshot-id".to_string(),
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

// ============================================================================
// Snapshot Coverage Tests (Issue #67)
//
// These tests cover defensive code paths in snapshots.rs to achieve ≥95% coverage.
// ============================================================================

#[tokio::test]
async fn test_create_snapshot_with_empty_trigger() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host so we have something to snapshot
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.220.1".to_string(),
            hostname: "empty-trigger-test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Create snapshot with empty trigger - should default to "manual"
    let response = client
        .create_snapshot(CreateSnapshotRequest {
            name: "test-empty-trigger".to_string(),
            trigger: "".to_string(), // Empty trigger
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!response.snapshot_id.is_empty());
    assert_eq!(response.entry_count, 1);

    // Verify the trigger defaulted to "manual" by listing snapshots
    let mut stream = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let snapshot = stream.message().await.unwrap().unwrap().snapshot.unwrap();
    assert_eq!(snapshot.trigger, "manual");
}

#[tokio::test]
async fn test_create_snapshot_with_empty_name() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host so we have something to snapshot
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.221.1".to_string(),
            hostname: "empty-name-test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Create snapshot with empty name - server generates a default name
    let response = client
        .create_snapshot(CreateSnapshotRequest {
            name: "".to_string(), // Empty name
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!response.snapshot_id.is_empty());
    assert_eq!(response.entry_count, 1);

    // Verify the snapshot was created with a generated name (format: snapshot-YYYYMMDD-HHMMSS)
    let mut stream = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let snapshot = stream.message().await.unwrap().unwrap().snapshot.unwrap();
    // When name is empty, server generates a default name starting with "snapshot-"
    assert!(
        snapshot.name.starts_with("snapshot-"),
        "Generated name should start with 'snapshot-', got: {}",
        snapshot.name
    );
}

#[tokio::test]
async fn test_rollback_with_empty_snapshot_id() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Try to rollback with empty snapshot_id - should return INVALID_ARGUMENT
    let result = client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: "".to_string(), // Empty snapshot_id
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("snapshot_id is required"));
}

#[tokio::test]
async fn test_delete_snapshot_with_empty_id() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Try to delete with empty snapshot_id - should return INVALID_ARGUMENT
    let result = client
        .delete_snapshot(DeleteSnapshotRequest {
            snapshot_id: "".to_string(), // Empty snapshot_id
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(status.message().contains("snapshot_id is required"));
}

// ============================================================================
// Rollback Integration Tests (Issue #58)
// ============================================================================

#[tokio::test]
async fn test_rollback_to_snapshot_basic() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Initial state: Create host1
    let host1 = client
        .add_host(AddHostRequest {
            ip_address: "192.168.210.1".to_string(),
            hostname: "rollback-test-1.local".to_string(),
            aliases: vec![],
            comment: Some("Initial state".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap()
        .into_inner();

    let host1_id = host1.id.clone();

    // Create snapshot of initial state
    let snapshot = client
        .create_snapshot(CreateSnapshotRequest {
            name: "before-changes".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let snapshot_id = snapshot.snapshot_id;

    // Modify state: Update host1 and add host2
    client
        .update_host(UpdateHostRequest {
            id: host1_id.clone(),
            ip_address: Some("192.168.210.99".to_string()),
            hostname: None,
            aliases: None,
            comment: Some("Modified after snapshot".to_string()),
            tags: None,
            expected_version: None,
        })
        .await
        .unwrap();

    client
        .add_host(AddHostRequest {
            ip_address: "192.168.210.2".to_string(),
            hostname: "rollback-test-2.local".to_string(),
            aliases: vec![],
            comment: Some("Added after snapshot".to_string()),
            tags: vec![],
        })
        .await
        .unwrap();

    // Verify modified state has 2 hosts
    let mut list_stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let mut hosts_before = vec![];
    while let Some(response) = list_stream
        .message()
        .await
        .expect("Failed to read stream message")
    {
        hosts_before.push(response.entry.expect("Missing entry in response"));
    }
    assert_eq!(hosts_before.len(), 2);

    // Rollback to initial snapshot
    let rollback_response = client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: snapshot_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(rollback_response.success);
    assert!(!rollback_response.new_snapshot_id.is_empty());

    // Validate backup snapshot ID is a valid ULID
    ulid::Ulid::from_string(&rollback_response.new_snapshot_id)
        .expect("Backup snapshot ID should be a valid ULID");

    // Verify restored state has 1 host with original values
    let mut list_stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let mut hosts_after = vec![];
    while let Some(response) = list_stream
        .message()
        .await
        .expect("Failed to read stream message")
    {
        hosts_after.push(response.entry.expect("Missing entry in response"));
    }

    assert_eq!(hosts_after.len(), 1);
    let restored = &hosts_after[0];
    assert_eq!(restored.ip_address, "192.168.210.1");
    assert_eq!(restored.hostname, "rollback-test-1.local");
    assert_eq!(restored.comment.as_deref().unwrap(), "Initial state");
    assert_eq!(restored.tags, vec!["test"]);
}

#[tokio::test]
async fn test_rollback_to_nonexistent_snapshot() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    let result = client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: "nonexistent-id".to_string(),
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    assert!(status.message().contains("Snapshot not found"));
}

#[tokio::test]
async fn test_rollback_creates_backup_snapshot() {
    use tonic::Streaming;

    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create initial state
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.211.1".to_string(),
            hostname: "backup-test.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Create snapshot1
    let snap1 = client
        .create_snapshot(CreateSnapshotRequest {
            name: "snapshot1".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    // Modify state
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.211.2".to_string(),
            hostname: "modified.local".to_string(),
            aliases: vec![],
            comment: Some("After snapshot".to_string()),
            tags: vec![],
        })
        .await
        .unwrap();

    // Count snapshots before rollback
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let mut count_before = 0;
    while let Some(_) = stream.message().await.unwrap() {
        count_before += 1;
    }
    assert_eq!(count_before, 1); // Only snapshot1

    // Rollback to snapshot1
    let rollback = client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: snap1.snapshot_id,
        })
        .await
        .unwrap()
        .into_inner();

    assert!(rollback.success);

    // Verify backup snapshot was created
    let mut stream: Streaming<_> = client
        .list_snapshots(ListSnapshotsRequest {
            limit: 0,
            offset: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let mut snapshots = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        snapshots.push(response.snapshot.unwrap());
    }

    assert_eq!(snapshots.len(), 2); // snapshot1 + pre-rollback backup

    // Find pre-rollback snapshot
    let backup_snap = snapshots
        .iter()
        .find(|s| s.trigger == "pre-rollback")
        .expect("Backup snapshot should exist");

    assert_eq!(backup_snap.snapshot_id, rollback.new_snapshot_id);
    assert_eq!(backup_snap.entry_count, 2); // Had 2 hosts before rollback
}

#[tokio::test]
async fn test_rollback_preserves_tags_and_comments() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create hosts with tags and comments
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.212.1".to_string(),
            hostname: "tags-test.local".to_string(),
            aliases: vec![],
            comment: Some("Important comment".to_string()),
            tags: vec!["production".to_string(), "critical".to_string()],
        })
        .await
        .unwrap();

    // Create snapshot
    let snapshot = client
        .create_snapshot(CreateSnapshotRequest {
            name: "with-tags".to_string(),
            trigger: "manual".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    // Delete the host
    let mut hosts = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let host = hosts.message().await.unwrap().unwrap().entry.unwrap();
    client
        .delete_host(DeleteHostRequest { id: host.id })
        .await
        .unwrap();

    // Verify empty
    let mut stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let mut count = 0;
    while let Some(_) = stream.message().await.unwrap() {
        count += 1;
    }
    assert_eq!(count, 0);

    // Rollback
    client
        .rollback_to_snapshot(RollbackToSnapshotRequest {
            snapshot_id: snapshot.snapshot_id,
        })
        .await
        .unwrap();

    // Verify tags and comment restored
    let mut stream = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap()
        .into_inner();

    let restored = stream.message().await.unwrap().unwrap().entry.unwrap();
    assert_eq!(restored.ip_address, "192.168.212.1");
    assert_eq!(restored.hostname, "tags-test.local");
    assert_eq!(restored.comment.as_deref().unwrap(), "Important comment");
    assert_eq!(
        restored.tags,
        vec!["production".to_string(), "critical".to_string()]
    );
}

// ============================================================================
// Error Code Tests (Design Invariant Coverage)
//
// These tests verify that the server returns correct gRPC status codes per
// the design document error mapping specification.
// ============================================================================

/// Test that adding a duplicate IP+hostname returns ALREADY_EXISTS
///
/// Design requirement: "Duplicate IP+hostname combinations are rejected"
/// Error mapping: Duplicate IP+hostname → ALREADY_EXISTS
#[tokio::test]
async fn test_add_duplicate_host_returns_already_exists() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add first host successfully
    let response = client
        .add_host(AddHostRequest {
            ip_address: "10.99.99.1".to_string(),
            hostname: "duplicate-test.local".to_string(),
            aliases: vec![],
            comment: Some("First entry".to_string()),
            tags: vec![],
        })
        .await;
    assert!(response.is_ok(), "First add should succeed");

    // Try to add the same IP+hostname combination again
    let result = client
        .add_host(AddHostRequest {
            ip_address: "10.99.99.1".to_string(),
            hostname: "duplicate-test.local".to_string(),
            aliases: vec![],
            comment: Some("Duplicate entry".to_string()),
            tags: vec!["different-tag".to_string()],
        })
        .await;

    assert!(result.is_err(), "Second add should fail");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::AlreadyExists,
        "Expected ALREADY_EXISTS, got {:?}: {}",
        status.code(),
        status.message()
    );
    assert!(
        status.message().contains("10.99.99.1")
            || status.message().contains("duplicate-test.local"),
        "Error message should reference the duplicate: {}",
        status.message()
    );
}

/// Test that same hostname with different IP is allowed (not a duplicate)
#[tokio::test]
async fn test_same_hostname_different_ip_allowed() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add first host
    client
        .add_host(AddHostRequest {
            ip_address: "10.98.98.1".to_string(),
            hostname: "shared-hostname.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .expect("First add should succeed");

    // Same hostname, different IP - should succeed
    let result = client
        .add_host(AddHostRequest {
            ip_address: "10.98.98.2".to_string(),
            hostname: "shared-hostname.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await;

    assert!(
        result.is_ok(),
        "Same hostname with different IP should be allowed"
    );
}

/// Test that same IP with different hostname is allowed (not a duplicate)
#[tokio::test]
async fn test_same_ip_different_hostname_allowed() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add first host
    client
        .add_host(AddHostRequest {
            ip_address: "10.97.97.1".to_string(),
            hostname: "first-hostname.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .expect("First add should succeed");

    // Same IP, different hostname - should succeed (IP can have multiple aliases)
    let result = client
        .add_host(AddHostRequest {
            ip_address: "10.97.97.1".to_string(),
            hostname: "second-hostname.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await;

    assert!(
        result.is_ok(),
        "Same IP with different hostname should be allowed"
    );
}

/// Test that invalid IP address returns INVALID_ARGUMENT
///
/// Design requirement: "IP must be valid IPv4 or IPv6"
/// Error mapping: Validation failure → INVALID_ARGUMENT
#[tokio::test]
async fn test_add_host_invalid_ip_returns_invalid_argument() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Invalid IP address
    let result = client
        .add_host(AddHostRequest {
            ip_address: "not-an-ip-address".to_string(),
            hostname: "valid-hostname.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await;

    assert!(result.is_err(), "Invalid IP should be rejected");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "Expected INVALID_ARGUMENT, got {:?}: {}",
        status.code(),
        status.message()
    );
}

/// Test various invalid IP formats return INVALID_ARGUMENT
#[tokio::test]
async fn test_add_host_various_invalid_ips() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    let invalid_ips = [
        ("", "empty IP"),
        ("256.1.1.1", "IPv4 octet > 255"),
        ("1.2.3.4.5", "too many IPv4 octets"),
        ("1.2.3", "incomplete IPv4"),
        (":::", "malformed IPv6"),
        ("192.168.1.1/24", "IP with CIDR notation"),
    ];

    for (ip, description) in invalid_ips {
        let result = client
            .add_host(AddHostRequest {
                ip_address: ip.to_string(),
                hostname: format!("test-{}.local", ip.replace(['.', ':', '/'], "-")),
                aliases: vec![],
                comment: None,
                tags: vec![],
            })
            .await;

        assert!(
            result.is_err(),
            "Invalid IP '{}' ({}) should be rejected",
            ip,
            description
        );
        let status = result.unwrap_err();
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "Invalid IP '{}' ({}) should return INVALID_ARGUMENT, got {:?}",
            ip,
            description,
            status.code()
        );
    }
}

/// Test that invalid hostname returns INVALID_ARGUMENT
///
/// Design requirement: "Hostname must be valid DNS name (RFC 1123)"
/// Error mapping: Validation failure → INVALID_ARGUMENT
#[tokio::test]
async fn test_add_host_invalid_hostname_returns_invalid_argument() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Invalid hostname (starts with hyphen)
    let result = client
        .add_host(AddHostRequest {
            ip_address: "10.96.96.1".to_string(),
            hostname: "-invalid-hostname.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await;

    assert!(result.is_err(), "Invalid hostname should be rejected");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "Expected INVALID_ARGUMENT, got {:?}: {}",
        status.code(),
        status.message()
    );
}

/// Test various invalid hostname formats return INVALID_ARGUMENT
#[tokio::test]
async fn test_add_host_various_invalid_hostnames() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    let invalid_hostnames = [
        ("", "empty hostname"),
        ("-startswithhyphen.local", "starts with hyphen"),
        ("endswithhyphen-.local", "ends with hyphen"),
        ("has spaces.local", "contains space"),
        ("has..double.dots", "consecutive dots"),
        (".startswith.dot", "starts with dot"),
    ];

    for (hostname, description) in invalid_hostnames {
        let result = client
            .add_host(AddHostRequest {
                ip_address: "10.95.95.1".to_string(),
                hostname: hostname.to_string(),
                aliases: vec![],
                comment: None,
                tags: vec![],
            })
            .await;

        assert!(
            result.is_err(),
            "Invalid hostname '{}' ({}) should be rejected",
            hostname,
            description
        );
        let status = result.unwrap_err();
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "Invalid hostname '{}' ({}) should return INVALID_ARGUMENT, got {:?}",
            hostname,
            description,
            status.code()
        );
    }
}

/// Test that update with nonexistent ID returns NOT_FOUND
///
/// Note: Uses valid ULID format - invalid ID format returns INVALID_ARGUMENT
#[tokio::test]
async fn test_update_nonexistent_host_returns_not_found() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Use valid ULID format that doesn't exist in database
    // Invalid ULID format would return INVALID_ARGUMENT instead
    let nonexistent_ulid = "01JFZZZZZZZZZZZZZZZZZZZZZZ";

    let result = client
        .update_host(UpdateHostRequest {
            id: nonexistent_ulid.to_string(),
            ip_address: Some("10.94.94.1".to_string()),
            hostname: None,
            aliases: None,
            comment: None,
            tags: None,
            expected_version: None,
        })
        .await;

    assert!(result.is_err(), "Update of nonexistent host should fail");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::NotFound,
        "Expected NOT_FOUND, got {:?}: {}",
        status.code(),
        status.message()
    );
}

/// Test that delete with nonexistent ID returns NOT_FOUND
///
/// Note: Uses valid ULID format - invalid ID format returns INVALID_ARGUMENT
#[tokio::test]
async fn test_delete_nonexistent_host_returns_not_found() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Use valid ULID format that doesn't exist in database
    let nonexistent_ulid = "01JFYYYYYYYYYYYYYYYYYYYYYY";

    let result = client
        .delete_host(DeleteHostRequest {
            id: nonexistent_ulid.to_string(),
        })
        .await;

    assert!(result.is_err(), "Delete of nonexistent host should fail");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::NotFound,
        "Expected NOT_FOUND, got {:?}: {}",
        status.code(),
        status.message()
    );
}

/// Test that get with nonexistent ID returns NOT_FOUND
///
/// Note: Uses valid ULID format - invalid ID format returns INVALID_ARGUMENT
#[tokio::test]
async fn test_get_nonexistent_host_returns_not_found() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Use valid ULID format that doesn't exist in database
    // ULID is exactly 26 characters: 10 for timestamp + 16 for randomness
    let nonexistent_ulid = "01JFWWWWWWWWWWWWWWWWWWWWWW";

    let result = client
        .get_host(GetHostRequest {
            id: nonexistent_ulid.to_string(),
        })
        .await;

    assert!(result.is_err(), "Get of nonexistent host should fail");
    let status = result.unwrap_err();
    assert_eq!(
        status.code(),
        tonic::Code::NotFound,
        "Expected NOT_FOUND, got {:?}: {}",
        status.code(),
        status.message()
    );
}

/// Test that invalid ID format returns INVALID_ARGUMENT (not NOT_FOUND)
///
/// This verifies proper validation order: format validation before database lookup
#[tokio::test]
async fn test_invalid_id_format_returns_invalid_argument() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    let invalid_ids = ["not-a-ulid", "", "12345", "too-short"];

    for invalid_id in invalid_ids {
        let result = client
            .get_host(GetHostRequest {
                id: invalid_id.to_string(),
            })
            .await;

        assert!(
            result.is_err(),
            "Invalid ID '{}' should be rejected",
            invalid_id
        );
        let status = result.unwrap_err();
        assert_eq!(
            status.code(),
            tonic::Code::InvalidArgument,
            "Invalid ID format '{}' should return INVALID_ARGUMENT, got {:?}",
            invalid_id,
            status.code()
        );
    }
}

// ============================================================================
// Aliases Integration Tests
//
// These tests verify the aliases feature works end-to-end through gRPC.
// ============================================================================

#[tokio::test]
async fn test_add_host_with_aliases() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    let response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["srv".to_string(), "s.local".to_string()],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let entry = response.entry.unwrap();
    assert_eq!(entry.aliases, vec!["srv", "s.local"]);
}

#[tokio::test]
async fn test_update_host_add_aliases() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create host without aliases
    let response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec![],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let id = response.id;

    // Update with aliases using wrapper
    let response = client
        .update_host(UpdateHostRequest {
            id: id.clone(),
            ip_address: None,
            hostname: None,
            comment: None,
            expected_version: None,
            aliases: Some(AliasesUpdate {
                values: vec!["srv".to_string(), "app".to_string()],
            }),
            tags: None,
        })
        .await
        .unwrap()
        .into_inner();

    let entry = response.entry.unwrap();
    assert_eq!(entry.aliases, vec!["srv", "app"]);
}

#[tokio::test]
async fn test_update_host_clear_aliases() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create host with aliases
    let response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["old-alias".to_string()],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let id = response.id;

    // Update with empty aliases wrapper to clear
    let response = client
        .update_host(UpdateHostRequest {
            id: id.clone(),
            ip_address: None,
            hostname: None,
            comment: None,
            expected_version: None,
            aliases: Some(AliasesUpdate { values: vec![] }),
            tags: None,
        })
        .await
        .unwrap()
        .into_inner();

    let entry = response.entry.unwrap();
    assert!(entry.aliases.is_empty());
}

#[tokio::test]
async fn test_update_host_preserves_aliases() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create host with aliases
    let response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["srv".to_string(), "app".to_string()],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let id = response.id;

    // Update hostname but omit aliases field (None wrapper)
    let response = client
        .update_host(UpdateHostRequest {
            id: id.clone(),
            ip_address: None,
            hostname: Some("newserver.local".to_string()),
            comment: None,
            expected_version: None,
            aliases: None, // Preserve existing aliases
            tags: None,
        })
        .await
        .unwrap()
        .into_inner();

    let entry = response.entry.unwrap();
    assert_eq!(entry.hostname, "newserver.local");
    assert_eq!(entry.aliases, vec!["srv", "app"]); // Unchanged
}

#[tokio::test]
async fn test_search_matches_alias() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create host with aliases
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["webserver".to_string(), "app".to_string()],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Search by alias name (should match)
    let mut stream = client
        .search_hosts(SearchHostsRequest {
            query: "webserver".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut results = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        results.push(response.entry.unwrap());
    }

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].hostname, "server.local");
    assert!(results[0].aliases.contains(&"webserver".to_string()));
}

#[tokio::test]
async fn test_search_alias_case_insensitive() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create host with lowercase alias
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.20".to_string(),
            hostname: "myserver.local".to_string(),
            aliases: vec!["www".to_string(), "api".to_string()],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    // Search with uppercase should still find the host (DNS is case-insensitive)
    let mut stream = client
        .search_hosts(SearchHostsRequest {
            query: "WWW".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut results = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        results.push(response.entry.unwrap());
    }

    assert_eq!(
        results.len(),
        1,
        "Should find host when searching with uppercase alias"
    );
    assert_eq!(results[0].hostname, "myserver.local");

    // Search with mixed case should also work
    let mut stream = client
        .search_hosts(SearchHostsRequest {
            query: "Api".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    let mut results = vec![];
    while let Some(response) = stream.message().await.unwrap() {
        results.push(response.entry.unwrap());
    }

    assert_eq!(
        results.len(),
        1,
        "Should find host when searching with mixed case alias"
    );
}

#[tokio::test]
async fn test_import_export_roundtrip_with_aliases() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host with aliases
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["srv".to_string(), "app".to_string()],
            comment: Some("Test server".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap();

    // Export as hosts format
    let export_response = client
        .export_hosts(ExportHostsRequest {
            format: "hosts".to_string(),
        })
        .await
        .unwrap();

    let mut export_data = Vec::new();
    let mut stream = export_response.into_inner();
    while let Some(chunk) = stream.message().await.unwrap() {
        export_data.extend_from_slice(&chunk.chunk);
    }

    // Delete the host
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let mut stream = list_response.into_inner();
    let first_entry = stream.message().await.unwrap().unwrap();
    let host_id = first_entry.entry.as_ref().unwrap().id.clone();

    client
        .delete_host(DeleteHostRequest { id: host_id })
        .await
        .unwrap();

    // Import the exported data
    let requests = vec![ImportHostsRequest {
        chunk: export_data,
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: Some("skip".to_string()),
        force: Some(false),
    }];

    let response = client
        .import_hosts(tokio_stream::iter(requests))
        .await
        .unwrap();

    let mut stream = response.into_inner();
    let progress = stream.message().await.unwrap().unwrap();

    assert_eq!(progress.created, 1);

    // Verify aliases are preserved
    let list_response = client
        .list_hosts(ListHostsRequest {
            filter: None,
            limit: None,
            offset: None,
        })
        .await
        .unwrap();

    let mut stream = list_response.into_inner();
    let restored_entry = stream.message().await.unwrap().unwrap();
    let restored = restored_entry.entry.unwrap();

    assert_eq!(restored.hostname, "server.local");
    // Aliases may be sorted during export/import
    let mut expected_aliases = vec!["srv", "app"];
    let mut actual_aliases = restored.aliases.clone();
    expected_aliases.sort();
    actual_aliases.sort();
    assert_eq!(actual_aliases, expected_aliases);
}

#[tokio::test]
async fn test_add_host_alias_matches_own_hostname_rejected() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Try to add host where an alias matches the canonical hostname
    // This should fail validation (alias cannot equal its own hostname)
    let result = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["srv".to_string(), "server.local".to_string()], // Invalid: matches hostname
            comment: None,
            tags: vec![],
        })
        .await;

    assert!(result.is_err(), "Should reject alias matching own hostname");
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("alias") || status.message().contains("hostname"),
        "Error should mention alias/hostname conflict: {}",
        status.message()
    );
}

#[tokio::test]
async fn test_add_host_alias_matches_own_hostname_case_insensitive() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Case-insensitive check: "SERVER.LOCAL" should match "server.local"
    let result = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["SERVER.LOCAL".to_string()], // Invalid: matches hostname (case-insensitive)
            comment: None,
            tags: vec![],
        })
        .await;

    assert!(
        result.is_err(),
        "Should reject alias matching own hostname (case-insensitive)"
    );
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_update_host_alias_matches_own_hostname_rejected() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Create host first
    let response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["srv".to_string()],
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap()
        .into_inner();

    let id = response.entry.unwrap().id;

    // Try to update with alias that matches hostname
    let result = client
        .update_host(UpdateHostRequest {
            id,
            ip_address: None,
            hostname: None,
            comment: None,
            expected_version: None,
            aliases: Some(AliasesUpdate {
                values: vec!["server.local".to_string()], // Invalid
            }),
            tags: None,
        })
        .await;

    assert!(
        result.is_err(),
        "Should reject alias matching own hostname on update"
    );
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn test_alias_duplicate_within_entry_rejected() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Try to add host with duplicate aliases
    let result = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["srv".to_string(), "srv".to_string()], // Duplicate alias
            comment: None,
            tags: vec![],
        })
        .await;

    assert!(result.is_err(), "Should reject duplicate aliases");
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(
        status.message().contains("duplicate") || status.message().contains("Duplicate"),
        "Error should mention duplicate: {}",
        status.message()
    );
}

#[tokio::test]
async fn test_alias_duplicate_case_insensitive_rejected() {
    let (addr, _temp_dir) = start_test_server().await;
    let mut client = create_client(addr).await;

    // Case-insensitive duplicate: "srv" == "SRV"
    let result = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            aliases: vec!["srv".to_string(), "SRV".to_string()], // Duplicate (case-insensitive)
            comment: None,
            tags: vec![],
        })
        .await;

    assert!(
        result.is_err(),
        "Should reject duplicate aliases (case-insensitive)"
    );
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
