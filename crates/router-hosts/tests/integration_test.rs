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
//! Manual testing with real certificates should be performed before release.
//!
//! TODO: Add mTLS integration tests with runtime certificate generation using rcgen
//! or similar library for comprehensive E2E security testing.

use router_hosts::server::commands::CommandHandler;
use router_hosts::server::db::Database;
use router_hosts::server::hooks::HookExecutor;
use router_hosts::server::hosts_file::HostsFileGenerator;
use router_hosts::server::service::HostsServiceImpl;
use router_hosts::server::write_queue::WriteQueue;
use router_hosts_common::proto::hosts_service_client::HostsServiceClient;
use router_hosts_common::proto::hosts_service_server::HostsServiceServer;
use router_hosts_common::proto::{
    AddHostRequest, DeleteHostRequest, ExportHostsRequest, GetHostRequest, ImportHostsRequest,
    ListHostsRequest, SearchHostsRequest, UpdateHostRequest,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tonic::transport::{Channel, Server};

/// Start a test server on a random port and return the address
async fn start_test_server() -> SocketAddr {
    // Bind to port 0 to let the OS assign an available port
    // This prevents port conflicts when tests run in parallel
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release the port for the server to use

    // Create in-memory database
    let db = Arc::new(Database::in_memory().unwrap());

    // Create hooks (no-op for tests)
    let hooks = Arc::new(HookExecutor::new(vec![], vec![], 30));

    // Create hosts file generator with temp path.
    //
    // Note on Box::leak: The temp directory must outlive the spawned server task,
    // but we can't move an Arc<TempDir> into the spawned task without complex
    // lifetime gymnastics. Since tests are short-lived and the OS cleans up /tmp
    // on reboot, leaking the TempDir handle is acceptable here. The actual temp
    // directory still gets cleaned up when the test process exits.
    let temp_dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let hosts_path = temp_dir.path().join("hosts");
    let hosts_file = Arc::new(HostsFileGenerator::new(hosts_path));

    // Create command handler
    let commands = Arc::new(CommandHandler::new(
        Arc::clone(&db),
        Arc::clone(&hosts_file),
        Arc::clone(&hooks),
    ));

    // Create write queue for serialized mutation operations
    let write_queue = WriteQueue::new(Arc::clone(&commands));

    // Create service
    let service = HostsServiceImpl::new(write_queue, Arc::clone(&commands), Arc::clone(&db));

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
            return addr;
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    let add_response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
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
    let addr = start_test_server().await;
    eprintln!("Test server started successfully on {}", addr);
}

#[tokio::test]
async fn test_update_host() {
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    let add_response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.20".to_string(),
            hostname: "old.local".to_string(),
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
            comment: Some("Updated".to_string()),
            tags: vec!["updated".to_string()],
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    let add_response = client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.30".to_string(),
            hostname: "delete.local".to_string(),
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add multiple hosts
    for i in 1..=3 {
        client
            .add_host(AddHostRequest {
                ip_address: format!("192.168.1.{}", 40 + i),
                hostname: format!("host{}.local", i),
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add hosts with different names
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.50".to_string(),
            hostname: "webserver.local".to_string(),
            comment: None,
            tags: vec![],
        })
        .await
        .unwrap();

    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.51".to_string(),
            hostname: "database.local".to_string(),
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add some hosts
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
            comment: Some("Test server".to_string()),
            tags: vec!["test".to_string()],
        })
        .await
        .unwrap();

    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.20".to_string(),
            hostname: "nas.local".to_string(),
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
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
    let addr = start_test_server().await;
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host with a comment containing a comma
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "server.local".to_string(),
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
    assert_eq!(header, "ip_address,hostname,comment,tags\n");

    // Second chunk should have properly escaped comment
    let entry = String::from_utf8(chunks[1].clone()).unwrap();
    assert!(entry.contains("\"Hello, world\"")); // Comma should be quoted
    assert!(entry.contains("tag1;tag2"));
}

#[tokio::test]
async fn test_import_hosts_via_grpc() {
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Import some hosts
    let import_data =
        b"192.168.1.10\tserver1.local\n192.168.1.11\tserver2.local\t# Second server\n";

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("hosts".to_string()),
        conflict_mode: Some("skip".to_string()),
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Add a host
    client
        .add_host(AddHostRequest {
            ip_address: "192.168.1.10".to_string(),
            hostname: "roundtrip.local".to_string(),
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Import hosts using JSON Lines format
    let import_data = br#"{"ip_address": "10.0.0.1", "hostname": "json1.local", "comment": "JSON import 1", "tags": ["test", "json"]}
{"ip_address": "10.0.0.2", "hostname": "json2.local"}"#;

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("json".to_string()),
        conflict_mode: Some("skip".to_string()),
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
    let addr = start_test_server().await;
    let mut client = create_client(addr).await;

    // Import hosts using CSV format
    let import_data = b"ip_address,hostname,comment,tags
10.1.0.1,csv1.local,CSV import 1,test;csv
10.1.0.2,csv2.local,,";

    let requests = vec![ImportHostsRequest {
        chunk: import_data.to_vec(),
        last_chunk: true,
        format: Some("csv".to_string()),
        conflict_mode: Some("skip".to_string()),
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
