//! Daily operations scenarios - normal usage patterns

use predicates::prelude::*;
use router_hosts_e2e::cli::{OutputFormat, TestCli};
use router_hosts_e2e::container::TestServer;
use std::io::Write;

/// Test CRUD workflow with host operations
#[tokio::test]
async fn test_crud_workflow() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Add host with JSON output for full ID extraction
    let output = cli
        .add_host("10.0.0.1", "server1.local")
        .comment("Test server")
        .tag("test")
        .format(OutputFormat::Json)
        .build()
        .output()
        .expect("Failed to run add");
    assert!(output.status.success());

    // Extract host ID from JSON output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse JSON");
    let id = json
        .get("id")
        .and_then(|v| v.as_str())
        .expect("Failed to extract ID from JSON");

    // List and verify
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.1"))
        .stdout(predicate::str::contains("server1.local"));

    // Update IP
    cli.update_host(id)
        .ip("10.0.0.2")
        .build()
        .assert()
        .success();

    // Get and verify update
    cli.get_host(id)
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.2"));

    // Delete
    cli.delete_host(id).assert().success();

    // List and verify gone
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("10.0.0.1").not());

    server.stop().await;
}

/// Test import/export roundtrip
/// Verifies that hosts can be imported from a file and exported to different formats
#[tokio::test]
async fn test_import_export_roundtrip() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Create hosts file to import with aliases
    let import_file = server.temp_dir.path().join("import.hosts");
    let mut f = std::fs::File::create(&import_file).unwrap();
    writeln!(f, "# Test hosts file").unwrap();
    writeln!(
        f,
        "192.168.1.10    server1.test.local srv1 s1  # Primary server"
    )
    .unwrap();
    writeln!(f, "192.168.1.20    server2.test.local srv2     # Database").unwrap();

    // Import (hosts format is default)
    cli.import(&import_file).build().assert().success();

    // Verify imported including aliases
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.10"))
        .stdout(predicate::str::contains("server2.test.local"))
        .stdout(predicate::str::contains("srv1"))
        .stdout(predicate::str::contains("s1"));

    // Export to JSON
    let export_output = cli.export("json").output().expect("Failed to export");
    assert!(export_output.status.success());
    let json = String::from_utf8_lossy(&export_output.stdout);
    assert!(json.contains("192.168.1.10"));
    assert!(json.contains("server1.test.local"));

    server.stop().await;
}

/// Test CRUD workflow with aliases
#[tokio::test]
async fn test_crud_with_aliases() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Add host with aliases
    // Note: Use hostname that doesn't contain alias names to avoid substring match issues
    let output = cli
        .add_host("10.0.0.10", "webserver.local")
        .alias("www")
        .alias("srv")
        .format(OutputFormat::Json)
        .build()
        .output()
        .expect("Failed to run add");
    assert!(output.status.success());

    // Extract ID
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Parse JSON");
    let id = json.get("id").and_then(|v| v.as_str()).unwrap();

    // Verify aliases in list output
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("www"))
        .stdout(predicate::str::contains("srv"));

    // Update aliases
    cli.update_host(id)
        .aliases(vec!["primary", "api"])
        .build()
        .assert()
        .success();

    // Verify updated aliases
    cli.get_host(id)
        .assert()
        .success()
        .stdout(predicate::str::contains("primary"))
        .stdout(predicate::str::contains("api"));

    // Clear aliases
    cli.update_host(id)
        .clear_aliases()
        .build()
        .assert()
        .success();

    // Verify aliases cleared (should not contain old aliases)
    cli.get_host(id)
        .assert()
        .success()
        .stdout(predicate::str::contains("www").not())
        .stdout(predicate::str::contains("primary").not());

    server.stop().await;
}

/// Test search matches aliases
#[tokio::test]
async fn test_search_by_alias() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Add host with alias
    cli.add_host("10.0.0.1", "webserver.local")
        .alias("www")
        .alias("http")
        .build()
        .assert()
        .success();

    // Search by alias should find the host
    cli.search("www")
        .assert()
        .success()
        .stdout(predicate::str::contains("webserver.local"));

    cli.search("http")
        .assert()
        .success()
        .stdout(predicate::str::contains("webserver.local"));

    server.stop().await;
}

#[tokio::test]
async fn test_search_and_filter() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Add hosts with different tags
    cli.add_host("10.1.0.1", "web1.prod.local")
        .tag("production")
        .tag("web")
        .build()
        .assert()
        .success();

    cli.add_host("10.1.0.2", "db1.prod.local")
        .tag("production")
        .tag("database")
        .build()
        .assert()
        .success();

    cli.add_host("10.2.0.1", "web1.dev.local")
        .tag("development")
        .tag("web")
        .build()
        .assert()
        .success();

    // Search by hostname pattern
    cli.search("prod")
        .assert()
        .success()
        .stdout(predicate::str::contains("web1.prod.local"))
        .stdout(predicate::str::contains("db1.prod.local"))
        .stdout(predicate::str::contains("web1.dev.local").not());

    // Search by tag
    cli.search("web")
        .assert()
        .success()
        .stdout(predicate::str::contains("web1.prod.local"))
        .stdout(predicate::str::contains("web1.dev.local"));

    server.stop().await;
}
