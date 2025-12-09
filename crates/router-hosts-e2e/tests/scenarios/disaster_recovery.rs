//! Disaster recovery scenarios - backup and restore workflows

use predicates::prelude::*;
use router_hosts_e2e::cli::TestCli;
use router_hosts_e2e::container::TestServer;

/// Test snapshot creation and rollback to restore state
#[tokio::test]
async fn test_snapshot_and_rollback() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Create initial state
    cli.add_host("192.168.100.1", "original.local")
        .comment("Original host")
        .build()
        .assert()
        .success();

    // Create snapshot with JSON output for full ID extraction
    let snapshot_output = cli
        .create_snapshot_json()
        .output()
        .expect("Failed to create snapshot");
    assert!(snapshot_output.status.success());

    // Extract snapshot ID from JSON output
    let stdout = String::from_utf8_lossy(&snapshot_output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse JSON");
    let snapshot_id = json
        .get("snapshot_id")
        .and_then(|v| v.as_str())
        .expect("Failed to extract snapshot_id from JSON");

    // Make breaking changes - get full host ID via JSON to avoid truncation
    let mut list_cmd = cli.list_hosts();
    list_cmd.args(["--format", "json"]);
    let list_output = list_cmd.output().expect("Failed to list");
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    let hosts: Vec<serde_json::Value> =
        serde_json::from_str(&list_stdout).expect("Failed to parse JSON");
    let host_id = hosts
        .iter()
        .find(|h| h.get("hostname").and_then(|v| v.as_str()) == Some("original.local"))
        .and_then(|h| h.get("id"))
        .and_then(|v| v.as_str())
        .expect("Failed to find host ID");

    cli.delete_host(host_id).assert().success();

    cli.add_host("192.168.100.99", "wrong.local")
        .comment("Wrong host")
        .build()
        .assert()
        .success();

    // Verify broken state
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("wrong.local"))
        .stdout(predicate::str::contains("original.local").not());

    // Rollback
    cli.rollback(snapshot_id).assert().success();

    // Verify restored state
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("original.local"))
        .stdout(predicate::str::contains("wrong.local").not());

    server.stop().await;
}

/// Test that rollback creates automatic backup snapshot
#[tokio::test]
async fn test_rollback_creates_backup() {
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // Create state
    cli.add_host("10.10.10.1", "backup-test.local")
        .build()
        .assert()
        .success();

    // Create snapshot with JSON output for full ID extraction
    let snapshot_output = cli
        .create_snapshot_json()
        .output()
        .expect("Failed to create snapshot");
    let stdout = String::from_utf8_lossy(&snapshot_output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Failed to parse JSON");
    let snapshot_id = json
        .get("snapshot_id")
        .and_then(|v| v.as_str())
        .expect("Failed to extract snapshot_id from JSON");

    // Modify
    cli.add_host("10.10.10.2", "extra.local")
        .build()
        .assert()
        .success();

    // Rollback
    cli.rollback(snapshot_id).assert().success();

    // Verify backup snapshot was created
    cli.list_snapshots()
        .assert()
        .success()
        .stdout(predicate::str::contains("pre-rollback"));

    server.stop().await;
}
