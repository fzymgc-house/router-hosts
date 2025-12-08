//! Disaster recovery scenarios - backup and restore workflows

use predicates::prelude::*;
use router_hosts_e2e::cli::TestCli;
use router_hosts_e2e::container::TestServer;

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

    // Create snapshot
    let snapshot_output = cli
        .create_snapshot("before-disaster")
        .output()
        .expect("Failed to create snapshot");
    assert!(snapshot_output.status.success());

    // Extract snapshot ID
    let stdout = String::from_utf8_lossy(&snapshot_output.stdout);
    let snapshot_id = stdout
        .lines()
        .find(|l| l.contains("ID:") || l.contains("snapshot_id"))
        .and_then(|l| l.split_whitespace().last())
        .expect("Failed to extract snapshot ID");

    // Make breaking changes
    let list_output = cli.list_hosts().output().expect("Failed to list");
    let list_stdout = String::from_utf8_lossy(&list_output.stdout);
    let host_id = list_stdout
        .lines()
        .find(|l| l.contains("original.local"))
        .and_then(|l| l.split_whitespace().next())
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

    // Create snapshot
    let snapshot_output = cli
        .create_snapshot("checkpoint")
        .output()
        .expect("Failed to create snapshot");
    let stdout = String::from_utf8_lossy(&snapshot_output.stdout);
    let snapshot_id = stdout
        .lines()
        .find(|l| l.contains("ID:") || l.contains("snapshot_id"))
        .and_then(|l| l.split_whitespace().last())
        .expect("Failed to extract snapshot ID");

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
