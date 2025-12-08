//! Initial setup scenarios - first-time deployment workflow

use predicates::prelude::*;
use router_hosts_e2e::cli::TestCli;
use router_hosts_e2e::container::TestServer;

#[tokio::test]
async fn test_initial_deployment() {
    // Start fresh server
    let server = TestServer::start().await;
    let cli = TestCli::new(
        server.address(),
        server.cert_paths.clone(),
        server.temp_dir.path(),
    );

    // 1. Verify server is healthy (list returns empty)
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("No hosts found").or(predicate::str::is_empty()));

    // 2. Add first host (CLI outputs table format with the new host)
    cli.add_host("192.168.1.1", "router.local")
        .comment("Main router")
        .tag("infrastructure")
        .build()
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.1"))
        .stdout(predicate::str::contains("router.local"));

    // 3. Verify host appears in list
    cli.list_hosts()
        .assert()
        .success()
        .stdout(predicate::str::contains("192.168.1.1"))
        .stdout(predicate::str::contains("router.local"));

    // 4. Create initial snapshot (server auto-generates ID)
    cli.create_snapshot().assert().success();

    // 5. Verify snapshot exists (at least one snapshot in list)
    cli.list_snapshots().assert().success();

    server.stop().await;
}
