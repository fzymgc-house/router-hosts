//! Authentication failure scenarios - security boundary testing

use predicates::prelude::*;
use router_hosts_e2e::certs::TestCertificates;
use router_hosts_e2e::cli::TestCli;
use router_hosts_e2e::container::TestServer;

#[tokio::test]
async fn test_wrong_ca_rejected() {
    let server = TestServer::start().await;

    // Generate a completely different set of certs (different CA)
    let wrong_certs = TestCertificates::generate();
    let wrong_certs_dir = server.temp_dir.path().join("wrong_certs");
    std::fs::create_dir_all(&wrong_certs_dir).unwrap();
    let wrong_paths = wrong_certs.write_to_dir(&wrong_certs_dir).unwrap();

    // Use server's CA for trust but wrong client cert
    let mut mixed_paths = wrong_paths.clone();
    mixed_paths.ca_cert = server.cert_paths.ca_cert.clone();

    let cli = TestCli::new(server.address(), mixed_paths, server.temp_dir.path());

    // Should fail with certificate verification error - client cert not signed by server's CA
    cli.list_hosts()
        .assert()
        .failure()
        .stderr(predicate::str::contains("certificate").or(predicate::str::contains("tls")));

    server.stop().await;
}

#[tokio::test]
async fn test_self_signed_client_rejected() {
    let server = TestServer::start().await;

    // Generate self-signed client cert (not signed by any CA)
    let self_signed = TestCertificates::generate();
    let self_signed_dir = server.temp_dir.path().join("self_signed");
    std::fs::create_dir_all(&self_signed_dir).unwrap();
    let self_signed_paths = self_signed.write_to_dir(&self_signed_dir).unwrap();

    // Use server's CA but self-signed client cert
    let mut mixed_paths = self_signed_paths.clone();
    mixed_paths.ca_cert = server.cert_paths.ca_cert.clone();

    let cli = TestCli::new(server.address(), mixed_paths, server.temp_dir.path());

    // Should fail with certificate verification error
    cli.list_hosts()
        .assert()
        .failure()
        .stderr(predicate::str::contains("certificate").or(predicate::str::contains("tls")));

    server.stop().await;
}
