//! Docker container management for E2E tests
//!
//! Uses testcontainers to manage the router-hosts server lifecycle.

use crate::certs::{CertPaths, TestCertificates};
use testcontainers::core::{ContainerPort, Mount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

/// Configuration for the test server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub hosts_file_path: String,
    pub database_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub tls_ca_path: String,
}

impl ServerConfig {
    /// Create config for container paths
    pub fn for_container(port: u16) -> Self {
        Self {
            bind_address: format!("0.0.0.0:{}", port),
            hosts_file_path: "/data/hosts".to_string(),
            database_path: "/data/router-hosts.db".to_string(),
            tls_cert_path: "/certs/server.pem".to_string(),
            tls_key_path: "/certs/server-key.pem".to_string(),
            tls_ca_path: "/certs/ca.pem".to_string(),
        }
    }

    /// Generate TOML config file content
    pub fn to_toml(&self) -> String {
        format!(
            r#"[server]
bind_address = "{}"
hosts_file_path = "{}"

[database]
path = "{}"

[tls]
cert_path = "{}"
key_path = "{}"
ca_cert_path = "{}"

[retention]
max_snapshots = 10
max_age_days = 7

[hooks]
on_success = []
on_failure = []
"#,
            self.bind_address,
            self.hosts_file_path,
            self.database_path,
            self.tls_cert_path,
            self.tls_key_path,
            self.tls_ca_path
        )
    }
}

/// A running test server container
pub struct TestServer {
    container: testcontainers::ContainerAsync<GenericImage>,
    pub port: u16,
    pub cert_paths: CertPaths,
    pub temp_dir: tempfile::TempDir,
}

impl TestServer {
    /// Start a new test server with fresh certificates
    pub async fn start() -> Self {
        Self::start_with_certs(TestCertificates::generate()).await
    }

    /// Start a test server with specific certificates
    pub async fn start_with_certs(certs: TestCertificates) -> Self {
        let image_name = crate::server_image();
        let (image, tag) = image_name
            .rsplit_once(':')
            .unwrap_or((&image_name, "latest"));

        // Create temp directory for certs and data
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let certs_dir = temp_dir.path().join("certs");
        let data_dir = temp_dir.path().join("data");
        std::fs::create_dir_all(&certs_dir).expect("Failed to create certs dir");
        std::fs::create_dir_all(&data_dir).expect("Failed to create data dir");

        // Write certificates
        let cert_paths = certs
            .write_to_dir(&certs_dir)
            .expect("Failed to write certs");

        // Write server config
        let config = ServerConfig::for_container(50051);
        let config_path = certs_dir.join("server.toml");
        std::fs::write(&config_path, config.to_toml()).expect("Failed to write config");

        // Create and start container
        // Note: tracing-subscriber outputs to stdout by default
        // RUST_LOG is required for tracing to output anything
        // API ordering: GenericImage methods first (with_wait_for, with_exposed_port),
        // then ContainerRequest methods (with_env_var, with_mount, with_cmd)
        let image = GenericImage::new(image, tag)
            .with_exposed_port(ContainerPort::Tcp(50051))
            .with_wait_for(WaitFor::message_on_stdout("Starting gRPC server on"));

        let container = image
            .with_env_var("RUST_LOG", "info")
            .with_mount(Mount::bind_mount(
                certs_dir.to_string_lossy().to_string(),
                "/certs",
            ))
            .with_mount(Mount::bind_mount(
                data_dir.to_string_lossy().to_string(),
                "/data",
            ))
            .with_cmd(vec!["server", "--config", "/certs/server.toml"])
            .start()
            .await
            .expect("Failed to start container");

        let port = container
            .get_host_port_ipv4(50051)
            .await
            .expect("Failed to get port");

        Self {
            container,
            port,
            cert_paths,
            temp_dir,
        }
    }

    /// Get the server address for client connections (host:port format)
    pub fn address(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Stop the container
    pub async fn stop(self) {
        self.container
            .stop()
            .await
            .expect("Failed to stop container");
    }
}
