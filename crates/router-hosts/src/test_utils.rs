//! Test utilities for router-hosts tests.
//!
//! Provides common setup functions to reduce duplication across test modules.

use std::path::PathBuf;
use std::sync::Arc;

use router_hosts_storage::backends::sqlite::SqliteStorage;
use router_hosts_storage::Storage;

use crate::server::acme::AcmeConfig;
use crate::server::config::{
    Config, DatabaseConfig, HooksConfig, RetentionConfig, ServerConfig, TlsConfig,
};
use crate::server::hooks::HookExecutor;
use crate::server::hosts_file::HostsFileGenerator;

/// Creates an in-memory SQLite storage for testing.
///
/// The storage is automatically initialized and ready for use.
pub async fn create_test_storage() -> Arc<dyn Storage> {
    let storage = SqliteStorage::new(":memory:")
        .await
        .expect("failed to create in-memory storage");
    storage
        .initialize()
        .await
        .expect("failed to initialize storage");
    Arc::new(storage)
}

/// Creates a default test configuration.
///
/// Uses placeholder paths for TLS certificates since tests typically
/// don't perform actual TLS operations.
pub fn create_test_config() -> Config {
    Config {
        server: ServerConfig {
            bind_address: "127.0.0.1:50051".to_string(),
            hosts_file_path: "/tmp/test_hosts".to_string(),
        },
        database: DatabaseConfig {
            path: None,
            url: Some("sqlite://:memory:".to_string()),
        },
        tls: TlsConfig {
            cert_path: PathBuf::from("/tmp/cert.pem"),
            key_path: PathBuf::from("/tmp/key.pem"),
            ca_cert_path: PathBuf::from("/tmp/ca.pem"),
        },
        retention: RetentionConfig {
            max_snapshots: 50,
            max_age_days: 30,
        },
        hooks: HooksConfig::default(),
        acme: AcmeConfig::default(),
        metrics: None,
    }
}

/// Creates a test configuration with a custom hosts file path.
pub fn create_test_config_with_hosts_path(hosts_path: &str) -> Config {
    let mut config = create_test_config();
    config.server.hosts_file_path = hosts_path.to_string();
    config
}

/// Creates a no-op hook executor for testing.
pub fn create_test_hooks() -> Arc<HookExecutor> {
    Arc::new(HookExecutor::new(vec![], vec![], 30))
}

/// Creates a hosts file generator with a temp path.
pub fn create_test_hosts_file(path: PathBuf) -> Arc<HostsFileGenerator> {
    Arc::new(HostsFileGenerator::new(path))
}
