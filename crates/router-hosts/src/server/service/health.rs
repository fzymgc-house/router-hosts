//! Health check RPC handlers
//!
//! Implements Liveness, Readiness, and Health RPCs for monitoring and probes.

use super::HostsServiceImpl;
use router_hosts_common::proto::{
    AcmeHealth, DatabaseHealth, HealthRequest, HealthResponse, HooksHealth, LivenessRequest,
    LivenessResponse, ReadinessRequest, ReadinessResponse, ServerInfo,
};
use tonic::{Request, Response, Status};
use tracing::debug;

impl HostsServiceImpl {
    /// Handle liveness probe
    ///
    /// Returns immediately with `alive: true`. No I/O operations.
    /// This should always succeed if the gRPC server is running.
    pub(crate) async fn handle_liveness(
        &self,
        _request: Request<LivenessRequest>,
    ) -> Result<Response<LivenessResponse>, Status> {
        debug!("Liveness probe: OK");
        Ok(Response::new(LivenessResponse { alive: true }))
    }

    /// Handle readiness probe
    ///
    /// Checks database connectivity. Returns `ready: false` with reason on failure.
    pub(crate) async fn handle_readiness(
        &self,
        _request: Request<ReadinessRequest>,
    ) -> Result<Response<ReadinessResponse>, Status> {
        match self.storage.health_check().await {
            Ok(()) => {
                debug!("Readiness probe: OK");
                Ok(Response::new(ReadinessResponse {
                    ready: true,
                    reason: String::new(),
                }))
            }
            Err(e) => {
                let reason = format!("Database health check failed: {}", e);
                debug!(reason = %reason, "Readiness probe: NOT READY");
                Ok(Response::new(ReadinessResponse {
                    ready: false,
                    reason,
                }))
            }
        }
    }

    /// Handle detailed health check
    ///
    /// Returns comprehensive status of all server components:
    /// - Server info (version, uptime, build info)
    /// - Database health (connected, backend type, latency)
    /// - ACME certificate status
    /// - Hooks configuration
    pub(crate) async fn handle_health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        // Gather database health with latency measurement
        let db_start = std::time::Instant::now();
        let (db_connected, db_error) = match self.storage.health_check().await {
            Ok(()) => (true, String::new()),
            Err(e) => (false, e.to_string()),
        };
        let db_latency_ms = db_start.elapsed().as_millis() as i64;

        let database = Some(DatabaseHealth {
            connected: db_connected,
            backend: self.storage.backend_name().to_string(),
            latency_ms: db_latency_ms,
            error: db_error,
        });

        // Gather ACME health
        let acme = Some(self.gather_acme_health().await);

        // Gather hooks health
        let hooks = Some(HooksHealth {
            configured_count: self.hooks.hook_count() as i32,
            hook_names: self.hooks.hook_names(),
        });

        // Gather server info
        let uptime_seconds = self.start_time.elapsed().as_secs() as i64;
        let server = Some(ServerInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds,
            build_info: format!(
                "v{} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_SHA").unwrap_or("unknown")
            ),
        });

        // Overall health: healthy if database is connected
        let healthy = db_connected;

        debug!(
            healthy = healthy,
            uptime_seconds = uptime_seconds,
            db_connected = db_connected,
            db_latency_ms = db_latency_ms,
            acme_enabled = self.acme_enabled,
            hook_count = self.hooks.hook_count(),
            "Health check complete"
        );

        Ok(Response::new(HealthResponse {
            healthy,
            server,
            database,
            acme,
            hooks,
        }))
    }

    /// Gather ACME certificate health status
    async fn gather_acme_health(&self) -> AcmeHealth {
        if !self.acme_enabled {
            return AcmeHealth {
                enabled: false,
                status: "disabled".to_string(),
                expires_at: 0,
                error: String::new(),
            };
        }

        // Try to read certificate expiry
        let cert_path = match &self.tls_cert_path {
            Some(path) => path,
            None => {
                return AcmeHealth {
                    enabled: true,
                    status: "unknown".to_string(),
                    expires_at: 0,
                    error: "no certificate path configured".to_string(),
                };
            }
        };

        match Self::read_cert_expiry(cert_path).await {
            Ok((status, expires_at)) => AcmeHealth {
                enabled: true,
                status,
                expires_at,
                error: String::new(),
            },
            Err(e) => AcmeHealth {
                enabled: true,
                status: "unknown".to_string(),
                expires_at: 0,
                error: e,
            },
        }
    }

    /// Read certificate expiry from file
    ///
    /// Returns (status, expires_at_unix_timestamp)
    /// Status is one of: "valid", "renewing", "expired"
    async fn read_cert_expiry(cert_path: &std::path::Path) -> Result<(String, i64), String> {
        let cert_pem = tokio::fs::read_to_string(cert_path)
            .await
            .map_err(|e| format!("failed to read certificate: {}", e))?;

        let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
            .map_err(|e| format!("failed to parse PEM: {:?}", e))?;

        let cert = pem
            .parse_x509()
            .map_err(|e| format!("failed to parse X509: {:?}", e))?;

        let not_after = cert.validity().not_after;
        let expires_at = not_after.timestamp();
        let now_ts = chrono::Utc::now().timestamp();
        let days_until_expiry = (expires_at - now_ts) / (24 * 60 * 60);

        let status = if days_until_expiry < 0 {
            "expired"
        } else if days_until_expiry <= 30 {
            // Within renewal window
            "renewing"
        } else {
            "valid"
        };

        Ok((status.to_string(), expires_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::commands::CommandHandler;
    use crate::server::hooks::HookExecutor;
    use crate::server::write_queue::WriteQueue;
    use chrono::{DateTime, Utc};
    use router_hosts_storage::{
        EventEnvelope, EventStore, HostEntry, HostFilter, HostProjection, Snapshot, SnapshotId,
        SnapshotMetadata, SnapshotStore, Storage, StorageError,
    };
    use std::sync::Arc;
    use ulid::Ulid;

    /// Mock storage for testing health checks
    ///
    /// Implements all required traits with minimal functionality.
    /// Only health_check and backend_name are actually used in tests.
    struct MockStorage {
        healthy: bool,
    }

    #[async_trait::async_trait]
    impl EventStore for MockStorage {
        async fn append_event(
            &self,
            _aggregate_id: Ulid,
            _event: EventEnvelope,
            _expected_version: Option<String>,
        ) -> Result<(), StorageError> {
            unimplemented!("MockStorage: append_event not needed for health tests")
        }

        async fn append_events(
            &self,
            _aggregate_id: Ulid,
            _events: Vec<EventEnvelope>,
            _expected_version: Option<String>,
        ) -> Result<(), StorageError> {
            unimplemented!("MockStorage: append_events not needed for health tests")
        }

        async fn load_events(
            &self,
            _aggregate_id: Ulid,
        ) -> Result<Vec<EventEnvelope>, StorageError> {
            unimplemented!("MockStorage: load_events not needed for health tests")
        }

        async fn get_current_version(
            &self,
            _aggregate_id: Ulid,
        ) -> Result<Option<String>, StorageError> {
            unimplemented!("MockStorage: get_current_version not needed for health tests")
        }

        async fn count_events(&self, _aggregate_id: Ulid) -> Result<i64, StorageError> {
            unimplemented!("MockStorage: count_events not needed for health tests")
        }
    }

    #[async_trait::async_trait]
    impl SnapshotStore for MockStorage {
        async fn save_snapshot(&self, _snapshot: Snapshot) -> Result<(), StorageError> {
            unimplemented!("MockStorage: save_snapshot not needed for health tests")
        }

        async fn get_snapshot(&self, _snapshot_id: &SnapshotId) -> Result<Snapshot, StorageError> {
            unimplemented!("MockStorage: get_snapshot not needed for health tests")
        }

        async fn list_snapshots(
            &self,
            _limit: Option<u32>,
            _offset: Option<u32>,
        ) -> Result<Vec<SnapshotMetadata>, StorageError> {
            unimplemented!("MockStorage: list_snapshots not needed for health tests")
        }

        async fn delete_snapshot(&self, _snapshot_id: &SnapshotId) -> Result<(), StorageError> {
            unimplemented!("MockStorage: delete_snapshot not needed for health tests")
        }

        async fn apply_retention_policy(
            &self,
            _max_count: Option<usize>,
            _max_age_days: Option<u32>,
        ) -> Result<usize, StorageError> {
            unimplemented!("MockStorage: apply_retention_policy not needed for health tests")
        }
    }

    #[async_trait::async_trait]
    impl HostProjection for MockStorage {
        async fn list_all(&self) -> Result<Vec<HostEntry>, StorageError> {
            // Return empty list for tests that need it
            Ok(vec![])
        }

        async fn get_by_id(&self, _id: Ulid) -> Result<HostEntry, StorageError> {
            unimplemented!("MockStorage: get_by_id not needed for health tests")
        }

        async fn find_by_ip_and_hostname(
            &self,
            _ip_address: &str,
            _hostname: &str,
        ) -> Result<Option<HostEntry>, StorageError> {
            unimplemented!("MockStorage: find_by_ip_and_hostname not needed for health tests")
        }

        async fn search(&self, _filter: HostFilter) -> Result<Vec<HostEntry>, StorageError> {
            unimplemented!("MockStorage: search not needed for health tests")
        }

        async fn get_at_time(
            &self,
            _at_time: DateTime<Utc>,
        ) -> Result<Vec<HostEntry>, StorageError> {
            unimplemented!("MockStorage: get_at_time not needed for health tests")
        }
    }

    #[async_trait::async_trait]
    impl Storage for MockStorage {
        fn backend_name(&self) -> &'static str {
            "mock"
        }

        async fn initialize(&self) -> Result<(), StorageError> {
            Ok(())
        }

        async fn health_check(&self) -> Result<(), StorageError> {
            if self.healthy {
                Ok(())
            } else {
                Err(StorageError::connection(
                    "mock connection failed",
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "mock failure"),
                ))
            }
        }

        async fn close(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    /// Create a minimal HostsServiceImpl for testing health endpoints
    ///
    /// Uses the simpler approach of constructing the service directly
    /// rather than going through full server initialization.
    fn create_test_service(healthy_storage: bool) -> HostsServiceImpl {
        create_test_service_with_hooks(healthy_storage, Arc::new(HookExecutor::default()))
    }

    fn create_test_service_with_hooks(
        healthy_storage: bool,
        hooks: Arc<HookExecutor>,
    ) -> HostsServiceImpl {
        let storage: Arc<dyn Storage> = Arc::new(MockStorage {
            healthy: healthy_storage,
        });

        // Create minimal dependencies for CommandHandler
        let hosts_file = Arc::new(crate::server::hosts_file::HostsFileGenerator::new(
            std::path::PathBuf::from("/dev/null"),
        ));

        // Create CommandHandler without a Config (it's only used for retention policy)
        // The health tests don't exercise those code paths
        let commands = Arc::new(CommandHandler::new_for_testing(
            Arc::clone(&storage),
            hosts_file,
            Arc::clone(&hooks),
        ));
        let write_queue = WriteQueue::new(Arc::clone(&commands));

        HostsServiceImpl::new(write_queue, commands, storage, hooks, false, None)
    }

    #[tokio::test]
    async fn test_liveness_always_succeeds() {
        let service = create_test_service(true);
        let response = service
            .handle_liveness(Request::new(LivenessRequest {}))
            .await
            .unwrap();
        assert!(response.into_inner().alive);
    }

    #[tokio::test]
    async fn test_liveness_succeeds_even_with_unhealthy_storage() {
        let service = create_test_service(false);
        let response = service
            .handle_liveness(Request::new(LivenessRequest {}))
            .await
            .unwrap();
        assert!(response.into_inner().alive);
    }

    #[tokio::test]
    async fn test_readiness_returns_ready_when_db_healthy() {
        let service = create_test_service(true);
        let response = service
            .handle_readiness(Request::new(ReadinessRequest {}))
            .await
            .unwrap();
        let inner = response.into_inner();
        assert!(inner.ready);
        assert!(inner.reason.is_empty());
    }

    #[tokio::test]
    async fn test_readiness_returns_not_ready_when_db_unhealthy() {
        let service = create_test_service(false);
        let response = service
            .handle_readiness(Request::new(ReadinessRequest {}))
            .await
            .unwrap();
        let inner = response.into_inner();
        assert!(!inner.ready);
        assert!(inner.reason.contains("Database health check failed"));
    }

    #[tokio::test]
    async fn test_health_returns_complete_status() {
        let service = create_test_service(true);
        let response = service
            .handle_health(Request::new(HealthRequest {}))
            .await
            .unwrap();
        let inner = response.into_inner();

        // Check overall health
        assert!(inner.healthy);

        // Check server info
        let server = inner.server.unwrap();
        assert!(!server.version.is_empty());
        assert!(server.uptime_seconds >= 0);
        assert!(server.build_info.contains('v'));

        // Check database health
        let db = inner.database.unwrap();
        assert!(db.connected);
        assert_eq!(db.backend, "mock");
        assert!(db.latency_ms >= 0);
        assert!(db.error.is_empty());

        // Check ACME health (disabled in test)
        let acme = inner.acme.unwrap();
        assert!(!acme.enabled);
        assert_eq!(acme.status, "disabled");

        // Check hooks health
        let hooks = inner.hooks.unwrap();
        assert_eq!(hooks.configured_count, 0);
        assert!(hooks.hook_names.is_empty());
    }

    #[tokio::test]
    async fn test_health_reflects_unhealthy_db() {
        let service = create_test_service(false);
        let response = service
            .handle_health(Request::new(HealthRequest {}))
            .await
            .unwrap();
        let inner = response.into_inner();

        // Overall health should be false
        assert!(!inner.healthy);

        // Database should show error
        let db = inner.database.unwrap();
        assert!(!db.connected);
        assert!(!db.error.is_empty());
    }

    #[tokio::test]
    async fn test_health_with_hooks_configured() {
        let hooks = Arc::new(HookExecutor::new(
            vec!["echo success".to_string()],
            vec!["notify failure".to_string()],
            30,
        ));

        let service = create_test_service_with_hooks(true, hooks);

        let response = service
            .handle_health(Request::new(HealthRequest {}))
            .await
            .unwrap();
        let hooks = response.into_inner().hooks.unwrap();

        assert_eq!(hooks.configured_count, 2);
        assert_eq!(hooks.hook_names.len(), 2);
        assert!(hooks.hook_names[0].contains("echo success"));
        assert!(hooks.hook_names[1].contains("notify failure"));
    }
}
