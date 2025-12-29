//! Health check HTTP server for Kubernetes probes.
//!
//! Provides `/healthz` (liveness) and `/readyz` (readiness) endpoints.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

use crate::client::RouterHostsClientTrait;

/// Default port for health check server.
pub const DEFAULT_HEALTH_PORT: u16 = 8081;

/// Shared state for health check endpoints.
pub struct HealthState<C: RouterHostsClientTrait> {
    /// Whether the operator has completed startup.
    started: AtomicBool,
    /// Client for checking router-hosts server connectivity.
    client: Arc<C>,
}

impl<C: RouterHostsClientTrait> HealthState<C> {
    /// Create new health state with the given client.
    pub fn new(client: Arc<C>) -> Self {
        Self {
            started: AtomicBool::new(false),
            client,
        }
    }

    /// Mark the operator as started and ready.
    pub fn mark_started(&self) {
        self.started.store(true, Ordering::SeqCst);
        info!("Health check: operator marked as started");
    }

    /// Check if the operator has completed startup.
    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::SeqCst)
    }

    /// Get a reference to the client.
    pub fn client(&self) -> &C {
        &self.client
    }
}

/// Run the health check HTTP server.
///
/// This function runs until the server encounters a fatal error.
/// It should be spawned as a separate task alongside the controllers.
///
/// The operator is marked as started only after the server successfully binds,
/// eliminating any race condition between startup and probe availability.
pub async fn run_health_server<C: RouterHostsClientTrait + Send + Sync + 'static>(
    state: Arc<HealthState<C>>,
    port: u16,
) -> std::io::Result<()> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<C>))
        .with_state(state.clone());

    // Bind to localhost only - health endpoints should only be accessible
    // within the pod via the kubelet, not externally
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await?;

    info!(port = port, "Health check server listening");

    // Mark as started only after successful bind - ensures readiness probes
    // can't succeed before the health server is actually listening
    state.mark_started();

    axum::serve(listener, app).await
}

/// Liveness probe endpoint.
///
/// Returns 200 OK if the process is alive.
/// Kubernetes will restart the pod if this endpoint stops responding.
async fn healthz() -> StatusCode {
    debug!("Liveness probe: OK");
    StatusCode::OK
}

/// Readiness probe endpoint.
///
/// Returns 200 OK if the operator is ready to process work.
/// Returns 503 Service Unavailable if:
/// - Startup has not completed
/// - Cannot connect to router-hosts server
async fn readyz<C: RouterHostsClientTrait + Send + Sync + 'static>(
    State(state): State<Arc<HealthState<C>>>,
) -> StatusCode {
    // Check if startup completed
    if !state.is_started() {
        debug!("Readiness probe: NOT READY (startup incomplete)");
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    // Check router-hosts server connectivity using the dedicated readiness RPC
    match state.client().check_readiness().await {
        Ok(true) => {
            debug!("Readiness probe: OK");
            StatusCode::OK
        }
        Ok(false) => {
            // Server responded but isn't ready (e.g., DB not connected)
            debug!("Readiness probe: NOT READY (server not ready)");
            StatusCode::SERVICE_UNAVAILABLE
        }
        Err(e) => {
            // Transport/connection failure
            warn!(error = %e, "Readiness probe: NOT READY (server unreachable)");
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockRouterHostsClientTrait;

    #[tokio::test]
    async fn test_healthz_returns_ok() {
        let result = healthz().await;
        assert_eq!(result, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_returns_unavailable_before_startup() {
        let mut mock_client = MockRouterHostsClientTrait::new();
        // Should not be called since startup is false
        mock_client.expect_check_readiness().never();

        let state = Arc::new(HealthState::new(Arc::new(mock_client)));

        let result = readyz(State(state)).await;
        assert_eq!(result, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_readyz_returns_ok_when_server_ready() {
        let mut mock_client = MockRouterHostsClientTrait::new();
        mock_client.expect_check_readiness().returning(|| Ok(true));

        let state = Arc::new(HealthState::new(Arc::new(mock_client)));
        state.mark_started();

        let result = readyz(State(state)).await;
        assert_eq!(result, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readyz_returns_unavailable_when_server_not_ready() {
        let mut mock_client = MockRouterHostsClientTrait::new();
        mock_client.expect_check_readiness().returning(|| Ok(false));

        let state = Arc::new(HealthState::new(Arc::new(mock_client)));
        state.mark_started();

        let result = readyz(State(state)).await;
        assert_eq!(result, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_readyz_returns_unavailable_when_server_unreachable() {
        let mut mock_client = MockRouterHostsClientTrait::new();
        mock_client.expect_check_readiness().returning(|| {
            Err(crate::client::ClientError::GrpcError(
                tonic::Status::unavailable("test"),
            ))
        });

        let state = Arc::new(HealthState::new(Arc::new(mock_client)));
        state.mark_started();

        let result = readyz(State(state)).await;
        assert_eq!(result, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_mark_started_is_idempotent() {
        let mock_client = MockRouterHostsClientTrait::new();
        let state = Arc::new(HealthState::new(Arc::new(mock_client)));

        // Initially not started
        assert!(!state.is_started());

        // First call marks as started
        state.mark_started();
        assert!(state.is_started());

        // Second call should be safe (idempotent)
        state.mark_started();
        assert!(state.is_started());

        // Third call still safe
        state.mark_started();
        assert!(state.is_started());
    }
}
