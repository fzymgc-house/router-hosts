//! Prometheus HTTP endpoint for /metrics

use super::MetricsError;
use std::net::SocketAddr;
use tokio::sync::oneshot;

/// Start the Prometheus HTTP server
///
/// The server exposes `/metrics` endpoint on plaintext HTTP.
/// It will shut down when `shutdown_rx` receives a signal.
pub async fn start_server(
    addr: SocketAddr,
    _shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), MetricsError> {
    // TODO: Implement in Task 4
    tracing::debug!(%addr, "Prometheus server start requested (not yet implemented)");
    Ok(())
}
