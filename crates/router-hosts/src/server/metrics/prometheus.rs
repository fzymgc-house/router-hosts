//! Prometheus HTTP endpoint for /metrics

use super::MetricsError;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Start the Prometheus HTTP server
///
/// The server exposes `/metrics` endpoint on plaintext HTTP.
/// Returns the actual bound address (useful when port 0 is specified).
/// It will shut down when `shutdown_rx` receives a signal.
pub async fn start_server(
    addr: SocketAddr,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<SocketAddr, MetricsError> {
    // Install the Prometheus recorder
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| MetricsError::PrometheusBind(format!("Failed to install recorder: {e}")))?;

    let handle = Arc::new(handle);

    // Bind TCP listener
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| MetricsError::PrometheusBind(format!("Failed to bind {addr}: {e}")))?;

    let actual_addr = listener
        .local_addr()
        .map_err(|e| MetricsError::PrometheusBind(format!("Failed to get local addr: {e}")))?;

    // Spawn server task
    tokio::spawn(run_server(listener, handle, shutdown_rx));

    Ok(actual_addr)
}

async fn run_server(
    listener: TcpListener,
    handle: Arc<PrometheusHandle>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let handle = Arc::clone(&handle);
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let handle = Arc::clone(&handle);
                                async move { handle_request(req, handle).await }
                            });
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(io, service)
                                .await
                            {
                                tracing::debug!(error = %e, "HTTP connection error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to accept connection");
                    }
                }
            }
            _ = &mut shutdown_rx => {
                tracing::debug!("Prometheus server shutting down");
                break;
            }
        }
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    handle: Arc<PrometheusHandle>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let metrics = handle.render();
            build_response(StatusCode::OK, "text/plain; version=0.0.4", metrics)
        }
        _ => build_response(StatusCode::NOT_FOUND, "text/plain", "Not Found".to_string()),
    };
    Ok(response)
}

fn build_response(status: StatusCode, content_type: &str, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal Server Error"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::time::Duration;

    #[tokio::test]
    #[serial]
    async fn test_prometheus_server_responds_to_metrics() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("valid socket addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let actual_addr = start_server(addr, shutdown_rx)
            .await
            .expect("server starts");

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Fetch metrics
        let url = format!("http://{actual_addr}/metrics");
        let response = reqwest::get(&url).await.expect("request succeeds");

        assert_eq!(response.status(), 200);
        let body = response.text().await.expect("body is text");
        // Should contain at least process metrics or be empty
        assert!(body.is_empty() || body.contains('#'));

        // Shutdown
        let _ = shutdown_tx.send(());
    }

    #[tokio::test]
    #[serial]
    async fn test_prometheus_server_404_for_other_paths() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("valid socket addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let actual_addr = start_server(addr, shutdown_rx)
            .await
            .expect("server starts");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let url = format!("http://{actual_addr}/other");
        let response = reqwest::get(&url).await.expect("request succeeds");

        assert_eq!(response.status(), 404);

        let _ = shutdown_tx.send(());
    }
}
