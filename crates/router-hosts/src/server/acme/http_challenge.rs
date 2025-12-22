//! HTTP-01 challenge server implementation
//!
//! This module provides an HTTP server that responds to ACME HTTP-01 challenges.
//! The server listens on the configured address (typically port 80) and serves
//! challenge responses at `/.well-known/acme-challenge/{token}`.
//!
//! # Architecture
//!
//! The server uses a shared `ChallengeStore` to store pending challenges.
//! When a challenge is added, the token and key authorization are stored.
//! When a request comes in for `/.well-known/acme-challenge/{token}`,
//! the server looks up the key authorization and returns it.
//!
//! # Usage
//!
//! ```no_run
//! use router_hosts::server::acme::http_challenge::{HttpChallengeServer, ChallengeStore};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let store = Arc::new(ChallengeStore::new());
//!     let server = HttpChallengeServer::new("0.0.0.0:80".parse().unwrap(), store.clone());
//!
//!     // Start server in background
//!     let handle = server.start().await.unwrap();
//!
//!     // Add a challenge
//!     store.add_challenge("token123", "key_auth_value");
//!
//!     // ... ACME validation happens ...
//!
//!     // Clean up
//!     store.remove_challenge("token123");
//!     handle.shutdown().await;
//! }
//! ```

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent connections to the HTTP challenge server.
/// This limits resource exhaustion from DoS attacks or connection floods.
const MAX_CONCURRENT_CONNECTIONS: usize = 100;

/// Timeout for individual HTTP request handling.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum requests per IP within the rate limit window.
const RATE_LIMIT_MAX_REQUESTS: usize = 20;

/// Time window for per-IP rate limiting.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Interval for rate limiter cleanup task (matches rate limit window)
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = RATE_LIMIT_WINDOW;

/// Maximum number of challenges that can be stored simultaneously.
/// This prevents unbounded memory growth from buggy or malicious callers.
/// Normal ACME operations typically have 1-10 challenges at a time.
const MAX_CHALLENGES: usize = 100;

/// Time-to-live for individual challenges.
/// ACME challenges are typically validated within seconds/minutes.
/// This ensures stale challenges are cleaned up even if explicit removal fails.
const CHALLENGE_TTL: Duration = Duration::from_secs(10 * 60); // 10 minutes

/// Per-IP rate limiter using a sliding window approach
#[derive(Debug, Default)]
struct IpRateLimiter {
    requests: RwLock<HashMap<IpAddr, Vec<Instant>>>,
}

impl IpRateLimiter {
    fn new() -> Self {
        Self {
            requests: RwLock::new(HashMap::new()),
        }
    }

    /// Check if a request from this IP should be allowed.
    /// Returns true if allowed, false if rate limited.
    async fn check_and_record(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - RATE_LIMIT_WINDOW;

        let mut requests = self.requests.write().await;

        // Get or create entry for this IP
        let timestamps = requests.entry(ip).or_insert_with(Vec::new);

        // Remove expired entries
        timestamps.retain(|&t| t > cutoff);

        // Check if under limit
        if timestamps.len() >= RATE_LIMIT_MAX_REQUESTS {
            return false;
        }

        // Record this request
        timestamps.push(now);
        true
    }

    /// Clean up old entries to prevent unbounded memory growth.
    /// Call this periodically (e.g., every few minutes).
    async fn cleanup(&self) {
        let cutoff = Instant::now() - RATE_LIMIT_WINDOW;
        let mut requests = self.requests.write().await;

        // Remove IPs with no recent requests
        requests.retain(|_, timestamps| {
            timestamps.retain(|&t| t > cutoff);
            !timestamps.is_empty()
        });
    }
}

/// Errors that can occur in the HTTP challenge server
#[derive(Debug, Error)]
#[allow(dead_code)] // Will be used when ACME integration is complete
pub enum HttpChallengeError {
    /// Failed to bind to address
    #[error("failed to bind to {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// Server error
    #[error("server error: {0}")]
    Server(String),
}

/// Entry in the challenge store with expiration tracking
#[derive(Debug, Clone)]
struct ChallengeEntry {
    key_auth: String,
    created_at: Instant,
}

/// Thread-safe store for pending ACME challenges
///
/// Maps token -> key_authorization with automatic expiration.
/// Enforces size limits to prevent unbounded memory growth.
#[derive(Debug, Default)]
#[allow(dead_code)] // Will be used when ACME integration is complete
pub struct ChallengeStore {
    challenges: RwLock<HashMap<String, ChallengeEntry>>,
}

#[allow(dead_code)] // Methods will be used when ACME integration is complete
impl ChallengeStore {
    /// Create a new empty challenge store
    pub fn new() -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
        }
    }

    /// Add a challenge to the store
    ///
    /// The token is the challenge identifier from ACME.
    /// The key_auth is the full key authorization string (token.thumbprint).
    ///
    /// Returns `false` if the store is at capacity (MAX_CHALLENGES).
    /// Expired challenges are cleaned up during this operation.
    pub async fn add_challenge(&self, token: &str, key_auth: &str) -> bool {
        let mut challenges = self.challenges.write().await;

        // Clean up expired entries first
        let now = Instant::now();
        challenges.retain(|_, entry| now.duration_since(entry.created_at) < CHALLENGE_TTL);

        // Check size limit
        if challenges.len() >= MAX_CHALLENGES && !challenges.contains_key(token) {
            warn!(
                max = MAX_CHALLENGES,
                current = challenges.len(),
                "Challenge store at capacity, rejecting new challenge"
            );
            return false;
        }

        debug!(token = %token, "Adding HTTP-01 challenge to store");
        challenges.insert(
            token.to_string(),
            ChallengeEntry {
                key_auth: key_auth.to_string(),
                created_at: now,
            },
        );
        true
    }

    /// Remove a challenge from the store
    pub async fn remove_challenge(&self, token: &str) {
        let mut challenges = self.challenges.write().await;
        debug!(token = %token, "Removing HTTP-01 challenge from store");
        challenges.remove(token);
    }

    /// Get the key authorization for a token
    ///
    /// Returns `None` if the token doesn't exist or has expired.
    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().await;
        challenges.get(token).and_then(|entry| {
            // Check if expired
            if Instant::now().duration_since(entry.created_at) >= CHALLENGE_TTL {
                None
            } else {
                Some(entry.key_auth.clone())
            }
        })
    }

    /// Check if the store has any pending (non-expired) challenges
    pub async fn has_challenges(&self) -> bool {
        let challenges = self.challenges.read().await;
        let now = Instant::now();
        challenges
            .values()
            .any(|entry| now.duration_since(entry.created_at) < CHALLENGE_TTL)
    }

    /// Clear all challenges
    pub async fn clear(&self) {
        let mut challenges = self.challenges.write().await;
        debug!("Clearing all HTTP-01 challenges");
        challenges.clear();
    }

    /// Get the number of active (non-expired) challenges
    #[cfg(test)]
    async fn len(&self) -> usize {
        let challenges = self.challenges.read().await;
        let now = Instant::now();
        challenges
            .values()
            .filter(|entry| now.duration_since(entry.created_at) < CHALLENGE_TTL)
            .count()
    }
}

/// Timeout for graceful shutdown before forcing abort
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle for controlling a running HTTP challenge server
#[allow(dead_code)] // Will be used when ACME integration is complete
pub struct HttpChallengeHandle {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    join_handle: tokio::task::JoinHandle<()>,
    abort_handle: tokio::task::AbortHandle,
    cleanup_handle: tokio::task::JoinHandle<()>,
}

#[allow(dead_code)] // Methods will be used when ACME integration is complete
impl HttpChallengeHandle {
    /// Shutdown the server gracefully with timeout
    ///
    /// Waits up to [`SHUTDOWN_TIMEOUT`] for the server to finish handling requests.
    /// If the timeout expires, the task is forcibly aborted to ensure
    /// the server shuts down promptly.
    pub async fn shutdown(self) {
        debug!("Shutting down HTTP challenge server");
        // Abort the cleanup task first
        self.cleanup_handle.abort();
        // Send shutdown signal (ignore error if receiver dropped)
        let _ = self.shutdown_tx.send(());
        // Wait for server to finish with timeout, then abort if necessary
        match tokio::time::timeout(SHUTDOWN_TIMEOUT, self.join_handle).await {
            Ok(_) => {
                debug!("HTTP challenge server shutdown completed gracefully");
            }
            Err(_) => {
                warn!(
                    "HTTP challenge server shutdown timed out after {:?}, aborting task",
                    SHUTDOWN_TIMEOUT
                );
                self.abort_handle.abort();
            }
        }
    }
}

/// HTTP-01 challenge server
///
/// This server listens for ACME HTTP-01 validation requests and serves
/// the appropriate key authorization responses.
#[allow(dead_code)] // Will be used when ACME integration is complete
pub struct HttpChallengeServer {
    bind_addr: SocketAddr,
    store: Arc<ChallengeStore>,
}

#[allow(dead_code)] // Methods will be used when ACME integration is complete
impl HttpChallengeServer {
    /// Create a new HTTP challenge server
    pub fn new(bind_addr: SocketAddr, store: Arc<ChallengeStore>) -> Self {
        Self { bind_addr, store }
    }

    /// Start the server and return a handle for controlling it
    pub async fn start(self) -> Result<HttpChallengeHandle, HttpChallengeError> {
        let listener =
            TcpListener::bind(self.bind_addr)
                .await
                .map_err(|e| HttpChallengeError::Bind {
                    addr: self.bind_addr,
                    source: e,
                })?;

        info!(addr = %self.bind_addr, "HTTP-01 challenge server listening");

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
        let store = self.store;

        // Semaphore to limit concurrent connections (DoS protection)
        let connection_semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        // Per-IP rate limiter
        let rate_limiter = Arc::new(IpRateLimiter::new());

        // Spawn a background task to periodically clean up the rate limiter
        let rate_limiter_cleanup = rate_limiter.clone();
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(RATE_LIMIT_CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                rate_limiter_cleanup.cleanup().await;
            }
        });

        let join_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, remote_addr)) => {
                                let store = store.clone();
                                let semaphore = connection_semaphore.clone();
                                let rate_limiter = rate_limiter.clone();

                                // Check per-IP rate limit
                                if !rate_limiter.check_and_record(remote_addr.ip()).await {
                                    warn!(remote = %remote_addr, "Rate limit exceeded, rejecting");
                                    continue;
                                }

                                // Try to acquire a permit (non-blocking)
                                let permit = match semaphore.try_acquire_owned() {
                                    Ok(permit) => permit,
                                    Err(_) => {
                                        warn!(remote = %remote_addr, "Connection limit reached, rejecting");
                                        // Drop the stream to reject the connection
                                        continue;
                                    }
                                };

                                tokio::spawn(async move {
                                    // Permit is held for the lifetime of this task
                                    let _permit = permit;

                                    let io = TokioIo::new(stream);
                                    let service = service_fn(move |req| {
                                        handle_request(req, store.clone(), remote_addr)
                                    });

                                    // Apply request timeout to prevent slow clients from holding connections
                                    let connection_result = tokio::time::timeout(
                                        REQUEST_TIMEOUT,
                                        http1::Builder::new().serve_connection(io, service)
                                    ).await;

                                    match connection_result {
                                        Ok(Ok(())) => {}
                                        Ok(Err(err)) => {
                                            // Don't log connection reset errors - these are normal
                                            if !err.to_string().contains("connection reset") {
                                                warn!(error = %err, "Error serving connection");
                                            }
                                        }
                                        Err(_) => {
                                            debug!(remote = %remote_addr, "Connection timed out");
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                error!(error = %e, "Error accepting connection");
                            }
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("HTTP-01 challenge server shutting down");
                        break;
                    }
                }
            }
        });

        let abort_handle = join_handle.abort_handle();
        Ok(HttpChallengeHandle {
            shutdown_tx,
            join_handle,
            abort_handle,
            cleanup_handle,
        })
    }
}

/// Handle an incoming HTTP request
#[allow(dead_code)] // Called by HttpChallengeServer::start
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    store: Arc<ChallengeStore>,
    remote_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    debug!(method = %method, path = %path, remote = %remote_addr, "HTTP request");

    // Only handle GET requests
    if method != Method::GET {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Method not allowed")))
            .expect("response builder"));
    }

    // Check if this is an ACME challenge request
    const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
    if !path.starts_with(CHALLENGE_PREFIX) {
        // Return 404 for any non-challenge path
        debug!(path = %path, "Not a challenge path, returning 404");
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not found")))
            .expect("response builder"));
    }

    // Extract token from path
    let token = &path[CHALLENGE_PREFIX.len()..];
    if token.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Missing token")))
            .expect("response builder"));
    }

    // Validate token to prevent path traversal attacks.
    // ACME tokens are base64url-encoded strings per RFC 8555.
    // They should only contain: A-Z, a-z, 0-9, -, _ (no slashes, dots, etc.)
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        warn!(
            token = %token,
            remote = %remote_addr,
            "Invalid token format, possible path traversal attempt"
        );
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("Invalid token format")))
            .expect("response builder"));
    }

    // Look up the key authorization
    match store.get_challenge(token).await {
        Some(key_auth) => {
            info!(token = %token, remote = %remote_addr, "Serving ACME challenge response");
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(key_auth)))
                .expect("response builder"))
        }
        None => {
            warn!(token = %token, remote = %remote_addr, "Unknown ACME challenge token");
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Challenge not found")))
                .expect("response builder"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_challenge_store_add_and_get() {
        let store = ChallengeStore::new();

        assert!(store.add_challenge("token1", "key_auth_1").await);
        assert!(store.add_challenge("token2", "key_auth_2").await);

        assert_eq!(
            store.get_challenge("token1").await,
            Some("key_auth_1".to_string())
        );
        assert_eq!(
            store.get_challenge("token2").await,
            Some("key_auth_2".to_string())
        );
        assert_eq!(store.get_challenge("unknown").await, None);
    }

    #[tokio::test]
    async fn test_challenge_store_remove() {
        let store = ChallengeStore::new();

        assert!(store.add_challenge("token1", "key_auth_1").await);
        assert!(store.has_challenges().await);

        store.remove_challenge("token1").await;
        assert!(!store.has_challenges().await);
        assert_eq!(store.get_challenge("token1").await, None);
    }

    #[tokio::test]
    async fn test_challenge_store_clear() {
        let store = ChallengeStore::new();

        assert!(store.add_challenge("token1", "key_auth_1").await);
        assert!(store.add_challenge("token2", "key_auth_2").await);
        assert!(store.has_challenges().await);

        store.clear().await;
        assert!(!store.has_challenges().await);
    }

    #[tokio::test]
    async fn test_challenge_store_size_limit() {
        let store = ChallengeStore::new();

        // Fill up to the limit
        for i in 0..MAX_CHALLENGES {
            assert!(
                store
                    .add_challenge(&format!("token{}", i), "key_auth")
                    .await,
                "Should accept challenge {} (under limit)",
                i
            );
        }

        assert_eq!(store.len().await, MAX_CHALLENGES);

        // Next add should fail (at capacity)
        assert!(
            !store.add_challenge("one_more", "key_auth").await,
            "Should reject challenge when at capacity"
        );

        // But updating existing token should succeed
        assert!(
            store.add_challenge("token0", "updated_key_auth").await,
            "Should allow updating existing token"
        );
    }

    #[tokio::test]
    async fn test_server_responds_to_challenge() {
        let store = Arc::new(ChallengeStore::new());
        assert!(store.add_challenge("test-token", "test-key-auth").await);

        // Find an available port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = HttpChallengeServer::new(addr, store.clone());
        let handle = server.start().await.unwrap();

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Make a request
        let client = reqwest::Client::new();
        let url = format!("http://{}/.well-known/acme-challenge/test-token", addr);

        let response = timeout(Duration::from_secs(5), client.get(&url).send())
            .await
            .expect("request should complete")
            .expect("request should succeed");

        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "test-key-auth");

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_server_returns_404_for_unknown_token() {
        let store = Arc::new(ChallengeStore::new());

        // Find an available port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = HttpChallengeServer::new(addr, store);
        let handle = server.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let url = format!("http://{}/.well-known/acme-challenge/unknown-token", addr);

        let response = timeout(Duration::from_secs(5), client.get(&url).send())
            .await
            .expect("request should complete")
            .expect("request should succeed");

        assert_eq!(response.status(), 404);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_server_returns_404_for_non_challenge_path() {
        let store = Arc::new(ChallengeStore::new());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = HttpChallengeServer::new(addr, store);
        let handle = server.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = reqwest::Client::new();

        // Test root path
        let response = client
            .get(format!("http://{}/", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);

        // Test other path
        let response = client
            .get(format!("http://{}/some/other/path", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_server_returns_405_for_non_get() {
        let store = Arc::new(ChallengeStore::new());
        assert!(store.add_challenge("token", "key_auth").await);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let server = HttpChallengeServer::new(addr, store);
        let handle = server.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = reqwest::Client::new();
        let url = format!("http://{}/.well-known/acme-challenge/token", addr);

        let response = client.post(&url).send().await.unwrap();
        assert_eq!(response.status(), 405);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn test_concurrent_challenge_access() {
        let store = Arc::new(ChallengeStore::new());

        // Spawn multiple tasks that add and read challenges
        let mut handles = vec![];
        for i in 0..10 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                let token = format!("token{}", i);
                let key_auth = format!("key_auth{}", i);
                assert!(store.add_challenge(&token, &key_auth).await);
                assert_eq!(store.get_challenge(&token).await, Some(key_auth));
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }
}
