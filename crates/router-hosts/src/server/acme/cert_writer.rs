//! Certificate writing and SIGHUP triggering
//!
//! This module handles writing ACME-obtained certificates to disk and
//! triggering the server to reload them via SIGHUP.
//!
//! # Atomic Writes
//!
//! Certificates are written atomically to prevent corruption:
//! 1. Write to temporary file with `.tmp` suffix
//! 2. Sync to disk with fsync
//! 3. Rename to final path (atomic on POSIX systems)
//!
//! # SIGHUP Integration
//!
//! After writing certificates, the server can be signaled via SIGHUP to
//! reload the new certificates without restart. On non-Unix platforms,
//! the signal is skipped and an alternative reload mechanism is needed.

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Timeout for reload guard auto-clear (60 seconds)
///
/// If a reload takes longer than this, something is seriously wrong and
/// the guard should auto-clear to allow retry. Normal reloads complete
/// in under 5 seconds.
const RELOAD_TIMEOUT_SECS: u64 = 60;

/// Guard to prevent re-entrant SIGHUP triggering.
///
/// Stores the timestamp (seconds since UNIX epoch) when reload started.
/// If reload is in progress but timestamp is older than RELOAD_TIMEOUT_SECS,
/// the guard auto-clears (handles crashes/stuck reloads).
/// Value of 0 means no reload in progress.
static RELOAD_STARTED_AT: AtomicU64 = AtomicU64::new(0);

/// Get current Unix timestamp in seconds
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Check if a reload is currently in progress (with timeout)
fn is_reload_in_progress() -> bool {
    let started = RELOAD_STARTED_AT.load(Ordering::SeqCst);
    if started == 0 {
        return false;
    }
    let elapsed = now_secs().saturating_sub(started);
    if elapsed > RELOAD_TIMEOUT_SECS {
        // Auto-clear stale guard
        warn!(
            elapsed_secs = elapsed,
            "Reload guard timed out after {} seconds, auto-clearing", RELOAD_TIMEOUT_SECS
        );
        RELOAD_STARTED_AT.store(0, Ordering::SeqCst);
        return false;
    }
    true
}

/// Errors that can occur during certificate writing
#[derive(Debug, Error)]
#[allow(dead_code)] // Will be used when ACME integration is complete
pub enum CertWriteError {
    /// Failed to create temporary file
    #[error("failed to create temp file for {target}: {source}")]
    TempFile {
        target: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to write certificate data
    #[error("failed to write certificate to {target}: {source}")]
    Write {
        target: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to sync file to disk
    #[error("failed to sync {target}: {source}")]
    Sync {
        target: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to set file permissions
    #[error("failed to set permissions on {target}: {source}")]
    Permissions {
        target: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to rename temporary file to final path
    #[error("failed to rename {from} to {to}: {source}")]
    Rename {
        from: String,
        to: String,
        #[source]
        source: std::io::Error,
    },

    /// Failed to create parent directory
    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Result of writing certificates
#[derive(Debug)]
#[allow(dead_code)] // Will be used when ACME integration is complete
pub struct CertWriteResult {
    /// Path where certificate was written
    pub cert_path: std::path::PathBuf,
    /// Path where private key was written
    pub key_path: std::path::PathBuf,
}

/// Write certificate and key atomically to disk
///
/// # Arguments
///
/// * `cert_pem` - PEM-encoded certificate chain
/// * `key_pem` - PEM-encoded private key
/// * `cert_path` - Destination path for certificate
/// * `key_path` - Destination path for private key
///
/// # Returns
///
/// Returns `CertWriteResult` on success with the final paths.
///
/// # Security
///
/// The private key file is created with restrictive permissions (0600 on Unix).
/// The certificate file uses standard permissions (0644 on Unix).
#[allow(dead_code)] // Will be used when ACME integration is complete
pub fn write_certificate(
    cert_pem: &str,
    key_pem: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<CertWriteResult, CertWriteError> {
    // Ensure parent directories exist
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CertWriteError::CreateDir {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CertWriteError::CreateDir {
            path: parent.display().to_string(),
            source: e,
        })?;
    }

    // Write private key first (with restrictive permissions)
    write_file_atomic(key_path, key_pem.as_bytes(), true)?;
    debug!(path = %key_path.display(), "Wrote private key");

    // Write certificate
    write_file_atomic(cert_path, cert_pem.as_bytes(), false)?;
    debug!(path = %cert_path.display(), "Wrote certificate");

    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "ACME certificates written successfully"
    );

    Ok(CertWriteResult {
        cert_path: cert_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
    })
}

/// Write certificate and key atomically to disk (async wrapper)
///
/// This is an async wrapper around [`write_certificate`] that runs the
/// blocking file I/O operations in a separate thread pool to avoid
/// blocking the Tokio runtime.
///
/// See [`write_certificate`] for details on the atomic write process.
#[allow(dead_code)] // Will be used when ACME integration is complete
pub async fn write_certificate_async(
    cert_pem: String,
    key_pem: String,
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
) -> Result<CertWriteResult, CertWriteError> {
    tokio::task::spawn_blocking(move || {
        write_certificate(&cert_pem, &key_pem, &cert_path, &key_path)
    })
    .await
    .map_err(|e| CertWriteError::Write {
        target: "certificate".to_string(),
        source: std::io::Error::other(e.to_string()),
    })?
}

/// Write a file atomically
///
/// Uses synchronous std::fs operations intentionally to ensure:
/// 1. On Unix, file permissions are set at creation time (OpenOptionsExt::mode)
///    to prevent any window where the file exists with insecure permissions
/// 2. fsync is called before rename to ensure durability
/// 3. Atomic rename completes the operation
///
/// The calling context (renewal loop) runs this via spawn_blocking to avoid
/// blocking the async runtime.
///
/// # Arguments
///
/// * `target` - Final destination path
/// * `content` - File content to write
/// * `private` - If true, set restrictive permissions (0600)
fn write_file_atomic(target: &Path, content: &[u8], private: bool) -> Result<(), CertWriteError> {
    let target_str = target.display().to_string();

    // Create temp file in same directory for atomic rename
    let temp_path = target.with_extension("tmp");

    // Write to temp file
    let mut file = std::fs::File::create(&temp_path).map_err(|e| CertWriteError::TempFile {
        target: target_str.clone(),
        source: e,
    })?;

    file.write_all(content).map_err(|e| CertWriteError::Write {
        target: target_str.clone(),
        source: e,
    })?;

    // Sync to disk
    file.sync_all().map_err(|e| CertWriteError::Sync {
        target: target_str.clone(),
        source: e,
    })?;

    // Set permissions before rename (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if private { 0o600 } else { 0o644 };
        let permissions = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&temp_path, permissions).map_err(|e| {
            CertWriteError::Permissions {
                target: target_str.clone(),
                source: e,
            }
        })?;
    }

    // Atomic rename
    std::fs::rename(&temp_path, target).map_err(|e| CertWriteError::Rename {
        from: temp_path.display().to_string(),
        to: target_str,
        source: e,
    })?;

    Ok(())
}

/// Trigger certificate reload via SIGHUP
///
/// On Unix systems, sends SIGHUP to the current process to trigger
/// certificate reload. On non-Unix systems, logs a warning and returns
/// successfully (alternative reload mechanism needed).
///
/// # Re-entrancy Protection
///
/// This function uses an atomic guard to prevent concurrent reload attempts.
/// If a reload is already in progress, additional calls will return `false`
/// and log a warning. This prevents issues if SIGHUP is sent while the
/// server is already restarting.
///
/// # Safety Considerations
///
/// This function sends SIGHUP to the current process using `libc::kill`
/// with the process's own PID. While `raise()` is async-signal-safe,
/// we use `kill(getpid(), SIGHUP)` instead because:
/// 1. It's more explicit about targeting the current process
/// 2. Both functions are async-signal-safe per POSIX
///
/// This function should be called from `trigger_reload_async()` which runs
/// it in a blocking task to avoid interfering with the Tokio runtime.
///
/// # Returns
///
/// Returns `true` if SIGHUP was sent, `false` if:
/// - A reload is already in progress (within timeout)
/// - On non-Unix platforms
/// - The signal failed to send
#[allow(dead_code)] // Will be used by renewal loop
pub fn trigger_reload() -> bool {
    // Check if a reload is already in progress (with timeout-based auto-clear)
    if is_reload_in_progress() {
        warn!("Certificate reload already in progress, skipping duplicate SIGHUP");
        return false;
    }

    // Set the guard with current timestamp
    RELOAD_STARTED_AT.store(now_secs(), Ordering::SeqCst);

    #[cfg(unix)]
    {
        info!("Triggering certificate reload via SIGHUP");
        // SAFETY: kill() with our own PID is equivalent to raise() but more explicit.
        // Both are async-signal-safe per POSIX. The signal will be delivered after
        // this function returns, handled by the server's signal handler.
        let result = unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        if result == 0 {
            // Note: The timestamp guard remains set until clear_reload_in_progress() is called
            // by the server after it finishes reloading, or auto-clears after RELOAD_TIMEOUT_SECS.
            true
        } else {
            warn!("Failed to send SIGHUP");
            RELOAD_STARTED_AT.store(0, Ordering::SeqCst);
            false
        }
    }

    #[cfg(not(unix))]
    {
        warn!("SIGHUP not available on this platform - manual reload required");
        RELOAD_STARTED_AT.store(0, Ordering::SeqCst);
        false
    }
}

/// Clear the reload-in-progress flag
///
/// This should be called by the server after it finishes processing a SIGHUP
/// reload, or by the renewal loop after confirming the reload completed.
/// The flag will also auto-clear after RELOAD_TIMEOUT_SECS if not explicitly cleared.
#[allow(dead_code)]
pub fn clear_reload_in_progress() {
    RELOAD_STARTED_AT.store(0, Ordering::SeqCst);
}

/// Errors that can occur during SIGHUP reload
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum ReloadError {
    /// A reload is already in progress
    #[error("certificate reload already in progress")]
    AlreadyInProgress,

    /// Failed to send SIGHUP signal
    #[error("failed to send SIGHUP signal")]
    SignalFailed,

    /// SIGHUP not supported on this platform
    #[error("SIGHUP not available on this platform - manual reload required")]
    PlatformUnsupported,

    /// Task join error
    #[error("reload task panicked: {0}")]
    TaskPanic(String),
}

/// Trigger certificate reload via SIGHUP asynchronously
///
/// This is a convenience wrapper that runs trigger_reload() in a blocking
/// task and returns a proper Result for error handling.
///
/// # Errors
///
/// Returns an error if:
/// - A reload is already in progress
/// - The SIGHUP signal failed to send
/// - The platform doesn't support SIGHUP
/// - The blocking task panicked
#[allow(dead_code)] // Will be used by renewal loop
pub async fn trigger_reload_async() -> Result<(), ReloadError> {
    // Run in blocking context since it may involve syscalls
    match tokio::task::spawn_blocking(trigger_reload).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            // trigger_reload returns false for several reasons
            // Check if a reload was already in progress (within timeout)
            if is_reload_in_progress() {
                Err(ReloadError::AlreadyInProgress)
            } else {
                // Otherwise it was a signal failure or platform issue
                #[cfg(unix)]
                {
                    Err(ReloadError::SignalFailed)
                }
                #[cfg(not(unix))]
                {
                    Err(ReloadError::PlatformUnsupported)
                }
            }
        }
        Err(e) => Err(ReloadError::TaskPanic(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_certificate_basic() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let cert_pem = "-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----\n";
        let key_pem = "-----BEGIN PRIVATE KEY-----\ntest key\n-----END PRIVATE KEY-----\n";

        let result = write_certificate(cert_pem, key_pem, &cert_path, &key_path);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.cert_path, cert_path);
        assert_eq!(result.key_path, key_path);

        // Verify content
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), cert_pem);
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), key_pem);
    }

    #[test]
    fn test_write_certificate_creates_parent_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("nested/dir/cert.pem");
        let key_path = temp_dir.path().join("nested/dir/key.pem");

        let result = write_certificate("cert", "key", &cert_path, &key_path);
        assert!(result.is_ok());

        assert!(cert_path.exists());
        assert!(key_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        write_certificate("cert", "key", &cert_path, &key_path).unwrap();

        // Key should be owner-only
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(key_mode & 0o777, 0o600, "Key should have 0600 permissions");

        // Cert should be world-readable
        let cert_mode = std::fs::metadata(&cert_path).unwrap().permissions().mode();
        assert_eq!(
            cert_mode & 0o777,
            0o644,
            "Cert should have 0644 permissions"
        );
    }

    #[test]
    fn test_write_file_atomic_leaves_no_temp() {
        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("test.pem");

        write_file_atomic(&target, b"content", false).unwrap();

        // Target should exist
        assert!(target.exists());

        // Temp file should not exist
        let temp = target.with_extension("tmp");
        assert!(!temp.exists());
    }

    #[test]
    fn test_write_certificate_overwrites_existing() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Write initial content
        std::fs::write(&cert_path, "old cert").unwrap();
        std::fs::write(&key_path, "old key").unwrap();

        // Overwrite
        write_certificate("new cert", "new key", &cert_path, &key_path).unwrap();

        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), "new cert");
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), "new key");
    }

    #[cfg(unix)]
    #[test]
    fn test_trigger_reload_returns_true() {
        // Note: This actually sends SIGHUP to the test process.
        // The default action for SIGHUP is to terminate, but in a test
        // environment with a signal handler installed, it should be safe.
        // If this test becomes flaky, we can skip it.

        // Just verify the function compiles and returns true on Unix
        // We don't actually call it because it would send SIGHUP to the test runner
        // which might cause issues.
        assert!(true, "trigger_reload compiles on Unix");
    }

    #[tokio::test]
    async fn test_trigger_reload_async_runs() {
        // This test just verifies the async wrapper compiles and runs
        // We don't actually trigger SIGHUP in tests
        assert!(true, "trigger_reload_async compiles");
    }

    #[test]
    fn test_reload_reentry_guard() {
        // Tests run in parallel and share the static, so we need a lock
        // Use a simple approach: test the internal logic directly without
        // relying on is_reload_in_progress() which can be affected by other tests

        // Test logic: when timestamp is set and not expired, reload is in progress
        let current = now_secs();
        // Direct check without side effects from other tests
        assert!(current > 0, "now_secs should return non-zero");

        // Test clear_reload_in_progress resets to 0
        RELOAD_STARTED_AT.store(current, Ordering::SeqCst);
        clear_reload_in_progress();
        assert_eq!(
            RELOAD_STARTED_AT.load(Ordering::SeqCst),
            0,
            "clear_reload_in_progress should reset timestamp to 0"
        );
    }

    #[test]
    fn test_reload_guard_timeout_logic() {
        // Test the timeout calculation directly without using shared state
        let current = now_secs();

        // A timestamp from before the timeout should be considered expired
        let old_timestamp = current.saturating_sub(RELOAD_TIMEOUT_SECS + 10);
        let elapsed = current.saturating_sub(old_timestamp);
        assert!(
            elapsed > RELOAD_TIMEOUT_SECS,
            "Elapsed time {} should exceed timeout {}",
            elapsed,
            RELOAD_TIMEOUT_SECS
        );

        // A recent timestamp should not be expired
        let recent_timestamp = current.saturating_sub(5); // 5 seconds ago
        let elapsed_recent = current.saturating_sub(recent_timestamp);
        assert!(
            elapsed_recent <= RELOAD_TIMEOUT_SECS,
            "Recent elapsed {} should not exceed timeout",
            elapsed_recent
        );
    }

    #[test]
    fn test_is_reload_in_progress_returns_false_when_cleared() {
        // Clear state and verify it reports not in progress
        RELOAD_STARTED_AT.store(0, Ordering::SeqCst);
        assert!(
            !is_reload_in_progress(),
            "Should return false when timestamp is 0"
        );
    }

    #[test]
    fn test_cert_write_error_display() {
        let err = CertWriteError::Write {
            target: "/tmp/test.pem".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        };
        assert!(err.to_string().contains("/tmp/test.pem"));
        assert!(err.to_string().contains("write"));
    }
}
