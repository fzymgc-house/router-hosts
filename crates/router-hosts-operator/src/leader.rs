//! Leader election for running multiple operator replicas safely.
//!
//! Uses Kubernetes Lease API via `kube-leader-election` to ensure only one
//! replica actively reconciles at a time. Non-leaders block waiting for
//! leadership, and the process exits if leadership is lost.
//!
//! # Pattern: Acquire or Exit
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐
//! │  Pod A (Leader) │     │  Pod B (Standby)│
//! │  Controllers    │     │    Blocked      │
//! │    Running      │     │    Waiting      │
//! └────────┬────────┘     └────────┬────────┘
//!          │                       │
//!          ▼                       ▼
//!     ┌─────────────────────────────────┐
//!     │   Lease: router-hosts-leader    │
//!     └─────────────────────────────────┘
//! ```

use std::time::Duration;

use anyhow::{ensure, Context, Result};
use kube::Client;
use kube_leader_election::{LeaseLock, LeaseLockParams};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// Maximum consecutive renewal failures before exiting.
/// Allows recovery from transient network issues.
const MAX_RENEWAL_FAILURES: u32 = 3;

/// Configuration for leader election.
///
/// Fields are private to enforce invariants. Use [`LeaderElectionConfig::from_env()`]
/// to create a configuration from environment variables, or [`LeaderElectionConfig::new()`]
/// for programmatic construction with validation.
#[derive(Debug, Clone)]
pub struct LeaderElectionConfig {
    enabled: bool,
    lease_name: String,
    namespace: String,
    holder_id: String,
    lease_duration: Duration,
    renew_interval: Duration,
}

impl LeaderElectionConfig {
    /// Create a new leader election configuration with validation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `lease_name` is empty
    /// - `namespace` is empty
    /// - `holder_id` is empty
    /// - `renew_interval >= lease_duration` (would cause leadership loss)
    pub fn new(
        lease_name: String,
        namespace: String,
        holder_id: String,
        lease_duration: Duration,
        renew_interval: Duration,
    ) -> Result<Self> {
        ensure!(!lease_name.is_empty(), "lease_name cannot be empty");
        ensure!(!namespace.is_empty(), "namespace cannot be empty");
        ensure!(!holder_id.is_empty(), "holder_id cannot be empty");
        ensure!(
            renew_interval < lease_duration,
            "renew_interval ({:?}) must be less than lease_duration ({:?})",
            renew_interval,
            lease_duration
        );

        Ok(Self {
            enabled: true,
            lease_name,
            namespace,
            holder_id,
            lease_duration,
            renew_interval,
        })
    }

    /// Create a disabled configuration (no leader election).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            lease_name: String::new(),
            namespace: String::new(),
            holder_id: String::new(),
            lease_duration: Duration::from_secs(15),
            renew_interval: Duration::from_secs(5),
        }
    }

    /// Load configuration from environment variables.
    ///
    /// Environment variables:
    /// - `LEADER_ELECTION_ENABLED`: "true" to enable (default: false)
    /// - `LEADER_ELECTION_LEASE_NAME`: Lease name (required if enabled)
    /// - `POD_NAMESPACE`: Namespace for the lease (required if enabled)
    /// - `POD_NAME`: This pod's name, used as holder identity (required if enabled)
    /// - `LEADER_ELECTION_LEASE_DURATION`: TTL in seconds (default: 15)
    /// - `LEADER_ELECTION_RENEW_INTERVAL`: Renewal interval in seconds (default: 5)
    pub fn from_env() -> Result<Self> {
        let enabled = std::env::var("LEADER_ELECTION_ENABLED")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);

        if !enabled {
            return Ok(Self::disabled());
        }

        let lease_name = std::env::var("LEADER_ELECTION_LEASE_NAME")
            .context("LEADER_ELECTION_LEASE_NAME required when leader election is enabled")?;

        let namespace = std::env::var("POD_NAMESPACE")
            .context("POD_NAMESPACE required when leader election is enabled")?;

        let holder_id = std::env::var("POD_NAME")
            .context("POD_NAME required when leader election is enabled")?;

        let lease_duration =
            parse_duration_env("LEADER_ELECTION_LEASE_DURATION", Duration::from_secs(15));

        let renew_interval =
            parse_duration_env("LEADER_ELECTION_RENEW_INTERVAL", Duration::from_secs(5));

        Self::new(
            lease_name,
            namespace,
            holder_id,
            lease_duration,
            renew_interval,
        )
    }

    /// Whether leader election is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Name of the Lease resource.
    pub fn lease_name(&self) -> &str {
        &self.lease_name
    }

    /// Namespace for the Lease resource.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Identity of this pod (from POD_NAME env var).
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Time before lease expires if not renewed.
    pub fn lease_duration(&self) -> Duration {
        self.lease_duration
    }

    /// How often to renew the lease.
    pub fn renew_interval(&self) -> Duration {
        self.renew_interval
    }
}

/// Parse a duration from an environment variable with logging on failure.
fn parse_duration_env(var_name: &str, default: Duration) -> Duration {
    match std::env::var(var_name) {
        Ok(v) => match v.parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(e) => {
                warn!(
                    env_var = var_name,
                    value = %v,
                    error = %e,
                    default_secs = default.as_secs(),
                    "Failed to parse duration env var, using default"
                );
                default
            }
        },
        Err(_) => default,
    }
}

/// Leader election manager using Kubernetes Lease API.
pub struct LeaderElection {
    lease_lock: LeaseLock,
    renew_interval: Duration,
}

impl LeaderElection {
    /// Create a new leader election manager.
    pub fn new(client: Client, config: &LeaderElectionConfig) -> Self {
        let lease_lock = LeaseLock::new(
            client,
            config.namespace(),
            LeaseLockParams {
                holder_id: config.holder_id().to_string(),
                lease_name: config.lease_name().to_string(),
                lease_ttl: config.lease_duration(),
            },
        );

        Self {
            lease_lock,
            renew_interval: config.renew_interval(),
        }
    }

    /// Acquire leadership, blocking until successful.
    ///
    /// This method will retry indefinitely until leadership is acquired.
    /// It should be called before starting controllers.
    pub async fn acquire(&self) -> Result<()> {
        info!("Attempting to acquire leadership...");

        loop {
            match self.lease_lock.try_acquire_or_renew().await {
                Ok(result) if result.acquired_lease => {
                    let holder = result
                        .lease
                        .as_ref()
                        .and_then(|l| l.spec.as_ref())
                        .and_then(|s| s.holder_identity.as_ref())
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    info!(holder = %holder, "Leadership acquired");
                    return Ok(());
                }
                Ok(result) => {
                    let current_holder = result
                        .lease
                        .as_ref()
                        .and_then(|l| l.spec.as_ref())
                        .and_then(|s| s.holder_identity.as_ref())
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    info!(current_holder = %current_holder, "Another pod is leader, waiting...");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to check leadership, retrying...");
                }
            }

            tokio::time::sleep(self.renew_interval).await;
        }
    }

    /// Spawn a background task that renews the lease periodically.
    ///
    /// If leadership is lost, this task will log an error and exit the process
    /// immediately. Kubernetes will then restart the pod, which will either
    /// re-acquire leadership or wait as a standby.
    ///
    /// Transient failures (network issues, API timeouts) are retried up to
    /// [`MAX_RENEWAL_FAILURES`] times before exiting.
    ///
    /// # Panics
    ///
    /// This function never returns normally - it either runs forever (renewing
    /// the lease) or exits the process on leadership loss.
    pub fn spawn_renewal_task(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.renew_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut consecutive_failures: u32 = 0;

            info!(
                interval_secs = self.renew_interval.as_secs(),
                max_failures = MAX_RENEWAL_FAILURES,
                "Starting lease renewal loop"
            );

            loop {
                interval.tick().await;

                match self.lease_lock.try_acquire_or_renew().await {
                    Ok(result) if result.acquired_lease => {
                        // Successfully renewed - reset failure counter
                        if consecutive_failures > 0 {
                            info!(
                                previous_failures = consecutive_failures,
                                "Lease renewed after transient failures"
                            );
                        }
                        consecutive_failures = 0;
                        tracing::trace!("Lease renewed");
                    }
                    Ok(result) => {
                        // Lost leadership to another pod - this is definitive, exit immediately
                        let new_holder = result
                            .lease
                            .as_ref()
                            .and_then(|l| l.spec.as_ref())
                            .and_then(|s| s.holder_identity.as_ref())
                            .map(|s| s.as_str())
                            .unwrap_or("unknown");
                        error!(
                            new_holder = %new_holder,
                            "Lost leadership to another pod, exiting"
                        );
                        std::process::exit(1);
                    }
                    Err(e) => {
                        // Transient failure - retry up to MAX_RENEWAL_FAILURES times
                        consecutive_failures += 1;
                        if consecutive_failures >= MAX_RENEWAL_FAILURES {
                            error!(
                                error = %e,
                                consecutive_failures = consecutive_failures,
                                max_failures = MAX_RENEWAL_FAILURES,
                                "Failed to renew lease after {} consecutive attempts, exiting",
                                MAX_RENEWAL_FAILURES
                            );
                            std::process::exit(1);
                        }
                        warn!(
                            error = %e,
                            attempt = consecutive_failures,
                            max_attempts = MAX_RENEWAL_FAILURES,
                            "Transient lease renewal failure, will retry"
                        );
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn config_from_env_disabled_by_default() {
        // Clear any existing env vars
        std::env::remove_var("LEADER_ELECTION_ENABLED");

        let config = LeaderElectionConfig::from_env().unwrap();
        assert!(!config.enabled());
    }

    #[test]
    #[serial]
    fn config_from_env_enabled_requires_vars() {
        std::env::set_var("LEADER_ELECTION_ENABLED", "true");
        std::env::remove_var("LEADER_ELECTION_LEASE_NAME");

        let result = LeaderElectionConfig::from_env();
        assert!(result.is_err());

        // Clean up
        std::env::remove_var("LEADER_ELECTION_ENABLED");
    }

    #[test]
    #[serial]
    fn config_from_env_with_all_vars() {
        std::env::set_var("LEADER_ELECTION_ENABLED", "true");
        std::env::set_var("LEADER_ELECTION_LEASE_NAME", "test-lease");
        std::env::set_var("POD_NAMESPACE", "default");
        std::env::set_var("POD_NAME", "test-pod");
        std::env::set_var("LEADER_ELECTION_LEASE_DURATION", "30");
        std::env::set_var("LEADER_ELECTION_RENEW_INTERVAL", "10");

        let config = LeaderElectionConfig::from_env().unwrap();
        assert!(config.enabled());
        assert_eq!(config.lease_name(), "test-lease");
        assert_eq!(config.namespace(), "default");
        assert_eq!(config.holder_id(), "test-pod");
        assert_eq!(config.lease_duration(), Duration::from_secs(30));
        assert_eq!(config.renew_interval(), Duration::from_secs(10));

        // Clean up
        std::env::remove_var("LEADER_ELECTION_ENABLED");
        std::env::remove_var("LEADER_ELECTION_LEASE_NAME");
        std::env::remove_var("POD_NAMESPACE");
        std::env::remove_var("POD_NAME");
        std::env::remove_var("LEADER_ELECTION_LEASE_DURATION");
        std::env::remove_var("LEADER_ELECTION_RENEW_INTERVAL");
    }

    #[test]
    fn config_new_validates_empty_strings() {
        let result = LeaderElectionConfig::new(
            String::new(), // empty lease_name
            "namespace".to_string(),
            "holder".to_string(),
            Duration::from_secs(15),
            Duration::from_secs(5),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("lease_name"));
    }

    #[test]
    fn config_new_validates_duration_relationship() {
        // renew_interval >= lease_duration should fail
        let result = LeaderElectionConfig::new(
            "lease".to_string(),
            "namespace".to_string(),
            "holder".to_string(),
            Duration::from_secs(10),
            Duration::from_secs(15), // greater than lease_duration
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("renew_interval"));
    }

    #[test]
    fn config_new_accepts_valid_config() {
        let result = LeaderElectionConfig::new(
            "lease".to_string(),
            "namespace".to_string(),
            "holder".to_string(),
            Duration::from_secs(15),
            Duration::from_secs(5),
        );
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(config.enabled());
        assert_eq!(config.lease_name(), "lease");
    }

    #[test]
    #[serial]
    fn config_logs_warning_on_invalid_duration() {
        // This test verifies that invalid duration values fall back to defaults
        // The warning log is verified by observation (would need tracing-test for assertion)
        std::env::set_var("LEADER_ELECTION_ENABLED", "true");
        std::env::set_var("LEADER_ELECTION_LEASE_NAME", "test");
        std::env::set_var("POD_NAMESPACE", "default");
        std::env::set_var("POD_NAME", "test-pod");
        std::env::set_var("LEADER_ELECTION_LEASE_DURATION", "invalid");
        std::env::set_var("LEADER_ELECTION_RENEW_INTERVAL", "also-invalid");

        let config = LeaderElectionConfig::from_env().unwrap();
        // Should fall back to defaults
        assert_eq!(config.lease_duration(), Duration::from_secs(15));
        assert_eq!(config.renew_interval(), Duration::from_secs(5));

        // Clean up
        std::env::remove_var("LEADER_ELECTION_ENABLED");
        std::env::remove_var("LEADER_ELECTION_LEASE_NAME");
        std::env::remove_var("POD_NAMESPACE");
        std::env::remove_var("POD_NAME");
        std::env::remove_var("LEADER_ELECTION_LEASE_DURATION");
        std::env::remove_var("LEADER_ELECTION_RENEW_INTERVAL");
    }
}
