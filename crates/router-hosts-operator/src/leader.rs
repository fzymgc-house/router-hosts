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

use anyhow::{Context, Result};
use kube::Client;
use kube_leader_election::{LeaseLock, LeaseLockParams};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// Configuration for leader election.
#[derive(Debug, Clone)]
pub struct LeaderElectionConfig {
    /// Whether leader election is enabled.
    pub enabled: bool,
    /// Name of the Lease resource.
    pub lease_name: String,
    /// Namespace for the Lease resource.
    pub namespace: String,
    /// Identity of this pod (from POD_NAME env var).
    pub holder_id: String,
    /// Time before lease expires if not renewed.
    pub lease_duration: Duration,
    /// How often to renew the lease.
    pub renew_interval: Duration,
}

impl LeaderElectionConfig {
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
            return Ok(Self {
                enabled: false,
                lease_name: String::new(),
                namespace: String::new(),
                holder_id: String::new(),
                lease_duration: Duration::from_secs(15),
                renew_interval: Duration::from_secs(5),
            });
        }

        let lease_name = std::env::var("LEADER_ELECTION_LEASE_NAME")
            .context("LEADER_ELECTION_LEASE_NAME required when leader election is enabled")?;

        let namespace = std::env::var("POD_NAMESPACE")
            .context("POD_NAMESPACE required when leader election is enabled")?;

        let holder_id = std::env::var("POD_NAME")
            .context("POD_NAME required when leader election is enabled")?;

        let lease_duration = std::env::var("LEADER_ELECTION_LEASE_DURATION")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(15));

        let renew_interval = std::env::var("LEADER_ELECTION_RENEW_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(5));

        Ok(Self {
            enabled,
            lease_name,
            namespace,
            holder_id,
            lease_duration,
            renew_interval,
        })
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
            &config.namespace,
            LeaseLockParams {
                holder_id: config.holder_id.clone(),
                lease_name: config.lease_name.clone(),
                lease_ttl: config.lease_duration,
            },
        );

        Self {
            lease_lock,
            renew_interval: config.renew_interval,
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
    /// # Panics
    ///
    /// This function never returns normally - it either runs forever (renewing
    /// the lease) or exits the process on leadership loss.
    pub fn spawn_renewal_task(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.renew_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            info!(
                interval_secs = self.renew_interval.as_secs(),
                "Starting lease renewal loop"
            );

            loop {
                interval.tick().await;

                match self.lease_lock.try_acquire_or_renew().await {
                    Ok(result) if result.acquired_lease => {
                        // Successfully renewed
                        tracing::trace!("Lease renewed");
                    }
                    Ok(result) => {
                        // Lost leadership to another pod
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
                        // Failed to renew - this could be transient, but if repeated
                        // it means we've lost the lease
                        error!(error = %e, "Failed to renew lease, exiting");
                        std::process::exit(1);
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_env_disabled_by_default() {
        // Clear any existing env vars
        std::env::remove_var("LEADER_ELECTION_ENABLED");

        let config = LeaderElectionConfig::from_env().unwrap();
        assert!(!config.enabled);
    }

    #[test]
    fn config_from_env_enabled_requires_vars() {
        std::env::set_var("LEADER_ELECTION_ENABLED", "true");
        std::env::remove_var("LEADER_ELECTION_LEASE_NAME");

        let result = LeaderElectionConfig::from_env();
        assert!(result.is_err());

        // Clean up
        std::env::remove_var("LEADER_ELECTION_ENABLED");
    }

    #[test]
    fn config_from_env_with_all_vars() {
        std::env::set_var("LEADER_ELECTION_ENABLED", "true");
        std::env::set_var("LEADER_ELECTION_LEASE_NAME", "test-lease");
        std::env::set_var("POD_NAMESPACE", "default");
        std::env::set_var("POD_NAME", "test-pod");
        std::env::set_var("LEADER_ELECTION_LEASE_DURATION", "30");
        std::env::set_var("LEADER_ELECTION_RENEW_INTERVAL", "10");

        let config = LeaderElectionConfig::from_env().unwrap();
        assert!(config.enabled);
        assert_eq!(config.lease_name, "test-lease");
        assert_eq!(config.namespace, "default");
        assert_eq!(config.holder_id, "test-pod");
        assert_eq!(config.lease_duration, Duration::from_secs(30));
        assert_eq!(config.renew_interval, Duration::from_secs(10));

        // Clean up
        std::env::remove_var("LEADER_ELECTION_ENABLED");
        std::env::remove_var("LEADER_ELECTION_LEASE_NAME");
        std::env::remove_var("POD_NAMESPACE");
        std::env::remove_var("POD_NAME");
        std::env::remove_var("LEADER_ELECTION_LEASE_DURATION");
        std::env::remove_var("LEADER_ELECTION_RENEW_INTERVAL");
    }
}
