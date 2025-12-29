//! Post-edit hook execution
//!
//! Hooks are shell commands that run after hosts file updates.
//!
//! # Failure Behavior
//!
//! Hook failures are logged but do NOT fail the overall operation by default.
//! This is intentional - the hosts file update has already succeeded, and
//! failing the operation would leave the system in an inconsistent state.
//!
//! Callers can check the returned failure count and take action if needed.
//! For critical hooks (e.g., DNS reload), consider:
//! - Monitoring logs for hook failures
//! - Using external health checks
//! - Implementing retry logic in the hook script itself

use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn};

use super::config::HookDefinition;

#[derive(Debug, Error)]
pub enum HookError {
    #[error("Hook timed out after {0} seconds")]
    Timeout(u64),

    #[error("Hook failed with exit code {0}: {1}")]
    Failed(i32, String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct HookExecutor {
    on_success: Vec<HookDefinition>,
    on_failure: Vec<HookDefinition>,
    timeout_secs: u64,
}

impl HookExecutor {
    pub fn new(
        on_success: Vec<HookDefinition>,
        on_failure: Vec<HookDefinition>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            on_success,
            on_failure,
            timeout_secs,
        }
    }

    /// Get names of all configured hooks for health reporting
    ///
    /// Returns both success and failure hooks with prefixes indicating their type.
    /// Uses the explicit hook names from configuration, which are safe to expose
    /// as they don't contain sensitive command details.
    pub fn hook_names(&self) -> Vec<String> {
        let mut names = Vec::with_capacity(self.on_success.len() + self.on_failure.len());
        for hook in &self.on_success {
            names.push(format!("on_success: {}", hook.name));
        }
        for hook in &self.on_failure {
            names.push(format!("on_failure: {}", hook.name));
        }
        names
    }

    /// Get count of configured hooks
    pub fn hook_count(&self) -> usize {
        self.on_success.len() + self.on_failure.len()
    }

    /// Run success hooks after successful hosts file regeneration
    ///
    /// Returns the number of hooks that failed. Callers can use this for
    /// observability or to take corrective action.
    pub async fn run_success(&self, entry_count: usize) -> usize {
        let mut failures = 0;
        for hook in &self.on_success {
            if let Err(e) = self.run_hook(hook, "success", entry_count).await {
                error!(
                    hook_name = %hook.name,
                    error = %e,
                    "Success hook failed - hosts file was updated but hook did not run successfully"
                );
                failures += 1;
            }
        }
        if failures > 0 {
            warn!(
                total_hooks = self.on_success.len(),
                failed_hooks = failures,
                "Some success hooks failed - check logs for details"
            );
        }
        failures
    }

    /// Run failure hooks after failed hosts file regeneration
    ///
    /// Returns the number of hooks that failed. Callers can use this for
    /// observability or to take corrective action.
    pub async fn run_failure(&self, entry_count: usize, error: &str) -> usize {
        let mut failures = 0;
        for hook in &self.on_failure {
            if let Err(e) = self
                .run_hook_with_error(hook, "failure", entry_count, error)
                .await
            {
                error!(
                    hook_name = %hook.name,
                    error = %e,
                    original_error = %error,
                    "Failure hook failed - hosts file regeneration failed and hook also failed"
                );
                failures += 1;
            }
        }
        if failures > 0 {
            warn!(
                total_hooks = self.on_failure.len(),
                failed_hooks = failures,
                "Some failure hooks failed - check logs for details"
            );
        }
        failures
    }

    async fn run_hook(
        &self,
        hook: &HookDefinition,
        event: &str,
        entry_count: usize,
    ) -> Result<(), HookError> {
        self.run_hook_with_error(hook, event, entry_count, "").await
    }

    async fn run_hook_with_error(
        &self,
        hook: &HookDefinition,
        event: &str,
        entry_count: usize,
        error_msg: &str,
    ) -> Result<(), HookError> {
        info!(hook_name = %hook.name, "Running hook");

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&hook.command)
            .env("ROUTER_HOSTS_EVENT", event)
            .env("ROUTER_HOSTS_ENTRY_COUNT", entry_count.to_string())
            .env("ROUTER_HOSTS_ERROR", error_msg)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let result = timeout(Duration::from_secs(self.timeout_secs), child.wait()).await;

        match result {
            Ok(Ok(status)) => {
                if status.success() {
                    info!(hook_name = %hook.name, "Hook completed successfully");
                    Ok(())
                } else {
                    let code = status.code().unwrap_or(-1);
                    error!(hook_name = %hook.name, exit_code = code, "Hook failed");
                    Err(HookError::Failed(code, hook.name.clone()))
                }
            }
            Ok(Err(e)) => {
                error!(
                    hook_name = %hook.name,
                    error = %e,
                    "Hook failed to wait for process"
                );
                Err(HookError::Io(e))
            }
            Err(_) => {
                if let Err(kill_err) = child.kill().await {
                    warn!(
                        hook_name = %hook.name,
                        error = %kill_err,
                        "Failed to kill timed out hook process"
                    );
                }
                error!(hook_name = %hook.name, "Hook timed out");
                Err(HookError::Timeout(self.timeout_secs))
            }
        }
    }
}

impl Default for HookExecutor {
    fn default() -> Self {
        Self::new(vec![], vec![], 30)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a HookDefinition for tests
    fn hook(name: &str, command: &str) -> HookDefinition {
        HookDefinition {
            name: name.to_string(),
            command: command.to_string(),
        }
    }

    #[tokio::test]
    async fn test_run_success_hook() {
        let executor = HookExecutor::new(vec![hook("log-success", "echo success")], vec![], 5);
        executor.run_success(10).await;
        // Should complete without error
    }

    #[tokio::test]
    async fn test_hook_with_env_vars() {
        let executor = HookExecutor::new(
            vec![hook(
                "check-event",
                "test \"$ROUTER_HOSTS_EVENT\" = \"success\"",
            )],
            vec![],
            5,
        );
        executor.run_success(10).await;
        // Should complete without error (env var is set correctly)
    }

    #[tokio::test]
    async fn test_hook_timeout() {
        let executor = HookExecutor::new(vec![hook("slow-hook", "sleep 10")], vec![], 1);
        // This will timeout but continue
        executor.run_success(10).await;
    }

    #[tokio::test]
    async fn test_empty_hooks() {
        let executor = HookExecutor::default();
        executor.run_success(0).await;
        executor.run_failure(0, "test error").await;
        // Should complete immediately with no hooks
    }

    #[tokio::test]
    async fn test_success_hook_failure() {
        let executor = HookExecutor::new(vec![hook("fail-hook", "exit 1")], vec![], 5);
        let failures = executor.run_success(10).await;
        assert_eq!(failures, 1, "Should report 1 failed hook");
    }

    #[tokio::test]
    async fn test_multiple_success_hooks_partial_failure() {
        let executor = HookExecutor::new(
            vec![
                hook("success1", "echo success1"),
                hook("fail1", "exit 1"),
                hook("success3", "echo success3"),
                hook("fail2", "exit 2"),
            ],
            vec![],
            5,
        );
        let failures = executor.run_success(10).await;
        assert_eq!(failures, 2, "Should report 2 failed hooks out of 4");
    }

    #[tokio::test]
    async fn test_run_failure_hooks() {
        let executor = HookExecutor::new(
            vec![],
            vec![hook(
                "check-error",
                "test \"$ROUTER_HOSTS_ERROR\" = \"test error\"",
            )],
            5,
        );
        let failures = executor.run_failure(10, "test error").await;
        assert_eq!(
            failures, 0,
            "Failure hook should succeed with correct error env var"
        );
    }

    #[tokio::test]
    async fn test_failure_hook_failure() {
        let executor = HookExecutor::new(vec![], vec![hook("fail-hook", "exit 1")], 5);
        let failures = executor.run_failure(10, "original error").await;
        assert_eq!(failures, 1, "Should report 1 failed failure hook");
    }

    #[tokio::test]
    async fn test_multiple_failure_hooks_partial_failure() {
        let executor = HookExecutor::new(
            vec![],
            vec![
                hook("failure1", "echo failure1"),
                hook("fail", "exit 1"),
                hook("failure3", "echo failure3"),
            ],
            5,
        );
        let failures = executor.run_failure(10, "test error").await;
        assert_eq!(failures, 1, "Should report 1 failed hook out of 3");
    }

    /// Test that ROUTER_HOSTS_ENTRY_COUNT environment variable is set correctly
    #[tokio::test]
    async fn test_entry_count_env_var() {
        let executor = HookExecutor::new(
            vec![hook(
                "check-count",
                "test \"$ROUTER_HOSTS_ENTRY_COUNT\" = \"42\"",
            )],
            vec![],
            5,
        );
        let failures = executor.run_success(42).await;
        assert_eq!(
            failures, 0,
            "Hook should succeed with correct entry count env var"
        );
    }

    /// Test all environment variables are set correctly for success hooks
    #[tokio::test]
    async fn test_all_env_vars_success_hook() {
        // This script checks all env vars are set correctly
        let script = r#"
            test "$ROUTER_HOSTS_EVENT" = "success" && \
            test "$ROUTER_HOSTS_ENTRY_COUNT" = "100" && \
            test -z "$ROUTER_HOSTS_ERROR"
        "#;
        let executor = HookExecutor::new(vec![hook("check-all-vars", script)], vec![], 5);
        let failures = executor.run_success(100).await;
        assert_eq!(
            failures, 0,
            "All env vars should be set correctly for success"
        );
    }

    /// Test all environment variables are set correctly for failure hooks
    #[tokio::test]
    async fn test_all_env_vars_failure_hook() {
        // This script checks all env vars are set correctly
        let script = r#"
            test "$ROUTER_HOSTS_EVENT" = "failure" && \
            test "$ROUTER_HOSTS_ENTRY_COUNT" = "50" && \
            test "$ROUTER_HOSTS_ERROR" = "Database connection failed"
        "#;
        let executor = HookExecutor::new(vec![], vec![hook("check-all-vars", script)], 5);
        let failures = executor.run_failure(50, "Database connection failed").await;
        assert_eq!(
            failures, 0,
            "All env vars should be set correctly for failure"
        );
    }

    /// Test hook timeout returns correct failure count
    #[tokio::test]
    async fn test_hook_timeout_returns_failure() {
        let executor = HookExecutor::new(vec![hook("slow-hook", "sleep 10")], vec![], 1);
        let failures = executor.run_success(10).await;
        assert_eq!(failures, 1, "Timed out hook should count as failure");
    }

    /// Test hooks run sequentially (order preserved)
    #[tokio::test]
    async fn test_hooks_run_sequentially() {
        // Create a temp file to track execution order
        let temp_dir = std::env::temp_dir();
        let order_file = temp_dir.join("hook_order_test");

        // Clean up from previous runs
        let _ = std::fs::remove_file(&order_file);

        // Use printf for portable output without newlines
        let executor = HookExecutor::new(
            vec![
                hook("hook1", &format!("printf '1' >> {}", order_file.display())),
                hook("hook2", &format!("printf '2' >> {}", order_file.display())),
                hook("hook3", &format!("printf '3' >> {}", order_file.display())),
            ],
            vec![],
            5,
        );

        let failures = executor.run_success(10).await;
        assert_eq!(failures, 0, "All hooks should succeed");

        // Verify order
        let content = std::fs::read_to_string(&order_file).unwrap_or_default();
        assert_eq!(content, "123", "Hooks should run in order");

        // Cleanup
        let _ = std::fs::remove_file(&order_file);
    }

    #[test]
    fn test_hook_error_display() {
        let err = HookError::Timeout(30);
        assert!(err.to_string().contains("30"));

        let err = HookError::Failed(1, "test-hook".to_string());
        assert!(err.to_string().contains("1"));
        assert!(err.to_string().contains("test-hook"));
    }

    #[test]
    fn test_hook_names_empty() {
        let executor = HookExecutor::default();
        assert!(executor.hook_names().is_empty());
        assert_eq!(executor.hook_count(), 0);
    }

    #[test]
    fn test_hook_names_success_only() {
        let executor = HookExecutor::new(
            vec![
                hook("reload-dns", "/usr/bin/reload-dns --config /etc/dns.conf"),
                hook("log-success", "logger 'hosts updated'"),
            ],
            vec![],
            5,
        );
        let names = executor.hook_names();
        assert_eq!(names.len(), 2);
        // Returns explicit hook names, not sanitized command basenames
        assert_eq!(names[0], "on_success: reload-dns");
        assert_eq!(names[1], "on_success: log-success");
        assert_eq!(executor.hook_count(), 2);
    }

    #[test]
    fn test_hook_names_failure_only() {
        let executor = HookExecutor::new(vec![], vec![hook("alert-ops", "notify failure")], 5);
        let names = executor.hook_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "on_failure: alert-ops");
        assert_eq!(executor.hook_count(), 1);
    }

    #[test]
    fn test_hook_names_both_types() {
        let executor = HookExecutor::new(
            vec![hook("success-hook", "echo success")],
            vec![
                hook("failure-hook-1", "echo fail1"),
                hook("failure-hook-2", "echo fail2"),
            ],
            5,
        );
        let names = executor.hook_names();
        assert_eq!(names.len(), 3);
        assert_eq!(names[0], "on_success: success-hook");
        assert_eq!(names[1], "on_failure: failure-hook-1");
        assert_eq!(names[2], "on_failure: failure-hook-2");
        assert_eq!(executor.hook_count(), 3);
    }
}
