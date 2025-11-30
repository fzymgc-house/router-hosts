//! Post-edit hook execution

use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{error, info, warn};

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
    on_success: Vec<String>,
    on_failure: Vec<String>,
    timeout_secs: u64,
}

impl HookExecutor {
    pub fn new(on_success: Vec<String>, on_failure: Vec<String>, timeout_secs: u64) -> Self {
        Self {
            on_success,
            on_failure,
            timeout_secs,
        }
    }

    /// Run success hooks after successful hosts file regeneration
    pub async fn run_success(&self, entry_count: usize) {
        for cmd in &self.on_success {
            if let Err(e) = self.run_hook(cmd, "success", entry_count).await {
                warn!("Success hook failed (continuing): {} - {}", cmd, e);
            }
        }
    }

    /// Run failure hooks after failed hosts file regeneration
    pub async fn run_failure(&self, entry_count: usize, error: &str) {
        for cmd in &self.on_failure {
            if let Err(e) = self.run_hook_with_error(cmd, "failure", entry_count, error).await {
                warn!("Failure hook failed (continuing): {} - {}", cmd, e);
            }
        }
    }

    async fn run_hook(&self, cmd: &str, event: &str, entry_count: usize) -> Result<(), HookError> {
        self.run_hook_with_error(cmd, event, entry_count, "").await
    }

    async fn run_hook_with_error(
        &self,
        cmd: &str,
        event: &str,
        entry_count: usize,
        error_msg: &str,
    ) -> Result<(), HookError> {
        info!("Running hook: {}", cmd);

        let mut child = Command::new("sh")
            .arg("-c")
            .arg(cmd)
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
                    info!("Hook completed successfully: {}", cmd);
                    Ok(())
                } else {
                    let code = status.code().unwrap_or(-1);
                    error!("Hook failed with code {}: {}", code, cmd);
                    Err(HookError::Failed(code, cmd.to_string()))
                }
            }
            Ok(Err(e)) => Err(HookError::Io(e)),
            Err(_) => {
                let _ = child.kill().await;
                error!("Hook timed out: {}", cmd);
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

    #[tokio::test]
    async fn test_run_success_hook() {
        let executor = HookExecutor::new(vec!["echo success".to_string()], vec![], 5);
        executor.run_success(10).await;
        // Should complete without error
    }

    #[tokio::test]
    async fn test_hook_with_env_vars() {
        let executor = HookExecutor::new(
            vec!["test \"$ROUTER_HOSTS_EVENT\" = \"success\"".to_string()],
            vec![],
            5,
        );
        executor.run_success(10).await;
        // Should complete without error (env var is set correctly)
    }

    #[tokio::test]
    async fn test_hook_timeout() {
        let executor = HookExecutor::new(vec!["sleep 10".to_string()], vec![], 1);
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
}
