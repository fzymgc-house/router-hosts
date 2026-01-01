//! Metric counter helpers

use metrics::{counter, gauge, histogram};
use std::time::{Duration, Instant};
use tracing::info;

/// Record a gRPC request with method and status
pub fn record_request(method: &str, status: &str, duration: Duration) {
    counter!("router_hosts_requests_total", "method" => method.to_string(), "status" => status.to_string()).increment(1);
    histogram!("router_hosts_request_duration_seconds", "method" => method.to_string())
        .record(duration.as_secs_f64());
}

/// Record a storage operation
pub fn record_storage_operation(operation: &str, status: &str, duration: Duration) {
    counter!("router_hosts_storage_operations_total", "operation" => operation.to_string(), "status" => status.to_string()).increment(1);
    histogram!("router_hosts_storage_duration_seconds", "operation" => operation.to_string())
        .record(duration.as_secs_f64());
}

/// Record a hook execution
pub fn record_hook_execution(name: &str, hook_type: &str, status: &str, duration: Duration) {
    counter!("router_hosts_hook_executions_total",
        "name" => name.to_string(),
        "type" => hook_type.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
    histogram!("router_hosts_hook_duration_seconds",
        "name" => name.to_string(),
        "type" => hook_type.to_string()
    )
    .record(duration.as_secs_f64());
}

/// Set the current host entry count gauge
pub fn set_hosts_entries_count(count: u64) {
    gauge!("router_hosts_hosts_entries").set(count as f64);
}

/// RAII guard for timing operations with optional context for access logging
pub struct TimedOperation {
    start: Instant,
    method: String,
    id: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
}

impl TimedOperation {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            method: method.into(),
            id: None,
            hostname: None,
            ip: None,
        }
    }

    /// Set the entity ID for access logging
    pub fn set_id(&mut self, id: impl Into<String>) {
        self.id = Some(id.into());
    }

    /// Set host context for access logging (hostname and/or IP)
    pub fn set_host_context(&mut self, hostname: Option<&str>, ip: Option<&str>) {
        self.hostname = hostname.map(String::from);
        self.ip = ip.map(String::from);
    }

    pub fn finish(self, status: &str) {
        let duration = self.start.elapsed();

        // Build log with available context
        match (&self.id, &self.hostname, &self.ip) {
            (Some(id), Some(hostname), Some(ip)) => {
                info!(
                    method = %self.method,
                    id = %id,
                    hostname = %hostname,
                    ip = %ip,
                    status = %status,
                    duration_ms = %duration.as_millis(),
                    "request"
                );
            }
            (Some(id), Some(hostname), None) => {
                info!(
                    method = %self.method,
                    id = %id,
                    hostname = %hostname,
                    status = %status,
                    duration_ms = %duration.as_millis(),
                    "request"
                );
            }
            (Some(id), None, Some(ip)) => {
                info!(
                    method = %self.method,
                    id = %id,
                    ip = %ip,
                    status = %status,
                    duration_ms = %duration.as_millis(),
                    "request"
                );
            }
            (Some(id), None, None) => {
                info!(
                    method = %self.method,
                    id = %id,
                    status = %status,
                    duration_ms = %duration.as_millis(),
                    "request"
                );
            }
            (None, Some(hostname), Some(ip)) => {
                info!(
                    method = %self.method,
                    hostname = %hostname,
                    ip = %ip,
                    status = %status,
                    duration_ms = %duration.as_millis(),
                    "request"
                );
            }
            (None, Some(hostname), None) => {
                info!(
                    method = %self.method,
                    hostname = %hostname,
                    status = %status,
                    duration_ms = %duration.as_millis(),
                    "request"
                );
            }
            (None, None, Some(ip)) => {
                info!(
                    method = %self.method,
                    ip = %ip,
                    status = %status,
                    duration_ms = %duration.as_millis(),
                    "request"
                );
            }
            (None, None, None) => {
                info!(
                    method = %self.method,
                    status = %status,
                    duration_ms = %duration.as_millis(),
                    "request"
                );
            }
        }

        record_request(&self.method, status, duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timed_operation_records_duration() {
        // Just verify it doesn't panic - actual recording needs prometheus installed
        let op = TimedOperation::new("test_method");
        std::thread::sleep(Duration::from_millis(1));
        op.finish("ok");
    }

    #[test]
    fn test_timed_operation_with_id() {
        let mut op = TimedOperation::new("GetHost");
        op.set_id("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        op.finish("ok");
    }

    #[test]
    fn test_timed_operation_with_host_context() {
        let mut op = TimedOperation::new("AddHost");
        op.set_host_context(Some("example.com"), Some("192.168.1.1"));
        op.finish("ok");
    }

    #[test]
    fn test_timed_operation_with_partial_host_context() {
        let mut op = TimedOperation::new("AddHost");
        op.set_host_context(Some("example.com"), None);
        op.finish("ok");

        let mut op2 = TimedOperation::new("AddHost");
        op2.set_host_context(None, Some("192.168.1.1"));
        op2.finish("ok");
    }

    #[test]
    fn test_timed_operation_with_full_context() {
        let mut op = TimedOperation::new("UpdateHost");
        op.set_id("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        op.set_host_context(Some("example.com"), Some("192.168.1.1"));
        op.finish("ok");
    }

    #[test]
    fn test_timed_operation_error_status() {
        let mut op = TimedOperation::new("DeleteHost");
        op.set_id("01ARZ3NDEKTSV4RRFFQ69G5FAV");
        op.finish("error");
    }
}
