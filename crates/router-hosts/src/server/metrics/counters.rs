//! Metric counter helpers

use metrics::{counter, gauge, histogram};
use std::time::{Duration, Instant};

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

/// RAII guard for timing operations
pub struct TimedOperation {
    start: Instant,
    method: String,
}

impl TimedOperation {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            method: method.into(),
        }
    }

    pub fn finish(self, status: &str) {
        record_request(&self.method, status, self.start.elapsed());
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
}
