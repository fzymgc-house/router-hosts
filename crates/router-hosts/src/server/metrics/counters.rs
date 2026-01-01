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

/// Maximum length for logged fields to prevent log flooding
const MAX_LOG_FIELD_LEN: usize = 256;

/// Sanitize user input for safe logging
///
/// Prevents log injection attacks by:
/// - Removing/replacing control characters (including newlines)
/// - Truncating excessive length
/// - Escaping special characters that could break log parsers
fn sanitize_for_log(input: &str) -> String {
    // Count chars, not bytes - important for multi-byte UTF-8 (e.g., emojis, CJK)
    let char_count = input.chars().count();
    let truncated = char_count > MAX_LOG_FIELD_LEN;

    let sanitized: String = input
        .chars()
        .take(MAX_LOG_FIELD_LEN)
        .map(|c| {
            // is_control() covers ASCII control chars including \n, \r, \t
            if c.is_control() {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect();

    if truncated {
        format!("{}...", sanitized)
    } else {
        sanitized
    }
}

/// RAII guard for timing operations with optional context for access logging
pub struct TimedOperation {
    start: Instant,
    method: String,
    id: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    query: Option<String>,
}

impl TimedOperation {
    pub fn new(method: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            method: method.into(),
            id: None,
            hostname: None,
            ip: None,
            query: None,
        }
    }

    /// Set the entity ID for access logging (sanitized to prevent log injection)
    pub fn set_id(&mut self, id: impl Into<String>) {
        self.id = Some(sanitize_for_log(&id.into()));
    }

    /// Set host context for access logging (sanitized to prevent log injection)
    pub fn set_host_context(&mut self, hostname: Option<&str>, ip: Option<&str>) {
        self.hostname = hostname.map(sanitize_for_log);
        self.ip = ip.map(sanitize_for_log);
    }

    /// Set search query for access logging (sanitized to prevent log injection)
    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = Some(sanitize_for_log(&query.into()));
    }

    pub fn finish(self, status: &str) {
        let duration = self.start.elapsed();

        // Local macro to emit structured log with variable optional fields
        // Handles query separately to avoid exponential match arm growth
        macro_rules! log_request {
            ($($field:ident = $val:expr),* $(,)?) => {
                if let Some(query) = &self.query {
                    info!(
                        method = %self.method,
                        $($field = %$val,)*
                        query = %query,
                        status = %status,
                        duration_ms = %duration.as_millis(),
                        "request"
                    )
                } else {
                    info!(
                        method = %self.method,
                        $($field = %$val,)*
                        status = %status,
                        duration_ms = %duration.as_millis(),
                        "request"
                    )
                }
            };
        }

        // Log with whichever context fields are available
        match (&self.id, &self.hostname, &self.ip) {
            (Some(id), Some(hostname), Some(ip)) => {
                log_request!(id = id, hostname = hostname, ip = ip)
            }
            (Some(id), Some(hostname), None) => log_request!(id = id, hostname = hostname),
            (Some(id), None, Some(ip)) => log_request!(id = id, ip = ip),
            (Some(id), None, None) => log_request!(id = id),
            (None, Some(hostname), Some(ip)) => log_request!(hostname = hostname, ip = ip),
            (None, Some(hostname), None) => log_request!(hostname = hostname),
            (None, None, Some(ip)) => log_request!(ip = ip),
            (None, None, None) => log_request!(),
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
    fn test_timed_operation_with_hostname_only() {
        let mut op = TimedOperation::new("AddHost");
        op.set_host_context(Some("example.com"), None);
        op.finish("ok");
    }

    #[test]
    fn test_timed_operation_with_ip_only() {
        let mut op = TimedOperation::new("SomeMethod");
        op.set_host_context(None, Some("192.168.1.1"));
        op.finish("ok");
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

    #[test]
    fn test_timed_operation_with_query() {
        let mut op = TimedOperation::new("SearchHosts");
        op.set_query("*.example.com");
        op.finish("ok");
    }

    #[test]
    fn test_sanitize_for_log_normal_input() {
        assert_eq!(sanitize_for_log("normal-input"), "normal-input");
    }

    #[test]
    fn test_sanitize_for_log_newlines() {
        let input = "line1\nline2\rline3";
        let result = sanitize_for_log(input);
        assert!(!result.contains('\n'));
        assert!(!result.contains('\r'));
        assert!(result.contains('\u{FFFD}')); // replacement char
    }

    #[test]
    fn test_sanitize_for_log_control_chars() {
        let input = "prefix\x00\x1f\x7fsuffix";
        let result = sanitize_for_log(input);
        assert!(!result.contains('\x00'));
        assert!(!result.contains('\x1f'));
        assert!(!result.contains('\x7f'));
    }

    #[test]
    fn test_sanitize_for_log_truncation() {
        let long_input = "a".repeat(500);
        let result = sanitize_for_log(&long_input);
        // Result should be 256 chars + "..."
        assert_eq!(result.chars().count(), MAX_LOG_FIELD_LEN + 3);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_sanitize_for_log_multibyte_utf8() {
        // Emoji is 4 bytes but 1 char - verify we count chars not bytes
        let emoji_input = "🎉".repeat(300); // 300 emojis = 300 chars but 1200 bytes
        let result = sanitize_for_log(&emoji_input);

        // Should truncate to 256 chars (emojis) + "..."
        assert_eq!(result.chars().count(), MAX_LOG_FIELD_LEN + 3);
        assert!(result.ends_with("..."));

        // Verify the truncated portion contains only emojis (no partial UTF-8)
        let without_ellipsis = &result[..result.len() - 3];
        assert!(without_ellipsis.chars().all(|c| c == '🎉'));
    }

    #[test]
    fn test_sanitize_for_log_mixed_multibyte() {
        // Mix of ASCII and multi-byte chars at boundary
        let input = format!("{}{}", "a".repeat(250), "日本語テスト"); // 250 ASCII + 6 CJK = 256 chars
        let result = sanitize_for_log(&input);

        // Exactly at limit, no truncation
        assert!(!result.ends_with("..."));
        assert_eq!(result.chars().count(), 256);
    }

    #[test]
    fn test_timed_operation_with_malicious_id() {
        let mut op = TimedOperation::new("GetHost");
        // Attempt log injection with newline
        op.set_id("valid-id\n{\"malicious\": \"json\"}");
        op.finish("ok");
        // Test passes if no panic - sanitization happens internally
    }
}
