//! Traefik match expression parser
//!
//! Extracts hostnames from Traefik match expressions like:
//! - `Host(`foo.example.com`)`
//! - `Host(`a.com`) || Host(`b.com`)`
//! - `HostSNI(`db.example.com`)`

use regex::Regex;
use std::sync::LazyLock;

static HOST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Host\(`([^`]+)`\)").expect("valid regex"));

static HOST_SNI_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"HostSNI\(`([^`]+)`\)").expect("valid regex"));

/// Extract all hostnames from a Traefik match expression.
///
/// Handles both `Host()` and `HostSNI()` matchers.
/// Complex boolean logic is ignored - all host values are extracted.
pub fn extract_hosts(match_expr: &str) -> Vec<String> {
    let mut hosts = Vec::new();

    for cap in HOST_REGEX.captures_iter(match_expr) {
        if let Some(host) = cap.get(1) {
            hosts.push(host.as_str().to_string());
        }
    }

    for cap in HOST_SNI_REGEX.captures_iter(match_expr) {
        if let Some(host) = cap.get(1) {
            hosts.push(host.as_str().to_string());
        }
    }

    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_host() {
        let expr = "Host(`foo.example.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["foo.example.com"]);
    }

    #[test]
    fn test_multiple_hosts_or() {
        let expr = "Host(`a.com`) || Host(`b.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_host_with_path_prefix() {
        let expr = "Host(`api.example.com`) && PathPrefix(`/v1`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["api.example.com"]);
    }

    #[test]
    fn test_host_sni() {
        let expr = "HostSNI(`db.example.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["db.example.com"]);
    }

    #[test]
    fn test_mixed_host_and_sni() {
        let expr = "Host(`web.example.com`) || HostSNI(`db.example.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["web.example.com", "db.example.com"]);
    }

    #[test]
    fn test_complex_expression() {
        let expr = "(Host(`a.com`) || Host(`b.com`)) && PathPrefix(`/api`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["a.com", "b.com"]);
    }

    #[test]
    fn test_no_hosts() {
        let expr = "PathPrefix(`/api`)";
        let hosts = extract_hosts(expr);
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_empty_expression() {
        let hosts = extract_hosts("");
        assert!(hosts.is_empty());
    }

    #[test]
    fn test_subdomain() {
        let expr = "Host(`app.staging.example.com`)";
        let hosts = extract_hosts(expr);
        assert_eq!(hosts, vec!["app.staging.example.com"]);
    }
}
