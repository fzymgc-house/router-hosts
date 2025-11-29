use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("Invalid hostname: {0}")]
    InvalidHostname(String),
}

pub type ValidationResult<T> = Result<T, ValidationError>;

// DNS label regex: alphanumeric and hyphens, 1-63 chars, no leading/trailing hyphen
static LABEL_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$").unwrap());

/// Validates an IP address (IPv4 or IPv6)
pub fn validate_ip_address(ip: &str) -> ValidationResult<IpAddr> {
    ip.parse::<IpAddr>()
        .map_err(|_| ValidationError::InvalidIpAddress(ip.to_string()))
}

/// Validates a DNS hostname (with or without domain)
/// Rules:
/// - Total length: 1-253 characters (RFC 1035)
/// - Labels separated by dots
/// - Each label: 1-63 chars, alphanumeric and hyphens
/// - Cannot start or end with hyphen
/// - Cannot start or end with dot
pub fn validate_hostname(hostname: &str) -> ValidationResult<String> {
    if hostname.is_empty() {
        return Err(ValidationError::InvalidHostname(
            "hostname cannot be empty".to_string(),
        ));
    }

    // RFC 1035: Maximum hostname length is 253 characters
    if hostname.len() > 253 {
        return Err(ValidationError::InvalidHostname(
            "hostname exceeds maximum length of 253 characters".to_string(),
        ));
    }

    if hostname.starts_with('.') || hostname.ends_with('.') {
        return Err(ValidationError::InvalidHostname(
            "hostname cannot start or end with dot".to_string(),
        ));
    }

    if hostname.starts_with('-') || hostname.ends_with('-') {
        return Err(ValidationError::InvalidHostname(
            "hostname cannot start or end with hyphen".to_string(),
        ));
    }

    for label in hostname.split('.') {
        if !LABEL_REGEX.is_match(label) {
            return Err(ValidationError::InvalidHostname(format!(
                "invalid label '{}' in hostname",
                label
            )));
        }
    }

    Ok(hostname.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ipv4_addresses() {
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("10.0.0.1").is_ok());
        assert!(validate_ip_address("127.0.0.1").is_ok());
        assert!(validate_ip_address("255.255.255.255").is_ok());
    }

    #[test]
    fn test_invalid_ipv4_addresses() {
        assert!(validate_ip_address("256.1.1.1").is_err());
        assert!(validate_ip_address("192.168.1").is_err());
        assert!(validate_ip_address("192.168.1.1.1").is_err());
        assert!(validate_ip_address("not-an-ip").is_err());
        assert!(validate_ip_address("").is_err());
    }

    #[test]
    fn test_valid_ipv6_addresses() {
        assert!(validate_ip_address("::1").is_ok());
        assert!(validate_ip_address("fe80::1").is_ok());
        assert!(validate_ip_address("2001:0db8:85a3::8a2e:0370:7334").is_ok());
        assert!(validate_ip_address("::ffff:192.168.1.1").is_ok());
    }

    #[test]
    fn test_invalid_ipv6_addresses() {
        assert!(validate_ip_address("gggg::1").is_err());
        assert!(validate_ip_address("::::::").is_err());
    }

    #[test]
    fn test_valid_hostnames() {
        assert!(validate_hostname("localhost").is_ok());
        assert!(validate_hostname("server.local").is_ok());
        assert!(validate_hostname("my-server").is_ok());
        assert!(validate_hostname("server123").is_ok());
        assert!(validate_hostname("sub.domain.example.com").is_ok());
    }

    #[test]
    fn test_invalid_hostnames() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-invalid").is_err());
        assert!(validate_hostname("invalid-").is_err());
        assert!(validate_hostname("in..valid").is_err());
        assert!(validate_hostname("invalid_host").is_err()); // underscores not allowed
        assert!(validate_hostname(".invalid").is_err());
        assert!(validate_hostname("invalid.").is_err());
    }

    #[test]
    fn test_hostname_edge_cases() {
        // Single character hostname
        assert!(validate_hostname("a").is_ok());
        assert!(validate_hostname("1").is_ok());

        // Numeric-only hostname (valid but worth testing)
        assert!(validate_hostname("123").is_ok());
        assert!(validate_hostname("123.456").is_ok());

        // Maximum label length (63 characters)
        let max_label = "a".repeat(63);
        assert!(validate_hostname(&max_label).is_ok());

        // Exceeds maximum label length (64 characters)
        let too_long_label = "a".repeat(64);
        assert!(validate_hostname(&too_long_label).is_err());

        // Maximum hostname length (253 characters)
        // Create a hostname with multiple labels totaling 253 chars
        let label = "a".repeat(63);
        let max_hostname = format!("{}.{}.{}.{}", label, label, label, &label[..61]); // 63+1+63+1+63+1+61 = 253
        assert_eq!(max_hostname.len(), 253);
        assert!(validate_hostname(&max_hostname).is_ok());

        // Exceeds maximum hostname length (254 characters)
        let too_long_hostname = format!("{}.{}.{}.{}", label, label, label, &label[..62]); // 254 chars
        assert_eq!(too_long_hostname.len(), 254);
        assert!(validate_hostname(&too_long_hostname).is_err());
    }
}
