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

    #[error("Alias '{0}' matches canonical hostname")]
    AliasMatchesHostname(String),

    #[error("Duplicate alias '{0}' in entry")]
    DuplicateAlias(String),
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
        // Explicitly check for empty labels (consecutive dots like "example..com")
        // Note: LABEL_REGEX would also reject this, but explicit check is clearer
        if label.is_empty() {
            return Err(ValidationError::InvalidHostname(
                "hostname cannot contain consecutive dots".to_string(),
            ));
        }

        if !LABEL_REGEX.is_match(label) {
            return Err(ValidationError::InvalidHostname(format!(
                "invalid label '{}' in hostname",
                label
            )));
        }
    }

    Ok(hostname.to_string())
}

/// Validate a single alias (same rules as hostname)
pub fn validate_alias(alias: &str) -> Result<(), ValidationError> {
    validate_hostname(alias)?;
    Ok(())
}

/// Validate alias list for a host entry
pub fn validate_aliases(
    aliases: &[String],
    canonical_hostname: &str,
) -> Result<(), ValidationError> {
    use std::collections::HashSet;

    let mut seen = HashSet::new();

    for alias in aliases {
        // Same validation as hostname
        validate_alias(alias)?;

        // Cannot match canonical hostname
        if alias.eq_ignore_ascii_case(canonical_hostname) {
            return Err(ValidationError::AliasMatchesHostname(alias.clone()));
        }

        // No duplicates within entry (case-insensitive)
        let lower = alias.to_lowercase();
        if !seen.insert(lower) {
            return Err(ValidationError::DuplicateAlias(alias.clone()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ==========================================================================
    // Property-based tests with proptest
    // ==========================================================================

    proptest! {
        /// Any valid IPv4 address string should parse successfully
        #[test]
        fn prop_valid_ipv4_parses(
            a in 0u8..=255,
            b in 0u8..=255,
            c in 0u8..=255,
            d in 0u8..=255,
        ) {
            let ip = format!("{}.{}.{}.{}", a, b, c, d);
            prop_assert!(validate_ip_address(&ip).is_ok(), "Failed to validate: {}", ip);
        }

        /// Any valid full IPv6 address should parse successfully
        #[test]
        fn prop_valid_ipv6_parses(
            a in 0u16..=0xFFFF,
            b in 0u16..=0xFFFF,
            c in 0u16..=0xFFFF,
            d in 0u16..=0xFFFF,
            e in 0u16..=0xFFFF,
            f in 0u16..=0xFFFF,
            g in 0u16..=0xFFFF,
            h in 0u16..=0xFFFF,
        ) {
            let ip = format!("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}", a, b, c, d, e, f, g, h);
            prop_assert!(validate_ip_address(&ip).is_ok(), "Failed to validate: {}", ip);
        }

        /// Compressed IPv6 addresses (using ::) should parse successfully
        #[test]
        fn prop_compressed_ipv6_parses(
            prefix in 0u16..=0xFFFF,
            suffix in 0u16..=0xFFFF,
        ) {
            // Test :: compression in middle (e.g., fe80::1)
            let ip_middle = format!("{:x}::{:x}", prefix, suffix);
            prop_assert!(validate_ip_address(&ip_middle).is_ok(), "Failed middle compression: {}", ip_middle);

            // Test leading :: (e.g., ::1, ::ffff)
            let ip_leading = format!("::{:x}", suffix);
            prop_assert!(validate_ip_address(&ip_leading).is_ok(), "Failed leading compression: {}", ip_leading);

            // Test trailing :: (e.g., fe80::)
            let ip_trailing = format!("{:x}::", prefix);
            prop_assert!(validate_ip_address(&ip_trailing).is_ok(), "Failed trailing compression: {}", ip_trailing);
        }

        /// Valid single-label hostnames (1-63 alphanumeric chars, no leading/trailing hyphen)
        #[test]
        fn prop_valid_single_label_hostname(
            // Start with alphanumeric
            first in "[a-zA-Z0-9]",
            // Middle can be alphanumeric or hyphens (0-61 chars to stay under 63 total)
            middle in "[a-zA-Z0-9-]{0,61}",
        ) {
            // Build hostname ensuring no trailing hyphen
            let hostname = if middle.is_empty() {
                first.to_string()
            } else if middle.ends_with('-') {
                // Ensure no trailing hyphen by appending alphanumeric
                format!("{}{}a", first, middle)
            } else {
                format!("{}{}", first, middle)
            };

            // Skip if too long (edge case from middle + suffix)
            if hostname.len() <= 63 {
                prop_assert!(
                    validate_hostname(&hostname).is_ok(),
                    "Failed to validate single label: {}",
                    hostname
                );
            }
        }

        /// Valid multi-label hostnames (e.g., sub.domain.com)
        #[test]
        fn prop_valid_multi_label_hostname(
            label1 in "[a-zA-Z0-9][a-zA-Z0-9]{0,10}",
            label2 in "[a-zA-Z0-9][a-zA-Z0-9]{0,10}",
            label3 in "[a-zA-Z0-9][a-zA-Z0-9]{0,5}",
        ) {
            let hostname = format!("{}.{}.{}", label1, label2, label3);
            prop_assert!(
                validate_hostname(&hostname).is_ok(),
                "Failed to validate multi-label: {}",
                hostname
            );
        }

        /// IP validation is consistent (same input always gives same result)
        #[test]
        fn prop_ip_validation_consistent(ip in ".*") {
            let result1 = validate_ip_address(&ip).is_ok();
            let result2 = validate_ip_address(&ip).is_ok();
            prop_assert_eq!(result1, result2, "Inconsistent validation for: {}", ip);
        }

        /// Hostname validation is consistent (same input always gives same result)
        #[test]
        fn prop_hostname_validation_consistent(hostname in ".*") {
            let result1 = validate_hostname(&hostname).is_ok();
            let result2 = validate_hostname(&hostname).is_ok();
            prop_assert_eq!(result1, result2, "Inconsistent validation for: {}", hostname);
        }

        /// Empty strings always fail IP validation
        #[test]
        fn prop_empty_ip_fails(spaces in " *") {
            prop_assert!(
                validate_ip_address(&spaces).is_err(),
                "Empty/whitespace should fail: '{}'",
                spaces
            );
        }

        /// Hostnames with underscores always fail (common mistake)
        #[test]
        fn prop_underscore_hostname_fails(
            prefix in "[a-z]{1,5}",
            suffix in "[a-z]{1,5}",
        ) {
            let hostname = format!("{}_{}",  prefix, suffix);
            prop_assert!(
                validate_hostname(&hostname).is_err(),
                "Underscore hostname should fail: {}",
                hostname
            );
        }

        /// Hostnames exceeding 253 chars always fail
        #[test]
        fn prop_oversized_hostname_fails(
            // Generate labels that will exceed 253 chars when combined
            label in "[a-z]{60,63}",
        ) {
            // Create a hostname > 253 chars using repeated labels
            let hostname = format!("{}.{}.{}.{}.{}", label, label, label, label, label);
            if hostname.len() > 253 {
                prop_assert!(
                    validate_hostname(&hostname).is_err(),
                    "Oversized hostname should fail: {} (len={})",
                    hostname,
                    hostname.len()
                );
            }
        }
    }

    // ==========================================================================
    // Traditional unit tests
    // ==========================================================================

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

#[cfg(test)]
mod alias_tests {
    use super::*;

    #[test]
    fn test_validate_alias_same_as_hostname() {
        // Valid hostname = valid alias
        assert!(validate_alias("server.local").is_ok());
        assert!(validate_alias("srv").is_ok());

        // Invalid hostname = invalid alias
        assert!(validate_alias("").is_err());
        assert!(validate_alias("-invalid").is_err());
    }

    #[test]
    fn test_validate_aliases_empty_allowed() {
        assert!(validate_aliases(&[], "server.local").is_ok());
    }

    #[test]
    fn test_validate_aliases_valid() {
        let aliases = vec!["srv".to_string(), "s.local".to_string()];
        assert!(validate_aliases(&aliases, "server.local").is_ok());
    }

    #[test]
    fn test_validate_aliases_matches_hostname() {
        let aliases = vec!["srv".to_string(), "server.local".to_string()];
        let err = validate_aliases(&aliases, "server.local").unwrap_err();
        assert!(matches!(err, ValidationError::AliasMatchesHostname(_)));
    }

    #[test]
    fn test_validate_aliases_matches_hostname_case_insensitive() {
        let aliases = vec!["SERVER.LOCAL".to_string()];
        let err = validate_aliases(&aliases, "server.local").unwrap_err();
        assert!(matches!(err, ValidationError::AliasMatchesHostname(_)));
    }

    #[test]
    fn test_validate_aliases_duplicate() {
        let aliases = vec!["srv".to_string(), "srv".to_string()];
        let err = validate_aliases(&aliases, "server.local").unwrap_err();
        assert!(matches!(err, ValidationError::DuplicateAlias(_)));
    }

    #[test]
    fn test_validate_aliases_duplicate_case_insensitive() {
        let aliases = vec!["srv".to_string(), "SRV".to_string()];
        let err = validate_aliases(&aliases, "server.local").unwrap_err();
        assert!(matches!(err, ValidationError::DuplicateAlias(_)));
    }

    #[test]
    fn test_validate_aliases_invalid_format() {
        let aliases = vec!["-invalid".to_string()];
        assert!(validate_aliases(&aliases, "server.local").is_err());
    }
}
