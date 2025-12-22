//! Environment variable expansion for configuration values
//!
//! Supports shell-style variable expansion in configuration strings:
//! - `${VAR}` - Required variable, error if missing or empty
//! - `${VAR:-default}` - Use default if VAR is unset or empty
//! - `$$` - Literal `$` character
//!
//! # Examples
//!
//! ```
//! use router_hosts::server::acme::env_expand::expand_env_vars;
//!
//! std::env::set_var("MY_TOKEN", "secret123");
//!
//! // Simple expansion
//! assert_eq!(expand_env_vars("token: ${MY_TOKEN}").unwrap(), "token: secret123");
//!
//! // With default value
//! assert_eq!(expand_env_vars("${MISSING:-fallback}").unwrap(), "fallback");
//!
//! // Escaped dollar sign
//! assert_eq!(expand_env_vars("price: $$100").unwrap(), "price: $100");
//!
//! // Required variable that's missing
//! assert!(expand_env_vars("${DOES_NOT_EXIST}").is_err());
//! ```

use regex::{Captures, Regex};
use std::sync::LazyLock;
use thiserror::Error;

/// Maximum expanded string size (64 KB)
///
/// This limit prevents unbounded expansion when environment variables
/// contain very large values. It's generous enough for any reasonable
/// configuration value while preventing potential memory exhaustion.
const MAX_EXPANDED_SIZE: usize = 64 * 1024;

/// Errors that can occur during environment variable expansion
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnvExpandError {
    /// A required environment variable is not set
    #[error("environment variable '{name}' is not set")]
    MissingVariable { name: String },

    /// A required environment variable is set but empty
    #[error("environment variable '{name}' is empty")]
    EmptyVariable { name: String },

    /// Invalid variable syntax (reserved for future use)
    #[error("invalid variable syntax: {0}")]
    #[allow(dead_code)]
    InvalidSyntax(String),

    /// Expanded result exceeds size limit
    #[error("expanded result exceeds maximum size of {MAX_EXPANDED_SIZE} bytes")]
    SizeExceeded,
}

/// Regex for matching ${VAR} or ${VAR:-default} patterns
///
/// Captures:
/// - Group 1: Variable name (e.g., "VAR")
/// - Group 2: Optional default value after ":-" (e.g., "default")
static ENV_VAR_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").expect("Invalid regex pattern")
});

/// Regex for matching escaped dollar signs ($$)
static ESCAPED_DOLLAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\$").expect("Invalid regex pattern"));

/// Expand environment variables in a string
///
/// # Arguments
///
/// * `input` - String potentially containing `${VAR}` or `${VAR:-default}` patterns
///
/// # Returns
///
/// The input string with all environment variables expanded
///
/// # Errors
///
/// - `EnvExpandError::MissingVariable` - A required variable is not set
/// - `EnvExpandError::EmptyVariable` - A required variable is set but empty
///
/// # Examples
///
/// ```
/// use router_hosts::server::acme::env_expand::expand_env_vars;
///
/// std::env::set_var("API_KEY", "secret");
///
/// // Basic expansion
/// let result = expand_env_vars("key=${API_KEY}").unwrap();
/// assert_eq!(result, "key=secret");
///
/// // With default
/// let result = expand_env_vars("${OPTIONAL:-default_value}").unwrap();
/// assert_eq!(result, "default_value");
/// ```
pub fn expand_env_vars(input: &str) -> Result<String, EnvExpandError> {
    // First pass: expand ${VAR} and ${VAR:-default} patterns
    let mut result = String::with_capacity(input.len());
    let mut last_end = 0;
    let mut error: Option<EnvExpandError> = None;

    for caps in ENV_VAR_PATTERN.captures_iter(input) {
        let full_match = caps.get(0).expect("Match group 0 always exists");
        let var_name = caps.get(1).expect("Match group 1 always exists").as_str();
        let default_value = caps.get(2).map(|m| m.as_str());

        // Append text before this match
        result.push_str(&input[last_end..full_match.start()]);
        last_end = full_match.end();

        // Look up the environment variable
        match std::env::var(var_name) {
            Ok(value) if !value.is_empty() => {
                result.push_str(&value);
            }
            Ok(_) => {
                // Variable is set but empty
                if let Some(default) = default_value {
                    result.push_str(default);
                } else {
                    error = Some(EnvExpandError::EmptyVariable {
                        name: var_name.to_string(),
                    });
                    break;
                }
            }
            Err(_) => {
                // Variable is not set
                if let Some(default) = default_value {
                    result.push_str(default);
                } else {
                    error = Some(EnvExpandError::MissingVariable {
                        name: var_name.to_string(),
                    });
                    break;
                }
            }
        }

        // Check size limit to prevent unbounded expansion
        if result.len() > MAX_EXPANDED_SIZE {
            return Err(EnvExpandError::SizeExceeded);
        }
    }

    if let Some(e) = error {
        return Err(e);
    }

    // Append remaining text after last match
    result.push_str(&input[last_end..]);

    // Second pass: unescape $$ to $
    let final_result = ESCAPED_DOLLAR.replace_all(&result, |_: &Captures| "$");

    Ok(final_result.into_owned())
}

/// Check if a string contains any environment variable references
///
/// Returns true if the string contains `${...}` patterns that would be expanded.
/// Does not validate that the variables exist.
#[allow(dead_code)]
pub fn contains_env_vars(input: &str) -> bool {
    ENV_VAR_PATTERN.is_match(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_simple_variable() {
        std::env::set_var("TEST_EXPAND_SIMPLE", "hello");
        let result = expand_env_vars("${TEST_EXPAND_SIMPLE}").unwrap();
        assert_eq!(result, "hello");
        std::env::remove_var("TEST_EXPAND_SIMPLE");
    }

    #[test]
    fn test_expand_variable_with_text() {
        std::env::set_var("TEST_EXPAND_TEXT", "world");
        let result = expand_env_vars("hello ${TEST_EXPAND_TEXT}!").unwrap();
        assert_eq!(result, "hello world!");
        std::env::remove_var("TEST_EXPAND_TEXT");
    }

    #[test]
    fn test_expand_multiple_variables() {
        std::env::set_var("TEST_EXPAND_A", "first");
        std::env::set_var("TEST_EXPAND_B", "second");
        let result = expand_env_vars("${TEST_EXPAND_A} and ${TEST_EXPAND_B}").unwrap();
        assert_eq!(result, "first and second");
        std::env::remove_var("TEST_EXPAND_A");
        std::env::remove_var("TEST_EXPAND_B");
    }

    #[test]
    fn test_expand_with_default_missing() {
        // Ensure variable doesn't exist
        std::env::remove_var("TEST_EXPAND_NONEXISTENT");
        let result = expand_env_vars("${TEST_EXPAND_NONEXISTENT:-fallback}").unwrap();
        assert_eq!(result, "fallback");
    }

    #[test]
    fn test_expand_with_default_empty() {
        std::env::set_var("TEST_EXPAND_EMPTY", "");
        let result = expand_env_vars("${TEST_EXPAND_EMPTY:-fallback}").unwrap();
        assert_eq!(result, "fallback");
        std::env::remove_var("TEST_EXPAND_EMPTY");
    }

    #[test]
    fn test_expand_with_default_value_exists() {
        std::env::set_var("TEST_EXPAND_EXISTS", "actual");
        let result = expand_env_vars("${TEST_EXPAND_EXISTS:-fallback}").unwrap();
        assert_eq!(result, "actual");
        std::env::remove_var("TEST_EXPAND_EXISTS");
    }

    #[test]
    fn test_expand_escaped_dollar() {
        let result = expand_env_vars("price: $$100").unwrap();
        assert_eq!(result, "price: $100");
    }

    #[test]
    fn test_expand_escaped_and_variable() {
        std::env::set_var("TEST_EXPAND_MIXED", "value");
        let result = expand_env_vars("$$${TEST_EXPAND_MIXED}$$").unwrap();
        assert_eq!(result, "$value$");
        std::env::remove_var("TEST_EXPAND_MIXED");
    }

    #[test]
    fn test_expand_missing_required_variable() {
        std::env::remove_var("TEST_EXPAND_REQUIRED_MISSING");
        let result = expand_env_vars("${TEST_EXPAND_REQUIRED_MISSING}");
        assert!(result.is_err());
        match result {
            Err(EnvExpandError::MissingVariable { name }) => {
                assert_eq!(name, "TEST_EXPAND_REQUIRED_MISSING");
            }
            _ => panic!("Expected MissingVariable error"),
        }
    }

    #[test]
    fn test_expand_empty_required_variable() {
        std::env::set_var("TEST_EXPAND_REQUIRED_EMPTY", "");
        let result = expand_env_vars("${TEST_EXPAND_REQUIRED_EMPTY}");
        assert!(result.is_err());
        match result {
            Err(EnvExpandError::EmptyVariable { name }) => {
                assert_eq!(name, "TEST_EXPAND_REQUIRED_EMPTY");
            }
            _ => panic!("Expected EmptyVariable error"),
        }
        std::env::remove_var("TEST_EXPAND_REQUIRED_EMPTY");
    }

    #[test]
    fn test_expand_no_variables() {
        let result = expand_env_vars("no variables here").unwrap();
        assert_eq!(result, "no variables here");
    }

    #[test]
    fn test_expand_empty_default() {
        std::env::remove_var("TEST_EXPAND_EMPTY_DEFAULT");
        let result = expand_env_vars("prefix${TEST_EXPAND_EMPTY_DEFAULT:-}suffix").unwrap();
        assert_eq!(result, "prefixsuffix");
    }

    #[test]
    fn test_expand_default_with_special_chars() {
        std::env::remove_var("TEST_EXPAND_SPECIAL");
        let result = expand_env_vars("${TEST_EXPAND_SPECIAL:-https://example.com/path}").unwrap();
        assert_eq!(result, "https://example.com/path");
    }

    #[test]
    fn test_expand_underscore_in_name() {
        std::env::set_var("TEST_WITH_UNDERSCORE_123", "works");
        let result = expand_env_vars("${TEST_WITH_UNDERSCORE_123}").unwrap();
        assert_eq!(result, "works");
        std::env::remove_var("TEST_WITH_UNDERSCORE_123");
    }

    #[test]
    fn test_expand_adjacent_variables() {
        std::env::set_var("TEST_ADJ_A", "hello");
        std::env::set_var("TEST_ADJ_B", "world");
        let result = expand_env_vars("${TEST_ADJ_A}${TEST_ADJ_B}").unwrap();
        assert_eq!(result, "helloworld");
        std::env::remove_var("TEST_ADJ_A");
        std::env::remove_var("TEST_ADJ_B");
    }

    #[test]
    fn test_contains_env_vars_true() {
        assert!(contains_env_vars("${VAR}"));
        assert!(contains_env_vars("prefix ${VAR} suffix"));
        assert!(contains_env_vars("${VAR:-default}"));
    }

    #[test]
    fn test_contains_env_vars_false() {
        assert!(!contains_env_vars("no variables"));
        assert!(!contains_env_vars("$$escaped"));
        assert!(!contains_env_vars("$NOT_BRACED"));
    }

    #[test]
    fn test_error_display() {
        let err = EnvExpandError::MissingVariable {
            name: "TEST".to_string(),
        };
        assert_eq!(err.to_string(), "environment variable 'TEST' is not set");

        let err = EnvExpandError::EmptyVariable {
            name: "TEST".to_string(),
        };
        assert_eq!(err.to_string(), "environment variable 'TEST' is empty");
    }

    #[test]
    fn test_expand_real_world_api_token() {
        std::env::set_var("CLOUDFLARE_API_TOKEN", "cf_token_12345");
        let toml_value = r#"api_token = "${CLOUDFLARE_API_TOKEN}""#;
        let result = expand_env_vars(toml_value).unwrap();
        assert_eq!(result, r#"api_token = "cf_token_12345""#);
        std::env::remove_var("CLOUDFLARE_API_TOKEN");
    }

    #[test]
    fn test_expand_url_with_credentials() {
        std::env::set_var("TEST_DB_USER", "admin");
        std::env::set_var("TEST_DB_PASS", "secret");
        let url = "postgres://${TEST_DB_USER}:${TEST_DB_PASS}@localhost/db";
        let result = expand_env_vars(url).unwrap();
        assert_eq!(result, "postgres://admin:secret@localhost/db");
        std::env::remove_var("TEST_DB_USER");
        std::env::remove_var("TEST_DB_PASS");
    }

    #[test]
    fn test_expand_size_limit_exceeded() {
        // Create a variable with a large value (just over 64KB when expanded)
        let large_value = "x".repeat(MAX_EXPANDED_SIZE + 1);
        std::env::set_var("TEST_LARGE_VAR", &large_value);

        let result = expand_env_vars("${TEST_LARGE_VAR}");
        assert!(matches!(result, Err(EnvExpandError::SizeExceeded)));

        std::env::remove_var("TEST_LARGE_VAR");
    }

    #[test]
    fn test_expand_size_limit_at_boundary() {
        // Create a variable at exactly the limit - should succeed
        let at_limit_value = "x".repeat(MAX_EXPANDED_SIZE);
        std::env::set_var("TEST_BOUNDARY_VAR", &at_limit_value);

        let result = expand_env_vars("${TEST_BOUNDARY_VAR}");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), MAX_EXPANDED_SIZE);

        std::env::remove_var("TEST_BOUNDARY_VAR");
    }

    #[test]
    fn test_error_display_size_exceeded() {
        let err = EnvExpandError::SizeExceeded;
        assert!(err.to_string().contains("65536"));
    }
}
