use crate::server::acme::{AcmeConfig, AcmeConfigError};
use router_hosts_storage::StorageError;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("hosts_file_path is required but not provided")]
    MissingHostsFilePath,

    #[error("bind_address is required but not provided")]
    MissingBindAddress,

    #[error("Config file security: {0}")]
    InsecureConfig(String),

    #[error("Storage configuration error: {0}")]
    StorageConfig(#[from] StorageError),

    #[error("ACME configuration error: {0}")]
    AcmeConfig(#[from] AcmeConfigError),

    #[error("Hook configuration error: {0}")]
    InvalidHook(String),
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub hosts_file_path: String,
}

/// Database/storage configuration
///
/// Supports two formats for backwards compatibility:
/// - `path = "/path/to/hosts.db"` - legacy format, converted to sqlite:// URL
/// - `url = "sqlite:///path/to/hosts.db"` - new URL format (also supports postgres://)
///
/// If both are specified, `url` takes precedence.
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    /// Legacy path format (deprecated, use `url` instead)
    #[serde(default)]
    pub path: Option<PathBuf>,

    /// Storage URL (e.g., "sqlite:///path/to/hosts.db" or "sqlite://:memory:")
    #[serde(default)]
    pub url: Option<String>,
}

impl DatabaseConfig {
    /// Get the storage URL, converting from legacy path format if needed.
    ///
    /// If no `url` or `path` is specified, returns an XDG-compliant default path:
    /// - Linux: `~/.local/share/router-hosts/hosts.db`
    /// - macOS: `~/Library/Application Support/router-hosts/hosts.db`
    /// - Windows: `C:\Users\<user>\AppData\Roaming\router-hosts\hosts.db`
    pub fn storage_url(&self) -> Result<String, ConfigError> {
        // Prefer url if specified
        if let Some(url) = &self.url {
            return Ok(url.clone());
        }

        // Fall back to converting path to sqlite:// URL
        if let Some(path) = &self.path {
            let path_str = path.to_string_lossy();
            // Convert absolute path to sqlite:// URL
            // Check for Unix absolute paths (/) and Windows absolute paths (C:\)
            let is_absolute = path_str.starts_with('/')
                || (path_str.len() >= 2
                    && path_str
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphabetic())
                    && path_str.chars().nth(1) == Some(':'));
            if is_absolute {
                return Ok(format!("sqlite://{}", path_str));
            } else {
                // Relative path
                return Ok(format!("sqlite://./{}", path_str));
            }
        }

        // Use XDG-compliant default path
        Self::default_storage_url()
    }

    /// Returns the XDG-compliant default storage URL.
    ///
    /// Platform-specific paths:
    /// - Linux: `~/.local/share/router-hosts/hosts.db`
    /// - macOS: `~/Library/Application Support/router-hosts/hosts.db`
    /// - Windows: `C:\Users\<user>\AppData\Roaming\router-hosts\hosts.db`
    pub fn default_storage_url() -> Result<String, ConfigError> {
        let data_dir = dirs::data_dir().ok_or_else(|| {
            ConfigError::StorageConfig(StorageError::InvalidConnectionString(
                "Could not determine user data directory. Please specify database.url explicitly."
                    .into(),
            ))
        })?;

        let db_path = data_dir.join("router-hosts").join("hosts.db");

        // Create directory if it doesn't exist
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ConfigError::StorageConfig(StorageError::InvalidConnectionString(format!(
                    "Failed to create storage directory '{}': {}. \
                     Please create it manually or specify database.url explicitly.",
                    parent.display(),
                    e
                )))
            })?;
        }

        let path_str = db_path.to_string_lossy();
        Ok(format!("sqlite://{}", path_str))
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct RetentionConfig {
    #[serde(default = "default_max_snapshots")]
    pub max_snapshots: usize,

    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,
}

fn default_max_snapshots() -> usize {
    50
}

fn default_max_age_days() -> u32 {
    30
}

/// Maximum length for hook names.
const MAX_HOOK_NAME_LENGTH: usize = 50;

/// A single hook definition with a name and command.
///
/// Hook names must be kebab-case (lowercase alphanumeric with hyphens)
/// and at most 50 characters.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct HookDefinition {
    /// Human-readable name for the hook (kebab-case, max 50 chars).
    /// Used in logs, health endpoints, and metrics.
    pub name: String,

    /// Shell command to execute.
    pub command: String,
}

impl HookDefinition {
    /// Create a new hook definition with validation.
    ///
    /// Returns an error if the name or command is invalid.
    /// Use this constructor when creating hooks programmatically
    /// to ensure validation is performed.
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::InvalidHook` if:
    /// - name is empty or whitespace-only
    /// - name is not valid kebab-case
    /// - name exceeds 50 characters
    /// - command is empty or whitespace-only
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Result<Self, ConfigError> {
        let hook = Self {
            name: name.into(),
            command: command.into(),
        };
        hook.validate()?;
        Ok(hook)
    }

    /// Validate the hook definition.
    ///
    /// Returns an error if:
    /// - name is empty or whitespace-only
    /// - name is not valid kebab-case
    /// - name exceeds 50 characters
    /// - command is empty or whitespace-only
    #[must_use = "validation errors must be checked; invalid hooks will cause runtime failures"]
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate name is non-empty
        if self.name.is_empty() {
            return Err(ConfigError::InvalidHook(
                "hook name must be non-empty".into(),
            ));
        }

        // Validate name length
        if self.name.len() > MAX_HOOK_NAME_LENGTH {
            return Err(ConfigError::InvalidHook(format!(
                "hook name '{}' exceeds {} character limit",
                self.name, MAX_HOOK_NAME_LENGTH
            )));
        }

        // Validate kebab-case format
        if !is_valid_kebab_case(&self.name) {
            return Err(ConfigError::InvalidHook(format!(
                "hook name '{}' is invalid (must be kebab-case: lowercase letters, numbers, \
                 and hyphens; no consecutive hyphens or leading/trailing hyphens)",
                self.name
            )));
        }

        // Validate command is non-empty and not whitespace-only
        if self.command.is_empty() || self.command.trim().is_empty() {
            return Err(ConfigError::InvalidHook(format!(
                "hook '{}' has empty or whitespace-only command",
                self.name
            )));
        }

        Ok(())
    }
}

/// Check if a string is valid kebab-case.
///
/// Valid kebab-case: lowercase alphanumeric segments separated by single hyphens.
/// Examples: "reload-dns", "log-success", "alert-ops-team"
/// Invalid: "Reload-DNS", "reload--dns", "-reload", "reload-"
fn is_valid_kebab_case(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Must not start or end with hyphen
    if s.starts_with('-') || s.ends_with('-') {
        return false;
    }

    // Check each character and no consecutive hyphens
    let mut prev_was_hyphen = false;
    for c in s.chars() {
        if c == '-' {
            if prev_was_hyphen {
                return false; // No consecutive hyphens
            }
            prev_was_hyphen = true;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            prev_was_hyphen = false;
        } else {
            return false; // Invalid character
        }
    }

    true
}

/// Configuration for post-edit hook commands
///
/// # Security Warning
///
/// **CRITICAL**: Hook commands execute as shell scripts with the same privileges as
/// the router-hosts server process. The configuration file MUST be:
/// - Owned by root or the service account
/// - Not writable by unprivileged users
/// - Located in a protected directory (e.g., /etc/router-hosts/)
///
/// If an attacker can modify the config file, they can execute arbitrary commands.
///
/// ## Safe Usage Guidelines
///
/// - NEVER interpolate user-controlled data into hook commands
/// - Use environment variables to pass context (entry count, error message, etc.)
/// - Hooks have a 30-second timeout to prevent DoS
/// - All hook executions are logged via tracing
/// - Hook failures do NOT fail the overall operation (hosts file is already updated)
///
/// ## Available Environment Variables
///
/// - `ROUTER_HOSTS_EVENT`: "success" or "failure"
/// - `ROUTER_HOSTS_ENTRY_COUNT`: Number of host entries
/// - `ROUTER_HOSTS_ERROR`: Error message (failure hooks only)
///
/// ## Example Configuration
///
/// ```toml
/// [[hooks.on_success]]
/// name = "reload-dns"
/// command = "systemctl reload dnsmasq"
///
/// [[hooks.on_failure]]
/// name = "alert-ops"
/// command = "/usr/local/bin/alert-failure"
/// ```
#[derive(Debug, Deserialize, Clone, Default)]
pub struct HooksConfig {
    #[serde(default)]
    pub on_success: Vec<HookDefinition>,

    #[serde(default)]
    pub on_failure: Vec<HookDefinition>,
}

impl HooksConfig {
    /// Validate all hook definitions.
    ///
    /// Checks that all hooks have valid names and commands,
    /// and that there are no duplicate names within each hook type.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate and check for duplicates in on_success
        let mut seen_names = std::collections::HashSet::new();
        for hook in &self.on_success {
            hook.validate()?;
            if !seen_names.insert(&hook.name) {
                return Err(ConfigError::InvalidHook(format!(
                    "duplicate hook name '{}' in on_success hooks",
                    hook.name
                )));
            }
        }

        // Validate and check for duplicates in on_failure
        seen_names.clear();
        for hook in &self.on_failure {
            hook.validate()?;
            if !seen_names.insert(&hook.name) {
                return Err(ConfigError::InvalidHook(format!(
                    "duplicate hook name '{}' in on_failure hooks",
                    hook.name
                )));
            }
        }

        Ok(())
    }
}

/// OpenTelemetry exporter configuration
#[derive(Debug, Deserialize, Clone)]
pub struct OtelConfig {
    /// gRPC endpoint for OTEL collector (e.g., "http://otel-collector:4317")
    pub endpoint: String,

    /// Service name for traces/metrics (defaults to "router-hosts")
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Export metrics via OTLP (default: true)
    #[serde(default = "default_true")]
    pub export_metrics: bool,

    /// Export traces via OTLP (default: true)
    #[serde(default = "default_true")]
    pub export_traces: bool,

    /// Optional headers for authentication (e.g., Authorization)
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

fn default_service_name() -> String {
    "router-hosts".to_string()
}

impl OtelConfig {
    /// Get the service name
    pub fn service_name(&self) -> &str {
        &self.service_name
    }
}

/// Metrics and observability configuration
///
/// When this section is absent from config, no metrics are collected
/// and no ports are opened. This is the default (opt-in) behavior.
#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    /// Address to bind Prometheus HTTP endpoint (e.g., "0.0.0.0:9090")
    /// If set, exposes /metrics endpoint on plaintext HTTP
    #[serde(default)]
    pub prometheus_bind: Option<SocketAddr>,

    /// OpenTelemetry configuration for metrics and traces export
    #[serde(default)]
    pub otel: Option<OtelConfig>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub tls: TlsConfig,

    #[serde(default)]
    pub retention: RetentionConfig,

    #[serde(default)]
    pub hooks: HooksConfig,

    /// ACME certificate management configuration
    #[serde(default)]
    pub acme: AcmeConfig,

    /// Metrics and observability configuration (opt-in)
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            max_snapshots: default_max_snapshots(),
            max_age_days: default_max_age_days(),
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        // Security check: warn if config file has insecure permissions
        // This is critical because the config file can contain hook commands
        // that execute with server privileges
        Self::check_config_permissions(path)?;

        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;

        // Validate required fields
        if config.server.bind_address.is_empty() {
            return Err(ConfigError::MissingBindAddress);
        }

        if config.server.hosts_file_path.is_empty() {
            return Err(ConfigError::MissingHostsFilePath);
        }

        // Validate and expand ACME configuration (handles ${VAR} expansion)
        config.acme.validate_and_expand()?;

        // Validate hook definitions
        config.hooks.validate()?;

        Ok(config)
    }

    /// Check config file permissions for security
    ///
    /// On Unix systems, warns if the config file is world-writable or group-writable.
    /// This is important because the config file can contain hook commands that
    /// execute with the server's privileges.
    #[cfg(unix)]
    fn check_config_permissions(path: &str) -> Result<(), ConfigError> {
        use std::os::unix::fs::PermissionsExt;

        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ConfigError::ReadError(e));
            }
            Err(_) => {
                // Can't check permissions, proceed with warning
                warn!(
                    path = path,
                    "Unable to check config file permissions - ensure file is not world-writable"
                );
                return Ok(());
            }
        };

        let mode = metadata.permissions().mode();

        // Check for world-writable (o+w = 0o002)
        if mode & 0o002 != 0 {
            return Err(ConfigError::InsecureConfig(format!(
                "Config file '{}' is world-writable (mode {:o}). \
                 This is a security risk as the config contains hook commands. \
                 Fix with: chmod o-w {}",
                path, mode, path
            )));
        }

        // Warn about group-writable (g+w = 0o020) but don't fail
        if mode & 0o020 != 0 {
            warn!(
                path = path,
                mode = format!("{:o}", mode),
                "Config file is group-writable - consider restricting with: chmod g-w {}",
                path
            );
        }

        Ok(())
    }

    /// Check config file permissions (non-Unix stub)
    #[cfg(not(unix))]
    fn check_config_permissions(_path: &str) -> Result<(), ConfigError> {
        // On non-Unix systems, we can't easily check permissions
        // Just proceed and rely on OS-level security
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse_minimal() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            path = "/var/lib/router-hosts/hosts.db"

            [tls]
            cert_path = "/etc/router-hosts/server.crt"
            key_path = "/etc/router-hosts/server.key"
            ca_cert_path = "/etc/router-hosts/ca.crt"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.bind_address, "0.0.0.0:50051");
        assert_eq!(config.server.hosts_file_path, "/etc/hosts");
        assert_eq!(config.retention.max_snapshots, 50);
    }

    #[test]
    fn test_config_missing_hosts_file_path() {
        use std::io::Write;

        let toml_str = r#"
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = ""

[database]
path = "/var/lib/router-hosts/hosts.db"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"
"#;

        // Create a temp file with the config
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(toml_str.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Call Config::from_file() and verify it returns MissingHostsFilePath error
        let result = Config::from_file(temp_file.path().to_str().unwrap());

        assert!(result.is_err());
        match result {
            Err(ConfigError::MissingHostsFilePath) => {
                // Expected error
            }
            _ => panic!(
                "Expected ConfigError::MissingHostsFilePath, got {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_config_missing_bind_address() {
        use std::io::Write;

        let toml_str = r#"
[server]
bind_address = ""
hosts_file_path = "/etc/hosts"

[database]
path = "/var/lib/router-hosts/hosts.db"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"
"#;

        // Create a temp file with the config
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(toml_str.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Call Config::from_file() and verify it returns MissingBindAddress error
        let result = Config::from_file(temp_file.path().to_str().unwrap());

        assert!(result.is_err());
        match result {
            Err(ConfigError::MissingBindAddress) => {
                // Expected error
            }
            _ => panic!("Expected ConfigError::MissingBindAddress, got {:?}", result),
        }
    }

    #[test]
    fn test_config_custom_retention() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            path = "/var/lib/router-hosts/hosts.db"

            [tls]
            cert_path = "/etc/router-hosts/server.crt"
            key_path = "/etc/router-hosts/server.key"
            ca_cert_path = "/etc/router-hosts/ca.crt"

            [retention]
            max_snapshots = 100
            max_age_days = 60
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();

        // Verify custom retention values override defaults
        assert_eq!(config.retention.max_snapshots, 100);
        assert_eq!(config.retention.max_age_days, 60);

        // Verify required fields are still present
        assert_eq!(config.server.bind_address, "0.0.0.0:50051");
        assert_eq!(config.server.hosts_file_path, "/etc/hosts");
    }

    #[test]
    #[cfg(unix)]
    fn test_config_world_writable_rejected() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let toml_str = r#"
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = "/etc/hosts"

[database]
path = "/var/lib/router-hosts/hosts.db"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"
"#;

        // Create a temp file and make it world-writable
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(toml_str.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Set world-writable permissions (0o666)
        let path = temp_file.path();
        fs::set_permissions(path, fs::Permissions::from_mode(0o666)).unwrap();

        // Verify loading fails with InsecureConfig error
        let result = Config::from_file(path.to_str().unwrap());

        assert!(result.is_err());
        match result {
            Err(ConfigError::InsecureConfig(msg)) => {
                assert!(msg.contains("world-writable"));
            }
            _ => panic!(
                "Expected ConfigError::InsecureConfig for world-writable file, got {:?}",
                result
            ),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_config_secure_permissions_accepted() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let toml_str = r#"
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = "/etc/hosts"

[database]
path = "/var/lib/router-hosts/hosts.db"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"
"#;

        // Create a temp file with secure permissions
        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(toml_str.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Set secure permissions (0o600 - owner read/write only)
        let path = temp_file.path();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();

        // Verify loading succeeds
        let result = Config::from_file(path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_database_config_legacy_path() {
        let config = DatabaseConfig {
            path: Some(PathBuf::from("/var/lib/router-hosts/hosts.db")),
            url: None,
        };
        let url = config.storage_url().unwrap();
        assert_eq!(url, "sqlite:///var/lib/router-hosts/hosts.db");
    }

    #[test]
    fn test_database_config_legacy_relative_path() {
        let config = DatabaseConfig {
            path: Some(PathBuf::from("data/hosts.db")),
            url: None,
        };
        let url = config.storage_url().unwrap();
        assert_eq!(url, "sqlite://./data/hosts.db");
    }

    #[test]
    fn test_database_config_url_format() {
        let config = DatabaseConfig {
            path: None,
            url: Some("sqlite://:memory:".to_string()),
        };
        let url = config.storage_url().unwrap();
        assert_eq!(url, "sqlite://:memory:");
    }

    #[test]
    fn test_database_config_url_takes_precedence() {
        let config = DatabaseConfig {
            path: Some(PathBuf::from("/ignored/path")),
            url: Some("sqlite://:memory:".to_string()),
        };
        let url = config.storage_url().unwrap();
        assert_eq!(url, "sqlite://:memory:");
    }

    #[test]
    fn test_database_config_missing_both_uses_default() {
        let config = DatabaseConfig {
            path: None,
            url: None,
        };
        let result = config.storage_url();
        // Should return XDG-compliant default path
        assert!(result.is_ok());
        let url = result.unwrap();
        assert!(url.starts_with("sqlite://"));
        assert!(url.contains("router-hosts"));
        assert!(url.ends_with("hosts.db"));
    }

    #[test]
    fn test_default_storage_url() {
        let url = DatabaseConfig::default_storage_url().unwrap();
        assert!(url.starts_with("sqlite://"));
        assert!(url.contains("router-hosts"));
        assert!(url.ends_with("hosts.db"));
    }

    #[test]
    fn test_config_with_url_format() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            url = "sqlite://:memory:"

            [tls]
            cert_path = "/etc/router-hosts/server.crt"
            key_path = "/etc/router-hosts/server.key"
            ca_cert_path = "/etc/router-hosts/ca.crt"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let url = config.database.storage_url().unwrap();
        assert_eq!(url, "sqlite://:memory:");
    }

    #[test]
    fn test_config_error_display() {
        // Test error display for various error variants
        let err = ConfigError::MissingHostsFilePath;
        assert!(err.to_string().contains("hosts_file_path"));

        let err = ConfigError::MissingBindAddress;
        assert!(err.to_string().contains("bind_address"));

        let err = ConfigError::InsecureConfig("test insecure".into());
        assert!(err.to_string().contains("test insecure"));
    }

    #[test]
    fn test_retention_config_default() {
        let retention = RetentionConfig::default();
        assert_eq!(retention.max_snapshots, 50);
        assert_eq!(retention.max_age_days, 30);
    }

    // Hook validation tests

    #[test]
    fn test_is_valid_kebab_case() {
        // Valid cases
        assert!(is_valid_kebab_case("reload-dns"));
        assert!(is_valid_kebab_case("log-success"));
        assert!(is_valid_kebab_case("alert-ops-team"));
        assert!(is_valid_kebab_case("a"));
        assert!(is_valid_kebab_case("abc123"));
        assert!(is_valid_kebab_case("reload2dns"));

        // Invalid cases
        assert!(!is_valid_kebab_case("")); // empty
        assert!(!is_valid_kebab_case("Reload-DNS")); // uppercase
        assert!(!is_valid_kebab_case("reload_dns")); // underscore
        assert!(!is_valid_kebab_case("reload--dns")); // consecutive hyphens
        assert!(!is_valid_kebab_case("-reload")); // leading hyphen
        assert!(!is_valid_kebab_case("reload-")); // trailing hyphen
        assert!(!is_valid_kebab_case("reload dns")); // space
        assert!(!is_valid_kebab_case("reload.dns")); // dot
    }

    #[test]
    fn test_hook_definition_valid() {
        let hook = HookDefinition {
            name: "reload-dns".to_string(),
            command: "systemctl reload dnsmasq".to_string(),
        };
        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_definition_empty_name() {
        let hook = HookDefinition {
            name: "".to_string(),
            command: "echo test".to_string(),
        };
        let err = hook.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn test_hook_definition_invalid_name_format() {
        let hook = HookDefinition {
            name: "Reload DNS".to_string(),
            command: "echo test".to_string(),
        };
        let err = hook.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("kebab-case"));
    }

    #[test]
    fn test_hook_definition_name_too_long() {
        let hook = HookDefinition {
            name: "a".repeat(51),
            command: "echo test".to_string(),
        };
        let err = hook.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("50 character limit"));
    }

    #[test]
    fn test_hook_definition_name_exactly_50_chars() {
        let hook = HookDefinition {
            name: "a".repeat(50),
            command: "echo test".to_string(),
        };
        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_definition_empty_command() {
        let hook = HookDefinition {
            name: "test-hook".to_string(),
            command: "".to_string(),
        };
        let err = hook.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("empty or whitespace-only command"));
    }

    #[test]
    fn test_hook_definition_whitespace_only_command() {
        let hook = HookDefinition {
            name: "test-hook".to_string(),
            command: "   \t\n  ".to_string(),
        };
        let err = hook.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("empty or whitespace-only command"));
    }

    #[test]
    fn test_hook_definition_unicode_in_name_rejected() {
        // Unicode characters should be rejected (not lowercase ASCII)
        let hook = HookDefinition {
            name: "héllo-wörld".to_string(),
            command: "echo test".to_string(),
        };
        let err = hook.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("kebab-case"));
    }

    #[test]
    fn test_hook_definition_emoji_in_name_rejected() {
        let hook = HookDefinition {
            name: "reload-🚀-dns".to_string(),
            command: "echo test".to_string(),
        };
        let err = hook.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("kebab-case"));
    }

    #[test]
    fn test_hook_definition_new_valid() {
        let hook = HookDefinition::new("reload-dns", "systemctl reload dnsmasq").unwrap();
        assert_eq!(hook.name, "reload-dns");
        assert_eq!(hook.command, "systemctl reload dnsmasq");
    }

    #[test]
    fn test_hook_definition_new_invalid_name() {
        let err = HookDefinition::new("Invalid Name", "echo test").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("kebab-case"));
    }

    #[test]
    fn test_hook_definition_new_invalid_command() {
        let err = HookDefinition::new("test-hook", "   ").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("empty or whitespace-only"));
    }

    #[test]
    fn test_hook_definition_equality() {
        let hook1 = HookDefinition {
            name: "reload-dns".to_string(),
            command: "systemctl reload dnsmasq".to_string(),
        };
        let hook2 = HookDefinition {
            name: "reload-dns".to_string(),
            command: "systemctl reload dnsmasq".to_string(),
        };
        let hook3 = HookDefinition {
            name: "reload-dns".to_string(),
            command: "different command".to_string(),
        };

        assert_eq!(hook1, hook2);
        assert_ne!(hook1, hook3);
    }

    #[test]
    fn test_hooks_config_valid() {
        let config = HooksConfig {
            on_success: vec![
                HookDefinition {
                    name: "reload-dns".to_string(),
                    command: "systemctl reload dnsmasq".to_string(),
                },
                HookDefinition {
                    name: "log-success".to_string(),
                    command: "logger 'updated'".to_string(),
                },
            ],
            on_failure: vec![HookDefinition {
                name: "alert-ops".to_string(),
                command: "/usr/local/bin/alert".to_string(),
            }],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_hooks_config_duplicate_on_success() {
        let config = HooksConfig {
            on_success: vec![
                HookDefinition {
                    name: "reload-dns".to_string(),
                    command: "cmd1".to_string(),
                },
                HookDefinition {
                    name: "reload-dns".to_string(),
                    command: "cmd2".to_string(),
                },
            ],
            on_failure: vec![],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("duplicate"));
        assert!(err.to_string().contains("on_success"));
    }

    #[test]
    fn test_hooks_config_duplicate_on_failure() {
        let config = HooksConfig {
            on_success: vec![],
            on_failure: vec![
                HookDefinition {
                    name: "alert-ops".to_string(),
                    command: "cmd1".to_string(),
                },
                HookDefinition {
                    name: "alert-ops".to_string(),
                    command: "cmd2".to_string(),
                },
            ],
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHook(_)));
        assert!(err.to_string().contains("duplicate"));
        assert!(err.to_string().contains("on_failure"));
    }

    #[test]
    fn test_hooks_config_same_name_different_types_allowed() {
        // Same name in on_success and on_failure is allowed
        let config = HooksConfig {
            on_success: vec![HookDefinition {
                name: "notify".to_string(),
                command: "notify-success".to_string(),
            }],
            on_failure: vec![HookDefinition {
                name: "notify".to_string(),
                command: "notify-failure".to_string(),
            }],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_hooks_config_empty() {
        let config = HooksConfig::default();
        assert!(config.validate().is_ok());
    }

    /// Test that validation order returns invalid name error before duplicate check
    #[test]
    fn test_hooks_config_invalid_before_duplicate_check() {
        // Hook has both an invalid name AND is a duplicate
        // Validation should fail on invalid name first
        let config = HooksConfig {
            on_success: vec![
                HookDefinition {
                    name: "Invalid Name".to_string(), // Invalid: has space and uppercase
                    command: "cmd1".to_string(),
                },
                HookDefinition {
                    name: "Invalid Name".to_string(), // Same invalid name (would be duplicate)
                    command: "cmd2".to_string(),
                },
            ],
            on_failure: vec![],
        };
        let err = config.validate().unwrap_err();
        // Should fail on invalid name (kebab-case), not duplicate detection
        assert!(
            err.to_string().contains("kebab-case"),
            "Expected kebab-case error, got: {}",
            err
        );
    }

    #[test]
    fn test_config_with_structured_hooks() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            url = "sqlite://:memory:"

            [tls]
            cert_path = "/etc/router-hosts/server.crt"
            key_path = "/etc/router-hosts/server.key"
            ca_cert_path = "/etc/router-hosts/ca.crt"

            [[hooks.on_success]]
            name = "reload-dns"
            command = "systemctl reload dnsmasq"

            [[hooks.on_failure]]
            name = "alert-ops"
            command = "/usr/local/bin/alert-failure"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.hooks.on_success.len(), 1);
        assert_eq!(config.hooks.on_success[0].name, "reload-dns");
        assert_eq!(
            config.hooks.on_success[0].command,
            "systemctl reload dnsmasq"
        );
        assert_eq!(config.hooks.on_failure.len(), 1);
        assert_eq!(config.hooks.on_failure[0].name, "alert-ops");
    }

    #[test]
    #[cfg(unix)]
    fn test_config_from_file_invalid_hook_name() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let toml_str = r#"
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = "/etc/hosts"

[database]
url = "sqlite://:memory:"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"

[[hooks.on_success]]
name = "Invalid Hook Name"
command = "echo test"
"#;

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(toml_str.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Set secure permissions
        let path = temp_file.path();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();

        let result = Config::from_file(path.to_str().unwrap());
        assert!(result.is_err());
        match result {
            Err(ConfigError::InvalidHook(msg)) => {
                assert!(msg.contains("kebab-case"));
            }
            _ => panic!(
                "Expected ConfigError::InvalidHook for invalid hook name, got {:?}",
                result
            ),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_config_from_file_duplicate_hook_names() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let toml_str = r#"
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = "/etc/hosts"

[database]
url = "sqlite://:memory:"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"

[[hooks.on_success]]
name = "reload-dns"
command = "systemctl reload dnsmasq"

[[hooks.on_success]]
name = "reload-dns"
command = "different command"
"#;

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(toml_str.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Set secure permissions
        let path = temp_file.path();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();

        let result = Config::from_file(path.to_str().unwrap());
        assert!(result.is_err());
        match result {
            Err(ConfigError::InvalidHook(msg)) => {
                assert!(msg.contains("duplicate"));
            }
            _ => panic!(
                "Expected ConfigError::InvalidHook for duplicate hook names, got {:?}",
                result
            ),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_config_from_file_empty_hook_command() {
        use std::fs;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let toml_str = r#"
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = "/etc/hosts"

[database]
url = "sqlite://:memory:"

[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"

[[hooks.on_success]]
name = "reload-dns"
command = ""
"#;

        let mut temp_file = tempfile::NamedTempFile::new().unwrap();
        temp_file.write_all(toml_str.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        // Set secure permissions
        let path = temp_file.path();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();

        let result = Config::from_file(path.to_str().unwrap());
        assert!(result.is_err());
        match result {
            Err(ConfigError::InvalidHook(msg)) => {
                assert!(msg.contains("empty or whitespace-only command"));
            }
            _ => panic!(
                "Expected ConfigError::InvalidHook for empty command, got {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_metrics_config_default_is_none() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            url = "sqlite://:memory:"

            [tls]
            cert_path = "/cert.pem"
            key_path = "/key.pem"
            ca_cert_path = "/ca.pem"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.metrics.is_none());
    }

    #[test]
    fn test_metrics_config_prometheus_only() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            url = "sqlite://:memory:"

            [tls]
            cert_path = "/cert.pem"
            key_path = "/key.pem"
            ca_cert_path = "/ca.pem"

            [metrics]
            prometheus_bind = "0.0.0.0:9090"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let metrics = config.metrics.unwrap();
        assert_eq!(
            metrics.prometheus_bind,
            Some("0.0.0.0:9090".parse().unwrap())
        );
        assert!(metrics.otel.is_none());
    }

    #[test]
    fn test_metrics_config_with_otel() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            url = "sqlite://:memory:"

            [tls]
            cert_path = "/cert.pem"
            key_path = "/key.pem"
            ca_cert_path = "/ca.pem"

            [metrics]
            prometheus_bind = "0.0.0.0:9090"

            [metrics.otel]
            endpoint = "http://otel-collector:4317"
            service_name = "my-router-hosts"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let metrics = config.metrics.unwrap();
        let otel = metrics.otel.unwrap();
        assert_eq!(otel.endpoint, "http://otel-collector:4317");
        assert_eq!(otel.service_name, "my-router-hosts");
    }

    #[test]
    fn test_otel_config_full() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            url = "sqlite://:memory:"

            [tls]
            cert_path = "/cert.pem"
            key_path = "/key.pem"
            ca_cert_path = "/ca.pem"

            [metrics.otel]
            endpoint = "http://otel-collector:4317"
            service_name = "my-service"
            export_metrics = true
            export_traces = false
            headers = { "Authorization" = "Bearer token123" }
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let otel = config.metrics.unwrap().otel.unwrap();
        assert_eq!(otel.endpoint, "http://otel-collector:4317");
        assert_eq!(otel.service_name(), "my-service");
        assert!(otel.export_metrics);
        assert!(!otel.export_traces);
        assert_eq!(
            otel.headers.get("Authorization").unwrap(),
            "Bearer token123"
        );
    }

    #[test]
    fn test_otel_config_defaults() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0:50051"
            hosts_file_path = "/etc/hosts"

            [database]
            url = "sqlite://:memory:"

            [tls]
            cert_path = "/cert.pem"
            key_path = "/key.pem"
            ca_cert_path = "/ca.pem"

            [metrics.otel]
            endpoint = "http://localhost:4317"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();
        let otel = config.metrics.unwrap().otel.unwrap();
        assert_eq!(otel.service_name(), "router-hosts");
        assert!(otel.export_metrics); // default true
        assert!(otel.export_traces); // default true
        assert!(otel.headers.is_empty());
    }
}
