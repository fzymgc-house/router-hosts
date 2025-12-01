use serde::Deserialize;
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
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub hosts_file_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: PathBuf,
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
/// [hooks]
/// on_success = ["systemctl reload dnsmasq"]
/// on_failure = ["/usr/local/bin/alert-failure"]
/// ```
#[derive(Debug, Deserialize, Clone, Default)]
pub struct HooksConfig {
    #[serde(default)]
    pub on_success: Vec<String>,

    #[serde(default)]
    pub on_failure: Vec<String>,
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
        let config: Config = toml::from_str(&content)?;

        // Validate required fields
        if config.server.bind_address.is_empty() {
            return Err(ConfigError::MissingBindAddress);
        }

        if config.server.hosts_file_path.is_empty() {
            return Err(ConfigError::MissingHostsFilePath);
        }

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
}
