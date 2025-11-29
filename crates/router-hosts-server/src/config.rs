use serde::Deserialize;
use std::path::PathBuf;
use thiserror::Error;

#[allow(dead_code)]
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
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind_address: String,
    pub hosts_file_path: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct RetentionConfig {
    #[serde(default = "default_max_snapshots")]
    pub max_snapshots: usize,

    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,
}

#[allow(dead_code)]
fn default_max_snapshots() -> usize {
    50
}
#[allow(dead_code)]
fn default_max_age_days() -> u32 {
    30
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct EditSessionConfig {
    #[serde(default = "default_timeout_minutes")]
    pub timeout_minutes: u64,
}

#[allow(dead_code)]
fn default_timeout_minutes() -> u64 {
    15
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct HooksConfig {
    #[serde(default)]
    pub on_success: Vec<String>,

    #[serde(default)]
    pub on_failure: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub tls: TlsConfig,

    #[serde(default)]
    pub retention: RetentionConfig,

    #[serde(default)]
    pub edit_session: EditSessionConfig,

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

impl Default for EditSessionConfig {
    fn default() -> Self {
        Self {
            timeout_minutes: default_timeout_minutes(),
        }
    }
}

#[allow(dead_code)]
impl Config {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
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
        assert_eq!(config.edit_session.timeout_minutes, 15);
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
}
