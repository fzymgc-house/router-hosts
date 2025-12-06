use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::PathBuf;

/// Client configuration with all connection settings
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_address: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

/// Configuration file structure
#[derive(Debug, Deserialize)]
struct ConfigFile {
    server: Option<ServerSection>,
    tls: Option<TlsSection>,
}

#[derive(Debug, Deserialize)]
struct ServerSection {
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TlsSection {
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    ca_cert_path: Option<PathBuf>,
}

impl ClientConfig {
    /// Load configuration with precedence: CLI > env > file
    pub fn load(
        config_path: Option<&PathBuf>,
        cli_server: Option<&str>,
        cli_cert: Option<&PathBuf>,
        cli_key: Option<&PathBuf>,
        cli_ca: Option<&PathBuf>,
    ) -> Result<Self> {
        // Load from file if specified or default location
        let file_config = Self::load_from_file(config_path)?;

        // Build config with precedence: CLI > env > file
        let server_address = cli_server
            .map(String::from)
            .or_else(|| std::env::var("ROUTER_HOSTS_SERVER").ok())
            .or(file_config.as_ref().and_then(|f| {
                f.server.as_ref().and_then(|s| s.address.clone())
            }))
            .ok_or_else(|| anyhow!("Server address required: use --server, ROUTER_HOSTS_SERVER, or config file"))?;

        let cert_path = cli_cert
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_CERT").ok().map(PathBuf::from))
            .or(file_config.as_ref().and_then(|f| {
                f.tls.as_ref().and_then(|t| t.cert_path.clone())
            }))
            .map(|p| Self::expand_tilde(p))
            .ok_or_else(|| anyhow!("Client certificate required: use --cert, ROUTER_HOSTS_CERT, or config file"))?;

        let key_path = cli_key
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_KEY").ok().map(PathBuf::from))
            .or(file_config.as_ref().and_then(|f| {
                f.tls.as_ref().and_then(|t| t.key_path.clone())
            }))
            .map(|p| Self::expand_tilde(p))
            .ok_or_else(|| anyhow!("Client key required: use --key, ROUTER_HOSTS_KEY, or config file"))?;

        let ca_cert_path = cli_ca
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_CA").ok().map(PathBuf::from))
            .or(file_config.as_ref().and_then(|f| {
                f.tls.as_ref().and_then(|t| t.ca_cert_path.clone())
            }))
            .map(|p| Self::expand_tilde(p))
            .ok_or_else(|| anyhow!("CA certificate required: use --ca, ROUTER_HOSTS_CA, or config file"))?;

        Ok(Self {
            server_address,
            cert_path,
            key_path,
            ca_cert_path,
        })
    }

    fn load_from_file(path: Option<&PathBuf>) -> Result<Option<ConfigFile>> {
        let config_path = match path {
            Some(p) => p.clone(),
            None => {
                // Try default location
                let default = Self::default_config_path();
                if !default.exists() {
                    return Ok(None);
                }
                default
            }
        };

        if !config_path.exists() {
            if path.is_some() {
                // Explicitly specified path must exist
                return Err(anyhow!("Config file not found: {:?}", config_path));
            }
            return Ok(None);
        }

        let content = std::fs::read_to_string(&config_path)?;
        let config: ConfigFile = toml::from_str(&content)?;
        Ok(Some(config))
    }

    fn default_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("router-hosts")
            .join("client.toml")
    }

    fn expand_tilde(path: PathBuf) -> PathBuf {
        if let Some(path_str) = path.to_str() {
            if path_str.starts_with("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(&path_str[2..]);
                }
            }
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_from_cli_args() {
        let cert = PathBuf::from("/tmp/cert.pem");
        let key = PathBuf::from("/tmp/key.pem");
        let ca = PathBuf::from("/tmp/ca.pem");

        let config = ClientConfig::load(
            None,
            Some("localhost:50051"),
            Some(&cert),
            Some(&key),
            Some(&ca),
        )
        .unwrap();

        assert_eq!(config.server_address, "localhost:50051");
        assert_eq!(config.cert_path, cert);
    }

    #[test]
    fn test_load_from_config_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[server]
address = "router.local:50051"

[tls]
cert_path = "/etc/certs/client.crt"
key_path = "/etc/certs/client.key"
ca_cert_path = "/etc/certs/ca.crt"
"#
        )
        .unwrap();

        let config = ClientConfig::load(
            Some(&file.path().to_path_buf()),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(config.server_address, "router.local:50051");
        assert_eq!(config.cert_path, PathBuf::from("/etc/certs/client.crt"));
    }

    #[test]
    fn test_cli_overrides_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[server]
address = "router.local:50051"

[tls]
cert_path = "/file/cert.crt"
key_path = "/file/key.key"
ca_cert_path = "/file/ca.crt"
"#
        )
        .unwrap();

        let cli_cert = PathBuf::from("/cli/cert.crt");
        let config = ClientConfig::load(
            Some(&file.path().to_path_buf()),
            Some("cli-server:9999"),
            Some(&cli_cert),
            None,
            None,
        )
        .unwrap();

        assert_eq!(config.server_address, "cli-server:9999");
        assert_eq!(config.cert_path, cli_cert);
        assert_eq!(config.key_path, PathBuf::from("/file/key.key"));
    }

    #[test]
    fn test_missing_required_fields() {
        let result = ClientConfig::load(None, None, None, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Server address required"));
    }
}
