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
            .or(file_config
                .as_ref()
                .and_then(|f| f.server.as_ref().and_then(|s| s.address.clone())))
            .ok_or_else(|| {
                anyhow!(
                    "Server address required: use --server, ROUTER_HOSTS_SERVER, or config file"
                )
            })?;

        let cert_path = cli_cert
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_CERT").ok().map(PathBuf::from))
            .or(file_config
                .as_ref()
                .and_then(|f| f.tls.as_ref().and_then(|t| t.cert_path.clone())))
            .map(Self::expand_tilde)
            .ok_or_else(|| {
                anyhow!(
                    "Client certificate required: use --cert, ROUTER_HOSTS_CERT, or config file"
                )
            })?;

        let key_path = cli_key
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_KEY").ok().map(PathBuf::from))
            .or(file_config
                .as_ref()
                .and_then(|f| f.tls.as_ref().and_then(|t| t.key_path.clone())))
            .map(Self::expand_tilde)
            .ok_or_else(|| {
                anyhow!("Client key required: use --key, ROUTER_HOSTS_KEY, or config file")
            })?;

        let ca_cert_path = cli_ca
            .cloned()
            .or_else(|| std::env::var("ROUTER_HOSTS_CA").ok().map(PathBuf::from))
            .or(file_config
                .as_ref()
                .and_then(|f| f.tls.as_ref().and_then(|t| t.ca_cert_path.clone())))
            .map(Self::expand_tilde)
            .ok_or_else(|| {
                anyhow!("CA certificate required: use --ca, ROUTER_HOSTS_CA, or config file")
            })?;

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
            if let Some(stripped) = path_str.strip_prefix("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(stripped);
                }
            }
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// RAII guard for environment variable cleanup.
    /// Automatically restores the original value (or removes the var) when dropped.
    /// This prevents env var leakage even if tests panic.
    struct EnvGuard {
        key: String,
        original: Option<String>,
    }

    impl EnvGuard {
        /// Set an environment variable and return a guard that restores it on drop.
        fn set(key: &str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key: key.to_string(),
                original,
            }
        }

        /// Remove an environment variable and return a guard that restores it on drop.
        fn remove(key: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::remove_var(key);
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }

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
    #[serial]
    fn test_load_from_config_file() {
        // Clear any env vars - guards ensure cleanup even on panic
        let _g1 = EnvGuard::remove("ROUTER_HOSTS_SERVER");
        let _g2 = EnvGuard::remove("ROUTER_HOSTS_CERT");
        let _g3 = EnvGuard::remove("ROUTER_HOSTS_KEY");
        let _g4 = EnvGuard::remove("ROUTER_HOSTS_CA");

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

        let config =
            ClientConfig::load(Some(&file.path().to_path_buf()), None, None, None, None).unwrap();

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
    #[serial]
    fn test_missing_required_fields() {
        // Clear any env vars - guards ensure cleanup even on panic
        let _g1 = EnvGuard::remove("ROUTER_HOSTS_SERVER");
        let _g2 = EnvGuard::remove("ROUTER_HOSTS_CERT");
        let _g3 = EnvGuard::remove("ROUTER_HOSTS_KEY");
        let _g4 = EnvGuard::remove("ROUTER_HOSTS_CA");

        let result = ClientConfig::load(None, None, None, None, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Server address required"));
    }

    #[test]
    #[serial]
    fn test_env_overrides_file() {
        // Clear env vars and set override - guards ensure cleanup even on panic
        let _g1 = EnvGuard::set("ROUTER_HOSTS_SERVER", "env-server:9999");
        let _g2 = EnvGuard::remove("ROUTER_HOSTS_CERT");
        let _g3 = EnvGuard::remove("ROUTER_HOSTS_KEY");
        let _g4 = EnvGuard::remove("ROUTER_HOSTS_CA");

        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[server]
address = "file-server:50051"

[tls]
cert_path = "/file/cert.crt"
key_path = "/file/key.key"
ca_cert_path = "/file/ca.crt"
"#
        )
        .unwrap();

        let config = ClientConfig::load(
            Some(&file.path().to_path_buf()),
            None, // no CLI override
            None,
            None,
            None,
        )
        .unwrap();

        // Env should override file
        assert_eq!(config.server_address, "env-server:9999");
        // File values should be used for TLS
        assert_eq!(config.cert_path, PathBuf::from("/file/cert.crt"));
    }

    #[test]
    fn test_tilde_expansion() {
        let home = dirs::home_dir().expect("home dir should exist");
        let expanded = ClientConfig::expand_tilde(PathBuf::from("~/test/path"));
        assert_eq!(expanded, home.join("test/path"));

        // Non-tilde path should be unchanged
        let unchanged = ClientConfig::expand_tilde(PathBuf::from("/absolute/path"));
        assert_eq!(unchanged, PathBuf::from("/absolute/path"));
    }

    #[test]
    #[serial]
    fn test_env_guard_restores_on_panic() {
        use std::panic;

        const TEST_KEY: &str = "ROUTER_HOSTS_PANIC_TEST";
        const ORIGINAL_VALUE: &str = "original";
        const PANIC_VALUE: &str = "panic_value";

        // Set initial value
        std::env::set_var(TEST_KEY, ORIGINAL_VALUE);

        // Run code that panics while holding an EnvGuard
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _guard = EnvGuard::set(TEST_KEY, PANIC_VALUE);
            // Verify the value was changed
            assert_eq!(std::env::var(TEST_KEY).unwrap(), PANIC_VALUE);
            // Now panic - EnvGuard::drop should still run
            panic!("intentional panic to test EnvGuard cleanup");
        }));

        // Verify panic occurred
        assert!(result.is_err());

        // Verify EnvGuard restored the original value despite the panic
        assert_eq!(
            std::env::var(TEST_KEY).unwrap(),
            ORIGINAL_VALUE,
            "EnvGuard should restore original value even after panic"
        );

        // Cleanup
        std::env::remove_var(TEST_KEY);
    }
}
