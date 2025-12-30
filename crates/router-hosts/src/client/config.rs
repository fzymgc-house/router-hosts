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
            Some(p) => {
                // Explicitly specified path must exist
                if !p.exists() {
                    return Err(anyhow!("Config file not found: {:?}", p));
                }
                p.clone()
            }
            None => {
                // Try candidate paths in priority order
                match Self::find_config_file() {
                    Some(found) => found,
                    None => return Ok(None),
                }
            }
        };

        let content = std::fs::read_to_string(&config_path)?;
        let config: ConfigFile = toml::from_str(&content)?;
        Ok(Some(config))
    }

    /// Find the first existing config file from candidate paths.
    ///
    /// Search order:
    /// 1. `$XDG_CONFIG_HOME/router-hosts/{client,config}.toml` (if XDG_CONFIG_HOME is set)
    /// 2. `~/.config/router-hosts/{client,config}.toml` (XDG default)
    /// 3. Platform-native config dir (macOS: ~/Library/Application Support/...)
    fn find_config_file() -> Option<PathBuf> {
        let filenames = ["client.toml", "config.toml"];

        for base_dir in Self::config_search_dirs() {
            let router_hosts_dir = base_dir.join("router-hosts");
            for filename in &filenames {
                let candidate = router_hosts_dir.join(filename);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// Get config directories to search, in priority order.
    fn config_search_dirs() -> Vec<PathBuf> {
        let mut dirs = Vec::new();

        // 1. XDG_CONFIG_HOME if explicitly set
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            let xdg_path = PathBuf::from(xdg);
            if xdg_path.is_absolute() {
                dirs.push(xdg_path);
            }
        }

        // 2. ~/.config (XDG default, works on all platforms)
        if let Some(home) = dirs::home_dir() {
            let xdg_default = home.join(".config");
            if !dirs.contains(&xdg_default) {
                dirs.push(xdg_default);
            }
        }

        // 3. Platform-native config dir (may duplicate ~/.config on Linux)
        if let Some(native) = dirs::config_dir() {
            if !dirs.contains(&native) {
                dirs.push(native);
            }
        }

        dirs
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
        use tempfile::TempDir;

        // Clear any env vars - guards ensure cleanup even on panic
        let _g1 = EnvGuard::remove("ROUTER_HOSTS_SERVER");
        let _g2 = EnvGuard::remove("ROUTER_HOSTS_CERT");
        let _g3 = EnvGuard::remove("ROUTER_HOSTS_KEY");
        let _g4 = EnvGuard::remove("ROUTER_HOSTS_CA");

        // Point XDG_CONFIG_HOME and HOME to empty temp dir so no config is found
        let temp = TempDir::new().unwrap();
        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", temp.path().to_str().unwrap());
        let _home_guard = EnvGuard::set("HOME", temp.path().to_str().unwrap());

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

    #[test]
    #[serial]
    fn test_config_search_dirs_includes_xdg_default() {
        let _guard = EnvGuard::remove("XDG_CONFIG_HOME");

        let dirs = ClientConfig::config_search_dirs();
        let home = dirs::home_dir().expect("home dir should exist");
        let xdg_default = home.join(".config");

        assert!(
            dirs.contains(&xdg_default),
            "Should include ~/.config in search dirs"
        );
    }

    #[test]
    #[serial]
    fn test_config_search_dirs_xdg_config_home_priority() {
        let _guard = EnvGuard::set("XDG_CONFIG_HOME", "/custom/xdg/config");

        let dirs = ClientConfig::config_search_dirs();

        assert_eq!(
            dirs[0],
            PathBuf::from("/custom/xdg/config"),
            "XDG_CONFIG_HOME should be first in search order"
        );
    }

    #[test]
    #[serial]
    fn test_find_config_file_prefers_client_toml() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let router_hosts_dir = temp.path().join("router-hosts");
        std::fs::create_dir_all(&router_hosts_dir).unwrap();

        // Create both files
        std::fs::write(router_hosts_dir.join("client.toml"), "[server]").unwrap();
        std::fs::write(router_hosts_dir.join("config.toml"), "[server]").unwrap();

        let _guard = EnvGuard::set("XDG_CONFIG_HOME", temp.path().to_str().unwrap());

        let found = ClientConfig::find_config_file();
        assert!(found.is_some());
        assert!(
            found.unwrap().ends_with("client.toml"),
            "Should prefer client.toml over config.toml"
        );
    }

    #[test]
    #[serial]
    fn test_find_config_file_falls_back_to_config_toml() {
        use tempfile::TempDir;

        let temp = TempDir::new().unwrap();
        let router_hosts_dir = temp.path().join("router-hosts");
        std::fs::create_dir_all(&router_hosts_dir).unwrap();

        // Create only config.toml
        std::fs::write(router_hosts_dir.join("config.toml"), "[server]").unwrap();

        let _guard = EnvGuard::set("XDG_CONFIG_HOME", temp.path().to_str().unwrap());

        let found = ClientConfig::find_config_file();
        assert!(found.is_some());
        assert!(
            found.unwrap().ends_with("config.toml"),
            "Should find config.toml when client.toml doesn't exist"
        );
    }

    #[test]
    #[serial]
    fn test_load_from_default_location_with_config_toml() {
        use tempfile::TempDir;

        // Clear env vars
        let _g1 = EnvGuard::remove("ROUTER_HOSTS_SERVER");
        let _g2 = EnvGuard::remove("ROUTER_HOSTS_CERT");
        let _g3 = EnvGuard::remove("ROUTER_HOSTS_KEY");
        let _g4 = EnvGuard::remove("ROUTER_HOSTS_CA");

        let temp = TempDir::new().unwrap();
        let router_hosts_dir = temp.path().join("router-hosts");
        std::fs::create_dir_all(&router_hosts_dir).unwrap();

        // Write config.toml (not client.toml)
        let config_content = r#"
[server]
address = "found-via-config-toml:50051"

[tls]
cert_path = "/etc/certs/client.crt"
key_path = "/etc/certs/client.key"
ca_cert_path = "/etc/certs/ca.crt"
"#;
        std::fs::write(router_hosts_dir.join("config.toml"), config_content).unwrap();

        let _xdg_guard = EnvGuard::set("XDG_CONFIG_HOME", temp.path().to_str().unwrap());

        let config = ClientConfig::load(None, None, None, None, None).unwrap();
        assert_eq!(
            config.server_address, "found-via-config-toml:50051",
            "Should load from config.toml in XDG location"
        );
    }
}
