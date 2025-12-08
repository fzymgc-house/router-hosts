//! CLI subprocess wrapper for E2E tests
//!
//! Provides a type-safe interface for running router-hosts CLI commands.

use crate::certs::CertPaths;
use assert_cmd::Command;
use std::path::PathBuf;

/// Wrapper for running CLI commands against a test server
pub struct TestCli {
    binary: PathBuf,
    server_address: String,
    cert_paths: CertPaths,
    config_path: PathBuf,
}

impl TestCli {
    /// Create a new CLI wrapper
    pub fn new(server_address: String, cert_paths: CertPaths, temp_dir: &std::path::Path) -> Self {
        let binary = crate::cli_binary();

        // Write client config file
        let config_path = temp_dir.join("client.toml");
        let config_content = format!(
            r#"[server]
address = "{}"

[tls]
cert_path = "{}"
key_path = "{}"
ca_cert_path = "{}"
"#,
            server_address,
            cert_paths.client_cert.display(),
            cert_paths.client_key.display(),
            cert_paths.ca_cert.display()
        );
        std::fs::write(&config_path, config_content).expect("Failed to write client config");

        Self {
            binary,
            server_address,
            cert_paths,
            config_path,
        }
    }

    /// Get a Command configured for this CLI
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("--config").arg(&self.config_path);
        cmd
    }

    /// Add a host entry
    pub fn add_host(&self, ip: &str, hostname: &str) -> AddHostBuilder<'_> {
        AddHostBuilder {
            cli: self,
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            comment: None,
            tags: Vec::new(),
        }
    }

    /// List all hosts
    pub fn list_hosts(&self) -> Command {
        let mut cmd = self.cmd();
        cmd.arg("list");
        cmd
    }

    /// Get a specific host by ID
    pub fn get_host(&self, id: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["get", id]);
        cmd
    }

    /// Delete a host
    pub fn delete_host(&self, id: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["delete", id]);
        cmd
    }

    /// Update a host
    pub fn update_host(&self, id: &str) -> UpdateHostBuilder<'_> {
        UpdateHostBuilder {
            cli: self,
            id: id.to_string(),
            ip: None,
            hostname: None,
            comment: None,
            tags: None,
        }
    }

    /// Search hosts
    pub fn search(&self, query: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["search", query]);
        cmd
    }

    /// Create a snapshot
    pub fn create_snapshot(&self, name: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["snapshot", "create", "--name", name]);
        cmd
    }

    /// List snapshots
    pub fn list_snapshots(&self) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["snapshot", "list"]);
        cmd
    }

    /// Rollback to a snapshot
    pub fn rollback(&self, snapshot_id: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["snapshot", "rollback", snapshot_id]);
        cmd
    }

    /// Export hosts
    pub fn export(&self, format: &str) -> Command {
        let mut cmd = self.cmd();
        cmd.args(["export", "--format", format]);
        cmd
    }

    /// Import hosts from file
    pub fn import(&self, file: &std::path::Path) -> ImportBuilder<'_> {
        ImportBuilder {
            cli: self,
            file: file.to_path_buf(),
            format: None,
            mode: None,
        }
    }

    /// Get the server address
    pub fn server_address(&self) -> &str {
        &self.server_address
    }

    /// Get the certificate paths
    pub fn cert_paths(&self) -> &CertPaths {
        &self.cert_paths
    }
}

/// Builder for add host command
pub struct AddHostBuilder<'a> {
    cli: &'a TestCli,
    ip: String,
    hostname: String,
    comment: Option<String>,
    tags: Vec<String>,
}

impl<'a> AddHostBuilder<'a> {
    pub fn comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    pub fn tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    pub fn build(self) -> Command {
        let mut cmd = self.cli.cmd();
        cmd.args(["add", "--ip", &self.ip, "--hostname", &self.hostname]);
        if let Some(comment) = &self.comment {
            cmd.args(["--comment", comment]);
        }
        for tag in &self.tags {
            cmd.args(["--tag", tag]);
        }
        cmd
    }
}

/// Builder for update host command
pub struct UpdateHostBuilder<'a> {
    cli: &'a TestCli,
    id: String,
    ip: Option<String>,
    hostname: Option<String>,
    comment: Option<String>,
    tags: Option<Vec<String>>,
}

impl<'a> UpdateHostBuilder<'a> {
    pub fn ip(mut self, ip: &str) -> Self {
        self.ip = Some(ip.to_string());
        self
    }

    pub fn hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_string());
        self
    }

    pub fn comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    pub fn tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = Some(tags.into_iter().map(String::from).collect());
        self
    }

    pub fn build(self) -> Command {
        let mut cmd = self.cli.cmd();
        cmd.args(["update", &self.id]);
        if let Some(ip) = &self.ip {
            cmd.args(["--ip", ip]);
        }
        if let Some(hostname) = &self.hostname {
            cmd.args(["--hostname", hostname]);
        }
        if let Some(comment) = &self.comment {
            cmd.args(["--comment", comment]);
        }
        if let Some(tags) = &self.tags {
            for tag in tags {
                cmd.args(["--tag", tag]);
            }
        }
        cmd
    }
}

/// Builder for import command
pub struct ImportBuilder<'a> {
    cli: &'a TestCli,
    file: PathBuf,
    format: Option<String>,
    mode: Option<String>,
}

impl<'a> ImportBuilder<'a> {
    pub fn format(mut self, format: &str) -> Self {
        self.format = Some(format.to_string());
        self
    }

    pub fn mode(mut self, mode: &str) -> Self {
        self.mode = Some(mode.to_string());
        self
    }

    pub fn build(self) -> Command {
        let mut cmd = self.cli.cmd();
        cmd.args(["import", self.file.to_str().unwrap()]);
        if let Some(format) = &self.format {
            cmd.args(["--format", format]);
        }
        if let Some(mode) = &self.mode {
            cmd.args(["--mode", mode]);
        }
        cmd
    }
}
