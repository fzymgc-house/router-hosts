//! ACME certificate management module
//!
//! This module provides automatic TLS certificate management via the ACME protocol,
//! supporting both HTTP-01 and DNS-01 challenges.
//!
//! # Features
//!
//! - **Automatic certificate provisioning** from Let's Encrypt or other ACME CAs
//! - **HTTP-01 challenge** for publicly accessible servers
//! - **DNS-01 challenge** for internal servers or wildcard certificates
//! - **Environment variable expansion** in configuration (`${VAR}` syntax)
//! - **Integration with SIGHUP** for hot certificate reload
//!
//! # Configuration Example
//!
//! ```toml
//! [acme]
//! enabled = true
//! directory_url = "https://acme-v02.api.letsencrypt.org/directory"
//! email = "admin@example.com"
//! domains = ["router.example.com"]
//! challenge_type = "http-01"
//!
//! [acme.http]
//! bind_address = "0.0.0.0:80"
//! ```
//!
//! For DNS-01 with Cloudflare:
//!
//! ```toml
//! [acme]
//! enabled = true
//! domains = ["router.example.com", "*.router.example.com"]
//! challenge_type = "dns-01"
//!
//! [acme.dns.cloudflare]
//! api_token = "${CLOUDFLARE_API_TOKEN}"
//! ```

pub mod config;
pub mod env_expand;

// Re-export types needed by server config
pub use config::{AcmeConfig, AcmeConfigError};

// Additional types will be used in later implementation phases
#[allow(unused_imports)]
pub use config::{
    ChallengeType, CloudflareConfig, DnsConfig, HttpChallengeConfig, RenewalConfig, WebhookConfig,
};
#[allow(unused_imports)]
pub use env_expand::{contains_env_vars, expand_env_vars, EnvExpandError};
