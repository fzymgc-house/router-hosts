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

pub mod cert_writer;
pub mod client;
pub mod config;
pub mod dns_provider;
pub mod env_expand;
pub mod http_challenge;
pub mod renewal;

// Re-export types needed by server config
pub use config::{AcmeConfig, AcmeConfigError};

// ACME client types (will be used when integration is complete)
#[allow(unused_imports)]
pub use client::{AcmeClient, AcmeError, CertificateBundle};

// Additional types will be used in later implementation phases
#[allow(unused_imports)]
pub use config::{
    ChallengeType, CloudflareConfig, DnsConfig, HttpChallengeConfig, RenewalConfig, WebhookConfig,
};
#[allow(unused_imports)]
pub use env_expand::{contains_env_vars, expand_env_vars, EnvExpandError};

// HTTP-01 challenge server types (will be used when ACME integration is complete)
#[allow(unused_imports)]
pub use http_challenge::{
    ChallengeStore, HttpChallengeError, HttpChallengeHandle, HttpChallengeServer,
};

// Certificate writing and SIGHUP trigger (will be used when ACME integration is complete)
#[allow(unused_imports)]
pub use cert_writer::{
    trigger_reload, trigger_reload_async, write_certificate, CertWriteError, CertWriteResult,
};

// Renewal loop types (will be used when ACME is integrated into server)
#[allow(unused_imports)]
pub use renewal::{AcmeRenewalLoop, RenewalError, RenewalHandle, TlsPaths};

// DNS provider types for DNS-01 challenge
#[allow(unused_imports)]
pub use dns_provider::{
    compute_dns01_digest, CloudflareProvider, DnsProvider, DnsProviderError, DnsRecord,
    WebhookProvider,
};
