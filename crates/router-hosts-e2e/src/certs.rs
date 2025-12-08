//! Certificate generation for E2E tests
//!
//! Generates CA, server, and client certificates at runtime using rcgen.

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

/// Paths to certificate files on disk
#[derive(Debug, Clone)]
pub struct CertPaths {
    pub ca_cert: std::path::PathBuf,
    pub server_cert: std::path::PathBuf,
    pub server_key: std::path::PathBuf,
    pub client_cert: std::path::PathBuf,
    pub client_key: std::path::PathBuf,
}

/// Generated test certificates (PEM format)
#[derive(Debug, Clone)]
pub struct TestCertificates {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
}

impl TestCertificates {
    /// Generate a fresh set of test certificates
    pub fn generate() -> Self {
        Self::generate_with_validity(Duration::from_secs(3600)) // 1 hour
    }

    /// Generate certificates with specific validity period
    pub fn generate_with_validity(validity: Duration) -> Self {
        // 1. Generate CA
        let ca_key = KeyPair::generate().expect("Failed to generate CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params
            .distinguished_name
            .push(DnType::OrganizationName, "router-hosts-e2e");
        ca_params.not_before = time::OffsetDateTime::now_utc();
        ca_params.not_after = time::OffsetDateTime::now_utc() + validity;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("Failed to generate CA cert");

        // 2. Generate server cert (signed by CA)
        let server_key = KeyPair::generate().expect("Failed to generate server key");
        let mut server_params = CertificateParams::default();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_params.subject_alt_names = vec![
            SanType::DnsName("localhost".try_into().expect("Invalid DNS name")),
            SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        ];
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server_params.not_before = time::OffsetDateTime::now_utc();
        server_params.not_after = time::OffsetDateTime::now_utc() + validity;
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("Failed to generate server cert");

        // 3. Generate client cert (signed by CA)
        let client_key = KeyPair::generate().expect("Failed to generate client key");
        let mut client_params = CertificateParams::default();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "test-client");
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.not_before = time::OffsetDateTime::now_utc();
        client_params.not_after = time::OffsetDateTime::now_utc() + validity;
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("Failed to generate client cert");

        Self {
            ca_cert_pem: ca_cert.pem(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// Generate expired certificates for testing auth failure
    pub fn generate_expired() -> Self {
        let ca_key = KeyPair::generate().expect("Failed to generate CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Expired Test CA");
        ca_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        ca_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("Failed to generate CA cert");

        let client_key = KeyPair::generate().expect("Failed to generate client key");
        let mut client_params = CertificateParams::default();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "expired-client");
        client_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(2);
        client_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("Failed to generate client cert");

        Self {
            ca_cert_pem: ca_cert.pem(),
            server_cert_pem: String::new(),
            server_key_pem: String::new(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// Write certificates to a directory
    pub fn write_to_dir(&self, dir: &Path) -> std::io::Result<CertPaths> {
        let ca_cert = dir.join("ca.pem");
        let server_cert = dir.join("server.pem");
        let server_key = dir.join("server-key.pem");
        let client_cert = dir.join("client.pem");
        let client_key = dir.join("client-key.pem");

        std::fs::write(&ca_cert, &self.ca_cert_pem)?;
        std::fs::write(&server_cert, &self.server_cert_pem)?;
        std::fs::write(&server_key, &self.server_key_pem)?;
        std::fs::write(&client_cert, &self.client_cert_pem)?;
        std::fs::write(&client_key, &self.client_key_pem)?;

        Ok(CertPaths {
            ca_cert,
            server_cert,
            server_key,
            client_cert,
            client_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificates() {
        let certs = TestCertificates::generate();
        assert!(certs.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(certs.server_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(certs.server_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(certs.client_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(certs.client_key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_write_to_dir() {
        let certs = TestCertificates::generate();
        let temp_dir = tempfile::tempdir().unwrap();
        let paths = certs.write_to_dir(temp_dir.path()).unwrap();

        assert!(paths.ca_cert.exists());
        assert!(paths.server_cert.exists());
        assert!(paths.server_key.exists());
        assert!(paths.client_cert.exists());
        assert!(paths.client_key.exists());
    }
}
