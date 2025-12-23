# DNS-01 Challenge Implementation Design

**Date:** 2025-12-22
**Issue:** #130
**Status:** Implemented (PR #137, merged 2025-12-23)

## Overview

Implement DNS-01 challenge support for ACME certificate management, enabling certificate acquisition for internal servers without port 80 access and wildcard certificates.

## Scope

### In Scope
- DNS provider trait abstraction
- Cloudflare DNS provider (built-in)
- Webhook DNS provider (generic/extensible)
- Zone ID auto-detection for Cloudflare
- DNS propagation delay handling
- Integration with existing renewal loop

### Out of Scope
- Other DNS providers (Route53, DigitalOcean, etc.) - use webhook
- CNAME delegation support (can add later)
- Multi-zone support (single zone per domain)

## Design

### 1. DNS Provider Trait

A common interface for all DNS providers:

```rust
/// Result of creating a DNS record
pub struct DnsRecord {
    /// Provider-specific record identifier for cleanup
    pub record_id: String,
    /// The domain name (e.g., "_acme-challenge.example.com")
    pub name: String,
}

/// Trait for DNS providers that can manage ACME challenge records
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create a TXT record for ACME challenge
    async fn create_txt_record(
        &self,
        domain: &str,
        content: &str,
    ) -> Result<DnsRecord, DnsProviderError>;

    /// Delete a previously created TXT record
    async fn delete_txt_record(&self, record: &DnsRecord) -> Result<(), DnsProviderError>;

    /// Wait for DNS propagation (provider-specific delay)
    async fn wait_for_propagation(&self);
}
```

**Rationale:** Trait-based design allows adding new providers without modifying core logic. The `record_id` enables cleanup regardless of whether the record name changed.

### 2. Cloudflare Provider

Uses Cloudflare's REST API v4:

```rust
pub struct CloudflareProvider {
    client: reqwest::Client,
    api_token: String,
    zone_id: String,
}

impl CloudflareProvider {
    /// Create provider with explicit zone ID
    pub fn new(api_token: String, zone_id: String) -> Self;

    /// Create provider with auto-detected zone ID
    pub async fn with_auto_zone(api_token: String, domain: &str) -> Result<Self, DnsProviderError>;
}
```

**API Endpoints:**
- `GET /zones?name={domain}` - Zone ID lookup
- `POST /zones/{zone_id}/dns_records` - Create TXT record
- `DELETE /zones/{zone_id}/dns_records/{record_id}` - Delete record

**Propagation:** 10 seconds (Cloudflare is fast)

### 3. Webhook Provider

Generic HTTP webhook for custom DNS APIs:

```rust
pub struct WebhookProvider {
    client: reqwest::Client,
    create_url: String,
    delete_url: String,  // Contains {record_id} placeholder
    headers: HashMap<String, String>,
    timeout: Duration,
}
```

**Create Request:**
```json
POST {create_url}
Content-Type: application/json

{
    "type": "TXT",
    "name": "_acme-challenge.example.com",
    "content": "challenge-token-hash"
}
```

**Create Response:**
```json
{
    "id": "record-123"
}
```

**Delete Request:**
```
DELETE {delete_url with {record_id} replaced}
```

**Propagation:** 120 seconds (conservative for unknown providers)

### 4. Challenge Flow Integration

Modify `renewal.rs` to support DNS-01:

```rust
AcmeChallengeType::Dns01 => {
    // 1. Get key authorization and compute digest
    let key_auth = order.key_authorization(challenge);
    let digest = compute_dns01_digest(&key_auth);

    // 2. Create TXT record via DNS provider
    let record_name = format!("_acme-challenge.{}", domain);
    let record = dns_provider.create_txt_record(&record_name, &digest).await?;

    // 3. Wait for DNS propagation
    dns_provider.wait_for_propagation().await;

    // 4. Tell ACME server we're ready
    order.set_challenge_ready(&challenge.url).await?;

    // 5. Wait for validation
    self.wait_for_order_ready(&mut order, auth.identifier.clone()).await?;

    // 6. Cleanup TXT record (best-effort, don't fail on error)
    if let Err(e) = dns_provider.delete_txt_record(&record).await {
        warn!(error = %e, "Failed to cleanup DNS challenge record");
    }
}
```

### 5. DNS-01 Digest Computation

Per RFC 8555, the TXT record value is:

```rust
fn compute_dns01_digest(key_authorization: &str) -> String {
    use sha2::{Sha256, Digest};
    use base64::Engine;

    let hash = Sha256::digest(key_authorization.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}
```

### 6. Configuration Integration

Update `validate_and_expand()` in `config.rs`:

```rust
ChallengeType::Dns01 => {
    let dns = self.dns.as_mut().ok_or_else(|| {
        AcmeConfigError::MissingField("acme.dns (required for dns-01 challenge)".into())
    })?;
    dns.validate_and_expand()?;
}
```

### 7. Provider Construction

Add method to create provider from config:

```rust
impl DnsConfig {
    pub async fn into_provider(self) -> Result<Box<dyn DnsProvider>, DnsProviderError> {
        if let Some(cf) = self.cloudflare {
            // Auto-detect zone ID if not specified
            let provider = if let Some(zone_id) = cf.zone_id {
                CloudflareProvider::new(cf.api_token, zone_id)
            } else {
                CloudflareProvider::with_auto_zone(cf.api_token, &domain).await?
            };
            return Ok(Box::new(provider));
        }

        if let Some(wh) = self.webhook {
            return Ok(Box::new(WebhookProvider::new(
                wh.create_url,
                wh.delete_url,
                wh.headers,
                Duration::from_secs(wh.timeout_seconds),
            )));
        }

        Err(DnsProviderError::NoProviderConfigured)
    }
}
```

## File Structure

```
crates/router-hosts/src/server/acme/
├── mod.rs              # Add dns_provider module
├── dns_provider/
│   ├── mod.rs          # DnsProvider trait, DnsRecord, DnsProviderError
│   ├── cloudflare.rs   # CloudflareProvider implementation
│   └── webhook.rs      # WebhookProvider implementation
├── config.rs           # Update DNS-01 validation (remove error, call dns.validate_and_expand)
└── renewal.rs          # Add DNS-01 challenge handling
```

## Dependencies

Already in workspace `Cargo.toml`:
- `reqwest = "0.12"` - HTTP client for DNS APIs
- `sha2 = "0.10"` - SHA256 for digest computation
- `base64 = "0.22"` - Base64 encoding for digest

New dependencies needed:
- None (all required crates already present)

## Error Handling

| Error | Behavior |
|-------|----------|
| Zone lookup failed | Fail with clear error message including domain |
| Record creation failed | Retry once, then fail order |
| Record deletion failed | Log warning, continue (best-effort cleanup) |
| Propagation timeout | N/A - fixed delay, no polling |
| API rate limit | Exponential backoff with max 3 retries |

## Testing Strategy

1. **Unit tests:** Digest computation, URL template substitution
2. **Integration tests:** Mock HTTP server for Cloudflare/webhook APIs
3. **E2E tests:** Pebble + challtestsrv (DNS challenge test server)

## Security Considerations

1. **API tokens:** Loaded from environment variables, never logged
2. **Minimal permissions:** Cloudflare token needs only "Zone:DNS:Edit"
3. **TLS verification:** All API calls use HTTPS with certificate verification
4. **Record cleanup:** Always attempt cleanup to avoid DNS pollution

## Implementation Order

1. Create `dns_provider/mod.rs` with trait and error types
2. Implement `dns_provider/cloudflare.rs`
3. Implement `dns_provider/webhook.rs`
4. Update `config.rs` to call DNS validation
5. Update `renewal.rs` with DNS-01 challenge flow
6. Add unit tests for each component
7. Add integration tests with mock servers
