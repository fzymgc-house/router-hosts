# ACME Support Design Document

**Date:** 2025-12-19
**Issue:** #15
**Status:** Implemented (PR #126 Phase 1 HTTP-01, PR #137 Phase 2 DNS-01)

## Overview

Add automatic TLS certificate management via ACME (Automated Certificate Management Environment) protocol to the router-hosts server. This enables automatic provisioning and renewal of server TLS certificates from Let's Encrypt or other ACME-compatible CAs.

## Scope

### In Scope
- **ACME for server certificate only** - The server's TLS certificate is automatically managed
- Client CA verification remains unchanged - clients must still present certificates signed by the configured CA
- HTTP-01 and DNS-01 challenge types
- Cloudflare DNS provider (built-in)
- Generic webhook DNS provider for extensibility
- Integration with existing SIGHUP certificate reload mechanism

### Out of Scope
- ACME for client certificates (mTLS client verification unchanged)
- TLS-ALPN-01 challenge (complex, rarely needed)
- Other DNS providers beyond Cloudflare (can add later via webhook)

## Design Decisions

### 1. Certificate Scope

ACME manages **server TLS certificate only**. Client authentication continues via traditional mTLS:
- Server presents ACME-issued certificate to clients
- Clients must present certificates signed by configured CA
- No changes to client validation logic

**Rationale:** Public CAs (Let's Encrypt) issue server certs, not client certs. Internal PKI handles client authentication.

### 2. Challenge Types

Support both HTTP-01 and DNS-01:

| Challenge | When to Use | Requirement |
|-----------|------------|-------------|
| HTTP-01 | Public-facing servers | Port 80 accessible from internet |
| DNS-01 | Internal servers, wildcards | DNS API access |

### 3. Environment Variable Expansion

Use `${VAR}` syntax for secrets in configuration:

```toml
[acme.dns.cloudflare]
api_token = "${CLOUDFLARE_API_TOKEN}"
```

**Expansion Rules:**
- `${VAR}` - Required variable, error if missing
- `${VAR:-default}` - Use default if VAR is unset or empty
- Expansion occurs at config load time
- Raw `$` can be escaped as `$$`

**Rationale:** Shell-style syntax is familiar and doesn't require special quoting in TOML.

### 4. Certificate Storage and Reload

ACME writes certificates to the same paths configured in `[tls]`:

```toml
[tls]
cert_path = "/etc/router-hosts/server.crt"
key_path = "/etc/router-hosts/server.key"
ca_cert_path = "/etc/router-hosts/ca.crt"
```

After writing new certs, ACME triggers SIGHUP for hot reload.

**Rationale:** Reuses existing infrastructure, no new file paths to manage.

### 5. Renewal Timing

Conservative renewal schedule:
- **Renewal window:** 30 days before expiry (Let's Encrypt certs are 90 days)
- **Retry interval:** 12 hours on failure
- **Jitter:** ±1 hour to avoid thundering herd

### 6. DNS Providers

#### Cloudflare (Built-in)

```toml
[acme.dns.cloudflare]
api_token = "${CLOUDFLARE_API_TOKEN}"
zone_id = "optional-zone-id"  # Auto-detected if omitted
```

#### Webhook (Generic)

```toml
[acme.dns.webhook]
create_url = "https://dns-api.example.com/records"
delete_url = "https://dns-api.example.com/records/{record_id}"
headers = { Authorization = "Bearer ${DNS_API_TOKEN}" }
```

**Webhook Protocol:**
- POST to `create_url` with JSON: `{"type": "TXT", "name": "_acme-challenge.domain.com", "content": "token"}`
- DELETE to `delete_url` with `{record_id}` substituted

## Configuration Schema

```toml
[acme]
enabled = true
directory_url = "https://acme-v02.api.letsencrypt.org/directory"  # or staging
email = "admin@example.com"
domains = ["router.example.com", "*.router.example.com"]
challenge_type = "dns-01"  # or "http-01"

# For HTTP-01 challenge
[acme.http]
bind_address = "0.0.0.0:80"

# For DNS-01 challenge with Cloudflare
[acme.dns.cloudflare]
api_token = "${CLOUDFLARE_API_TOKEN}"

# OR for DNS-01 challenge with webhook
[acme.dns.webhook]
create_url = "https://api.example.com/dns/txt"
delete_url = "https://api.example.com/dns/txt/{record_id}"
headers = { Authorization = "Bearer ${DNS_TOKEN}" }
```

## Implementation Phases

### Phase 1: Core Infrastructure (This PR)
1. Config parsing with `${VAR}` expansion
2. `instant-acme` integration for ACME client
3. HTTP-01 challenge solver (standalone HTTP server)
4. Certificate writing + SIGHUP trigger
5. Renewal loop with exponential backoff

### Phase 2: DNS Providers (Follow-up PR)
1. Cloudflare DNS-01 provider
2. Webhook DNS-01 provider
3. Zone ID auto-detection for Cloudflare

### Phase 3: Polish (Follow-up PR)
1. Metrics/observability for cert renewal
2. CLI command to force renewal
3. Health check endpoint for cert expiry

## Error Handling

| Error | Behavior |
|-------|----------|
| Missing env var | Fail at config load with clear error message |
| ACME rate limit | Exponential backoff, max 24h retry |
| Challenge timeout | Retry after 12h |
| Certificate write fail | Log error, keep existing cert |
| SIGHUP trigger fail | Log error, cert is on disk for manual reload |

## Testing Strategy

1. **Unit tests:** Env var expansion, config parsing
2. **Integration tests:** Mock ACME server (pebble)
3. **E2E tests:** Real Let's Encrypt staging environment (optional, CI-only)

## Security Considerations

1. **Secrets in config:** Environment variables keep secrets out of config files
2. **Private key handling:** Keys written with 0600 permissions, never logged
3. **ACME account key:** Stored alongside certs, backed up with cert backup
4. **DNS credentials:** Scoped to minimum permissions (zone edit only)

## Dependencies

New workspace dependencies added:
- `instant-acme = "0.7"` - ACME client
- `rcgen = "0.13"` - CSR generation
- `reqwest = "0.12"` - HTTP client for DNS APIs
- `hyper = "1.5"` - HTTP-01 challenge server
- `hyper-util = "0.1"` - Hyper utilities
- `http-body-util = "0.1"` - HTTP body utilities
- `regex = "1.11"` - Environment variable expansion parsing

## Open Questions

None - all design decisions approved during brainstorming.
