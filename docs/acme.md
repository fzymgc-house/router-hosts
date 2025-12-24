# ACME Certificate Management

The server supports automatic TLS certificate management via ACME protocol (e.g., Let's Encrypt).

## Enabling ACME

Add an `[acme]` section to your server configuration:

```toml
[acme]
enabled = true
directory_url = "https://acme-v02.api.letsencrypt.org/directory"  # Or staging URL for testing
email = "admin@example.com"
domains = ["router.example.com", "api.example.com"]
challenge_type = "http-01"  # or "dns-01" for wildcard certs and internal servers

[acme.renewal]
days_before_expiry = 30     # Renew when cert expires within 30 days
jitter_minutes = 60         # Random delay to prevent thundering herd
```

## Challenge Types

### HTTP-01

Best for publicly accessible servers:
- Requires port 80 accessible from the internet
- Simpler setup, no DNS API access needed
- Cannot issue wildcard certificates

### DNS-01

Best for internal servers and wildcards:
- Works behind firewalls
- Supports wildcard certificates (`*.example.com`)
- Requires DNS provider API access

## DNS-01 Challenge Configuration

For DNS-01 challenges, configure one DNS provider. Supports Cloudflare (built-in) or any DNS API via webhook.

### Cloudflare Provider

```toml
[acme]
enabled = true
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
email = "admin@example.com"
domains = ["*.example.com", "example.com"]  # Wildcard requires DNS-01
challenge_type = "dns-01"

[acme.dns.cloudflare]
api_token = "${CF_API_TOKEN}"  # Token with Zone:DNS:Edit permission
zone_id = "abc123"             # Optional - auto-detected from domain if omitted
```

### Webhook Provider (generic)

For DNS providers without built-in support:

```toml
[acme]
enabled = true
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
email = "admin@example.com"
domains = ["internal.example.com"]
challenge_type = "dns-01"

[acme.dns.webhook]
# POST to create TXT record, expects {"id": "record-id"} response
create_url = "https://dns-api.example.com/records"
# DELETE to remove record, {record_id} replaced with ID from create response
delete_url = "https://dns-api.example.com/records/{record_id}"
timeout_seconds = 30  # Request timeout (propagation delay is fixed at 120s)

[acme.dns.webhook.headers]
Authorization = "Bearer ${DNS_API_TOKEN}"
```

## Environment Variable Expansion

Sensitive values can reference environment variables:

```toml
[acme.dns.cloudflare]
api_token = "${CF_API_TOKEN}"                    # Required
zone_id = "${CF_ZONE_ID:-auto}"                  # With default
```

Supported syntax:
- `${VAR}` - Required variable (fails if unset/empty)
- `${VAR:-default}` - Use default if unset/empty
- `$$` - Literal dollar sign

## File Locations

| File | Path | Permissions |
|------|------|-------------|
| Certificate | Configured TLS cert path | 0644 |
| Private Key | Configured TLS key path | 0600 |
| Account Credentials | `<data_dir>/acme-account.json` | 0600 |

### Windows Security Note

On Windows, Unix-style file permissions (0600) cannot be set.
Credential files inherit permissions from the parent directory's ACL. Operators must ensure
the credentials directory is only accessible by the service account. A warning is logged
when writing credentials on non-Unix platforms.

### Platform-Specific Defaults

The default `credentials_path` (`/var/lib/router-hosts/acme-account.json`)
is Unix-specific. On Windows, you must explicitly set this to a valid path:

```toml
[acme]
credentials_path = "C:\\ProgramData\\router-hosts\\acme-account.json"
```

## Testing with Pebble

ACME integration tests use [Pebble](https://github.com/letsencrypt/pebble) (Let's Encrypt's test server).
Tests run locally with Docker but are not yet integrated into CI.

**Running locally:**
```bash
cargo test -p router-hosts acme  # Runs Pebble tests via testcontainers
```

**CI integration:** Tracked in issue #127. Requires configuring Pebble's self-signed CA
certificate trust in the CI environment.

## Troubleshooting

### HTTP-01 Challenge Issues

**Certificate renewal fails repeatedly:**
1. Verify DNS records point to this server
2. Ensure port 80 is accessible from the internet
3. Check Let's Encrypt rate limits: https://letsencrypt.org/docs/rate-limits/
4. Review server logs for detailed error messages

### DNS-01 Challenge Issues

**"Zone not found" error:**
- Verify the domain matches a zone in your DNS provider account
- For Cloudflare: check the zone exists in your account dashboard
- If using subdomains, the parent zone must exist (e.g., `sub.example.com` requires `example.com` zone)
- Consider explicitly configuring `zone_id` instead of relying on auto-detection

**"API token invalid" or authentication errors:**
- Cloudflare: Verify token has `Zone:DNS:Edit` permission
- Cloudflare: Ensure token is scoped to the correct zone
- Check token hasn't expired or been revoked
- Verify environment variable expansion is working: `echo $CF_API_TOKEN`

**"DNS record creation timed out" error:**
- Check DNS provider API status page for outages
- Verify network connectivity to DNS provider API
- For Cloudflare: check you haven't hit API rate limits (1200 requests/5 min)
- Try increasing `DNS_OPERATION_TIMEOUT` if on slow network

**Challenge validation fails after record creation:**
- Increase propagation delay in config (default: 10s for Cloudflare, 120s for webhook)
- Use `dig _acme-challenge.yourdomain.com TXT` to verify record is visible
- Some DNS providers have longer propagation times

**Stale TXT records after failed renewal:**
- If renewal crashes, `_acme-challenge.*` TXT records may remain
- Manually delete via DNS provider dashboard or API
- These don't affect functionality but clutter your DNS zone

### General Issues

**Rate limit errors:**
- Let's Encrypt allows 5 certificates per domain per week
- Use staging URL for testing: `https://acme-staging-v02.api.letsencrypt.org/directory`
- Wait 1 week for rate limits to reset

**Account credential backup:**
- The `acme-account.json` file contains your ACME account private key
- Back up this file to avoid needing to re-register with Let's Encrypt
- File is written atomically with 0600 permissions
