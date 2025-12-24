# Troubleshooting Guide

This document covers common issues and their solutions.

## Connection Issues

### "Connection refused" error

**Symptoms:** Client cannot connect to server

**Causes and solutions:**
1. Server not running - start the server
2. Wrong address/port - check configuration
3. Firewall blocking connection - add firewall rule
4. Server bound to wrong interface - check `bind_address` in config

### "Certificate verify failed" error

**Symptoms:** TLS handshake fails

**Causes and solutions:**
1. Wrong CA certificate - verify CA matches server's issuer
2. Certificate expired - check certificate dates with `openssl x509 -in cert.pem -noout -dates`
3. Hostname mismatch - verify server certificate includes the hostname you're connecting to
4. Clock skew - ensure client and server clocks are synchronized

### "Permission denied" error

**Symptoms:** Client authenticates but operations fail

**Causes and solutions:**
1. Client certificate not trusted by server CA
2. Client certificate revoked (if CRL checking enabled)
3. Certificate subject doesn't match access rules (if implemented)

## Database Issues

### "Database locked" error (SQLite)

**Symptoms:** Operations fail with database lock errors

**Causes and solutions:**
1. Multiple processes accessing same database file - use PostgreSQL for multi-instance
2. Stale lock file - delete `.db-wal` and `.db-shm` files if server crashed
3. NFS/network filesystem - SQLite doesn't work well on network filesystems

### "Connection pool exhausted" error (PostgreSQL)

**Symptoms:** Operations timeout waiting for database connection

**Causes and solutions:**
1. Pool too small - increase `max_connections` in config
2. Long-running transactions - check for stuck queries
3. Connection leak - check server logs for unclosed connections

## Hosts File Issues

### Changes not appearing

**Symptoms:** Added/updated hosts not visible in /etc/hosts

**Causes and solutions:**
1. Server hasn't regenerated file - check server logs
2. Post-edit hook failed - check hook execution logs
3. File permissions - verify server can write to hosts file
4. Atomic rename failed - check disk space and filesystem

### Hosts file corrupted

**Symptoms:** /etc/hosts has invalid content

**Solutions:**
1. Rollback to previous snapshot: `router-hosts snapshot rollback <id>`
2. Export and reimport:
   ```bash
   router-hosts snapshot show <id> > backup.txt
   # Fix manually if needed
   router-hosts host import --file backup.txt --conflict-mode replace
   ```

## ACME Issues

See [ACME documentation](acme.md#troubleshooting) for certificate-specific issues.

### Quick ACME Checklist

1. **HTTP-01 failures:**
   - DNS points to this server?
   - Port 80 accessible?
   - Rate limited? (check logs)

2. **DNS-01 failures:**
   - Zone exists in provider?
   - API token has correct permissions?
   - Record propagated? (use `dig`)

## Performance Issues

### Slow list/search operations

**Causes and solutions:**
1. Large dataset - add pagination with `--limit` and `--offset`
2. Missing indexes - check database configuration
3. Network latency - consider local caching or PostgreSQL read replicas

### High memory usage

**Causes and solutions:**
1. Large import - use streaming import instead of loading all at once
2. Event log too large - configure retention to prune old events
3. Connection pool too large - reduce pool size

## Hook Issues

### Hooks not executing

**Causes and solutions:**
1. Hook disabled - check `[hooks]` section in config
2. Script not executable - `chmod +x /path/to/hook.sh`
3. Script not found - use absolute paths
4. Timeout - hooks have 30s default timeout

### Hook executing but no effect

**Causes and solutions:**
1. Environment variables - hooks run in limited environment
2. Working directory - hooks run from server's working directory
3. Error not logged - add explicit logging to hook script

## Logging and Debugging

### Enable debug logging

```bash
# Server
RUST_LOG=debug router-hosts server

# Specific component
RUST_LOG=info,router_hosts_storage=debug router-hosts server

# Very verbose
RUST_LOG=trace router-hosts server
```

### Common log patterns

| Pattern | Meaning |
|---------|---------|
| `accepted connection` | Client connected successfully |
| `TLS handshake failed` | Certificate issue |
| `event stored` | Write operation succeeded |
| `regenerating hosts file` | About to update /etc/hosts |
| `hook completed` | Post-edit hook finished |
| `SIGHUP received` | Certificate reload triggered |

## Getting Help

If you can't resolve an issue:

1. Check the [GitHub issues](https://github.com/fzymgc-house/router-hosts/issues) for similar problems
2. Enable debug logging and capture relevant output
3. Open a new issue with:
   - router-hosts version (`router-hosts --version`)
   - Operating system and version
   - Configuration (redact sensitive values)
   - Error messages and logs
   - Steps to reproduce

## Recovery Procedures

### Complete database recovery

If the database is corrupted beyond repair:

```bash
# Stop server
systemctl stop router-hosts

# Backup corrupted database (for analysis)
mv /var/lib/router-hosts/hosts.db /var/lib/router-hosts/hosts.db.corrupt

# Reimport from most recent export
router-hosts host import --file /backup/hosts-export.json

# Or reimport from /etc/hosts directly
router-hosts host import --file /etc/hosts
```

### Certificate emergency replacement

If certificates are compromised:

```bash
# Generate new certificates (example with mkcert)
mkcert -install
mkcert -cert-file server.crt -key-file server.key router.example.com

# Replace on server
cp server.crt /etc/router-hosts/
cp server.key /etc/router-hosts/

# Trigger reload
pkill -HUP router-hosts

# Generate new client certs and distribute to clients
mkcert -client -cert-file client.crt -key-file client.key client@example.com
```
