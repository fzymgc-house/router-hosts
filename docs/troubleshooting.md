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
2. List snapshots and reimport:

   ```bash
   router-hosts snapshot list
   # Choose a snapshot ID from the list, then rollback:
   router-hosts snapshot rollback <id>
   ```

## ACME Issues

See [ACME documentation](guides/acme.md#troubleshooting) for certificate-specific issues.

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

## Kubernetes Operator Issues

The router-hosts operator watches Kubernetes resources and creates DNS entries automatically.

> **Note:** The Go operator reconciles two resource types — `HostMapping` and Traefik `IngressRoute`/`IngressRouteTCP`. There is no Kubernetes `Service` controller and no `enabled`/`hostname`/`ip-address` annotation API. See the [Kubernetes Operator guide](guides/kubernetes.md).

### HostMapping not syncing

**Symptoms:** `HostMapping` exists but no DNS entry is created; `status.phase` is `Error`.

**Causes and solutions:**

1. `spec.ip` is missing or invalid — it is **required** and must be a valid IPv4/IPv6 address. (The field is `spec.ip`; the pre-0.10.2 CRD used `spec.ipAddress`.)
2. Read the failure reason from status:

```bash
kubectl get hostmapping <name> -n <namespace> \
  -o jsonpath='{.status.phase}{" "}{.status.message}'
```

### IngressRoute hostnames not registered

**Symptoms:** A Traefik `IngressRoute`/`IngressRouteTCP` exists but its hosts are missing from router-hosts.

**Causes and solutions:**

1. Only `` Host(`…`) `` (IngressRoute) and `` HostSNI(`…`) `` (IngressRouteTCP) patterns in `spec.routes[].match` are extracted. Other match expressions yield no hostnames.
2. Hostnames that fail RFC 1123 validation are logged and skipped — check the operator logs.
3. Entries are created with the operator's `--default-ingress-ip`. If that flag is empty, hosts are created with no IP; set `routerHosts.defaultIngressIP` in the chart.

```bash
# Operator logs (extraction warnings, gRPC errors)
kubectl logs -n router-hosts-system -l app.kubernetes.io/name=router-hosts-operator --tail=100

# Inspect the operator-managed host-id map on the resource
kubectl get ingressroute <name> -n <namespace> \
  -o jsonpath='{.metadata.annotations.router-hosts\.fzymgc\.house/host-ids}'
```

### DNS entry not updated after a resource change

**Symptoms:** Changed a `HostMapping`/`IngressRoute` but router-hosts doesn't reflect it.

**Causes and solutions:**

1. Check operator logs for reconcile errors.
2. Verify the router-hosts server is reachable.
3. Transient failures are retried with a requeue backoff — give it a moment.

### Operator not connecting to router-hosts server

**Symptoms:** All reconciliations fail with client errors

**Causes and solutions:**

1. Verify the server address passed via `--server-address` (Helm `routerHosts.serverAddress`)
2. Check mTLS certificates are valid and mounted
3. Verify network connectivity between operator and server

```bash
# Check operator configuration (flags are on the Deployment, not a CRD)
kubectl get deployment -n router-hosts-system router-hosts-operator \
  -o jsonpath='{.spec.template.spec.containers[0].args}'

# Check certificate secrets exist
kubectl get secrets -n router-hosts-system | grep tls
```

## Logging and Debugging

### Enable debug logging

```bash
# Server (with debug logging)
LOG_LEVEL=debug router-hosts serve

# Very verbose
LOG_LEVEL=trace router-hosts serve
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
router-hosts host import /backup/hosts-export.json --input-format json

# Or reimport from /etc/hosts directly
router-hosts host import /etc/hosts
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
