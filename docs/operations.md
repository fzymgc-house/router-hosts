# Operations Guide

This document covers operational aspects of running router-hosts in production.

## Post-Edit Hooks

Server executes shell commands after /etc/hosts updates:

- `on_success` hooks - after successful regeneration (e.g., reload dnsmasq)
- `on_failure` hooks - after failed regeneration (e.g., alerting)
- Hooks run with 30s timeout, failures logged but don't fail operation
- Environment variables provide context (event type, entry count, snapshot ID)

### Configuration Example

```toml
[hooks]
on_success = [
    "systemctl reload dnsmasq",
    "/usr/local/bin/notify-slack.sh"
]
on_failure = [
    "/usr/local/bin/alert-ops.sh"
]
```

### Environment Variables

Hooks receive these environment variables:

| Variable | Description |
|----------|-------------|
| `ROUTER_HOSTS_EVENT` | Event type (add, update, delete, import) |
| `ROUTER_HOSTS_ENTRY_COUNT` | Number of entries after operation |
| `ROUTER_HOSTS_SNAPSHOT_ID` | ID of created snapshot (if any) |

## Certificate Reload via SIGHUP

The server supports dynamic TLS certificate reload via SIGHUP signal (Unix only).

### How It Works

1. Server receives SIGHUP signal
2. Validates new certificates on disk (PEM format, key present, CA present)
3. If valid: graceful shutdown (30s drain), restart with new certs
4. If invalid: logs error, keeps running with current certs

### Graceful Shutdown Details

During the 30-second graceful shutdown period:

- **New connections**: Rejected (server stops accepting)
- **In-flight gRPC requests**: Allowed to complete
- **WriteQueue operations**: Continue processing until completion or timeout
- **Storage layer**: Shared across reloads (database connections persist)

If the timeout expires before all operations complete, remaining connections are forcibly closed. The server logs a warning indicating some requests may have been interrupted.

**What persists across reloads:**
- Storage backend (DuckDB/SQLite/PostgreSQL connection)
- CommandHandler (business logic)
- HookExecutor (post-edit hooks configuration)
- HostsFileGenerator (output path configuration)

**What is recreated:**
- TLS certificates (the whole point of SIGHUP)
- gRPC server instance
- WriteQueue (fresh channel and worker task)

### Usage

```bash
# Find server PID and send SIGHUP
pkill -HUP router-hosts

# Or with explicit PID
kill -HUP $(pgrep router-hosts)
```

### Integration with Vault Agent

Configure Vault Agent to send SIGHUP after certificate renewal:

```hcl
template {
  source      = "cert.tpl"
  destination = "/etc/router-hosts/server.crt"
  command     = "pkill -HUP router-hosts"
}
```

### Platform Support

| Platform | SIGHUP Support |
|----------|----------------|
| Linux    | Yes            |
| macOS    | Yes            |
| Windows  | No (logs warning) |

### Certificate Validation

**What gets validated on SIGHUP:**
- Files exist and are readable
- Valid PEM format
- Private key can be parsed
- CA certificate can be parsed

**What doesn't get validated:**
- Certificate expiry (server starts with expired certs)
- CA chain validity (checked at connection time)
- Key/cert match (checked by tonic on load)

## Logging

The server uses `tracing` for structured logging.

### Log Levels

| Level | Use Case |
|-------|----------|
| `error` | Operation failures, certificate errors |
| `warn` | Degraded operation, hook timeouts |
| `info` | Normal operations, startup/shutdown |
| `debug` | Request details, hook execution |
| `trace` | Wire-level details |

### Configuration

Set via `RUST_LOG` environment variable:

```bash
# All components at info level
RUST_LOG=info router-hosts server

# Debug for storage, info for everything else
RUST_LOG=info,router_hosts_storage=debug router-hosts server

# Trace gRPC traffic
RUST_LOG=info,tonic=trace router-hosts server
```

## Monitoring

### Health Checks

The server exposes gRPC health checking (future enhancement):

```bash
grpc_health_probe -addr=localhost:50051 -tls \
  -tls-ca-cert=/path/to/ca.crt \
  -tls-client-cert=/path/to/client.crt \
  -tls-client-key=/path/to/client.key
```

### Metrics

Metrics are logged but not yet exposed via Prometheus endpoint (future enhancement).

Key metrics to monitor:
- Request latency (p50, p95, p99)
- Request error rate
- Active connections
- Storage operation duration
- Hook execution time

## Backup and Recovery

### Automatic Snapshots

The server creates snapshots before destructive operations:
- Before import (replaces all hosts)
- Before rollback (creates backup of current state)

### Manual Backup

```bash
# Export current state
router-hosts host export --format json > backup.json

# List available snapshots
router-hosts snapshot list

# View specific snapshot
router-hosts snapshot show <id>
```

### Recovery

```bash
# Rollback to previous snapshot
router-hosts snapshot rollback <id>

# Import from backup
router-hosts host import --file backup.json --conflict-mode replace
```

### Retention Policy

Configure snapshot retention in server config:

```toml
[retention]
max_count = 50          # Keep at most 50 snapshots
max_age_days = 30       # Delete snapshots older than 30 days
```

## Security Considerations

### File Permissions

| File | Recommended Permissions |
|------|------------------------|
| Server certificate | 0644 |
| Server private key | 0600 |
| CA certificate | 0644 |
| Database file | 0600 |
| Hosts file | 0644 |

### Network Security

- Server binds to configured address only
- TLS 1.2+ required (rustls defaults)
- Client certificates required for all connections
- No anonymous or insecure connections allowed

### Audit Trail

All operations are logged with:
- Client certificate subject (who)
- Operation type and parameters (what)
- Timestamp (when)
- Success/failure status (outcome)
