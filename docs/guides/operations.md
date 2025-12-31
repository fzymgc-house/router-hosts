# Operations Guide

This document covers operational aspects of running router-hosts in production.

## Post-Edit Hooks

Server executes shell commands after /etc/hosts updates:

- `on_success` hooks - after successful regeneration (e.g., reload dnsmasq)
- `on_failure` hooks - after failed regeneration (e.g., alerting)
- Hooks run with 30s timeout, failures logged but don't fail operation
- Environment variables provide context (event type, entry count, error message)

### Configuration Example

Each hook requires a `name` and `command`:

```toml
[[hooks.on_success]]
name = "reload-dns"
command = "systemctl reload dnsmasq"

[[hooks.on_success]]
name = "notify-slack"
command = "/usr/local/bin/notify-slack.sh"

[[hooks.on_failure]]
name = "alert-ops"
command = "/usr/local/bin/alert-ops.sh"
```

### Hook Name Requirements

Hook names must follow these rules:
- **Format**: Kebab-case only (lowercase letters, numbers, hyphens)
- **Length**: Maximum 50 characters
- **Uniqueness**: No duplicate names within the same hook type
- **Examples**: `reload-dns`, `alert-ops-team`, `log-update`

Hook names appear in health endpoints and logs, providing meaningful identification without exposing sensitive command details.

### Environment Variables

Hooks receive these environment variables:

| Variable | Description |
|----------|-------------|
| `ROUTER_HOSTS_EVENT` | "success" or "failure" |
| `ROUTER_HOSTS_ENTRY_COUNT` | Number of host entries |
| `ROUTER_HOSTS_ERROR` | Error message (failure hooks only) |

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

The server exposes health check RPCs within `HostsService` for monitoring and orchestration systems.

**Available Health RPCs:**

| RPC | Purpose | Checks |
|-----|---------|--------|
| `Liveness` | Process alive check | Returns immediately (no I/O) |
| `Readiness` | Ready to serve | Verifies database connectivity |
| `Health` | Detailed status | Server, database, ACME, hooks |

**Using grpcurl for health checks:**

```bash
# Check readiness (verifies database)
grpcurl -cacert /path/to/ca.crt \
  -cert /path/to/client.crt \
  -key /path/to/client.key \
  localhost:50051 router_hosts.v1.HostsService/Readiness

# Get detailed health status
grpcurl -cacert /path/to/ca.crt \
  -cert /path/to/client.crt \
  -key /path/to/client.key \
  localhost:50051 router_hosts.v1.HostsService/Health
```

**Health Response Fields:**

| Field | Description |
|-------|-------------|
| `healthy` | Overall health status |
| `server_status` | gRPC server status |
| `database_status` | Storage backend connectivity |
| `acme_status` | ACME certificate manager status (if configured) |
| `hooks` | Individual hook health status |

The `Readiness` RPC is suitable for Kubernetes readiness probes as it verifies the server can process requests (database is accessible).

### Operator Health Endpoints

The Kubernetes operator exposes HTTP health endpoints (separate from the server's gRPC Health service):

| Endpoint | Purpose | Behavior |
|----------|---------|----------|
| `/healthz` | Liveness | Returns 200 if process is alive |
| `/readyz` | Readiness | Returns 200 if startup complete AND router-hosts server reachable |

See [Operator Documentation](kubernetes.md#observability) for details on probe configuration.

## Prometheus Metrics

### Configuration

Metrics are opt-in. Add a `[metrics]` section to enable:

```toml
[metrics]
# Prometheus HTTP endpoint (plaintext)
prometheus_bind = "0.0.0.0:9090"

# Optional: OpenTelemetry export
[metrics.otel]
endpoint = "http://otel-collector:4317"
service_name = "router-hosts"  # defaults to "router-hosts"
```

### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `router_hosts_requests_total` | Counter | `method`, `status` | Total gRPC requests |
| `router_hosts_request_duration_seconds` | Histogram | `method` | Request latency |
| `router_hosts_storage_operations_total` | Counter | `operation`, `status` | DB operations count |
| `router_hosts_storage_duration_seconds` | Histogram | `operation` | DB operation latency |
| `router_hosts_hook_executions_total` | Counter | `name`, `type`, `status` | Hook execution count |
| `router_hosts_hook_duration_seconds` | Histogram | `name`, `type` | Hook execution time |
| `router_hosts_hosts_entries` | Gauge | - | Current host entry count |

### Scraping

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'router-hosts'
    static_configs:
      - targets: ['router-hosts:9090']
```

## Backup and Recovery

### Automatic Snapshots

The server creates snapshots before destructive operations:
- Before import (replaces all hosts)
- Before rollback (creates backup of current state)

### Manual Backup

```bash
# Export current state
router-hosts host export --export-format json > backup.json

# List available snapshots
router-hosts snapshot list
```

### Recovery

```bash
# Rollback to previous snapshot
router-hosts snapshot rollback <id>

# Import from backup
router-hosts host import backup.json --conflict-mode replace
```

### Retention Policy

Configure snapshot retention in server config:

```toml
[retention]
max_snapshots = 50      # Keep at most 50 snapshots
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
