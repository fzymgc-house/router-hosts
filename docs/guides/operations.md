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

### Access Logs

The server emits structured access logs at INFO level for every gRPC request. These logs provide observability into server operations.

**Log Format:**

Each request produces a single log line with structured fields:

| Field | Description | Always Present |
|-------|-------------|----------------|
| `method` | gRPC method name (e.g., AddHost, GetHost) | Yes |
| `status` | Result status (`ok` or `error`) | Yes |
| `duration_ms` | Request duration in milliseconds | Yes |
| `id` | Host entry ULID (for CRUD operations) | When available |
| `hostname` | Host's hostname | When available |
| `ip` | Host's IP address | When available |
| `query` | Search query (for SearchHosts) | When available |

**Example Output:**

```
INFO request method=AddHost id=01JG... hostname=myserver.local ip=192.168.1.10 status=ok duration_ms=5
INFO request method=GetHost id=01JG... hostname=myserver.local ip=192.168.1.10 status=ok duration_ms=2
INFO request method=UpdateHost id=01JG... hostname=newname.local ip=10.0.0.5 status=ok duration_ms=3
INFO request method=DeleteHost id=01JG... status=ok duration_ms=1
INFO request method=ListHosts status=ok duration_ms=12
INFO request method=SearchHosts query=*.example.com status=ok duration_ms=8
```

**Security:**

All user-provided fields (id, hostname, ip, query) are sanitized before logging to prevent log injection attacks:

- Control characters (newlines, carriage returns, tabs) are replaced with the Unicode replacement character (U+FFFD)
- Fields are truncated to 256 characters maximum to prevent log flooding
- This protects against malicious input that could inject fake log entries or break log parsers

**Privacy Considerations:**

Access logs contain IP addresses and hostnames which may be considered sensitive:

- **IP addresses**: May be PII under GDPR and similar regulations
- **Hostnames**: Could reveal internal infrastructure naming

Consider your log retention policies and access controls accordingly. For environments with strict privacy requirements, configure log aggregation to filter or redact these fields.

**Querying Logs:**

Example queries for common log aggregation tools:

```bash
# Find all failed requests
grep 'status=error' /var/log/router-hosts.log

# Find operations on a specific host
grep 'hostname=myserver.local' /var/log/router-hosts.log

# Find slow requests (>100ms)
awk '/duration_ms=[0-9]{3,}/' /var/log/router-hosts.log

# Find search operations
grep 'method=SearchHosts' /var/log/router-hosts.log
```

**Log Filtering/Redaction:**

For environments requiring PII redaction, configure your log aggregator to filter sensitive fields:

```yaml
# Vector (vector.dev) example
transforms:
  redact_pii:
    type: remap
    inputs: ["router_hosts_logs"]
    source: |
      .ip = "REDACTED"
      .hostname = redact(.hostname, filters: ["pattern"], patterns: [r'\.[a-z]+$'])
```

```yaml
# Fluentd example
<filter router-hosts.**>
  @type record_transformer
  <record>
    ip ${record["ip"] ? "REDACTED" : nil}
  </record>
</filter>
```

Note: The logged IP addresses and hostnames are the **host entry values** being managed, not client connection IPs. Client authentication is via mTLS certificates and is not logged in access logs.

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

## Metrics and Tracing (OpenTelemetry)

All metrics and traces are exported via OpenTelemetry (OTLP/gRPC) to a collector of your choice.

### Configuration

Metrics and tracing are opt-in. Add a `[metrics.otel]` section to enable:

```toml
[metrics.otel]
endpoint = "http://otel-collector:4317"
service_name = "router-hosts"     # Optional, defaults to "router-hosts"
export_metrics = true             # Optional, defaults to true
export_traces = true              # Optional, defaults to true
export_interval_secs = 60         # Optional, defaults to 60 seconds
# headers = { "Authorization" = "Bearer token" }  # Optional
```

The `export_interval_secs` option controls how frequently metrics are pushed to the OTEL collector. Lower values increase metric freshness but add collector overhead. The default of 60 seconds balances freshness with efficiency for most deployments.

### Available Metrics

All metrics recorded via `counter!()`, `histogram!()`, and `gauge!()` macros are exported to the OTEL collector:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `router_hosts_requests_total` | Counter | `method`, `status` | Total gRPC requests |
| `router_hosts_request_duration_seconds` | Histogram | `method` | Request latency |
| `router_hosts_storage_operations_total` | Counter | `operation`, `status` | DB operations count |
| `router_hosts_storage_duration_seconds` | Histogram | `operation` | DB operation latency |
| `router_hosts_hook_executions_total` | Counter | `name`, `type`, `status` | Hook execution count |
| `router_hosts_hook_duration_seconds` | Histogram | `name`, `type` | Hook execution time |
| `router_hosts_hosts_entries` | Gauge | - | Current host entry count |

### Prometheus Scraping via OTEL Collector

If you need Prometheus-style `/metrics` scraping, configure your OTEL collector to expose a Prometheus endpoint:

```yaml
# otel-collector-config.yaml
exporters:
  prometheus:
    endpoint: "0.0.0.0:9090"

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheus]
```

Then configure your Prometheus to scrape the collector:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'router-hosts'
    static_configs:
      - targets: ['otel-collector:9090']
```

### Trace Context Propagation

Incoming gRPC requests with W3C Trace Context headers (`traceparent`, `tracestate`) are automatically linked to distributed traces.

### Graceful Degradation

- No `[metrics.otel]` config → no OTEL layers, zero overhead
- `export_traces = false` → trace exporter disabled (still logs to console)
- `export_metrics = false` → metrics export disabled
- Collector unavailable at runtime → OpenTelemetry SDK handles retry/backoff internally

**Note:** Invalid configuration (malformed endpoint, invalid headers) will cause server startup to fail. Verify your OTEL collector is reachable before deploying.

### Collector Retry Behavior

When the OTEL collector becomes unavailable at runtime:

- **Traces:** The batch exporter retries with exponential backoff (5s initial, 30s max). Failed spans are dropped after retry exhaustion to prevent memory growth.
- **Metrics:** The periodic reader (60s interval) retries on each export cycle. Metrics are aggregated in-memory and the latest values are sent when connectivity resumes.
- **Logging:** Failed exports log at `warn` level. Enable `RUST_LOG=opentelemetry=debug` for detailed retry diagnostics.

This design ensures the server never blocks on telemetry failures—observability is best-effort.

### Kubernetes Collector Sidecar

Example collector sidecar configuration:

```yaml
containers:
  - name: otel-collector
    image: otel/opentelemetry-collector:latest
    ports:
      - containerPort: 4317
    volumeMounts:
      - name: otel-config
        mountPath: /etc/otelcol
volumes:
  - name: otel-config
    configMap:
      name: otel-collector-config
```

### Troubleshooting OTEL

**No traces/metrics appearing in collector:**

1. Verify connectivity: `grpcurl -plaintext otel-collector:4317 list`
2. Check server logs for `OTEL.*initialized` messages
3. Confirm `export_traces` and `export_metrics` are `true` (or omitted for defaults)
4. Ensure collector is configured to receive OTLP/gRPC on port 4317

**Server fails to start with OTEL errors:**

1. Validate endpoint URL format: `http://host:port` (no trailing slash)
2. Check header syntax in config: `headers = { "Key" = "Value" }`
3. Ensure collector is reachable from server network

**High memory usage with OTEL enabled:**

1. Verify collector is healthy—backpressure from failing exports can buffer spans
2. Consider reducing trace sampling in high-throughput scenarios
3. Check for circular trace propagation in service mesh configurations

**Debug logging:**

```bash
RUST_LOG=opentelemetry=debug,router_hosts=debug ./router-hosts server
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
