# Configuration Reference

Complete reference for all configuration options.

## Server Configuration

### `[server]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bind_address` | string | `"0.0.0.0:50051"` | gRPC server listen address |
| `hosts_file_path` | path | `/etc/hosts.d/router-hosts` | Output hosts(5) file path |
| `dnsmasq_conf_path` | path | - | Output dnsmasq conf-dir file of `local=`/`address=` directives (additive) |
| `unbound_conf_path` | path | - | Output unbound conf-dir file of `local-zone`/`local-data` directives (additive) |
| `unbound_ttl` | int | `300` | TTL (seconds) for `unbound_conf_path` `local-data` records |

At least one of `hosts_file_path`, `dnsmasq_conf_path`, or `unbound_conf_path` must be set.

When `dnsmasq_conf_path` is configured, router-hosts also writes a file for
consumption via dnsmasq `conf-dir`, emitting a directive pair per name and
alias:

```text
local=/<fqdn>/
address=/<fqdn>/<ip>
```

The `address=` line answers the matching record type (`A` for an IPv4 address,
`AAAA` for an IPv6 address). The companion `local=` line makes dnsmasq
authoritative for that exact name, so a query for the *other* record type
returns `NODATA` instead of being forwarded upstream. This prevents
public-AAAA leaks in split-horizon setups (GH #325).

The `local=` line is required because dnsmasq 2.86+ forwards non-matching
record types upstream when only `address=` is present. Both directives are
scoped per-name, not zone-wide like `local=/<domain>/` (which would return
`NXDOMAIN` for unmanaged names in the zone).

When `unbound_conf_path` is configured, router-hosts writes, per managed name,
one `local-zone: "<fqdn>." static` plus its `local-data` records:

```text
local-zone: "api.fzymgc.house." static
local-data: "api.fzymgc.house. 300 IN A 10.0.0.5"
local-data: "api.fzymgc.house. 300 IN AAAA fd00::5"
```

`static` answers the listed record types and returns NODATA for any other type
at that name, so a name's missing types (e.g. AAAA, HTTPS/type-65) are never
forwarded upstream. Names are emitted **verbatim** (trailing-dot normalized): a
bare, non-FQDN alias (e.g. `api`) becomes `local-zone: "api." static`, making
unbound authoritative for that entire pseudo-TLD — inventories MUST carry FQDNs.
Reload is out of scope: point a host-side systemd path unit at the conf
directory to reload unbound on write.

### `[database]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `path` | path | XDG data dir | SQLite database file path |
| `url` | string | - | PostgreSQL connection URL (use instead of `path`) |

### `[tls]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert_path` | path | required | Server certificate file |
| `key_path` | path | required | Server private key file |
| `ca_cert_path` | path | required | CA certificate for client verification |

### `[hooks]`

Hooks are arrays of hook definitions. Each hook has a `name` (kebab-case identifier) and `command` (shell command).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `on_success` | array of hooks | `[]` | Hooks to run after successful host updates |
| `on_failure` | array of hooks | `[]` | Hooks to run after failed host updates |

Each hook definition:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique kebab-case identifier (used in logs/metrics) |
| `command` | string | Shell command to execute |

Example hooks:

```toml
[[hooks.on_success]]
name = "reload-dnsmasq"
command = "systemctl reload dnsmasq"

[[hooks.on_failure]]
name = "notify-failure"
command = "notify-send 'router-hosts update failed'"
```

## Client Configuration

### `[server]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `address` | string | required | Server gRPC address |

### `[tls]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert_path` | path | required | Client certificate file |
| `key_path` | path | required | Client private key file |
| `ca_cert_path` | path | required | CA certificate for server verification |
