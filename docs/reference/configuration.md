# Configuration Reference

Complete reference for all configuration options.

## Server Configuration

### `[server]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bind_address` | string | `"0.0.0.0:50051"` | gRPC server listen address |
| `hosts_file_path` | path | `/etc/hosts.d/router-hosts` | Output hosts file path |

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
