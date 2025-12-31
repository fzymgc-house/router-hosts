# Configuration Reference

Complete reference for all configuration options.

## Server Configuration

### `[server]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `listen_addr` | string | `"0.0.0.0:50051"` | gRPC server listen address |
| `health_addr` | string | `"0.0.0.0:8080"` | Health check HTTP server address |

### `[tls]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert_file` | path | required | Server certificate file |
| `key_file` | path | required | Server private key file |
| `ca_file` | path | required | CA certificate for client verification |

### `[storage]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `database_url` | string | SQLite in XDG data dir | Database connection URL |

### `[hooks]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `post_update` | array | `[]` | Commands to run after host updates |

Example hook:

```toml
[[hooks.post_update]]
name = "restart-dnsmasq"
command = "systemctl restart dnsmasq"
```

## Client Configuration

### `[client]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `server_addr` | string | required | Server gRPC address |

### `[tls]`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert_file` | path | required | Client certificate file |
| `key_file` | path | required | Client private key file |
| `ca_file` | path | required | CA certificate for server verification |
