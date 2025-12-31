# Configuration

router-hosts uses TOML configuration files for both server and client.

## Server Configuration

Create `server.toml`:

```toml
[server]
bind_address = "0.0.0.0:50051"
hosts_file_path = "/etc/hosts.d/router-hosts"

[database]
# SQLite (default) - just specify path
path = "/var/lib/router-hosts/hosts.db"

# PostgreSQL alternative - use url instead
# url = "postgres://user:pass@localhost/router_hosts"

[tls]
cert_path = "/path/to/server.pem"
key_path = "/path/to/server-key.pem"
ca_cert_path = "/path/to/ca.pem"
```

Start the server:

```bash
router-hosts server --config server.toml
```

## Client Configuration

The client looks for configuration in these locations (in order):

1. `$XDG_CONFIG_HOME/router-hosts/client.toml`
2. `~/.config/router-hosts/client.toml`
3. `./client.toml`

Create `client.toml`:

```toml
[server]
address = "router-hosts.example.com:50051"

[tls]
cert_path = "/path/to/client.pem"
key_path = "/path/to/client-key.pem"
ca_cert_path = "/path/to/ca.pem"
```

See [Configuration Reference](../reference/configuration.md) for all options.
