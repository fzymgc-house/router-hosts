# Configuration

router-hosts uses TOML configuration files for both server and client.

## Server Configuration

Create `server.toml`:

```toml
[server]
listen_addr = "0.0.0.0:50051"

[tls]
cert_file = "/path/to/server.crt"
key_file = "/path/to/server.key"
ca_file = "/path/to/ca.crt"

[storage]
# SQLite (default)
database_url = "sqlite:///var/lib/router-hosts/hosts.db"

# PostgreSQL alternative
# database_url = "postgres://user:pass@localhost/router_hosts"
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
[client]
server_addr = "https://router-hosts.example.com:50051"

[tls]
cert_file = "/path/to/client.crt"
key_file = "/path/to/client.key"
ca_file = "/path/to/ca.crt"
```

See [Configuration Reference](../reference/configuration.md) for all options.
