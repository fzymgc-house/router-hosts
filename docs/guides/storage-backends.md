# Storage Backends

router-hosts supports three storage backends. SQLite is the default and recommended for most deployments.

## Comparison

| Feature | SQLite | PostgreSQL | DuckDB |
|---------|--------|------------|--------|
| Setup complexity | Low | Medium | Low |
| Concurrent connections | Limited | High | Limited |
| Embedded | Yes | No | Yes |
| Production ready | Yes | Yes | Experimental |

## SQLite (Default)

Best for single-server deployments. Zero configuration required.

```toml
[database]
path = "/var/lib/router-hosts/hosts.db"
```

Default location (if no path specified): `~/.local/share/router-hosts/hosts.db`

## PostgreSQL

Best for high-availability deployments with multiple server instances.

```toml
[database]
url = "postgres://user:password@localhost:5432/router_hosts"
```

Requires PostgreSQL 14+.

## DuckDB

Experimental backend. Requires the `router-hosts-duckdb` binary variant.

```toml
[database]
path = "/var/lib/router-hosts/hosts.duckdb"
```

!!! warning
    DuckDB support is experimental. Use SQLite or PostgreSQL for production.
