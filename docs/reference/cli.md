# CLI Reference

Command-line interface documentation for router-hosts.

!!! note "Auto-generated"
    This documentation should be regenerated from `router-hosts --help` after building.

## Overview

router-hosts uses a subcommand-based CLI built with [Cobra](https://github.com/spf13/cobra).

### Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--server` | `-s` | Server address (host:port) |
| `--cert` | | Client certificate path |
| `--key` | | Client key path |
| `--ca-cert` | | CA certificate path |
| `--config` | `-c` | Path to config file |
| `--quiet` | `-q` | Suppress non-error output |
| `--format` | `-f` | Output format (table, json, csv) |

#### `--config` resolution

`--config <path>` selects the client config file explicitly. When it is
given, the [XDG search](#config-file-auto-discovery) below is **not**
performed at all — the named file is the only file consulted. An
explicit path that cannot be read, cannot be parsed, or carries an
unknown key is a hard error naming that path; there is no fallback to
auto-discovery on failure.

The resolved config file is still the **lowest**-precedence layer,
regardless of whether it came from `--config` or from auto-discovery:
the `ROUTER_HOSTS_*` environment variables outrank it, and the
`--server`, `--cert`, `--key`, and `--ca` value flags outrank those.

##### Config file auto-discovery

When `--config` is absent, the client searches for `client.toml` (or
`config.toml`) in this order and uses the first match:

1. `$XDG_CONFIG_HOME/router-hosts/`
2. `~/.config/router-hosts/` (only when `XDG_CONFIG_HOME` is unset)
3. `~/Library/Application Support/router-hosts/` (macOS only)

No config file on any search path is a fully supported deployment —
env vars and flags alone are enough.

### Commands

| Command | Description |
|---------|-------------|
| `host add` | Add a new host entry |
| `host get` | Get a host entry by ID |
| `host update` | Update an existing host entry |
| `host delete` | Delete a host entry |
| `host list` | List all host entries |
| `host search` | Search host entries |
| `host import` | Import hosts from file |
| `host export` | Export hosts to stdout or file |
| `snapshot create` | Create a new snapshot |
| `snapshot list` | List all snapshots |
| `snapshot rollback` | Rollback to a snapshot |
| `snapshot delete` | Delete a snapshot |
| `serve` | Start the gRPC server |
| `render` | Render host data through a template once |
| `watch` | Keep a rendered artifact current as a long-lived sink |
| `health` | Check server health |
| `version` | Print version information |

### `render`

One-shot: renders the current host data through a template and exits. See
the [Consumer-Rendered Output guide](../guides/consumer-rendered-output.md)
and the [Template Data Contract](template-contract.md) for the field set a
template may reference. Reads the same global connection flags as the rest
of the CLI.

| Flag | Default | Description |
|------|---------|-------------|
| `--template` | *(required)* | Path to a `text/template` file declaring its contract version |
| `--out` | stdout | Artifact output path |

### `watch`

Long-lived sink: opens a streaming connection and keeps `--out` current as
host data changes, with automatic reconnect and a local sidecar status
file. See the
[Consumer-Rendered Output guide](../guides/consumer-rendered-output.md)
for the full walkthrough. Reads the same global connection flags as the
rest of the CLI.

| Flag | Default | Description |
|------|---------|-------------|
| `--template` | *(required)* | Path to a `text/template` file declaring its contract version |
| `--out` | *(required)* | Artifact output path, kept current for the life of the process |
| `--exec` | *(none)* | Command run via `sh -c` after every successful write (e.g. a resolver reload) |
| `--exec-timeout` | 30s | Timeout for the post-write command |
| `--status-file` | `<out>.status` | Sidecar status file path |
| `--status-interval` | 30s | Interval between upstream status reports |

## Examples

```bash
# Add a host
router-hosts host add --ip 192.168.1.10 --hostname server.local --tag homelab

# List all hosts
router-hosts host list

# Search by hostname pattern
router-hosts host search --hostname "*.local"

# Export in hosts format
router-hosts host export --format hosts

# Start server
router-hosts serve --config server.toml
```
