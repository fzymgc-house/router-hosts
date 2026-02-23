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
| `health` | Check server health |
| `version` | Print version information |

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
