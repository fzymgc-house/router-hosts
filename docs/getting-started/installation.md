# Installation

!!! note "Pre-built binaries"
    Pre-built binaries are not yet available for the Go version. Build from source or use Docker.

## Docker

```bash
docker pull ghcr.io/fzymgc-house/router-hosts:latest
```

## Build from Source

Requires Go 1.24+ and buf CLI.

```bash
git clone https://github.com/fzymgc-house/router-hosts.git
cd router-hosts
task build:release
```

Binaries available at `bin/router-hosts` and `bin/operator`.
