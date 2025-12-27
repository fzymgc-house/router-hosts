# Devcontainer Design

**Date:** 2025-12-26
**Status:** Approved

## Overview

Devcontainer setup for router-hosts development, supporting VS Code Remote Containers, GitHub Codespaces, and CLI-only usage.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| DuckDB handling | Feature flag (separate config) | Most developers don't need DuckDB; avoid slow builds |
| Base image | Microsoft devcontainer Rust | Purpose-built, features integrate well |
| Docker support | Full Docker-in-Docker | E2E tests and testcontainers need it |
| Default shell | Fish (zsh also installed) | User preference; both available |
| Tool installation | Homebrew over apt | Consistent, up-to-date packages |
| Python tooling | uv/uvx | Fast, modern alternative to pipx |

## File Structure

```
.devcontainer/
├── devcontainer.json          # Main config (no DuckDB)
├── devcontainer-duckdb.json   # Variant with DuckDB support
├── Dockerfile                 # Custom image with cargo tools
├── Dockerfile.duckdb          # DuckDB variant (pre-builds bundled DuckDB)
└── post-create.sh             # Setup script (Homebrew packages, pre-commit)
```

## Dockerfile

Minimal - only what can't come from features or Homebrew:

```dockerfile
FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# Install cargo tools (not available via Homebrew)
RUN cargo install cargo-nextest cargo-llvm-cov
```

## Dockerfile.duckdb

Pre-builds DuckDB to cache the slow bundled compilation:

```dockerfile
FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# DuckDB version - keep in sync with Cargo.toml workspace dependencies
ARG DUCKDB_VERSION=1.1
ENV DUCKDB_VERSION=${DUCKDB_VERSION}

# Install cargo tools
RUN cargo install cargo-nextest cargo-llvm-cov

# Pre-build DuckDB to cache the slow bundled compilation
RUN cargo new --lib /tmp/duckdb-warmup \
    && cd /tmp/duckdb-warmup \
    && echo "duckdb = { version = \"${DUCKDB_VERSION}\", features = [\"bundled\"] }" >> Cargo.toml \
    && cargo build --release \
    && rm -rf /tmp/duckdb-warmup
```

## devcontainer.json

```json
{
  "name": "router-hosts",
  "build": {
    "dockerfile": "Dockerfile"
  },
  "features": {
    "ghcr.io/devcontainers/features/common-utils:2": {
      "installZsh": true,
      "installFish": true,
      "configureFishAsDefaultShell": true
    },
    "ghcr.io/devcontainers/features/docker-in-docker:2": {},
    "ghcr.io/devcontainers/features/homebrew:1": {},
    "ghcr.io/anthropics/claude-code:1": {}
  },
  "customizations": {
    "vscode": {
      "extensions": [
        "rust-lang.rust-analyzer",
        "serayuzgur.crates",
        "tamasfe.even-better-toml",
        "usernamehw.errorlens",
        "vadimcn.vscode-lldb"
      ],
      "settings": {
        "terminal.integrated.defaultProfile.linux": "fish",
        "editor.formatOnSave": true,
        "rust-analyzer.check.command": "clippy",
        "rust-analyzer.check.extraArgs": ["--", "-D", "warnings"]
      }
    }
  },
  "postCreateCommand": ".devcontainer/post-create.sh",
  "remoteUser": "vscode"
}
```

## devcontainer-duckdb.json

Same as above but with:
- `"name": "router-hosts (with DuckDB)"`
- `"dockerfile": "Dockerfile.duckdb"`

## post-create.sh

```bash
#!/bin/bash
set -euo pipefail

echo "==> Installing Homebrew packages..."
brew install \
    bufbuild/buf/buf \
    git-lfs \
    go-task/tap/go-task \
    neovim \
    protobuf \
    shellcheck \
    uv

echo "==> Setting up git-lfs..."
git lfs install

echo "==> Installing pre-commit hooks..."
uvx pre-commit install
uvx pre-commit install --hook-type pre-push

echo "==> Building project (first build caches dependencies)..."
task build || echo "[WARNING] Initial build failed - you may need to fix compilation errors"

echo "==> Development environment ready!"
```

## Tool Sources

| Tool | Source |
|------|--------|
| zsh | `common-utils` feature |
| fish | `common-utils` feature |
| docker | `docker-in-docker` feature |
| claude | `claude-code` feature |
| protobuf | Homebrew |
| buf | Homebrew |
| task | Homebrew |
| shellcheck | Homebrew |
| uv | Homebrew |
| git-lfs | Homebrew |
| neovim | Homebrew |
| cargo-nextest | Dockerfile (cargo install) |
| cargo-llvm-cov | Dockerfile (cargo install) |

## Usage

### VS Code

1. Install "Dev Containers" extension
2. Open command palette → "Reopen in Container"
3. Select configuration (default or DuckDB variant)

### GitHub Codespaces

1. Click "Code" → "Codespaces" → "Create codespace"
2. Default configuration used automatically

### CLI Only (Minimal)

```bash
# Note: This is a minimal approach that does NOT run post-create.sh,
# install Homebrew packages, or set up the full development environment.
# For full tooling, use VS Code or the devcontainer CLI.
docker build -t router-hosts-dev -f .devcontainer/Dockerfile .
docker run -it -v $(pwd):/workspace router-hosts-dev
```

## Shell Customization

Default shell is fish. To switch to zsh:

```bash
chsh -s /usr/bin/zsh
```
