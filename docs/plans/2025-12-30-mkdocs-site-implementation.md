# MkDocs Documentation Site Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a professional documentation site using MkDocs Material, deployed to Cloudflare Pages via GitHub Actions on each release.

**Architecture:** MkDocs Material generates static HTML from markdown. GitHub Actions builds the site on release (downloading release binaries for CLI docs, running protoc-gen-doc for API docs). Versioning via `mike` creates `/vX.Y.Z/` paths with `latest` alias. Wrangler deploys to Cloudflare Pages.

**Tech Stack:** MkDocs Material, mike (versioning), protoc-gen-doc, GitHub Actions, Cloudflare Pages, wrangler

---

## Phase 1: Infrastructure Setup

### Task 1.1: Create MkDocs Configuration

**Files:**
- Create: `mkdocs.yml`

**Step 1: Create mkdocs.yml with Material theme**

```yaml
site_name: router-hosts
site_url: https://router-hosts-docs.pages.dev
repo_url: https://github.com/fzymgc-house/router-hosts
repo_name: fzymgc-house/router-hosts
edit_uri: edit/main/docs/

theme:
  name: material
  palette:
    - scheme: slate
      primary: deep purple
      accent: purple
      toggle:
        icon: material/brightness-4
        name: Switch to light mode
    - scheme: default
      primary: deep purple
      accent: purple
      toggle:
        icon: material/brightness-7
        name: Switch to dark mode
  features:
    - content.code.copy
    - content.action.edit
    - navigation.sections
    - navigation.top
    - navigation.indexes
    - search.highlight
    - search.suggest
    - toc.integrate
  icon:
    repo: fontawesome/brands/github

plugins:
  - search
  - git-revision-date-localized:
      type: date
      fallback_to_build_date: true
      # enable_creation_date: false (disabled - only shows last updated)

markdown_extensions:
  - pymdownx.highlight:
      anchor_linenums: true
      line_spans: __span
      pygments_lang_class: true
  - pymdownx.inlinehilite
  - pymdownx.snippets
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
  - admonition
  - pymdownx.details
  - pymdownx.tabbed:
      alternate_style: true
  - tables
  - toc:
      permalink: true

extra:
  version:
    provider: mike

nav:
  - Home: index.md
  - Getting Started:
    - getting-started/index.md
    - Installation: getting-started/installation.md
    - Configuration: getting-started/configuration.md
  - Guides:
    - guides/index.md
    - Operations: guides/operations.md
    - ACME Certificates: guides/acme.md
    - Kubernetes Operator: guides/kubernetes.md
    - Storage Backends: guides/storage-backends.md
  - Reference:
    - reference/index.md
    - CLI Reference: reference/cli.md
    - API Reference: reference/api.md
    - Configuration Reference: reference/configuration.md
  - Contributing:
    - contributing/index.md
    - Architecture: contributing/architecture.md
    - Testing: contributing/testing.md
    - Releasing: contributing/releasing.md
  - Troubleshooting: troubleshooting.md
```

**Step 2: Verify YAML syntax**

Run: `python -c "import yaml; yaml.safe_load(open('mkdocs.yml'))"`
Expected: No output (success)

**Step 3: Commit**

```bash
git add mkdocs.yml
git commit -m "build(docs): add MkDocs Material configuration"
```

---

### Task 1.2: Create Directory Structure

**Files:**
- Create: `docs/index.md`
- Create: `docs/getting-started/index.md`
- Create: `docs/getting-started/installation.md`
- Create: `docs/getting-started/configuration.md`
- Create: `docs/guides/index.md`
- Create: `docs/guides/storage-backends.md`
- Create: `docs/reference/index.md`
- Create: `docs/reference/configuration.md`
- Create: `docs/contributing/index.md`

**Step 1: Create directory structure**

```bash
mkdir -p docs/getting-started docs/guides docs/reference docs/contributing
```

**Step 2: Create placeholder index.md (landing page)**

`docs/index.md`:
```markdown
# router-hosts

A Rust CLI for managing DNS host entries via client-server architecture with gRPC over mTLS.

## Features

- **Client-Server Architecture** — Centralized host management with secure gRPC communication
- **mTLS Security** — Mutual TLS authentication for all client-server communication
- **Multiple Storage Backends** — SQLite (default), PostgreSQL, and DuckDB support
- **ACME Integration** — Automatic certificate management with Let's Encrypt
- **Kubernetes Operator** — Native Kubernetes integration for declarative host management
- **Event Sourcing** — Full audit trail with snapshot-based state recovery

## Quick Start

```bash
# Install
brew install fzymgc-house/tap/router-hosts

# Start server
router-hosts server --config server.toml

# Add a host
router-hosts add 192.168.1.100 myserver.local --tags homelab
```

[Get Started](getting-started/index.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/fzymgc-house/router-hosts){ .md-button }
```

**Step 3: Create getting-started/index.md**

`docs/getting-started/index.md`:
```markdown
# Getting Started

This guide helps you install and configure router-hosts for your environment.

## Overview

router-hosts uses a client-server architecture:

- **Server** — Stores host entries, serves gRPC API over mTLS
- **Client** — CLI that connects to server to manage hosts

## Next Steps

1. [Installation](installation.md) — Install the binary, Docker image, or build from source
2. [Configuration](configuration.md) — Configure server and client settings
```

**Step 4: Create getting-started/installation.md**

`docs/getting-started/installation.md`:
```markdown
# Installation

## Binary Installation

### Homebrew (macOS/Linux)

```bash
brew install fzymgc-house/tap/router-hosts
```

### Download Binary

Download from [GitHub Releases](https://github.com/fzymgc-house/router-hosts/releases):

=== "Linux (x86_64)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-linux-x86_64.tar.gz
    tar -xzf router-hosts-linux-x86_64.tar.gz
    sudo mv router-hosts /usr/local/bin/
    ```

=== "macOS (Apple Silicon)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-darwin-aarch64.tar.gz
    tar -xzf router-hosts-darwin-aarch64.tar.gz
    sudo mv router-hosts /usr/local/bin/
    ```

=== "macOS (Intel)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-darwin-x86_64.tar.gz
    tar -xzf router-hosts-darwin-x86_64.tar.gz
    sudo mv router-hosts /usr/local/bin/
    ```

## Docker

```bash
docker pull ghcr.io/fzymgc-house/router-hosts:latest
```

## Build from Source

Requires Rust 1.75+ and buf CLI.

```bash
git clone https://github.com/fzymgc-house/router-hosts.git
cd router-hosts
cargo build --release
```

Binary available at `target/release/router-hosts`.
```

**Step 5: Create getting-started/configuration.md**

`docs/getting-started/configuration.md`:
```markdown
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
```

**Step 6: Create guides/index.md**

`docs/guides/index.md`:
```markdown
# Guides

In-depth guides for operating and extending router-hosts.

- [Operations](operations.md) — Server management, SIGHUP reload, hooks
- [ACME Certificates](acme.md) — Automatic certificate management
- [Kubernetes Operator](kubernetes.md) — Deploy with the Kubernetes operator
- [Storage Backends](storage-backends.md) — SQLite, PostgreSQL, DuckDB comparison
```

**Step 7: Create guides/storage-backends.md**

`docs/guides/storage-backends.md`:
```markdown
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
[storage]
database_url = "sqlite:///var/lib/router-hosts/hosts.db"
```

Default location (if no URL specified): `~/.local/share/router-hosts/hosts.db`

## PostgreSQL

Best for high-availability deployments with multiple server instances.

```toml
[storage]
database_url = "postgres://user:password@localhost:5432/router_hosts"
```

Requires PostgreSQL 14+.

## DuckDB

Experimental backend. Requires the `router-hosts-duckdb` binary variant.

```toml
[storage]
database_url = "duckdb:///var/lib/router-hosts/hosts.duckdb"
```

!!! warning
    DuckDB support is experimental. Use SQLite or PostgreSQL for production.
```

**Step 8: Create reference/index.md**

`docs/reference/index.md`:
```markdown
# Reference

Complete reference documentation for router-hosts.

- [CLI Reference](cli.md) — Command-line interface documentation
- [API Reference](api.md) — gRPC API documentation
- [Configuration Reference](configuration.md) — All configuration options
```

**Step 9: Create reference/configuration.md**

`docs/reference/configuration.md`:
```markdown
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
```

**Step 10: Create contributing/index.md**

`docs/contributing/index.md`:
```markdown
# Contributing

Thank you for your interest in contributing to router-hosts!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/fzymgc-house/router-hosts.git
   cd router-hosts
   ```

2. Install prerequisites:
   - Rust 1.75+ (`rustup install stable`)
   - buf CLI (`brew install bufbuild/buf/buf`)
   - pre-commit (`pip install pre-commit && pre-commit install`)

3. Build and test:
   ```bash
   task build
   task test
   ```

## Guidelines

- Follow [Conventional Commits](https://www.conventionalcommits.org/)
- Maintain 80%+ test coverage
- Run `task lint` before committing

## Resources

- [Architecture](architecture.md) — System design and internals
- [Testing](testing.md) — Test infrastructure and E2E tests
- [Releasing](releasing.md) — Release process
```

**Step 11: Commit directory structure**

```bash
git add docs/
git commit -m "docs: create MkDocs site directory structure"
```

---

### Task 1.3: Create CLI Documentation Generator Script

**Files:**
- Create: `scripts/generate-cli-docs.sh`

**Step 1: Create the script**

`scripts/generate-cli-docs.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Generate CLI reference documentation from --help output
#
# Usage: ./scripts/generate-cli-docs.sh [binary-path]
# Default binary: ./target/release/router-hosts

BINARY="${1:-./target/release/router-hosts}"
OUTPUT="docs/reference/cli.md"

if [[ ! -x "$BINARY" ]]; then
    echo "Error: Binary not found or not executable: $BINARY" >&2
    exit 1
fi

cat > "$OUTPUT" << 'HEADER'
# CLI Reference

Command-line interface documentation for router-hosts.

!!! note "Auto-generated"
    This documentation is auto-generated from `router-hosts --help`.

HEADER

# Global help
echo '## Global Usage' >> "$OUTPUT"
echo '' >> "$OUTPUT"
echo '```' >> "$OUTPUT"
"$BINARY" --help >> "$OUTPUT"
echo '```' >> "$OUTPUT"
echo '' >> "$OUTPUT"

# Extract subcommands from help output
# Matches lines that start with whitespace followed by a word (subcommand name)
subcommands=$("$BINARY" --help | grep -E '^\s{2,}[a-z]' | awk '{print $1}' | grep -v '^-' || true)

for cmd in $subcommands; do
    # Skip if it looks like an option (starts with -)
    if [[ "$cmd" == -* ]]; then
        continue
    fi

    echo "## $cmd" >> "$OUTPUT"
    echo '' >> "$OUTPUT"
    echo '```' >> "$OUTPUT"
    "$BINARY" "$cmd" --help >> "$OUTPUT" 2>&1 || echo "Error getting help for $cmd" >> "$OUTPUT"
    echo '```' >> "$OUTPUT"
    echo '' >> "$OUTPUT"
done

echo "Generated CLI documentation at $OUTPUT"
```

**Step 2: Make executable**

```bash
chmod +x scripts/generate-cli-docs.sh
```

**Step 3: Test locally (build binary first if needed)**

```bash
cargo build --release -p router-hosts
./scripts/generate-cli-docs.sh
cat docs/reference/cli.md | head -50
```

Expected: Markdown file with CLI help output

**Step 4: Commit**

```bash
git add scripts/generate-cli-docs.sh docs/reference/cli.md
git commit -m "build(docs): add CLI documentation generator script"
```

---

### Task 1.4: Create Proto Documentation Generator Script

**Files:**
- Create: `scripts/generate-proto-docs.sh`

**Step 1: Create the script**

`scripts/generate-proto-docs.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Generate API reference documentation from protobuf definitions
#
# Usage: ./scripts/generate-proto-docs.sh
# Requires: protoc-gen-doc (go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest)

OUTPUT_DIR="docs/reference"
OUTPUT_FILE="$OUTPUT_DIR/api.md"

# Check for protoc
if ! command -v protoc &> /dev/null; then
    echo "Error: protoc not found. Install Protocol Buffers compiler." >&2
    exit 1
fi

# Check for protoc-gen-doc
if ! command -v protoc-gen-doc &> /dev/null; then
    echo "Error: protoc-gen-doc not found." >&2
    echo "Install with: go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Generate markdown from proto files
protoc \
    --doc_out="$OUTPUT_DIR" \
    --doc_opt=markdown,api.md \
    -I proto \
    proto/router_hosts/v1/hosts.proto

# Add header to generated file
TEMP_FILE=$(mktemp)
cat > "$TEMP_FILE" << 'HEADER'
# API Reference

gRPC API documentation for router-hosts.

!!! note "Auto-generated"
    This documentation is auto-generated from protobuf definitions.

---

HEADER

cat "$OUTPUT_FILE" >> "$TEMP_FILE"
mv "$TEMP_FILE" "$OUTPUT_FILE"

echo "Generated API documentation at $OUTPUT_FILE"
```

**Step 2: Make executable**

```bash
chmod +x scripts/generate-proto-docs.sh
```

**Step 3: Test locally (requires protoc-gen-doc)**

```bash
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest
./scripts/generate-proto-docs.sh
cat docs/reference/api.md | head -50
```

Expected: Markdown file with proto documentation

**Step 4: Commit**

```bash
git add scripts/generate-proto-docs.sh docs/reference/api.md
git commit -m "build(docs): add proto documentation generator script"
```

---

### Task 1.5: Create GitHub Actions Workflow

**Files:**
- Create: `.github/workflows/docs.yml`

**Step 1: Create the workflow**

`.github/workflows/docs.yml`:
```yaml
name: Deploy Docs

on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to deploy (e.g., v0.8.0). Defaults to latest release.'
        required: false
        type: string

permissions:
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Determine version
        id: version
        run: |
          if [[ "${{ github.event_name }}" == "release" ]]; then
            VERSION="${{ github.event.release.tag_name }}"
          elif [[ -n "${{ inputs.version }}" ]]; then
            VERSION="${{ inputs.version }}"
          else
            VERSION=$(gh release view --json tagName -q .tagName)
          fi
          echo "version=$VERSION" >> "$GITHUB_OUTPUT"
          echo "Deploying docs for version: $VERSION"
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Download release binary
        run: |
          VERSION="${{ steps.version.outputs.version }}"
          gh release download "$VERSION" \
            --pattern 'router-hosts-*-x86_64-unknown-linux-gnu.tar.gz' \
            --dir /tmp
          tar -xzf /tmp/router-hosts-*-x86_64-unknown-linux-gnu.tar.gz -C /tmp
          chmod +x /tmp/router-hosts
          /tmp/router-hosts --version
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Install protoc
        uses: arduino/setup-protoc@v3
        with:
          version: '25.x'

      - name: Install protoc-gen-doc
        run: go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Python dependencies
        run: |
          pip install mkdocs-material \
            mkdocs-git-revision-date-localized-plugin \
            mike

      - name: Generate CLI docs
        run: ./scripts/generate-cli-docs.sh /tmp/router-hosts

      - name: Generate API docs
        run: ./scripts/generate-proto-docs.sh

      - name: Configure git
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"

      - name: Deploy versioned docs
        run: |
          VERSION="${{ steps.version.outputs.version }}"
          mike deploy --push --update-aliases "$VERSION" latest
          mike set-default --push latest

      - name: Deploy to Cloudflare Pages
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: pages deploy site --project-name=router-hosts-docs
```

**Step 2: Verify YAML syntax**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/docs.yml'))"
```

Expected: No output (success)

**Step 3: Commit**

```bash
git add .github/workflows/docs.yml
git commit -m "ci(docs): add GitHub Actions workflow for docs deployment"
```

---

### Task 1.6: Add Python Requirements for Local Development

**Files:**
- Create: `docs/requirements.txt`

**Step 1: Create requirements file**

`docs/requirements.txt`:
```
mkdocs-material>=9.5.0
mkdocs-git-revision-date-localized-plugin>=1.2.0
mike>=2.0.0
```

**Step 2: Add to .gitignore if not present**

Check and add `site/` to .gitignore (MkDocs build output):

```bash
grep -q '^site/$' .gitignore || echo 'site/' >> .gitignore
```

**Step 3: Commit**

```bash
git add docs/requirements.txt .gitignore
git commit -m "build(docs): add Python requirements for MkDocs"
```

---

### Task 1.7: Test Local Build

**Step 1: Install dependencies**

```bash
pip install -r docs/requirements.txt
```

**Step 2: Build site locally**

```bash
mkdocs build
```

Expected: `site/` directory created with HTML files

**Step 3: Serve locally and verify**

```bash
mkdocs serve &
sleep 3
curl -s http://127.0.0.1:8000 | head -20
kill %1
```

Expected: HTML content returned

**Step 4: No commit needed (verification only)**

---

## Phase 2: Content Migration

### Task 2.1: Move Existing Documentation Files

**Files:**
- Move: `docs/architecture.md` → `docs/contributing/architecture.md`
- Move: `docs/operations.md` → `docs/guides/operations.md`
- Move: `docs/operator.md` → `docs/guides/kubernetes.md`
- Move: `docs/acme.md` → `docs/guides/acme.md`
- Move: `docs/releasing.md` → `docs/contributing/releasing.md`
- Move: `docs/e2e-testing.md` → `docs/contributing/testing.md`

**Step 1: Move files**

```bash
git mv docs/architecture.md docs/contributing/architecture.md
git mv docs/operations.md docs/guides/operations.md
git mv docs/operator.md docs/guides/kubernetes.md
git mv docs/acme.md docs/guides/acme.md
git mv docs/releasing.md docs/contributing/releasing.md
git mv docs/e2e-testing.md docs/contributing/testing.md
```

**Step 2: Commit moves**

```bash
git commit -m "docs: migrate existing documentation to new structure"
```

---

### Task 2.2: Update Internal Cross-References

**Files:**
- Modify: All migrated docs to fix relative links

**Step 1: Find and fix broken links**

Search for links that need updating:

```bash
rg '\]\([^)]*\.md\)' docs/ --type md
```

Update any broken relative paths in the migrated files. Common fixes:
- `architecture.md` → `../contributing/architecture.md` (from guides)
- `operations.md` → `operations.md` (within guides, no change needed)

**Step 2: Update CLAUDE.md references**

In root `CLAUDE.md`, update doc references to new paths.

**Step 3: Verify no broken links**

```bash
mkdocs build --strict 2>&1 | grep -i "warning\|error" || echo "No warnings"
```

**Step 4: Commit fixes**

```bash
git add -A
git commit -m "docs: fix cross-references after migration"
```

---

### Task 2.3: Exclude Plans from Site Build

**Files:**
- Modify: `mkdocs.yml`

**Step 1: Add not_in_nav configuration**

The `nav` in mkdocs.yml already excludes plans (they're not listed). Verify plans directory is not included.

**Step 2: Build and verify plans are excluded**

```bash
mkdocs build
ls site/ | grep -i plan || echo "Plans not in output (correct)"
```

**Step 3: No commit needed if already correct**

---

## Phase 3: Documentation Audit

### Task 3.1: Audit Architecture Documentation

**Files:**
- Modify: `docs/contributing/architecture.md`

**Step 1: Read current architecture.md**

Review content against current codebase.

**Step 2: Verify code references exist**

Check that referenced modules, functions, and paths still exist:

```bash
# Example: check if referenced paths exist
rg "router-hosts-common" --files
rg "router-hosts-storage" --files
```

**Step 3: Update outdated sections**

- Add Prometheus metrics section if missing
- Add health check endpoints section if missing
- Add leader election (operator) section if missing
- Update storage backend descriptions

**Step 4: Add Mermaid architecture diagram if missing**

```mermaid
flowchart TB
    subgraph Client
        CLI[router-hosts CLI]
    end

    subgraph Server
        GRPC[gRPC Server]
        ES[Event Store]
        SNAP[Snapshot Store]
        PROJ[Host Projection]
    end

    subgraph Storage
        SQLite[(SQLite)]
        PG[(PostgreSQL)]
        Duck[(DuckDB)]
    end

    CLI -->|mTLS| GRPC
    GRPC --> ES
    GRPC --> SNAP
    GRPC --> PROJ
    ES --> SQLite
    ES --> PG
    ES --> Duck
```

**Step 5: Commit updates**

```bash
git add docs/contributing/architecture.md
git commit -m "docs(architecture): update and verify content accuracy"
```

---

### Task 3.2: Audit Operations Documentation

**Files:**
- Modify: `docs/guides/operations.md`

**Step 1: Verify SIGHUP behavior matches code**

Check signal handling implementation:

```bash
rg "SIGHUP" --type rust
```

**Step 2: Verify hook configuration format**

Check current hook format in code:

```bash
rg "hooks" crates/ --type rust -A 5 | head -30
```

**Step 3: Update hook examples if format changed**

**Step 4: Commit updates**

```bash
git add docs/guides/operations.md
git commit -m "docs(operations): verify and update content"
```

---

### Task 3.3: Audit Kubernetes Operator Documentation

**Files:**
- Modify: `docs/guides/kubernetes.md`

**Step 1: Verify CRD definitions match**

```bash
cat charts/router-hosts-operator/crds/*.yaml | head -50
```

**Step 2: Verify Helm values match**

```bash
cat charts/router-hosts-operator/values.yaml
```

**Step 3: Add leader election documentation if missing**

**Step 4: Add health check documentation if missing**

**Step 5: Commit updates**

```bash
git add docs/guides/kubernetes.md
git commit -m "docs(kubernetes): update operator documentation"
```

---

### Task 3.4: Audit Remaining Documents

**Files:**
- Review: `docs/guides/acme.md`
- Review: `docs/contributing/testing.md`
- Review: `docs/contributing/releasing.md`
- Review: `docs/troubleshooting.md`

**Step 1: Review each document for accuracy**

For each file:
1. Read content
2. Verify commands work
3. Verify paths exist
4. Update outdated information

**Step 2: Commit all updates**

```bash
git add docs/
git commit -m "docs: complete documentation audit"
```

---

### Task 3.5: Archive Completed Plans

**Files:**
- Move completed plans to `docs/plans/archive/`

**Step 1: List all plans**

```bash
ls docs/plans/*.md 2>/dev/null | grep -v archive
```

**Step 2: Review each plan's status**

For each plan, check if the work is complete by looking for:
- Merged PRs referenced
- Features that now exist in codebase

**Step 3: Move completed plans**

```bash
mkdir -p docs/plans/archive
# Move completed plans (example)
git mv docs/plans/2025-12-XX-completed-plan.md docs/plans/archive/
```

**Step 4: Commit archival**

```bash
git commit -m "docs(plans): archive completed implementation plans"
```

---

## Phase 4: CLAUDE.md Cleanup

### Task 4.1: Audit Root CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Read current CLAUDE.md**

Review for duplication with published docs.

**Step 2: Remove duplicated content**

Content that should be in docs, not CLAUDE.md:
- Detailed architecture explanations (reference `docs/contributing/architecture.md`)
- Full configuration examples (reference `docs/reference/configuration.md`)
- Troubleshooting guides (reference `docs/troubleshooting.md`)

**Step 3: Keep essential development workflow**

CLAUDE.md should contain:
- Quick command reference (`task build`, `task test`)
- Commit message format
- Required skills/workflows
- Links to detailed docs

**Step 4: Commit cleanup**

```bash
git add CLAUDE.md
git commit -m "docs(claude): reduce duplication, reference published docs"
```

---

### Task 4.2: Review Crate-Level CLAUDE.md

**Files:**
- Review: `crates/*/CLAUDE.md` (if any exist)

**Step 1: Check for existing crate CLAUDE.md files**

```bash
rg --files -g "CLAUDE.md" crates/
```

**Step 2: If they exist, ensure they only contain crate-specific information**

**Step 3: Remove if they duplicate root CLAUDE.md**

**Step 4: Commit any changes**

```bash
git add -A
git commit -m "docs(claude): clean up crate-level CLAUDE.md files" || echo "No changes"
```

---

## Phase 5: Polish

### Task 5.1: Verify Local Build

**Step 1: Clean build**

```bash
rm -rf site/
mkdocs build --strict
```

Expected: No warnings or errors

**Step 2: Verify all pages render**

```bash
find site -name "*.html" | wc -l
```

Expected: Multiple HTML files

**Step 3: No commit needed (verification)**

---

### Task 5.2: Test Version Selector

**Step 1: Set up mike locally**

```bash
mike deploy --no-push v0.8.0 latest
mike set-default --no-push latest
```

**Step 2: Serve with mike**

```bash
mike serve &
sleep 3
curl -s http://127.0.0.1:8000 | grep -i "version" || echo "Check version selector manually"
kill %1
```

**Step 3: No commit needed (verification)**

---

### Task 5.3: Create PR

**Step 1: Push branch**

```bash
git push -u origin docs/mkdocs-site
```

**Step 2: Create PR**

```bash
gh pr create \
  --title "docs: create MkDocs Material documentation site" \
  --body "$(cat <<'EOF'
## Summary

Implements #180 - MkDocs Material documentation site with Cloudflare Pages deployment.

### Changes

- Add MkDocs Material configuration with dark mode default
- Create site structure (getting started, guides, reference, contributing)
- Add CLI and API documentation generators
- Add GitHub Actions workflow for release-triggered deployment
- Migrate existing documentation to new structure
- Complete documentation audit and updates
- Clean up CLAUDE.md to reduce duplication

### Infrastructure

- **Deployment:** GitHub Actions → Cloudflare Pages (via wrangler)
- **Versioning:** mike creates `/vX.Y.Z/` paths with `latest` alias
- **Trigger:** On release publish

### Required Secrets

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

### Testing

- [x] Local build passes (`mkdocs build --strict`)
- [x] All existing tests pass
- [ ] Manual review of rendered site

Closes #180

---
🤖 Generated with Claude Code
EOF
)"
```

**Step 3: Request review**

Use `pr-review-toolkit:review-pr` skill for self-review before requesting human review.

---

## Completion Checklist

- [ ] Phase 1: Infrastructure setup complete
- [ ] Phase 2: Content migration complete
- [ ] Phase 3: Documentation audit complete
- [ ] Phase 4: CLAUDE.md cleanup complete
- [ ] Phase 5: Polish and PR complete
- [ ] All tests passing
- [ ] PR created and reviewed
