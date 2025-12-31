# MkDocs Material Documentation Site Design

**Issue:** #180
**Date:** 2025-12-30
**Status:** Draft

## Summary

Create a professional documentation site using MkDocs Material, published to Cloudflare Pages via GitHub Actions. The site serves both external users adopting router-hosts and internal contributors maintaining the project.

## Goals

1. Publish versioned documentation matching each release
2. Auto-generate CLI and API reference from source
3. Consolidate and audit existing documentation
4. Establish sustainable documentation practices

## Architecture

### Site Structure

```
docs/
├── index.md                    # Landing page
├── getting-started/
│   ├── index.md               # Quick start
│   ├── installation.md        # Binary, Docker, source
│   └── configuration.md       # Server & client config
├── reference/
│   ├── cli.md                 # Auto-generated from --help
│   ├── api.md                 # Auto-generated from protos
│   └── configuration.md       # Full config reference
├── guides/
│   ├── operations.md          # SIGHUP, hooks (existing)
│   ├── acme.md                # ACME certificates (existing)
│   ├── kubernetes.md          # Operator usage (existing)
│   └── storage-backends.md    # SQLite, PostgreSQL, DuckDB
├── contributing/
│   ├── index.md               # Contributing guide
│   ├── architecture.md        # System design (existing)
│   ├── testing.md             # E2E testing (existing)
│   └── releasing.md           # Release process (existing)
└── troubleshooting.md         # Troubleshooting guide (existing)
```

### Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Static site generator | MkDocs Material | Rich features, Python ecosystem, excellent search |
| Hosting | Cloudflare Pages | Fast CDN, simple deployment, free tier sufficient |
| Versioning | mike | Standard MkDocs versioning tool |
| CI/CD | GitHub Actions | Existing infrastructure, full build control |
| Diagrams | Mermaid | Version-controlled, renders natively in Material |

### Deployment Pipeline

```mermaid
flowchart LR
    A[Release Published] --> B[Download Release Binary]
    B --> C[Generate CLI Docs]
    C --> D[Generate API Docs]
    D --> E[Build MkDocs Site]
    E --> F[Deploy via mike]
    F --> G[Sync to Cloudflare Pages]
```

**Trigger:** Release published (not push to main)

Each release creates a versioned docs deployment. The `latest` alias points to the most recent stable release. Users select versions via the site's version selector.

## Configuration

### MkDocs Configuration

```yaml
site_name: router-hosts
site_url: https://router-hosts-docs.pages.dev
repo_url: https://github.com/fzymgc-house/router-hosts
repo_name: fzymgc-house/router-hosts

theme:
  name: material
  palette:
    - scheme: slate              # Dark mode default
      toggle:
        icon: material/brightness-4
        name: Switch to light mode
    - scheme: default
      toggle:
        icon: material/brightness-7
        name: Switch to dark mode
  features:
    - content.code.copy
    - navigation.sections
    - navigation.top
    - search.highlight
    - toc.integrate

plugins:
  - search
  - git-revision-date-localized:
      type: date
      fallback_to_build_date: true

markdown_extensions:
  - pymdownx.highlight:
      anchor_linenums: true
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
  - admonition
  - pymdownx.details
```

### GitHub Actions Workflow

```yaml
name: Deploy Docs

on:
  release:
    types: [published]
  workflow_dispatch:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Download release binary
        run: |
          VERSION=${{ github.event.release.tag_name }}
          gh release download "$VERSION" \
            --pattern 'router-hosts-*-linux-x86_64.tar.gz' \
            --dir /tmp
          tar -xzf /tmp/router-hosts-*-linux-x86_64.tar.gz -C /tmp
          chmod +x /tmp/router-hosts
        env:
          GH_TOKEN: ${{ github.token }}

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: |
          pip install mkdocs-material \
            mkdocs-git-revision-date-localized-plugin \
            mike

      - name: Install protoc-gen-doc
        run: |
          go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest

      - name: Generate CLI docs
        run: ./scripts/generate-cli-docs.sh /tmp/router-hosts

      - name: Generate API docs
        run: ./scripts/generate-proto-docs.sh

      - name: Deploy versioned docs
        run: |
          VERSION=${{ github.event.release.tag_name }}
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          mike deploy --push --update-aliases "$VERSION" latest

      - name: Deploy to Cloudflare Pages
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: pages deploy site --project-name=router-hosts-docs
```

## Documentation Generation Scripts

### CLI Reference Generation

`scripts/generate-cli-docs.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

BINARY="${1:-./target/release/router-hosts}"
OUTPUT="docs/reference/cli.md"

cat > "$OUTPUT" << 'EOF'
# CLI Reference

Auto-generated from `router-hosts --help`.

EOF

echo '## Global Options' >> "$OUTPUT"
echo '```' >> "$OUTPUT"
"$BINARY" --help >> "$OUTPUT"
echo '```' >> "$OUTPUT"

for cmd in $("$BINARY" --help | grep -E '^\s+\w+\s' | awk '{print $1}'); do
  echo "" >> "$OUTPUT"
  echo "## $cmd" >> "$OUTPUT"
  echo '```' >> "$OUTPUT"
  "$BINARY" "$cmd" --help >> "$OUTPUT" 2>&1 || true
  echo '```' >> "$OUTPUT"
done
```

### API Reference Generation

`scripts/generate-proto-docs.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

protoc \
  --doc_out=docs/reference \
  --doc_opt=markdown,api.md \
  -I proto \
  proto/router_hosts/v1/hosts.proto
```

## Content Migration

### Existing Docs Mapping

| Current Location | New Location | Action |
|-----------------|--------------|--------|
| `docs/architecture.md` | `docs/contributing/architecture.md` | Move |
| `docs/operations.md` | `docs/guides/operations.md` | Move |
| `docs/operator.md` | `docs/guides/kubernetes.md` | Move, rename |
| `docs/acme.md` | `docs/guides/acme.md` | Move |
| `docs/troubleshooting.md` | `docs/troubleshooting.md` | Keep |
| `docs/releasing.md` | `docs/contributing/releasing.md` | Move |
| `docs/e2e-testing.md` | `docs/contributing/testing.md` | Move, rename |
| `docs/plans/` | Exclude from site | Add to nav exclusion |

### New Content Required

| File | Description |
|------|-------------|
| `docs/index.md` | Project overview, key features, quick links |
| `docs/getting-started/index.md` | Quick start guide |
| `docs/getting-started/installation.md` | Installation methods |
| `docs/getting-started/configuration.md` | Basic configuration |
| `docs/guides/storage-backends.md` | SQLite, PostgreSQL, DuckDB comparison |
| `docs/contributing/index.md` | How to contribute |

## Documentation Audit

### Content Review Checklist

For each document:

1. **Currency** — Verify content matches current codebase
   - Check referenced code paths exist
   - Verify CLI flags and options
   - Test configuration examples
2. **Completeness** — Document recent features
   - Health check endpoints
   - Prometheus metrics
   - Leader election
   - Storage backend differences
3. **Coherence** — Ensure clarity and consistency
   - Remove duplicate content
   - Fix broken cross-references
   - Use consistent terminology
4. **Accuracy** — Validate all examples work

### Plans Archival

Review each plan in `docs/plans/`:
- Completed work → move to `docs/plans/archive/`
- In-progress work → keep in `docs/plans/`

### CLAUDE.md Audit

| Location | Purpose | Principle |
|----------|---------|-----------|
| Root `CLAUDE.md` | Development workflow | Minimal; reference docs for details |
| `crates/*/CLAUDE.md` | Crate-specific context | Only if unique patterns exist |
| `docs/CLAUDE.md` | Doc contribution | Style guide, build instructions |

CLAUDE.md files point to documentation; they do not duplicate it.

## Implementation Phases

### Phase 1: Infrastructure Setup
- Create `mkdocs.yml`
- Set up directory structure
- Create generation scripts
- Create GitHub Actions workflow
- Configure Cloudflare Pages project
- Verify end-to-end deployment

### Phase 2: Content Migration
- Move existing docs to new locations
- Update cross-references
- Exclude `docs/plans/` from build
- Create landing page and navigation

### Phase 3: Documentation Audit
- Review each doc against codebase
- Update outdated content
- Fill documentation gaps
- Archive completed plans
- Add Mermaid diagrams

### Phase 4: CLAUDE.md Cleanup
- Trim root CLAUDE.md
- Review crate-level CLAUDE.md files
- Remove duplication with published docs

### Phase 5: Polish
- Test version selector
- Verify mobile responsiveness
- Check search functionality
- Final review

## Infrastructure Requirements

### Cloudflare Configuration

1. Create Pages project: `router-hosts-docs`
2. Connect to GitHub repository (for direct deploy, not build)
3. Use default `*.pages.dev` domain

### GitHub Secrets

| Secret | Purpose |
|--------|---------|
| `CLOUDFLARE_API_TOKEN` | Wrangler deployment authentication |
| `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account identifier |

## Success Criteria

- Documentation site builds without errors
- All existing markdown docs incorporated
- Automatic deployment on release
- Mobile-responsive design
- Sub-2-second page loads
- Working version selector
- Accurate CLI and API reference
