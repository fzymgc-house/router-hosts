# Release Process

This document describes the automated release process for router-hosts using [release-plz](https://release-plz.dev).

## Overview

Releases are fully automated:

1. **Push commits to `main`** using [Conventional Commits](https://www.conventionalcommits.org/) format
2. **release-plz creates a Release PR** with version bumps and changelog updates
3. **Merge the Release PR** to trigger the release
4. **Workflows build and publish** binaries, Helm chart, and documentation

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│ Push commit │────▶│ Release PR   │────▶│ Merge PR    │────▶│ v-release.yml│
│ to main     │     │ auto-created │     │ pushes tag  │     │ builds binaries│
└─────────────┘     └──────────────┘     └─────────────┘     └──────────────┘
                                                                    │
                                         ┌──────────────────────────┴───────┐
                                         │                                  │
                                    ┌────▼─────┐                    ┌───────▼──────┐
                                    │helm-release│                   │docs.yml      │
                                    │publishes   │                   │deploys docs  │
                                    │chart       │                   │              │
                                    └────────────┘                   └──────────────┘
```

## Conventional Commits

All commits to `main` **must** use Conventional Commits format. This enables:

- Automatic version determination (major/minor/patch)
- Automatic changelog generation
- Pre-commit validation via cocogitto

### Commit Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Version Bump Rules

| Commit Type | Version Bump | Example |
|-------------|--------------|---------|
| `feat!:` or `BREAKING CHANGE:` | Major (0.x → 1.0) | API breaking change |
| `feat:` | Minor (0.8.0 → 0.9.0) | New feature |
| `fix:`, `perf:` | Patch (0.8.0 → 0.8.1) | Bug fix, performance |
| `docs:`, `refactor:`, `test:`, `ci:`, `chore:` | No bump | Internal changes |

### Pre-commit Validation

Commit messages are validated automatically:

```bash
# Install pre-commit hooks (including commit-msg validation)
pre-commit install
pre-commit install --hook-type commit-msg
pre-commit install --hook-type pre-push
```

If your commit message doesn't follow the format, the commit will be rejected with guidance.

## Creating a Release

### Standard Release Flow

1. **Push conventional commits to `main`**
   ```bash
   git commit -m "feat(server): add metrics endpoint"
   git push origin main
   ```

2. **Wait for Release PR**
   - `release-plz.yml` workflow runs automatically
   - Creates/updates PR titled "chore: release vX.Y.Z"
   - PR contains version bumps and changelog updates

3. **Review the Release PR**
   - Verify changelog entries are accurate
   - Confirm version bump is correct (major/minor/patch)
   - Check that Helm chart version is synced

4. **Merge the Release PR**
   - Merging triggers the `release-plz release` command
   - This pushes the version tag (e.g., `v0.9.0`)

5. **Automated workflows trigger on tag**
   - `v-release.yml`: Builds binaries, creates GitHub Release
   - `helm-release.yml`: Publishes Helm chart to ghcr.io
   - `docs.yml`: Deploys documentation to Cloudflare Pages

### Version Files

release-plz automatically updates these files:

| File | Fields Updated |
|------|----------------|
| `Cargo.toml` (workspace) | `version` |
| `charts/router-hosts-operator/Chart.yaml` | `version`, `appVersion` |
| `CHANGELOG.md` | New release section |

## Testing Releases Locally

Before pushing, test the release build process:

```bash
# Test release build locally (without publishing)
dist build --artifacts=local --output-format=json

# Dry-run for a specific tag (shows what would be created)
dist plan --tag=v0.9.0

# Check what artifacts would be generated
dist plan --tag=v0.9.0 --output-format=json | jq '.artifacts'

# Test that binaries are stripped (for smaller size)
cargo build --profile=dist -p router-hosts
ls -lh target/dist/router-hosts
file target/dist/router-hosts  # Should show "stripped"

# Verify the binary runs correctly
./target/dist/router-hosts --version
./target/dist/router-hosts --help
```

## Required GitHub Secrets

The following secrets must be configured in the repository:

### Release Secrets

- **`HOMEBREW_TAP_TOKEN`**: Personal access token with `contents: write` permission for `fzymgc-house/homebrew-tap`
  - Create at: https://github.com/settings/tokens/new
  - Required scopes: `public_repo` (or `repo` if tap is private)
  - Add at: https://github.com/fzymgc-house/router-hosts/settings/secrets/actions

### Documentation Deployment Secrets

For automated documentation deployment to Cloudflare Pages:

- **`CLOUDFLARE_ACCOUNT_ID`**: Cloudflare account identifier
  - Find at: Cloudflare Dashboard → Account Home → right sidebar
- **`CLOUDFLARE_PAGES_ACCOUNT_API`**: API token with Pages deployment permission
  - Create at: Cloudflare Dashboard → My Profile → API Tokens → Create Token
  - Use template: "Edit Cloudflare Pages"
  - Or custom token with: `Zone:Read`, `Account:Cloudflare Pages:Edit`

## Documentation Setup

Create a Cloudflare Pages project before the first release:

1. Go to Cloudflare Dashboard → Workers & Pages → Create
2. Select "Pages" → "Direct Upload" (not Git connection)
3. Name the project: `router-hosts-docs`
4. The docs workflow will deploy using Wrangler

## Post-Release Verification

After the release workflow completes, use the automated verification script:

```bash
# Automated verification (downloads, verifies attestations, checks audit data)
./scripts/verify-release.sh v0.9.0
```

Or manually verify each step:

```bash
# 1. Verify GitHub Release was created
gh release view v0.9.0

# 2. Test shell installer (in clean environment/container)
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/fzymgc-house/router-hosts/releases/download/v0.9.0/router-hosts-installer.sh | sh

# 3. Verify binary attestations
gh attestation verify router-hosts --repo fzymgc-house/router-hosts

# 4. Test Homebrew tap installation (preferred method)
brew install fzymgc-house/tap/router-hosts

# Alternative: Direct formula install from release
curl -LO https://github.com/fzymgc-house/router-hosts/releases/download/v0.9.0/router-hosts.rb
brew install --formula ./router-hosts.rb

# 5. Test binary with audit data
cargo auditable audit router-hosts

# 6. Verify Helm chart
helm pull oci://ghcr.io/fzymgc-house/charts/router-hosts-operator --version 0.9.0
```

## Release Tag Format

release-plz uses semantic versioning with `v` prefix:

- `v0.9.0` - Standard release
- `v0.9.1-rc.1` - Pre-release (marked as prerelease in GitHub)

## Workflow Configuration

### release-plz.yml

Creates/updates release PRs and pushes tags when merged. Configuration in `release-plz.toml`.

### v-release.yml

Builds binaries using cargo-dist. Named `v-release.yml` because cargo-dist uses this convention when `tag-namespace = "v"` is configured.

**Warning:** Do not rename `v-release.yml` manually. Running `dist generate-ci` will recreate it with the original name.

### helm-release.yml

Publishes Helm chart to GitHub Container Registry (ghcr.io) as an OCI artifact.

**Requirements:**
- Helm 4.x (specifically v4.0.4 or later)
- Chart version must match the release tag

For manual chart publishing (if workflow failed):

```bash
gh workflow run helm-release.yml -f tag=v0.9.0
```

## Release Artifacts

Each release includes:

| Artifact | Description |
|----------|-------------|
| `router-hosts-x86_64-unknown-linux-gnu.tar.xz` | Linux x86_64 binary |
| `router-hosts-aarch64-unknown-linux-gnu.tar.xz` | Linux ARM64 binary |
| `router-hosts-x86_64-apple-darwin.tar.xz` | macOS Intel binary |
| `router-hosts-aarch64-apple-darwin.tar.xz` | macOS Apple Silicon binary |
| `router-hosts-installer.sh` | Universal shell installer |
| `router-hosts.rb` | Homebrew formula |
| `router-hosts-operator` Helm chart | Published to `oci://ghcr.io/fzymgc-house/charts` |

## Rollback

If a release has issues:

1. **Don't delete the release** - users may have already downloaded it
2. Create a new patch release with the fix (e.g., v0.9.1)
3. Add a note to the problematic release warning users
4. If critical security issue:
   - Create hotfix immediately
   - Consider yanking the vulnerable release (rare)

## Troubleshooting

### Release PR not created

1. Check that commits use Conventional Commits format
2. Verify `release-plz.yml` workflow ran successfully
3. Look for existing release PR that needs updating

### Version not bumping

- Commits like `docs:`, `chore:`, `ci:` don't trigger version bumps
- Use `feat:` for new features, `fix:` for bug fixes

### Helm chart version mismatch

release-plz automatically syncs Chart.yaml via `version_files` in `release-plz.toml`. If mismatch occurs:

1. Check `release-plz.toml` version_files configuration
2. Manually update Chart.yaml and re-push

### cargo-semver-checks failure

If release-plz detects a breaking change but commit wasn't marked as breaking:

1. Amend commit to use `feat!:` or add `BREAKING CHANGE:` footer
2. Or acknowledge the breaking change in the release PR
