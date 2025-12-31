# Release Process

This document describes how to create and verify releases for router-hosts.

## Testing Releases Locally

Before creating a release tag, test the release build process locally:

```bash
# Test release build locally (without publishing)
dist build --artifacts=local --output-format=json

# Dry-run for a specific tag (shows what would be created)
dist plan --tag=v0.5.0

# Check what artifacts would be generated
dist plan --tag=v0.5.0 --output-format=json | jq '.artifacts'

# Test that binaries are stripped (for smaller size)
cargo build --profile=dist -p router-hosts
ls -lh target/dist/router-hosts
file target/dist/router-hosts  # Should show "stripped"

# Verify the binary runs correctly
./target/dist/router-hosts --version
./target/dist/router-hosts --help
```

## Required GitHub Secrets

The following secrets must be configured in the repository for releases to work:

- **`HOMEBREW_TAP_TOKEN`**: Personal access token with `contents: write` permission for `fzymgc-house/homebrew-tap`
  - Create at: https://github.com/settings/tokens/new
  - Required scopes: `public_repo` (or `repo` if tap is private)
  - Add at: https://github.com/fzymgc-house/router-hosts/settings/secrets/actions

## Creating a Release

1. **Update version in `Cargo.toml`** (workspace root):
   ```toml
   [workspace.package]
   version = "0.6.0"  # Update this
   ```

2. **Update Helm chart version** in `charts/router-hosts-operator/Chart.yaml`:
   ```yaml
   version: 0.6.0      # Must match the tag (without 'v' prefix)
   appVersion: 0.6.0   # Should match the application version
   ```

3. **Update CHANGELOG.md** with release notes

4. **Commit version bump**:
   ```bash
   git commit -am "chore: bump version to v0.6.0"
   git push origin main
   ```

5. **Create and push tag** (triggers release workflows):
   ```bash
   git tag v0.6.0
   git push origin v0.6.0
   ```

6. **Monitor release workflows**:
   - `v-release.yml`: Builds binaries, generates installers, creates GitHub Release
   - `helm-release.yml`: Publishes Helm chart to ghcr.io OCI registry
   - Both workflows trigger on version tags matching `v*.*.*`

## Post-Release Verification

After the release workflow completes, use the automated verification script:

```bash
# Automated verification (downloads, verifies attestations, checks audit data)
./scripts/verify-release.sh v0.6.0
```

Or manually verify each step:

```bash
# 1. Verify GitHub Release was created
gh release view v0.6.0

# 2. Test shell installer (in clean environment/container)
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/fzymgc-house/router-hosts/releases/download/v0.6.0/router-hosts-installer.sh | sh

# 3. Verify binary attestations
gh attestation verify router-hosts --repo fzymgc-house/router-hosts

# 4. Test Homebrew tap installation (preferred method)
brew install fzymgc-house/tap/router-hosts

# Alternative: Direct formula install from release
curl -LO https://github.com/fzymgc-house/router-hosts/releases/download/v0.6.0/router-hosts.rb
brew install --formula ./router-hosts.rb

# 5. Test binary with audit data
cargo auditable audit router-hosts
```

## Release Tag Format

Use semantic versioning with `v` prefix:
- `v0.5.0` - Standard release
- `v0.5.1-rc.1` - Pre-release (marked as prerelease in GitHub)
- `0.5.0` - Won't trigger workflow (v prefix required)
- `release-0.5.0` - Won't trigger workflow

## Workflow Configuration

**Note:** The release workflow is named `v-release.yml` (not `release.yml`) because
cargo-dist uses this naming convention when `tag-namespace = "v"` is configured.

**Warning:** Do not rename `v-release.yml` manually. Running `dist generate-ci` will
recreate it with the original name, and any custom changes will be lost. Always use
`dist generate-ci` to regenerate the workflow file after modifying `dist-workspace.toml`.

## Helm Chart Release

The Helm chart is published to GitHub Container Registry (ghcr.io) as an OCI artifact.

### Chart Release Process

The Helm chart version **must match the release tag**. The workflow validates this and will fail if there's a mismatch.

1. **Update Chart.yaml versions** before tagging:
   ```bash
   # Edit charts/router-hosts-operator/Chart.yaml
   version: 0.8.0      # Must match the tag (without 'v' prefix)
   appVersion: 0.8.0   # Should match the application version
   ```

2. **Commit the Chart.yaml update** along with other release changes

3. **Create and push tag** - the `helm-release.yml` workflow triggers automatically

4. **Verify chart publication**:
   ```bash
   # Pull the chart to verify it's published
   helm pull oci://ghcr.io/fzymgc-house/charts/router-hosts-operator --version 0.8.0

   # Or install directly
   helm install router-hosts-operator \
     oci://ghcr.io/fzymgc-house/charts/router-hosts-operator \
     --version 0.8.0
   ```

### Manual Chart Publishing

To publish a chart for an existing tag (e.g., if the workflow failed or was added after the tag):

```bash
gh workflow run helm-release.yml -f tag=v0.7.0
```

### Chart Version Validation

The workflow validates that:
- `version` in Chart.yaml matches the git tag
- `appVersion` in Chart.yaml matches the git tag

If either doesn't match, the workflow fails with a clear error message indicating which version needs to be updated.

### Helm Version Requirements

The release workflow uses **Helm 4.x** (specifically v4.0.4 or later). Helm 4 provides:

- Improved OCI registry support with better error handling
- Native OCI artifact publishing without experimental flags
- Better compatibility with ghcr.io container registry

For details on Helm 4 changes, see: https://helm.sh/blog/helm-4-0-0-released/

If you need to run helm commands locally for chart development, ensure you have Helm 4.x installed:

```bash
helm version  # Should show v4.x.x
```

## Release Artifacts

Each release includes:

| Artifact | Description |
|----------|-------------|
| `router-hosts-x86_64-unknown-linux-gnu.tar.gz` | Linux x86_64 binary |
| `router-hosts-aarch64-unknown-linux-gnu.tar.gz` | Linux ARM64 binary |
| `router-hosts-x86_64-apple-darwin.tar.gz` | macOS Intel binary |
| `router-hosts-aarch64-apple-darwin.tar.gz` | macOS Apple Silicon binary |
| `router-hosts-installer.sh` | Universal shell installer |
| `router-hosts.rb` | Homebrew formula |
| `router-hosts-operator` Helm chart | Published to `oci://ghcr.io/fzymgc-house/charts` |

## Rollback

If a release has issues:

1. **Don't delete the release** - users may have already downloaded it
2. Create a new patch release with the fix (e.g., v0.6.1)
3. Add a note to the problematic release warning users
4. If critical security issue:
   - Create hotfix immediately
   - Consider yanking the vulnerable release (rare)
