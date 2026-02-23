# Release Process

This document describes the automated release process for router-hosts using [release-please](https://github.com/googleapis/release-please).

## Overview

The release pipeline is being set up for the Go rewrite. The general flow will be:

1. **Push commits to `main`** using [Conventional Commits](https://www.conventionalcommits.org/) format
2. **release-please creates a Release PR** with version bumps and changelog updates
3. **Merge the Release PR** to trigger the release
4. **Workflows build and publish** binaries and documentation

!!! note "Release pipeline not yet configured"
    The Go release pipeline (binary builds, container images, etc.) is not yet set up.
    The sections below describe the commit conventions and release-please workflow
    that are already in place.

## Conventional Commits

All commits to `main` **must** use Conventional Commits format. This enables:

- Automatic version determination (major/minor/patch)
- Automatic changelog generation
- Pre-commit validation via cocogitto

### Commit Format

```text
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

### Commit Validation

Commit messages are validated automatically via lefthook:

```bash
# Install lefthook hooks
brew install lefthook
lefthook install
```

If your commit message doesn't follow the format, the commit will be rejected with guidance.

### Prerequisites

The commit message validation requires cocogitto:

```bash
# Install cocogitto (macOS)
brew install cocogitto
```

## Creating a Release

### Standard Release Flow

1. **Push conventional commits to `main`**

   ```bash
   git commit -m "feat(server): add metrics endpoint"
   git push origin main
   ```

2. **Wait for Release PR**
   - `release-please.yml` workflow runs automatically
   - Creates/updates PR titled "chore(main): release router-hosts X.Y.Z"
   - PR contains version bumps and changelog updates

3. **Review the Release PR**
   - Verify changelog entries are accurate
   - Confirm version bump is correct (major/minor/patch)

4. **Merge the Release PR**
   - Merging pushes the version tag (e.g., `v0.9.0`)
   - Tag push triggers downstream workflows

5. **Automated workflows trigger on tag** (to be configured)

### Version Files

release-please automatically updates these files:

| File | Fields Updated |
|------|----------------|
| `CHANGELOG.md` | New release section |

## Required GitHub Secrets

The following secrets must be configured in the repository:

### Release Secrets

- **`RELEASE_PLEASE_APP_ID`**: GitHub App ID for release-please authentication
  - The GitHub App must have `contents: write` and `pull-requests: write` permissions
  - Using a GitHub App allows the release PR merge to trigger downstream workflows

- **`RELEASE_PLEASE_PRIVATE_KEY`**: GitHub App private key (PEM format)
  - Generate in the GitHub App settings

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

After the release workflow completes:

```bash
# 1. Verify GitHub Release was created
gh release view v0.9.0

# 2. Download and test binary
gh release download v0.9.0
./router-hosts --version
./router-hosts --help
```

## Release Tag Format

release-please uses semantic versioning with `v` prefix:

- `v0.9.0` - Standard release
- `v0.9.1-rc.1` - Pre-release (marked as prerelease in GitHub)

## Workflow Configuration

### release-please.yml

Creates/updates release PRs and pushes tags when merged. Configuration in `release-please-config.json`.

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
2. Verify `release-please.yml` workflow ran successfully
3. Look for existing release PR that needs updating
4. Check GitHub App permissions (needs `contents: write` and `pull-requests: write`)

### Version not bumping

- Commits like `docs:`, `chore:`, `ci:` don't trigger version bumps
- Use `feat:` for new features, `fix:` for bug fixes

### GitHub App token issues

If the release PR doesn't trigger downstream workflows:

1. Verify GitHub App has correct permissions
2. Check that secrets `RELEASE_PLEASE_APP_ID` and `RELEASE_PLEASE_PRIVATE_KEY` are set
3. Ensure the App is installed on the repository
