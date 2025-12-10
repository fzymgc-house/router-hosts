# GHCR Image Pruning Design

**Date:** 2025-12-10
**Status:** Ready for implementation
**Related:** Issue #73

## Overview

Implement automatic cleanup of old Docker images in GitHub Container Registry (GHCR) to prevent storage bloat while preserving images needed for deployment.

## Problem

The Docker workflow builds images for every commit to main, creating three tags per build:
- `${SHA}` - multi-arch manifest
- `${SHA}-amd64` - AMD64 architecture image
- `${SHA}-arm64` - ARM64 architecture image

Without cleanup, these SHA-tagged images accumulate indefinitely, consuming storage.

## Requirements

### Retention Policy

**Delete:**
- SHA-tagged images older than 7 days

**Preserve:**
- `latest` tag (always)
- Semantic version tags (`v0.5.0`, `v1.0.0`, etc.)
- At least 3 most recent builds (safety net)

### Deployment Patterns

The system supports three deployment approaches:
- `latest` tag for dev/testing environments
- Specific SHA tags for production pinning
- Release tags for stable versions

All three tag types must remain available.

### Architecture Tag Handling

Delete manifest and architecture-specific tags as a unit. When removing SHA `abc123`, also remove `abc123-amd64` and `abc123-arm64`.

## Design

### Workflow Structure

**File:** `.github/workflows/cleanup-images.yml`

**Schedule:**
- Runs weekly on Sunday at 2 AM UTC
- `workflow_dispatch` enabled for manual triggering and testing

**Execution environment:**
- Standard GitHub-hosted runner (ubuntu-latest)
- Minimal resource requirements (API calls only)

**Environment variables:**
```yaml
env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
  PACKAGE_NAME: router-hosts
```

### Permissions

```yaml
permissions:
  packages: write  # Required to delete package versions
  contents: read   # Standard read access
```

Uses `GITHUB_TOKEN` for authentication. No additional secrets required.

### Cleanup Steps

Three separate deletion steps handle manifest and architecture tags:

#### Step 1: Delete Manifest Tags

```yaml
- name: Delete old manifest images
  uses: actions/delete-package-versions@v5
  with:
    package-name: 'router-hosts'
    package-type: 'container'
    token: ${{ secrets.GITHUB_TOKEN }}
    min-versions-to-keep: 3
    older-than: 7
    ignore-versions: '^latest$|^v\d+\.\d+\.\d+'
    delete-only-untagged-versions: false
    version-pattern: '^[0-9a-f]{40}$'
```

#### Step 2: Delete AMD64 Tags

```yaml
- name: Delete old amd64 images
  uses: actions/delete-package-versions@v5
  with:
    package-name: 'router-hosts'
    package-type: 'container'
    token: ${{ secrets.GITHUB_TOKEN }}
    min-versions-to-keep: 3
    older-than: 7
    ignore-versions: '^latest$|^v\d+\.\d+\.\d+'
    delete-only-untagged-versions: false
    version-pattern: '^[0-9a-f]{40}-amd64$'
```

#### Step 3: Delete ARM64 Tags

```yaml
- name: Delete old arm64 images
  uses: actions/delete-package-versions@v5
  with:
    package-name: 'router-hosts'
    package-type: 'container'
    token: ${{ secrets.GITHUB_TOKEN }}
    min-versions-to-keep: 3
    older-than: 7
    ignore-versions: '^latest$|^v\d+\.\d+\.\d+'
    delete-only-untagged-versions: false
    version-pattern: '^[0-9a-f]{40}-arm64$'
```

### Configuration Parameters

**`min-versions-to-keep: 3`**
- Safety net: preserves 3 most recent versions even if older than 7 days
- Prevents complete deletion if no recent builds exist
- Applied per tag type (manifest, amd64, arm64)

**`older-than: 7`**
- Time-based retention in days
- Aligns with weekly cleanup schedule
- More predictable than count-based retention

**`ignore-versions: '^latest$|^v\d+\.\d+\.\d+'`**
- Protects `latest` tag via exact match
- Protects semantic versions via pattern match
- Applied before other filters
- **Note:** Matches basic semver tags only (v1.0.0). Pre-release tags (v1.0.0-beta.1) and build metadata (v1.0.0+build.123) are NOT protected. Expand pattern if using pre-release tags.

**`version-pattern`**
- Conceptual pattern: `'^[0-9a-f]{40}(-amd64|-arm64)?$'`
- Implemented as three separate regexes in workflow:
  - Manifest: `'^[0-9a-f]{40}$'` (exact 40-char SHA)
  - AMD64: `'^[0-9a-f]{40}-amd64$'` (SHA with amd64 suffix)
  - ARM64: `'^[0-9a-f]{40}-arm64$'` (SHA with arm64 suffix)
- Prevents accidental deletion of non-SHA tags

## Safety Mechanisms

### Multi-Layered Protection

1. **Positive pattern matching** - `version-pattern` must match
2. **Negative pattern exclusion** - `ignore-versions` must not match
3. **Minimum retention** - `min-versions-to-keep` prevents complete deletion
4. **Dry-run testing** - Add `dry-run: true` for validation without deletion

### Error Handling

**Individual step failures:**
- Steps run independently
- Failure in one step doesn't prevent others
- Orphaned architecture tags (if manifest deletion fails) cleaned up in next run
- Trade-off prioritizes storage savings over perfect multi-arch consistency

**No rollback mechanism:**
- Deletions are permanent
- Images can be rebuilt from git history if needed
- Weekly schedule allows time to detect issues

### Monitoring

**Workflow logs:**
- Show which versions were deleted
- Timestamps for audit trail
- Success/failure status per step

**GHCR audit log:**
- Records all package modifications
- Accessible via GitHub UI
- Permanent record independent of workflow logs

## Testing Strategy

### Pre-Deployment

1. **Dry-run validation:**
   - Enable `dry-run: true` in PR
   - Trigger via `workflow_dispatch`
   - Review logs for correct tag identification
   - Verify protected tags excluded

2. **Regex testing:**
   ```bash
   # List current package versions
   gh api /orgs/fzymgc-house/packages/container/router-hosts/versions \
     --jq '.[] | {name: .name, created_at: .created_at}'

   # Count SHA-tagged versions
   gh api /orgs/fzymgc-house/packages/container/router-hosts/versions \
     --jq '[.[] | .name] | map(select(test("^[0-9a-f]{40}$"))) | length'
   ```

### Post-Deployment

1. **First run monitoring:**
   - Watch workflow execution logs
   - Compare GHCR versions before/after
   - Confirm 7-day cutoff works correctly
   - Verify minimum 3 versions retained

2. **Ongoing validation:**
   - Weekly: Check storage usage trends
   - Monthly: Audit release tag preservation
   - Continuous: E2E tests pull `:latest` successfully

### Rollback Plan

**If cleanup too aggressive:**
- Disable workflow via GitHub UI
- Rebuild needed images by triggering Docker workflow on specific commits
- Images recreatable from any git commit

## Implementation Checklist

- [ ] Create `.github/workflows/cleanup-images.yml`
- [ ] Configure three deletion steps (manifest, amd64, arm64)
- [ ] Set weekly cron schedule (Sunday 2 AM UTC)
- [ ] Enable `workflow_dispatch` for manual testing
- [ ] Test with `dry-run: true` enabled
- [ ] Review dry-run logs for correctness
- [ ] Disable dry-run and merge to main
- [ ] Monitor first production run
- [ ] Verify storage usage decreases over time
- [ ] Update issue #73 with results

## Alternative Approaches Considered

**Count-based retention (rejected):**
- Keep last N builds instead of time-based
- More complex: "last N per branch" vs "last N total"
- Less predictable with varying commit frequency
- Time-based retention simpler and clearer

**Single-step cleanup (rejected):**
- Use one action call with complex regex
- Harder to debug and maintain
- Less explicit handling of architecture tags
- Three-step approach clearer and more maintainable

**Custom script (rejected):**
- Write bash/Python script using `gh api`
- More control but more code to maintain
- `actions/delete-package-versions` well-maintained and tested
- Action provides safety features built-in

## References

- [actions/delete-package-versions](https://github.com/actions/delete-package-versions)
- [GitHub Packages API](https://docs.github.com/en/rest/packages)
- Current Docker workflow: `.github/workflows/docker.yml`
