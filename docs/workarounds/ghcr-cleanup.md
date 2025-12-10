# GHCR Image Cleanup Workarounds

## Overview

This document explains the workarounds required for GHCR (GitHub Container Registry) image cleanup due to limitations in available GitHub Actions.

## Problem Statement

The official `actions/delete-package-versions@v5` action **does not support** critical parameters that were assumed to work in our initial design:

- ❌ `older-than`: Time-based retention (e.g., "delete images older than 7 days")
- ❌ `version-pattern`: Regex filtering (e.g., "only delete SHA-tagged images")
- ❌ `dry-run`: Safe testing mode

These parameters are **silently ignored** by the action, making the workflow ineffective and dangerous (no dry-run protection).

## Solution: snok/container-retention-policy

We use `snok/container-retention-policy@v3.0.1` as a replacement because it:

✅ Supports time-based retention via `cut-off`
✅ Supports dry-run mode
✅ Active maintenance (235 stars, recent commits)
✅ Issues get resolved promptly

### Why Not dataaxiom/ghcr-cleanup-action?

Despite having more features, dataaxiom was rejected due to:

❌ **Critical bugs in core functionality:**
  - [Issue #99](https://github.com/dataaxiom/ghcr-cleanup-action/issues/99): `older-than + keep-n-tagged` deletes wrong images (3 months unresolved)
  - [Issue #101](https://github.com/dataaxiom/ghcr-cleanup-action/issues/101): Multi-tagged images unconditionally deleted (2 months no response)

❌ **Signs of abandonment:**
  - Last commit: 3.5 months ago
  - Last release: 11 months ago
  - No maintainer response to critical bugs

## Workarounds Required with snok

### 1. No Regex Pattern Matching

**Problem:** snok does NOT support regex patterns like `version-pattern: '^[0-9a-f]{40}$'` to select which images to delete.

**Workaround:**
Use an **inverted protection model**:
- Explicitly list tags to **protect** via `image-tags`
- All other tags matching `tag-selection` will be candidates for deletion
- Deletion is subject to `cut-off` (time) and `keep-n-most-recent` (count)

**Example:**
```yaml
image-tags: |
  latest
  v0.5.0
  v*.*.*-alpha.*
  v*.*.*-beta.*
  v*.*.*-rc.*
```

This protects:
- The `latest` tag
- The current version `v0.5.0`
- Pre-release tags matching the wildcard patterns

**Consequence:** SHA-tagged dev images (e.g., `abc123def456`, `abc123def456-amd64`) are NOT protected and will be deleted based on age/count criteria.

### 2. Wildcard Pattern Support

**Good news:** snok supports glob-style wildcards in `image-tags`:
- `v*.*.*-alpha.*` matches `v1.0.0-alpha.1`, `v2.3.4-alpha.99`
- `v*.*.*-beta.*` matches `v1.0.0-beta.1`
- `v*.*.*-rc.*` matches `v1.0.0-rc.1`

This is sufficient for protecting semver tags with common pre-release identifiers.

### 3. Build Metadata Tags Not Protected

**Limitation:** The pattern `v*.*.*+*` does NOT work in snok.

**Consequence:** Build metadata tags like `v1.0.0+build.123` are NOT protected by our current configuration.

**Mitigation:**
If you use build metadata in production:
1. Add specific tags to the protection list: `v1.0.0+build.123`
2. OR switch to pre-release syntax: `v1.0.0-build.123`

### 4. Multi-Architecture Image Handling

**Original design assumption:** We needed separate steps for:
- Manifest images (SHA tags like `abc123def456`)
- Architecture-specific images (SHA tags like `abc123def456-amd64`, `abc123def456-arm64`)

**Reality with snok:** A single step handles all tags because:
- `tag-selection: tagged` targets ALL tagged images
- Protected tags (via `image-tags`) are excluded
- Both manifest and architecture tags share the same SHA prefix
- Unprotected = eligible for cleanup

**Result:** One step replaces three, simplifying the workflow.

## Configuration Mapping

| Feature | actions/delete-package-versions | snok/container-retention-policy |
|---------|--------------------------------|--------------------------------|
| Time-based retention | ❌ `older-than: 7` (unsupported) | ✅ `cut-off: 1w` |
| Regex filtering | ❌ `version-pattern: '^...$'` (unsupported) | ⚠️ Use inverted `image-tags` protection |
| Keep N recent | ✅ `min-versions-to-keep: 3` | ✅ `keep-n-most-recent: 3` |
| Dry-run mode | ❌ `dry-run: true` (unsupported) | ✅ `dry-run: true` |
| Tag selection | ✅ `delete-only-untagged-versions` | ✅ `tag-selection: tagged/untagged/all` |

## Testing Strategy

1. **Initial dry-run:** The workflow is configured with `dry-run: true` by default
2. **Manual trigger:** Use `workflow_dispatch` to test without waiting for the schedule
3. **Review logs:** Check which images would be deleted before disabling dry-run
4. **Gradual rollout:**
   - Week 1: Dry-run mode, verify correct targeting
   - Week 2: Disable dry-run if behavior is correct

## Maintenance Notes

### Adding New Protected Tags

When releasing new versions, **you may need to update** `image-tags`:

```yaml
image-tags: |
  latest
  v0.5.0
  v0.6.0  # Add new release
  v*.*.*-alpha.*
  v*.*.*-beta.*
  v*.*.*-rc.*
```

However, wildcard patterns should cover most cases automatically.

### Monitoring

Check workflow runs weekly:
- Verify expected number of deletions
- Confirm protected tags are not touched
- Watch for unexpected pattern matches

### Upstream Issues to Watch

**snok/container-retention-policy:**
- ⭐ Active project, issues get resolved
- Check for new features (e.g., regex support in future releases)

**actions/delete-package-versions:**
- 🔍 Watch for parameter support additions in future versions
- If official action adds `older-than`, `version-pattern`, `dry-run`, we can reconsider

## References

- [snok/container-retention-policy Documentation](https://github.com/snok/container-retention-policy)
- [actions/delete-package-versions Documentation](https://github.com/actions/delete-package-versions)
- [dataaxiom/ghcr-cleanup-action Issue #99](https://github.com/dataaxiom/ghcr-cleanup-action/issues/99) (broken `older-than + keep-n-tagged`)
- [dataaxiom/ghcr-cleanup-action Issue #101](https://github.com/dataaxiom/ghcr-cleanup-action/issues/101) (multi-tagged images bug)
- [Original Design Document](../plans/2025-12-10-ghcr-image-pruning-design.md)
