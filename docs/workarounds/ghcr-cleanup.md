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
Use **negation syntax** with the `!` prefix to protect specific tags:
- Tags prefixed with `!` are **protected** from deletion
- The `*` wildcard targets all other tags for deletion
- Deletion is subject to `cut-off` (time) and `keep-n-most-recent` (count)

**Example:**
```yaml
# Protect production tags, delete everything else
image-tags: "!latest !v*.*.* *"
```

This configuration:
- `!latest` - protects the `latest` tag
- `!v*.*.*` - protects all semver tags (v0.5.0, v1.0.0-rc.1, etc.)
- `*` - targets all other tags for deletion

**Consequence:** SHA-tagged dev images (e.g., `abc123def456`, `abc123def456-amd64`) are NOT protected and will be deleted based on age/count criteria.

**Important:** Without the `!` prefix, `image-tags` acts as a **selection filter** (only delete these tags), not a protection list. Always use `!` for tags you want to keep.

### 2. Wildcard Pattern Support

**Good news:** snok supports glob-style wildcards in `image-tags`:
- `!v*.*.*` matches and protects all semver-like tags:
  - `v0.5.0`, `v1.0.0` (release versions)
  - `v1.0.0-alpha.1`, `v1.0.0-beta.1`, `v1.0.0-rc.1` (pre-releases)
- `*` matches all remaining tags for deletion

The simplified `!v*.*.*` pattern protects all semver tags in one rule, eliminating the need for separate alpha/beta/rc patterns.

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

**Reality with snok:** A single step handles all images because:
- `tag-selection: both` targets tagged AND untagged images
- Protected tags (via `!` prefix in `image-tags`) are excluded
- Both manifest and architecture tags share the same SHA prefix
- Untagged intermediate layers are also cleaned up

**Why `tag-selection: both`:**
- **Tagged images:** SHA-based dev images (abc123def456) are cleaned
- **Untagged images:** Orphaned manifests and intermediate layers are cleaned
- More comprehensive cleanup with the same safety guarantees

**Result:** One step handles all cleanup, including orphaned untagged images.

## Configuration Mapping

| Feature | actions/delete-package-versions | snok/container-retention-policy |
|---------|--------------------------------|--------------------------------|
| Time-based retention | ❌ `older-than: 7` (unsupported) | ✅ `cut-off: 1w` |
| Regex filtering | ❌ `version-pattern: '^...$'` (unsupported) | ⚠️ Use `!` prefix negation syntax |
| Keep N recent | ✅ `min-versions-to-keep: 3` | ✅ `keep-n-most-recent: 3` |
| Dry-run mode | ❌ `dry-run: true` (unsupported) | ✅ `dry-run: true` |
| Tag selection | ✅ `delete-only-untagged-versions` | ✅ `tag-selection: both` (tagged + untagged) |

## Testing Strategy

1. **Initial dry-run:** The workflow is configured with `dry-run: true` by default
2. **Manual trigger:** Use `workflow_dispatch` to test without waiting for the schedule
3. **Review logs:** Check which images would be deleted before disabling dry-run
4. **Gradual rollout:**
   - Week 1: Dry-run mode, verify correct targeting
   - Week 2: Disable dry-run if behavior is correct

## Post-Deployment Validation

**Status:** Deployed to production with `dry-run: true` (2025-12-10)

### Initial Validation Results

**Test run:** https://github.com/fzymgc-house/router-hosts/actions/runs/20113283842

✅ **Workflow executed successfully**
- All parameters properly recognized
- No unexpected input warnings (unlike broken `actions/delete-package-versions`)
- Action correctly identified package and evaluated retention policy

✅ **Zero deletions (expected)**
- All current images are < 7 days old
- Only 4 images exist (within `keep-n-most-recent: 3` safety threshold)
- No protected tags (`latest`, `v0.5.0`) exist in GHCR yet

**Current images (2025-12-10):**
- `e45ffc730c592a715a9bed7c24329860fb7d641d-arm64` (< 1 day)
- `832d870f5f0f82b7193c249f0d8870f5aec0deb5-arm64` (< 1 day)
- `832d870f5f0f82b7193c249f0d8870f5aec0deb5-amd64` (< 1 day)
- `71b0bb7499152275a90096a22e87ac626d9cf144-amd64` (< 2 days)

### Why Current Behavior is Correct

The action correctly identified SHA-tagged architecture images as **deletion candidates** but kept them because:
1. All images are within the 7-day retention window (`cut-off: 1w`)
2. Total image count (4) is within safety threshold (`keep-n-most-recent: 3`)

This validates:
- ✅ Protection model works (SHA tags are unprotected, eligible for cleanup)
- ✅ Time-based filtering works (images < 7 days are kept)
- ✅ Count-based safety net works (keeps minimum N recent)

### Required Follow-Up Actions

**BEFORE disabling dry-run, complete these validations:**

1. **Wait for deletion candidates to accumulate** (1-2 weeks)
   - Need images older than 7 days for realistic testing
   - Need more than 3 images to test count-based deletion

2. **Review dry-run logs showing actual deletions**
   ```bash
   # Check next workflow run after images age
   gh run list --workflow=cleanup-images.yml --limit 1 --json databaseId --jq '.[0].databaseId' | xargs gh run view --log | grep "would delete"
   ```

   **Verify:**
   - SHA-tagged images > 7 days old are flagged for deletion
   - Protected tags (`latest`, `v0.5.0`, pre-release patterns) are NOT flagged
   - Architecture-specific tags (`-amd64`, `-arm64`) are handled correctly

3. **Monitor weekly scheduled runs**
   - First scheduled run: Sunday 2025-12-15 at 2 AM UTC
   - Review logs for 2-3 consecutive weeks
   - Confirm behavior is consistent

4. **Disable dry-run only after validation**
   ```yaml
   # Change in .github/workflows/cleanup-images.yml after validation
   dry-run: false  # ONLY after reviewing logs showing expected behavior
   ```

5. **Monitor first production deletion**
   - Verify actual deletions match dry-run predictions
   - Check GHCR package count decreases appropriately
   - Confirm no protected tags were deleted

6. **Document actual behavior**
   - Update this section with first real deletion results
   - Note any unexpected behavior or edge cases discovered

### Tracking Issue

See issue #88 for tracking post-deployment validation checklist.

## Maintenance Notes

### Adding New Protected Tags

With the simplified `!v*.*.*` pattern, **no updates are needed** for new semver releases:

```yaml
# This pattern automatically protects all semver tags
image-tags: "!latest !v*.*.* *"
```

New versions like `v0.6.0`, `v1.0.0`, `v1.0.0-rc.1` are automatically protected.

**Only update if you need to protect non-semver tags** (e.g., `!stable !edge`).

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
