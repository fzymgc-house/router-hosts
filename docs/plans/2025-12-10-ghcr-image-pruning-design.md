# GHCR Image Pruning Design

**Date:** 2025-12-10
**Status:** Corrective implementation (replaced actions/delete-package-versions with snok/container-retention-policy)
**Related:** Issue #73
**Corrective PR:** TBD

## Overview

Implement automatic cleanup of old Docker images in GitHub Container Registry (GHCR) to prevent storage bloat while preserving images needed for deployment.

## Corrective Action (2025-12-10)

**Problem Discovered:** Post-merge dry-run testing revealed that `actions/delete-package-versions@v5` **does NOT support** critical parameters used in the original design:
- ❌ `older-than`: Silently ignored (time-based retention broken)
- ❌ `version-pattern`: Silently ignored (SHA tag filtering broken)
- ❌ `dry-run`: Silently ignored (no safe testing mode)

**Impact:** The workflow was completely ineffective and potentially dangerous without dry-run protection.

**Resolution:** Replaced `actions/delete-package-versions` with `snok/container-retention-policy@v3.0.1` which:
- ✅ Supports time-based retention via `cut-off: 1w`
- ✅ Supports dry-run mode
- ✅ Active maintenance and responsive issue resolution
- ⚠️ Requires workaround for regex filtering (use inverted `image-tags` protection model)

**Alternative Rejected:** `dataaxiom/ghcr-cleanup-action` was evaluated but rejected due to critical bugs in core features (issues #99, #101) and signs of project abandonment.

**Documentation:** See `docs/workarounds/ghcr-cleanup.md` for detailed workaround explanations.

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

### Permissions

```yaml
permissions:
  packages: write  # Required to delete package versions
  contents: read   # Standard read access
```

Uses `GITHUB_TOKEN` for authentication. No additional secrets required.

### Cleanup Step (Corrected Implementation)

**Single step** using `snok/container-retention-policy@v3.0.1`:

```yaml
- name: Clean up old container images
  uses: snok/container-retention-policy@v3.0.1
  with:
    account: fzymgc-house
    token: ${{ secrets.GITHUB_TOKEN }}
    image-names: router-hosts
    cut-off: 1w
    keep-n-most-recent: 3
    tag-selection: tagged
    image-tags: |
      latest
      v0.5.0
      v*.*.*-alpha.*
      v*.*.*-beta.*
      v*.*.*-rc.*
    dry-run: true
```

**Key difference from original design:** One step replaces three. The inverted protection model (explicit tag protection via `image-tags`) automatically handles manifest and architecture tags without separate steps.

### Configuration Parameters

**`cut-off: 1w`** (replaces `older-than: 7`)
- Time-based retention: 1 week
- Aligns with weekly cleanup schedule
- More predictable than count-based retention alone

**`keep-n-most-recent: 3`** (replaces `min-versions-to-keep: 3`)
- Safety net: preserves 3 most recent versions even if older than 1 week
- Prevents complete deletion if no recent builds exist
- Applied globally (not per tag type)

**`tag-selection: tagged`** (replaces `delete-only-untagged-versions: false`)
- Targets only tagged images for cleanup
- Excludes untagged images from consideration
- SHA-tagged dev images (e.g., `abc123def456`) are "tagged" and eligible

**`image-tags`** (replaces `ignore-versions` regex)
- **Inverted model:** Lists tags to PROTECT, not patterns to match
- Protected tags are excluded from cleanup consideration
- Supports glob-style wildcards for pattern matching:
  - `v*.*.*-alpha.*` matches pre-release alpha tags
  - `v*.*.*-beta.*` matches pre-release beta tags
  - `v*.*.*-rc.*` matches release candidate tags
- Unprotected tags (SHA-based dev images) cleaned based on `cut-off`

**`dry-run: true`**
- **CRITICAL FEATURE:** Actually supported (unlike original action)
- Safe testing mode logs what WOULD be deleted without deleting
- Required for validation before disabling

### Workarounds Required

**No regex pattern matching:**
- Cannot use `version-pattern: '^[0-9a-f]{40}$'` to SELECT which images to delete
- Workaround: Use `image-tags` to explicitly protect production tags
- Consequence: Must maintain explicit protection list for releases

**Build metadata tags not protected:**
- Pattern `v*.*.*+*` doesn't work in glob syntax
- Tags like `v1.0.0+build.123` are NOT protected
- Mitigation: Use pre-release syntax instead: `v1.0.0-build.123`

See `docs/workarounds/ghcr-cleanup.md` for detailed explanations.

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

- [x] Create `.github/workflows/cleanup-images.yml`
- [x] Replace broken action with snok/container-retention-policy
- [x] Configure inverted protection model via image-tags
- [x] Set weekly cron schedule (Sunday 2 AM UTC)
- [x] Enable `workflow_dispatch` for manual testing
- [x] Test with `dry-run: true` enabled
- [ ] **CRITICAL:** Review dry-run logs for correctness (DO NOT SKIP)
- [ ] Disable dry-run and merge to main
- [ ] Monitor first production run
- [ ] Verify storage usage decreases over time
- [ ] Update issue #73 with results

## Alternative Approaches Considered

### GitHub Actions Evaluated

**actions/delete-package-versions@v5 (BROKEN - original choice):**
- ❌ `older-than`, `version-pattern`, `dry-run` parameters NOT supported
- ❌ Parameters silently ignored without warnings
- ❌ No time-based retention capability
- ✅ Official GitHub action
- **Verdict:** Completely ineffective for our requirements

**snok/container-retention-policy@v3.0.1 (SELECTED):**
- ✅ Time-based retention via `cut-off`
- ✅ Dry-run mode for safe testing
- ✅ Active maintenance (235 stars, recent commits)
- ✅ Issues get resolved promptly
- ⚠️ No regex pattern matching (workaround via `image-tags`)
- **Verdict:** Best available option with manageable trade-offs

**dataaxiom/ghcr-cleanup-action (REJECTED):**
- ✅ Feature-rich (has `older-than`, `keep-n-tagged`, extensive options)
- ❌ Critical bugs in core features:
  - Issue #99: `older-than + keep-n-tagged` deletes wrong images (3 months unresolved)
  - Issue #101: Multi-tagged images unconditionally deleted (2 months no response)
- ❌ Signs of abandonment (last commit 3.5 months ago, last release 11 months ago)
- **Verdict:** Too risky despite feature completeness

### Implementation Patterns Evaluated

**Count-based retention (rejected):**
- Keep last N builds instead of time-based
- More complex: "last N per branch" vs "last N total"
- Less predictable with varying commit frequency
- Time-based retention simpler and clearer

**Multi-step cleanup (original design, now obsolete):**
- Three separate steps for manifest, amd64, arm64
- More explicit but more verbose
- Required when using pattern matching per tag type
- Single-step approach (snok) simpler and equally effective

**Custom script (rejected):**
- Write bash/Python script using `gh api`
- More control but more code to maintain
- Third-party actions provide safety features built-in
- Maintenance burden not justified

## References

### GitHub Actions
- [snok/container-retention-policy](https://github.com/snok/container-retention-policy) - **Current implementation**
- [actions/delete-package-versions](https://github.com/actions/delete-package-versions) - Original choice (broken)
- [dataaxiom/ghcr-cleanup-action](https://github.com/dataaxiom/ghcr-cleanup-action) - Evaluated and rejected

### Project Documentation
- Workaround documentation: `docs/workarounds/ghcr-cleanup.md`
- Current Docker workflow: `.github/workflows/docker.yml`
- Cleanup workflow: `.github/workflows/cleanup-images.yml`

### GitHub APIs
- [GitHub Packages API](https://docs.github.com/en/rest/packages)

### Related Issues
- [dataaxiom #99](https://github.com/dataaxiom/ghcr-cleanup-action/issues/99) - Broken `older-than + keep-n-tagged`
- [dataaxiom #101](https://github.com/dataaxiom/ghcr-cleanup-action/issues/101) - Multi-tagged images bug
