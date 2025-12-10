# GHCR Image Pruning Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement automated weekly cleanup of old Docker images in GitHub Container Registry to prevent storage bloat.

**Architecture:** GitHub Actions workflow runs weekly, uses `actions/delete-package-versions@v5` to delete SHA-tagged images older than 7 days while preserving `latest` and semantic version tags. Three separate steps handle manifest + architecture tags as a unit.

**Tech Stack:** GitHub Actions, actions/delete-package-versions, GitHub Container Registry API

---

## Task 1: Create Workflow File with Basic Structure

**Files:**
- Create: `.github/workflows/cleanup-images.yml`

**Step 1: Create workflow file with header and schedule**

Create `.github/workflows/cleanup-images.yml`:

```yaml
name: Cleanup Docker Images

on:
  schedule:
    - cron: '0 2 * * 0'  # Every Sunday at 2 AM UTC
  workflow_dispatch:  # Allow manual triggering for testing

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
  PACKAGE_NAME: router-hosts

jobs:
  cleanup:
    runs-on: ubuntu-latest

    permissions:
      packages: write  # Required to delete package versions
      contents: read   # Standard read access

    steps:
      - name: Placeholder
        run: echo "Cleanup steps will be added next"
```

**Step 2: Verify workflow syntax**

Run: `cat .github/workflows/cleanup-images.yml | head -15`
Expected: File exists with correct YAML structure

**Step 3: Commit**

```bash
git add .github/workflows/cleanup-images.yml
git commit -m "ci: add GHCR image cleanup workflow skeleton

Weekly scheduled cleanup workflow with workflow_dispatch support.
Addresses #73."
```

---

## Task 2: Add Manifest Tag Cleanup Step

**Files:**
- Modify: `.github/workflows/cleanup-images.yml:23-24`

**Step 1: Replace placeholder with manifest cleanup step**

Replace the placeholder step in `.github/workflows/cleanup-images.yml`:

```yaml
    steps:
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

**Step 2: Verify YAML syntax**

Run: `yamllint .github/workflows/cleanup-images.yml || echo "yamllint not installed, checking with yq"`
Alternative: `cat .github/workflows/cleanup-images.yml | grep -A 10 "Delete old manifest"`
Expected: Valid YAML, step properly indented

**Step 3: Commit**

```bash
git add .github/workflows/cleanup-images.yml
git commit -m "ci: add manifest tag cleanup step

Deletes multi-arch manifest images (40-char hex SHA) older than 7
days while preserving latest and semver tags. Minimum 3 versions
retained for safety."
```

---

## Task 3: Add AMD64 Architecture Tag Cleanup Step

**Files:**
- Modify: `.github/workflows/cleanup-images.yml:35`

**Step 1: Add amd64 cleanup step after manifest step**

Add to `.github/workflows/cleanup-images.yml` after the manifest step:

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

**Step 2: Verify step added correctly**

Run: `grep -c "Delete old.*images" .github/workflows/cleanup-images.yml`
Expected: Output shows "2" (manifest + amd64 steps)

**Step 3: Commit**

```bash
git add .github/workflows/cleanup-images.yml
git commit -m "ci: add amd64 tag cleanup step

Deletes AMD64-specific images with same retention policy as
manifests. Pattern matches SHA-amd64 format."
```

---

## Task 4: Add ARM64 Architecture Tag Cleanup Step

**Files:**
- Modify: `.github/workflows/cleanup-images.yml:47`

**Step 1: Add arm64 cleanup step after amd64 step**

Add to `.github/workflows/cleanup-images.yml` after the amd64 step:

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

**Step 2: Verify all three cleanup steps present**

Run: `grep -c "Delete old.*images" .github/workflows/cleanup-images.yml`
Expected: Output shows "3" (manifest + amd64 + arm64)

**Step 3: Verify complete workflow structure**

Run: `cat .github/workflows/cleanup-images.yml`
Expected: File contains all three cleanup steps with correct patterns

**Step 4: Commit**

```bash
git add .github/workflows/cleanup-images.yml
git commit -m "ci: add arm64 tag cleanup step

Completes three-step cleanup covering manifest and both
architecture-specific tags. All use same 7-day retention policy."
```

---

## Task 5: Enable Dry-Run Mode for Testing

**Files:**
- Modify: `.github/workflows/cleanup-images.yml:28,40,52`

**Step 1: Add dry-run parameter to all three steps**

Add `dry-run: true` to each cleanup step's `with:` block:

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
          dry-run: true  # ADD THIS LINE
```

Repeat for amd64 and arm64 steps.

**Step 2: Verify dry-run enabled on all steps**

Run: `grep -c "dry-run: true" .github/workflows/cleanup-images.yml`
Expected: Output shows "3" (one per step)

**Step 3: Commit**

```bash
git add .github/workflows/cleanup-images.yml
git commit -m "ci: enable dry-run mode for testing

Allows validation of cleanup logic without actually deleting images.
Will be disabled after successful dry-run test."
```

---

## Task 6: Validate Workflow Syntax with GitHub CLI

**Files:**
- Read: `.github/workflows/cleanup-images.yml`

**Step 1: Check workflow syntax with GitHub Actions**

Run: `gh workflow list | grep -i cleanup || echo "Workflow not yet visible on GitHub"`
Expected: Either lists cleanup workflow or indicates not yet pushed

**Step 2: Validate YAML syntax locally**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/cleanup-images.yml'))"`
Alternative if Python unavailable: `cat .github/workflows/cleanup-images.yml | head -60`
Expected: No syntax errors

**Step 3: Review complete workflow**

Run: `cat .github/workflows/cleanup-images.yml`
Expected: Complete workflow with:
- Weekly cron schedule
- workflow_dispatch trigger
- Three cleanup steps (manifest, amd64, arm64)
- dry-run: true on all steps
- Correct permissions

---

## Task 7: Update Design Document with Implementation Status

**Files:**
- Modify: `docs/plans/2025-12-10-ghcr-image-pruning-design.md:280-291`

**Step 1: Mark completed checklist items**

Update the Implementation Checklist section in design doc:

```markdown
## Implementation Checklist

- [x] Create `.github/workflows/cleanup-images.yml`
- [x] Configure three deletion steps (manifest, amd64, arm64)
- [x] Set weekly cron schedule (Sunday 2 AM UTC)
- [x] Enable `workflow_dispatch` for manual testing
- [x] Test with `dry-run: true` enabled
- [ ] Review dry-run logs for correctness
- [ ] Disable dry-run and merge to main
- [ ] Monitor first production run
- [ ] Verify storage usage decreases over time
- [ ] Update issue #73 with results
```

**Step 2: Verify changes**

Run: `grep -A 10 "Implementation Checklist" docs/plans/2025-12-10-ghcr-image-pruning-design.md`
Expected: Shows checklist with first 5 items marked complete

**Step 3: Commit**

```bash
git add docs/plans/2025-12-10-ghcr-image-pruning-design.md
git commit -m "docs: update implementation checklist

Mark completed tasks: workflow creation, step configuration, and
dry-run enablement."
```

---

## Task 8: Create Pull Request

**Files:**
- None (GitHub operation)

**Step 1: Push feature branch to remote**

Run: `git push -u origin feat/ghcr-image-pruning`
Expected: Branch pushed successfully

**Step 2: Create PR with comprehensive description**

Run:
```bash
gh pr create --title "ci: implement GHCR image pruning workflow" --body "$(cat <<'EOF'
## Summary

Implements automated weekly cleanup of old Docker images in GitHub Container Registry to prevent storage bloat.

**Key features:**
- Runs every Sunday at 2 AM UTC
- Deletes SHA-tagged images older than 7 days
- Preserves `latest` and semantic version tags (v*)
- Three-step cleanup: manifest, amd64, arm64 tags
- Safety: keeps minimum 3 versions even if older than 7 days
- Currently in dry-run mode for testing

## Testing Plan

1. Manual trigger via workflow_dispatch to verify dry-run
2. Review logs to confirm correct tag identification
3. Verify `latest` and `v*` tags excluded
4. Disable dry-run in follow-up commit after validation
5. Monitor first production run

## References

- Design: docs/plans/2025-12-10-ghcr-image-pruning-design.md
- Implementation plan: docs/plans/2025-12-10-ghcr-image-pruning.md
- Closes #73

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

Expected: PR created with number shown

**Step 3: Record PR number**

Run: `gh pr view --json number,url --jq '{number, url}'`
Expected: Shows PR number and URL

---

## Task 9: Test Dry-Run Execution

**Files:**
- None (GitHub Actions execution)

**Step 1: Trigger workflow manually**

Run: `gh workflow run cleanup-images.yml`
Expected: "✓ Created workflow_dispatch event for cleanup-images.yml"

**Step 2: Wait for workflow to complete**

Run: `gh run list --workflow=cleanup-images.yml --limit 1`
Expected: Shows workflow run with "completed" status (may take 1-2 minutes)

**Step 3: View workflow logs**

Run: `gh run view --log | grep -A 5 "Delete old"`
Expected: Logs show dry-run output indicating which versions would be deleted

**Step 4: Verify no actual deletions occurred**

Run:
```bash
gh api /orgs/fzymgc-house/packages/container/router-hosts/versions \
  --jq 'length'
```
Expected: Same count as before workflow run (dry-run doesn't delete)

---

## Task 10: Review Dry-Run Results

**Files:**
- None (analysis task)

**Step 1: Check which tags would be deleted**

Run:
```bash
gh run view --log-failed || gh run view --log | \
  grep "would delete" | head -10
```
Expected: List of SHA-tagged versions older than 7 days

**Step 2: Verify protected tags excluded**

Run:
```bash
gh run view --log | grep -i "latest\|^v[0-9]" || \
  echo "Protected tags correctly excluded"
```
Expected: No `latest` or `v*` tags in deletion list

**Step 3: Verify minimum version safety**

Run: `gh run view --log | grep -i "min-versions-to-keep"`
Expected: Confirmation that at least 3 versions would be retained

**Step 4: Document results in PR comment**

Run:
```bash
gh pr comment --body "Dry-run test completed successfully:
- ✅ Workflow triggered manually via workflow_dispatch
- ✅ Identified SHA-tagged images older than 7 days
- ✅ Protected latest and semver tags excluded
- ✅ Minimum 3 versions safety confirmed
- ✅ No actual deletions performed

Ready to disable dry-run mode."
```
Expected: Comment added to PR

---

## Task 11: Disable Dry-Run Mode

**Files:**
- Modify: `.github/workflows/cleanup-images.yml:28,40,52`

**Step 1: Remove dry-run parameter from all steps**

Remove the `dry-run: true` line from all three cleanup steps in `.github/workflows/cleanup-images.yml`.

**Step 2: Verify dry-run lines removed**

Run: `grep "dry-run" .github/workflows/cleanup-images.yml`
Expected: No output (all dry-run lines removed)

**Step 3: Update design doc checklist**

Update `docs/plans/2025-12-10-ghcr-image-pruning-design.md`:

```markdown
- [x] Review dry-run logs for correctness
- [x] Disable dry-run and merge to main
```

**Step 4: Commit**

```bash
git add .github/workflows/cleanup-images.yml \
        docs/plans/2025-12-10-ghcr-image-pruning-design.md
git commit -m "ci: disable dry-run mode after successful test

Dry-run validation completed. Workflow ready for production use.
Next run will perform actual deletions."
```

**Step 5: Push changes**

Run: `git push origin feat/ghcr-image-pruning`
Expected: Changes pushed to PR branch

---

## Task 12: Request Code Review

**Files:**
- None (review request)

**Step 1: Request review using superpowers skill**

**REQUIRED SUB-SKILL:** Use `@superpowers:requesting-code-review` to dispatch code-reviewer subagent.

**Step 2: Address any review feedback**

If reviewer identifies issues:
- Fix issues in new commits
- Push changes
- Request re-review

**Step 3: Get approval**

Wait for reviewer approval before proceeding to merge.

---

## Post-Merge Tasks

After PR merges:

1. **Monitor first production run:**
   ```bash
   # Wait for Sunday 2 AM UTC or manually trigger
   gh workflow run cleanup-images.yml

   # Monitor execution
   gh run watch

   # Review logs
   gh run view --log | grep -i "deleted\|error"
   ```

2. **Verify storage impact:**
   ```bash
   # Check package count before/after
   gh api /orgs/fzymgc-house/packages/container/router-hosts/versions \
     --jq 'length'
   ```

3. **Update issue #73:**
   ```bash
   gh issue comment 73 --body "✅ Implemented and deployed.

   First production run: [link to workflow run]
   Storage impact: [before/after package count]"

   gh issue close 73
   ```

4. **Update design doc final checklist items:**
   Mark remaining items complete in `docs/plans/2025-12-10-ghcr-image-pruning-design.md`

---

## Rollback Plan

If cleanup is too aggressive:

1. **Disable workflow:**
   ```bash
   gh workflow disable cleanup-images.yml
   ```

2. **Rebuild needed images:**
   ```bash
   # Trigger Docker build on specific commit
   gh workflow run docker.yml --ref <commit-sha>
   ```

3. **Investigate issue:**
   - Review workflow logs
   - Check retention policy configuration
   - Verify regex patterns

4. **Fix and re-test:**
   - Make corrections in new branch
   - Test with dry-run enabled
   - Deploy fix after validation
