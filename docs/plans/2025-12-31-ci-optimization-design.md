# CI Build Optimization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce CI build times by 20%+ through job parallelization, test deduplication, workflow consolidation, and composite action reuse.

**Issue:** [#183](https://github.com/fzymgc-house/router-hosts/issues/183) - Optimize CI build process

---

## Complete Workflow Inventory

| Workflow | Trigger | Purpose | Optimization Scope |
|----------|---------|---------|-------------------|
| `ci.yml` | push/PR to main | Build, test, coverage, Docker, E2E | **PRIMARY TARGET** |
| `pr-checks.yml` | PR to main | pre-commit (clippy, fmt) | Consolidate with ci.yml |
| `docker.yml` | push/PR/tags | Multi-arch Docker builds | Skip on PRs |
| `v-release.yml` | version tags | cargo-dist releases | No changes (managed) |
| `cleanup-images.yml` | weekly | Prune old images | No changes |
| `claude*.yml` | comments/PRs | AI assistance | No changes |

---

## Cross-Workflow Redundancy Analysis

### Problem 1: Five Docker Builds on Every PR (CRITICAL)

On a PR to main, both `ci.yml` AND `docker.yml` trigger:

| Workflow | Dockerfile | Architecture | Build Method |
|----------|------------|--------------|--------------|
| ci.yml | Dockerfile.ci | amd64 only | Pre-built binary (fast) |
| docker.yml | Dockerfile | amd64 | cargo-chef (slow) |
| docker.yml | Dockerfile | arm64 | cargo-chef (slow) |
| docker.yml | Dockerfile.duckdb | amd64 | cargo-chef (slow) |
| docker.yml | Dockerfile.duckdb | arm64 | cargo-chef (slow) |

**Impact**: 4 redundant cargo-chef builds (~10-15 min each) on every PR.
**docker.yml on PRs**: Only validates build (doesn't push), but still compiles everything.

**Solution**: Skip docker.yml on PRs - ci.yml already validates Docker builds.

### Problem 2: Duplicate Linting on PRs

Both workflows run on PRs to main:
- **pr-checks.yml**: `pre-commit` → cargo fmt, clippy, buf lint
- **ci.yml**: `task lint` → cargo fmt, clippy, buf lint

**Impact**: Same checks run twice (~2 min duplicated).

**Solution Options**:
1. Remove pr-checks.yml entirely (ci.yml covers it)
2. Make pr-checks.yml fast-feedback only (fmt check, no clippy)
3. Consolidate into single workflow

### Problem 3: Tests Run Up to Three Times

On a PR:
1. **pr-checks.yml**: `pre-commit --hook-stage pre-push` may run tests
2. **ci.yml**: `task test:postgres` (PostgreSQL tests)
3. **ci.yml**: `task test:coverage:ci` (ALL tests again)

**Impact**: Tests potentially run 3 times (~4.5 min duplicated).

---

## Optimization Strategy Summary

| Phase | Change | Expected Savings |
|-------|--------|------------------|
| 1 | Skip docker.yml on PRs | ~40-60 min aggregate runner time |
| 2 | Remove redundant test:postgres step | ~1.5-2 min |
| 3 | Parallelize ci.yml into 4 jobs | ~5-6 min |
| 4 | Consolidate pr-checks.yml | ~2 min |
| 5 | Create composite actions | ~30-60 sec + maintainability |
| 6 | Increase E2E parallelism | ~30-60 sec |

**Total expected improvement**: 40-50% faster PR feedback, significant runner cost reduction.

---

## Current State Analysis

### CI Workflow (`ci.yml`) - Current Sequential Steps

| Step | Description | Est. Time |
|------|-------------|-----------|
| 1 | Checkout + Rust + protoc + buf + Task | ~2 min |
| 2 | Cache Rust deps + nextest + llvm-cov | ~30 sec |
| 3 | `task build` (debug) | ~2 min |
| 4 | `task test:postgres` | ~1.5 min |
| 5 | `task build:release` | ~3 min |
| 6 | `task docker:build-ci` | ~1 min |
| 7 | Docker verify | ~10 sec |
| 8 | `task e2e:quick` | ~2 min |
| 9 | `task test:coverage:ci` (**runs ALL tests again**) | ~3 min |
| 10 | Upload coverage | ~10 sec |
| **Total** | | **~15 min** |

### Key Redundancies Identified

1. **Test redundancy (CRITICAL)**: Tests run TWICE:
   - `task test:postgres` - PostgreSQL backend tests
   - `task test:coverage:ci` - ALL tests including PostgreSQL (redundant!)

2. **No parallelization**: All 10 steps run sequentially in single job

3. **Duplicate setup**: `ci.yml` and `pr-checks.yml` both install Rust, protoc, buf

4. **E2E parallelism**: Uses `--test-threads=2` on 4-CPU runner

---

## Optimization Strategy

### Phase 1: Eliminate Test Redundancy (HIGH IMPACT)

**Problem**: `test:postgres` runs PostgreSQL tests, then `test:coverage:ci` runs ALL tests again including PostgreSQL.

**Solution**: Remove separate `test:postgres` step - coverage already runs all tests.

**Expected savings**: 1.5-2 minutes

### Phase 2: Parallelize Jobs (HIGH IMPACT)

**Current**: Single monolithic `build` job
**Proposed**: Three parallel jobs

```
                    ┌─────────┐
                    │  lint   │ (~1.5 min) - fast feedback
                    └────┬────┘
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
    ┌───────────────┐           ┌─────────────┐
    │ test-coverage │           │    build    │ (~4 min)
    │   (~4 min)    │           └──────┬──────┘
    └───────────────┘                  │
                                       ▼
                               ┌───────────────┐
                               │     e2e       │ (~3 min)
                               └───────────────┘
```

**Critical path**: lint → build → e2e = ~8.5 min (was ~15 min)
**Expected savings**: 5-6 minutes (40%+)

### Phase 3: Create Composite Actions (MEDIUM IMPACT)

Extract common setup into reusable actions:
- `.github/actions/rust-setup/action.yml` - Rust + protoc + buf + cache
- `.github/actions/ci-tools/action.yml` - nextest + llvm-cov + Task

**Expected savings**: 30-60 seconds + maintainability improvement

### Phase 4: Increase E2E Parallelism (LOW IMPACT)

Change `--test-threads=2` to `--test-threads=4` on 4-CPU runner.

**Expected savings**: 30-60 seconds

---

## Task 1: Create Composite Action for Rust Setup

**Files:**
- Create: `.github/actions/rust-setup/action.yml`

**Step 1: Create the composite action**

```yaml
name: 'Rust Development Setup'
description: 'Install Rust toolchain, protoc, buf, and configure caching'

inputs:
  cache-targets:
    description: 'Whether to cache target directory'
    required: false
    default: 'false'
  save-cache:
    description: 'Whether to save cache (only on main branch)'
    required: false
    default: 'false'

runs:
  using: 'composite'
  steps:
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      shell: bash

    - name: Install protoc
      run: |
        sudo apt-get update
        sudo apt-get install -y protobuf-compiler
        echo "PROTOC=$(which protoc)" >> "$GITHUB_ENV"
      shell: bash
      env:
        DEBIAN_FRONTEND: noninteractive

    - name: Install buf
      uses: bufbuild/buf-setup-action@v1
      with:
        github_token: ${{ github.token }}

    - name: Cache Rust dependencies
      uses: Swatinem/rust-cache@v2
      with:
        cache-targets: ${{ inputs.cache-targets }}
        save-if: ${{ inputs.save-cache }}
        key: ${{ runner.os }}-cargo
```

---

## Task 2: Create Composite Action for CI Tools

**Files:**
- Create: `.github/actions/ci-tools/action.yml`

**Step 1: Create the composite action**

```yaml
name: 'CI Tools Setup'
description: 'Install Task, cargo-nextest, and cargo-llvm-cov'

runs:
  using: 'composite'
  steps:
    - name: Install Task
      uses: arduino/setup-task@v2

    - name: Install cargo-nextest
      uses: taiki-e/install-action@v2
      with:
        tool: cargo-nextest

    - name: Install cargo-llvm-cov
      uses: taiki-e/install-action@v2
      with:
        tool: cargo-llvm-cov
```

---

## Task 3: Refactor CI Workflow with Parallel Jobs

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Replace monolithic workflow with parallel jobs**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  # ─────────────────────────────────────────────────────────────
  # Job 1: Lint - Fast feedback on code quality
  # ─────────────────────────────────────────────────────────────
  lint:
    runs-on:
      - runs-on=${{ github.run_id }}/runner=2cpu-linux-x64/image=ubuntu24-full-x64/extras=s3-cache/spot=lowest-price

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Setup Rust environment
        uses: ./.github/actions/rust-setup

      - name: Install Task
        uses: arduino/setup-task@v2

      - name: Run linters
        run: task lint

  # ─────────────────────────────────────────────────────────────
  # Job 2: Build - Create release binary for E2E tests
  # ─────────────────────────────────────────────────────────────
  build:
    runs-on:
      - runs-on=${{ github.run_id }}/runner=4cpu-linux-x64/image=ubuntu24-full-x64/extras=s3-cache+docker/spot=lowest-price/volume=150gb:600mbs:4000iops

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Setup Rust environment
        uses: ./.github/actions/rust-setup
        with:
          save-cache: ${{ github.ref == 'refs/heads/main' }}

      - name: Install Task
        uses: arduino/setup-task@v2

      - name: Build release binary
        run: task build:release

      - name: Upload release binary
        uses: actions/upload-artifact@v6
        with:
          name: release-binary
          path: target/release/router-hosts
          retention-days: 1

  # ─────────────────────────────────────────────────────────────
  # Job 3: Test with Coverage - Run all tests with coverage
  # ─────────────────────────────────────────────────────────────
  test-coverage:
    needs: [lint]  # Fast-fail on lint errors
    runs-on:
      - runs-on=${{ github.run_id }}/runner=4cpu-linux-x64/image=ubuntu24-full-x64/extras=s3-cache+docker/spot=lowest-price/volume=150gb:600mbs:4000iops

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Setup Rust environment
        uses: ./.github/actions/rust-setup

      - name: Setup CI tools
        uses: ./.github/actions/ci-tools

      - name: Check test coverage (≥80% required)
        run: task test:coverage:ci

      - name: Upload coverage report
        uses: actions/upload-artifact@v6
        if: always()
        with:
          name: coverage-report
          path: coverage/
          retention-days: 14

  # ─────────────────────────────────────────────────────────────
  # Job 4: E2E Tests - Requires release binary
  # ─────────────────────────────────────────────────────────────
  e2e:
    needs: [build]
    runs-on:
      - runs-on=${{ github.run_id }}/runner=4cpu-linux-x64/image=ubuntu24-full-x64/extras=s3-cache+docker/spot=lowest-price/volume=150gb:600mbs:4000iops

    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io

      - uses: actions/checkout@v6

      - name: Setup Rust environment
        uses: ./.github/actions/rust-setup

      - name: Install Task
        uses: arduino/setup-task@v2

      - name: Download release binary
        uses: actions/download-artifact@v6
        with:
          name: release-binary
          path: target/release/

      - name: Make binary executable
        run: chmod +x target/release/router-hosts

      - name: Build CI Docker image
        run: task docker:build-ci IMAGE_NAME=router-hosts IMAGE_TAG=ci

      - name: Verify Docker image runs
        run: |
          echo "Testing binary inside container..."
          docker run --rm router-hosts:ci --help
          docker run --rm router-hosts:ci server --help
          echo "Binary runs successfully"

      - name: Run E2E tests
        run: task e2e:quick IMAGE_NAME=router-hosts IMAGE_TAG=ci
```

**Key changes:**
1. Split into 4 parallel jobs: `lint`, `build`, `test-coverage`, `e2e`
2. Removed redundant `task test:postgres` (coverage runs all tests)
3. Use composite actions for setup
4. Use 2-CPU runner for lint (faster startup, cheaper)
5. Artifact upload/download for release binary between jobs

---

## Task 4: Increase E2E Test Parallelism

**Files:**
- Modify: `Taskfile.yml`

**Step 1: Update e2e task to use 4 threads**

Change `--test-threads=2` to `--test-threads=4` in both `e2e` and `e2e:quick` tasks:

```yaml
e2e:
  desc: Run E2E acceptance tests
  deps: ["docker:build", "build:release"]
  env:
    ROUTER_HOSTS_IMAGE: '{{.LOCAL_IMAGE}}'
    ROUTER_HOSTS_BINARY: '{{.USER_WORKING_DIR}}/target/release/router-hosts'
  cmds:
    - cargo test -p router-hosts-e2e --release -- --test-threads=4

e2e:quick:
  desc: Run E2E tests (skip rebuild, assumes image exists)
  env:
    ROUTER_HOSTS_IMAGE: '{{.LOCAL_IMAGE}}'
    ROUTER_HOSTS_BINARY: '{{.USER_WORKING_DIR}}/target/release/router-hosts'
  cmds:
    - cargo test -p router-hosts-e2e --release -- --test-threads=4
```

---

## Task 5: Update PR Checks Workflow to Use Composite Action

**Files:**
- Modify: `.github/workflows/pr-checks.yml`

**Step 1: Refactor to use composite action**

```yaml
name: PR Checks

on:
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always

jobs:
  lint:
    runs-on:
      - runs-on=${{ github.run_id }}/runner=4cpu-linux-x64/image=ubuntu24-full-x64/extras=s3-cache/spot=lowest-price/volume=150gb:600mbs:4000iops
    steps:
      - uses: runs-on/action@v2
        with:
          metrics: cpu,network,memory,disk,io
      - uses: actions/checkout@v6

      - name: Setup Rust environment
        uses: ./.github/actions/rust-setup

      - name: Install pre-commit
        run: pip install pre-commit

      - name: Run pre-commit (all hooks)
        run: |
          # Run commit-stage hooks first
          pre-commit run --all-files
          # Run push-stage hooks (clippy, tests) separately to avoid cache skipping
          pre-commit run --all-files --hook-stage pre-push
```

---

## Expected Results

### Before Optimization

| Metric | Value |
|--------|-------|
| Total CI time | ~15 minutes |
| Critical path | Sequential (all steps) |
| Jobs | 1 (monolithic) |
| Test runs | 2 (postgres + coverage) |

### After Optimization

| Metric | Value |
|--------|-------|
| Total CI time | ~8-9 minutes |
| Critical path | lint → build → e2e |
| Jobs | 4 (parallel) |
| Test runs | 1 (coverage only) |

### Improvement

- **Time savings**: 6-7 minutes (40-45%)
- **Fast feedback**: Lint errors detected in ~1.5 min vs ~15 min
- **Maintainability**: Composite actions reduce duplication

---

## Rollback Plan

If issues arise:
1. Revert `ci.yml` to previous version from `main`
2. Delete `.github/actions/` directory
3. Revert `Taskfile.yml` e2e thread count change

All changes are additive and backwards-compatible.

---

## Commit Strategy

```
feat(ci): add composite actions for rust and ci-tools setup

Extracts common setup steps into reusable composite actions:
- .github/actions/rust-setup: Rust, protoc, buf, caching
- .github/actions/ci-tools: Task, nextest, llvm-cov

Part of #183
```

```
feat(ci): parallelize CI workflow into separate jobs

Splits monolithic build job into 4 parallel jobs:
- lint: Fast code quality feedback (2-CPU runner)
- build: Release binary for E2E tests
- test-coverage: All tests with 80% threshold
- e2e: End-to-end tests using release binary

Removes redundant test:postgres step (coverage runs all tests).

Closes #183
```

```
perf(ci): increase E2E test parallelism to 4 threads

Uses all 4 CPUs on the runner for E2E tests instead of 2.

Part of #183
```

---

## Task 6: Skip Docker Workflow on PRs

**Files:**
- Modify: `.github/workflows/docker.yml`

**Rationale**: On PRs, docker.yml builds 4 Docker images using cargo-chef (slow, ~10-15 min each) just to validate Dockerfile syntax. ci.yml already builds and validates `Dockerfile.ci` with a pre-built binary, providing sufficient PR validation.

**Step 1: Remove pull_request trigger from docker.yml**

Change:
```yaml
on:
  push:
    branches: [main]
    tags: ['v*']
  pull_request:
    branches: [main]
```

To:
```yaml
on:
  push:
    branches: [main]
    tags: ['v*']
  # Note: PR builds removed - ci.yml validates Docker builds via Dockerfile.ci
  # Multi-arch builds only needed on merge to main or release tags
```

**Expected savings**: ~40-60 min aggregate runner time per PR (4 cargo-chef builds eliminated).

---

## Task 7: Consolidate PR Checks into CI Workflow

**Files:**
- Modify: `.github/workflows/pr-checks.yml`

**Option A: Remove pr-checks.yml entirely** (Recommended)

The parallelized ci.yml now has a dedicated `lint` job that provides fast feedback (~1.5 min). pre-commit hooks are better run locally, not in CI.

**Step 1: Delete pr-checks.yml**

```bash
git rm .github/workflows/pr-checks.yml
```

**Option B: Convert to fast-feedback-only workflow**

If pre-commit enforcement is required, keep only the fastest checks:

```yaml
name: PR Quick Checks

on:
  pull_request:
    branches: [main]

jobs:
  format-check:
    runs-on:
      - runs-on=${{ github.run_id }}/runner=2cpu-linux-x64/image=ubuntu24-full-x64/extras=s3-cache/spot=lowest-price
    steps:
      - uses: runs-on/action@v2
      - uses: actions/checkout@v6

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Check Rust formatting
        run: cargo fmt --check

      - name: Install buf
        uses: bufbuild/buf-setup-action@v1
        with:
          github_token: ${{ github.token }}

      - name: Check protobuf formatting
        run: buf format --diff --exit-code
```

This provides ~30-second feedback on formatting issues only. Clippy and tests run in ci.yml.

---

## Updated Workflow Dependency Diagram

### Before Optimization (PR to main)

```
┌─────────────────────────────────────────────────────────────────────┐
│ pr-checks.yml                                                       │
│ └─ lint (pre-commit: fmt + clippy + tests)              ~3-5 min   │
└─────────────────────────────────────────────────────────────────────┘
                              ↓ (parallel)
┌─────────────────────────────────────────────────────────────────────┐
│ ci.yml                                                              │
│ └─ build (sequential: build → test:postgres → build:release →      │
│           docker:build-ci → e2e → test:coverage)        ~15 min    │
└─────────────────────────────────────────────────────────────────────┘
                              ↓ (parallel)
┌─────────────────────────────────────────────────────────────────────┐
│ docker.yml                                                          │
│ ├─ build-amd64 (standard + duckdb)                      ~20-30 min │
│ ├─ build-arm64 (standard + duckdb)                      ~20-30 min │
│ └─ (manifest skipped on PRs)                                        │
└─────────────────────────────────────────────────────────────────────┘

Total runner time: ~60-80 min across all workflows
```

### After Optimization (PR to main)

```
┌─────────────────────────────────────────────────────────────────────┐
│ ci.yml (parallelized)                                               │
│                                                                     │
│   ┌─────────┐                                                       │
│   │  lint   │ (~1.5 min) ← Fast feedback                           │
│   └────┬────┘                                                       │
│        │                                                            │
│   ┌────┴────────────────┐                                          │
│   ▼                     ▼                                          │
│ ┌───────────────┐  ┌─────────┐                                     │
│ │ test-coverage │  │  build  │                                     │
│ │   (~4 min)    │  │ (~4 min)│                                     │
│ └───────────────┘  └────┬────┘                                     │
│                         ▼                                          │
│                    ┌─────────┐                                     │
│                    │   e2e   │ (~3 min)                            │
│                    └─────────┘                                     │
│                                                                     │
│ Critical path: lint → build → e2e = ~8.5 min                       │
└─────────────────────────────────────────────────────────────────────┘

docker.yml: SKIPPED on PRs (only runs on push to main/tags)
pr-checks.yml: REMOVED (consolidated into ci.yml lint job)

Total runner time: ~12-15 min (single workflow, parallel jobs)
Improvement: 75-80% reduction in aggregate runner time
```

---

## Final Expected Results

### PR Workflow Comparison

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Time to first feedback | ~3-5 min | ~1.5 min | 50-70% faster |
| Total CI completion | ~15 min | ~8.5 min | 43% faster |
| Aggregate runner time | ~60-80 min | ~15 min | 75-80% reduction |
| Number of Docker builds | 5 | 1 | 80% reduction |
| Number of test runs | 2-3 | 1 | 50-67% reduction |

### Push to Main Comparison

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| ci.yml | ~15 min | ~8.5 min | 43% faster |
| docker.yml | ~20-30 min | ~20-30 min | No change (needed for multi-arch) |

---

## v-release.yml Analysis

**No changes recommended.** This workflow is managed by cargo-dist and triggers only on version tags. It has proper job dependencies and artifact caching already:

```
plan → build-local-artifacts → build-global-artifacts → host → publish-homebrew-formula → announce
```

The workflow uses cargo-dist's own caching and is well-optimized for release builds.

---

## cleanup-images.yml Analysis

**No changes recommended.** This is a weekly scheduled job that cleans up old container images. It runs on `ubuntu-latest` (not custom runners) and completes in under 1 minute.

Current settings:
- Runs weekly (Sunday 2 AM UTC)
- Keeps images from past 7 days
- Keeps 3 most recent images
- Protects `latest` and `v*.*.*` tags
- Currently in `dry-run: true` mode (needs to be enabled for production)

**Note**: Consider enabling `dry-run: false` when ready to actually clean up images.
