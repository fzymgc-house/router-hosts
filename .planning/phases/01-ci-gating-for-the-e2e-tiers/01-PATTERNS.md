# Phase 1: CI Gating for the e2e Tiers - Pattern Map

**Mapped:** 2026-08-02
**Files analyzed:** 8 (2 created, 6 modified)
**Analogs found:** 8 / 8 (one caveat: no in-repo precedent for asserting `t.Fatalf`/fake-`testing.TB` behavior — see "No Analog Found")

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|-----------------|----------------|
| `internal/testutil/wait/wait.go` | utility | event-driven (polling) | `internal/storage/storagetest/suite.go` | exact (package shape: non-`_test.go`, untagged, imports `testing`) |
| `internal/testutil/wait/wait_test.go` | test | request-response (unit test) | none for the `t.Fatalf`-timeout-path assertion; `internal/storage/sqlite/compliance_test.go` for the general "call an exported testutil function from `_test.go`" shape | partial |
| `.github/workflows/ci-go.yml` (3 new jobs: `e2e-fast`, `e2e-docker`, `e2e-proc`) | config | batch (CI job) | `test` job (`ci-go.yml:39-62`) | exact (job skeleton) |
| `.github/workflows/ci-go.yml` (`ci-go-complete` extension) | config | event-driven (aggregation) | `ci-go-complete` itself (`ci-go.yml:136-164`) | exact (extend existing shape) |
| `e2e/docker_e2e_test.go` (`requireDocker`) | test | request-response (precondition guard) | itself, current implementation (`docker_e2e_test.go:136-146`) | exact (in-place modification) |
| `e2e/docker_e2e_test.go` (`waitForDockerServer`) | test | event-driven (polling) | `internal/testutil/wait.Until`/`UntilValue` (once built) | role-match — this is one of the 5 pollers being converted |
| `e2e/helpers_test.go` (`waitForServer`, bind-retry loop) | test | event-driven (polling) | same — converts to `wait.Until` | role-match |
| `e2e/proc_harness_test.go` (`waitForProcAddr`, `waitForFileContent`, `waitForSidecar`) | test | event-driven (polling) | same — converts to `wait.Until`/`UntilValue` | role-match |
| `e2e/e2e_test.go` (5 of 6 sleep sites) | test | event-driven (polling) | same — converts to `wait.Until` | role-match |
| `e2e/e2e_test.go:757` (intentional 300ms hold) | test | event-driven (duration hold, NOT polling) | itself — MUST NOT be converted | n/a (kept, marker comment strengthened) |
| `docs/contributing/testing.md` | config (docs) | n/a | existing file content (not yet read — see Note below) | n/a |

**Note on `docs/contributing/testing.md`:** not read in this pass since CONTEXT.md marks it "may need" updating and gives no locked requirement beyond documenting `RH_E2E_REQUIRE_DOCKER`. Planner should read the file directly when scoping that task; no pattern extraction needed since it's prose, not code with a structural analog.

## Pattern Assignments

### `internal/testutil/wait/wait.go` (utility, event-driven polling)

**Analog:** `internal/storage/storagetest/suite.go`

**Package shape** (lines 1-18, verified this session):
```go
// Package storagetest provides a reusable compliance test suite that any
// storage.Storage implementation must pass. Embed these functions into a
// backend-specific _test.go file and call them with a freshly initialised store.
package storagetest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/require"

	"github.com/fzymgc-house/router-hosts/internal/domain"
	"github.com/fzymgc-house/router-hosts/internal/eventid"
	"github.com/fzymgc-house/router-hosts/internal/storage"
)
```
This is a normal, non-`_test.go`, untagged, importable package that imports `"testing"` directly — the exact shape RESEARCH.md's Q-02 required and empirically verified (0 golangci-lint issues; `go list -deps ./cmd/...` shows no leak into either shipped binary). `internal/testutil/wait` should mirror this: package doc comment, plain `import "testing"`, no build tag.

**Core pattern to build** (RESEARCH.md's own design survey, `wait.go` target shape):
```go
package wait

import (
	"testing"
	"time"
)

// Until polls cond every interval until it returns true or timeout elapses.
// On timeout, it calls tb.Fatalf with desc — there is no error return to
// silently ignore.
func Until(tb testing.TB, timeout, interval time.Duration, desc string, cond func() bool) {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(interval)
	}
	tb.Fatalf("timed out after %s waiting for: %s", timeout, desc)
}
```
A second generic `UntilValue[T any](...)` is needed to absorb `waitForFileContent`/`waitForSidecar`'s "return the satisfying value, report last-observed value/error on timeout" contract — see RESEARCH.md "wait.Until Design Survey" for the full signature. This split is `[ASSUMED]`/Claude's Discretion, not locked.

**Five call sites this package must absorb (verbatim current code, read this session):**

`e2e/helpers_test.go:366-384` (`waitForServer`, dial-until-connect):
```go
func waitForServer(t *testing.T, addr, caCertPath, clientCertPath, clientKeyPath string) {
	t.Helper()
	tlsCfg := buildClientTLSConfig(t, caCertPath, clientCertPath, clientKeyPath)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 500 * time.Millisecond},
			"tcp", addr, tlsCfg,
		)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready within 10 seconds", addr)
}
```

`e2e/helpers_test.go:207-217` (bind-retry loop inside `startServer` — structurally different: retries the *action* itself, not a passive read; flagged in RESEARCH.md as needing the planner's own call on whether `wait.Until`'s condition-closure shape fits or whether this stays a documented exception):
```go
const maxBindAttempts = 20
const bindRetryDelay = 100 * time.Millisecond
var lis net.Listener
var err error
for attempt := 0; attempt < maxBindAttempts; attempt++ {
	lis, err = net.Listen("tcp", bindAddr)
	if err == nil {
		break
	}
	time.Sleep(bindRetryDelay)
}
require.NoError(t, err, "listen on %s after %d attempts", bindAddr, maxBindAttempts)
```

`e2e/docker_e2e_test.go:252-280` (`waitForDockerServer` — has a side effect, container-log dump, on both the inner "exited" branch and final timeout; RESEARCH.md flags this as not fitting either generic shape cleanly):
```go
func waitForDockerServer(t *testing.T, env *dockerEnv) {
	t.Helper()
	caCertPEM := mustReadFile(t, env.caCertPath)
	deadline := time.Now().Add(startupTimeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", env.containerID).Output()
		if err != nil || strings.TrimSpace(string(out)) != "true" {
			logs, _ := exec.Command("docker", "logs", env.containerID).CombinedOutput()
			t.Fatalf("container exited before becoming ready:\n%s", string(logs))
		}
		conn := dialGRPCWithCerts(t, env.grpcAddr, caCertPEM, env.clientCert, env.clientKey)
		client := hostsv1.NewHostsServiceClient(conn)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err = client.Liveness(ctx, &hostsv1.LivenessRequest{})
		cancel()
		_ = conn.Close()
		if err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", env.containerID).CombinedOutput()
	t.Fatalf("container did not become ready within %v:\n%s", startupTimeout, string(logs))
}
```

`e2e/proc_harness_test.go:346-359` (`waitForProcAddr` — TCP dial, identical shape to `waitForServer`):
```go
func waitForProcAddr(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready within 10 seconds", addr)
}
```

`e2e/proc_harness_test.go:494-520` (`waitForFileContent` — read-and-predicate, returns satisfying value, `UntilValue`-shaped):
```go
func waitForFileContent(t *testing.T, path string, deadline time.Duration, pred func(string) bool) string {
	t.Helper()
	end := time.Now().Add(deadline)
	var last string
	var lastErr error
	for time.Now().Before(end) {
		data, err := os.ReadFile(path)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		lastErr = nil
		last = string(data)
		if pred(last) {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("waiting for %s: condition not met within %s; last read error: %v", path, deadline, lastErr)
	}
	t.Fatalf("waiting for %s: condition not met within %s; last content:\n%s", path, deadline, last)
	return ""
}
```

`e2e/proc_harness_test.go:525-556` (`waitForSidecar` — same `UntilValue` shape, JSON-parsing variant):
```go
func waitForSidecar(t *testing.T, path string, deadline time.Duration, pred func(procSinkStatus) bool) procSinkStatus {
	t.Helper()
	end := time.Now().Add(deadline)
	var lastRaw string
	var lastErr error
	for time.Now().Before(end) {
		data, err := os.ReadFile(path)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		lastRaw = string(data)
		var st procSinkStatus
		if err := json.Unmarshal(data, &st); err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		lastErr = nil
		if pred(st) {
			return st
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("waiting for sidecar %s: condition not met within %s; last error: %v", path, deadline, lastErr)
	}
	t.Fatalf("waiting for sidecar %s: condition not met within %s; last content:\n%s", path, deadline, lastRaw)
	return procSinkStatus{}
}
```

**Six inline poll loops in `e2e/e2e_test.go` to convert (verbatim, this session):**

`e2e_test.go:662-682` (`TestE2E_WatchSinkHealthKeyedByCN` — note: uses `require.True` after the loop, not `t.Fatalf` inside; converting to `wait.Until` changes the failure-reporting shape, which is in-scope per D-13):
```go
var found bool
deadline := time.Now().Add(5 * time.Second)
for time.Now().Before(deadline) {
	snap := env.sinkHealth.Snapshot()
	if st, ok := snap.States["e2e-test-client"]; ok {
		assert.Equal(t, int64(3), st.ConsecutiveFailures)
		assert.Equal(t, contract.TemplateVersion, st.ContractVersion)
		assert.Equal(t, initial.GetChangeId(), st.RenderedChangeID)
		assert.Len(t, snap.States, 1, "registry should hold exactly one key")
		_, hasEmptyKey := snap.States[""]
		assert.False(t, hasEmptyKey, "registry must not hold an entry under the empty key")
		found = true
		break
	}
	time.Sleep(20 * time.Millisecond)
}
require.True(t, found, "sink health registry should hold an entry keyed by e2e-test-client")
```

`e2e_test.go:739-747` (artifact-appears poll, `TestE2E_WatchSinkSurvivesServerRestart` step 1):
```go
var initialBytes []byte
deadline := time.Now().Add(10 * time.Second)
for time.Now().Before(deadline) {
	b, readErr := os.ReadFile(outPath)
	if readErr == nil {
		initialBytes = b
		break
	}
	time.Sleep(50 * time.Millisecond)
}
require.NotEmpty(t, initialBytes, "sink should have written an initial artifact")
```

`e2e_test.go:754-757` — **KEEP, DO NOT CONVERT** (intentional outage-window hold):
```go
// 3. While it is down, the artifact stays byte-identical and the
// sidecar's failure count rises.
time.Sleep(300 * time.Millisecond)
```
D-13 requires the marker comment be strengthened with a literal, greppable token (e.g. `// SLEEP-INTENTIONAL:`) so a future automated sweep can positively identify it rather than infer intent from prose. The existing comment two lines above (lines 750-752 in RESEARCH.md's citation: "No wait-for-readiness here: that is exactly what would remove the outage window step 3 asserts against") stays as the explanation; add the marker token as a distinct, matchable prefix.

`e2e_test.go:763-770` (failure-observed poll, step 3 continued):
```go
var sawFailure bool
deadline = time.Now().Add(10 * time.Second)
for time.Now().Before(deadline) {
	if n, ok := readSidecarConsecutiveFailures(t, statusPath); ok && n > 0 {
		sawFailure = true
		break
	}
	time.Sleep(50 * time.Millisecond)
}
require.True(t, sawFailure, "sidecar should report a rising failure count during the outage")
```

`e2e_test.go:787-795` (new-content poll, step 5) and `e2e_test.go:799-806` (failures-cleared poll, step 5 continued) follow the identical shape — read directly if the planner needs exact text; both are straightforward `wait.Until` conversions with a boolean predicate.

---

### `internal/testutil/wait/wait_test.go` (test)

**No exact in-repo analog for the timeout-assertion problem.** `rg -n "testing.TB" --type go .` and a search for a fake-`testing.TB`/`TestFatalf` helper both returned no matches anywhere in this repository — there is no existing precedent for testing a function that itself calls `t.Fatalf` (which invokes `runtime.Goexit()` and cannot be asserted with ordinary `require`/`assert` on the same goroutine).

The planner must design this from scratch. Standard Go approaches (not sourced from this repo, offered as external reference only since D-16/CI-03 require this phase's own gates to be demonstrated red):
- Run the timeout-path subtest in a separate goroutine with a minimal fake `testing.TB` implementation (only `Helper()`, `Fatalf()`, and whatever other methods the interface requires are exercised) that records the `Fatalf` call instead of calling `runtime.Goexit()`, or
- Use `testing.T`'s own subtest isolation: `t.Run("timeout", func(t *testing.T) { ... })` and assert on `t.Failed()`/output capture is unreliable for `Fatalf` in the same subtest, so most Go codebases hand-roll a small `fakeTB` struct implementing `testing.TB` for exactly this purpose.

Flag this explicitly to the planner: this is new machinery, not a pattern extraction, and should be scoped as such in the plan.

---

### `.github/workflows/ci-go.yml` — three new jobs + `ci-go-complete` extension

**Analog:** `test` job (lines 39-62) for job skeleton; `ci-go-complete` (lines 136-164) for the aggregator, both read verbatim this session — **use these exact pinned SHAs, do not re-resolve to `@v7`/`@v1` tags**:

**Job skeleton** (`ci-go.yml:39-56`, the `test` job's setup steps before its task-specific step):
```yaml
  test:
    name: Test
    runs-on: namespace-profile-linux-amd64-4x8
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7
        with:
          go-version-file: go.mod
          cache: false
      - name: Cache Go modules and build
        uses: namespacelabs/nscloud-cache-action@c5f8dab7560444c4bf8dbc64f1b203431873c547 # v1
        with:
          cache: go
      - name: Install task runner
        run: go install github.com/go-task/task/v3/cmd/task@latest
      - name: Run tests with coverage
        run: task test:coverage:ci
```

**Aggregator, current full text** (`ci-go.yml:136-164` — this is what D-01/D-02 extend, verbatim, so the planner can diff against it precisely):
```yaml
  ci-go-complete:
    name: CI (Go) Complete
    if: always()
    needs: [lint, vuln, test, build, buf-check, manifests, docs]
    runs-on: namespace-profile-linux-amd64-2x4
    timeout-minutes: 5
    steps:
      - name: Check job results
        env:
          LINT_RESULT: ${{ needs.lint.result }}
          VULN_RESULT: ${{ needs.vuln.result }}
          TEST_RESULT: ${{ needs.test.result }}
          BUILD_RESULT: ${{ needs.build.result }}
          BUF_RESULT: ${{ needs.buf-check.result }}
          MANIFESTS_RESULT: ${{ needs.manifests.result }}
          DOCS_RESULT: ${{ needs.docs.result }}
        run: |
          if [[ "$LINT_RESULT" != "success" ]] ||
             [[ "$VULN_RESULT" != "success" ]] ||
             [[ "$TEST_RESULT" != "success" ]] ||
             [[ "$BUILD_RESULT" != "success" ]] ||
             [[ "$BUF_RESULT" != "success" ]] ||
             [[ "$MANIFESTS_RESULT" != "success" ]] ||
             [[ "$DOCS_RESULT" != "success" ]]; then
            echo "One or more CI jobs failed"
            exit 1
          fi
          echo "All CI jobs passed"
```
Extend `needs:` to `[lint, vuln, test, build, buf-check, manifests, docs, e2e-fast, e2e-docker, e2e-proc]`; add `E2E_FAST_RESULT`/`E2E_DOCKER_RESULT`/`E2E_PROC_RESULT` env vars and matching `!= "success"` OR-chained checks, preserving the exact style (D-02: not `== "failure"`, since `if: always()` means `cancelled`/`skipped` must also trip the gate).

**Trigger block to extend for D-05's `workflow_dispatch` half** (`ci-go.yml:2-4`):
```yaml
on:
  pull_request:
    branches: [main]
```
Add a `workflow_dispatch:` key alongside `pull_request:`. Note: per RESEARCH.md's critical finding, the `[ci skip]` marker-strip half of D-05 is NOT achievable inside this repo (it lives in the globally-installed GSD tool's `ship.md` template) — only the `workflow_dispatch:` trigger addition belongs in this file.

**New job env-gate pattern for `e2e-docker`** (sets `RH_E2E_REQUIRE_DOCKER`, no precedent in existing jobs for a job-level `env:` block — this is new, not copied, since none of the 7 existing jobs set job-level env vars; `test`'s coverage threshold is passed via the Taskfile instead). Use standard GitHub Actions `env:` at the job level, matching the shape already used for `env:` inside `ci-go-complete`'s step (lines 144-151) as the closest in-repo precedent for the `env:` block syntax itself.

**D-08's fresh-build step for `e2e-proc`** has no existing analog (no current job removes `bin/`); it's a plain `run: rm -rf bin/` step inserted before the `task test:e2e:proc` step, following the same `- name: ... / run: ...` step shape used throughout every existing job.

---

### `e2e/docker_e2e_test.go` — `requireDocker` (test, request-response precondition guard)

**Analog:** itself, current implementation (`docker_e2e_test.go:136-146`, read this session):
```go
// requireDocker skips the test if Docker is not available.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not found, skipping Docker E2E test")
	}
	// Verify Docker daemon is running
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not running, skipping Docker E2E test")
	}
}
```

**Target shape** (D-06, from RESEARCH.md Pattern 3, both skip sites gated on the same env check):
```go
func requireDocker(t *testing.T) {
	t.Helper()
	required := os.Getenv("RH_E2E_REQUIRE_DOCKER") != ""
	if _, err := exec.LookPath("docker"); err != nil {
		if required {
			t.Fatalf("docker not found, but RH_E2E_REQUIRE_DOCKER is set: %v", err)
		}
		t.Skip("docker not found, skipping Docker E2E test")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		if required {
			t.Fatalf("docker daemon not running, but RH_E2E_REQUIRE_DOCKER is set: %v", err)
		}
		t.Skip("docker daemon not running, skipping Docker E2E test")
	}
}
```
Requires adding `"os"` to this file's import block if not already present — check before writing.

## Shared Patterns

### CI job skeleton (checkout → setup-go → cache → install task → run task target)
**Source:** `.github/workflows/ci-go.yml:39-56` (the `test` job)
**Apply to:** `e2e-fast`, `e2e-docker`, `e2e-proc` — all three new jobs
**Pinned SHAs to reuse verbatim (do not re-resolve to floating tags):**
- `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7`
- `actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7`
- `namespacelabs/nscloud-cache-action@c5f8dab7560444c4bf8dbc64f1b203431873c547 # v1`

### `!= "success"` aggregator check under `if: always()`
**Source:** `.github/workflows/ci-go.yml:152-163`
**Apply to:** the `ci-go-complete` extension — preserves D-02's correctness requirement (catches `cancelled`/`skipped`, not just `failure`)

### `t.Helper()` + bounded deadline loop + `t.Fatalf` on timeout
**Source:** all five existing pollers (`waitForServer`, `waitForDockerServer`, `waitForProcAddr`, `waitForFileContent`, `waitForSidecar`) — every one follows `t.Helper()` → `deadline := time.Now().Add(N)` → `for time.Now().Before(deadline) { ...; time.Sleep(interval) }` → `t.Fatalf(...)`
**Apply to:** `internal/testutil/wait.Until`/`UntilValue` design, and every converted call site in `e2e/e2e_test.go`, `e2e/helpers_test.go`, `e2e/docker_e2e_test.go`, `e2e/proc_harness_test.go`

### `t.Helper()` precondition guard with `t.Skip`/`t.Fatalf` branching
**Source:** `e2e/docker_e2e_test.go:136-146` (`requireDocker`, current)
**Apply to:** the D-06 env-gated rewrite of the same function — same function, in-place modification, not a new analog elsewhere

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `internal/testutil/wait/wait_test.go` (timeout-path assertion specifically) | test | request-response (unit test) | No fake-`testing.TB` or `t.Fatalf`-under-goroutine-isolation precedent exists anywhere in this repo (`rg -n "testing.TB" --type go .` returns zero matches). This is new machinery — the planner should design a minimal `fakeTB` implementing `testing.TB`'s `Fatalf`/`Helper` (and any other required methods) run in its own goroutine, since ordinary `require`/`assert` cannot observe a `t.Fatalf` call made on the same goroutine without triggering `runtime.Goexit()` in the test itself. |
| `docs/contributing/testing.md` | config (docs) | n/a | Prose documentation; no structural code analog applies. Planner should read the file directly before scoping the `RH_E2E_REQUIRE_DOCKER` documentation task. |
| `e2e/helpers_test.go` bind-retry loop → `wait.Until` fit | test | event-driven | Structurally different from the other 6 pollers (retries an *action* — `net.Listen` — not a passive read of existing state). RESEARCH.md explicitly leaves this as an open design point for the planner: either express it as a `wait.Until` condition-closure that performs the listen attempt internally, or leave it as a documented exception with its own thin loop. |
| `.github/workflows/ci-go.yml` job-level `env:` block for `e2e-docker` (`RH_E2E_REQUIRE_DOCKER: "1"`) | config | n/a | No existing job in this workflow sets a job-level `env:` block (only `ci-go-complete`'s step-level `env:` exists as a syntax precedent). Standard GitHub Actions syntax applies; not copied from an in-repo job. |

## Metadata

**Analog search scope:** `.github/workflows/ci-go.yml`, `internal/storage/storagetest/`, `internal/storage/sqlite/compliance_test.go`, `e2e/*.go` (all four e2e test files), repo-wide `rg` for `testing.TB`
**Files scanned:** 8 target files + 3 analog source files, all read in full or via targeted `sed`/`Read` ranges this session
**Pattern extraction date:** 2026-08-02
