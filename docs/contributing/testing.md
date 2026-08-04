# End-to-End Testing

This document describes the E2E test suite for router-hosts.

## Overview

router-hosts has **three** e2e test tiers, each behind its own Go build tag
and `task` target, each proving a different thing and — the part that
matters when deciding where to add a new test — each **not** proving certain
other things.

| Tier | Build tag | Task command | Proves | Does NOT prove |
|------|-----------|--------------|--------|-----------------|
| In-process | `e2e` | `task test:e2e` | Real mTLS handshake, real TLS listener, gRPC CRUD/streaming behavior — all in one process | Anything about the CLI's flag parsing or config-file resolution. The client is driven through `commands.NewRootCmd(...).SetArgs([...])` inside the SAME test process, never through a shell |
| Containerized server | `docker_e2e` | `task test:e2e:docker` (requires Docker) | The server builds and runs correctly inside the shipped Docker image | Anything about the CLI's flag parsing or config-file resolution — the client is STILL driven in-process, only the server is containerized |
| Real process | `proc_e2e` | `task test:e2e:proc` (requires `task build` first) | The shipped binary, launched as a real OS process via `os/exec` on BOTH sides of the mTLS connection, correctly parses CLI flags and resolves its config file | Container networking, resolver reload, or anything else that needs more than one host — see "Deferred: containerized two-node verification" below |

**Why this matters:** the in-process tier drives the client inside the test
process itself, so it cannot exercise CLI flag parsing or config-file
resolution at all — that whole seam simply never runs. This is exactly why a
`--config` defect (gap G-01-1: `watch --config <path>` silently fell back to
an XDG-discovered config instead of failing loudly on a bad explicit path)
shipped through a full phase of green e2e runs and 45 UAT items before being
caught. If you are adding a test for anything CLI-flag- or
config-resolution-related, it belongs in the `proc_e2e` tier — an in-process
test cannot see it.

## Running E2E Tests

```bash
# In-process (real TLS, no external dependencies)
task test:e2e

# Containerized server, in-process client (requires Docker)
task test:e2e:docker

# Real OS processes on both sides of mTLS (builds the binary first)
task test:e2e:proc
```

## Prerequisites

- Go 1.25+
- `task test:e2e`: no external dependencies (certificates and gRPC transport
  are handled in-process)
- `task test:e2e:docker`: Docker daemon running
- `task test:e2e:proc`: no external dependencies beyond the Go toolchain and
  `task`; no Docker, no network access beyond loopback, no privileged ports

### `RH_E2E_REQUIRE_DOCKER`

`task test:e2e:docker` probes for the `docker` binary and a reachable daemon
before running. What happens when that probe fails depends on
`RH_E2E_REQUIRE_DOCKER`:

- **Unset (the contributor default):** the tier **skips** if Docker is
  missing or the daemon is down, so `task test:e2e:docker` stays usable on a
  machine without a Docker daemon.
- **Set to any non-empty value** — which the `e2e-docker` CI job does — the
  same conditions **fail** the test instead of skipping it, so a green
  `e2e-docker` run can never mean "Docker was missing so we skipped."

Presence, not truthiness, is what counts: `RH_E2E_REQUIRE_DOCKER=0` still
means required, exactly as `RH_E2E_REQUIRE_DOCKER=1` does. The variable is
never parsed as a boolean.

## Test Scenarios

### In-process (`e2e`)

The in-process suite includes tests across the areas below, in
`e2e/e2e_test.go` and `e2e/helpers_test.go`:

| Area | Description |
|------|-------------|
| CRUD | Create, read, update, delete host entries |
| Import/Export | Round-trip import and export of hosts files |
| Aliases | Hostname alias operations |
| Search | Search by hostname, IP, and alias |
| Auth: Wrong CA | Reject client with certificate from wrong CA |
| Auth: Self-signed | Reject client with self-signed certificate |
| Snapshots | Create and list snapshots |
| Rollback | Rollback to previous snapshot |
| Watch | Push-on-mutation, sink health keyed by CN, survives server restart |

### Real process (`proc_e2e`)

`e2e/proc_e2e_test.go`, backed by the harness in `e2e/proc_harness_test.go`:

| Test | Proves |
|------|--------|
| `TestProcE2E_ColdStartWatchHonorsConfigFlag` | `watch --config <path>` connects to the server named by `<path>`, not to an equally valid, equally reachable server discoverable on the process's XDG search path (two live servers, discriminated by content) |
| `TestProcE2E_MissingExplicitConfigFailsLoudly` | An unusable `--config` kills the process loudly, names the path in its output, and writes no artifact — even with a working config sitting on the XDG search path |
| `TestProcE2E_ChangeIDPropagatesToSidecar` | A mutation made by a SEPARATE real CLI process reaches a running sink's rendered artifact and advances the sidecar's `rendered_change_id` |

## Architecture

```text
In-process (e2e), containerized-server (docker_e2e):

┌─────────────────────────────────────────────────┐
│                  Test Process                    │
│                                                  │
│  ┌──────────────┐         ┌──────────────────┐  │
│  │   Test Code  │         │   gRPC Server    │  │
│  │   (client)   │◀───────▶│  (in-process or  │  │
│  │              │  (m)TLS  │   containerized) │  │
│  └──────────────┘         └──────────────────┘  │
│                                                  │
│  ┌──────────────┐         ┌──────────────────┐  │
│  │  crypto/x509 │         │  SQLite          │  │
│  │  (certs)     │         │  (storage)       │  │
│  └──────────────┘         └──────────────────┘  │
└─────────────────────────────────────────────────┘

Real process (proc_e2e):

┌─────────────────────────────────────────────────┐
│                  Test Process                    │
│                                                  │
│  os/exec ──▶ router-hosts serve   (real process) │
│  os/exec ──▶ router-hosts serve   (real process) │
│  os/exec ──▶ router-hosts watch   (real process) │
│  os/exec ──▶ router-hosts host add (one-shot)    │
│                                                  │
│  Every process gets an EXPLICIT environment      │
│  (hermeticEnv): XDG_CONFIG_HOME + HOME point at  │
│  the test's temp dirs, never the developer's own │
│                                                  │
│  Assertions read the artifact and sidecar files  │
│  from disk by path — never an in-memory handle   │
└─────────────────────────────────────────────────┘
```

## Writing New E2E Tests

New in-process E2E tests go in the `e2e/` directory alongside
`e2e/e2e_test.go`.

### Test Structure (in-process)

```go
func TestMyScenario(t *testing.T) {
    // Setup: start in-process server with mTLS
    env := setupTestEnv(t)

    // Act: execute client operations
    resp, err := env.client.AddHost(env.ctx, &pb.AddHostRequest{
        IpAddress: "192.168.1.1",
        Hostname:  "test.local",
    })
    require.NoError(t, err)
    assert.Equal(t, "192.168.1.1", resp.Host.IpAddress)

    // Cleanup is automatic via t.Cleanup()
}
```

### Best Practices

1. **Isolation**: Each test gets its own server instance and database
2. **Determinism**: Don't rely on system time or random values
3. **Cleanup**: Use `t.Cleanup()` for resource teardown
4. **Timeouts**: Use `context.WithTimeout()` for operations
5. **Assertions**: Use `testify/require` for fatal checks, `testify/assert` for non-fatal

### When to add a `proc_e2e` test instead

Add a `proc_e2e` test — not an in-process one — whenever the behavior under
test lives in the CLI-flag-to-config-loading seam: flag parsing, config file
discovery/precedence, environment variable resolution, or anything else that
only exists because the binary was launched from a shell. An in-process test
cannot see any of that, by construction.

`e2e/proc_harness_test.go` provides the reusable building blocks:

- `procBinaryPath(t)` — resolves the built binary, failing hard (never
  skipping) if it is missing
- `newPKIBundle(t, dir)` / `issueClientCert(t, bundle, cn)` — mTLS material,
  with a CN parameter per client certificate
- `writeServerConfigFile` / `writeClientConfigFile` — TOML config writers,
  parameterized by address and directory
- `startServerProcess` / `startSinkProcess` / `runCLI` — real `os/exec`
  process launchers for `serve`, `watch`, and one-shot subcommands
- `hermeticEnv(t, xdgDir)` — the explicit child-process environment (see
  "Hermetic environment" below)
- `waitForFileContent` / `waitForSidecar` — thin wrappers over
  `internal/testutil/wait.UntilValue`

All readiness waiting across the three e2e tiers goes through
`internal/testutil/wait` (`wait.Until` / `wait.UntilValue`), which reports a
timeout via `t.Fatalf` rather than returning an error a caller could
silently drop. The one deliberate exception is a fixed-duration sleep in
`e2e/e2e_test.go` marked `SLEEP-INTENTIONAL:` — it holds an outage window
open for an assertion about behavior *during* an outage, not readiness, so
converting it to a poll would erase the window the test exists to check. A
future sweep for stray sleeps should treat that marker as the signal to
leave it alone.

Certificate generation in `e2e/proc_harness_test.go` is a deliberate,
~90-line duplication of the equivalent helpers in `e2e/helpers_test.go`
rather than a shared import. Do not "fix" this by merging the files: doing
so would pull the in-process server/service construction those helpers
carry into a suite whose entire purpose is proving nothing is constructed
in-process.

### Hermetic environment

Every `proc_e2e` process launch uses an EXPLICIT child environment
(`hermeticEnv`), never the parent's inherited environment:

- `XDG_CONFIG_HOME` points at the test's own temp directory
- `HOME` points at a FRESH temp directory, so the `~/.config` fallback and
  the darwin `~/Library/Application Support` fallback
  (`clientConfigSearchPaths` in `internal/config/client.go`) cannot reach a
  developer's real config
- Every `ROUTER_HOSTS_*` env var the client config loader consults is
  blanked explicitly

A test that accidentally inherited a developer's real config would pass on
that developer's machine for the wrong reason — this is why the explicit
environment is load-bearing, not a nicety.

## Certificate Generation

Both the in-process (`e2e`) and real-process (`proc_e2e`) suites generate
certificates at runtime using `crypto/x509` and `crypto/ecdsa`: a CA, a
server leaf, and per-test client leaves. The in-process suite keeps
certificates in memory where possible; the real-process suite writes them to
each test's `t.TempDir()`, since the certs must be readable by a separate OS
process. Neither suite writes outside its own temp directory.

## Deferred: containerized two-node verification

UAT test 42 (phase `01-consumer-rendered-output-templates-sink`) is blocked
pending a real unbound host and a second machine, and calls for "a
process/container-level harness rather than the current fully in-process e2e
suite ... worth designing as one harness, not two." Building that
containerized unbound instance and two-node convergence verification is out
of scope for the `proc_e2e` tier and stays deferred, but the `proc_e2e`
harness was deliberately built so that work extends it rather than
replacing it:

- **PKI is N-party from the start.** `issueClientCert` takes a CN parameter;
  a two-node convergence test needs two distinct CNs (sink health is keyed
  by CN), and a harness that mints only one would be unextendable.
- **Config generation is transport-agnostic.** `writeServerConfigFile` and
  `writeClientConfigFile` emit TOML to a directory and take an address as a
  parameter — a container harness mounts the same directory and passes a
  container-network address; nothing assumes loopback.
- **Launch is the only container-specific seam.** `startServerProcess` and
  `startSinkProcess` confine process start/stop to small functions;
  swapping them for container invocations replaces those functions and
  nothing else.
- **Observation is filesystem-based, not in-memory.** `waitForFileContent`
  and `waitForSidecar` poll files by path with a deadline — a bind-mounted
  container volume satisfies the identical assertion unchanged.
- **Multiple sinks are already expressible.** `startSinkProcess` returns a
  handle with its own artifact and sidecar paths, so starting a second sink
  is a second call, not a refactor.

Explicitly left out of the `proc_e2e` tier, and left for that future work:
no docker-compose file, no unbound container, no cross-container
networking, no resolver-reload assertion, and no two-node convergence test.

## Benchmark Gate: peak-heap regression check (`lazybench`, LAZY-02)

Alongside the three e2e tiers, one more tier is a required gate on every PR:
a benchmark that proves the paged storage-read path (`ListPage`) keeps peak
memory flat as the dataset grows, in contrast to the drained path
(`ListAll`), which materializes everything into one slice and scales with
entry count. This is LAZY-02's regression check for D-13: without it, a
future change that silently reintroduces full materialization on the paged
path would only be caught by someone happening to profile it by hand.

| Tier | Build tag | Task command | CI job |
|------|-----------|---------------|--------|
| Benchmark gate | `lazybench` | `task test:bench:lazy` | `bench-lazy` |

**Build tag and isolation.** `internal/storage/sqlite/projection_bench_test.go`
and `internal/server`'s equivalent live behind `//go:build lazybench`, so
they are excluded from the default build and from `task test` entirely —
confirmed by grepping a full `task test` run for `BenchmarkPeakMemory` and
finding zero matches.

**Why it does not run under `task test`, and does not use `-race`.**
`task test` runs the full suite with `-race`. `-race` instruments every
memory access, which both slows a 10,000-entry fixture significantly and
perturbs the allocation accounting this tier exists to measure — the same
reasoning `append_bench_test.go`'s `BenchmarkAppendEventsBatch` already
uses for timing, extended here to peak-heap sampling. Running it inside
`task test` would make the very quantity under test unreliable, so it gets
its own build tag, its own task target, and its own CI job instead of
riding along inside the race-enabled suite.

**How it differs from `BenchmarkAppendEventsBatch`.** That benchmark is a
recorded measurement only — no threshold is wired into CI, deliberately,
because a wall-clock threshold is flaky by construction. `BenchmarkPeakMemory`
is the opposite: it asserts a ratio and is a required, blocking CI gate.

**What it measures.** The primary metric is *marginal peak live heap*,
sampled via `internal/heapsample.PeakDuring`: a background goroutine polls
`runtime.MemStats.HeapAlloc` on a 250µs ticker during the measured call and
reports the sampled peak minus a `runtime.GC()`-then-`ReadMemStats` baseline
taken immediately before the call. The 250µs interval was chosen empirically
(100µs showed both a wider spread and direct evidence of stop-the-world poll
overhead; 250µs and 500µs performed comparably) — see plan 02-05's SUMMARY
for the measured spreads. Because `runtime.ReadMemStats` briefly stops the
world, every sample is itself an approximation, which is exactly why the
gate asserts a ratio with margin rather than a tight absolute figure.

The `allocs/op` and `B/op` figures the benchmark also reports
(`b.ReportAllocs()`) are **informational only** and must never become
load-bearing: cumulative allocation is roughly O(entry count) for the paged
and drained paths alike, so it cannot distinguish "peak held at once" from
"total allocated over the run." A future contributor investigating a red run
should look at the reported `peak-heap-bytes` metric, not reach for
`-benchmem` numbers as a fix.

**What it asserts — a ratio, never an absolute ceiling.** Two assertions,
both in `BenchmarkPeakMemory` (mirrored in `internal/server`'s consumer-level
benchmark):

- `pagedRatio < 1.8` — the paged path's peak heap must stay roughly flat as
  the fixture grows 10x (1,000 to 10,000 live entries). This is the
  load-bearing claim.
- `drainedRatio > pagedRatio * 1.4` — the drained path's peak must scale
  measurably faster than the paged path's, i.e. the two paths must stay
  clearly separated.

Neither assertion is an absolute byte ceiling, and that is deliberate: a
fixed number is a magic constant someone bumps the first time it goes red,
which quietly turns the gate into a rubber stamp. The gate exists to catch
*separation collapsing* — the paged path starting to scale like the drained
one — not to enforce a specific byte count.

This design was proven, not assumed. The `drainedRatio` assertion originally
was a fixed `drainedRatio > 2.2`, derived from 15 local macOS/arm64 runs.
Its first real run on Linux CI (`workflow_dispatch` run `30867901912`,
`goos=linux goarch=amd64`, AMD EPYC) failed: `pagedRatio` was `1.010` (well
inside bound) but `drainedRatio` was only `1.775` — Linux's allocator and GC
grow the drained path's marginal peak less than macOS's do. The *qualitative*
behavior still held (1.775 vs 1.010 is a decisive gap), but the *magnitude*
constant, derived only from local runs, did not travel to a different OS/
arch. The fix (commit `a0691da`) replaced the fixed threshold with the
`drainedRatio > pagedRatio * 1.4` separation check above, and that change
was itself proven with a deliberate-regression RED run on Linux CI
(`workflow_dispatch` run `30868423963`: removing the drained arm's
`ListAll` retention collapsed both paths to near-flat and the assertion
correctly failed) before being trusted. **Do not "simplify" this back to a
fixed multiplier** — if it goes red, treat it as the paths having genuinely
stopped separating, and investigate the separation, never widen the
threshold to turn a red run green.

**Expected exception: the `hosts` export format.** The `hosts`-format
residual path in `internal/server`'s consumer benchmark is *expected* to
scale with entry count — this is a recorded, sanctioned scope decision under
D-02 (documented in REQUIREMENTS.md's Out of Scope table), not a regression.
A contributor seeing that specific number grow should not treat it as a
finding.

## CI Integration

All three e2e tiers plus the benchmark gate run on every pull request
(`.github/workflows/ci-go.yml`), as parallel jobs:

| Job | Runs |
|-----|------|
| `e2e-fast` | `task test:e2e` |
| `e2e-docker` | `task test:e2e:docker` |
| `e2e-proc` | `task test:e2e:proc` (after removing `bin/`, so the binary under test is always a fresh build) |
| `bench-lazy` | `task test:bench:lazy` — see "Benchmark Gate" above |

Their results feed the single aggregated required check, `CI (Go) Complete`,
via the `ci-go-complete` job: a tier that fails, is cancelled, or is skipped
makes that check fail, so a merge cannot land without all four green.

There is no merge queue in this repository and merges are squash-only, so
the pull-request check *is* the merge gate — the fast tier and the slower
container/process/benchmark tiers gate at the same moment rather than in two
stages.

`internal/ciwiring`'s test (`TestEveryGatedTierIsWiredIntoAggregator`)
asserts that every `e2e-*` and `bench-*` job in `ci-go.yml` is represented
in `ci-go-complete`'s aggregation, so adding a new gated tier without wiring
it into the aggregator fails `task test`.

This closes [issue #403](https://github.com/fzymgc-house/router-hosts/issues/403):
gap G-01-1 (a `--config` regression that shipped through a full phase of
green e2e runs) was a direct consequence of no e2e tier running
automatically on any PR — that gap is why all three e2e tiers, and now the
benchmark gate, are required gates rather than developer-run-only suites.
