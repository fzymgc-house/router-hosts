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
- `waitForFileContent` / `waitForSidecar` — filesystem-based polling helpers

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

## CI Integration

**None of the three e2e tiers currently run in CI**
(`.github/workflows/ci-go.yml`). The `test` job runs `task test:coverage:ci`,
which is `go test ./internal/...` with a coverage threshold — unit and
integration tests only, not `task test:e2e`, `task test:e2e:docker`, or
`task test:e2e:proc`.

This is a known limitation, not a settled decision: it is recorded here
rather than silently carried forward, and tracked in
[issue #403](https://github.com/fzymgc-house/router-hosts/issues/403). Gap
G-01-1 (a `--config` regression that shipped through a full phase of green
e2e runs) is a direct consequence of no e2e tier running automatically on
any PR.
