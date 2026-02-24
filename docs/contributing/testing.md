# End-to-End Testing

This document describes the E2E test suite for router-hosts.

## Overview

E2E tests validate the full stack with real mTLS authentication. Tests run in-process using `crypto/x509` for certificate generation and `bufconn` for gRPC transport. No Docker is required.

## Running E2E Tests

```bash
# Run all E2E tests
task test:e2e
```

## Prerequisites

- Go 1.24+
- No external dependencies (certificates and gRPC transport are handled in-process)

## Test Scenarios

The E2E suite includes 10 tests in the `e2e/` directory:

| Area | Tests | Description |
|------|-------|-------------|
| CRUD | 3 | Create, read, update, delete host entries |
| Import/Export | 1 | Round-trip import and export of hosts files |
| Aliases | 1 | Hostname alias operations |
| Search | 1 | Search by hostname, IP, and alias |
| Auth: Wrong CA | 1 | Reject client with certificate from wrong CA |
| Auth: Self-signed | 1 | Reject client with self-signed certificate |
| Snapshots | 1 | Create and list snapshots |
| Rollback | 1 | Rollback to previous snapshot |

## Architecture

```text
┌─────────────────────────────────────────────────┐
│                  Test Process                    │
│                                                  │
│  ┌──────────────┐         ┌──────────────────┐  │
│  │   Test Code  │         │   gRPC Server    │  │
│  │   (client)   │◀───────▶│   (in-process)   │  │
│  │              │ bufconn  │                  │  │
│  └──────────────┘         └──────────────────┘  │
│                                                  │
│  ┌──────────────┐         ┌──────────────────┐  │
│  │  crypto/x509 │         │  SQLite :memory: │  │
│  │  (certs)     │         │  (storage)       │  │
│  └──────────────┘         └──────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Writing New E2E Tests

New E2E tests go in the `e2e/` directory.

### Test Structure

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

1. **Isolation**: Each test gets its own server instance and in-memory database
2. **Determinism**: Don't rely on system time or random values
3. **Cleanup**: Use `t.Cleanup()` for resource teardown
4. **Timeouts**: Use `context.WithTimeout()` for operations
5. **Assertions**: Use `testify/require` for fatal checks, `testify/assert` for non-fatal

## Certificate Generation

E2E tests generate certificates at runtime using `crypto/x509` and `crypto/ecdsa`. Each test creates its own CA, server certificate, and client certificate. Certificates are created in memory and do not touch the filesystem.

## CI Integration

E2E tests run in GitHub Actions on:

- Every pull request
- Every push to `main`

No Docker or special runner configuration is needed.
