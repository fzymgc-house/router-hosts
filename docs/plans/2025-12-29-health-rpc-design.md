# Health RPC Design

**Issue:** #163
**Date:** 2025-12-29
**Status:** Approved

## Summary

Add dedicated health check RPCs to the router-hosts gRPC API to replace the operator's current approach of using `find_by_hostname("")` for readiness probes.

## Motivation

The operator's readiness probe currently calls `find_by_hostname("")` every 10 seconds. This:
- Executes a full streaming RPC
- Queries the database unnecessarily
- Has poor semantics (repurposing a query as health check)

A dedicated health API provides lightweight, purpose-built endpoints.

## Design

### Three Endpoints

| Endpoint | Response | Purpose |
|----------|----------|---------|
| **Liveness** | Simple bool | Process alive, gRPC working |
| **Readiness** | Bool + reason | Ready to serve (DB connected) |
| **Health** | Rich status object | Detailed component status for monitoring |

### Proto Definition

```protobuf
// Health check messages

message LivenessRequest {}
message LivenessResponse {
  bool alive = 1;
}

message ReadinessRequest {}
message ReadinessResponse {
  bool ready = 1;
  string reason = 2;  // Empty if ready, reason if not
}

message HealthRequest {}
message HealthResponse {
  bool healthy = 1;
  ServerInfo server = 2;
  DatabaseHealth database = 3;
  AcmeHealth acme = 4;
  HooksHealth hooks = 5;
}

message ServerInfo {
  string version = 1;
  int64 uptime_seconds = 2;
  string build_info = 3;  // e.g., "v0.6.0 (abc1234)"
}

message DatabaseHealth {
  bool connected = 1;
  string backend = 2;  // "sqlite", "postgresql", "duckdb"
  int64 latency_ms = 3;
  string error = 4;  // Empty if healthy
}

message AcmeHealth {
  bool enabled = 1;
  string status = 2;  // "valid", "renewing", "expired", "disabled"
  int64 expires_at = 3;  // Unix timestamp, 0 if disabled
  string error = 4;
}

message HooksHealth {
  int32 configured_count = 1;
  repeated string hook_names = 2;
}
```

Service additions:
```protobuf
service HostsService {
  // ... existing RPCs ...

  rpc Liveness(LivenessRequest) returns (LivenessResponse);
  rpc Readiness(ReadinessRequest) returns (ReadinessResponse);
  rpc Health(HealthRequest) returns (HealthResponse);
}
```

### Server Implementation

**Liveness**: Returns immediately with `alive: true`. No I/O.

**Readiness**: Calls `storage.health_check()`. Returns `ready: false` with reason on failure.

**Health**: Gathers status from all components:
- Database: health check with latency timing
- ACME: certificate status and expiry from certificate manager
- Hooks: enumerate configured hook scripts
- Server: version from `CARGO_PKG_VERSION`, uptime from server start time

### Operator Changes

Update `RouterHostsClientTrait`:
```rust
async fn check_readiness(&self) -> Result<bool, ClientError>;
```

Update `health.rs` readiness probe to use `check_readiness()` instead of `find_by_hostname("")`.

## Implementation Scope

| Component | Changes |
|-----------|---------|
| `proto/router_hosts/v1/hosts.proto` | Add 3 RPCs + messages |
| `crates/router-hosts/src/server/` | Implement 3 RPC handlers |
| `crates/router-hosts/src/server/` | Add uptime tracking, expose ACME/hooks state |
| `crates/router-hosts-operator/src/client.rs` | Add `check_readiness()` method |
| `crates/router-hosts-operator/src/health.rs` | Use `check_readiness()` |
| Tests | Update mocks, add unit tests |

Estimated ~200-300 lines of new code.

## Testing

- Unit tests for each RPC handler
- Mock-based operator tests for `check_readiness()`
- E2E tests calling all three RPCs against real server

## Alternatives Considered

1. **Single Health RPC with flags** - Rejected; three distinct endpoints are clearer
2. **HTTP health endpoints** - Rejected; keep everything in gRPC for consistency
3. **Database check in liveness** - Rejected; liveness should be minimal

## References

- Issue #163
- PR #158 (operator health checks)
