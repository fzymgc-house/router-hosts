# Operator Health Checks Design

**Status:** Approved
**Created:** 2025-12-28
**Author:** Claude (with Sean)
**Issue:** #155

## Overview

Add HTTP health check endpoints (`/healthz` and `/readyz`) to the router-hosts-operator for proper Kubernetes liveness and readiness probes.

## Architecture

The health server runs as a separate task alongside the controllers:

```
┌─────────────────────────────────────────────────────────┐
│                    main.rs                               │
│                                                          │
│  tokio::select! {                                        │
│    ├── run_controllers(...)         ← existing          │
│    ├── run_garbage_collection(...)  ← existing          │
│    ├── run_health_server(...)       ← NEW               │
│    └── signal handlers              ← existing          │
│  }                                                       │
└─────────────────────────────────────────────────────────┘
```

**New module**: `src/health.rs`
- `HealthState` struct holding shared state (Arc)
- `/healthz` handler - returns 200 if process alive
- `/readyz` handler - pings router-hosts server

**Shared state** between health server and main:
- Reference to `RouterHostsClient` for connectivity check
- Startup complete flag

**Port**: 8081 (configurable via `HEALTH_PORT` env var)

## Endpoints

### `/healthz` (Liveness)

Simple check - if the HTTP server responds, the process is alive.

```rust
async fn healthz() -> StatusCode {
    StatusCode::OK
}
```

Returns:
- `200 OK` - Process is running
- No response - Process is dead (Kubernetes restarts pod)

### `/readyz` (Readiness)

Checks router-hosts server connectivity:

```rust
async fn readyz(State(state): State<Arc<HealthState>>) -> StatusCode {
    // Check if startup completed
    if !state.started.load(Ordering::Relaxed) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }

    // Ping router-hosts server (lightweight RPC)
    match state.client.health_check().await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
```

Returns:
- `200 OK` - Ready to process work
- `503 Service Unavailable` - Not ready (startup incomplete or server unreachable)

**Note**: The router-hosts gRPC service doesn't have a dedicated health check RPC. We use `ListHosts` with empty filter as a lightweight connectivity test that exercises the full gRPC/mTLS path.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HEALTH_PORT` | `8081` | Port for health HTTP server |

### Helm Values

```yaml
healthCheck:
  port: 8081
```

### Deployment Probes

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8081
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /readyz
    port: 8081
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Implementation

### Files to Modify/Create

| File | Change |
|------|--------|
| `crates/router-hosts-operator/Cargo.toml` | Add `axum = "0.7"` dependency |
| `crates/router-hosts-operator/src/health.rs` | New - Health server and handlers |
| `crates/router-hosts-operator/src/lib.rs` | Export `health` module |
| `crates/router-hosts-operator/src/main.rs` | Add health server to `select!` |
| `charts/router-hosts-operator/values.yaml` | Add `healthCheck.port` |
| `charts/router-hosts-operator/templates/deployment.yaml` | Add probes and port |

### Dependencies

```toml
axum = "0.7"
```

## Follow-up

- Create issue: `feat(api): add Health RPC for lightweight connectivity check`
