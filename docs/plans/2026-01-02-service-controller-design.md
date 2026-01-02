# Service Controller Design

**Date:** 2026-01-02
**Status:** Approved

## Summary

Add a new controller to the router-hosts operator that watches Kubernetes `v1/Service` resources and creates DNS entries for LoadBalancer and NodePort Services.

## Goals

1. Support LoadBalancer Services with automatic IP discovery from status
2. Support NodePort Services with explicit IP annotation
3. Reuse existing annotation patterns and deletion handling
4. Strict validation to prevent misconfiguration

## Supported Service Types

| Type | IP Resolution | If Missing |
|------|---------------|------------|
| `LoadBalancer` | `.status.loadBalancer.ingress[0].ip` | Wait/retry with backoff |
| `NodePort` | `ip-address` annotation | Reject with error event |
| `ClusterIP` | Not supported | Reject with warning event |
| `ExternalName` | Not supported | Reject with warning event |

## Annotations

### Required

```yaml
metadata:
  annotations:
    router-hosts.fzymgc.house/enabled: "true"
    router-hosts.fzymgc.house/hostname: "myservice.example.com"
```

The `hostname` annotation is **required** for Services because they don't have hostnames in their spec (unlike Ingress). This keeps registration explicit.

### Optional

```yaml
    router-hosts.fzymgc.house/ip-address: "1.2.3.4"   # Required for NodePort, optional override for LoadBalancer
    router-hosts.fzymgc.house/aliases: "alt1,alt2"    # Additional hostnames
    router-hosts.fzymgc.house/tags: "env:prod"        # Custom tags
    router-hosts.fzymgc.house/grace-period: "300"     # Deletion delay (seconds)
```

## Examples

### LoadBalancer Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-app
  annotations:
    router-hosts.fzymgc.house/enabled: "true"
    router-hosts.fzymgc.house/hostname: "app.example.com"
spec:
  type: LoadBalancer
  ports:
    - port: 443
  selector:
    app: my-app
```

IP is automatically discovered from `.status.loadBalancer.ingress[0].ip` once assigned.

### NodePort Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-nodeport
  annotations:
    router-hosts.fzymgc.house/enabled: "true"
    router-hosts.fzymgc.house/hostname: "nodeport.example.com"
    router-hosts.fzymgc.house/ip-address: "192.168.1.100"  # Required
spec:
  type: NodePort
  ports:
    - port: 80
      nodePort: 30080
  selector:
    app: my-app
```

The `ip-address` annotation is required because NodePort exposes on all nodes - which IP to register is topology-dependent.

## Reconciliation Flow

```
Service Event (create/update/delete)
    │
    ├─► Check router-hosts.fzymgc.house/enabled == "true"
    │       └─► No: Skip (not managed)
    │
    ├─► Validate Service type (LoadBalancer or NodePort only)
    │       └─► Invalid: Emit warning event, skip
    │
    ├─► Check router-hosts.fzymgc.house/hostname annotation
    │       └─► Missing: Emit error event, skip
    │
    ├─► Resolve IP:
    │       ├─► LoadBalancer: .status.loadBalancer.ingress[0].ip
    │       │       └─► Pending: Requeue with backoff
    │       └─► NodePort: ip-address annotation
    │               └─► Missing: Emit error event, skip
    │
    └─► Create/Update/Delete host entry via gRPC
```

## Kubernetes Events

| Event | Type | Condition |
|-------|------|-----------|
| `InvalidServiceType` | Warning | ClusterIP or ExternalName annotated |
| `MissingHostname` | Warning | `hostname` annotation missing |
| `MissingIPAddress` | Warning | NodePort without `ip-address` |
| `PendingLoadBalancer` | Normal | Waiting for IP assignment |
| `HostRegistered` | Normal | Entry created/updated |
| `HostDeleted` | Normal | Entry removed |

## Implementation

### New File

```
crates/router-hosts-operator/src/controllers/service.rs
```

### Structure

Mirrors existing controllers (ingress.rs, ingressroute.rs):

- `is_enabled()` - Check opt-in annotation
- `extract_hostname()` - Get hostname from annotation
- `resolve_ip()` - Type-specific IP resolution
- `build_tags()` - Ownership tags with `kind:Service`
- `reconcile()` - Main reconciliation logic
- `on_error()` - Error handling with exponential backoff

### Changes to Existing Files

| File | Change |
|------|--------|
| `controllers/mod.rs` | Add `pub mod service;` |
| `main.rs` | Start Service controller alongside others |

### Reused Components

- `DeletionScheduler` - Grace period handling
- `RetryTracker` - Exponential backoff
- Existing annotation constants from `config.rs`
- Ownership tag building logic

## Testing

### Unit Tests

- IP extraction from LoadBalancer status (with/without IP, hostname fallback)
- Validation logic (reject ClusterIP, missing hostname, missing NodePort IP)
- Tag building with `kind:Service`

### Integration Tests

- Mock router-hosts client
- Full reconciliation cycle for LoadBalancer
- Full reconciliation cycle for NodePort
- Deletion with grace period

## Scope

- ~200-300 lines of new code in `service.rs`
- Minimal changes to `mod.rs` and `main.rs`
- No config schema changes
- No new annotations (reuses existing)

## Future Considerations

Not in scope for this implementation:

- ExternalName Service support (maps to external hostname, not IP)
- Headless Service support (no single IP)
- Multi-IP LoadBalancer support (only first IP used)
