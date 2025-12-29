# Leader Election for HA - Design Document

**Issue**: #154
**Date**: 2025-12-29
**Status**: Approved

## Summary

Implement Kubernetes leader election for the router-hosts operator to enable running multiple replicas safely, with only one actively reconciling at a time.

## Architecture

### Pattern: Acquire or Exit

On startup, attempt to acquire leadership via Kubernetes Lease. If successful, run controllers. If leadership is lost, exit immediately and let Kubernetes restart the pod.

```
┌─────────────────┐     ┌─────────────────┐
│  Pod A (Leader) │     │  Pod B (Standby)│
│  ┌───────────┐  │     │  ┌───────────┐  │
│  │Controllers│  │     │  │  Blocked  │  │
│  │  Running  │◄─┼─────┼──│  Waiting  │  │
│  └───────────┘  │     │  └───────────┘  │
│       ▲         │     │       │         │
│       │         │     │       │         │
│  ┌────┴────┐    │     │  ┌────┴────┐    │
│  │  Lease  │    │     │  │  Lease  │    │
│  │ Renewal │    │     │  │ Acquire │    │
│  └─────────┘    │     │  └─────────┘    │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
    ┌─────────────────────────────────┐
    │   Lease: router-hosts-leader    │
    │   Holder: pod-a                 │
    │   Expires: +15s                 │
    └─────────────────────────────────┘
```

### Key Components

1. `kube-leader-election` crate for Lease management
2. Background task renewing lease every 5s (TTL 15s)
3. Controllers blocked until leadership acquired
4. Process exit on leadership loss (K8s restarts pod)

## Implementation

### Files to Modify

| File | Change |
|------|--------|
| `crates/router-hosts-operator/Cargo.toml` | Add `kube-leader-election` dependency |
| `crates/router-hosts-operator/src/leader.rs` | New module for leader election logic |
| `crates/router-hosts-operator/src/main.rs` | Integrate leader election at startup |
| `crates/router-hosts-operator/src/lib.rs` | Export leader module |
| `charts/.../values.yaml` | Add `leaderElection` config section |
| `charts/.../templates/deployment.yaml` | Add POD_NAME env var, conditional logic |
| `charts/.../templates/role.yaml` | Add Lease permissions |
| `charts/.../README.md` | Document leader election feature |

### Rust Module: `leader.rs`

```rust
use kube_leader_election::{LeaseLock, LeaseLockParams};
use std::time::Duration;

pub struct LeaderElectionConfig {
    pub enabled: bool,
    pub lease_name: String,
    pub namespace: String,
    pub holder_id: String,           // From POD_NAME env var
    pub lease_duration: Duration,    // Default: 15s
    pub renew_interval: Duration,    // Default: 5s
}

pub struct LeaderElection { /* ... */ }

impl LeaderElection {
    /// Block until leadership is acquired
    pub async fn acquire(&self) -> Result<()>;

    /// Spawn renewal loop - exits process on leadership loss
    pub fn spawn_renewal_task(&self) -> JoinHandle<()>;
}
```

### Integration in `main.rs`

```rust
// After loading config, before starting controllers:
if leader_config.enabled {
    info!("Leader election enabled, acquiring leadership...");
    let leader = LeaderElection::new(kube_client.clone(), leader_config)?;

    leader.acquire().await?;  // Blocks until we're leader
    info!("Leadership acquired, starting controllers");

    leader.spawn_renewal_task();  // Background renewal, exits on loss
}

// ... existing controller startup code ...
```

### Helm Values

```yaml
# Leader election for running multiple replicas
leaderElection:
  # Enable leader election (auto-enabled when replicaCount >= 2)
  enabled: false
  # Lease resource name (default: fullname + "-leader")
  leaseName: ""
  # Lease TTL in seconds
  leaseDurationSeconds: 15
  # Renewal interval in seconds
  renewIntervalSeconds: 5
```

### Helm Smart Default

Leader election is automatically enabled when `replicaCount >= 2` unless explicitly disabled:

```yaml
{{- $leaderElectionEnabled := .Values.leaderElection.enabled }}
{{- if and (not (hasKey .Values.leaderElection "enabled")) (ge (int .Values.replicaCount) 2) }}
  {{- $leaderElectionEnabled = true }}
{{- end }}
```

### RBAC for Leases

```yaml
{{- if or .Values.leaderElection.enabled (ge (int .Values.replicaCount) 2) }}
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "create", "update"]
{{- end }}
```

### Environment Variables

```yaml
env:
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
  - name: POD_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
  {{- if $leaderElectionEnabled }}
  - name: LEADER_ELECTION_ENABLED
    value: "true"
  - name: LEADER_ELECTION_LEASE_NAME
    value: {{ include "router-hosts-operator.fullname" . }}-leader
  - name: LEADER_ELECTION_LEASE_DURATION
    value: "{{ .Values.leaderElection.leaseDurationSeconds }}"
  - name: LEADER_ELECTION_RENEW_INTERVAL
    value: "{{ .Values.leaderElection.renewIntervalSeconds }}"
  {{- end }}
```

## Implementation Steps

1. Add `kube-leader-election` dependency to Cargo.toml
2. Create `src/leader.rs` module with `LeaderElection` struct
3. Integrate leader election in `main.rs` startup flow
4. Update Helm `values.yaml` with leaderElection config
5. Update Helm `role.yaml` with conditional Lease RBAC
6. Update Helm `deployment.yaml` with env vars and smart default
7. Update Helm `README.md` to document the feature
8. Add tests and verify with multiple replicas

## Exit Behavior

When the renewal loop detects leadership loss:
1. Log error with details
2. Call `std::process::exit(1)`
3. Kubernetes restarts the pod
4. Pod either re-acquires leadership or waits as standby

## References

- [kube-rs Availability Guide](https://kube.rs/controllers/availability/)
- [kube-leader-election crate](https://github.com/hendrikmaus/kube-leader-election)
- [Kubernetes Leases](https://kubernetes.io/docs/concepts/architecture/leases/)
