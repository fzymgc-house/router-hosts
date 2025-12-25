# router-hosts-operator Design

**Status:** Draft
**Created:** 2025-12-24
**Author:** Claude (with Sean)

## Overview

router-hosts-operator is a Kubernetes controller that watches Ingress and Traefik IngressRoute resources and synchronizes hostnames to a router-hosts server for internal DNS resolution.

### Use Cases

- **Homelab/internal DNS** - Services in k8s automatically get internal DNS entries
- **Split-horizon DNS** - External DNS handled elsewhere, internal network resolves to internal IPs
- **Router integration** - Router uses hosts entries driven by k8s ingress definitions

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Kubernetes Cluster                          │
│                                                                   │
│  ┌─────────────┐  ┌──────────────────┐  ┌────────────────────┐  │
│  │   Ingress   │  │  IngressRoute    │  │  IngressRouteTCP   │  │
│  │ (annotated) │  │   (annotated)    │  │    (annotated)     │  │
│  └──────┬──────┘  └────────┬─────────┘  └─────────┬──────────┘  │
│         │                  │                      │              │
│         └──────────────────┼──────────────────────┘              │
│                            ▼                                     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              router-hosts-operator                           ││
│  │  ┌─────────────┐ ┌──────────────┐ ┌───────────────────────┐ ││
│  │  │ Reconcilers │ │ IP Resolver  │ │ Deletion Scheduler    │ ││
│  │  └─────────────┘ └──────────────┘ └───────────────────────┘ ││
│  └──────────────────────────┬──────────────────────────────────┘│
│                             │ gRPC/mTLS                          │
└─────────────────────────────┼────────────────────────────────────┘
                              ▼
                    ┌──────────────────┐
                    │  router-hosts    │
                    │  server (router) │
                    └──────────────────┘
```

The operator runs as a Deployment with leader election. It watches annotated resources, extracts hostnames, resolves target IPs, and calls the router-hosts gRPC API to create/update/delete entries.

## Custom Resource Definitions

### RouterHostsConfig (cluster-scoped, singleton)

```yaml
apiVersion: router-hosts.fzymgc.house/v1alpha1
kind: RouterHostsConfig
metadata:
  name: default
spec:
  # Connection to router-hosts server
  server:
    endpoint: "router.lan:50051"
    tlsSecretRef:
      name: router-hosts-mtls
      namespace: router-hosts-system

  # IP resolution strategy (ordered fallback)
  ipResolution:
    - type: IngressController
      serviceName: traefik
      serviceNamespace: traefik-system
    - type: Static
      address: "192.168.1.100"

  # Deletion behavior
  deletion:
    gracePeriodSeconds: 300  # 5 minute TTL before removal

  # Tags added to all managed entries
  defaultTags:
    - "k8s-operator"
    - "cluster:homelab"
```

### HostMapping (namespaced, explicit entries)

```yaml
apiVersion: router-hosts.fzymgc.house/v1alpha1
kind: HostMapping
metadata:
  name: external-service
  namespace: default
spec:
  hostname: legacy-app.example.com
  ipAddress: 10.0.0.50  # Optional, uses ipResolution if omitted
  aliases:
    - legacy.local
  tags:
    - "external"
status:
  synced: true
  routerHostsId: "01H5..."
  lastSyncTime: "2024-01-15T10:30:00Z"
  conditions:
    - type: Synced
      status: "True"
      lastTransitionTime: "2024-01-15T10:30:00Z"
      reason: Success
      message: "Host synced to router-hosts"
```

## Annotations & Resource Selection

### Opt-in Annotation

Resources must have this annotation to be processed:

```yaml
router-hosts.fzymgc.house/enabled: "true"
```

### Optional Override Annotations

| Annotation | Purpose |
|------------|---------|
| `router-hosts.fzymgc.house/ip-address` | Override resolved IP for this resource |
| `router-hosts.fzymgc.house/tags` | Additional tags (comma-separated) |
| `router-hosts.fzymgc.house/aliases` | Custom aliases (comma-separated) |
| `router-hosts.fzymgc.house/grace-period` | Override deletion grace period (seconds) |

### Watched Resources

| Resource | API Group | Hostname Extraction |
|----------|-----------|---------------------|
| Ingress | networking.k8s.io/v1 | `spec.rules[].host` |
| IngressRoute | traefik.io/v1alpha1 | Parse `Host()` from `spec.routes[].match` |
| IngressRouteTCP | traefik.io/v1alpha1 | Parse `HostSNI()` from `spec.routes[].match` |
| HostMapping | router-hosts.fzymgc.house/v1alpha1 | `spec.hostname` directly |

### Match Parsing (Traefik)

Simple regex extraction - not a full expression parser:

```
Host(`foo.example.com`)           → ["foo.example.com"]
Host(`a.com`) || Host(`b.com`)    → ["a.com", "b.com"]
HostSNI(`db.example.com`)         → ["db.example.com"]
```

Complex boolean logic ignored - extract all Host/HostSNI values.

## Reconciliation & State Management

### Adoption vs Creation

When the operator first sees a hostname it needs to manage:

1. **Search router-hosts** for existing entry with that hostname
2. **If exists without `k8s-operator` tag** → Adopt it:
   - Add operator tags including `pre-existing:true`
   - Update IP/aliases if needed
3. **If exists with `k8s-operator` tag** → Already managed, update as needed
4. **If not exists** → Create new entry (no `pre-existing` tag)

### Ownership Tags

Every managed entry gets these tags:

```
k8s-operator                        # Ownership marker
cluster:<cluster-name>              # From config
source:<resource-uid>               # Links back to k8s resource
namespace:<namespace>               # For filtering
kind:<Ingress|IngressRoute|...>     # Resource type
pre-existing:true                   # Only if adopted, not created
```

### Deletion Behavior

| Entry State | Action |
|-------------|--------|
| Has `pre-existing:true` | Remove all operator tags, leave entry intact |
| No `pre-existing` tag | Schedule for deletion after grace period |

This ensures manually-created entries survive operator lifecycle.

### Deletion Scheduler

When a hostname is removed or resource deleted:

1. Entry marked with `pending-deletion:<timestamp>` tag
2. Background task checks pending deletions
3. After grace period expires → `DeleteHost` (or remove tags if pre-existing)
4. If resource reappears before expiry → remove pending tag, keep entry

### Leader Election

Uses `coordination.k8s.io/v1` Lease in the operator namespace. Only the leader:
- Runs reconciliation loops
- Processes deletion queue
- Connects to router-hosts server

Standby replicas watch the lease, ready to take over.

## Crate Structure

```
router-hosts/
├── crates/
│   ├── router-hosts-common/       # Existing: proto, validation
│   ├── router-hosts-storage/      # Existing: storage backends
│   ├── router-hosts/              # Existing: main binary
│   ├── router-hosts-duckdb/       # Existing: DuckDB variant
│   ├── router-hosts-e2e/          # Existing: E2E tests
│   └── router-hosts-operator/     # NEW
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── config.rs          # CRD definitions
│           ├── controllers/
│           │   ├── mod.rs
│           │   ├── ingress.rs
│           │   ├── ingressroute.rs
│           │   ├── ingressroutetcp.rs
│           │   └── hostmapping.rs
│           ├── resolver.rs        # IP resolution strategies
│           ├── client.rs          # router-hosts gRPC client wrapper
│           ├── deletion.rs        # TTL-based deletion scheduler
│           └── matcher.rs         # Traefik match expression parser
```

### Key Dependencies

```toml
[dependencies]
router-hosts-common = { path = "../router-hosts-common" }

# Kubernetes
kube = { version = "0.96", features = ["runtime", "derive"] }
k8s-openapi = { version = "0.23", features = ["v1_30"] }

# Async runtime
tokio = { version = "1", features = ["full"] }

# gRPC client
tonic = "0.12"
```

## Error Handling & Observability

### Error Categories

| Error Type | Handling | Status Condition |
|------------|----------|------------------|
| router-hosts unreachable | Exponential backoff, requeue | `Ready=False`, reason `ServerUnreachable` |
| mTLS auth failure | Log error, don't retry until secret changes | `Ready=False`, reason `AuthenticationFailed` |
| Invalid hostname/IP | Skip entry, log warning | `Synced=False`, reason `ValidationFailed` |
| Ingress controller IP not found | Fall through to next resolution strategy | N/A (fallback) |
| Conflict (version mismatch) | Refetch and retry | Transient, auto-recovers |

### Metrics (Prometheus)

```
router_hosts_operator_synced_entries{cluster,namespace,kind}    # Gauge
router_hosts_operator_sync_errors_total{reason}                 # Counter
router_hosts_operator_sync_duration_seconds                     # Histogram
router_hosts_operator_pending_deletions                         # Gauge
router_hosts_operator_server_connected                          # Gauge (0/1)
```

### Events

Emit Kubernetes Events on source resources:

- `SyncSucceeded` - entries synced successfully
- `SyncFailed` - sync error with reason
- `EntryAdopted` - pre-existing entry adopted
- `EntryScheduledForDeletion` - grace period started
- `EntryDeleted` - removed from router-hosts

## Deployment

### Helm Chart Structure

```
charts/router-hosts-operator/
├── Chart.yaml
├── values.yaml
├── crds/
│   ├── routerhostsconfig.yaml
│   └── hostmapping.yaml
├── templates/
│   ├── deployment.yaml
│   ├── serviceaccount.yaml
│   ├── clusterrole.yaml
│   ├── clusterrolebinding.yaml
│   ├── role.yaml              # Namespace-scoped for lease
│   ├── rolebinding.yaml
│   ├── servicemonitor.yaml    # Optional Prometheus
│   └── secret.yaml            # Optional mTLS template
```

### RBAC Requirements

```yaml
# ClusterRole
rules:
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses", "ingresses/status"]
    verbs: ["get", "list", "watch", "patch"]

  - apiGroups: ["traefik.io"]
    resources: ["ingressroutes", "ingressroutetcps"]
    verbs: ["get", "list", "watch"]

  - apiGroups: ["router-hosts.fzymgc.house"]
    resources: ["routerhostsconfigs", "hostmappings", "hostmappings/status"]
    verbs: ["get", "list", "watch", "patch", "update"]

  - apiGroups: [""]
    resources: ["services"]
    verbs: ["get", "list"]

  - apiGroups: [""]
    resources: ["events"]
    verbs: ["create", "patch"]

# Role (in operator namespace)
rules:
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "create", "update"]
```

### Deployment Highlights

- 2 replicas (HA with leader election)
- Resource limits: 128Mi memory, 100m CPU
- Secret volume mount for mTLS certificates
- Liveness/readiness probes on `/healthz`

## Testing Strategy

### Unit Tests

| Component | Test Focus |
|-----------|------------|
| `matcher.rs` | Regex extraction of Host()/HostSNI() from match expressions |
| `resolver.rs` | IP resolution fallback chain, annotation overrides |
| `deletion.rs` | TTL scheduling, pre-existing entry preservation |
| `config.rs` | CRD validation, defaults |

### Integration Tests

Using `kube-rs` test fixtures with a mock API server:

- Reconciler correctly processes Ingress → builds correct AddHostRequest
- Annotation changes trigger updates
- Resource deletion schedules cleanup
- Pre-existing entry adoption adds correct tags
- Grace period expiry triggers deletion (or tag removal for pre-existing)

### E2E Tests

Extend existing E2E suite or create parallel:

- Create Ingress → verify host in router-hosts
- IngressRoute/TCP → verify hosts
- Delete resource → verify grace period behavior
- Pre-existing entry preservation
- Leader election failover

## Future Considerations

- Multi-cluster support (sync from multiple clusters to one router-hosts)
- Webhook validation for CRDs
- Full Traefik match expression parser (complex boolean logic)
- Integration with external-dns as alternative backend
