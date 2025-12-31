# Kubernetes Operator

The router-hosts Kubernetes operator automates DNS registration for Kubernetes workloads. It watches Traefik IngressRoutes and custom HostMapping resources, automatically creating and maintaining corresponding host entries in the router-hosts server.

## Overview

**Key features:**
- Watches Traefik `IngressRoute` and `IngressRouteTCP` resources
- Supports explicit `HostMapping` CRD for non-Ingress workloads
- Automatic IP resolution from ingress controllers or static addresses
- Graceful deletion with configurable grace periods
- Leader election for high availability deployments
- Health endpoints for Kubernetes probes

## Installation

The operator is deployed via Helm chart. See [charts/router-hosts-operator/README.md](../charts/router-hosts-operator/README.md) for complete installation instructions.

**Quick start:**

```bash
# Create mTLS secret
kubectl create namespace router-hosts-system
kubectl create secret generic router-hosts-mtls \
  -n router-hosts-system \
  --from-file=ca.crt=/path/to/ca.crt \
  --from-file=tls.crt=/path/to/client.crt \
  --from-file=tls.key=/path/to/client.key

# Install operator
helm install router-hosts-operator charts/router-hosts-operator \
  --namespace router-hosts-system
```

## Custom Resource Definitions

### RouterHostsConfig

Cluster-scoped configuration for the operator. Only one instance should exist.

```yaml
apiVersion: router-hosts.fzymgc.house/v1alpha1
kind: RouterHostsConfig
metadata:
  name: default
spec:
  # gRPC endpoint of router-hosts server
  endpoint: "router.lan:50051"

  # Reference to mTLS credentials Secret
  tlsSecretRef:
    name: router-hosts-mtls
    namespace: router-hosts-system

  # IP resolution strategies (tried in order)
  ipResolution:
    - type: ingressController
      serviceName: traefik
      serviceNamespace: traefik-system
    - type: static
      address: "192.168.1.100"

  # Grace period before deletion (seconds)
  deletion:
    gracePeriodSeconds: 300

  # Tags added to all entries
  defaultTags:
    - k8s-operator
    - cluster:production
```

### HostMapping

Namespace-scoped resource for explicit host mappings. Use this for workloads not exposed via Ingress.

```yaml
apiVersion: router-hosts.fzymgc.house/v1alpha1
kind: HostMapping
metadata:
  name: legacy-app
  namespace: default
spec:
  # Required: hostname to register
  hostname: legacy.example.com

  # Optional: explicit IP (uses IP resolution if omitted)
  ipAddress: "10.0.0.50"

  # Optional: hostname aliases
  aliases:
    - legacy.local
    - legacy.lan

  # Optional: additional tags
  tags:
    - external
    - legacy
```

**Status fields:**

| Field | Description |
|-------|-------------|
| `synced` | Whether entry is synced to router-hosts |
| `routerHostsId` | The router-hosts entry ID (if synced) |
| `lastSyncTime` | Last successful sync timestamp |
| `error` | Error message if sync failed |
| `conditions` | Kubernetes-style conditions (`Synced`, `Ready`) |

**kubectl output:**

```bash
$ kubectl get hostmapping -A
NAMESPACE   NAME         HOSTNAME              IP           SYNCED
default     legacy-app   legacy.example.com    10.0.0.50    True
```

### Traefik Resources

The operator watches Traefik CRDs when annotated with `router-hosts.fzymgc.house/enabled: "true"`.

**IngressRoute:**

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: myapp
  annotations:
    router-hosts.fzymgc.house/enabled: "true"
spec:
  routes:
    - match: Host(`myapp.example.com`)
      kind: Rule
      services:
        - name: myapp
          port: 80
```

**IngressRouteTCP:**

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRouteTCP
metadata:
  name: postgres
  annotations:
    router-hosts.fzymgc.house/enabled: "true"
spec:
  routes:
    - match: HostSNI(`postgres.example.com`)
      services:
        - name: postgres
          port: 5432
```

## Annotations

Control operator behavior per-resource using annotations:

| Annotation | Description | Example |
|------------|-------------|---------|
| `router-hosts.fzymgc.house/enabled` | Enable sync for this resource | `"true"` |
| `router-hosts.fzymgc.house/ip-address` | Override resolved IP | `"192.168.1.200"` |
| `router-hosts.fzymgc.house/tags` | Additional tags (comma-separated) | `"production,public"` |
| `router-hosts.fzymgc.house/aliases` | Hostname aliases (comma-separated) | `"app.local,app.lan"` |
| `router-hosts.fzymgc.house/grace-period` | Override deletion grace period (seconds) | `"600"` |

## IP Resolution

The operator resolves IP addresses using a fallback chain:

1. **Annotation override**: `router-hosts.fzymgc.house/ip-address` annotation
2. **HostMapping spec**: `ipAddress` field (for HostMapping resources only)
3. **Ingress controller**: LoadBalancer IP from configured Service
4. **Static fallback**: Configured static address

### Resolution Strategies

**IngressController**: Discovers IP from a Kubernetes Service (typically the ingress controller):

```yaml
ipResolution:
  - type: ingressController
    serviceName: traefik
    serviceNamespace: traefik-system
```

The operator checks:
1. Service LoadBalancer `.status.loadBalancer.ingress[*].ip`
2. Service ClusterIP (fallback)

**Static**: Fixed IP address:

```yaml
ipResolution:
  - type: static
    address: "192.168.1.100"
```

## Deletion Handling

When a watched resource is deleted, the operator:

1. Marks the host entry with a `pending-deletion:<timestamp>` tag
2. Waits for the grace period (default: 300 seconds)
3. Deletes the entry from router-hosts after grace period expires

This prevents DNS disruptions during rolling updates or brief resource deletions.

**Override per-resource:**

```yaml
annotations:
  router-hosts.fzymgc.house/grace-period: "600"  # 10 minutes
```

## Observability

### Health Endpoints

The operator exposes HTTP health endpoints:

| Endpoint | Purpose | Behavior |
|----------|---------|----------|
| `/healthz` | Liveness | Returns 200 if process is alive |
| `/readyz` | Readiness | Returns 200 if startup complete AND router-hosts server reachable |

Kubernetes probes:
- **Startup**: `/readyz` - verifies server connectivity (allows 150s for initial connection)
- **Liveness**: `/healthz` - checks process health
- **Readiness**: `/readyz` - removes from service if router-hosts unreachable

### Logging

Configure log level via Helm values:

```yaml
logging:
  level: info  # trace, debug, info, warn, error
```

View logs:

```bash
kubectl logs -n router-hosts-system -l app.kubernetes.io/name=router-hosts-operator -f
```

## High Availability

### Leader Election

For high availability, run multiple replicas with leader election. Only one replica actively reconciles; others wait as standby.

**Enable HA:**

```yaml
replicaCount: 2

# Auto-enabled when replicas >= 2, or explicitly:
leaderElection:
  enabled: true
  leaseDurationSeconds: 15  # Lease TTL
  renewIntervalSeconds: 5   # Renewal interval
```

**How it works:**

1. On startup, each pod attempts to acquire the Kubernetes Lease
2. First pod to acquire becomes leader, starts controllers
3. Other pods block waiting for leadership
4. Leader renews the lease every 5 seconds
5. If leadership is lost, pod exits and Kubernetes restarts it
6. Restarted pod re-enters the acquire-or-wait cycle

**Features:**
- Automatic failover if leader crashes
- Zero-downtime rolling updates
- Acquire-or-exit pattern ensures clean state

### RBAC for Leader Election

When leader election is enabled, additional RBAC permissions are required:

```yaml
# Automatically added by Helm chart when leaderElection.enabled or replicaCount >= 2
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "create", "update"]
```

## Troubleshooting

### Check Operator Status

```bash
# Pod status
kubectl get pods -n router-hosts-system

# Operator logs
kubectl logs -n router-hosts-system -l app.kubernetes.io/name=router-hosts-operator

# Config status
kubectl get routerhostsconfig -o yaml
```

### Check HostMapping Status

```bash
# List all HostMappings
kubectl get hostmapping -A

# Detailed status
kubectl describe hostmapping <name> -n <namespace>
```

### Common Issues

**Operator fails to start:**
- Verify mTLS Secret exists with keys: `ca.crt`, `tls.crt`, `tls.key`
- Check Secret namespace matches `tlsSecretRef.namespace`

**Resources not syncing:**
- Verify annotation `router-hosts.fzymgc.house/enabled: "true"` is present
- Check HostMapping status for error messages
- Ensure RouterHostsConfig exists and is valid

**IP resolution failing:**
- Verify ingress controller Service exists
- Check Service has LoadBalancer IP or ClusterIP
- Try adding static fallback strategy

**Connectivity issues:**
- Check `/readyz` endpoint returns 200
- Verify router-hosts server is reachable from cluster
- Confirm TLS certificates are valid and not expired

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ IngressRoute│  │IngressRoute │  │    HostMapping      │  │
│  │   (Traefik) │  │    TCP      │  │       (CRD)         │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │             │
│         └────────────────┼─────────────────────┘             │
│                          │                                   │
│                          ▼                                   │
│              ┌───────────────────────┐                       │
│              │  router-hosts-operator │                      │
│              │  ┌─────────────────┐  │                       │
│              │  │ Leader Election │  │ (if HA enabled)      │
│              │  └────────┬────────┘  │                       │
│              │           ▼           │                       │
│              │  ┌─────────────────┐  │                       │
│              │  │   Controllers   │  │                       │
│              │  │ • IngressRoute  │  │                       │
│              │  │ • IngressTCP    │  │                       │
│              │  │ • HostMapping   │  │                       │
│              │  └────────┬────────┘  │                       │
│              │           │           │                       │
│              │  ┌────────▼────────┐  │                       │
│              │  │  IP Resolution  │  │                       │
│              │  └────────┬────────┘  │                       │
│              └───────────┼───────────┘                       │
│                          │                                   │
└──────────────────────────┼───────────────────────────────────┘
                           │ gRPC/mTLS
                           ▼
                ┌─────────────────────┐
                │  router-hosts server │
                │    (/etc/hosts)      │
                └─────────────────────┘
```

## See Also

- [Helm Chart README](../charts/router-hosts-operator/README.md) - Installation and configuration
- [Architecture](../contributing/architecture.md) - Overall system design
- [Operations](operations.md) - Server operations and monitoring
