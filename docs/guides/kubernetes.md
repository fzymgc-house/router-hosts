# Kubernetes Operator

The router-hosts Kubernetes operator automates DNS registration for Kubernetes workloads. It watches Traefik `IngressRoute`/`IngressRouteTCP` resources and custom `HostMapping` resources, creating and maintaining the corresponding host entries in the router-hosts server over gRPC/mTLS.

## Overview

**What the operator does:**

- Watches Traefik `IngressRoute` and `IngressRouteTCP` resources and registers the hostnames in their routing rules.
- Reconciles the `HostMapping` CRD for explicit, non-Ingress host entries.
- Talks to the router-hosts server over gRPC with mutual TLS.
- Cleans up host entries when the source resource is deleted, using finalizers.
- Exposes Prometheus metrics and Kubernetes health probes, and supports leader election for HA.

**What it does not do** (despite earlier Rust-operator documentation): there is **no** `RouterHostsConfig` CRD, **no** Kubernetes `Service` controller, and **no** per-resource annotation API. Configuration is entirely via command-line flags set by the Helm chart, and IngressRoutes are watched cluster-wide without an opt-in annotation. See [Configuration](#configuration).

## Installation

The operator is deployed via Helm chart. See the [Helm Chart README](https://github.com/fzymgc-house/router-hosts/blob/main/charts/router-hosts-operator/README.md) for complete installation instructions.

**Quick start:**

```bash
# Create the mTLS client secret in the operator's namespace
kubectl create namespace router-hosts-system
kubectl create secret generic router-hosts-mtls \
  -n router-hosts-system \
  --from-file=ca.crt=/path/to/ca.crt \
  --from-file=tls.crt=/path/to/client.crt \
  --from-file=tls.key=/path/to/client.key

# Install the operator
helm install router-hosts-operator charts/router-hosts-operator \
  --namespace router-hosts-system \
  --set routerHosts.serverAddress=router.lan:50051 \
  --set routerHosts.defaultIngressIP=192.168.1.100
```

## Configuration

The operator has no configuration CRD. It is configured by command-line flags, which the Helm chart renders from `values.yaml`. The most relevant values:

| Helm value | Operator flag | Purpose |
|------------|---------------|---------|
| `routerHosts.serverAddress` | `--server-address` | gRPC address (`host:port`) of the router-hosts server |
| `routerHosts.defaultIngressIP` | `--default-ingress-ip` | IP assigned to every host extracted from IngressRoutes |
| `routerHosts.tlsSecret` | `--tls-ca` / `--tls-cert` / `--tls-key` | mTLS client identity (Secret mounted into the pod) |
| `replicaCount` (≥ 2) | `--leader-elect` | Enables leader election automatically |
| `metrics.bindAddress` | `--metrics-bind-address` | Prometheus metrics listen address (`"0"` disables) |
| `healthCheck.port` | `--health-probe-bind-address` | Health/readiness probe HTTP port |

> **`defaultIngressIP` is required for IngressRoutes.** If it is empty, the IngressRoute controller logs a warning and creates host entries with no IP. Leave it empty only if you exclusively use `HostMapping` resources (which carry their own IP).

The mTLS Secret **must** live in the operator's own namespace; it is mounted into the pod rather than referenced cross-namespace.

## Custom Resources

### HostMapping

Namespace-scoped resource for explicit host mappings. Use it for workloads not exposed via a Traefik IngressRoute.

```yaml
apiVersion: router-hosts.fzymgc.house/v1alpha1
kind: HostMapping
metadata:
  name: legacy-app
  namespace: default
spec:
  # Required: hostname to register
  hostname: legacy.example.com

  # Required: IPv4 or IPv6 address for the entry
  ip: "10.0.0.50"

  # Optional: hostname aliases (additional names for the same IP)
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
| `phase` | Sync state: `Pending`, `Synced`, or `Error` |
| `message` | Human-readable detail about the current phase |
| `hostId` | The router-hosts server-assigned entry ID |
| `hostVersion` | Server version string (optimistic concurrency) |
| `lastSyncTime` | Timestamp of the last successful sync |
| `conditions` | Standard Kubernetes conditions (`Synced`) |

**kubectl output** (short name `hm`):

```bash
$ kubectl get hostmapping -A
NAMESPACE   NAME         IP          HOSTNAME             PHASE    AGE
default     legacy-app   10.0.0.50   legacy.example.com   Synced   2m
```

### Traefik IngressRoute / IngressRouteTCP

The operator watches **all** `IngressRoute` and `IngressRouteTCP` resources cluster-wide — there is no opt-in annotation. For each resource it extracts hostnames from the routing rules and registers them:

- `IngressRoute`: hostnames inside `` Host(`…`) `` in `spec.routes[].match`.
- `IngressRouteTCP`: hostnames inside `` HostSNI(`…`) `` in `spec.routes[].match`.

Every extracted hostname is registered with the configured `--default-ingress-ip` and tagged `kubernetes`, `traefik`, `ingress`. Hostnames that fail validation are logged and skipped.

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: myapp
spec:
  routes:
    - match: Host(`myapp.example.com`)
      kind: Rule
      services:
        - name: myapp
          port: 80
```

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRouteTCP
metadata:
  name: postgres
spec:
  routes:
    - match: HostSNI(`postgres.example.com`)
      services:
        - name: postgres
          port: 5432
```

The operator records the hostname → server-entry-ID map it created in an internal `router-hosts.fzymgc.house/host-ids` annotation on the resource. This annotation is managed by the operator; do not edit it.

## IP Assignment

There is no IP-resolution strategy chain. IP comes from exactly one place per resource type:

- **HostMapping**: the required `spec.ip` field.
- **IngressRoute / IngressRouteTCP**: the operator-wide `--default-ingress-ip` flag (Helm `routerHosts.defaultIngressIP`). The same IP is used for every IngressRoute-derived host.

If you need different IPs for different IngressRoute hosts, register those hosts with `HostMapping` resources instead.

## Reconciliation

The operator reconciles a resource when its spec changes, when it is created or deleted, and on the controller-runtime periodic resync. Its own status writes are deliberately **not** reconciled, so a converged resource stays quiescent instead of hot-looping.

**Drift correction.** Because status-only writes are filtered, a host edited **directly on the router-hosts server** (out-of-band, not through Kubernetes) is reconverged on the next spec change, an operator restart (a fresh informer LIST re-runs every resource), or the periodic resync. The resync interval is the controller-runtime `SyncPeriod` (default ~10h); the operator uses that default and does not currently expose a flag to change it, so absent a spec change or restart, out-of-band drift persists until the next resync.

If a host entry is **deleted** out-of-band while its `HostMapping` still exists, the next reconcile recreates it from the desired spec — the Kubernetes resource is the source of truth.

## Deletion

The operator attaches a finalizer to every resource it manages (`router-hosts.fzymgc.house/host-cleanup` for HostMappings, `router-hosts.fzymgc.house/ingressroute-cleanup` for IngressRoutes). When the resource is deleted, the operator deletes the corresponding host entries from the router-hosts server **immediately**, then removes the finalizer.

There is no deletion grace period and no `pending-deletion` tagging. If the server is unreachable during cleanup, the finalizer is retained and the delete is retried on the next reconcile, so the Kubernetes object remains until cleanup succeeds.

## Observability

### Health Endpoints

The operator exposes two HTTP endpoints on `--health-probe-bind-address` (Helm `healthCheck.port`, default `8081`):

| Endpoint | Probe | Behavior |
|----------|-------|----------|
| `/healthz` | Liveness | Returns 200 while the process is alive |
| `/readyz` | Readiness / startup | Returns 200 once the manager has started |

Both endpoints are process-health pings; they do **not** test gRPC connectivity to the router-hosts server. The chart's startup probe allows roughly 150s (`startupProbe.periodSeconds` × `failureThreshold`) before liveness/readiness apply.

### Metrics

Prometheus metrics are served on `--metrics-bind-address` (Helm `metrics.bindAddress`, default `:8080`). Set `metrics.bindAddress: "0"` to disable.

### Logging

The operator logs structured JSON to stdout at info level. (Log level is not currently configurable via the chart.)

```bash
kubectl logs -n router-hosts-system -l app.kubernetes.io/name=router-hosts-operator -f
```

## High Availability

Run multiple replicas with leader election so only one replica reconciles at a time; the others stand by.

```yaml
replicaCount: 2   # leader election is auto-enabled when replicaCount >= 2
```

Leader election uses a Kubernetes Lease with ID `router-hosts-operator.fzymgc.house`, managed by controller-runtime. Lease timings are not configurable via the chart. When leader election is enabled, the chart adds RBAC for `coordination.k8s.io/leases`. On loss of leadership the pod exits and is restarted by Kubernetes, re-entering the acquire-or-wait cycle.

## Troubleshooting

### Check operator status

```bash
# Pod status
kubectl get pods -n router-hosts-system

# Operator logs (reconcile errors, gRPC failures, startup warnings)
kubectl logs -n router-hosts-system -l app.kubernetes.io/name=router-hosts-operator
```

Configuration lives in the Deployment's args and the mounted mTLS Secret, not in a CRD:

```bash
kubectl get deployment -n router-hosts-system router-hosts-operator -o jsonpath='{.spec.template.spec.containers[0].args}'
```

### Check HostMapping status

```bash
kubectl get hostmapping -A
kubectl describe hostmapping <name> -n <namespace>
```

The `Synced` condition and `status.message` carry the reason for any failure.

### Common issues

**Operator fails to start:**

- Verify the mTLS Secret exists in the operator namespace with keys `ca.crt`, `tls.crt`, `tls.key`.
- Confirm `routerHosts.serverAddress` points at a reachable gRPC endpoint.

**HostMapping stuck in `Error` / `invalid IP address`:**

- `spec.ip` is required and must be a valid IPv4/IPv6 address. (Older docs and the pre-0.10.2 CRD used `spec.ipAddress`; the field is `spec.ip`.)
- Inspect `status.message` for the server's rejection reason.

**IngressRoute hosts created with an empty IP:**

- Set `routerHosts.defaultIngressIP`. With it empty, the IngressRoute controller logs a warning and creates entries with no IP.

**Hostnames from an IngressRoute are missing:**

- Only `` Host(`…`) `` (IngressRoute) and `` HostSNI(`…`) `` (IngressRouteTCP) patterns are extracted. Invalid hostnames are skipped — check the operator logs.

**Connectivity issues:**

- Confirm the router-hosts server is reachable from the cluster and the mTLS certificates are valid and unexpired. gRPC errors surface in the operator logs on each reconcile.

## Architecture

```text
┌───────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                        │
│   ┌──────────────┐   ┌─────────────────┐   ┌──────────────────┐   │
│   │ IngressRoute │   │ IngressRouteTCP │   │   HostMapping    │   │
│   │   (Traefik)  │   │    (Traefik)    │   │      (CRD)       │   │
│   └──────┬───────┘   └────────┬────────┘   └────────┬─────────┘   │
│          └────────────────────┴─────────────────────┘             │
│                                │                                  │
│                                ▼                                  │
│                 ┌───────────────────────────┐                     │
│                 │   router-hosts-operator   │                     │
│                 │  ┌─────────────────────┐  │                     │
│                 │  │  Leader Election    │  │ (if replicaCount≥2) │
│                 │  └──────────┬──────────┘  │                     │
│                 │             ▼             │                     │
│                 │  ┌─────────────────────┐  │                     │
│                 │  │     Controllers     │  │                     │
│                 │  │ • IngressRoute(TCP) │  │                     │
│                 │  │ • HostMapping       │  │                     │
│                 │  └──────────┬──────────┘  │                     │
│                 └─────────────┼─────────────┘                     │
└───────────────────────────────┼───────────────────────────────────┘
                                │ gRPC / mTLS
                                ▼
                    ┌──────────────────────┐
                    │  router-hosts server │
                    │      (/etc/hosts)    │
                    └──────────────────────┘
```

## See Also

- [Helm Chart README](https://github.com/fzymgc-house/router-hosts/blob/main/charts/router-hosts-operator/README.md) — installation and configuration
- [Architecture](../contributing/architecture.md) — overall system design
- [Operations](operations.md) — server operations and monitoring
