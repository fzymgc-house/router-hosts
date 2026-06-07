# router-hosts-operator Helm Chart

Kubernetes operator that syncs Traefik `IngressRoute` hostnames and explicit
`HostMapping` resources to a router-hosts server over mTLS.

The operator binary ships inside the combined `router-hosts` image; this chart
overrides the image entrypoint to run it. Configuration is passed entirely as
command-line flags (there is no `RouterHostsConfig` CRD).

## Prerequisites

- Kubernetes 1.31+
- Helm 3.0+
- router-hosts server with mTLS enabled
- Traefik CRDs installed (for `IngressRoute`/`IngressRouteTCP` syncing)

## Installation

### 1. Create the mTLS Secret

The operator reads its client certificate, key, and CA from files mounted from a
Secret. **The Secret must live in the operator's own namespace** — it is mounted
as a volume, not read cross-namespace — and contain the keys `ca.crt`, `tls.crt`,
and `tls.key`:

```bash
kubectl create namespace router-hosts-system

kubectl create secret generic router-hosts-mtls \
  -n router-hosts-system \
  --from-file=ca.crt=/path/to/ca.crt \
  --from-file=tls.crt=/path/to/client.crt \
  --from-file=tls.key=/path/to/client.key
```

### 2. Install the Chart

From the OCI registry (recommended):

```bash
helm install router-hosts-operator \
  oci://ghcr.io/fzymgc-house/charts/router-hosts-operator \
  --namespace router-hosts-system \
  --version VERSION \
  --set routerHosts.serverAddress=router.example.com:50051 \
  --set routerHosts.defaultIngressIP=192.168.1.100
```

Or from a source checkout:

```bash
helm install router-hosts-operator charts/router-hosts-operator \
  --namespace router-hosts-system
```

### 3. Customize Values

Create a `values.yaml`:

```yaml
routerHosts:
  # gRPC server address (--server-address)
  serverAddress: "router.example.com:50051"

  # IP assigned to hosts extracted from IngressRoutes (--default-ingress-ip).
  # Required for the IngressRoute controller to create usable entries.
  defaultIngressIP: "192.168.1.100"

  # mTLS Secret, mounted from this release's namespace.
  tlsSecret:
    name: router-hosts-mtls
    mountPath: /etc/router-hosts/tls

# Two or more replicas auto-enable leader election.
replicaCount: 2

resources:
  limits:
    cpu: 200m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

Then install with custom values:

```bash
helm install router-hosts-operator charts/router-hosts-operator \
  -f values.yaml \
  --namespace router-hosts-system
```

## Configuration

### Key Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository (combined router-hosts image) | `ghcr.io/fzymgc-house/router-hosts` |
| `image.tag` | Image tag | Chart appVersion |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of replicas | `1` |
| `leaderElection.enabled` | Enable leader election (`--leader-elect`) | unset (auto-enabled when replicas >= 2) |
| `routerHosts.serverAddress` | gRPC server address (`--server-address`) | `router.lan:50051` |
| `routerHosts.defaultIngressIP` | IP for IngressRoute-derived hosts (`--default-ingress-ip`) | `""` |
| `routerHosts.tlsSecret.name` | mTLS Secret name (mounted from the release namespace) | `router-hosts-mtls` |
| `routerHosts.tlsSecret.mountPath` | Mount path for the mTLS Secret | `/etc/router-hosts/tls` |
| `metrics.bindAddress` | Metrics endpoint (`--metrics-bind-address`); `"0"` disables | `":8080"` |
| `healthCheck.port` | Health probe HTTP port (`--health-probe-bind-address`) | `8081` |
| `healthCheck.livenessProbe.*` | Liveness probe timing settings | See values.yaml |
| `healthCheck.readinessProbe.*` | Readiness probe timing settings | See values.yaml |
| `healthCheck.startupProbe.*` | Startup probe timing settings | See values.yaml |
| `serviceAccount.create` | Create ServiceAccount | `true` |
| `rbac.create` | Create RBAC resources | `true` |

> Tagging is fixed in the binary and not configurable via this chart:
> IngressRoute-derived hosts get `kubernetes`, `traefik`, and `ingress`;
> `HostMapping` entries get only the `tags` from their spec. The log level
> (`info`, JSON) is also fixed.

### Health Check Endpoints

The operator serves HTTP probe endpoints on `healthCheck.port`:

| Endpoint | Purpose | Behavior |
|----------|---------|----------|
| `/healthz` | Liveness | 200 OK while the process is alive (ping check) |
| `/readyz` | Readiness + Startup | 200 OK once the manager is serving (ping check) |

### RBAC Permissions

With `rbac.create: true`, the chart grants the cluster permissions the
controllers actually use:

- **IngressRoutes / IngressRouteTCP** (`traefik.io/v1alpha1`): get, list, watch,
  update, patch — the controller writes a finalizer and the host-id annotation
  back to the object.
- **HostMappings** (`router-hosts.fzymgc.house/v1alpha1`): get, list, watch,
  update, patch, plus the `status` and `finalizers` subresources.

When leader election is enabled (including auto-enabled for `replicaCount >= 2`),
a namespaced Role additionally grants:

- **Leases** (`coordination.k8s.io/v1`): get, list, watch, create, update, patch, delete
- **Events** (`""`): create, patch

The mTLS Secret is consumed via a volume mount and requires no RBAC.

## High Availability

The operator supports multiple replicas using Kubernetes Lease-based leader
election (controller-runtime). Only the leader reconciles; others stand by and
take over on failover. Leader election is auto-enabled when `replicaCount >= 2`,
or set `leaderElection.enabled` explicitly. The lease ID is
`router-hosts-operator.fzymgc.house`; lease timings are managed by
controller-runtime and are not tunable through this chart.

```yaml
replicaCount: 2
# leaderElection:
#   enabled: true   # override the replicaCount>=2 default
```

## Usage

### Sync Traefik IngressRoutes

The operator watches `IngressRoute` and `IngressRouteTCP` resources and creates a
host entry (at `routerHosts.defaultIngressIP`) for each hostname it finds in the
``Host(`...`)`` / ``HostSNI(`...`)`` match rules. No annotation is required.

```yaml
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: myapp
  namespace: default
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`myapp.example.com`)
      kind: Rule
      services:
        - name: myapp
          port: 80
```

### Create Explicit Host Mappings

For hosts not backed by an IngressRoute:

```yaml
apiVersion: router-hosts.fzymgc.house/v1alpha1
kind: HostMapping
metadata:
  name: legacy-app
  namespace: default
spec:
  ip: "10.0.0.50"            # required
  hostname: legacy.example.com # required
  aliases:                    # optional
    - legacy.local
  tags:                       # optional
    - external
```

## Upgrading

```bash
helm upgrade router-hosts-operator charts/router-hosts-operator \
  -f values.yaml \
  --namespace router-hosts-system
```

## Uninstalling

```bash
helm uninstall router-hosts-operator --namespace router-hosts-system
```

CRDs are not removed automatically. To delete the `HostMapping` CRD:

```bash
kubectl delete crd hostmappings.router-hosts.fzymgc.house
```

## Troubleshooting

### Check Operator Logs

```bash
kubectl logs -n router-hosts-system -l app.kubernetes.io/name=router-hosts-operator -f
```

### Check HostMapping Status

```bash
kubectl get hostmapping -A
kubectl describe hostmapping <name> -n <namespace>
```

### Common Issues

- **Operator fails to start / TLS errors**: confirm the mTLS Secret exists in the
  operator's namespace and contains `ca.crt`, `tls.crt`, `tls.key`, and that the
  client certificate is trusted by the server's CA.
- **IngressRoute hosts created with no IP**: set `routerHosts.defaultIngressIP`.
- **`forbidden` errors in logs**: ensure `rbac.create: true` (or that equivalent
  RBAC exists) so the controllers can write finalizers/annotations.

## Development

```bash
# Lint the chart
helm lint charts/router-hosts-operator

# Render templates
helm template test charts/router-hosts-operator

# Test with custom values
helm template test charts/router-hosts-operator -f my-values.yaml
```

## License

Same as router-hosts project license.
