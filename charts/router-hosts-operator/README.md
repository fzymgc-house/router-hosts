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
- Gateway API CRDs (`gateway.networking.k8s.io`) installed in the cluster —
  required only when `gateway.enabled` is `true`. This chart does **not**
  bundle these CRDs; install them separately before enabling the value.

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
| `gateway.enabled` | Enable the HTTPRoute/GRPCRoute/TLSRoute controllers (`--enable-gateway`) | `false` |
| `serviceController.enabled` | Enable the Kubernetes Service controller (`--enable-service`) | `false` |

A controller is started only for a route kind whose CRD is actually installed
in the cluster at `gateway.networking.k8s.io/v1`; enabling `gateway.enabled`
on a cluster with only some route kinds installed is safe.

The Service controller's values key is deliberately `serviceController`, not
the bare `service` key. `service:` is a near-universal Helm convention
reserved for a chart's own Service resource, and claiming it here would
permanently block ever adding one to this chart. This asymmetry with
`gateway.enabled` above is intentional, not an oversight.

> Tagging is fixed in the binary and not configurable via this chart:
> IngressRoute-derived hosts get `kubernetes`, `traefik`, and `ingress`;
> Gateway-derived hosts get `kubernetes`, `gateway`, and the lowercase kind
> name (`httproute`, `grpcroute`, or `tlsroute`), with a
> `k8s-gateway:<namespace>/<name>` provenance comment; Service-derived hosts
> get `kubernetes` and `service`, with a `k8s-service:<namespace>/<name>`
> provenance comment; `HostMapping` entries get only the `tags` from their
> spec. The log level (`info`, JSON) is also fixed.

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
- **HTTPRoutes / GRPCRoutes / TLSRoutes** (`gateway.networking.k8s.io/v1`):
  get, list, watch, update, patch — the controller writes the same cleanup
  finalizer and a host-ids annotation back to the route object.
- **Gateways** (`gateway.networking.k8s.io/v1`): get, list, watch only — the
  operator only reads `status.addresses` to resolve an IP and never writes a
  Gateway.
- **HostMappings** (`router-hosts.fzymgc.house/v1alpha1`): get, list, watch,
  update, patch, plus the `status` and `finalizers` subresources.
- **Services** (`""`): get, list, watch, update, patch — the controller writes
  the cleanup finalizer and the host-ids annotation back to the Service. No
  `delete`, and no Service status subresource.
- **Events** (`""`): create, patch, cluster-wide — the controller reports
  configuration problems on the Service itself so its owner can see them with
  `kubectl describe service`. This also fixes `HostMapping`'s event reporting
  outside the operator's own namespace, which previously only had the
  namespace-scoped leader-election grant below.

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

### Sync Gateway API Routes

With `gateway.enabled: true` and the Gateway API CRDs installed, the operator
watches `HTTPRoute`, `GRPCRoute`, and `TLSRoute` resources and creates a host
entry for each hostname in `spec.hostnames`:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: myapp
  namespace: default
spec:
  parentRefs:
    - name: my-gateway
  hostnames:
    - myapp.example.com
  rules:
    - backendRefs:
        - name: myapp
          port: 80
```

Behavioral notes:

- **IP resolution**: the entry IP comes from the first `IPAddress`-typed
  address of the first parent Gateway (in `parentRefs` declaration order) that
  has one. `Hostname`-typed addresses are skipped.
- **Fallback**: `routerHosts.defaultIngressIP` is used when no parent Gateway
  supplies an address. With no fallback configured, the route is requeued and
  retried rather than given an IP-less entry.
- **Wildcard hostnames** (`*.example.com`) are skipped — they cannot become a
  concrete DNS entry.

### Sync Kubernetes Services

With `serviceController.enabled: true`, the operator additionally watches
`v1/Service` resources and creates a host entry for each `LoadBalancer` or
`NodePort` Service that explicitly opts in via annotation:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: myapp
  namespace: default
  annotations:
    router-hosts.fzymgc.house/enabled: "true"
    router-hosts.fzymgc.house/hostname: myapp.example.com
    router-hosts.fzymgc.house/aliases: myapp.local,myapp-internal.example.com
spec:
  type: LoadBalancer
  selector:
    app: myapp
  ports:
    - port: 443
```

There are two independent gates, and neither substitutes for the other: the
chart-level `serviceController.enabled: true` toggle, and the per-Service
`router-hosts.fzymgc.house/enabled: "true"` annotation. A Service without the
annotation is never touched, even with the controller enabled cluster-wide.

**Annotation reference:**

| Annotation | Required | Purpose |
|------------|----------|---------|
| `router-hosts.fzymgc.house/enabled` | Yes | `"true"` to opt this Service in. |
| `router-hosts.fzymgc.house/hostname` | Yes | The single hostname to register. A Service has no hostname in its spec, so this is always explicit. |
| `router-hosts.fzymgc.house/aliases` | No | Comma-separated aliases, mapped to the host entry's native `Aliases` field. Invalid aliases are dropped with a warning, never fatal. |
| `router-hosts.fzymgc.house/ip-address` | Required for `NodePort`; optional override for `LoadBalancer` | The IP to publish. |

**Supported types**: only `LoadBalancer` and `NodePort`. `ClusterIP`,
`ExternalName`, and headless Services are unsupported — annotating one
produces an `InvalidServiceType` warning Event and no entry.

**IP resolution**: for `LoadBalancer`, the first
`status.loadBalancer.ingress[]` entry with a non-empty `ip`, in declaration
order; entries carrying only a `hostname` (AWS ELB style) are skipped,
because a CNAME target is not a host entry IP. While no IP is available the
Service is retried and no IP-less entry is ever created. For `NodePort` the
IP comes only from the `ip-address` annotation, because a NodePort is
exposed on every node and which address to publish is topology-dependent.
The `ip-address` annotation overrides `LoadBalancer` status when both are
present.

**No default fallback**: `routerHosts.defaultIngressIP` is **not** used for
Service-derived entries, unlike IngressRoute- and Gateway-derived ones. A
Service's IP is knowable from the object itself, so a default would be a
guess rather than a fallback — and sharing that IP across controllers is
what makes cross-controller hostname collisions routine.

**Events**: a Service owner may see four reasons via
`kubectl describe service`: `InvalidServiceType`, `MissingHostname`,
`MissingIPAddress` (all `Warning`), and `PendingLoadBalancer` (`Normal`,
while an IP is still provisioning). Success is logged by the operator
rather than evented, to keep the event stream usable.

**Cleanup**: the operator adds a
`router-hosts.fzymgc.house/service-cleanup` finalizer and removes the DNS
entry when the Service is deleted, when it is opted out (`enabled`
annotation removed or set to a non-`"true"` value), when its type changes to
an unsupported one, or when its hostname annotation changes.

**Cache footprint**: once enabled, the operator's shared informer caches
every Service in the cluster, not only the annotated ones — a cache
selector can filter on a label but not on an annotation. This is fine at
homelab and small-cluster scale; a label-based opt-in is the change to make
if the operator ever runs against a cluster with thousands of Services.

**Not supported in this release**: multi-IP / dual-stack (AAAA) entries,
hostname-typed `LoadBalancer` ingress, deletion grace periods, and a
user-supplied tags annotation.

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
- **Gateway API routes not producing entries**: check, in order, whether
  `gateway.enabled` is `false`; whether the route kind's CRD is not installed
  at `gateway.networking.k8s.io/v1` (the operator only starts a controller for
  kinds whose CRD is present); or whether neither a parent Gateway address nor
  `routerHosts.defaultIngressIP` yields an IP. The operator's startup log lines
  name each skipped route kind and the required apiVersion.

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
