# router-hosts-operator Helm Chart

Kubernetes operator for syncing Ingress hostnames to router-hosts server.

## Prerequisites

- Kubernetes 1.31+
- Helm 3.0+
- router-hosts server with mTLS enabled

## Installation

### 1. Create mTLS Secret

First, create a Secret containing the mTLS certificates for connecting to the router-hosts server:

```bash
kubectl create namespace router-hosts-system

kubectl create secret generic router-hosts-mtls \
  -n router-hosts-system \
  --from-file=ca.crt=/path/to/ca.crt \
  --from-file=tls.crt=/path/to/client.crt \
  --from-file=tls.key=/path/to/client.key
```

### 2. Install the Chart

```bash
helm install router-hosts-operator charts/router-hosts-operator \
  --namespace router-hosts-system \
  --create-namespace
```

### 3. Customize Values

Create a `values.yaml` file:

```yaml
routerHosts:
  endpoint: "router.example.com:50051"

  tlsSecretRef:
    name: router-hosts-mtls
    namespace: router-hosts-system

  ipResolution:
    - type: ingressController
      serviceName: traefik
      serviceNamespace: traefik-system
    - type: static
      address: "192.168.1.100"

  deletion:
    gracePeriodSeconds: 600

  defaultTags:
    - k8s-operator
    - cluster:production

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
| `image.repository` | Image repository | `ghcr.io/fzymgc-house/router-hosts-operator` |
| `image.tag` | Image tag | Chart appVersion (`0.6.0`) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of replicas | `1` |
| `leaderElection.enabled` | Enable leader election | `false` (auto-enabled if replicas >= 2) |
| `leaderElection.leaseName` | Lease resource name | `<fullname>-leader` |
| `leaderElection.leaseDurationSeconds` | Lease TTL in seconds | `15` |
| `leaderElection.renewIntervalSeconds` | Lease renewal interval | `5` |
| `routerHosts.endpoint` | gRPC endpoint (host:port) | `router.lan:50051` |
| `routerHosts.tlsSecretRef.name` | mTLS Secret name | `router-hosts-mtls` |
| `routerHosts.tlsSecretRef.namespace` | mTLS Secret namespace | `router-hosts-system` |
| `routerHosts.ipResolution` | IP resolution strategies | See values.yaml |
| `routerHosts.deletion.gracePeriodSeconds` | Grace period before deletion | `300` |
| `routerHosts.defaultTags` | Tags added to all entries | `["k8s-operator"]` |
| `serviceAccount.create` | Create ServiceAccount | `true` |
| `rbac.create` | Create RBAC resources | `true` |
| `logging.level` | Log level (trace/debug/info/warn/error) | `info` |
| `healthCheck.port` | Port for health check HTTP server | `8081` |
| `healthCheck.livenessProbe.*` | Liveness probe timing settings | See values.yaml |
| `healthCheck.readinessProbe.*` | Readiness probe timing settings | See values.yaml |
| `healthCheck.startupProbe.*` | Startup probe timing settings | See values.yaml |

### IP Resolution Strategies

The operator tries each strategy in order until it finds a valid IP:

#### IngressController

Discovers IP from a Kubernetes Service (typically an ingress controller):

```yaml
ipResolution:
  - type: ingressController
    serviceName: traefik
    serviceNamespace: traefik-system
```

#### Static

Uses a fixed IP address:

```yaml
ipResolution:
  - type: static
    address: "192.168.1.100"
```

### Health Check Endpoints

The operator exposes HTTP health check endpoints for Kubernetes probes:

| Endpoint | Purpose | Behavior |
|----------|---------|----------|
| `/healthz` | Liveness | Returns 200 OK if process is alive |
| `/readyz` | Readiness + Startup | Returns 200 OK if startup complete AND router-hosts server reachable |

#### Probe Configuration

| Probe | Endpoint | Purpose |
|-------|----------|---------|
| **Startup** | `/readyz` | Verifies server connectivity before pod is considered started (allows 150s) |
| **Liveness** | `/healthz` | Checks process is alive; restarts pod if unresponsive |
| **Readiness** | `/readyz` | Checks server connectivity; removes pod from service if unreachable |

The readiness probe performs a gRPC call to verify connectivity to the router-hosts server. If the server becomes unreachable (network partition, server restart, certificate expiration), the pod transitions to NotReady state, preventing new work while allowing in-flight operations to complete.

Configure the health check port if needed:

```yaml
healthCheck:
  port: 8081  # Default port
```

### RBAC Permissions

The operator requires these cluster-level permissions:

- **Ingresses** (`networking.k8s.io/v1`): get, list, watch
- **IngressRoutes/IngressRouteTCP** (`traefik.io/v1alpha1`): get, list, watch
- **HostMappings** (`router-hosts.fzymgc.house/v1alpha1`): get, list, watch, update status
- **RouterHostsConfigs** (`router-hosts.fzymgc.house/v1alpha1`): get, list, watch
- **Secrets**: get (for reading mTLS certificates)
- **Services**: get, list (for IP resolution)

When leader election is enabled (including auto-enabled for replicas >= 2):
- **Leases** (`coordination.k8s.io/v1`): get, create, update (in release namespace)

## High Availability

### Leader Election

The operator supports running multiple replicas for high availability using Kubernetes Lease-based leader election. Only one replica (the leader) actively reconciles resources at a time; other replicas wait as standby.

**Features:**
- Automatic failover: If the leader crashes, a standby acquires leadership
- Zero-downtime upgrades: Standby pods can take over during rolling updates
- Acquire-or-exit pattern: Pods exit on leadership loss, letting Kubernetes restart them

**Smart defaults:**
- Leader election is automatically enabled when `replicaCount >= 2`
- Can be explicitly enabled/disabled via `leaderElection.enabled`

**To run with HA:**

```yaml
replicaCount: 2

# Optional: customize leader election (defaults work for most cases)
leaderElection:
  enabled: true                  # Auto-enabled when replicas >= 2
  leaseDurationSeconds: 15       # Lease TTL
  renewIntervalSeconds: 5        # Renewal interval
```

**How it works:**
1. On startup, each pod attempts to acquire the Kubernetes Lease
2. The first pod to acquire becomes leader and starts controllers
3. Other pods block waiting for leadership
4. Leader renews the lease every 5 seconds
5. If leadership is lost, the pod exits and Kubernetes restarts it
6. The restarted pod re-enters the acquire-or-wait cycle

## Usage

### Enable Ingress Sync

Add annotation to Ingress resources:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myapp
  annotations:
    router-hosts.fzymgc.house/enabled: "true"
spec:
  rules:
    - host: myapp.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: myapp
                port:
                  number: 80
```

### Create Explicit Host Mappings

For hosts not managed by Ingress:

```yaml
apiVersion: router-hosts.fzymgc.house/v1alpha1
kind: HostMapping
metadata:
  name: legacy-app
  namespace: default
spec:
  hostname: legacy.example.com
  ipAddress: "10.0.0.50"  # Optional: uses IP resolution if omitted
  aliases:
    - legacy.local
  tags:
    - external
```

### Advanced Annotations

Override behavior per Ingress:

```yaml
annotations:
  router-hosts.fzymgc.house/enabled: "true"
  router-hosts.fzymgc.house/ip-address: "192.168.1.200"  # Override IP
  router-hosts.fzymgc.house/tags: "production,public"    # Additional tags
  router-hosts.fzymgc.house/aliases: "app.local,app.lan" # Hostname aliases
  router-hosts.fzymgc.house/grace-period: "600"          # Override grace period (seconds)
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

Note: CRDs are not automatically deleted. To remove them:

```bash
kubectl delete crd routerhostsconfigs.router-hosts.fzymgc.house
kubectl delete crd hostmappings.router-hosts.fzymgc.house
```

## Troubleshooting

### Check Operator Logs

```bash
kubectl logs -n router-hosts-system -l app.kubernetes.io/name=router-hosts-operator -f
```

### Verify Configuration

```bash
kubectl get routerhostsconfig -o yaml
```

### Check HostMapping Status

```bash
kubectl get hostmapping -A
kubectl describe hostmapping <name> -n <namespace>
```

### Common Issues

**Operator fails to start**: Check mTLS Secret exists and contains required keys (`ca.crt`, `tls.crt`, `tls.key`)

**Ingresses not syncing**: Verify annotation `router-hosts.fzymgc.house/enabled: "true"` is present

**IP resolution failing**: Check Service exists and has LoadBalancer or ExternalIP

## Development

### Testing Chart Locally

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
