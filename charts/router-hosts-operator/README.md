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
| `routerHosts.endpoint` | gRPC endpoint (host:port) | `router.lan:50051` |
| `routerHosts.tlsSecretRef.name` | mTLS Secret name | `router-hosts-mtls` |
| `routerHosts.tlsSecretRef.namespace` | mTLS Secret namespace | `router-hosts-system` |
| `routerHosts.ipResolution` | IP resolution strategies | See values.yaml |
| `routerHosts.deletion.gracePeriodSeconds` | Grace period before deletion | `300` |
| `routerHosts.defaultTags` | Tags added to all entries | `["k8s-operator"]` |
| `serviceAccount.create` | Create ServiceAccount | `true` |
| `rbac.create` | Create RBAC resources | `true` |
| `logging.level` | Log level (trace/debug/info/warn/error) | `info` |

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

### RBAC Permissions

The operator requires these cluster-level permissions:

- **Ingresses** (`networking.k8s.io/v1`): get, list, watch
- **IngressRoutes/IngressRouteTCP** (`traefik.io/v1alpha1`): get, list, watch
- **HostMappings** (`router-hosts.fzymgc.house/v1alpha1`): get, list, watch, update status
- **RouterHostsConfigs** (`router-hosts.fzymgc.house/v1alpha1`): get, list, watch
- **Secrets**: get (for reading mTLS certificates)
- **Services**: get, list (for IP resolution)

## Known Limitations

### No Leader Election

The operator currently runs as a single replica without leader election. This means:

- **No high availability**: If the pod crashes, there's brief downtime until Kubernetes restarts it
- **Rolling updates cause gaps**: During upgrades, there's a period where no operator is running
- **Do not scale beyond 1 replica**: Multiple replicas would cause duplicate processing

For most home lab and small cluster use cases, this is acceptable. The operator is stateless and recovers quickly on restart.

**Workaround**: Use `strategy.type: Recreate` in the Deployment to minimize overlap during updates.

**Tracking issue**: [#154](https://github.com/fzymgc-house/router-hosts/issues/154)

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
