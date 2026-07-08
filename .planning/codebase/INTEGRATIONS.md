# External Integrations

**Analysis Date:** 2026-07-08

## APIs & External Services

**gRPC Service (self-hosted):**

- `RouterHostsService` - Primary API over gRPC/mTLS on port 50051
  - Definition: `proto/router_hosts/v1/*.proto`, stubs in `api/v1/router_hosts`
  - RPCs: host CRUD (`AddHost`, `GetHost`, `UpdateHost`, `DeleteHost`), `ListHosts`/`SearchHosts` (server-streaming), `ImportHosts`/`ExportHosts` (bidi/streaming), snapshots (`CreateSnapshot`, `ListSnapshots`, `RollbackToSnapshot`, `DeleteSnapshot`), `CompactAggregates`, health (`Liveness`, `Readiness`, `Health`)

**Certificate Authority (ACME):**

- Let's Encrypt / ACME CA - Certificate issuance via `github.com/go-acme/lego/v4`
  - SDK/Client: `internal/acme/acme.go` (lego client, P256 key type)
  - Directory URL configurable (`DirectoryURL`)
  - Challenge: DNS-01

**Cloudflare DNS:**

- Cloudflare - DNS-01 challenge solver for ACME certificate acquisition
  - SDK/Client: `github.com/go-acme/lego/v4/providers/dns/cloudflare` in `internal/acme/acme.go`
  - Auth: API token via config `DNS.Cloudflare.APIToken`, resolved through `config.ExpandEnvVars` (env-var expansion)

**Kubernetes API:**

- Kubernetes cluster - Operator reconciles `HostMapping` and `IngressRoute` custom resources
  - Client: `sigs.k8s.io/controller-runtime`, `k8s.io/client-go` in `internal/operator`
  - CRD types: `api/operator/v1alpha1`; Helm chart in `charts/router-hosts-operator`

## Data Storage

**Databases:**

- SQLite - Event-sourced storage (events, snapshots, host projection)
  - Connection: file path from config `[database] path` (e.g. `/data/router-hosts.db`)
  - Client: `zombiezen.com/go/sqlite` (pure Go, modernc backend), implemented in `internal/storage/sqlite`
  - Storage interfaces (`EventStore`, `SnapshotStore`, `HostProjection`) in `internal/storage`

**File Storage:**

- Local filesystem - Managed hosts file (`hosts_file_path`), atomically updated
- Optional dnsmasq conf-dir output (`dnsmasq_conf_path`) - authoritative `local=`/`address=` directives
- Optional unbound conf-dir output (`unbound_conf_path`, `unbound_ttl`) - authoritative `local-zone`/`local-data` directives

**Caching:**

- None

## Authentication & Identity

**mTLS (mutual TLS):**

- Client certificate authentication for all gRPC calls
  - Server config `[tls]`: `cert_path`, `key_path`, `ca_cert_path`
  - Only clients with certs signed by the configured CA may connect
  - Client wrapper: `internal/client` (mTLS dial)
  - Cert provisioning helpers: `examples/generate-certs.sh`, `examples/generate-certs-vault.sh`

**HashiCorp Vault (optional):**

- Vault PKI + Vault Agent for certificate provisioning (external, optional)
  - Setup scripts: `examples/setup-vault-pki.sh`, `examples/setup-vault-approle.sh`, `examples/vault-agent-config.hcl.example`, `examples/docker-compose.vault-agent.yml`

## Monitoring & Observability

**Metrics:**

- OpenTelemetry - Metrics via `go.opentelemetry.io/otel` with OTLP gRPC exporter (`otlpmetricgrpc`)
  - Server metrics in `internal/server`
- Prometheus client (`github.com/prometheus/client_golang`) available (indirect)

**Error Tracking:**

- None (structured errors via `samber/oops` with error codes)

**Logs:**

- `go-logr/logr` structured logging (used by controller-runtime and server)

## CI/CD & Deployment

**Hosting:**

- Container image (distroless static), deployable to Kubernetes via Helm chart `charts/router-hosts-operator`

**CI Pipeline:**

- GitHub Actions (`.github/workflows/`) - `ci-go.yml` runs lint, test, build, buf checks
- release-please + GoReleaser for releases

## Environment Configuration

**Required config (TOML, not env):**

- Server: `bind_address`, `hosts_file_path`, `[database] path`, `[tls]` cert/key/ca paths
- ACME (optional): `DirectoryURL`, `DNS.Cloudflare.APIToken`

**Env vars:**

- Referenced indirectly via `config.ExpandEnvVars` in config values (e.g. Cloudflare API token)

**Secrets location:**

- TLS certs on filesystem (`/certs/`), recommended `chmod 600` for config files
- Optionally provisioned via Vault Agent

## Webhooks & Callbacks

**Incoming:**

- None (gRPC RPCs only)

**Outgoing:**

- Post-update hooks - Shell commands run after successful hosts file update
  - Config `[hooks] on_success`, `on_failure` (e.g. `systemctl reload dnsmasq`)
  - Implemented in `internal/server` hooks

---

*Integration audit: 2026-07-08*
