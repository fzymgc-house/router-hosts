# Router-Hosts Deployment Examples

This directory contains example configurations and scripts for deploying router-hosts.

## Quick Start (Development)

```bash
# 1. Generate self-signed certificates
./generate-certs.sh

# 2. Create directories and config
mkdir -p ../config ../data
cp server.toml.example ../config/server.toml

# 3. Start the server
cd ..
docker compose up -d

# 4. Verify it's running
docker compose logs -f
# Look for: "Starting gRPC server on 0.0.0.0:50051"

# 5. Connect with client
router-hosts --server localhost:50051 \
  --cert certs/client.pem \
  --key certs/client-key.pem \
  --ca certs/ca.pem \
  list
```

## Directory Structure

After setup, your project root should look like:

```
router-hosts/
├── docker-compose.yml      # Main compose file
├── config/
│   └── server.toml         # Server configuration
├── certs/
│   ├── ca.pem              # Certificate Authority
│   ├── server.pem          # Server certificate
│   ├── server-key.pem      # Server private key
│   ├── client.pem          # Client certificate
│   └── client-key.pem      # Client private key
├── data/
│   ├── router-hosts.db     # DuckDB database (created on first run)
│   └── hosts               # Generated hosts file
└── examples/               # This directory
```

## Certificate Options

### Option 1: Self-Signed (Development/Testing)

```bash
./generate-certs.sh [output-dir]
```

Creates CA, server, and client certificates valid for 365 days. Edit the script to customize:
- `SERVER_CN` - Server common name
- `SERVER_SAN` - Subject Alternative Names (hostnames/IPs clients use to connect)

### Option 2: HashiCorp Vault PKI (Production)

First-time setup:
```bash
export VAULT_ADDR=https://vault.example.com:8200
vault login

# One-time: Configure PKI secrets engine
./setup-vault-pki.sh

# Issue certificates
./generate-certs-vault.sh
```

Subsequent certificate issuance:
```bash
./generate-certs-vault.sh
```

Environment variables:
- `VAULT_PKI_PATH` - PKI mount path (default: `pki`)
- `VAULT_SERVER_ROLE` - Server certificate role (default: `router-hosts-server`)
- `VAULT_CLIENT_ROLE` - Client certificate role (default: `router-hosts-client`)
- `CERT_TTL` - Certificate validity (default: `8760h` / 1 year)

### Option 3: Vault Agent (Automated Renewal)

For production deployments with automatic certificate renewal:

```bash
# 1. Setup PKI (if not already done)
./setup-vault-pki.sh

# 2. Create AppRole for Vault Agent authentication
./setup-vault-approle.sh

# 3. Configure Vault Agent
cp vault-agent-config.hcl.example vault-agent-config.hcl
# Edit vault-agent-config.hcl:
#   - Set correct Vault address
#   - Adjust common_name and alt_names for your server
#   - Configure TTL (default: 24h with auto-renewal)

# 4. Start with Vault Agent
docker compose -f docker-compose.vault-agent.yml up -d
```

How it works:
- Vault Agent authenticates using AppRole credentials
- Automatically fetches server certificate from Vault PKI
- Renews certificates before expiration (checks every 5 minutes)
- Writes certificates to shared volume for router-hosts to use

Files:
- `docker-compose.vault-agent.yml` - Compose file with Vault Agent sidecar
- `vault-agent-config.hcl.example` - Vault Agent configuration template
- `setup-vault-approle.sh` - Creates AppRole and fetches credentials

## Configuration

### Server Configuration (`server.toml`)

Required settings:
- `server.bind_address` - gRPC listen address (e.g., `0.0.0.0:50051`)
- `server.hosts_file_path` - Path to managed hosts file
- `database.path` - DuckDB database file path
- `tls.*` - Certificate paths for mTLS

Optional settings:
- `retention.max_snapshots` - Maximum snapshots to keep (default: 50)
- `retention.max_age_days` - Maximum snapshot age (default: 30)
- `hooks.on_success` - Commands to run after successful update
- `hooks.on_failure` - Commands to run after failed update

### Client Configuration (`client.toml`)

Copy to `~/.config/router-hosts/client.toml`:
```bash
mkdir -p ~/.config/router-hosts
cp client.toml.example ~/.config/router-hosts/client.toml
# Edit to set your server address and certificate paths
```

Configuration precedence: CLI flags > Environment variables > Config file

## Troubleshooting

### Connection refused

```
Error: transport error: Connection refused
```

- Check server is running: `docker compose ps`
- Verify port is exposed: `docker compose port router-hosts 50051`
- Check logs: `docker compose logs router-hosts`

### Certificate errors

```
Error: certificate verify failed
```

- Ensure client uses same CA that signed server cert
- Check server hostname matches certificate SAN
- Verify certificate hasn't expired: `openssl x509 -in cert.pem -noout -dates`

### Permission denied

```
Error: Config file is world-writable
```

- Fix config permissions: `chmod 600 config/server.toml`

### Health check failing

```
docker compose ps
# Shows: unhealthy
```

- Check server logs: `docker compose logs router-hosts`
- Verify port binding: `docker compose exec router-hosts nc -z localhost 50051`

## Multi-Container Setups

### With dnsmasq

```yaml
# docker-compose.override.yml
services:
  dnsmasq:
    image: jpillora/dnsmasq
    ports:
      - "53:53/udp"
    volumes:
      - ./data/hosts:/etc/hosts.router-hosts:ro
    command: --hostsfile=/etc/hosts.router-hosts
    depends_on:
      router-hosts:
        condition: service_healthy
```

### With hooks for DNS reload

In `config/server.toml`:
```toml
[hooks]
on_success = ["docker exec dnsmasq kill -HUP 1"]
```

Note: The server container needs Docker socket access to run `docker exec`.

## Certificate Renewal

### Manual Certificate Renewal

When using manually generated certificates (`generate-certs.sh` or `generate-certs-vault.sh`):

1. Generate new certificates
2. Replace files in `certs/` directory
3. Restart router-hosts: `docker compose restart router-hosts`

### Vault Agent Certificate Renewal

Vault Agent automatically renews certificates before expiration. However, **router-hosts does not automatically reload certificates** when they change on disk.

**Current behavior:**
- Vault Agent renews certificates (default: every 24h)
- router-hosts continues using in-memory certificates until restarted
- Certificates remain valid, but rotation requires restart

**Workarounds:**

1. **Scheduled restart** - Use cron or systemd timer to restart periodically:
   ```bash
   # Restart daily at 3am
   0 3 * * * docker compose -f /path/to/docker-compose.vault-agent.yml restart router-hosts
   ```

2. **Short-lived containers** - Use orchestrator (Kubernetes, Nomad) that restarts pods on certificate change

3. **Certificate validity buffer** - Use longer TTLs (e.g., 7 days) with 24h renewal, giving ample time for restarts

**Future enhancement:** Hot certificate reload via SIGHUP is planned but not yet implemented.

## Security Considerations

1. **Config file permissions** - Server rejects world-writable config files
2. **Certificate storage** - Private keys should be mode 600
3. **Network exposure** - Consider binding to localhost or private network only
4. **Vault integration** - Use short-lived certificates with automated renewal
5. **AppRole credentials** - Keep `vault-approle/` secure; equivalent to passwords
