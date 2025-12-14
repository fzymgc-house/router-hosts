#!/usr/bin/env bash
# Generate certificates for router-hosts using HashiCorp Vault PKI
#
# Prerequisites:
#   - vault CLI installed and authenticated (VAULT_ADDR and VAULT_TOKEN set)
#   - PKI secrets engine mounted and configured (see setup-vault-pki.sh)
#   - Roles created for server and client certificates
#
# Usage:
#   export VAULT_ADDR=https://vault.example.com:8200
#   export VAULT_TOKEN=hvs.xxxxx  # or use vault login
#   ./generate-certs-vault.sh [output-dir]
#
# Environment variables:
#   VAULT_ADDR          - Vault server address (required)
#   VAULT_TOKEN         - Vault authentication token (or use vault login)
#   VAULT_PKI_PATH      - PKI mount path (default: pki)
#   VAULT_SERVER_ROLE   - Role for server certs (default: router-hosts-server)
#   VAULT_CLIENT_ROLE   - Role for client certs (default: router-hosts-client)
#   CERT_TTL            - Certificate validity (default: 8760h = 1 year)

set -euo pipefail

# Resolve script directory for reliable relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/../certs}"

# Configuration
PKI_PATH="${VAULT_PKI_PATH:-pki}"
SERVER_ROLE="${VAULT_SERVER_ROLE:-router-hosts-server}"
CLIENT_ROLE="${VAULT_CLIENT_ROLE:-router-hosts-client}"
TTL="${CERT_TTL:-8760h}"

# =============================================================================
# CUSTOMIZE THESE VALUES for your environment
# =============================================================================
# SERVER_CN: Common name for the server certificate
# SERVER_ALT_NAMES: DNS names clients will use to connect (comma-separated)
# SERVER_IP_SANS: IP addresses clients will use to connect (comma-separated)
# =============================================================================
SERVER_CN="router-hosts"
SERVER_ALT_NAMES="localhost,router-hosts,router.local"
SERVER_IP_SANS="127.0.0.1"

# Client identity
CLIENT_CN="router-hosts-client"

# Verify required tools are available
for cmd in vault jq openssl; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd not found"
        case "$cmd" in
            vault) echo "Install from https://developer.hashicorp.com/vault/install" ;;
            jq) echo "Install from https://jqlang.github.io/jq/download/" ;;
            openssl) echo "Install via your package manager" ;;
        esac
        exit 1
    fi
done

if [[ -z "${VAULT_ADDR:-}" ]]; then
    echo "Error: VAULT_ADDR not set"
    exit 1
fi

# Test authentication
if ! vault token lookup &> /dev/null; then
    echo "Error: Not authenticated to Vault. Run 'vault login' or set VAULT_TOKEN"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# Set restrictive umask for private key generation (prevents race condition)
umask 077

# Cleanup temporary files on exit (contain private keys)
trap 'rm -f server-response.json client-response.json' EXIT

echo "Using Vault at: $VAULT_ADDR"
echo "PKI path: $PKI_PATH"
echo "Output directory: $(pwd)"
echo ""

# Fetch CA certificate
echo "Fetching CA certificate..."
vault read -field=certificate "${PKI_PATH}/cert/ca" > ca.pem

# Issue server certificate
echo "Issuing server certificate (role: $SERVER_ROLE)..."
if ! vault write -format=json "${PKI_PATH}/issue/${SERVER_ROLE}" \
    common_name="$SERVER_CN" \
    alt_names="$SERVER_ALT_NAMES" \
    ip_sans="$SERVER_IP_SANS" \
    ttl="$TTL" > server-response.json; then
    echo "Error: Failed to issue server certificate from Vault"
    cat server-response.json 2>/dev/null || true
    exit 1
fi

# Validate response contains certificate data
if ! jq -e '.data.certificate' server-response.json >/dev/null 2>&1; then
    echo "Error: Vault response missing certificate data"
    jq '.' server-response.json 2>/dev/null || cat server-response.json
    exit 1
fi

jq -r '.data.certificate' server-response.json > server.pem
jq -r '.data.private_key' server-response.json > server-key.pem

# Append CA chain if present (intermediate CAs for proper validation)
if jq -e '.data.ca_chain | length > 0' server-response.json &>/dev/null; then
    echo "Appending CA chain to server certificate..."
    jq -r '.data.ca_chain[]' server-response.json >> server.pem
fi

# Issue client certificate
echo "Issuing client certificate (role: $CLIENT_ROLE)..."
if ! vault write -format=json "${PKI_PATH}/issue/${CLIENT_ROLE}" \
    common_name="$CLIENT_CN" \
    ttl="$TTL" > client-response.json; then
    echo "Error: Failed to issue client certificate from Vault"
    cat client-response.json 2>/dev/null || true
    exit 1
fi

# Validate response contains certificate data
if ! jq -e '.data.certificate' client-response.json >/dev/null 2>&1; then
    echo "Error: Vault response missing certificate data"
    jq '.' client-response.json 2>/dev/null || cat client-response.json
    exit 1
fi

jq -r '.data.certificate' client-response.json > client.pem
jq -r '.data.private_key' client-response.json > client-key.pem

# Append CA chain if present (intermediate CAs for proper validation)
if jq -e '.data.ca_chain | length > 0' client-response.json &>/dev/null; then
    echo "Appending CA chain to client certificate..."
    jq -r '.data.ca_chain[]' client-response.json >> client.pem
fi

# Cleanup is handled by trap, but be explicit
rm -f server-response.json client-response.json

# Restore default umask and set final permissions
# (umask 077 already created keys with 600, but be explicit)
umask 022
chmod 600 ./*-key.pem
chmod 644 ./*.pem

echo ""
echo "Certificates generated successfully:"
ls -la
echo ""
echo "Server certificate expires: $(openssl x509 -in server.pem -noout -enddate 2>/dev/null | cut -d= -f2)"
echo "Client certificate expires: $(openssl x509 -in client.pem -noout -enddate 2>/dev/null | cut -d= -f2)"
echo ""
echo "Copy to your deployment:"
echo "  Server: ca.pem, server.pem, server-key.pem"
echo "  Client: ca.pem, client.pem, client-key.pem"
