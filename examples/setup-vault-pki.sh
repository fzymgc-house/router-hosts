#!/usr/bin/env bash
# Setup Vault PKI secrets engine for router-hosts certificates
#
# This script configures a PKI secrets engine with:
#   - Root CA (or intermediate if you have an existing root)
#   - Server role for issuing server certificates (serverAuth)
#   - Client role for issuing client certificates (clientAuth)
#
# Prerequisites:
#   - vault CLI installed
#   - Authenticated with admin/policy that can mount secrets engines
#
# Usage:
#   export VAULT_ADDR=https://vault.example.com:8200
#   export VAULT_TOKEN=hvs.xxxxx
#   ./setup-vault-pki.sh
#
# For production:
#   - Use an intermediate CA signed by your organization's root
#   - Restrict role permissions with Vault policies
#   - Enable audit logging
#   - Consider shorter TTLs with automated renewal

set -euo pipefail

# Resolve script directory for reliable relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PKI_PATH="${VAULT_PKI_PATH:-pki}"
MAX_LEASE_TTL="${PKI_MAX_TTL:-87600h}"  # 10 years for CA
DEFAULT_CERT_TTL="${PKI_DEFAULT_TTL:-8760h}"  # 1 year for certs
CA_OUTPUT_DIR="${CA_OUTPUT_DIR:-${SCRIPT_DIR}/../certs}"

echo "Setting up Vault PKI at: $VAULT_ADDR"
echo "PKI mount path: $PKI_PATH"
echo ""

# =============================================================================
# PRODUCTION WARNING
# =============================================================================
# This script generates a NEW ROOT CA in Vault. For production environments:
#   - Use an intermediate CA signed by your organization's existing root
#   - Run: vault write pki/intermediate/generate/internal ...
#   - Sign with your root CA
#   - Import: vault write pki/intermediate/set-signed certificate=@signed.pem
#
# See: https://developer.hashicorp.com/vault/tutorials/secrets-management/pki-engine
# =============================================================================

if [[ "${SKIP_ROOT_CA_WARNING:-}" != "true" ]]; then
    echo "⚠️  WARNING: This will generate a NEW ROOT CA"
    echo "   For production, use an intermediate CA instead."
    echo ""
    echo "   Set SKIP_ROOT_CA_WARNING=true to skip this prompt."
    echo ""
    read -r -p "Continue with root CA generation? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo "Aborted. See comments in script for production setup."
        exit 1
    fi
    echo ""
fi

# Enable PKI secrets engine (idempotent - will fail if already enabled)
echo "Enabling PKI secrets engine..."
vault secrets enable -path="$PKI_PATH" pki 2>/dev/null || echo "PKI already enabled at $PKI_PATH"

# Tune the mount for longer TTLs
echo "Configuring PKI mount..."
vault secrets tune -max-lease-ttl="$MAX_LEASE_TTL" "$PKI_PATH"

# Generate root CA (for development/testing)
echo "Generating root CA..."
mkdir -p "$CA_OUTPUT_DIR"
vault write -format=json "${PKI_PATH}/root/generate/internal" \
    common_name="router-hosts-ca" \
    organization="router-hosts" \
    ttl="$MAX_LEASE_TTL" \
    key_type="rsa" \
    key_bits=4096 \
    | jq -r '.data.certificate' > "${CA_OUTPUT_DIR}/ca.pem"

echo "CA certificate saved to ${CA_OUTPUT_DIR}/ca.pem"

# Configure CA and CRL URLs (adjust for your Vault deployment)
echo "Configuring CA URLs..."
vault write "${PKI_PATH}/config/urls" \
    issuing_certificates="${VAULT_ADDR}/v1/${PKI_PATH}/ca" \
    crl_distribution_points="${VAULT_ADDR}/v1/${PKI_PATH}/crl"

# Create server role
echo "Creating server certificate role..."
vault write "${PKI_PATH}/roles/router-hosts-server" \
    allowed_domains="localhost,router-hosts,router.local" \
    allow_bare_domains=true \
    allow_subdomains=true \
    allow_localhost=true \
    allow_ip_sans=true \
    server_flag=true \
    client_flag=false \
    key_type="rsa" \
    key_bits=3072 \
    max_ttl="$DEFAULT_CERT_TTL" \
    ttl="$DEFAULT_CERT_TTL"

# Create client role
echo "Creating client certificate role..."
vault write "${PKI_PATH}/roles/router-hosts-client" \
    allowed_domains="router-hosts-client" \
    allow_bare_domains=true \
    allow_any_name=true \
    enforce_hostnames=false \
    server_flag=false \
    client_flag=true \
    key_type="rsa" \
    key_bits=3072 \
    max_ttl="$DEFAULT_CERT_TTL" \
    ttl="$DEFAULT_CERT_TTL"

echo ""
echo "PKI setup complete!"
echo ""
echo "Roles created:"
echo "  - router-hosts-server (for server certificates)"
echo "  - router-hosts-client (for client certificates)"
echo ""
echo "To issue certificates, run:"
echo "  ./generate-certs-vault.sh ../certs"
echo ""
echo "Example Vault policy for certificate issuers:"
cat << 'EOF'

# router-hosts-cert-issuer.hcl
path "pki/issue/router-hosts-server" {
  capabilities = ["create", "update"]
}

path "pki/issue/router-hosts-client" {
  capabilities = ["create", "update"]
}

path "pki/cert/ca" {
  capabilities = ["read"]
}

EOF

# =============================================================================
# INTERMEDIATE CA SETUP (Production)
# =============================================================================
# For production, use an intermediate CA signed by your organization's root.
# Uncomment and modify the following commands:
#
# # 1. Generate intermediate CSR
# vault write -format=json pki_int/intermediate/generate/internal \
#     common_name="router-hosts-intermediate-ca" \
#     organization="Your Organization" \
#     | jq -r '.data.csr' > intermediate.csr
#
# # 2. Sign the CSR with your external root CA
# #    (This step happens outside Vault, using your root CA)
# #    Example with OpenSSL:
# #    openssl ca -config root-ca.conf -in intermediate.csr -out intermediate.pem
#
# # 3. Import signed certificate
# vault write pki_int/intermediate/set-signed certificate=@intermediate.pem
#
# # 4. Configure URLs for the intermediate CA
# vault write pki_int/config/urls \
#     issuing_certificates="${VAULT_ADDR}/v1/pki_int/ca" \
#     crl_distribution_points="${VAULT_ADDR}/v1/pki_int/crl"
#
# See: https://developer.hashicorp.com/vault/tutorials/secrets-management/pki-engine-external-ca
# =============================================================================
