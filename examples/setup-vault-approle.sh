#!/usr/bin/env bash
# Setup Vault AppRole authentication for router-hosts Vault Agent
#
# Creates an AppRole with permissions to:
#   - Issue server certificates from PKI
#   - Read CA certificate
#
# Prerequisites:
#   - vault CLI installed
#   - Authenticated with admin privileges
#   - PKI secrets engine configured (run setup-vault-pki.sh first)
#
# Usage:
#   export VAULT_ADDR=https://vault.example.com:8200
#   vault login
#   ./setup-vault-approle.sh
#
# Output:
#   - vault-approle/role_id
#   - vault-approle/secret_id

set -euo pipefail

# Resolve script directory for reliable relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/vault-approle}"

PKI_PATH="${VAULT_PKI_PATH:-pki}"
APPROLE_NAME="router-hosts-agent"

echo "Setting up AppRole at: $VAULT_ADDR"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Enable AppRole auth method (idempotent)
echo "Enabling AppRole auth method..."
vault auth enable approle 2>/dev/null || echo "AppRole already enabled"

# Create policy for router-hosts agent
echo "Creating policy: router-hosts-agent..."
vault policy write router-hosts-agent - <<EOF
# Allow issuing server certificates
path "${PKI_PATH}/issue/router-hosts-server" {
  capabilities = ["create", "update"]
}

# Allow reading CA certificate
path "${PKI_PATH}/cert/ca" {
  capabilities = ["read"]
}

# Allow token self-renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOF

# Create AppRole
echo "Creating AppRole: $APPROLE_NAME..."
vault write "auth/approle/role/${APPROLE_NAME}" \
    token_policies="router-hosts-agent" \
    token_ttl="1h" \
    token_max_ttl="24h" \
    secret_id_ttl="0" \
    secret_id_num_uses="0"

# Fetch credentials
echo "Fetching AppRole credentials..."
mkdir -p "$OUTPUT_DIR"

vault read -field=role_id "auth/approle/role/${APPROLE_NAME}/role-id" > "${OUTPUT_DIR}/role_id"
vault write -field=secret_id -f "auth/approle/role/${APPROLE_NAME}/secret-id" > "${OUTPUT_DIR}/secret_id"

# Set restrictive permissions
chmod 600 "${OUTPUT_DIR}/role_id" "${OUTPUT_DIR}/secret_id"

echo ""
echo "AppRole setup complete!"
echo ""
echo "Credentials saved to:"
echo "  ${OUTPUT_DIR}/role_id"
echo "  ${OUTPUT_DIR}/secret_id"
echo ""
echo "Next steps:"
echo "  1. Copy vault-agent-config.hcl.example to vault-agent-config.hcl"
echo "  2. Edit vault-agent-config.hcl with your Vault address and settings"
echo "  3. Run: docker compose -f docker-compose.vault-agent.yml up -d"
echo ""
echo "Security notes:"
echo "  - Keep secret_id secure (equivalent to a password)"
echo "  - For production, consider using response wrapping"
echo "  - Rotate secret_id periodically"
