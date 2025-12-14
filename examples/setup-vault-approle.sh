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
#   ./setup-vault-approle.sh [--no-wrap] [output-dir]
#
# Options:
#   --no-wrap  Disable response wrapping (writes plaintext secret_id)
#              Use only for development/testing environments
#
# Default behavior (production):
#   Uses response wrapping - secret_id is wrapped with 5-minute TTL
#   Must be unwrapped on target system before use
#
# Output:
#   - vault-approle/role_id
#   - vault-approle/wrapped_secret_id (default, must be unwrapped)
#   - vault-approle/secret_id (only with --no-wrap)

set -euo pipefail

# Resolve script directory for reliable relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
# Default to wrapped (secure) - use --no-wrap to disable
USE_WRAPPED=true
OUTPUT_DIR="${SCRIPT_DIR}/vault-approle"

for arg in "$@"; do
    case "$arg" in
        --no-wrap)
            USE_WRAPPED=false
            echo "⚠️  WARNING: Using --no-wrap writes plaintext credentials to disk"
            echo "   This is acceptable for development but NOT recommended for production"
            echo ""
            ;;
        --wrapped)
            # Keep for backward compatibility, but it's now the default
            USE_WRAPPED=true
            ;;
        *)
            OUTPUT_DIR="$arg"
            ;;
    esac
done

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

if [[ "$USE_WRAPPED" == "true" ]]; then
    echo "Using response wrapping for secret_id (5-minute TTL)..."
    # Response wrapping returns a single-use token that can only be unwrapped once
    # The wrapped token expires after 5 minutes - retrieve immediately on target system
    vault write -wrap-ttl=5m -field=wrapping_token -f "auth/approle/role/${APPROLE_NAME}/secret-id" > "${OUTPUT_DIR}/wrapped_secret_id"
    chmod 600 "${OUTPUT_DIR}/role_id" "${OUTPUT_DIR}/wrapped_secret_id"
    echo ""
    echo "AppRole setup complete (with response wrapping)!"
    echo ""
    echo "Credentials saved to:"
    echo "  ${OUTPUT_DIR}/role_id"
    echo "  ${OUTPUT_DIR}/wrapped_secret_id (expires in 5 minutes!)"
    echo ""
    echo "IMPORTANT: Unwrap the secret_id immediately on the target system:"
    echo "  VAULT_TOKEN=\$(cat ${OUTPUT_DIR}/wrapped_secret_id) vault unwrap -field=secret_id > secret_id"
    echo ""
    echo "Or configure Vault Agent to use wrapped secret_id:"
    echo "  auto_auth {"
    echo "    method \"approle\" {"
    echo "      config = {"
    echo "        role_id_file_path = \"/vault-approle/role_id\""
    echo "        secret_id_response_wrapping_path = \"auth/approle/role/${APPROLE_NAME}/secret-id\""
    echo "      }"
    echo "    }"
    echo "  }"
else
    vault write -field=secret_id -f "auth/approle/role/${APPROLE_NAME}/secret-id" > "${OUTPUT_DIR}/secret_id"
    chmod 600 "${OUTPUT_DIR}/role_id" "${OUTPUT_DIR}/secret_id"
    echo ""
    echo "AppRole setup complete!"
    echo ""
    echo "Credentials saved to:"
    echo "  ${OUTPUT_DIR}/role_id"
    echo "  ${OUTPUT_DIR}/secret_id"
fi

echo ""
echo "Next steps:"
echo "  1. Copy vault-agent-config.hcl.example to vault-agent-config.hcl"
echo "  2. Edit vault-agent-config.hcl with your Vault address and settings"
echo "  3. Run: docker compose -f docker-compose.vault-agent.yml up -d"
echo ""
echo "Security notes:"
echo "  - Keep credentials secure (equivalent to passwords)"
echo "  - Response wrapping is enabled by default (use --no-wrap only for dev)"
echo "  - Rotate secret_id periodically"
echo "  - Consider using Vault Agent auto-auth with instance metadata in production"
