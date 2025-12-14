#!/usr/bin/env bash
# Generate self-signed certificates for router-hosts mTLS
#
# Usage: ./generate-certs.sh [output-dir]
#
# This creates:
#   - ca.pem / ca-key.pem         - Certificate Authority
#   - server.pem / server-key.pem - Server certificate
#   - client.pem / client-key.pem - Client certificate
#
# For production, use a proper PKI or tools like step-ca, cfssl, or Vault.

set -euo pipefail

# Resolve script directory for reliable relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/../certs}"

DAYS_VALID=365
KEY_SIZE=2048

# =============================================================================
# CUSTOMIZE THESE VALUES for your environment
# =============================================================================
# SERVER_CN: Common name for the server certificate
# SERVER_SAN: Subject Alternative Names - must include all hostnames/IPs
#             clients will use to connect to the server
# =============================================================================
SERVER_CN="router-hosts"
SERVER_SAN="DNS:localhost,DNS:router-hosts,DNS:router.local,IP:127.0.0.1"

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

# Set restrictive umask for private key generation (prevents race condition)
umask 077

echo "Generating CA..."
openssl genrsa -out ca-key.pem "$KEY_SIZE"
openssl req -new -x509 -days "$DAYS_VALID" \
    -key ca-key.pem \
    -out ca.pem \
    -subj "/CN=router-hosts-ca/O=router-hosts"

echo "Generating server certificate..."
openssl genrsa -out server-key.pem "$KEY_SIZE"
openssl req -new \
    -key server-key.pem \
    -out server.csr \
    -subj "/CN=$SERVER_CN/O=router-hosts"

# Create server cert with SANs
cat > server-ext.cnf << EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SERVER_SAN
EOF

openssl x509 -req -days "$DAYS_VALID" \
    -in server.csr \
    -CA ca.pem \
    -CAkey ca-key.pem \
    -CAcreateserial \
    -out server.pem \
    -extfile server-ext.cnf

echo "Generating client certificate..."
openssl genrsa -out client-key.pem "$KEY_SIZE"
openssl req -new \
    -key client-key.pem \
    -out client.csr \
    -subj "/CN=router-hosts-client/O=router-hosts"

cat > client-ext.cnf << EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl x509 -req -days "$DAYS_VALID" \
    -in client.csr \
    -CA ca.pem \
    -CAkey ca-key.pem \
    -CAcreateserial \
    -out client.pem \
    -extfile client-ext.cnf

# Cleanup CSRs and temp files
rm -f ./*.csr ./*.cnf ca.srl

# Restore default umask and set final permissions
# (umask 077 already created keys with 600, but be explicit)
umask 022
chmod 600 ./*-key.pem
chmod 644 ./*.pem

echo ""
echo "Certificates generated in: $(pwd)"
echo ""
ls -la
echo ""
echo "Copy to your deployment:"
echo "  Server: ca.pem, server.pem, server-key.pem"
echo "  Client: ca.pem, client.pem, client-key.pem"
