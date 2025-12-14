#!/usr/bin/env bash
# Generate self-signed certificates for router-hosts mTLS
#
# Usage: ./generate-certs.sh [--dry-run] [output-dir]
#
# Options:
#   --dry-run  Show what would be created without writing files
#
# This creates:
#   - ca.pem / ca-key.pem         - Certificate Authority
#   - server.pem / server-key.pem - Server certificate
#   - client.pem / client-key.pem - Client certificate
#
# For production, use a proper PKI or tools like step-ca, cfssl, or Vault.

set -euo pipefail

# Parse arguments
DRY_RUN=false
OUTPUT_DIR=""

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=true
            ;;
        *)
            OUTPUT_DIR="$arg"
            ;;
    esac
done

# Resolve script directory for reliable relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/../certs}"

DAYS_VALID=365
# NIST recommends 3072-bit RSA for security through 2030
# See: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
KEY_SIZE=3072

# =============================================================================
# CUSTOMIZE THESE VALUES for your environment
# =============================================================================
# SERVER_CN: Common name for the server certificate
# SERVER_SAN: Subject Alternative Names - must include all hostnames/IPs
#             clients will use to connect to the server
# =============================================================================
SERVER_CN="router-hosts"
SERVER_SAN="DNS:localhost,DNS:router-hosts,DNS:router.local,IP:127.0.0.1"

# Dry-run mode: show what would be created and exit
if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY RUN - Would create certificates with:"
    echo ""
    echo "Output directory: $OUTPUT_DIR"
    echo "Key size: $KEY_SIZE bits (RSA)"
    echo "Validity: $DAYS_VALID days"
    echo ""
    echo "CA Certificate:"
    echo "  - CN: router-hosts-ca"
    echo "  - Files: ca.pem, ca-key.pem"
    echo ""
    echo "Server Certificate:"
    echo "  - CN: $SERVER_CN"
    echo "  - SANs: $SERVER_SAN"
    echo "  - Files: server.pem, server-key.pem"
    echo ""
    echo "Client Certificate:"
    echo "  - CN: router-hosts-client"
    echo "  - Files: client.pem, client-key.pem"
    echo ""
    echo "Run without --dry-run to generate certificates."
    exit 0
fi

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

# Validate certificates
echo ""
echo "Validating certificates..."

# Verify CA
if ! openssl x509 -in ca.pem -noout 2>/dev/null; then
    echo "Error: CA certificate is invalid"
    exit 1
fi

# Verify server certificate chain and key match
if ! openssl verify -CAfile ca.pem server.pem >/dev/null 2>&1; then
    echo "Error: Server certificate chain validation failed"
    exit 1
fi
SERVER_CERT_MOD=$(openssl x509 -in server.pem -noout -modulus 2>/dev/null | openssl md5)
SERVER_KEY_MOD=$(openssl rsa -in server-key.pem -noout -modulus 2>/dev/null | openssl md5)
if [[ "$SERVER_CERT_MOD" != "$SERVER_KEY_MOD" ]]; then
    echo "Error: Server certificate and key do not match"
    exit 1
fi

# Verify client certificate chain and key match
if ! openssl verify -CAfile ca.pem client.pem >/dev/null 2>&1; then
    echo "Error: Client certificate chain validation failed"
    exit 1
fi
CLIENT_CERT_MOD=$(openssl x509 -in client.pem -noout -modulus 2>/dev/null | openssl md5)
CLIENT_KEY_MOD=$(openssl rsa -in client-key.pem -noout -modulus 2>/dev/null | openssl md5)
if [[ "$CLIENT_CERT_MOD" != "$CLIENT_KEY_MOD" ]]; then
    echo "Error: Client certificate and key do not match"
    exit 1
fi

echo "✓ All certificates validated successfully"

echo ""
echo "Certificates generated in: $(pwd)"
echo ""
ls -la
echo ""
echo "Server certificate SANs:"
openssl x509 -in server.pem -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^[[:space:]]*/  /'
echo ""
echo "Copy to your deployment:"
echo "  Server: ca.pem, server.pem, server-key.pem"
echo "  Client: ca.pem, client.pem, client-key.pem"
