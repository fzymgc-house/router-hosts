#!/usr/bin/env bash
set -euo pipefail

# Generate API reference documentation from protobuf definitions
#
# Usage: ./scripts/generate-proto-docs.sh
# Requires: protoc-gen-doc (go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest)

OUTPUT_DIR="docs/reference"
OUTPUT_FILE="$OUTPUT_DIR/api.md"

# Check for protoc
if ! command -v protoc &> /dev/null; then
    echo "Error: protoc not found. Install Protocol Buffers compiler." >&2
    exit 1
fi

# Check for protoc-gen-doc
if ! command -v protoc-gen-doc &> /dev/null; then
    echo "Error: protoc-gen-doc not found." >&2
    echo "Install with: go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@latest" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Generate markdown from proto files
protoc \
    --doc_out="$OUTPUT_DIR" \
    --doc_opt=markdown,api.md \
    -I proto \
    proto/router_hosts/v1/hosts.proto

# Add header to generated file
TEMP_FILE=$(mktemp)
cat > "$TEMP_FILE" << 'HEADER'
# API Reference

gRPC API documentation for router-hosts.

!!! note "Auto-generated"
    This documentation is auto-generated from protobuf definitions.

---

HEADER

cat "$OUTPUT_FILE" >> "$TEMP_FILE"
mv "$TEMP_FILE" "$OUTPUT_FILE"

echo "Generated API documentation at $OUTPUT_FILE"
