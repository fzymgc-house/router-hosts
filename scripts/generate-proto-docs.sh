#!/usr/bin/env bash
set -euo pipefail

# Generate API reference documentation from protobuf definitions
#
# Usage: ./scripts/generate-proto-docs.sh
# Requires: protoc-gen-doc (go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1)

OUTPUT_DIR="docs/reference"
OUTPUT_FILE="$OUTPUT_DIR/api.md"
PROTO_FILE="proto/router_hosts/v1/hosts.proto"

# Check for protoc
if ! command -v protoc &> /dev/null; then
    echo "Error: protoc not found. Install Protocol Buffers compiler." >&2
    exit 1
fi

# Check for protoc-gen-doc
if ! command -v protoc-gen-doc &> /dev/null; then
    echo "Error: protoc-gen-doc not found." >&2
    echo "Install with: go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1" >&2
    exit 1
fi

# Verify proto file exists
if [[ ! -f "$PROTO_FILE" ]]; then
    echo "Error: Proto file not found: $PROTO_FILE" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR" || {
    echo "Error: Failed to create output directory: $OUTPUT_DIR" >&2
    exit 1
}

# Generate markdown from proto files
if ! protoc \
    --doc_out="$OUTPUT_DIR" \
    --doc_opt=markdown,api.md \
    -I proto \
    "$PROTO_FILE"; then
    echo "Error: Failed to generate API documentation from protobuf definitions" >&2
    echo "Ensure proto files exist and are valid" >&2
    exit 1
fi

# Verify protoc generated the file
if [[ ! -f "$OUTPUT_FILE" ]]; then
    echo "Error: protoc did not generate expected output file: $OUTPUT_FILE" >&2
    exit 1
fi

# Add header to generated file
TEMP_FILE=$(mktemp)
trap 'rm -f "$TEMP_FILE"' EXIT

cat > "$TEMP_FILE" << 'HEADER'
# API Reference

gRPC API documentation for router-hosts.

!!! note "Auto-generated"
    This documentation is auto-generated from protobuf definitions.

---

HEADER

cat "$OUTPUT_FILE" >> "$TEMP_FILE"
mv "$TEMP_FILE" "$OUTPUT_FILE"

# Verify output has content
line_count=$(wc -l < "$OUTPUT_FILE" | tr -d ' ')
if [[ "$line_count" -lt 20 ]]; then
    echo "Error: Generated documentation appears incomplete ($line_count lines)" >&2
    exit 1
fi

echo "Generated API documentation at $OUTPUT_FILE ($line_count lines)"
