#!/usr/bin/env bash
set -euo pipefail

# Generate CLI reference documentation from --help output
#
# Usage: ./scripts/generate-cli-docs.sh [binary-path]
# Default binary: ./target/release/router-hosts

BINARY="${1:-./target/release/router-hosts}"
OUTPUT="docs/reference/cli.md"

if [[ ! -x "$BINARY" ]]; then
    echo "Error: Binary not found or not executable: $BINARY" >&2
    exit 1
fi

cat > "$OUTPUT" << 'HEADER'
# CLI Reference

Command-line interface documentation for router-hosts.

!!! note "Auto-generated"
    This documentation is auto-generated from `router-hosts --help`.

HEADER

# Global help
echo '## Global Usage' >> "$OUTPUT"
echo '' >> "$OUTPUT"
echo '```' >> "$OUTPUT"
"$BINARY" --help >> "$OUTPUT"
echo '```' >> "$OUTPUT"
echo '' >> "$OUTPUT"

# Extract subcommands from help output
# Matches lines that start with whitespace followed by a word (subcommand name)
subcommands=$("$BINARY" --help | grep -E '^\s{2,}[a-z]' | awk '{print $1}' | grep -v '^-' || true)

for cmd in $subcommands; do
    # Skip if it looks like an option (starts with -)
    if [[ "$cmd" == -* ]]; then
        continue
    fi

    echo "## $cmd" >> "$OUTPUT"
    echo '' >> "$OUTPUT"
    echo '```' >> "$OUTPUT"
    "$BINARY" "$cmd" --help >> "$OUTPUT" 2>&1 || echo "Error getting help for $cmd" >> "$OUTPUT"
    echo '```' >> "$OUTPUT"
    echo '' >> "$OUTPUT"
done

echo "Generated CLI documentation at $OUTPUT"
