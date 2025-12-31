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

# Get global help output first (validates binary works)
help_output=$("$BINARY" --help) || {
    echo "Error: Failed to get help output from $BINARY" >&2
    exit 1
}

{
    cat << 'HEADER'
# CLI Reference

Command-line interface documentation for router-hosts.

!!! note "Auto-generated"
    This documentation is auto-generated from `router-hosts --help`.

HEADER

    # Global help
    echo '## Global Usage'
    echo ''
    echo '```'
    echo "$help_output"
    echo '```'
    echo ''
} > "$OUTPUT"

# Extract subcommands from help output
# Matches lines that start with whitespace followed by a word (subcommand name)
# Filter out "help" subcommand as it doesn't support --help flag
subcommands=$(echo "$help_output" | grep -E '^\s{2,}[a-z]' | awk '{print $1}' | grep -v '^-' | grep -v '^help$' || true)

if [[ -z "$subcommands" ]]; then
    echo "Warning: No subcommands found in help output" >&2
fi

errors=()
for cmd in $subcommands; do
    # Skip if it looks like an option (starts with -)
    if [[ "$cmd" == -* ]]; then
        continue
    fi

    {
        echo "## $cmd"
        echo ''
        echo '```'
    } >> "$OUTPUT"

    if ! "$BINARY" "$cmd" --help >> "$OUTPUT" 2>&1; then
        echo "Error: Failed to get help for subcommand: $cmd" >&2
        errors+=("$cmd")
    fi

    {
        echo '```'
        echo ''
    } >> "$OUTPUT"
done

if [[ ${#errors[@]} -gt 0 ]]; then
    echo "Error: Failed to generate help for subcommands: ${errors[*]}" >&2
    exit 1
fi

# Verify output has meaningful content (more than just the header)
line_count=$(wc -l < "$OUTPUT" | tr -d ' ')
if [[ "$line_count" -lt 20 ]]; then
    echo "Error: Generated documentation appears incomplete ($line_count lines)" >&2
    exit 1
fi

echo "Generated CLI documentation at $OUTPUT ($line_count lines)"
