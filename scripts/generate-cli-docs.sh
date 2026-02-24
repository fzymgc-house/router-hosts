#!/usr/bin/env bash
set -euo pipefail

# Generate CLI reference documentation from --help output
#
# Usage: ./scripts/generate-cli-docs.sh [binary-path]
# Default binary: ./bin/router-hosts

BINARY="${1:-./bin/router-hosts}"
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

# Extract subcommands from the "Available Commands:" section of Cobra help.
# Only lines between "Available Commands:" and the next blank line are parsed.
extract_subcommands() {
    local help_text="$1"
    echo "$help_text" | awk '
        /^Available Commands:/ { found=1; next }
        found && /^$/ { exit }
        found && /^  [a-z]/ { print $1 }
    '
}

subcommands=$(extract_subcommands "$help_output" | grep -v '^help$' || true)

if [[ -z "$subcommands" ]]; then
    echo "Warning: No subcommands found in help output" >&2
fi

errors=()

# generate_command_docs recursively generates docs for a command and its subcommands.
# Arguments: display_prefix (e.g. "host add"), command_args (e.g. "host add")
generate_command_docs() {
    local display_prefix="$1"
    shift
    local cmd_args=("$@")

    local cmd_help
    if ! cmd_help=$("$BINARY" "${cmd_args[@]}" --help 2>&1); then
        echo "Error: Failed to get help for: ${cmd_args[*]}" >&2
        errors+=("${cmd_args[*]}")
        return
    fi

    # Determine heading level based on nesting depth
    local depth=${#cmd_args[@]}
    local hashes="##"
    for ((i = 1; i < depth; i++)); do
        hashes+="#"
    done

    {
        echo "$hashes $display_prefix"
        echo ''
        echo '```'
        echo "$cmd_help"
        echo '```'
        echo ''
    } >> "$OUTPUT"

    # Recurse into nested subcommands
    local nested
    nested=$(extract_subcommands "$cmd_help" | grep -v '^help$' || true)
    for sub in $nested; do
        generate_command_docs "$display_prefix $sub" "${cmd_args[@]}" "$sub"
    done
}

for cmd in $subcommands; do
    generate_command_docs "$cmd" "$cmd"
done

if [[ ${#errors[@]} -gt 0 ]]; then
    echo "Error: Failed to generate help for: ${errors[*]}" >&2
    exit 1
fi

# Verify output has meaningful content (more than just the header)
line_count=$(wc -l < "$OUTPUT" | tr -d ' ')
if [[ "$line_count" -lt 20 ]]; then
    echo "Error: Generated documentation appears incomplete ($line_count lines)" >&2
    exit 1
fi

echo "Generated CLI documentation at $OUTPUT ($line_count lines)"
