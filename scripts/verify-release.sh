#!/bin/bash
# Verify a router-hosts release
# Usage: ./scripts/verify-release.sh v0.6.0

set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 v0.6.0"
    exit 1
fi

if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "Error: Version must start with 'v' (e.g., v0.6.0)"
    exit 1
fi

echo "=== Verifying release $VERSION ==="
echo

echo "1. Checking GitHub Release..."
gh release view "$VERSION" --json tagName,name,isDraft,isPrerelease,assets \
    --jq '{tag: .tagName, name: .name, draft: .isDraft, prerelease: .isPrerelease, assets: (.assets | length)}'
echo

echo "2. Listing release assets..."
gh release view "$VERSION" --json assets --jq '.assets[].name'
echo

echo "3. Downloading binary for verification..."
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Download based on current platform (handle multiple uname -m variants)
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) ARCHIVE="router-hosts-aarch64-apple-darwin.tar.xz" ;;
    Darwin-x86_64) ARCHIVE="router-hosts-x86_64-apple-darwin.tar.xz" ;;
    Linux-aarch64|Linux-arm64) ARCHIVE="router-hosts-aarch64-unknown-linux-gnu.tar.xz" ;;
    Linux-x86_64|Linux-amd64) ARCHIVE="router-hosts-x86_64-unknown-linux-gnu.tar.xz" ;;
    *) echo "Unsupported platform: $(uname -s)-$(uname -m)"; exit 1 ;;
esac

gh release download "$VERSION" --pattern "$ARCHIVE" --pattern "${ARCHIVE}.sha256" --dir "$TMPDIR"
echo "Downloaded: $ARCHIVE"
echo

echo "4. Verifying checksum..."
EXPECTED_SHA=$(cat "$TMPDIR/${ARCHIVE}.sha256" | awk '{print $1}')
ACTUAL_SHA=$(shasum -a 256 "$TMPDIR/$ARCHIVE" | awk '{print $1}')
if [[ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]]; then
    echo "❌ ERROR: Checksum mismatch!"
    echo "Expected: $EXPECTED_SHA"
    echo "Actual:   $ACTUAL_SHA"
    exit 1
fi
echo "✅ Checksum verified: $EXPECTED_SHA"
echo

tar -xf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"
echo "Extracted: $ARCHIVE"
echo

echo "5. Verifying GitHub attestation..."
if ! gh attestation verify "$TMPDIR/router-hosts" --repo fzymgc-house/router-hosts; then
    echo
    echo "❌ ERROR: Attestation verification failed!"
    echo "This binary may not be authentic. Do not use in production."
    echo
    echo "If this is an older release before attestations were enabled, you may"
    echo "skip this check by setting SKIP_ATTESTATION=1"
    if [[ "${SKIP_ATTESTATION:-}" != "1" ]]; then
        exit 1
    fi
    echo "Continuing due to SKIP_ATTESTATION=1..."
fi
echo

echo "6. Checking binary info..."
file "$TMPDIR/router-hosts"
"$TMPDIR/router-hosts" --version
echo

echo "7. Checking embedded audit data..."
if command -v cargo-auditable &> /dev/null; then
    cargo auditable info "$TMPDIR/router-hosts" | head -20
else
    echo "Note: cargo-auditable not installed, skipping audit check"
    echo "Install with: cargo install cargo-auditable"
fi
echo

echo "=== Release $VERSION verification complete ==="
