#!/bin/bash
set -euo pipefail

echo "==> Installing Homebrew packages..."
brew install \
    bufbuild/buf/buf \
    git-lfs \
    go-task/tap/go-task \
    neovim \
    protobuf \
    shellcheck \
    uv

echo "==> Setting up git-lfs..."
git lfs install

echo "==> Installing pre-commit hooks..."
uvx pre-commit install
uvx pre-commit install --hook-type pre-push

echo "==> Building project (first build caches dependencies)..."
task build

echo "==> Development environment ready!"
