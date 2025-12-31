# Installation

## Binary Installation

### Homebrew (macOS/Linux)

```bash
brew install fzymgc-house/tap/router-hosts
```

### Download Binary

Download from [GitHub Releases](https://github.com/fzymgc-house/router-hosts/releases):

=== "Linux (x86_64)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-x86_64-unknown-linux-gnu.tar.xz
    tar -xJf router-hosts-x86_64-unknown-linux-gnu.tar.xz
    sudo mv router-hosts /usr/local/bin/
    ```

=== "Linux (ARM64)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-aarch64-unknown-linux-gnu.tar.xz
    tar -xJf router-hosts-aarch64-unknown-linux-gnu.tar.xz
    sudo mv router-hosts /usr/local/bin/
    ```

=== "macOS (Apple Silicon)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-aarch64-apple-darwin.tar.xz
    tar -xJf router-hosts-aarch64-apple-darwin.tar.xz
    sudo mv router-hosts /usr/local/bin/
    ```

=== "macOS (Intel)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-x86_64-apple-darwin.tar.xz
    tar -xJf router-hosts-x86_64-apple-darwin.tar.xz
    sudo mv router-hosts /usr/local/bin/
    ```

## Docker

```bash
docker pull ghcr.io/fzymgc-house/router-hosts:latest
```

## Build from Source

Requires Rust 1.75+ and buf CLI.

```bash
git clone https://github.com/fzymgc-house/router-hosts.git
cd router-hosts
cargo build --release
```

Binary available at `target/release/router-hosts`.
