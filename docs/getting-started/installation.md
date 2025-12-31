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
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-linux-x86_64.tar.gz
    tar -xzf router-hosts-linux-x86_64.tar.gz
    sudo mv router-hosts /usr/local/bin/
    ```

=== "macOS (Apple Silicon)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-darwin-aarch64.tar.gz
    tar -xzf router-hosts-darwin-aarch64.tar.gz
    sudo mv router-hosts /usr/local/bin/
    ```

=== "macOS (Intel)"
    ```bash
    curl -LO https://github.com/fzymgc-house/router-hosts/releases/latest/download/router-hosts-darwin-x86_64.tar.gz
    tar -xzf router-hosts-darwin-x86_64.tar.gz
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
