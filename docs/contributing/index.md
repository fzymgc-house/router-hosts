# Contributing

Thank you for your interest in contributing to router-hosts!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/fzymgc-house/router-hosts.git
   cd router-hosts
   ```

2. Install prerequisites:
   - Rust 1.75+ (`rustup install stable`)
   - buf CLI (`brew install bufbuild/buf/buf`)
   - pre-commit (`pip install pre-commit && pre-commit install`)

3. Build and test:
   ```bash
   task build
   task test
   ```

## Guidelines

- Follow [Conventional Commits](https://www.conventionalcommits.org/)
- Maintain 80%+ test coverage
- Run `task lint` before committing

## Resources

- [Architecture](architecture.md) — System design and internals
- [Testing](testing.md) — Test infrastructure and E2E tests
- [Releasing](releasing.md) — Release process
