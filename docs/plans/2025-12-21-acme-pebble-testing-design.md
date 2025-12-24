# ACME Pebble Testing Design

**Status: IMPLEMENTED** (2025-12-24)

## Problem

The ACME module has comprehensive test coverage for non-network logic, but the full ACME protocol flow (account creation, order creation, challenge handling, certificate issuance) requires a live ACME server. Tests using Pebble (Let's Encrypt's test server) were removed because `instant-acme` 0.8 changed its API for custom HTTP client configuration.

## Solution

`instant-acme` 0.8.4 provides `Account::builder_with_root(pem_path)` which configures the HTTP client to trust a custom root CA certificate. This is simpler than the original custom `HttpClient` approach.

## Implementation

### API Changes

Added optional custom root CA support to `AcmeClient`:

```rust
pub struct AcmeClient {
    account: RwLock<Option<Account>>,
    config: AcmeConfig,
    root_ca_path: Option<PathBuf>,  // NEW: custom CA for testing
}

impl AcmeClient {
    /// Create client with default CA (production use)
    pub fn new(config: AcmeConfig) -> Result<Self, AcmeError> { ... }

    /// Create client with custom root CA (testing with Pebble)
    pub fn with_root_ca(
        config: AcmeConfig,
        root_ca_path: impl Into<PathBuf>,
    ) -> Result<Self, AcmeError> { ... }

    /// Helper to create account builder with optional CA
    fn create_account_builder(&self) -> Result<AccountBuilder, AcmeError> {
        match &self.root_ca_path {
            Some(ca_path) => Account::builder_with_root(ca_path),
            None => Account::builder(),
        }
    }
}
```

### Test Infrastructure

The `PebbleTestEnv` writes the embedded CA to a temp file:

```rust
const PEBBLE_CA_PEM: &str = include_str!("pebble-ca.pem");

impl PebbleTestEnv {
    async fn start() -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let ca_path = temp_dir.path().join("pebble-ca.pem");
        std::fs::write(&ca_path, PEBBLE_CA_PEM).unwrap();
        // ...start containers...
        Self { ca_path, ... }
    }

    fn ca_path(&self) -> &Path { &self.ca_path }
}
```

Tests use the custom CA:

```rust
let client = AcmeClient::with_root_ca(config, env.ca_path())
    .expect("Failed to create ACME client with custom CA");
```

### Files Modified

| File | Change |
|------|--------|
| `client.rs` | Add `with_root_ca()`, `create_account_builder()`, `root_ca_path` field |
| `acme_test.rs` | Add CA path handling, restore 3 Pebble integration tests |
| `tests/pebble-ca.pem` | Pebble's test CA certificate |

### instant-acme 0.8 API Changes

The test code uses the new async stream API:

```rust
// Get authorizations as async stream
let mut authorizations = order.authorizations();
while let Some(result) = authorizations.next().await {
    let mut authz = result?;

    // Get challenge by type
    let mut challenge = authz.challenge(ChallengeType::Http01)?;

    // Mark challenge ready
    challenge.set_ready().await?;
}

// Poll for order readiness
order.poll_ready(&RetryPolicy::default()).await?;
```

## Outcome

- 15 ACME tests pass (3 Pebble integration tests restored)
- Coverage: 81.38% (above 80% threshold)
- All tests run with Docker (testcontainers)
- No system trust store modifications required
