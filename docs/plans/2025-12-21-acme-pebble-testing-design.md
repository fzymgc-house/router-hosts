# ACME Pebble Testing Design

## Problem

The ACME module has comprehensive test coverage for non-network logic, but the full ACME protocol flow (account creation, order creation, challenge handling, certificate issuance) requires a live ACME server. Tests using Pebble (Let's Encrypt's test server) were marked `#[ignore]` because `instant-acme` appeared to not support custom HTTP clients for trusting Pebble's self-signed CA.

## Solution

`instant-acme` already supports custom HTTP clients via:
- `Account::create_with_http()`
- `Account::from_credentials_and_http()`

The `HttpClient` trait is public, and any `HyperClient<C, Full<Bytes>>` where `C: Connect` automatically implements it.

## Design

### API Changes

Add optional custom HTTP client support to `AcmeClient`:

```rust
pub struct AcmeClient {
    account: RwLock<Option<Account>>,
    config: AcmeConfig,
    http_client: Option<Box<dyn instant_acme::HttpClient>>,
}

impl AcmeClient {
    /// Create client with default HTTP (production use)
    pub fn new(config: AcmeConfig) -> Result<Self, AcmeError> { ... }

    /// Create client with custom HTTP client (testing use)
    pub fn with_http_client(
        config: AcmeConfig,
        http_client: Box<dyn instant_acme::HttpClient>,
    ) -> Result<Self, AcmeError> { ... }
}
```

### Test Infrastructure

Create a helper function that builds a hyper client trusting Pebble's CA:

```rust
fn create_pebble_http_client() -> Box<dyn instant_acme::HttpClient> {
    const PEBBLE_CA_PEM: &str = include_str!("pebble-ca.pem");

    let mut roots = RootCertStore::empty();
    // ... configure rustls with Pebble CA

    Box::new(HyperClient::builder(TokioExecutor::new()).build(https))
}
```

### Files Modified

| File | Change |
|------|--------|
| `client.rs` | Add `with_http_client()`, update `ensure_account()` |
| `acme_test.rs` | Add `create_pebble_http_client()`, remove `#[ignore]` |
| `tests/pebble-ca.pem` | New file - Pebble's test CA |
| `Cargo.toml` | Add `hyper-util` dev-dependency |

### Removed

- `#[cfg(not(tarpaulin_include))]` from `client.rs` and `renewal.rs`
- `#[ignore]` from Pebble integration tests

## Expected Outcome

- All 15 ACME tests run (no ignored)
- Coverage ≥80% maintained
- CI passes
