# SIGHUP Certificate Reload Design

**Issue:** #98
**Status:** ✅ Implemented (PR #118, merged 2025-12-16)
**Date:** 2025-12-15

## Summary

Add support for dynamic TLS certificate reload via SIGHUP signal. When the server receives SIGHUP, it validates the new certificates, performs a graceful shutdown, and restarts with the new certificates.

## Goals

- Enable certificate rotation without full server restart
- Support Vault Agent and other automated certificate renewal tools
- Maintain zero-downtime for existing connections during reload

## Non-Goals

- File watching (may be added later)
- ACME/Let's Encrypt integration (separate issue #15)
- Windows support for SIGHUP (Unix-only signal)

## Architecture

### Server Loop Structure

Instead of a single `serve()` call, the server runs in a loop:

```rust
pub async fn run_server(config: Arc<Config>) -> Result<(), ServerError> {
    loop {
        // Load TLS certs (re-read on each iteration)
        let tls_config = load_tls_config(&config.tls).await?;

        // Run server until shutdown signal
        let reason = serve_until_signal(config, tls_config).await?;

        match reason {
            ShutdownReason::Terminate => break,  // SIGTERM/Ctrl+C - exit
            ShutdownReason::Reload => continue,  // SIGHUP - restart loop
        }
    }
    Ok(())
}
```

### Shutdown Reason Enum

```rust
enum ShutdownReason {
    /// SIGTERM or Ctrl+C - exit completely
    Terminate,
    /// SIGHUP - reload certificates and restart
    Reload,
}
```

### Signal Handling

Expand existing `shutdown_signal()` to handle SIGHUP:

```rust
async fn shutdown_signal() -> ShutdownReason {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
        ShutdownReason::Terminate
    };

    #[cfg(unix)]
    let sigterm = async {
        signal::unix::signal(SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
        ShutdownReason::Terminate
    };

    #[cfg(unix)]
    let sighup = async {
        signal::unix::signal(SignalKind::hangup())
            .expect("Failed to install SIGHUP handler")
            .recv()
            .await;
        ShutdownReason::Reload
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<ShutdownReason>();

    #[cfg(not(unix))]
    let sighup = std::future::pending::<ShutdownReason>();

    tokio::select! {
        reason = ctrl_c => reason,
        reason = sigterm => reason,
        reason = sighup => reason,
    }
}
```

## Certificate Validation

Before initiating graceful shutdown, validate the new certificates:

```rust
fn validate_tls_config(config: &TlsConfig) -> Result<(), TlsError> {
    // 1. Read all three files
    let cert = std::fs::read(&config.cert_path)?;
    let key = std::fs::read(&config.key_path)?;
    let ca = std::fs::read(&config.ca_cert_path)?;

    // 2. Parse PEM format
    let cert_chain = parse_pem_certs(&cert)?;
    let private_key = parse_pem_key(&key)?;

    // 3. Verify key matches certificate
    verify_key_matches_cert(&cert_chain, &private_key)?;

    // 4. Parse CA cert
    let _ = parse_pem_certs(&ca)?;

    Ok(())
}
```

### What We Validate

- Files exist and are readable
- Valid PEM format
- Private key matches certificate's public key
- CA cert is valid PEM

### What We Don't Validate

- Certificate expiry (server should start even with expired certs)
- CA chain validity (client verification handles this at connection time)

## Reload Behavior

### On Valid Certificates

1. Log: `info!("Received SIGHUP, reloading certificates...")`
2. Validate new certificates from disk
3. Log: `info!("Certificates validated, initiating graceful shutdown")`
4. Graceful shutdown with 30s drain timeout
5. Loop restarts, loads new certificates
6. Log: `info!("Server restarted with new certificates")`

### On Invalid Certificates

1. Log: `info!("Received SIGHUP, reloading certificates...")`
2. Validate new certificates - FAILS
3. Log: `error!("Certificate reload failed: {reason}, keeping current certificates")`
4. Server continues running with existing certificates
5. No restart occurs

### Graceful Shutdown Timeout

Fixed 30-second timeout for connection draining. This matches gRPC default timeouts and covers most RPC operations.

## Platform Support

| Platform | SIGHUP Support |
|----------|----------------|
| Linux | Yes |
| macOS | Yes |
| Windows | No (logs warning at startup) |

On Windows, the server logs a warning that certificate reload via signal is not supported.

## Files to Modify

| File | Changes |
|------|---------|
| `crates/router-hosts/src/server/mod.rs` | Add server loop, `ShutdownReason`, SIGHUP handler, validation |
| `crates/router-hosts/src/server/error.rs` | Add TLS validation error variants if needed |
| `CLAUDE.md` | Document SIGHUP reload feature |
| `examples/README.md` | Add certificate reload instructions |

## Testing Strategy

### Unit Tests

- `test_validate_tls_config_valid` - Valid cert/key/CA passes
- `test_validate_tls_config_missing_file` - Missing file returns error
- `test_validate_tls_config_invalid_pem` - Malformed PEM returns error
- `test_validate_tls_config_key_mismatch` - Mismatched key/cert returns error

### E2E Test

```rust
#[tokio::test]
async fn test_sighup_certificate_reload() {
    // 1. Start server with initial certs
    // 2. Make successful gRPC call
    // 3. Replace cert files on disk with new certs
    // 4. Send SIGHUP to server process
    // 5. Wait for reload (poll health endpoint)
    // 6. Make another gRPC call - should succeed
}
```

### Manual Testing Checklist

- [ ] SIGHUP with valid new certs → server restarts, new connections work
- [ ] SIGHUP with invalid certs → error logged, server keeps running
- [ ] SIGHUP during active connection → connection completes, then restart
- [ ] Multiple SIGHUPs in quick succession → handled gracefully

## Usage

### With Vault Agent

Configure Vault Agent to send SIGHUP after certificate renewal:

```hcl
template {
  source      = "cert.tpl"
  destination = "/etc/router-hosts/server.crt"
  command     = "pkill -HUP router-hosts"
}
```

### Manual Reload

```bash
# Find server PID
pgrep router-hosts

# Send SIGHUP
kill -HUP <pid>

# Or using pkill
pkill -HUP router-hosts
```

## Future Considerations

- **File watcher:** Could add `notify` crate for automatic reload on file change
- **Reload endpoint:** Could add gRPC endpoint for reload (requires auth)
- **Metrics:** Could expose reload count and last reload time via metrics
