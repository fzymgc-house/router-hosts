# Structured Hook Definitions

**Issue:** #165
**Date:** 2025-12-29
**Status:** Approved

## Summary

Replace simple command strings in hook configuration with structured definitions containing explicit names and commands. This enables meaningful hook identification in health endpoints, logs, and metrics without exposing sensitive command details.

## Configuration Schema

### New Format

```toml
[[hooks.on_success]]
name = "reload-dns"
command = "/usr/bin/reload-dns --config /etc/dns.conf"

[[hooks.on_success]]
name = "log-update"
command = "logger 'hosts updated'"

[[hooks.on_failure]]
name = "alert-ops"
command = "/usr/local/bin/alert-failure"
```

### Rust Types

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct HookDefinition {
    pub name: String,
    pub command: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct HooksConfig {
    #[serde(default)]
    pub on_success: Vec<HookDefinition>,
    #[serde(default)]
    pub on_failure: Vec<HookDefinition>,
}
```

## Validation Rules

### Name Constraints

- Non-empty
- Kebab-case only: lowercase alphanumeric with hyphens (`[a-z0-9]+(-[a-z0-9]+)*`)
- Maximum 50 characters
- Must be unique within hook type (no duplicate names in `on_success` or `on_failure`)

### Command Constraints

- Non-empty

### Error Messages

```
Config error: hook name must be non-empty
Config error: hook name 'Reload DNS' is invalid (must be kebab-case: lowercase letters, numbers, hyphens)
Config error: hook name exceeds 50 character limit
Config error: duplicate hook name 'reload-dns' in on_success hooks
Config error: hook command must be non-empty
```

## HookExecutor Changes

### Updated Structure

```rust
pub struct HookExecutor {
    on_success: Vec<HookDefinition>,
    on_failure: Vec<HookDefinition>,
    timeout_secs: u64,
}
```

### Simplified hook_names()

```rust
pub fn hook_names(&self) -> Vec<String> {
    let mut names = Vec::with_capacity(self.on_success.len() + self.on_failure.len());
    for hook in &self.on_success {
        names.push(format!("on_success: {}", hook.name));
    }
    for hook in &self.on_failure {
        names.push(format!("on_failure: {}", hook.name));
    }
    names
}
```

### Removed

- `sanitize_command()` - no longer needed with explicit names

### Logging

```rust
info!(hook_name = %hook.name, "Running hook");
info!(hook_name = %hook.name, "Hook completed successfully");
error!(hook_name = %hook.name, exit_code = code, "Hook failed");
```

## Breaking Change

This is a breaking change. Users must migrate from:

```toml
[hooks]
on_success = ["echo success"]
```

To:

```toml
[[hooks.on_success]]
name = "log-success"
command = "echo success"
```

## Files to Modify

1. `crates/router-hosts/src/server/config.rs` - Add `HookDefinition`, update `HooksConfig`, add validation
2. `crates/router-hosts/src/server/hooks.rs` - Update `HookExecutor`, remove `sanitize_command()`
3. `crates/router-hosts/src/server/service/health.rs` - Update test mocks
4. `docs/operations.md` - Document new format

## Testing

- Validation: kebab-case enforcement, 50-char limit, duplicate rejection, empty rejection
- Executor: all existing tests updated to use `HookDefinition`
- Health: verify hook names appear correctly in health responses
