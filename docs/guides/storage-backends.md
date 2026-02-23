# Storage Backend

router-hosts uses SQLite as its storage backend. SQLite provides an embedded,
zero-configuration database that stores all data in a single file.

## Configuration

```toml
[database]
path = "/var/lib/router-hosts/hosts.db"
```

Default location (if no path specified): `~/.local/share/router-hosts/hosts.db`

## Implementation

The Go implementation uses `modernc.org/sqlite`, a pure-Go SQLite driver
that requires no CGo or system libraries. This ensures maximum portability
across platforms.

## Event Store

All changes are stored as immutable events. The current state is reconstructed
from the event log, providing a complete audit trail.

## In-Memory Mode

For testing, use in-memory SQLite: `":memory:"` as the database path.
