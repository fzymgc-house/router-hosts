# Proto Alignment Design

**Date:** 2025-12-01
**Status:** ✅ Implemented
**Related:** [v0.5.0 Design](2025-12-01-router-hosts-v1-design.md), [Tasks](2025-12-01-v1-tasks.md)

Aligns `proto/router_hosts/v1/hosts.proto` with the v0.5.0 design document.

## Changes Summary

| Change | Type | Impact |
|--------|------|--------|
| Add `version` field to HostEntry | Addition | New ULID field for optimistic concurrency |
| Add `expected_version` to UpdateHostRequest | Addition | Optional field for concurrency checks |
| Remove `active` field from HostEntry | Breaking | Soft deletes → tombstone events |
| Remove BulkAddHosts RPC | Breaking | Use ImportHosts or multiple AddHost calls |
| Remove `name` from Snapshot | Breaking | Snapshots identified by ID/timestamp |
| Update ImportHostsRequest | Addition | Add format and conflict_mode fields |
| Update ImportHostsResponse | Breaking | Restructure progress fields |
| Fix UUID → ULID comment | Documentation | Consistency with implementation |

## HostEntry

```protobuf
message HostEntry {
  // Unique identifier for this host entry (ULID format)
  string id = 1;
  string ip_address = 2;
  string hostname = 3;
  optional string comment = 4;
  repeated string tags = 5;
  google.protobuf.Timestamp created_at = 6;
  google.protobuf.Timestamp updated_at = 7;
  // Version identifier for optimistic concurrency (ULID, changes on each update)
  string version = 8;
}
```

Field 8 changes from `bool active` to `string version`.

## UpdateHostRequest

```protobuf
message UpdateHostRequest {
  string id = 1;
  optional string ip_address = 2;
  optional string hostname = 3;
  optional string comment = 4;
  repeated string tags = 5;
  // Expected version for optimistic concurrency (ULID)
  // If provided and doesn't match current version, returns ABORTED
  optional string expected_version = 6;
}
```

New field 6 for optimistic concurrency.

## Removals

**BulkAddHosts:** Remove message types and RPC:
- `BulkAddHostsRequest`
- `BulkAddHostsResponse`
- `rpc BulkAddHosts`

**Snapshot name:** Remove from both:
- `Snapshot.name` (field 5)
- `CreateSnapshotRequest.name` (field 1)

**Comments:** Update DeleteHost comments to say "tombstone event" not "soft delete".

## ImportHosts Changes

**Request:**
```protobuf
message ImportHostsRequest {
  bytes chunk = 1;
  bool last_chunk = 2;
  optional string format = 3;        // "hosts", "json", "csv"
  optional string conflict_mode = 4; // "skip" (default), "replace", "strict"
}
```

**Response:**
```protobuf
message ImportHostsResponse {
  int32 processed = 1;  // Total entries processed
  int32 created = 2;    // Successfully created
  int32 skipped = 3;    // Duplicates skipped
  int32 failed = 4;     // Validation failures
  optional string error = 5;
}
```

## Server Implementation Approach

Minimal changes to keep codebase compiling:

1. **Update database layer** - Add `version` field, remove `active` field
2. **Generate version ULIDs** - On AddHost and UpdateHost
3. **Check expected_version** - Return ABORTED on mismatch
4. **Remove BulkAddHosts handler** - Already returns unimplemented
5. **Stub import changes** - Default to "skip" mode, return new response fields

## Follow-on Tasks

After this PR, add to tasks document:
- CLI conflict resolution with diff display
- Import conflict modes (replace, strict) full implementation
- Event store integration with version tracking
