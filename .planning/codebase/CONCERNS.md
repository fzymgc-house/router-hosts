# Codebase Concerns

**Analysis Date:** 2026-07-08

This is a mature, well-maintained Go codebase (112 test files vs. 44 source files, 80% enforced coverage, structured errors via `samber/oops`, no `//nolint` directives, no library-code `panic`/`os.Exit`). Concerns below are refinements and watch-areas rather than acute failures.

## Tech Debt

**Oversized service layer:**

- Issue: `internal/server/service.go` is 1033 lines with 31 top-level functions — the gRPC service, streaming import/export, CSV formatting, and command dispatch all live in one file.
- Files: `internal/server/service.go`
- Impact: High cognitive load; harder to locate/modify a single RPC; merge-conflict hotspot.
- Fix approach: Split by responsibility — e.g. `service_import.go`, `service_export.go`, `service_query.go` — keeping the `Service` receiver methods but grouping by RPC family.

**Large command dispatcher:**

- Issue: `internal/server/commands.go` (519 lines) concentrates command handling.
- Files: `internal/server/commands.go`
- Impact: Same as above — growth pressure on a single file.
- Fix approach: Group command handlers by aggregate/operation.

**Legacy Rust-era migration carried in-tree:**

- Issue: `internal/storage/sqlite/legacy_migration.go` (515 lines) migrates data from the pre-Go (Rust) `host_events` schema, decoding Rust `EventData` JSON.
- Files: `internal/storage/sqlite/legacy_migration.go`
- Impact: Permanent maintenance surface for a one-time migration path; couples the storage layer to a defunct schema.
- Fix approach: Gate behind a version check (already `legacyMigrationVersion = 3`); once all deployments are known-migrated, plan a deprecation + removal milestone.

## Known Bugs

None detected. The only `TODO`/`FIXME`/`HACK` marker in the codebase is a benign explanatory comment:

- `e2e/docker_e2e_test.go:231` — note about normalizing `docker port` output; not a defect.

## Security Considerations

**mTLS-only trust boundary:**

- Risk: All client-server auth relies on mutual TLS. Misconfiguration (wrong CA, expired certs) is the primary failure/attack surface.
- Files: `internal/client` (client mTLS wrapper), `internal/server/server.go`, `internal/acme/acme.go`
- Current mitigation: ACME/lego auto-renewal (`internal/acme/acme.go`, `renewalLoop`); CLAUDE.md forbids skipping TLS/CA verification.
- Recommendations: Ensure cert-renewal failures surface loudly (alert/metric) rather than silently expiring; verify no code path allows `InsecureSkipVerify`.

**Ignored errors on cleanup paths (ACME temp files):**

- Risk: `_ = tmp.Close()` / `_ = os.Remove(tmpPath)` in cert writing swallow errors. Low security impact, but a failed remove could leave key material in a temp path.
- Files: `internal/acme/acme.go:312-334`
- Current mitigation: These are deferred cleanup fallbacks after the primary write path.
- Recommendations: Confirm temp files are created with `0600` perms in a private dir; log (not just discard) removal failures for key material.

## Performance Bottlenecks

**Single-goroutine write serialization:**

- Problem: All storage writes are funneled through one goroutine (`WriteQueue`), so write throughput is inherently serial.
- Files: `internal/server/writequeue.go`
- Cause: Deliberate design to serialize concurrent writes against SQLite and preserve event ordering.
- Improvement path: Acceptable for a router-hosts control plane (low write volume). If write load grows, consider batching multiple enqueued commands per SQLite transaction.

## Fragile Areas

**WriteQueue context-cancellation trade-off:**

- Files: `internal/server/writequeue.go`
- Why fragile: Documented known trade-off — if a caller's context is cancelled after a command is enqueued but before the result returns, the write may still commit storage-side while the caller sees a context error.
- Safe modification: The mitigation is idempotency (optimistic concurrency on updates/deletes, IP+hostname dedup on AddHost). Any new write RPC MUST preserve retry-safety, or the trade-off becomes a correctness bug.
- Test coverage: WriteQueue has a co-located test; verify cancellation-during-enqueue is exercised.

**Legacy migration JSON decoding:**

- Files: `internal/storage/sqlite/legacy_migration.go`
- Why fragile: Manually mirrors an external (Rust) struct via pointer-heavy `omitempty` JSON tags; schema drift or a malformed legacy row could break migration. Several `_ = sqlitex.Execute(...)` calls discard errors (lines 83, 408).
- Safe modification: Do not alter `rustEventMetadata` field mapping without a legacy-data fixture test.
- Test coverage: Confirm migration has fixture-based tests covering malformed/partial legacy rows.

## Scaling Limits

**SQLite single-writer model:**

- Current capacity: Suitable for a homelab/router DNS control plane — modest host counts, low write concurrency.
- Limit: Serial writes + single-file SQLite bound horizontal scale; no multi-node write replication.
- Scaling path: Not a near-term concern for the stated use case. Event-sourced design would permit a future pluggable `EventStore` backend if needed.

## Dependencies at Risk

**Pre-release protobuf pin:**

- Risk: `google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af` is pinned to a pseudo-version (untagged commit) rather than a released tag.
- Impact: Reproducibility/supply-chain clarity; potential surprise on upstream changes.
- Migration plan: Move to a tagged release once available.

**Bleeding-edge Go toolchain:**

- Risk: `go 1.26.4` in `go.mod` — very recent; CLAUDE.md lists 1.25+ as prerequisite.
- Impact: Contributors on older toolchains cannot build; CI must track the pinned version.
- Migration plan: Keep prerequisite docs and CI in sync with the `go.mod` directive.

## Missing Critical Features

None identified. Feature surface (CLI, TUI, gRPC server, K8s operator, ACME, import/export, snapshots) is broad and coherent for the project scope.

## Test Coverage Gaps

Coverage is enforced at ≥80% (`Taskfile.yml:49`). Files without a co-located `_test.go` (may be covered indirectly by suite/integration tests — verify):

- `internal/storage/sqlite/eventstore.go`, `projection.go`, `snapshots.go` — likely exercised via `internal/storage/storagetest/suite.go`, but confirm direct-path coverage.
  - Files: `internal/storage/sqlite/*.go`
  - Risk: SQLite persistence bugs (concurrency, migration) could pass if only the abstract suite runs against a mock.
  - Priority: Medium
- `internal/client/output/{format,csv,json,table}.go` — output formatters have no co-located tests.
  - Risk: Formatting regressions (CSV escaping, JSON shape) reach users silently.
  - Priority: Medium
- `internal/operator/hostclient.go` — operator client wrapper untested at file level.
  - Risk: Operator-to-server integration breakage.
  - Priority: Medium
- `cmd/router-hosts/main.go`, `cmd/operator/main.go` — thin entrypoints (contain the only library-adjacent `os.Exit`); acceptable to leave untested.
  - Priority: Low

---

*Concerns audit: 2026-07-08*
