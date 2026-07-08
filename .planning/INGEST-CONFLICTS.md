# Ingest Conflict Report

## Conflict Detection Report

### BLOCKERS (0)

No blockers. All four ADRs are LOCKED and mutually consistent (three compaction ADRs — 4w2, v5b, vl8 — are complementary facets of one design; bzg is a separate unbound decision). No LOCKED-vs-LOCKED contradiction. Cross-ref graph is an acyclic impl→design DAG (no cycles, max depth well under 50). No UNKNOWN-confidence-low documents.

### WARNINGS (0)

No competing acceptance variants. Zero PRD-typed documents were ingested, so no divergent-acceptance-criteria conflicts exist.

### INFO (3)

[INFO] Auto-resolved: ADR > SPEC on unbound local-zone type
  Found: docs/superpowers/specs/2026-07-07-unbound-conf-path-design.md defines the unbound_conf_path output and includes a Decisions section on local-zone behavior.
  Note: Locked ADR docs/adr/router-hosts-bzg (Accepted) fixes per-name "local-zone static" (not typetransparent, not zone-wide). The ADR is authoritative; the SPEC implements it and does not contradict it. Recorded in synthesized intel with the ADR as the governing decision.

[INFO] Auto-resolved: ADR > SPEC on aggregate compaction
  Found: docs/superpowers/specs/2026-06-26-aggregate-compaction-design.md defines the compaction event type, storage atomicity, and metrics.
  Note: Locked ADRs docs/adr/router-hosts-v5b (HostCompacted seed event), -vl8 (manual remediate+observe scope), and -4w2 (sacrifice GetAtTime) are authoritative on the compaction data model and scope. The SPEC is consistent with them; ADRs govern where they overlap.

[INFO] Rust to Go stack supersession
  Found: docs/plans/2025-12-24-sqlite-default-implementation.md, docs/plans/2025-12-24-sqlite-default-storage-design.md, docs/plans/2025-12-24-router-hosts-operator-impl.md, docs/plans/2026-01-02-service-controller-impl.md, and docs/plans/2025-12-21-acme-pebble-testing-design.md describe a Rust/Cargo stack (crates/, kube-rs, instant-acme, Cargo feature flags).
  Note: docs/plans/2026-02-22-golang-migration-design.md explicitly supersedes that stack; the current codebase is Go, SQLite-only (zombiezen.com/go/sqlite, no CGo), with a Go cmd/operator. These are same-precedence DOCs so this is not a precedence auto-resolution — the supersession is content-declared by the migration design. Treat Rust-referencing plan docs as historical context, not current architecture. No destination-file gate.
