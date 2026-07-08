# Context (DOC Intel)

Running notes from 13 DOC-classified documents (implementation plans and design rationale). Keyed by topic, with source attribution. These are context only — not decisions, requirements, or contracts.

---

## Topic: Certificate reload

- source: docs/plans/2025-12-15-sighup-cert-reload-impl.md — Task-by-task plan implementing SIGHUP cert rotation without full server restart. Cross-refs the sighup-cert-reload-design SPEC.

## Topic: Hosts aliases

- source: docs/plans/2025-12-16-hosts-aliases-impl.md — Implementation plan for hostname alias support and tags/aliases wrapper messages across storage backends; introduces AliasesModified event. Embeds protobuf schema fragments but is a step-by-step plan. Cross-refs proto/router_hosts/v1/hosts.proto.

## Topic: ACME / testing

- source: docs/plans/2025-12-21-acme-pebble-testing-design.md — Notes (Status: IMPLEMENTED) on restoring live ACME protocol tests using Pebble with a custom root CA via instant-acme 0.8.4. References a Rust-era `instant-acme` dependency (historical stack — see Rust→Go supersession INFO in INGEST-CONFLICTS.md).

## Topic: Kubernetes operator

- source: docs/plans/2025-12-24-router-hosts-operator-impl.md — Implementation plan for the operator syncing Ingress/IngressRoute hostnames; HostMapping CRD, kube-rs, gRPC/mTLS, leader election. (kube-rs = Rust-era stack; historical.)
- source: docs/plans/2026-01-02-service-controller-impl.md — Plan to add a Service controller for LoadBalancer/NodePort DNS entries. Cross-refs `crates/router-hosts-operator/src/controllers/service.rs` (Rust paths — historical, superseded by Go `cmd/operator`).
- source: docs/plans/2026-06-07-gateway-api-support-plan.md — Implementation plan for a Gateway API controller (HTTPRoute/GRPCRoute/TLSRoute) registering route hostnames as DNS entries; Helm chart + gateway-api dependency. Cross-refs the gateway-api-support-design SPEC. (Go-era, current.)

## Topic: Storage (SQLite / DuckDB)

- source: docs/plans/2025-12-24-sqlite-default-storage-design.md — Design rationale for making SQLite the default backend and moving DuckDB to a separate binary. Has a "Design Decisions" table but Status: IMPLEMENTED, not an ADR. References Rust/Cargo feature flags and Docker images (historical stack).
- source: docs/plans/2025-12-24-sqlite-default-implementation.md — Plan to make SQLite default and split DuckDB into a wrapper binary; Cargo feature flags, XDG paths. Rust/Cargo stack — historical/superseded by the Go migration (current codebase is Go, SQLite-only, no CGo).

## Topic: Observability (OpenTelemetry)

- source: docs/plans/2026-01-01-otel-integration-impl.md — Plan adding OpenTelemetry distributed tracing, metrics export (OTLP/Prometheus), and trace-context propagation via OtelConfig.

## Topic: Go migration (stack transition)

- source: docs/plans/2026-02-22-golang-migration-design.md — Design plan migrating router-hosts from Rust to Go, preserving event sourcing, gRPC/mTLS, K8s operator; simplifying storage to SQLite. Has a "Key Decisions" table, Status: Draft. This document is the authoritative record of the Rust→Go stack supersession that renders the earlier Rust/Cargo-referencing docs historical.
- source: docs/plans/2026-02-22-golang-migration-plan.md — Task-by-task Go migration implementation plan. Cross-refs the golang-migration-design DOC.

## Topic: Aggregate compaction

- source: docs/superpowers/plans/2026-06-26-aggregate-compaction.md — Implementation plan for server-side host-aggregate compaction (HostCompacted event, CompactAggregates RPC, compact CLI) plus cardinality-safe per-aggregate event-count metrics. Derived from the aggregate-compaction-design SPEC; governed by locked ADRs v5b/vl8/4w2.

## Topic: Unbound conf output

- source: docs/superpowers/plans/2026-07-07-unbound-conf-path.md — Implementation plan for the optional `unbound_conf_path` output emitting authoritative local-zone/local-data directives (DNS leak mitigation). Derived from the unbound-conf-path-design SPEC; governed by locked ADR bzg. Cross-refs configuration and operations docs.

---

## Cross-cutting note: Rust → Go stack transition

Several early DOCs (sqlite-default-*, acme-pebble-testing, operator-impl, service-controller-impl) describe a Rust/Cargo (`crates/`, kube-rs, instant-acme) stack. The 2026-02-22 Go migration (design + plan) explicitly supersedes that stack; the current codebase (per CLAUDE.md) is Go, SQLite-only (zombiezen.com/go/sqlite, no CGo), with a Go `cmd/operator`. Treat Rust-referencing plan docs as historical intent, not current architecture. Recorded as an INFO entry in INGEST-CONFLICTS.md.
